//! macOS backend: generate an SBPL profile and run `/usr/bin/sandbox-exec`.
//! Base and network profiles derive from openai/codex (see THIRD_PARTY_NOTICES.md).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use warden_core::{LaunchedChild, ProxyHandle, Sandbox, SandboxError, SandboxSpec, Signal};

const BASE: &str = include_str!("../profiles/seatbelt_base.sbpl");
const NETWORK: &str = include_str!("../profiles/seatbelt_network.sbpl");
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub struct Seatbelt;

/// Resolve symlinks the way the kernel will see the path (e.g. /var -> /private/var).
fn canon(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Profile text plus `-D` parameters. Paths go through params so they need no escaping.
pub fn profile(spec: &SandboxSpec) -> (String, Vec<(String, PathBuf)>) {
    let mut params = Vec::new();
    let mut p = String::new();
    p.push_str(BASE);
    p.push_str("\n; ---- warden: filesystem\n(allow file-read*)\n");

    let mut write_parts = Vec::new();
    for (i, root) in spec.read_write.iter().enumerate() {
        let key = format!("WRITABLE_{i}");
        params.push((key.clone(), canon(root)));
        // keep .git internals read-only inside writable roots: a planted hook would run
        // outside the sandbox on the developer's next commit
        let git = canon(root).join(".git");
        if git.is_dir() {
            let hk = format!("WRITABLE_{i}_GIT");
            params.push((hk.clone(), git.join("hooks")));
            let ck = format!("WRITABLE_{i}_GITCFG");
            params.push((ck.clone(), git.join("config")));
            let gk = format!("WRITABLE_{i}_GITDIR");
            params.push((gk.clone(), git.clone()));
            // the literal `.git` entry too, so it cannot be renamed away and replaced
            write_parts.push(format!(
                "(require-all (subpath (param \"{key}\")) (require-not (subpath (param \"{hk}\"))) (require-not (literal (param \"{ck}\"))) (require-not (literal (param \"{gk}\"))))"
            ));
        } else if git.is_file() {
            // worktree/submodule `gitdir:` pointer: repointing it runs code via a fake git dir
            let gk = format!("WRITABLE_{i}_GITDIR");
            params.push((gk.clone(), git));
            write_parts.push(format!(
                "(require-all (subpath (param \"{key}\")) (require-not (literal (param \"{gk}\"))))"
            ));
        } else {
            write_parts.push(format!("(subpath (param \"{key}\"))"));
        }
    }
    if !write_parts.is_empty() {
        p.push_str(&format!(
            "(allow file-write*\n  {}\n)\n",
            write_parts.join("\n  ")
        ));
    }
    for (i, d) in spec.deny_read.iter().enumerate() {
        let key = format!("DENY_{i}");
        params.push((key.clone(), canon(d)));
        p.push_str(&format!("(deny file-read* file-write* (subpath (param \"{key}\")) (literal (param \"{key}\")))\n"));
    }

    p.push_str("\n; ---- warden: network (loopback to the egress proxy only)\n");
    p.push_str("(allow system-socket (socket-domain AF_UNIX))\n");
    if spec.network.allow_local_binding {
        p.push_str("(allow network-bind (local ip \"localhost:*\"))\n(allow network-inbound (local ip \"localhost:*\"))\n(allow network-outbound (remote ip \"localhost:*\"))\n");
    }
    match &spec.network.proxy {
        ProxyHandle::Tcp(addr) => {
            p.push_str(&format!(
                "(allow network-outbound (remote ip \"localhost:{}\"))\n",
                addr.port()
            ));
        }
        ProxyHandle::Unix { path, .. } => {
            params.push(("PROXY_SOCK".into(), canon(path)));
            p.push_str(
                "(allow network-outbound (remote unix-socket (path (param \"PROXY_SOCK\"))))\n",
            );
        }
    }
    if let Some(cred) = spec.env.get(crate::credsock::ENV) {
        params.push(("CRED_SOCK".into(), canon(Path::new(cred))));
        p.push_str("(allow network-outbound (remote unix-socket (path (param \"CRED_SOCK\"))))\n");
    }
    p.push_str(NETWORK);
    (p, params)
}

pub fn args(spec: &SandboxSpec, argv: &[OsString]) -> Vec<OsString> {
    let (profile, params) = profile(spec);
    let mut out: Vec<OsString> = vec!["-p".into(), profile.into()];
    for (k, v) in params {
        let mut d = OsString::from(format!("-D{k}="));
        d.push(v);
        out.push(d);
    }
    out.push("--".into());
    out.extend(argv.iter().cloned());
    out
}

impl Sandbox for Seatbelt {
    fn name(&self) -> &str {
        "seatbelt"
    }
    fn preflight(&self, spec: &SandboxSpec) -> Result<(), SandboxError> {
        if !Path::new(SANDBOX_EXEC).exists() {
            return Err(SandboxError::Preflight(format!("{SANDBOX_EXEC} not found")));
        }
        for p in spec.read_write.iter().chain([&spec.workspace]) {
            if !p.exists() {
                return Err(SandboxError::Preflight(format!(
                    "path does not exist: {}",
                    p.display()
                )));
            }
        }
        Ok(())
    }
    fn spawn(&self, spec: &SandboxSpec, argv: &[OsString]) -> Result<LaunchedChild, SandboxError> {
        crate::unix::spawn(&SANDBOX_EXEC.into(), &args(spec, argv), spec)
    }
    fn wait(&self, child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError> {
        crate::unix::wait(child)
    }
    fn signal(&self, child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError> {
        crate::unix::signal(child, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use warden_core::{HostRule, NetworkSpec};

    fn spec(dir: &Path) -> SandboxSpec {
        SandboxSpec {
            workspace: dir.join("ws"),
            read_only: vec![],
            read_write: vec![dir.join("ws")],
            deny_read: vec![dir.join("secret")],
            network: NetworkSpec {
                allow_hosts: vec![HostRule {
                    host: "x".into(),
                    port: 443,
                }],
                proxy: ProxyHandle::Tcp("127.0.0.1:4321".parse().unwrap()),
                allow_local_binding: false,
            },
            env: BTreeMap::new(),
            cwd: dir.join("ws"),
        }
    }

    #[test]
    fn profile_has_expected_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ws/.git/hooks")).unwrap();
        let (p, params) = profile(&spec(dir.path()));
        assert!(p.starts_with(";"));
        assert!(p.contains("(deny default)"));
        assert!(p.contains("(allow file-read*)"));
        assert!(p.contains("(require-not (subpath (param \"WRITABLE_0_GIT\")))"));
        assert!(p.contains("(require-not (literal (param \"WRITABLE_0_GITDIR\")))"));
        assert!(p.contains("(deny file-read* file-write* (subpath (param \"DENY_0\"))"));
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:4321\"))"));
        assert!(
            !p.contains("(allow network-outbound)"),
            "no blanket network allow"
        );
        assert_eq!(
            params
                .iter()
                .filter(|(k, _)| k.starts_with("WRITABLE_0"))
                .count(),
            4
        );
    }

    #[test]
    fn git_file_literal_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        std::fs::write(dir.path().join("ws/.git"), "gitdir: /elsewhere\n").unwrap();
        let (p, params) = profile(&spec(dir.path()));
        assert!(p.contains("(require-not (literal (param \"WRITABLE_0_GITDIR\")))"));
        assert!(!p.contains("WRITABLE_0_GIT\""));
        assert!(params.iter().any(|(k, _)| k == "WRITABLE_0_GITDIR"));
    }

    /// Runs the real sandbox: reads outside are fine, the denied dir is not, writes
    /// outside the workspace fail, and a direct TCP connect is refused.
    #[test]
    fn sandbox_exec_enforces() {
        if !Path::new(SANDBOX_EXEC).exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(dir.path().join("secret")).unwrap();
        std::fs::write(dir.path().join("secret/key"), "k").unwrap();
        let mut s = spec(dir.path());
        s.env.insert("PATH".into(), "/usr/bin:/bin".into());
        let script = format!(
            "cat {secret} >/dev/null 2>&1 && echo READ_SECRET_OK || echo READ_SECRET_DENIED; \
             echo x > {ws}/f 2>/dev/null && echo WRITE_WS_OK || echo WRITE_WS_DENIED; \
             echo x > {outside} 2>/dev/null && echo WRITE_OUT_OK || echo WRITE_OUT_DENIED; \
             cat /etc/hosts >/dev/null 2>&1 && echo READ_ETC_OK || echo READ_ETC_DENIED; \
             nc -z -w 1 1.1.1.1 443 >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED",
            secret = dir.path().join("secret/key").display(),
            ws = ws.display(),
            outside = dir.path().join("outside.txt").display(),
        );
        let out = std::process::Command::new(SANDBOX_EXEC)
            .args(args(&s, &["/bin/sh".into(), "-c".into(), script.into()]))
            .env_clear()
            .envs(&s.env)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("READ_SECRET_DENIED"),
            "{text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(text.contains("WRITE_WS_OK"), "{text}");
        assert!(text.contains("WRITE_OUT_DENIED"), "{text}");
        assert!(text.contains("READ_ETC_OK"), "{text}");
        assert!(text.contains("NET_DENIED"), "{text}");
    }
}
