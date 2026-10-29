//! Linux backend: bubblewrap for mounts, namespaces and loopback, then a
//! re-exec'd helper (`warden __linux-sandbox`) that starts the proxy bridge,
//! applies seccomp and execs the harness. Layout follows
//! openai/codex `codex-rs/linux-sandbox` (see THIRD_PARTY_NOTICES.md).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use warden_core::{LaunchedChild, ProxyHandle, Sandbox, SandboxError, SandboxSpec, Signal};

pub const HELPER_SUBCOMMAND: &str = "__linux-sandbox";

#[derive(Default)]
pub struct LinuxSandbox {
    /// Path to `bwrap`; `None` searches PATH.
    pub bwrap: Option<PathBuf>,
}

fn find_bwrap(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.is_file().then(|| p.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("bwrap"))
            .find(|p| p.is_file())
    })
}

fn user_namespaces_available() -> bool {
    // Debian/Ubuntu knob; absent means unrestricted on most kernels.
    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(v) => v.trim() != "0",
        Err(_) => true,
    }
}

/// bwrap argv (without the bwrap binary itself), ending in `-- <self> __linux-sandbox ... -- argv`.
pub fn bwrap_args(spec: &SandboxSpec, self_exe: &Path, argv: &[OsString]) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        "--new-session".into(),
        "--die-with-parent".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-net".into(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
    ];
    for rw in &spec.read_write {
        a.extend(["--bind".into(), rw.clone().into(), rw.clone().into()]);
        let git = rw.join(".git");
        if git.is_dir() {
            for sub in ["hooks", "config"] {
                let p = git.join(sub);
                if p.exists() {
                    a.extend(["--ro-bind".into(), p.clone().into(), p.into()]);
                }
            }
        }
    }
    for d in &spec.deny_read {
        if d.is_dir() {
            a.extend(["--tmpfs".into(), d.clone().into()]);
        } else if d.is_file() {
            a.extend(["--ro-bind".into(), "/dev/null".into(), d.clone().into()]);
        }
    }
    let mut helper: Vec<OsString> = vec![self_exe.into(), HELPER_SUBCOMMAND.into()];
    if let ProxyHandle::Unix { path, port } = &spec.network.proxy {
        a.extend(["--bind".into(), path.clone().into(), path.clone().into()]);
        helper.extend([
            "--proxy-uds".into(),
            path.clone().into(),
            "--proxy-port".into(),
            port.to_string().into(),
        ]);
    }
    if let Some(cred) = spec.env.get(crate::credsock::ENV) {
        a.extend(["--bind".into(), cred.into(), cred.into()]);
    }
    a.extend(["--chdir".into(), spec.cwd.clone().into(), "--".into()]);
    a.extend(helper);
    a.push("--".into());
    a.extend(argv.iter().cloned());
    a
}

impl Sandbox for LinuxSandbox {
    fn name(&self) -> &str {
        "bwrap+landlock+seccomp"
    }
    fn preflight(&self, spec: &SandboxSpec) -> Result<(), SandboxError> {
        if find_bwrap(self.bwrap.as_deref()).is_none() {
            return Err(SandboxError::Preflight(
                "bubblewrap (`bwrap`) not found; install it (apt install bubblewrap)".into(),
            ));
        }
        if !user_namespaces_available() {
            return Err(SandboxError::Preflight(
                "unprivileged user namespaces are disabled; the sandbox cannot isolate the network (see docs/THREAT_MODEL.md, C1)".into(),
            ));
        }
        if !matches!(spec.network.proxy, ProxyHandle::Unix { .. }) {
            return Err(SandboxError::Preflight(
                "linux backend needs a unix-socket proxy listener".into(),
            ));
        }
        Ok(())
    }
    fn spawn(&self, spec: &SandboxSpec, argv: &[OsString]) -> Result<LaunchedChild, SandboxError> {
        let bwrap = find_bwrap(self.bwrap.as_deref())
            .ok_or_else(|| SandboxError::Preflight("bwrap missing".into()))?;
        let self_exe = std::env::current_exe()?;
        crate::unix::spawn(&bwrap.into(), &bwrap_args(spec, &self_exe, argv), spec)
    }
    fn wait(&self, child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError> {
        crate::unix::wait(child)
    }
    fn signal(&self, child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError> {
        crate::unix::signal(child, sig)
    }
}

// ------------------------------------------------------------------ helper (runs inside bwrap)

/// `warden __linux-sandbox [--proxy-uds P --proxy-port N] -- argv...`
pub fn run_helper(args: &[OsString]) -> ! {
    let mut proxy_uds: Option<PathBuf> = None;
    let mut proxy_port: u16 = 0;
    let mut it = args.iter();
    let mut argv: Vec<OsString> = Vec::new();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--proxy-uds") => proxy_uds = it.next().map(PathBuf::from),
            Some("--proxy-port") => {
                proxy_port = it
                    .next()
                    .and_then(|p| p.to_str()?.parse().ok())
                    .unwrap_or(0)
            }
            Some("--") => {
                argv.extend(it.cloned());
                break;
            }
            _ => die(&format!("unexpected helper arg {a:?}")),
        }
    }
    if argv.is_empty() {
        die("no command");
    }
    if let Some(uds) = proxy_uds {
        // bwrap brings `lo` up in the new namespace before dropping its caps
        std::thread::spawn(move || {
            if let Err(e) = crate::proxy::run_bridge(&uds, proxy_port) {
                eprintln!("warden: proxy bridge failed: {e}");
            }
        });
        wait_for_port(proxy_port);
    }
    if let Err(e) = harden() {
        die(&format!("sandbox hardening failed: {e}"));
    }
    // The bridge lives in this process, so the harness runs as a child instead of
    // replacing us (exec would kill the bridge thread). PDEATHSIG ties its life
    // to ours; bwrap's --die-with-parent ties ours to warden's.
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // SAFETY: the pre_exec hook only calls prctl, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match cmd.status() {
        Ok(status) => std::process::exit(crate::unix::exit_code(status)),
        Err(e) => die(&format!("exec {:?}: {e}", argv[0])),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("warden: {msg}");
    std::process::exit(126)
}

fn wait_for_port(port: u16) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Defence in depth under bwrap: no new privileges, and a seccomp filter that
/// leaves only AF_UNIX and AF_INET-to-loopback sockets usable (the namespace has
/// nothing else anyway) and blocks ptrace/io_uring/process_vm_*.
fn harden() -> std::io::Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    use std::collections::BTreeMap;

    // SAFETY: prctl with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ] {
        rules.insert(nr, vec![]);
    }
    // socket(domain != AF_UNIX && domain != AF_INET && domain != AF_INET6) -> deny
    let not_unix = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::AF_UNIX as u64,
    )
    .map_err(io)?;
    let not_inet = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::AF_INET as u64,
    )
    .map_err(io)?;
    let not_inet6 = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::AF_INET6 as u64,
    )
    .map_err(io)?;
    rules.insert(
        libc::SYS_socket,
        vec![SeccompRule::new(vec![not_unix, not_inet, not_inet6]).map_err(io)?],
    );

    let arch = if cfg!(target_arch = "aarch64") {
        seccompiler::TargetArch::aarch64
    } else {
        seccompiler::TargetArch::x86_64
    };
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(io)?;
    let prog: BpfProgram = filter.try_into().map_err(io)?;
    seccompiler::apply_filter(&prog).map_err(io)
}

fn io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use warden_core::{HostRule, NetworkSpec};

    #[test]
    fn bwrap_args_shape() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
        let spec = SandboxSpec {
            workspace: ws.clone(),
            read_only: vec![],
            read_write: vec![ws.clone()],
            deny_read: vec![dir.path().to_path_buf()],
            network: NetworkSpec {
                allow_hosts: vec![HostRule {
                    host: "x".into(),
                    port: 443,
                }],
                proxy: ProxyHandle::Unix {
                    path: "/tmp/p.sock".into(),
                    port: 3128,
                },
                allow_local_binding: false,
            },
            env: BTreeMap::new(),
            cwd: ws.clone(),
        };
        let a: Vec<String> = bwrap_args(&spec, Path::new("/opt/warden"), &["pi".into()])
            .iter()
            .map(|s| s.to_string_lossy().into())
            .collect();
        assert!(a.contains(&"--unshare-net".to_string()));
        let hooks = ws.join(".git/hooks").display().to_string();
        assert!(a.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == hooks));
        assert!(a.windows(2).any(|w| w[0] == "--tmpfs"));
        let tail: Vec<_> = a.iter().rev().take(7).rev().cloned().collect();
        assert_eq!(
            tail,
            [
                "__linux-sandbox",
                "--proxy-uds",
                "/tmp/p.sock",
                "--proxy-port",
                "3128",
                "--",
                "pi"
            ]
        );
    }
}
