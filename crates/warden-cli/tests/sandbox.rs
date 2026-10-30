//! Integration test: `warden run` must block a read of a denied path, a write
//! outside the workspace and a direct connection to a non-allowlisted host,
//! while an allowlisted host is reachable through the proxy. Uses the binary's
//! hidden `__probe` subcommand as the "harness" via an adapter override.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

fn fixture(root: &Path, allowed_port: u16) -> (std::path::PathBuf, std::path::PathBuf) {
    fixture_with(
        root,
        allowed_port,
        serde_json::json!([{ "kind": "static", "id": "gw", "format": "openai-chat", "base_url": "https://gw.example.com/v1" }]),
    )
}

fn fixture_with(
    root: &Path,
    allowed_port: u16,
    providers: serde_json::Value,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let config = root.join("config");
    std::fs::create_dir_all(config.join("adapters")).unwrap();
    let data = root.join("data");
    std::fs::create_dir_all(&data).unwrap();

    let key = warden_policy::sign::keygen();
    std::fs::write(
        config.join("trusted-keys"),
        warden_policy::key_to_string(&key.verifying_key()),
    )
    .unwrap();

    let mut bundle: serde_json::Value =
        serde_json::from_str(include_str!("../../../examples/policy.bundle")).unwrap();
    bundle["defaults"]["allow_dev_identity"] = serde_json::json!(true);
    for id in ["probe", "shell"] {
        bundle["catalog"]["harnesses"]
            .as_array_mut()
            .unwrap()
            .push(id.into());
        bundle["catalog"]["harness_sets"]["approved"]
            .as_array_mut()
            .unwrap()
            .push(id.into());
    }
    bundle["catalog"]["hosts"]["local"] =
        serde_json::json!({ "host": "127.0.0.1", "port": allowed_port, "purpose": "test" });
    bundle["catalog"]["host_sets"]["registries"]
        .as_array_mut()
        .unwrap()
        .push("local".into());
    bundle["providers"] = providers;
    let bundle_path = config.join("policy.bundle");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    warden_policy::sign::sign_file(&bundle_path, &key).unwrap();

    // The probe adapter: run this very binary with `__probe` prepended.
    std::fs::write(
        config.join("adapters/probe.toml"),
        format!(
            r#"
[harness]
id = "probe"
name = "probe"
executable = "warden-probe-not-on-path"
[detect]
candidates = ['{exe}']
[inject.openai-chat]
base_url_env = "OPENAI_BASE_URL"
key_env = "OPENAI_API_KEY"
model_args = ["__probe"]
"#,
            exe = env!("CARGO_BIN_EXE_warden")
        ),
    )
    .unwrap();
    // A plain shell, so a test can script a harness: `warden run shell -- '<script>'`.
    std::fs::write(
        config.join("adapters/shell.toml"),
        r#"
[harness]
id = "shell"
name = "shell"
executable = "sh"
[detect]
candidates = ['/bin/sh']
[inject.openai-chat]
base_url_env = "OPENAI_BASE_URL"
key_env = "OPENAI_API_KEY"
model_args = ["-c"]
"#,
    )
    .unwrap();
    (config, data)
}

fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn sandbox_blocks_read_write_and_connect() {
    let root = tempfile::tempdir().unwrap();
    let (allowed, allowed_port) = listener();
    let (_other, other_port) = listener();
    std::thread::spawn(move || {
        for s in allowed.incoming().flatten() {
            let mut s = s;
            let mut b = [0u8; 16];
            let _ = s.read(&mut b);
            let _ = s.write_all(b"hello");
        }
    });
    let (config, data) = fixture(root.path(), allowed_port);

    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let home = root.path().join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/id_ed25519"), "secret").unwrap();
    let outside = root.path().join("outside.txt");

    // The static provider reads WARDEN_STATIC_KEY_GW so the test never touches the keychain.
    let run = |extra: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_warden"));
        c.current_dir(&ws)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("WARDEN_CONFIG", &config)
            .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
            .env("WARDEN_DATA", &data)
            .env("WARDEN_AUDIT", "none")
            .env("WARDEN_STATIC_KEY_GW", "sk-test")
            .env(
                "WARDEN_DEV_IDENTITY",
                r#"{"subject":"tester","groups":["engineering"]}"#,
            )
            .args(["run", "probe"])
            .args(extra)
            .arg("--")
            .arg(home.join(".ssh/id_ed25519"))
            .arg(&outside)
            .arg(format!("127.0.0.1:{other_port}"));
        let out = c.output().unwrap();
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status,
        )
    };

    let (stdout, stderr, status) = run(&["--dry-run"]);
    assert!(status.success(), "dry run failed: {stderr}");
    assert!(
        stdout.contains("OPENAI_BASE_URL=https://gw.example.com/v1"),
        "{stdout}"
    );
    assert!(stdout.contains("OPENAI_API_KEY=<secret>"), "{stdout}");
    assert!(
        !stdout.contains("sk-test"),
        "secret leaked into dry-run output"
    );

    let (stdout, stderr, status) = run(&[]);
    assert!(
        status.success(),
        "run failed ({status}): {stderr}\n{stdout}"
    );
    assert!(stdout.contains("read=denied"), "{stdout}\n{stderr}");
    assert!(stdout.contains("write=denied"), "{stdout}\n{stderr}");
    assert!(stdout.contains("direct=denied"), "{stdout}\n{stderr}");
    // the allowlisted port is reachable only through the proxy
    assert!(
        stderr.contains(&format!(
            "blocked connection from probe to 127.0.0.1:{other_port}"
        )),
        "{stdout}\n{stderr}"
    );

    // same probe against the allowlisted port via the proxy succeeds
    let mut c = Command::new(env!("CARGO_BIN_EXE_warden"));
    let out = c
        .current_dir(&ws)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("WARDEN_CONFIG", &config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", &data)
        .env("WARDEN_AUDIT", "none")
        .env("WARDEN_STATIC_KEY_GW", "sk-test")
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"tester","groups":["engineering"]}"#,
        )
        .args(["run", "probe", "--"])
        .arg(ws.join("readable.txt"))
        .arg(ws.join("written.txt"))
        .arg(format!("127.0.0.1:{allowed_port}"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("write=ok"), "{stdout}");
    assert!(
        stdout.contains("proxy=ok"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ws.join("written.txt").exists());
}

#[test]
#[cfg(unix)] // signals; Windows has none to forward
fn sigterm_reaches_harness_handler() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let root = tempfile::tempdir().unwrap();
    let (config, data) = fixture(root.path(), 1);
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let mut warden = Command::new(env!("CARGO_BIN_EXE_warden"))
        .current_dir(&ws)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root.path())
        .env("WARDEN_CONFIG", &config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", &data)
        .env("WARDEN_AUDIT", "none")
        .env("WARDEN_STATIC_KEY_GW", "sk-test")
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"tester","groups":["engineering"]}"#,
        )
        .args(["run", "shell", "--"])
        .arg(r#"trap "echo GOT_TERM; exit 5" TERM; echo started; sleep 30 & wait"#)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(warden.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "started");
    // SAFETY: kill(2) on the child we spawned.
    unsafe { libc::kill(warden.id() as libc::pid_t, libc::SIGTERM) };
    // the orphaned `sleep` keeps the pipe open, so read the one line instead of to EOF
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "GOT_TERM");
    assert_eq!(warden.wait().unwrap().code(), Some(5));
}

#[test]
fn denied_launch_exits_77() {
    let root = tempfile::tempdir().unwrap();
    let (config, data) = fixture(root.path(), 1);
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .current_dir(root.path())
        .env("WARDEN_CONFIG", &config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", &data)
        .env("WARDEN_AUDIT", "none")
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"outsider","groups":["sales"]}"#,
        )
        .args(["run", "probe", "--dry-run", "--", "a", "b", "c"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(77),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no permit policy matched"));
}

#[test]
fn unsigned_bundle_refused() {
    let root = tempfile::tempdir().unwrap();
    let (config, data) = fixture(root.path(), 1);
    std::fs::remove_file(config.join("policy.bundle.sig")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .env("WARDEN_CONFIG", &config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", &data)
        .args(["policy", "show"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(78));
}

/// `warden run <args>` in `cwd` with a cleared env, as the sibling tests do.
fn warden_in(cwd: &Path, home: &Path, config: &Path, data: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_warden"));
    c.current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("WARDEN_CONFIG", config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", data)
        .env("WARDEN_AUDIT", "none")
        .env("WARDEN_STATIC_KEY_GW", "sk-test")
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"tester","groups":["engineering"]}"#,
        )
        .arg("run")
        .args(args);
    c
}

#[test]
fn workspace_containing_warden_dirs_refused() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let (config, data) = fixture(root.path(), 1);
    let sibling = root.path().join("ws");
    std::fs::create_dir_all(&sibling).unwrap();
    // (cwd, data dir): the parent of the config dir; the data dir itself
    for (cwd, data_dir) in [
        (root.path().to_path_buf(), elsewhere.path().to_path_buf()),
        (data.clone(), data.clone()),
    ] {
        let out = warden_in(
            &cwd,
            root.path(),
            &config,
            &data_dir,
            &["probe", "--dry-run"],
        )
        .output()
        .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(77), "{}: {stderr}", cwd.display());
        let named = format!(
            "writable root {} contains",
            cwd.canonicalize().unwrap().display()
        );
        assert!(stderr.contains(&named), "{stderr}");
        assert!(
            stderr.contains("run warden from a project directory"),
            "{stderr}"
        );
    }
    // control: a sibling of the config and data dirs is fine
    let out = warden_in(
        &sibling,
        root.path(),
        &config,
        &data,
        &["probe", "--dry-run"],
    )
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn workspace_containing_trusted_keys_or_bundle_refused() {
    let root = tempfile::tempdir().unwrap();
    let (config, data) = fixture(root.path(), 1);
    let keys = root.path().join("keys");
    let pol = root.path().join("pol");
    for d in [&keys, &pol] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::copy(config.join("trusted-keys"), keys.join("trusted-keys")).unwrap();
    for f in ["policy.bundle", "policy.bundle.sig"] {
        std::fs::copy(config.join(f), pol.join(f)).unwrap();
    }
    for (cwd, flag, file) in [
        (&keys, "--trusted-keys", keys.join("trusted-keys")),
        (&pol, "--policy", pol.join("policy.bundle")),
    ] {
        let mut c = warden_in(cwd, root.path(), &config, &data, &[]);
        let out = c
            .arg(flag)
            .arg(&file)
            .args(["probe", "--dry-run"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(77), "{flag}: {stderr}");
        assert!(stderr.contains(&file.display().to_string()), "{stderr}");
    }
}

/// A refused launch must not leave the LiteLLM key it already minted alive.
#[test]
fn refused_launch_revokes_credential() {
    use std::sync::{Arc, Mutex};
    let (gateway, gateway_port) = listener();
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = requests.clone();
    std::thread::spawn(move || {
        for mut s in gateway.incoming().flatten() {
            let mut buf = Vec::new();
            let mut b = [0u8; 1024];
            // headers, then the body the request line promises
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&b[..n]),
                }
            }
            let text = String::from_utf8_lossy(&buf).into_owned();
            let head_end = text.find("\r\n\r\n").map_or(text.len(), |i| i + 4);
            let want = text
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")?
                        .trim()
                        .parse()
                        .ok()
                })
                .unwrap_or(0usize);
            let mut have = buf.len() - head_end.min(buf.len());
            while have < want {
                match s.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => have += n,
                }
            }
            seen.lock()
                .unwrap()
                .push(text.lines().next().unwrap_or("").to_string());
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"key\":\"sk-x\"}\n",
            );
        }
    });
    let root = tempfile::tempdir().unwrap();
    let (config, data) = fixture_with(
        root.path(),
        1,
        serde_json::json!([{ "kind": "litellm", "id": "gw", "base_url": format!("http://127.0.0.1:{gateway_port}") }]),
    );
    let out = warden_in(root.path(), root.path(), &config, &data, &["probe"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(77), "{stderr}");
    assert!(
        stderr.contains("run warden from a project directory"),
        "{stderr}"
    );
    let seen = requests.lock().unwrap();
    assert!(
        seen.iter().any(|r| r.starts_with("POST /key/generate")),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|r| r.starts_with("POST /key/delete")),
        "{seen:?}"
    );
}

/// `git init`ed workspace (or None when git is unavailable) and the shell run in it.
fn git_workspace(root: &Path) -> Option<std::path::PathBuf> {
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    match Command::new("git").arg("init").arg("-q").arg(&ws).status() {
        Ok(s) if s.success() => Some(ws),
        _ => {
            eprintln!("skipping: git not available");
            None
        }
    }
}

/// Runs `script` as the harness in `ws`; returns (stdout, stdout + stderr).
fn run_script(root: &Path, ws: &Path, script: &str) -> (String, String) {
    let (config, data) = (root.join("config"), root.join("data"));
    let out = warden_in(ws, root, &config, &data, &["shell", "--", script])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let msg = format!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    (stdout, msg)
}

#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn git_dir_cannot_be_swapped() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), 1);
    let Some(ws) = git_workspace(root.path()) else {
        return;
    };
    let script = r#"
if mv .git .git.old 2>/dev/null; then echo rename=ok; else echo rename=denied; fi
if echo x > .git/warden-probe; then echo write=ok; else echo write=denied; fi
if git -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m x; then echo commit=ok; else echo commit=failed; fi
rm -rf .git 2>/dev/null
mkdir .git 2>/dev/null
mkdir -p .git/hooks 2>/dev/null
echo '#!/bin/sh' > .git/hooks/pre-commit 2>/dev/null
"#;
    let (stdout, msg) = run_script(root.path(), &ws, script);
    assert!(stdout.contains("rename=denied"), "{msg}");
    assert!(stdout.contains("write=ok"), "{msg}");
    assert!(stdout.contains("commit=ok"), "{msg}");
    // `rm -rf .git` could not remove the entry itself, nor the protected parts inside
    assert!(ws.join(".git/hooks").is_dir(), "{msg}");
    assert!(ws.join(".git/config").is_file(), "{msg}");
    assert!(!ws.join(".git/hooks/pre-commit").exists(), "{msg}");
    assert!(!ws.join(".git.old").exists(), "{msg}");
}

/// The hooks dir does not exist at launch; the harness must still not get to create it.
#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn missing_git_hooks_cannot_be_created() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), 1);
    let Some(ws) = git_workspace(root.path()) else {
        return;
    };
    std::fs::remove_dir_all(ws.join(".git/hooks")).unwrap();
    let script = r#"
mkdir -p .git/hooks 2>/dev/null
if echo '#!/bin/sh' > .git/hooks/pre-commit 2>/dev/null; then echo hook=ok; else echo hook=denied; fi
"#;
    let (stdout, msg) = run_script(root.path(), &ws, script);
    assert!(stdout.contains("hook=denied"), "{msg}");
    assert!(!ws.join(".git/hooks/pre-commit").exists(), "{msg}");
}

/// A worktree's `.git` is a `gitdir:` file; repointing it must fail.
#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn git_file_cannot_be_rewritten() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), 1);
    let main = root.path().join("main");
    let ws = root.path().join("ws");
    let git = |dir: &Path, args: &[&str]| {
        Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    std::fs::create_dir_all(&main).unwrap();
    if !(git(&main, &["init", "-q"])
        && git(&main, &["commit", "-q", "--allow-empty", "-m", "x"])
        && git(&main, &["worktree", "add", "-q", ws.to_str().unwrap()]))
    {
        eprintln!("skipping: git worktree not available");
        return;
    }
    assert!(ws.join(".git").is_file());
    let before = std::fs::read_to_string(ws.join(".git")).unwrap();
    let script = r#"
if echo 'gitdir: ./fake' > .git 2>/dev/null; then echo write=ok; else echo write=denied; fi
if rm -f .git 2>/dev/null; then echo rm=ok; else echo rm=denied; fi
if mv .git .git.old 2>/dev/null; then echo rename=ok; else echo rename=denied; fi
"#;
    let (stdout, msg) = run_script(root.path(), &ws, script);
    for step in ["write=denied", "rm=denied", "rename=denied"] {
        assert!(stdout.contains(step), "{msg}");
    }
    assert_eq!(std::fs::read_to_string(ws.join(".git")).unwrap(), before);
}
