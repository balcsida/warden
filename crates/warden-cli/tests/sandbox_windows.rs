//! Windows sandbox (phase A) integration tests: the restricted token limits
//! writes to the writable roots, `.git/hooks` and `.git/config` stay read-only
//! and `.git` cannot be renamed, ACL grants are idempotent and do not follow
//! junctions, the child cannot open warden or another launch for write, and
//! killing warden kills the harness's whole tree.
//! Network egress and deny-read are not enforced on Windows yet, so the bundle
//! sets `sandbox_allow_degraded` and nothing here asserts them.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A policy bundle with two harnesses: `probe` (this binary's `__probe`) and
/// `cmd` (`cmd.exe /c <args>`, for exit codes and process trees).
fn fixture(root: &Path, degraded: bool) -> (PathBuf, PathBuf) {
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
    bundle["defaults"]["sandbox_allow_degraded"] = serde_json::json!(degraded);
    for id in ["probe", "cmd"] {
        bundle["catalog"]["harnesses"]
            .as_array_mut()
            .unwrap()
            .push(id.into());
        bundle["catalog"]["harness_sets"]["approved"]
            .as_array_mut()
            .unwrap()
            .push(id.into());
    }
    bundle["providers"] = serde_json::json!([{ "kind": "static", "id": "gw", "format": "openai-chat", "base_url": "https://gw.example.com/v1" }]);
    let bundle_path = config.join("policy.bundle");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    warden_policy::sign::sign_file(&bundle_path, &key).unwrap();

    let adapter = |id: &str, exe: &str, arg: &str| {
        format!(
            r#"
[harness]
id = "{id}"
name = "{id}"
executable = "{id}-not-on-path"
[detect]
candidates = ['{exe}']
[inject.openai-chat]
base_url_env = "OPENAI_BASE_URL"
key_env = "OPENAI_API_KEY"
model_args = ["{arg}"]
"#
        )
    };
    std::fs::write(
        config.join("adapters/probe.toml"),
        adapter("probe", env!("CARGO_BIN_EXE_warden"), "__probe"),
    )
    .unwrap();
    std::fs::write(
        config.join("adapters/cmd.toml"),
        adapter("cmd", &std::env::var("COMSPEC").unwrap(), "/c"),
    )
    .unwrap();
    (config, data)
}

struct Env {
    _root: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    ws: PathBuf,
    outside: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(degraded: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (config, data) = fixture(root.path(), degraded);
        let ws = root.path().join("ws");
        std::fs::create_dir_all(ws.join(".git").join("hooks")).unwrap();
        std::fs::write(ws.join(".git").join("config"), "[core]\n").unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        Self {
            _root: root,
            config,
            data,
            ws,
            outside,
            home,
        }
    }

    /// `warden run <harness> -- <args>` in the workspace, with a minimal environment.
    fn command(&self, harness: &str, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_warden"));
        c.current_dir(&self.ws).env_clear();
        for k in [
            "SystemRoot",
            "windir",
            "PATH",
            "PATHEXT",
            "COMSPEC",
            "TEMP",
            "TMP",
        ] {
            if let Some(v) = std::env::var_os(k) {
                c.env(k, v);
            }
        }
        c.env("USERPROFILE", &self.home)
            .env("WARDEN_CONFIG", &self.config)
            .env("WARDEN_TRUSTED_KEYS", self.config.join("trusted-keys"))
            .env("WARDEN_DATA", &self.data)
            .env("WARDEN_AUDIT", "none")
            .env("WARDEN_STATIC_KEY_GW", "sk-test")
            .env(
                "WARDEN_DEV_IDENTITY",
                r#"{"subject":"tester","groups":["engineering"]}"#,
            )
            .args(["run", harness, "--"])
            .args(args);
        c
    }

    /// Run the probe with `write` as the file to write; returns (stdout, stderr).
    fn probe_write(&self, write: &Path) -> (String, String) {
        let out = self
            .command(
                "probe",
                &[
                    self.ws.join("missing").to_str().unwrap(),
                    write.to_str().unwrap(),
                    "127.0.0.1:1",
                ],
            )
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

fn icacls(path: &Path) -> String {
    let out = Command::new("icacls").arg(path).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn writes_limited_to_writable_roots_and_git_internals_read_only() {
    let e = Env::new(true);

    let inside = e.ws.join("written.txt");
    let (stdout, stderr) = e.probe_write(&inside);
    assert!(stdout.contains("write=ok"), "{stdout}\n{stderr}");
    assert!(inside.exists());
    assert!(stderr.contains("NOT enforced"), "{stderr}");

    for (target, label) in [
        (e.outside.join("out.txt"), "outside every writable root"),
        (
            e.ws.join(".git").join("hooks").join("pre-commit"),
            ".git/hooks",
        ),
        (e.ws.join(".git").join("config"), ".git/config"),
    ] {
        let (stdout, stderr) = e.probe_write(&target);
        assert!(
            stdout.contains("write=denied"),
            "{label}: {stdout}\n{stderr}"
        );
    }
    assert!(!e.outside.join("out.txt").exists());
    assert!(!e.ws.join(".git").join("hooks").join("pre-commit").exists());
    assert_eq!(
        std::fs::read_to_string(e.ws.join(".git").join("config")).unwrap(),
        "[core]\n"
    );
}

#[test]
fn repeated_launches_leave_acls_unchanged() {
    let e = Env::new(true);
    let hooks = e.ws.join(".git").join("hooks");
    let before = (icacls(&e.ws), icacls(&hooks));

    e.probe_write(&e.ws.join("a.txt"));
    let first = (icacls(&e.ws), icacls(&hooks));
    assert_ne!(before, first, "first launch must grant the capability SID");
    assert!(first.1.contains("(DENY)"), "{}", first.1);

    e.probe_write(&e.ws.join("b.txt"));
    // b.txt itself inherits the grant, so compare the roots only
    assert_eq!(first, (icacls(&e.ws), icacls(&hooks)));
}

#[test]
fn git_dir_cannot_be_renamed_or_replaced_but_stays_writable() {
    let e = Env::new(true);
    let git = e.ws.join(".git");

    // the rename trick: move .git away, copy it back with a planted hook
    let out = e
        .command("cmd", &["ren", ".git", ".git.old"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(git.join("hooks").is_dir());
    assert!(!e.ws.join(".git.old").exists());

    // delete and recreate
    let out = e
        .command("cmd", &["rd", "/s", "/q", ".git"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        std::fs::read_to_string(git.join("config")).unwrap(),
        "[core]\n"
    );

    // objects and refs live under .git and must stay writable
    let probe = git.join("warden-probe");
    let (stdout, stderr) = e.probe_write(&probe);
    assert!(stdout.contains("write=ok"), "{stdout}\n{stderr}");
    assert!(probe.exists());
}

#[test]
fn junction_in_a_new_root_is_not_followed() {
    let e = Env::new(true);
    let target = e.outside.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep.txt"), "keep").unwrap();
    let link = e.ws.join("link");
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let before = (icacls(&target), icacls(&target.join("keep.txt")));

    let (stdout, stderr) = e.probe_write(&link.join("pwned.txt"));
    assert!(stdout.contains("write=denied"), "{stdout}\n{stderr}");
    assert!(!target.join("pwned.txt").exists());
    assert_eq!(before, (icacls(&target), icacls(&target.join("keep.txt"))));
}

/// Probe output lines `open_<right>=ok|denied` as a single string, for `OpenProcess` on `pid`.
fn probe_open(e: &Env, pid: Option<u32>) -> String {
    let missing = e.ws.join("missing");
    let write = e.ws.join("w.txt");
    let pid = pid.map(|p| p.to_string());
    let mut args = vec![
        missing.to_str().unwrap(),
        write.to_str().unwrap(),
        "127.0.0.1:1",
    ];
    args.extend(pid.as_deref());
    let out = e.command("probe", &args).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("open"))
        .collect::<Vec<_>>()
        .join(" ")
}

const ALL_DENIED: &str = "open_vm_write=denied open_create_thread=denied open_dup_handle=denied";

#[test]
fn child_cannot_open_the_warden_process_for_write() {
    let e = Env::new(true);
    assert_eq!(probe_open(&e, None), ALL_DENIED);
}

#[test]
fn child_cannot_open_another_launches_process_for_write() {
    let (a, b) = (Env::new(true), Env::new(true));
    let mut first = a
        .command("cmd", &["ping", "-n", "4218", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_until("the first launch's ping to start", || {
        !ping_pids("4218").is_empty()
    });
    let victim = ping_pids("4218")[0];

    let opened = probe_open(&b, Some(victim));
    first.kill().unwrap();
    first.wait().unwrap();
    assert_eq!(opened, ALL_DENIED);
}

#[test]
fn harness_exit_code_propagates() {
    let e = Env::new(true);
    let out = e.command("cmd", &["exit", "3"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    // exit codes wider than a byte survive
    let out = e.command("cmd", &["exit", "300"]).output().unwrap();
    assert_eq!(out.status.code(), Some(300), "{out:?}");
}

fn ping_pids(marker: &str) -> Vec<u32> {
    let script = format!(
        "Get-CimInstance Win32_Process | Where-Object {{ $_.Name -eq 'ping.exe' -and $_.CommandLine -like '*{marker}*' }} | ForEach-Object {{ $_.ProcessId }}"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn pings(marker: &str) -> usize {
    ping_pids(marker).len()
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn killing_warden_kills_the_whole_process_tree() {
    let e = Env::new(true);
    // warden -> cmd.exe -> ping.exe; 4217 identifies this test's ping
    let mut warden = e
        .command("cmd", &["ping", "-n", "4217", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_until("the grandchild to start", || pings("4217") > 0);

    warden.kill().unwrap();
    warden.wait().unwrap();
    wait_until("the grandchild to die", || pings("4217") == 0);
}

#[test]
fn refuses_without_the_degraded_opt_in() {
    let e = Env::new(false);
    let out = e.command("cmd", &["exit", "0"]).output().unwrap();
    assert_eq!(out.status.code(), Some(69), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("sandbox_allow_degraded"),
        "{out:?}"
    );
}
