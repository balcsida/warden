//! Integration test: `warden run` must block a read of a denied path, a write
//! outside the workspace and a direct connection to a non-allowlisted host,
//! while an allowlisted host is reachable through the proxy. Uses the binary's
//! hidden `__probe` subcommand as the "harness" via an adapter override.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

fn fixture(root: &Path, allowed_port: u16) -> (std::path::PathBuf, std::path::PathBuf) {
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
    bundle["catalog"]["harnesses"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["catalog"]["harness_sets"]["approved"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["catalog"]["hosts"]["local"] =
        serde_json::json!({ "host": "127.0.0.1", "port": allowed_port, "purpose": "test" });
    bundle["catalog"]["host_sets"]["registries"]
        .as_array_mut()
        .unwrap()
        .push("local".into());
    bundle["providers"] = serde_json::json!([{ "kind": "static", "id": "gw", "format": "openai-chat", "base_url": "https://gw.example.com/v1" }]);
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
    assert!(status.success(), "run failed: {stderr}\n{stdout}");
    assert!(stdout.contains("read=denied"), "{stdout}\n{stderr}");
    assert!(stdout.contains("write=denied"), "{stdout}\n{stderr}");
    assert!(stdout.contains("direct=denied"), "{stdout}\n{stderr}");
    // the allowlisted port is reachable only through the proxy
    assert!(
        stderr.contains(&format!(
            "blocked connection from probe to 127.0.0.1:{other_port}"
        )),
        "{stderr}"
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
