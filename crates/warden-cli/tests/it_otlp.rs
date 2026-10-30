//! OTLP audit exporter against a real OpenTelemetry Collector (config in
//! `tests/it/otlp/collector.yaml`). One `warden run probe` must ship the launch
//! events as log records; an unreachable collector must not hold the launch up.
//!
//! Opt in with `WARDEN_IT_OTLP_ENDPOINT` (e.g. http://127.0.0.1:14318/v1/logs) and
//! `WARDEN_IT_OTLP_FILE` (the collector's output file as seen by the host).
//! Without them the test is skipped so `cargo test` stays hermetic, unless
//! `WARDEN_IT_REQUIRED` is set (CI).

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const KEY: &str = "sk-it-otlp-secret";
// The collector's bearertokenauth extension accepts only this header.
const AUTH: &str = "Bearer wit-otlp-token";

fn fixture(root: &Path, endpoint: &str) -> (std::path::PathBuf, std::path::PathBuf) {
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
    bundle["defaults"]["audit"] =
        serde_json::json!({ "otlp_endpoint": endpoint, "headers": { "authorization": AUTH } });
    bundle["catalog"]["harnesses"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["catalog"]["harness_sets"]["approved"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
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

/// One `warden run probe` with the bundle's own audit sink (no `--audit`).
fn launch(root: &Path, endpoint: &str) -> Duration {
    let (config, data) = fixture(root, endpoint);
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let start = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .current_dir(&ws)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("WARDEN_CONFIG", &config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", &data)
        .env("WARDEN_STATIC_KEY_GW", KEY)
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"tester","groups":["engineering"]}"#,
        )
        .args(["run", "probe", "--"])
        .arg(home.join("nope"))
        .arg(ws.join("written.txt"))
        .arg("127.0.0.1:1")
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    assert!(
        out.status.success(),
        "run failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    elapsed
}

fn attr<'a>(attrs: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    attrs
        .as_array()?
        .iter()
        .find(|a| a["key"] == key)?
        .pointer("/value/stringValue")?
        .as_str()
}

/// Every log record in the collector's JSON-lines file, with its resource.
fn records(file: &str) -> Vec<(serde_json::Value, serde_json::Value)> {
    let mut out = vec![];
    for line in file.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        for rl in v["resourceLogs"].as_array().into_iter().flatten() {
            for sl in rl["scopeLogs"].as_array().into_iter().flatten() {
                for r in sl["logRecords"].as_array().into_iter().flatten() {
                    out.push((rl["resource"].clone(), r.clone()));
                }
            }
        }
    }
    out
}

#[test]
fn exports_audit_events_to_collector() {
    let (Ok(endpoint), Ok(file)) = (
        std::env::var("WARDEN_IT_OTLP_ENDPOINT"),
        std::env::var("WARDEN_IT_OTLP_FILE"),
    ) else {
        assert!(
            std::env::var_os("WARDEN_IT_REQUIRED").is_none(),
            "WARDEN_IT_REQUIRED is set but WARDEN_IT_OTLP_ENDPOINT / WARDEN_IT_OTLP_FILE are not both set"
        );
        eprintln!("WARDEN_IT_OTLP_ENDPOINT / WARDEN_IT_OTLP_FILE not set; skipping");
        return;
    };
    let names = [
        "policy.loaded",
        "policy.decision",
        "credential.issued",
        "harness.launch",
        "credential.revoked",
        "harness.exit",
    ];

    // The file outlives runs; only look at what this launch appends.
    let before = std::fs::metadata(&file)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let root = tempfile::tempdir().unwrap();
    launch(root.path(), &endpoint);

    // The exit-time flush is synchronous, but the collector's file exporter buffers briefly.
    let deadline = Instant::now() + Duration::from_secs(20);
    let (text, recs) = loop {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_default()
            .split_off(before);
        let recs = records(&text);
        let have = |n: &str| recs.iter().any(|(_, r)| r["eventName"] == n);
        if names.iter().all(|n| have(n)) || Instant::now() > deadline {
            break (text, recs);
        }
        std::thread::sleep(Duration::from_millis(250));
    };

    for n in names {
        let (res, rec) = recs
            .iter()
            .find(|(_, r)| r["eventName"] == n)
            .unwrap_or_else(|| panic!("{n} never reached the collector:\n{text}"));
        assert_eq!(rec["body"]["stringValue"], n, "{rec}");
        assert_eq!(rec["severityText"], "INFO", "{rec}");
        assert_eq!(attr(&res["attributes"], "service.name"), Some("warden"));
        assert_eq!(
            attr(&res["attributes"], "service.version"),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }
    let find = |n: &str| &recs.iter().find(|(_, r)| r["eventName"] == n).unwrap().1["attributes"];
    assert!(attr(find("policy.loaded"), "version").is_some());
    assert_eq!(attr(find("policy.decision"), "allowed"), Some("true"));
    assert_eq!(attr(find("policy.decision"), "harness"), Some("probe"));
    assert_eq!(attr(find("credential.issued"), "provider"), Some("gw"));
    assert_eq!(attr(find("harness.launch"), "harness"), Some("probe"));
    assert_eq!(attr(find("credential.revoked"), "provider"), Some("gw"));
    assert_eq!(attr(find("harness.exit"), "code"), Some("0"));

    assert!(!text.contains(KEY), "credential leaked into exported audit");
}

#[test]
fn unreachable_collector_does_not_block_launch() {
    if std::env::var("WARDEN_IT_OTLP_ENDPOINT").is_err() {
        assert!(
            std::env::var_os("WARDEN_IT_REQUIRED").is_none(),
            "WARDEN_IT_REQUIRED is set but WARDEN_IT_OTLP_ENDPOINT is not"
        );
        eprintln!("WARDEN_IT_OTLP_ENDPOINT not set; skipping");
        return;
    }
    // Closed port, and a listener that accepts but never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_url = format!("http://{}/v1/logs", silent.local_addr().unwrap());
    for endpoint in ["http://127.0.0.1:1/v1/logs", silent_url.as_str()] {
        let root = tempfile::tempdir().unwrap();
        let took = launch(root.path(), endpoint);
        eprintln!("launch against {endpoint} took {took:?}");
        assert!(took < Duration::from_secs(10), "launch took {took:?}");
    }
}
