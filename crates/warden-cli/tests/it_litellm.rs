//! `warden` against a real OSS LiteLLM proxy (see `tests/it/litellm/`): the mint server
//! mints a key, a sandboxed harness completes through it, and the key is dead after exit.
//!
//! Opt in with `WARDEN_IT_LITELLM_URL` and `WARDEN_IT_LITELLM_MASTER_KEY`. Without
//! them the test is skipped so `cargo test` stays hermetic, unless `WARDEN_IT_REQUIRED`
//! is set (CI): then a missing variable is a failure.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

/// Prints the key, then one completion made through the sandbox's proxy with it. Plain
/// HTTP on purpose: uvicorn 404s the absolute-form target unless the proxy rewrites it.
const HARNESS: &str = r#"echo "$LITELLM_API_KEY"; exec curl -sS "$LITELLM_BASE_URL/v1/chat/completions" -H "Authorization: Bearer $LITELLM_API_KEY" -H "Content-Type: application/json" -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}'"#;

struct Fixture {
    root: tempfile::TempDir,
    config: std::path::PathBuf,
    data: std::path::PathBuf,
}

fn fixture(litellm_url: &str, mint_port: u16) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir_all(config.join("adapters")).unwrap();
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let key = warden_policy::sign::keygen();
    std::fs::write(
        config.join("trusted-keys"),
        warden_policy::key_to_string(&key.verifying_key()),
    )
    .unwrap();
    let mut bundle: Value =
        serde_json::from_str(include_str!("../../../examples/policy.bundle")).unwrap();
    bundle["defaults"]["allow_dev_identity"] = json!(true);
    bundle["defaults"]["credential_ttl"] = json!(3600);
    bundle["catalog"]["harnesses"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["catalog"]["harness_sets"]["approved"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["providers"] = json!([{
        "kind": "litellm", "id": "gw",
        "base_url": litellm_url,
        "mint_url": format!("http://127.0.0.1:{mint_port}")
    }]);
    let bundle_path = config.join("policy.bundle");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    warden_policy::sign::sign_file(&bundle_path, &key).unwrap();
    std::fs::write(
        config.join("adapters/probe.toml"),
        format!(
            "[harness]\nid = \"probe\"\nname = \"probe\"\nexecutable = \"sh\"\n[detect]\ncandidates = [\"/bin/sh\"]\n[inject.litellm]\nbase_url_env = \"LITELLM_BASE_URL\"\nkey_env = \"LITELLM_API_KEY\"\nmodel_args = [\"-c\", '''{}''', \"sh\"]\n",
            HARNESS.replace('$', "$$")
        ),
    )
    .unwrap();
    Fixture { root, config, data }
}

fn warden(f: &Fixture) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_warden"));
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", f.root.path())
        .env("WARDEN_CONFIG", &f.config)
        .env("WARDEN_TRUSTED_KEYS", f.config.join("trusted-keys"))
        .env("WARDEN_DATA", &f.data)
        .env("WARDEN_AUDIT", "none");
    c
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_mint(f: &Fixture, litellm_url: &str, master: &str, port: u16) -> Server {
    let child = warden(f)
        .env("LITELLM_MASTER_KEY", master)
        .args([
            "mint-serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--litellm-url",
            litellm_url,
            "--allow-dev-identity",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let up = (0..100).any(|_| {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() || {
            std::thread::sleep(Duration::from_millis(50));
            false
        }
    });
    assert!(up, "mint-serve did not start listening on port {port}");
    Server(child)
}

fn complete(litellm_url: &str, key: &str) -> reqwest::blocking::Response {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{litellm_url}/v1/chat/completions"))
        .bearer_auth(key)
        .json(&json!({"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .unwrap()
}

#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn real_litellm_mint_run_revoke() {
    let (Ok(url), Ok(master)) = (
        std::env::var("WARDEN_IT_LITELLM_URL"),
        std::env::var("WARDEN_IT_LITELLM_MASTER_KEY"),
    ) else {
        assert!(
            std::env::var_os("WARDEN_IT_REQUIRED").is_none(),
            "WARDEN_IT_REQUIRED is set but WARDEN_IT_LITELLM_URL / WARDEN_IT_LITELLM_MASTER_KEY are not both set"
        );
        eprintln!("WARDEN_IT_LITELLM_URL / WARDEN_IT_LITELLM_MASTER_KEY not set; skipping");
        return;
    };
    let url = url.trim_end_matches('/');
    let mint_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let f = fixture(url, mint_port);
    let _server = start_mint(&f, url, &master, mint_port);
    let ws = f.root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();

    let out = warden(&f)
        .current_dir(&ws)
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"it-alice","groups":["engineering"]}"#,
        )
        .args(["run", "probe"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (key, completion) = stdout.split_once('\n').expect(&stdout);
    assert!(key.starts_with("sk-"), "{stdout}");
    let completion: Value = serde_json::from_str(completion).expect(&stdout);
    assert_eq!(
        completion["choices"][0]["message"]["content"], "hello from mock",
        "{completion}"
    );

    // LiteLLM keeps the record of a deleted key, so the scoping is still visible.
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let info: Value = client
        .get(format!("{url}/key/info"))
        .query(&[("key", key)])
        .bearer_auth(&master)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let info = &info["info"];
    assert!(
        info["key_alias"]
            .as_str()
            .unwrap()
            .starts_with("warden/it-alice/probe/"),
        "{info}"
    );
    assert_eq!(info["user_id"], "it-alice");
    assert_eq!(info["models"], json!(["claude-sonnet-5", "gpt-6-luna"])); // standard tier only
    assert_eq!(info["metadata"]["issued_by"], "warden");
    assert_eq!(info["metadata"]["harness"], "probe");
    assert_eq!(info["status"], "deleted", "{info}");

    assert_eq!(
        complete(url, key).status().as_u16(),
        401,
        "the key must be dead after the harness exits"
    );

    // The revoke endpoint refuses keys warden did not issue.
    let foreign: Value = client
        .post(format!("{url}/key/generate"))
        .bearer_auth(&master)
        .json(&json!({"models": ["claude-sonnet-5"], "duration": "300s"}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let foreign = foreign["key"].as_str().unwrap();
    let resp = client
        .post(format!("http://127.0.0.1:{mint_port}/v1/revoke"))
        .bearer_auth(foreign)
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(complete(url, foreign).status().as_u16(), 200);
}
