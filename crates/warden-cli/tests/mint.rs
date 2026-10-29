//! `warden mint-serve` end to end: the client sends its identity token to the mint
//! server, the server re-checks policy and calls LiteLLM `/key/generate` with the
//! master key, and the client launches with the returned key. Policy denials and
//! bad tokens are refused server side.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MASTER: &str = "sk-master-0000";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Records every /key/generate call: (authorization header, body).
type Calls = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

fn mock_litellm() -> (u16, Calls) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let seen: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::default();
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for mut r in server.incoming_requests() {
            let auth = r
                .headers()
                .iter()
                .find(|h| h.field.equiv("authorization"))
                .map(|h| h.value.to_string())
                .unwrap_or_default();
            let mut body = String::new();
            let _ = r.as_reader().read_to_string(&mut body);
            let path = r.url().to_string();
            if path == "/key/generate" {
                s2.lock()
                    .unwrap()
                    .push((auth, serde_json::from_str(&body).unwrap_or_default()));
                let _ = r.respond(tiny_http::Response::from_string(
                    r#"{"key":"sk-virtual-1","expires":"2030-01-01T00:00:00Z"}"#,
                ));
            } else {
                let _ = r.respond(tiny_http::Response::from_string("{}"));
            }
        }
    });
    (port, seen)
}

struct Fixture {
    root: tempfile::TempDir,
    config: std::path::PathBuf,
    data: std::path::PathBuf,
}

fn fixture(litellm_port: u16, mint_port: u16) -> Fixture {
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
    let mut bundle: serde_json::Value =
        serde_json::from_str(include_str!("../../../examples/policy.bundle")).unwrap();
    bundle["defaults"]["allow_dev_identity"] = serde_json::json!(true);
    bundle["defaults"]["credential_ttl"] = serde_json::json!(3600);
    bundle["catalog"]["harnesses"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["catalog"]["harness_sets"]["approved"]
        .as_array_mut()
        .unwrap()
        .push("probe".into());
    bundle["providers"] = serde_json::json!([{
        "kind": "litellm", "id": "gw",
        "base_url": format!("http://127.0.0.1:{litellm_port}"),
        "mint_url": format!("http://127.0.0.1:{mint_port}")
    }]);
    let bundle_path = config.join("policy.bundle");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    warden_policy::sign::sign_file(&bundle_path, &key).unwrap();
    std::fs::write(
        config.join("adapters/probe.toml"),
        format!(
            "[harness]\nid = \"probe\"\nname = \"probe\"\nexecutable = \"nope\"\n[detect]\ncandidates = [\"{}\"]\n[inject.litellm]\nbase_url_env = \"LITELLM_BASE_URL\"\nkey_env = \"LITELLM_API_KEY\"\nmodel_args = [\"__probe\"]\n",
            env!("CARGO_BIN_EXE_warden")
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

fn start_mint(f: &Fixture, litellm_port: u16, mint_port: u16) -> Server {
    let child = warden(f)
        .env("LITELLM_MASTER_KEY", MASTER)
        .args([
            "mint-serve",
            "--listen",
            &format!("127.0.0.1:{mint_port}"),
            "--litellm-url",
            &format!("http://127.0.0.1:{litellm_port}"),
            "--team",
            "engineering=team-eng",
            "--allow-dev-identity",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", mint_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Server(child)
}

#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn mint_serve_issues_scoped_keys() {
    let (litellm_port, seen) = mock_litellm();
    let mint_port = free_port();
    let f = fixture(litellm_port, mint_port);
    let _server = start_mint(&f, litellm_port, mint_port);
    let ws = f.root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();

    // engineering user: launch allowed, standard models only, team mapped
    let out = warden(&f)
        .current_dir(&ws)
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"alice","groups":["engineering"]}"#,
        )
        .args(["run", "probe", "--", "x", "y", "127.0.0.1:9"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let (auth, body) = &calls[0];
    assert_eq!(
        auth,
        &format!("Bearer {MASTER}"),
        "mint server must use the master key"
    );
    assert_eq!(body["user_id"], "alice");
    assert_eq!(body["team_id"], "team-eng");
    assert_eq!(body["duration"], "3600s");
    let models: Vec<&str> = body["models"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    assert!(
        models.contains(&"claude-sonnet-5") && !models.contains(&"claude-opus-5-5"),
        "{models:?}"
    );

    // outsider: mint server refuses even if a tampered client asked
    let resp = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{mint_port}/v1/mint"))
        .bearer_auth(r#"dev:{"subject":"mallory","groups":["sales"]}"#)
        .json(&serde_json::json!({"harness": "probe", "models": ["claude-opus-5-5"], "ttl_secs": 999999}))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    // garbage token
    let resp = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{mint_port}/v1/mint"))
        .bearer_auth("not-a-jwt")
        .json(
            &serde_json::json!({"harness": "probe", "models": ["claude-sonnet-5"], "ttl_secs": 60}),
        )
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(seen.lock().unwrap().len(), 1, "no extra keys minted");
}
