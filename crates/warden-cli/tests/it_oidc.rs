//! OIDC against a real IdP (Dex, config in `tests/it/oidc/dex.yaml`): `warden login`
//! (device flow), `warden run` with the stored identity and token refresh,
//! `warden logout`, and `warden mint-serve` verifying a real ID token.
//!
//! Opt in with `WARDEN_IT_OIDC_ISSUER=<dex issuer url>`; the stored tokens go to the
//! OS keyring, so run it where a keyring is unlocked. Without it the tests are
//! skipped so `cargo test` stays hermetic.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;

const CLIENT: &str = "warden-it";
const OTHER_CLIENT: &str = "warden-other";
const MASTER: &str = "sk-master-0000";

fn issuer() -> Option<String> {
    let issuer = std::env::var("WARDEN_IT_OIDC_ISSUER").ok();
    if issuer.is_none() {
        eprintln!("WARDEN_IT_OIDC_ISSUER not set; skipping");
    }
    issuer
}

struct Fixture {
    root: tempfile::TempDir,
    config: std::path::PathBuf,
    data: std::path::PathBuf,
}

/// Signed bundle whose identity is the real issuer and whose launch policy needs
/// the group Dex's mock connector puts in the token.
fn fixture(issuer: &str) -> Fixture {
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
    bundle["identity"] = serde_json::json!({ "issuer": issuer, "client_id": CLIENT });
    bundle["defaults"]["credential_ttl"] = serde_json::json!(3600);
    let launch = bundle["policies"][0]
        .as_str()
        .unwrap()
        .replace("engineering", "authors");
    bundle["policies"][0] = launch.into();
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
    std::fs::write(
        config.join("adapters/probe.toml"),
        format!(
            "[harness]\nid = \"probe\"\nname = \"probe\"\nexecutable = \"nope\"\n[detect]\ncandidates = [\"{}\"]\n[inject.openai-chat]\nbase_url_env = \"OPENAI_BASE_URL\"\nkey_env = \"OPENAI_API_KEY\"\nmodel_args = [\"__probe\"]\n",
            env!("CARGO_BIN_EXE_warden")
        ),
    )
    .unwrap();
    Fixture { root, config, data }
}

/// No `WARDEN_DEV_IDENTITY`: identity comes from the keyring or the IdP.
fn warden(f: &Fixture) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_warden"));
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", f.root.path())
        .env("WARDEN_CONFIG", &f.config)
        .env("WARDEN_TRUSTED_KEYS", f.config.join("trusted-keys"))
        .env("WARDEN_DATA", &f.data)
        .env("WARDEN_AUDIT", "none")
        .env("WARDEN_STATIC_KEY_GW", "sk-test");
    // The keyring's secret service lives on the session bus.
    for var in ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"] {
        if let Ok(v) = std::env::var(var) {
            c.env(var, v);
        }
    }
    c
}

/// Approve a device user code the way a browser would: submit it to the IdP and
/// follow the redirects through the mock connector.
fn approve(issuer: &str, user_code: &str) {
    let resp = reqwest::blocking::Client::new()
        .post(format!("{issuer}/device/auth/verify_code"))
        .form(&[("user_code", user_code)])
        .send()
        .unwrap();
    assert!(resp.status().is_success(), "approve: {}", resp.status());
}

/// Full device flow driven over HTTP; returns the raw ID token.
fn id_token_for(issuer: &str, client_id: &str) -> String {
    let http = reqwest::blocking::Client::new();
    let dev: serde_json::Value = http
        .post(format!("{issuer}/device/code"))
        .form(&[
            ("client_id", client_id),
            ("scope", "openid profile email groups"),
        ])
        .send()
        .unwrap()
        .json()
        .unwrap();
    approve(issuer, dev["user_code"].as_str().unwrap());
    let tok: serde_json::Value = http
        .post(format!("{issuer}/token"))
        .form(&[
            ("client_id", client_id),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", dev["device_code"].as_str().unwrap()),
        ])
        .send()
        .unwrap()
        .json()
        .unwrap();
    tok["id_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{tok}"))
        .to_string()
}

fn subject_of(id_token: &str) -> String {
    let payload = id_token.split('.').nth(1).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    claims["sub"].as_str().unwrap().to_string()
}

fn launch_probe(f: &Fixture) -> std::process::Output {
    let ws = f.root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    warden(f)
        .current_dir(&ws)
        .args(["run", "probe", "--", "x", "y", "127.0.0.1:9"])
        .output()
        .unwrap()
}

#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn login_run_refresh_logout() {
    let Some(issuer) = issuer() else { return };
    let f = fixture(&issuer);

    // a. device flow end to end
    let mut login = warden(&f)
        .arg("login")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(login.stderr.take().unwrap());
    let mut line = String::new();
    let user_code = loop {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "login printed no code"
        );
        if let Some(code) = line.trim().split("enter code: ").nth(1) {
            assert!(line.contains(&issuer), "{line}");
            break code.to_string();
        }
    };
    approve(&issuer, &user_code);
    let mut stdout = String::new();
    login
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).unwrap();
    assert!(login.wait().unwrap().success(), "login failed: {rest}");
    assert!(stdout.contains("groups: authors"), "{stdout}");

    // b + c. Dex's 2 minute ID tokens are inside warden's 5 minute reuse window, so
    // every launch refreshes; three launches also cover refresh-token rotation.
    for n in 1..=3 {
        let out = launch_probe(&f);
        assert!(
            out.status.success(),
            "launch {n}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // e. logout drops the stored entry
    assert!(warden(&f).arg("logout").status().unwrap().success());
    let out = launch_probe(&f);
    assert_eq!(out.status.code(), Some(77));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not logged in"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Records the body of every /key/generate call.
fn mock_litellm() -> (u16, Arc<Mutex<Vec<serde_json::Value>>>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for mut r in server.incoming_requests() {
            let mut body = String::new();
            let _ = r.as_reader().read_to_string(&mut body);
            if r.url() == "/key/generate" {
                s2.lock()
                    .unwrap()
                    .push(serde_json::from_str(&body).unwrap_or_default());
            }
            let _ = r.respond(tiny_http::Response::from_string(
                r#"{"key":"sk-virtual-1","expires":"2030-01-01T00:00:00Z"}"#,
            ));
        }
    });
    (port, seen)
}

#[test]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore)]
fn mint_serve_verifies_real_id_token() {
    let Some(issuer) = issuer() else { return };
    let f = fixture(&issuer);
    let (litellm_port, seen) = mock_litellm();
    let mint_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _server = Server(
        warden(&f)
            .env("LITELLM_MASTER_KEY", MASTER)
            .args([
                "mint-serve",
                "--listen",
                &format!("127.0.0.1:{mint_port}"),
                "--litellm-url",
                &format!("http://127.0.0.1:{litellm_port}"),
                "--team",
                "authors=team-authors",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", mint_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mint = |token: &str| {
        reqwest::blocking::Client::new()
            .post(format!("http://127.0.0.1:{mint_port}/v1/mint"))
            .bearer_auth(token)
            .json(&serde_json::json!({"harness": "probe", "models": ["claude-sonnet-5"], "ttl_secs": 60}))
            .send()
            .unwrap()
            .status()
            .as_u16()
    };

    let token = id_token_for(&issuer, CLIENT);
    assert_eq!(mint(&token), 200);
    {
        let calls = seen.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["user_id"], subject_of(&token));
        assert_eq!(calls[0]["team_id"], "team-authors");
    }

    // flip a character in the middle of the signature (the last one only holds padding bits)
    let (head, sig) = token.rsplit_once('.').unwrap();
    let mut sig = sig.to_string();
    let flipped = if sig.as_bytes()[10] == b'A' { "B" } else { "A" };
    sig.replace_range(10..11, flipped);
    assert_eq!(mint(&format!("{head}.{sig}")), 401, "tampered signature");

    assert_eq!(
        mint(&id_token_for(&issuer, OTHER_CLIENT)),
        401,
        "token issued to another client"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "rejected tokens mint nothing"
    );
}
