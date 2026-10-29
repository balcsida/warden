//! Per-harness conformance: launch the real harness under `warden run` against
//! an in-process mock gateway and assert the gateway saw a completion request
//! carrying the injected key for the configured model.
//!
//! Opt in with `WARDEN_CONFORMANCE=<harness>` (the harness must be installed).
//! Without it the test is skipped so `cargo test` stays hermetic.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MODEL: &str = "conformance-model";
const KEY: &str = "sk-warden-conformance-0001";

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    auth: String,
    model: Option<String>,
}

/// Speaks just enough of three APIs (plus LiteLLM discovery) for a `-p "say hi"` turn.
fn mock_gateway() -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let headers: BTreeMap<String, String> = req
                .headers()
                .iter()
                .map(|h| {
                    (
                        h.field.as_str().to_string().to_ascii_lowercase(),
                        h.value.to_string(),
                    )
                })
                .collect();
            let auth = headers
                .get("authorization")
                .or(headers.get("x-api-key"))
                .cloned()
                .unwrap_or_default();
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let json: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
            let model = json.get("model").and_then(|m| m.as_str()).map(String::from);
            let stream = json
                .get("stream")
                .and_then(|s| s.as_bool())
                .unwrap_or(false);
            let path = req.url().split('?').next().unwrap_or_default().to_string();
            s2.lock().unwrap().push(Seen {
                path: path.clone(),
                auth,
                model,
            });

            let (ct, text) = respond(&path, stream);
            let r = tiny_http::Response::from_string(text).with_header(
                format!("Content-Type: {ct}")
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            let _ = req.respond(r);
        }
    });
    (port, seen)
}

fn respond(path: &str, stream: bool) -> (&'static str, String) {
    let models = serde_json::json!({ "object": "list", "data": [{ "id": MODEL, "object": "model", "owned_by": "warden" }] });
    let model_info = serde_json::json!({ "data": [{
        "model_name": MODEL,
        "litellm_params": { "model": format!("anthropic/{MODEL}") },
        "model_info": { "mode": "chat", "max_input_tokens": 200000, "max_output_tokens": 8192, "litellm_provider": "anthropic",
                        "supported_endpoints": ["/v1/messages", "/v1/chat/completions"], "input_cost_per_token": 0, "output_cost_per_token": 0 }
    }]});
    if path.ends_with("/models") {
        return ("application/json", models.to_string());
    }
    if path.ends_with("/model/info") {
        return ("application/json", model_info.to_string());
    }
    if path.ends_with("/messages") {
        if stream {
            let ev = |t: &str, d: serde_json::Value| format!("event: {t}\ndata: {d}\n\n");
            let s = ev(
                "message_start",
                serde_json::json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":MODEL,"content":[],"stop_reason":null,"usage":{"input_tokens":1,"output_tokens":0}}}),
            ) + &ev(
                "content_block_start",
                serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            ) + &ev(
                "content_block_delta",
                serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}),
            ) + &ev(
                "content_block_stop",
                serde_json::json!({"type":"content_block_stop","index":0}),
            ) + &ev(
                "message_delta",
                serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}),
            ) + &ev("message_stop", serde_json::json!({"type":"message_stop"}));
            return ("text/event-stream", s);
        }
        return ("application/json", serde_json::json!({"id":"msg_1","type":"message","role":"assistant","model":MODEL,"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}).to_string());
    }
    if path.ends_with("/chat/completions") {
        if stream {
            let chunk = |delta: serde_json::Value, finish: Option<&str>| {
                format!(
                    "data: {}\n\n",
                    serde_json::json!({"id":"chatcmpl-1","object":"chat.completion.chunk","created":0,"model":MODEL,"choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
                )
            };
            let s = chunk(serde_json::json!({"role":"assistant","content":"hi"}), None)
                + &chunk(serde_json::json!({}), Some("stop"))
                + "data: [DONE]\n\n";
            return ("text/event-stream", s);
        }
        return ("application/json", serde_json::json!({"id":"chatcmpl-1","object":"chat.completion","created":0,"model":MODEL,"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}).to_string());
    }
    if path.ends_with("/responses") {
        let resp = serde_json::json!({"id":"resp_1","object":"response","created_at":0,"status":"completed","model":MODEL,"output":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hi","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}});
        if stream {
            let ev = |t: &str, d: serde_json::Value| format!("event: {t}\ndata: {d}\n\n");
            let s = ev(
                "response.created",
                serde_json::json!({"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","model":MODEL,"output":[]}}),
            ) + &ev(
                "response.output_item.added",
                serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","status":"in_progress","role":"assistant","content":[]}}),
            ) + &ev(
                "response.content_part.added",
                serde_json::json!({"type":"response.content_part.added","output_index":0,"item_id":"msg_1","content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}),
            ) + &ev(
                "response.output_text.delta",
                serde_json::json!({"type":"response.output_text.delta","output_index":0,"item_id":"msg_1","content_index":0,"delta":"hi"}),
            ) + &ev(
                "response.output_text.done",
                serde_json::json!({"type":"response.output_text.done","output_index":0,"item_id":"msg_1","content_index":0,"text":"hi"}),
            ) + &ev(
                "response.content_part.done",
                serde_json::json!({"type":"response.content_part.done","output_index":0,"item_id":"msg_1","content_index":0,"part":{"type":"output_text","text":"hi","annotations":[]}}),
            ) + &ev(
                "response.output_item.done",
                serde_json::json!({"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hi","annotations":[]}]}}),
            ) + &ev(
                "response.completed",
                serde_json::json!({"type":"response.completed","response":resp}),
            );
            return ("text/event-stream", s);
        }
        return ("application/json", resp.to_string());
    }
    (
        "application/json",
        serde_json::json!({"ok": true}).to_string(),
    )
}

/// Which API format the static provider advertises for each harness, and the
/// non-interactive invocation.
fn harness_setup(h: &str) -> (&'static str, Vec<&'static str>) {
    match h {
        "claude-code" => (
            "anthropic-messages",
            vec!["-p", "say hi", "--output-format", "text"],
        ),
        "codex" => (
            "openai-responses",
            vec!["exec", "--skip-git-repo-check", "say hi"],
        ),
        "opencode" => ("anthropic-messages", vec!["run", "say hi"]),
        "pi" => ("anthropic-messages", vec!["-p", "say hi"]),
        other => panic!("unknown harness {other}"),
    }
}

#[test]
fn harness_uses_injected_gateway() {
    let Ok(harness) = std::env::var("WARDEN_CONFORMANCE") else {
        eprintln!("WARDEN_CONFORMANCE not set; skipping");
        return;
    };
    let (port, seen) = mock_gateway();
    let (format, args) = harness_setup(&harness);
    let base_url = format!("http://127.0.0.1:{port}/v1");

    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir_all(&config).unwrap();
    let data = std::env::var("WARDEN_DATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| root.path().join("data"));
    std::fs::create_dir_all(&data).unwrap();
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();

    let key = warden_policy::sign::keygen();
    std::fs::write(
        config.join("trusted-keys"),
        warden_policy::key_to_string(&key.verifying_key()),
    )
    .unwrap();
    let mut bundle: serde_json::Value =
        serde_json::from_str(include_str!("../../../examples/policy.bundle")).unwrap();
    bundle["defaults"]["allow_dev_identity"] = serde_json::json!(true);
    bundle["providers"] = serde_json::json!([{ "kind": "static", "id": "gw", "format": format, "base_url": base_url }]);
    bundle["catalog"]["models"] =
        serde_json::json!({ MODEL: { "provider": "gw", "tier": "standard" } });
    bundle["catalog"]["default_model"] = serde_json::json!(MODEL);
    // Pi via pi-provider-litellm prefers the litellm format: point it at the proxy root.
    if harness == "pi" {
        bundle["providers"] = serde_json::json!([{ "kind": "litellm-static", "id": "gw", "base_url": format!("http://127.0.0.1:{port}") }]);
    }
    let bundle_path = config.join("policy.bundle");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    warden_policy::sign::sign_file(&bundle_path, &key).unwrap();

    let home = std::env::var("HOME").unwrap_or_default();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
    cmd.current_dir(&ws)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("TERM", "xterm-256color")
        .env("WARDEN_CONFIG", &config)
        .env("WARDEN_TRUSTED_KEYS", config.join("trusted-keys"))
        .env("WARDEN_DATA", &data)
        .env("WARDEN_AUDIT", "stderr")
        .env("WARDEN_STATIC_KEY_GW", KEY)
        .env(
            "WARDEN_DEV_IDENTITY",
            r#"{"subject":"conformance","groups":["engineering","codex-pilot"]}"#,
        )
        .args(["run", &harness, "--"])
        .args(&args)
        .stdin(std::process::Stdio::null());
    let out = run_with_timeout(cmd, Duration::from_secs(180));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!(
        "--- {harness} exit={:?}\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        out.status.code()
    );

    let seen = seen.lock().unwrap().clone();
    eprintln!("--- gateway saw {} request(s): {seen:#?}", seen.len());
    let completion = seen.iter().find(|s| {
        s.path.ends_with("/messages")
            || s.path.ends_with("/chat/completions")
            || s.path.ends_with("/responses")
    });
    let completion = completion.unwrap_or_else(|| {
        panic!("{harness} never called the gateway's completion endpoint; stderr:\n{stderr}")
    });
    assert!(
        completion.auth.contains(KEY),
        "{harness} did not send the injected key; auth header was {:?}",
        completion.auth
    );
    assert_eq!(
        completion.model.as_deref(),
        Some(MODEL),
        "{harness} asked for a different model"
    );
    // Every blocked connection is one the adapter declared; a new phone-home host shows up here.
    let blocked: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("blocked connection"))
        .collect();
    eprintln!("--- blocked: {blocked:?}");
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> std::process::Output {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn warden");
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            return child.wait_with_output().unwrap();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
