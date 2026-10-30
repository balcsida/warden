//! `warden mint-serve`: the one server-side piece. Holds the LiteLLM master key,
//! verifies the caller's IdP ID token, re-evaluates the signed bundle's policy for
//! that user, and mints a scoped virtual key via `/key/generate`. Lets OSS LiteLLM
//! (no JWT auth) still hand out short-lived per-user keys. `/v1/revoke` deletes a
//! key it minted: OSS LiteLLM only lets the master key delete keys.

use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use warden_core::{Action, Identity, IdentityError};
use warden_policy::{AdapterNeeds, Ctx, VerifiedBundle};
use warden_provider::{KeyResponse, MintRequest, key_generate_body};

use crate::{Cli, EX_CONFIG, Fail};

pub struct Config {
    pub listen: String,
    pub litellm_url: url::Url,
    pub master_key: SecretString,
    /// group -> LiteLLM team_id, first match wins in the order given.
    pub teams: Vec<(String, String)>,
    pub allow_dev_identity: bool,
}

pub fn run(cli: &Cli, cfg: Config) -> Result<ExitCode, Fail> {
    let bundle = Arc::new(crate::run::load_bundle(cli)?);
    let server = tiny_http::Server::http(&cfg.listen)
        .map_err(|e| Fail::new(EX_CONFIG, format!("listen {}: {e}", cfg.listen)))?;
    eprintln!(
        "warden mint-serve listening on {} for bundle v{} -> {}",
        server.server_addr(),
        bundle.bundle.meta.version,
        cfg.litellm_url
    );
    let cfg = Arc::new(cfg);
    for req in server.incoming_requests() {
        let (bundle, cfg) = (bundle.clone(), cfg.clone());
        std::thread::spawn(move || handle(req, &bundle, &cfg));
    }
    Ok(ExitCode::SUCCESS)
}

fn reply(req: tiny_http::Request, status: u16, body: serde_json::Value) {
    let r = tiny_http::Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(
            "Content-Type: application/json"
                .parse::<tiny_http::Header>()
                .expect("header"),
        );
    let _ = req.respond(r);
}

fn handle(mut req: tiny_http::Request, v: &VerifiedBundle, cfg: &Config) {
    let revoke_path = req.url() == "/v1/revoke";
    if req.method() != &tiny_http::Method::Post || (req.url() != "/v1/mint" && !revoke_path) {
        return reply(
            req,
            404,
            serde_json::json!({"error": "POST /v1/mint or /v1/revoke"}),
        );
    }
    let auth = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("authorization"))
        .map(|h| h.value.to_string())
        .unwrap_or_default();
    let Some(token) = auth
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return reply(
            req,
            401,
            serde_json::json!({"error": "missing bearer token"}),
        );
    };
    if revoke_path {
        return match revoke(token, cfg) {
            Ok(()) => reply(req, 200, serde_json::json!({"revoked": true})),
            Err((status, msg)) => reply(req, status, serde_json::json!({"error": msg})),
        };
    }
    let mut body = String::new();
    if req
        .as_reader()
        .take(64 * 1024)
        .read_to_string(&mut body)
        .is_err()
    {
        return reply(req, 400, serde_json::json!({"error": "unreadable body"}));
    }
    let Ok(mreq) = serde_json::from_str::<MintRequest>(&body) else {
        return reply(req, 400, serde_json::json!({"error": "bad request body"}));
    };
    let identity = match verify(token, v, cfg) {
        Ok(i) => i,
        Err(e) => {
            return reply(
                req,
                401,
                serde_json::json!({"error": format!("token rejected: {e}")}),
            );
        }
    };
    match mint(&identity, &mreq, v, cfg) {
        Ok(kr) => reply(req, 200, serde_json::to_value(kr).expect("json")),
        Err((status, msg)) => reply(req, status, serde_json::json!({"error": msg})),
    }
}

fn verify(token: &str, v: &VerifiedBundle, cfg: &Config) -> Result<Identity, IdentityError> {
    // Test and CI path: the bundle must opt in AND the server must be started with the flag.
    if cfg.allow_dev_identity
        && v.bundle.defaults.allow_dev_identity
        && let Some(json) = token.strip_prefix("dev:")
    {
        #[derive(serde::Deserialize)]
        struct Dev {
            subject: String,
            #[serde(default)]
            groups: Vec<String>,
        }
        let d: Dev =
            serde_json::from_str(json).map_err(|e| IdentityError::Provider(e.to_string()))?;
        return Ok(Identity {
            subject: d.subject,
            email: None,
            groups: d.groups,
            id_token: SecretString::from(token.to_string()),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        });
    }
    warden_identity::verify_id_token(&v.bundle.identity, token)
}

/// Possession of the virtual key is the proof of ownership: the holder can already
/// spend it, so letting it end the key grants nothing new and works after the ID
/// token has expired. Only keys this server minted (`metadata.issued_by`) qualify, so
/// the endpoint is no master-key delete oracle for other keys.
fn revoke(key: &str, cfg: &Config) -> Result<(), (u16, String)> {
    if !is_virtual_key(key) {
        return Err((401, "not a virtual key".into()));
    }
    // Per call; the client's mint-path revoke timeout (warden-provider) covers both calls.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| (500, e.to_string()))?;
    let litellm = |path: &str| (cfg.litellm_url.join(path).expect("url"), &cfg.master_key);
    let (url, master) = litellm("key/info");
    let resp = client
        .get(url)
        .query(&[("key", key)])
        .bearer_auth(master.expose_secret())
        .send()
        .map_err(|e| (502, format!("litellm: {}", e.without_url())))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err((404, "unknown key".into()));
    }
    if !resp.status().is_success() {
        return Err((502, format!("litellm /key/info returned {}", resp.status())));
    }
    let info: serde_json::Value = resp
        .json()
        .map_err(|e| (502, format!("litellm body: {}", e.without_url())))?;
    if info["info"]["metadata"]["issued_by"] != "warden" {
        return Err((403, "not a warden-issued key".into()));
    }
    let (url, master) = litellm("key/delete");
    let resp = client
        .post(url)
        .bearer_auth(master.expose_secret())
        .json(&serde_json::json!({ "keys": [key] }))
        .send()
        .map_err(|e| (502, format!("litellm: {}", e.without_url())))?;
    if !resp.status().is_success() {
        return Err((
            502,
            format!("litellm /key/delete returned {}", resp.status()),
        ));
    }
    eprintln!("revoked a key for {}", info["info"]["user_id"]);
    Ok(())
}

/// LiteLLM virtual keys are `sk-` plus URL-safe base64. Refuses other bearers (e.g. the
/// stored hashed token) before they reach LiteLLM.
fn is_virtual_key(key: &str) -> bool {
    key.strip_prefix("sk-").is_some_and(|rest| {
        (8..=200).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Policy is re-evaluated server side; the client's model list is only a filter.
fn mint(
    identity: &Identity,
    mreq: &MintRequest,
    v: &VerifiedBundle,
    cfg: &Config,
) -> Result<KeyResponse, (u16, String)> {
    let b = &v.bundle;
    let vars = std::collections::BTreeMap::new();
    let needs = AdapterNeeds::default();
    let ents = v
        .evaluator
        .entities(b, identity, &needs, &mreq.harness, &vars)
        .map_err(|e| (500, e.to_string()))?;
    let ctx = Ctx {
        harness: mreq.harness.clone(),
        workspace: String::new(),
        os: "server".into(),
        warden_version: env!("CARGO_PKG_VERSION").into(),
    };
    let launch = v.evaluator.authorize(
        &ents,
        &v.evaluator.user(identity),
        Action::Launch,
        &v.evaluator.harness(&mreq.harness),
        &ctx,
    );
    if !launch.allowed {
        return Err((
            403,
            format!("launch {} denied: {}", mreq.harness, launch.reason),
        ));
    }
    let eff = v
        .evaluator
        .effective(b, &ents, identity, &needs, &ctx, &vars);
    let models: Vec<String> = mreq
        .models
        .iter()
        .filter(|m| eff.models.contains(m))
        .cloned()
        .collect();
    if models.is_empty() {
        return Err((
            403,
            "none of the requested models is allowed for this user".into(),
        ));
    }
    let ttl = Duration::from_secs(mreq.ttl_secs).min(b.defaults.credential_ttl);
    let team = cfg
        .teams
        .iter()
        .find(|(g, _)| identity.groups.contains(g))
        .map(|(_, t)| t.as_str());
    let body = key_generate_body(
        &identity.subject,
        &mreq.harness,
        &models,
        ttl,
        b.defaults.max_budget_usd,
        team,
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| (500, e.to_string()))?;
    let url = cfg.litellm_url.join("key/generate").expect("url");
    let resp = client
        .post(url)
        .bearer_auth(cfg.master_key.expose_secret())
        .json(&body)
        .send()
        .map_err(|e| (502, format!("litellm: {}", e.without_url())))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err((
            502,
            format!(
                "litellm /key/generate returned {status}: {}",
                text.chars().take(300).collect::<String>()
            ),
        ));
    }
    let kr: KeyResponse = resp
        .json()
        .map_err(|e| (502, format!("litellm body: {}", e.without_url())))?;
    eprintln!(
        "minted key for {} harness={} models={} team={}",
        identity.subject,
        mreq.harness,
        models.join(","),
        team.unwrap_or("-")
    );
    Ok(kr)
}

#[cfg(test)]
mod tests {
    use super::is_virtual_key;

    #[test]
    fn virtual_key_shape() {
        assert!(is_virtual_key("sk-abcDEF123_-xyz"));
        assert!(!is_virtual_key("sk-short"));
        assert!(!is_virtual_key(&format!("sk-{}", "a".repeat(201))));
        assert!(!is_virtual_key("eyJhbGciOi.jwt.token"));
        assert!(!is_virtual_key(&"a".repeat(64))); // hashed token
        assert!(!is_virtual_key("sk-abc def123456"));
        assert!(!is_virtual_key("sk-abc&key=other1"));
    }
}
