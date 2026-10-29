//! Credential providers. `StaticProvider` reads a long-lived gateway key from the
//! OS keychain; `LiteLlmProvider` mints a per-launch virtual key with a TTL,
//! model list and budget, authenticating with the user's OIDC ID token.

use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};
use url::Url;

use warden_core::{ApiFormat, Credential, IssueRequest, Provider, ProviderConfig, ProviderError};

pub const KEYCHAIN_SERVICE: &str = "warden";

pub fn from_config(cfg: &ProviderConfig, litellm_http: Option<LiteLlmHttp>) -> Box<dyn Provider> {
    match cfg {
        ProviderConfig::Static {
            id,
            format,
            base_url,
        } => Box::new(StaticProvider {
            id: id.clone(),
            format: *format,
            base_url: base_url.clone(),
        }),
        ProviderConfig::Litellm { id, base_url } => Box::new(LiteLlmProvider {
            id: id.clone(),
            base_url: base_url.clone(),
            http: litellm_http.unwrap_or_default(),
        }),
    }
}

/// Formats a provider can hand out, in the order a harness should prefer them.
pub fn offered_formats(cfg: &ProviderConfig) -> Vec<ApiFormat> {
    match cfg {
        ProviderConfig::Static { format, .. } => vec![*format],
        ProviderConfig::Litellm { .. } => vec![
            ApiFormat::Litellm,
            ApiFormat::AnthropicMessages,
            ApiFormat::OpenaiResponses,
            ApiFormat::OpenaiChat,
        ],
    }
}

/// Path suffix a LiteLLM proxy serves each format on.
fn litellm_url(root: &Url, format: ApiFormat) -> Url {
    let mut s = root.as_str().trim_end_matches('/').to_string();
    match format {
        ApiFormat::Litellm => {}
        ApiFormat::AnthropicMessages => s.push_str("/anthropic"),
        ApiFormat::OpenaiChat | ApiFormat::OpenaiResponses => s.push_str("/v1"),
    }
    Url::parse(&s).expect("root was a url")
}

// ---------------------------------------------------------------- static

pub struct StaticProvider {
    pub id: String,
    pub format: ApiFormat,
    pub base_url: Url,
}

pub fn keychain_entry(provider_id: &str) -> Result<keyring::Entry, ProviderError> {
    keyring::Entry::new(KEYCHAIN_SERVICE, &format!("provider:{provider_id}"))
        .map_err(|e| ProviderError::Other(e.to_string()))
}

impl StaticProvider {
    pub fn set_key(provider_id: &str, key: &str) -> Result<(), ProviderError> {
        keychain_entry(provider_id)?
            .set_password(key)
            .map_err(|e| ProviderError::Other(e.to_string()))
    }
}

impl Provider for StaticProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn issue(&self, req: &IssueRequest) -> Result<Credential, ProviderError> {
        if !req.formats.contains(&self.format) {
            return Err(ProviderError::NoCommonFormat(self.id.clone()));
        }
        // CI and headless hosts: WARDEN_STATIC_KEY_<ID> in warden's own environment
        // (the child never inherits it). Otherwise the OS keychain.
        let env_name = format!(
            "WARDEN_STATIC_KEY_{}",
            self.id.to_ascii_uppercase().replace('-', "_")
        );
        let key = match std::env::var(&env_name) {
            Ok(k) if !k.is_empty() => k,
            _ => keychain_entry(&self.id)?.get_password().map_err(|e| {
                ProviderError::Other(format!(
                    "no key for provider `{}` ({e}); run `warden provider set-key {}` or set {env_name}",
                    self.id, self.id
                ))
            })?,
        };
        Ok(Credential {
            base_url: self.base_url.clone(),
            format: self.format,
            secret: SecretString::from(key),
            expires_at: None,
            models: req.models.to_vec(),
        })
    }
    fn revoke(&self, _cred: &Credential) -> Result<(), ProviderError> {
        Ok(())
    }
}

// ---------------------------------------------------------------- litellm

#[derive(Clone)]
pub struct LiteLlmHttp {
    pub timeout: Duration,
    pub max_budget_usd: Option<f64>,
}

impl Default for LiteLlmHttp {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_budget_usd: None,
        }
    }
}

pub struct LiteLlmProvider {
    pub id: String,
    pub base_url: Url,
    pub http: LiteLlmHttp,
}

#[derive(serde::Deserialize)]
struct KeyResponse {
    key: String,
    #[serde(default)]
    expires: Option<String>,
}

impl Provider for LiteLlmProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn issue(&self, req: &IssueRequest) -> Result<Credential, ProviderError> {
        let format = *offered_formats(&ProviderConfig::Litellm {
            id: self.id.clone(),
            base_url: self.base_url.clone(),
        })
        .iter()
        .find(|f| req.formats.contains(f))
        .ok_or_else(|| ProviderError::NoCommonFormat(self.id.clone()))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(self.http.timeout)
            .build()
            .map_err(|e| ProviderError::Other(e.to_string()))?;
        let ttl_secs = req.ttl.as_secs().max(60);
        let body = serde_json::json!({
            "duration": format!("{ttl_secs}s"),
            "models": req.models,
            "max_budget": self.http.max_budget_usd,
            "user_id": req.identity.subject,
            "key_alias": format!("warden/{}/{}/{}", req.identity.subject, req.harness, warden_core::now_secs()),
            "metadata": { "harness": req.harness, "issued_by": "warden" },
        });
        let url = litellm_url(&self.base_url, ApiFormat::Litellm)
            .join("key/generate")
            .expect("url");
        let resp = client
            .post(url)
            .bearer_auth(req.identity.id_token.expose_secret())
            .json(&body)
            .send()
            .map_err(|e| ProviderError::Other(format!("litellm key/generate: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(ProviderError::Other(format!(
                "litellm key/generate returned {status}: {}",
                text.chars().take(300).collect::<String>()
            )));
        }
        let kr: KeyResponse = resp
            .json()
            .map_err(|e| ProviderError::Other(format!("litellm key/generate body: {e}")))?;
        let expires_at = kr
            .expires
            .as_deref()
            .and_then(parse_rfc3339)
            .or(Some(SystemTime::now() + req.ttl));
        Ok(Credential {
            base_url: litellm_url(&self.base_url, format),
            format,
            secret: SecretString::from(kr.key),
            expires_at,
            models: req.models.to_vec(),
        })
    }

    fn revoke(&self, cred: &Credential) -> Result<(), ProviderError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| ProviderError::Other(e.to_string()))?;
        let url = litellm_url(&self.base_url, ApiFormat::Litellm)
            .join("key/delete")
            .expect("url");
        // A virtual key may delete itself.
        client
            .post(url)
            .bearer_auth(cred.secret.expose_secret())
            .json(&serde_json::json!({ "keys": [cred.secret.expose_secret()] }))
            .send()
            .map_err(|e| ProviderError::Other(e.to_string()))?;
        Ok(())
    }
}

/// Minimal RFC 3339 `YYYY-MM-DDTHH:MM:SS[.frac][Z|+00:00]` parser; LiteLLM returns UTC.
fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let time: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ':')
        .collect();
    let mut t = time.split(':').map(|x| x.parse::<i64>().ok());
    let (hh, mm, ss) = (t.next()??, t.next()??, t.next().flatten().unwrap_or(0));
    // days from civil (Howard Hinnant)
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    u64::try_from(secs)
        .ok()
        .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn rfc3339() {
        let t = parse_rfc3339("2026-10-29T12:00:00Z").unwrap();
        assert_eq!(
            t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            1793275200
        );
        assert!(parse_rfc3339("garbage").is_none());
    }

    #[test]
    fn urls() {
        let root: Url = "https://gw.example.com/".parse().unwrap();
        assert_eq!(
            litellm_url(&root, ApiFormat::AnthropicMessages).as_str(),
            "https://gw.example.com/anthropic"
        );
        assert_eq!(
            litellm_url(&root, ApiFormat::OpenaiChat).as_str(),
            "https://gw.example.com/v1"
        );
        assert_eq!(
            litellm_url(&root, ApiFormat::Litellm)
                .join("key/generate")
                .unwrap()
                .as_str(),
            "https://gw.example.com/key/generate"
        );
    }

    #[test]
    fn litellm_issue_posts_key_generate() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen: Arc<Mutex<Vec<(String, String, serde_json::Value)>>> = Arc::default();
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
                r.as_reader().read_to_string(&mut body).unwrap();
                s2.lock().unwrap().push((
                    r.url().to_string(),
                    auth,
                    serde_json::from_str(&body).unwrap(),
                ));
                let resp = tiny_http::Response::from_string(
                    r#"{"key":"sk-virtual","expires":"2030-01-01T00:00:00Z"}"#,
                )
                .with_header(
                    "Content-Type: application/json"
                        .parse::<tiny_http::Header>()
                        .unwrap(),
                );
                r.respond(resp).unwrap();
            }
        });
        let p = LiteLlmProvider {
            id: "gw".into(),
            base_url: format!("http://127.0.0.1:{port}").parse().unwrap(),
            http: LiteLlmHttp {
                timeout: Duration::from_secs(5),
                max_budget_usd: Some(5.0),
            },
        };
        let ident = warden_core::Identity {
            subject: "alice".into(),
            email: None,
            groups: vec![],
            id_token: SecretString::from("idtok"),
            expires_at: SystemTime::now(),
        };
        let models = vec!["claude-sonnet-5".to_string()];
        let cred = p
            .issue(&IssueRequest {
                identity: &ident,
                harness: "pi",
                formats: &[ApiFormat::AnthropicMessages, ApiFormat::Litellm],
                models: &models,
                ttl: Duration::from_secs(3600),
            })
            .unwrap();
        assert_eq!(
            cred.format,
            ApiFormat::Litellm,
            "litellm format preferred when the harness accepts it"
        );
        assert_eq!(cred.secret.expose_secret(), "sk-virtual");
        assert_eq!(cred.base_url.as_str(), format!("http://127.0.0.1:{port}/"));
        let seen = seen.lock().unwrap();
        let (url, auth, body) = &seen[0];
        assert_eq!(url, "/key/generate");
        assert_eq!(auth, "Bearer idtok");
        assert_eq!(body["duration"], "3600s");
        assert_eq!(body["models"][0], "claude-sonnet-5");
        assert_eq!(body["user_id"], "alice");
        assert_eq!(body["max_budget"], 5.0);
    }
}
