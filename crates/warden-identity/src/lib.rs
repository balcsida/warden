//! OIDC device-authorization flow (RFC 8628) against any discoverable IdP.
//! Tokens live in the OS keychain; the ID token's signature is verified against
//! the issuer's JWKS; group claims are read from a configurable (dotted) path.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, ClientId, DeviceAuthorizationUrl, EmptyExtraTokenFields, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce, OAuth2TokenResponse,
    RefreshToken, Scope, StandardErrorResponse, StandardTokenResponse, TokenResponse,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use warden_core::{Identity, IdentityConfig, IdentityError, IdentityProvider};

/// Catch every non-standard claim so the groups claim can live anywhere.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Extra(pub serde_json::Map<String, serde_json::Value>);
impl AdditionalClaims for Extra {}

type Fields = IdTokenFields<
    Extra,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type TokenResp = StandardTokenResponse<Fields, CoreTokenType>;
type Client = openidconnect::Client<
    Extra,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    TokenResp,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,      // auth
    EndpointSet,      // device auth
    EndpointNotSet,   // introspection
    EndpointNotSet,   // revocation
    EndpointSet,      // token
    EndpointMaybeSet, // userinfo
>;

const KEYCHAIN_SERVICE: &str = "warden";

#[derive(Serialize, Deserialize)]
struct Stored {
    refresh_token: Option<String>,
    id_token: String,
    expires_at: u64,
}

pub struct OidcDeviceFlow;

fn perr<E: std::fmt::Display>(e: E) -> IdentityError {
    IdentityError::Provider(e.to_string())
}

fn entry(cfg: &IdentityConfig) -> Result<keyring::Entry, IdentityError> {
    keyring::Entry::new(
        KEYCHAIN_SERVICE,
        &format!("oidc:{}|{}", cfg.issuer, cfg.client_id),
    )
    .map_err(|e| IdentityError::Keychain(e.to_string()))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Walk a dotted path (`realm_access.roles`) and collect strings.
pub fn groups_from(extra: &serde_json::Map<String, serde_json::Value>, path: &str) -> Vec<String> {
    let mut cur = serde_json::Value::Object(extra.clone());
    for part in path.split('.') {
        cur = match cur.get(part) {
            Some(v) => v.clone(),
            None => return vec![],
        };
    }
    match cur {
        serde_json::Value::Array(a) => a
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        serde_json::Value::String(s) => vec![s],
        _ => vec![],
    }
}

async fn client(
    cfg: &IdentityConfig,
    http: &openidconnect::reqwest::Client,
) -> Result<Client, IdentityError> {
    let issuer =
        IssuerUrl::new(cfg.issuer.as_str().trim_end_matches('/').to_string()).map_err(perr)?;
    let meta = CoreProviderMetadata::discover_async(issuer, http)
        .await
        .map_err(perr)?;
    // Device endpoint is not part of the core metadata type; read it from the raw document.
    let raw: serde_json::Value = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            cfg.issuer.as_str().trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(perr)?
        .json()
        .await
        .map_err(perr)?;
    let dev = raw
        .get("device_authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IdentityError::Provider("IdP does not advertise device_authorization_endpoint".into())
        })?
        .to_string();
    let token_url = meta
        .token_endpoint()
        .cloned()
        .ok_or_else(|| IdentityError::Provider("IdP has no token_endpoint".into()))?;
    let c: Client = openidconnect::Client::from_provider_metadata(
        meta,
        ClientId::new(cfg.client_id.clone()),
        None,
    )
    .set_device_authorization_url(DeviceAuthorizationUrl::new(dev).map_err(perr)?)
    .set_token_uri(token_url);
    Ok(c)
}

fn http_client() -> Result<openidconnect::reqwest::Client, IdentityError> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(perr)
}

fn identity_from(
    cfg: &IdentityConfig,
    c: &Client,
    resp: &TokenResp,
) -> Result<(Identity, Stored), IdentityError> {
    let id_token = resp
        .id_token()
        .ok_or_else(|| IdentityError::Provider("token response has no id_token".into()))?;
    // Device flow carries no nonce; the signature, issuer, audience and expiry are still checked.
    let claims = id_token
        .claims(&c.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
        .map_err(perr)?;
    let groups = groups_from(&claims.additional_claims().0, &cfg.groups_claim);
    let expires_at = claims.expiration();
    let expires_secs = expires_at.timestamp().max(0) as u64;
    let identity = Identity {
        subject: claims.subject().to_string(),
        email: claims.email().map(|e| e.to_string()),
        groups,
        id_token: SecretString::from(id_token.to_string()),
        expires_at: UNIX_EPOCH + Duration::from_secs(expires_secs),
    };
    let stored = Stored {
        refresh_token: resp.refresh_token().map(|r| r.secret().clone()),
        id_token: id_token.to_string(),
        expires_at: expires_secs,
    };
    Ok((identity, stored))
}

fn save(cfg: &IdentityConfig, stored: &Stored) -> Result<(), IdentityError> {
    entry(cfg)?
        .set_password(&serde_json::to_string(stored).expect("json"))
        .map_err(|e| IdentityError::Keychain(e.to_string()))
}

/// Verify a raw ID token (signature via the issuer's JWKS, issuer, audience, expiry)
/// and return the identity it asserts. Used by `warden mint-serve`.
pub fn verify_id_token(cfg: &IdentityConfig, token: &str) -> Result<Identity, IdentityError> {
    rt().block_on(async {
        let http = http_client()?;
        let c = client(cfg, &http).await?;
        let id_token: openidconnect::IdToken<
            Extra,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        > = token.parse().map_err(perr)?;
        let claims = id_token
            .claims(&c.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
            .map_err(perr)?;
        Ok(Identity {
            subject: claims.subject().to_string(),
            email: claims.email().map(|e| e.to_string()),
            groups: groups_from(&claims.additional_claims().0, &cfg.groups_claim),
            id_token: SecretString::from(token.to_string()),
            expires_at: UNIX_EPOCH
                + Duration::from_secs(claims.expiration().timestamp().max(0) as u64),
        })
    })
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio")
}

impl IdentityProvider for OidcDeviceFlow {
    fn login(&self, cfg: &IdentityConfig) -> Result<Identity, IdentityError> {
        let (identity, stored) = rt().block_on(async {
            let http = http_client()?;
            let c = client(cfg, &http).await?;
            let mut req = c.exchange_device_code();
            for s in &cfg.scopes {
                req = req.add_scope(Scope::new(s.clone()));
            }
            let details: openidconnect::DeviceAuthorizationResponse<
                openidconnect::EmptyExtraDeviceAuthorizationFields,
            > = req.request_async(&http).await.map_err(perr)?;
            eprintln!(
                "Open {} and enter code: {}",
                details.verification_uri().as_str(),
                details.user_code().secret()
            );
            if let Some(full) = details.verification_uri_complete() {
                eprintln!("(or open {})", full.secret());
            }
            let resp: TokenResp = c
                .exchange_device_access_token(&details)
                .request_async(&http, tokio::time::sleep, Some(details.expires_in()))
                .await
                .map_err(perr)?;
            identity_from(cfg, &c, &resp)
        })?;
        // Outside the runtime: the secret-service backend blocks on its own executor.
        save(cfg, &stored)?;
        Ok(identity)
    }

    fn current(&self, cfg: &IdentityConfig) -> Result<Identity, IdentityError> {
        let raw = match entry(cfg)?.get_password() {
            Ok(r) => r,
            Err(keyring::Error::NoEntry) => return Err(IdentityError::NotLoggedIn),
            Err(e) => return Err(IdentityError::Keychain(e.to_string())),
        };
        let stored: Stored = serde_json::from_str(&raw).map_err(|_| IdentityError::NotLoggedIn)?;
        let (identity, refreshed) = rt().block_on(async {
            let http = http_client()?;
            let c = client(cfg, &http).await?;
            // Still valid for 5 minutes: verify the cached token locally and reuse it.
            if stored.expires_at > now() + 300 {
                let id_token: openidconnect::IdToken<
                    Extra,
                    CoreGenderClaim,
                    CoreJweContentEncryptionAlgorithm,
                    CoreJwsSigningAlgorithm,
                > = stored.id_token.parse().map_err(perr)?;
                if let Ok(claims) =
                    id_token.claims(&c.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
                {
                    let identity = Identity {
                        subject: claims.subject().to_string(),
                        email: claims.email().map(|e| e.to_string()),
                        groups: groups_from(&claims.additional_claims().0, &cfg.groups_claim),
                        id_token: SecretString::from(stored.id_token.clone()),
                        expires_at: UNIX_EPOCH + Duration::from_secs(stored.expires_at),
                    };
                    return Ok((identity, None));
                }
            }
            let Some(refresh) = stored.refresh_token.as_deref() else {
                return Err(IdentityError::NotLoggedIn);
            };
            let resp: TokenResp = c
                .exchange_refresh_token(&RefreshToken::new(refresh.to_string()))
                .request_async(&http)
                .await
                .map_err(|_| IdentityError::NotLoggedIn)?;
            let (identity, mut new_stored) = identity_from(cfg, &c, &resp)?;
            // IdPs that don't rotate refresh tokens omit it from the response.
            if new_stored.refresh_token.is_none() {
                new_stored.refresh_token = Some(refresh.to_string());
            }
            Ok((identity, Some(new_stored)))
        })?;
        if let Some(stored) = refreshed {
            save(cfg, &stored)?;
        }
        Ok(identity)
    }

    fn logout(&self, cfg: &IdentityConfig) -> Result<(), IdentityError> {
        match entry(cfg)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(IdentityError::Keychain(e.to_string())),
        }
    }
}

/// For tests and `--identity-file`: a static identity with no IdP. Never used in
/// a signed bundle's normal path; the CLI only enables it under `WARDEN_DEV_IDENTITY`.
pub struct StaticIdentity(pub Identity);

impl IdentityProvider for StaticIdentity {
    fn login(&self, _cfg: &IdentityConfig) -> Result<Identity, IdentityError> {
        Ok(self.0.clone())
    }
    fn current(&self, _cfg: &IdentityConfig) -> Result<Identity, IdentityError> {
        Ok(self.0.clone())
    }
    fn logout(&self, _cfg: &IdentityConfig) -> Result<(), IdentityError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_paths() {
        let extra: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{"groups":["a","b"],"realm_access":{"roles":["r1"]},"dept":"eng"}"#,
        )
        .unwrap();
        assert_eq!(groups_from(&extra, "groups"), ["a", "b"]);
        assert_eq!(groups_from(&extra, "realm_access.roles"), ["r1"]);
        assert_eq!(groups_from(&extra, "dept"), ["eng"]);
        assert!(groups_from(&extra, "missing").is_empty());
    }
}
