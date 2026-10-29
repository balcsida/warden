//! Bundle file format, signature verification, expiry.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::prelude::BASE64_STANDARD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use warden_core::{Defaults, IdentityConfig, ProviderConfig};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy bundle not found at {0}")]
    Missing(PathBuf),
    #[error("signature file {0} missing")]
    MissingSignature(PathBuf),
    #[error("no trusted keys at {0}; an administrator must install the org's verifying key")]
    NoTrustedKeys(PathBuf),
    #[error("bad trusted key on line {0}: {1}")]
    BadTrustedKey(usize, String),
    #[error("bundle signature does not verify against any trusted key")]
    BadSignature,
    #[error("bundle expired at {not_after} (grace {grace_secs}s exhausted)")]
    Expired { not_after: u64, grace_secs: u64 },
    #[error("bundle issued in the future (issued_at {0}); check the clock")]
    FromFuture(u64),
    #[error("bundle parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("cedar schema error: {0}")]
    Schema(String),
    #[error("cedar policy error: {0}")]
    Policy(String),
    #[error("policies fail validation against the schema: {0}")]
    Validation(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMeta {
    pub version: String,
    pub issuer: String,
    /// Unix seconds.
    pub issued_at: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub provider: String,
    #[serde(default)]
    pub tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEntry {
    /// May contain `${workspace}` and `${HOME}`.
    pub path: String,
    /// `ro`, `rw`, or `deny`.
    pub access: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub host: String,
    #[serde(default = "d443")]
    pub port: u16,
    #[serde(default)]
    pub purpose: String,
}

fn d443() -> u16 {
    443
}

/// The universe of things policies can refer to (§4.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub harnesses: Vec<String>,
    #[serde(default)]
    pub harness_sets: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub models: BTreeMap<String, ModelEntry>,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub paths: BTreeMap<String, PathEntry>,
    #[serde(default)]
    pub path_sets: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub hosts: BTreeMap<String, HostEntry>,
    #[serde(default)]
    pub host_sets: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub meta: BundleMeta,
    /// Cedar policies, one or more per string.
    pub policies: Vec<String>,
    #[serde(default)]
    pub catalog: Catalog,
    pub identity: IdentityConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub defaults: Defaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFile {
    pub sig: String,
}

/// A bundle that has been verified and whose policies validated against the schema.
pub struct VerifiedBundle {
    pub bundle: Bundle,
    pub sha256_hex: String,
    pub verified_by: String,
    pub evaluator: crate::cedar::Evaluator,
}

pub fn read_trusted_keys(path: &Path) -> Result<Vec<VerifyingKey>, PolicyError> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| PolicyError::NoTrustedKeys(path.to_path_buf()))?;
    let mut keys = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(parse_key(line).map_err(|e| PolicyError::BadTrustedKey(i + 1, e))?);
    }
    if keys.is_empty() {
        return Err(PolicyError::NoTrustedKeys(path.to_path_buf()));
    }
    Ok(keys)
}

pub fn parse_key(b64: &str) -> Result<VerifyingKey, String> {
    let bytes = B64.decode(b64).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

pub fn key_to_string(k: &VerifyingKey) -> String {
    B64.encode(k.to_bytes())
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Load `<path>` + `<path>.sig`, verify, parse, validate. Any failure is fatal.
pub fn load(path: &Path, trusted: &[VerifyingKey]) -> Result<VerifiedBundle, PolicyError> {
    let bytes = std::fs::read(path).map_err(|_| PolicyError::Missing(path.to_path_buf()))?;
    let sig_path = PathBuf::from(format!("{}.sig", path.display()));
    let sig_text = std::fs::read_to_string(&sig_path)
        .map_err(|_| PolicyError::MissingSignature(sig_path.clone()))?;
    let sig_file: SignatureFile = serde_json::from_str(&sig_text)?;
    let sig_bytes = B64
        .decode(sig_file.sig.trim())
        .map_err(|_| PolicyError::BadSignature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| PolicyError::BadSignature)?;
    let key = trusted
        .iter()
        .find(|k| k.verify_strict(&bytes, &sig).is_ok())
        .ok_or(PolicyError::BadSignature)?;
    load_verified_bytes(&bytes, key_to_string(key), now_secs())
}

pub(crate) fn load_verified_bytes(
    bytes: &[u8],
    verified_by: String,
    now: u64,
) -> Result<VerifiedBundle, PolicyError> {
    let bundle: Bundle = serde_json::from_slice(bytes)?;
    // 5 minutes of clock skew tolerated.
    if bundle.meta.issued_at > now + 300 {
        return Err(PolicyError::FromFuture(bundle.meta.issued_at));
    }
    let grace = bundle.defaults.not_after_grace.as_secs();
    if now > bundle.meta.not_after.saturating_add(grace) {
        return Err(PolicyError::Expired {
            not_after: bundle.meta.not_after,
            grace_secs: grace,
        });
    }
    let evaluator = crate::cedar::Evaluator::new(&bundle)?;
    Ok(VerifiedBundle {
        sha256_hex: sha256_hex(bytes),
        bundle,
        verified_by,
        evaluator,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl VerifiedBundle {
    pub fn is_past_not_after(&self) -> bool {
        now_secs() > self.bundle.meta.not_after
    }
}
