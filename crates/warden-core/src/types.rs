//! Types shared by every crate, and the traits the leaf crates implement.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, SystemTime};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

/// Wire format a harness can speak to a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ApiFormat {
    /// Harness has first-class LiteLLM support: base_url is the proxy root and the
    /// harness picks the wire protocol per model itself (e.g. Pi + pi-provider-litellm).
    Litellm,
    AnthropicMessages,
    OpenaiChat,
    OpenaiResponses,
}

impl ApiFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Litellm => "litellm",
            Self::AnthropicMessages => "anthropic-messages",
            Self::OpenaiChat => "openai-chat",
            Self::OpenaiResponses => "openai-responses",
        }
    }
}

// ---------------------------------------------------------------- identity

#[derive(Clone)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub id_token: SecretString,
    pub expires_at: SystemTime,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("subject", &self.subject)
            .field("email", &self.email)
            .field("groups", &self.groups)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub issuer: Url,
    pub client_id: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Dotted path into the ID token claims, e.g. `groups` or `realm_access.roles`.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "email", "groups"]
        .map(String::from)
        .to_vec()
}
fn default_groups_claim() -> String {
    "groups".into()
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("not logged in; run `warden login`")]
    NotLoggedIn,
    #[error("identity provider error: {0}")]
    Provider(String),
    #[error("keychain error: {0}")]
    Keychain(String),
}

pub trait IdentityProvider {
    fn login(&self, cfg: &IdentityConfig) -> Result<Identity, IdentityError>;
    fn current(&self, cfg: &IdentityConfig) -> Result<Identity, IdentityError>;
    fn logout(&self, cfg: &IdentityConfig) -> Result<(), IdentityError>;
}

// ---------------------------------------------------------------- provider

#[derive(Clone)]
pub struct Credential {
    pub base_url: Url,
    pub format: ApiFormat,
    pub secret: SecretString,
    pub expires_at: Option<SystemTime>,
    pub models: Vec<String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("base_url", &self.base_url.as_str())
            .field("format", &self.format)
            .field("expires_at", &self.expires_at)
            .field("models", &self.models)
            .finish_non_exhaustive()
    }
}

pub struct IssueRequest<'a> {
    pub identity: &'a Identity,
    pub harness: &'a str,
    /// Formats the harness can inject, in preference order.
    pub formats: &'a [ApiFormat],
    pub models: &'a [String],
    pub ttl: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider {0} speaks none of the formats the harness accepts")]
    NoCommonFormat(String),
    #[error("provider error: {0}")]
    Other(String),
}

pub trait Provider {
    fn id(&self) -> &str;
    fn issue(&self, req: &IssueRequest) -> Result<Credential, ProviderError>;
    fn revoke(&self, cred: &Credential) -> Result<(), ProviderError>;
}

// ---------------------------------------------------------------- sandbox

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRule {
    /// Exact host, or `*.suffix` for any subdomain.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    443
}

impl HostRule {
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if port != self.port {
            return false;
        }
        let host = host.to_ascii_lowercase();
        match self.host.strip_prefix("*.") {
            Some(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
            None => host == self.host.to_ascii_lowercase(),
        }
    }
}

/// Where the sandboxed process reaches the egress proxy.
#[derive(Debug, Clone)]
pub enum ProxyHandle {
    /// Loopback TCP, reachable from inside the sandbox (macOS).
    Tcp(std::net::SocketAddr),
    /// Unix socket to bind into the sandbox; a bridge inside exposes it on `port` (Linux).
    Unix { path: PathBuf, port: u16 },
}

#[derive(Debug, Clone)]
pub struct NetworkSpec {
    pub allow_hosts: Vec<HostRule>,
    pub proxy: ProxyHandle,
    pub allow_local_binding: bool,
}

#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub workspace: PathBuf,
    pub read_only: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub network: NetworkSpec,
    /// The complete child environment. Nothing is inherited implicitly.
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Interrupt,
    Terminate,
    Hangup,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("sandbox preflight failed: {0}")]
    Preflight(String),
    #[error("spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
}

pub struct LaunchedChild {
    pub pid: u32,
    pub(crate) inner: Box<dyn std::any::Any + Send>,
}

impl LaunchedChild {
    pub fn new<T: std::any::Any + Send>(pid: u32, inner: T) -> Self {
        Self {
            pid,
            inner: Box::new(inner),
        }
    }
    pub fn inner_mut<T: std::any::Any>(&mut self) -> Option<&mut T> {
        self.inner.downcast_mut()
    }
}

pub trait Sandbox {
    fn name(&self) -> &str;
    fn preflight(&self, spec: &SandboxSpec) -> Result<(), SandboxError>;
    fn spawn(&self, spec: &SandboxSpec, argv: &[OsString]) -> Result<LaunchedChild, SandboxError>;
    fn wait(&self, child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError>;
    fn signal(&self, child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError>;
}

// ---------------------------------------------------------------- policy

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Launch,
    LaunchUnsandboxed,
    UseProvider,
    UseModel,
    ReadPath,
    WritePath,
    Connect,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::LaunchUnsandboxed => "launchUnsandboxed",
            Self::UseProvider => "useProvider",
            Self::UseModel => "useModel",
            Self::ReadPath => "readPath",
            Self::WritePath => "writePath",
            Self::Connect => "connect",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub policy_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default = "default_ttl_secs", with = "secs")]
    pub credential_ttl: Duration,
    pub max_budget_usd: Option<f64>,
    #[serde(default = "default_true")]
    pub protect_git_internals: bool,
    #[serde(default)]
    pub sandbox_allow_degraded: bool,
    /// How long past `not_after` the bundle is still accepted.
    #[serde(default = "default_grace_secs", with = "secs")]
    pub not_after_grace: Duration,
    pub audit: Option<AuditConfig>,
}

fn default_true() -> bool {
    true
}
fn default_ttl_secs() -> Duration {
    Duration::from_secs(8 * 3600)
}
fn default_grace_secs() -> Duration {
    Duration::from_secs(7 * 24 * 3600)
}

mod secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub otlp_endpoint: Url,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProviderConfig {
    Static {
        id: String,
        format: ApiFormat,
        base_url: Url,
    },
    Litellm {
        id: String,
        base_url: Url,
    },
}

impl ProviderConfig {
    pub fn id(&self) -> &str {
        match self {
            Self::Static { id, .. } | Self::Litellm { id, .. } => id,
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
