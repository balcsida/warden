//! `warden`: harness-neutral launcher. See docs/DESIGN.md §5 for the launch sequence.

mod dirs;
mod doctor;
mod mint;
mod policy_cmd;
mod probe;
mod run;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

pub const EX_USAGE: u8 = 64;
pub const EX_UNAVAILABLE: u8 = 69;
pub const EX_NOPERM: u8 = 77;
pub const EX_CONFIG: u8 = 78;

#[derive(Parser)]
#[command(
    name = "warden",
    version,
    about = "Launch agentic coding harnesses under one set of rules"
)]
pub struct Cli {
    /// Policy bundle path (default: $WARDEN_POLICY, then the user and system config dirs)
    #[arg(long, global = true, env = "WARDEN_POLICY")]
    pub policy: Option<PathBuf>,
    /// Trusted verifying keys file (default: the system config dir)
    #[arg(long, global = true, env = "WARDEN_TRUSTED_KEYS")]
    pub trusted_keys: Option<PathBuf>,
    /// Audit sink: otlp (from the bundle), stderr, none
    #[arg(long, global = true, env = "WARDEN_AUDIT")]
    pub audit: Option<String>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Sign in to the organisation's identity provider (device flow)
    Login,
    /// Forget the stored identity
    Logout,
    /// Launch a harness under policy, sandbox and provider routing
    Run {
        harness: String,
        /// Model id from the catalog; default: bundle default or first allowed
        #[arg(long, short)]
        model: Option<String>,
        /// Print the plan (secret masked) and exit without launching
        #[arg(long)]
        dry_run: bool,
        /// Skip the OS sandbox; requires the `launchUnsandboxed` permission
        #[arg(long)]
        no_sandbox: bool,
        /// Arguments passed to the harness
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Check this machine: policy, identity, sandbox, installed harnesses
    Doctor,
    /// Inspect or sign policy bundles
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Server side: mint LiteLLM virtual keys for IdP-authenticated users (no LiteLLM Enterprise needed)
    MintServe {
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// LiteLLM proxy root URL
        #[arg(long)]
        litellm_url: url::Url,
        /// Environment variable holding the LiteLLM master key
        #[arg(long, default_value = "LITELLM_MASTER_KEY")]
        master_key_env: String,
        /// IdP group -> LiteLLM team_id mapping, repeatable; first match wins
        #[arg(long = "team", value_name = "GROUP=TEAM_ID")]
        teams: Vec<String>,
        /// Accept `dev:<json>` bearer tokens when the bundle also allows dev identities (tests only)
        #[arg(long, hide = true)]
        allow_dev_identity: bool,
    },
    /// Manage provider secrets for the `static` provider
    Provider {
        #[command(subcommand)]
        cmd: ProviderCmd,
    },
    /// Internal: print the current credential (used via key-helper hooks)
    #[command(name = "__credential", hide = true)]
    Credential,
    /// Internal: Linux in-sandbox helper
    #[command(name = "__linux-sandbox", hide = true)]
    LinuxSandbox {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Internal: sandbox probe used by the integration tests
    #[command(name = "__probe", hide = true)]
    Probe {
        read: PathBuf,
        write: PathBuf,
        /// host:port to connect to directly and via the proxy
        connect: String,
        /// Windows: also try to open this process (default: the parent) with write-class access
        pid: Option<u32>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCmd {
    /// Show bundle metadata, policies and, if logged in, the effective decisions
    Show,
    /// Generate a signing key pair (prints both; store the private key safely)
    Keygen,
    /// Sign a bundle file with a private key, writing `<bundle>.sig`
    Sign {
        bundle: PathBuf,
        /// Base64 private key, or `-` to read from stdin
        #[arg(long)]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum ProviderCmd {
    /// Store the key for a `static` provider in the OS keychain (read from stdin)
    SetKey { id: String },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("WARDEN_LOG"))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Credential => return credential(),
        #[cfg(target_os = "linux")]
        Cmd::LinuxSandbox { args } => warden_sandbox::linux::run_helper(args),
        #[cfg(not(target_os = "linux"))]
        Cmd::LinuxSandbox { .. } => return fail(EX_USAGE, "linux helper on a non-linux host"),
        Cmd::Probe {
            read,
            write,
            connect,
            pid,
        } => return probe::run(read, write, connect, *pid),
        _ => {}
    }
    match run::dispatch(&cli) {
        Ok(code) => code,
        Err(e) => fail(e.code, &e.msg),
    }
}

fn credential() -> ExitCode {
    #[cfg(unix)]
    {
        let Some(path) = std::env::var_os(warden_sandbox::credsock::ENV) else {
            return fail(EX_CONFIG, "WARDEN_CREDENTIAL_SOCK is not set");
        };
        match warden_sandbox::credsock::fetch(std::path::Path::new(&path)) {
            Ok(tok) => {
                print!("{tok}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(EX_UNAVAILABLE, &format!("credential socket: {e}")),
        }
    }
    #[cfg(not(unix))]
    {
        fail(
            EX_UNAVAILABLE,
            "credential helper is unix-only in milestone 1",
        )
    }
}

pub fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("warden: {msg}");
    ExitCode::from(code)
}

/// Error with a sysexits-style code; every launch failure goes through this.
pub struct Fail {
    pub code: u8,
    pub msg: String,
}

impl Fail {
    pub fn new(code: u8, msg: impl ToString) -> Self {
        Self {
            code,
            msg: msg.to_string(),
        }
    }
}

impl<E: std::fmt::Display> From<E> for Fail {
    fn from(e: E) -> Self {
        Self::new(1, e.to_string())
    }
}
