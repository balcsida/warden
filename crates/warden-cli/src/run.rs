//! The launch sequence (docs/DESIGN.md §5) and the shared loaders the other
//! subcommands reuse.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use warden_audit::{AuditSink, Event};
use warden_core::adapter::LaunchContext;
use warden_core::{
    Action, AdapterSet, HostRule, Identity, IdentityProvider, IssueRequest, NetworkSpec, Provider,
    ProxyHandle, Sandbox, SandboxSpec,
};
use warden_policy::{AdapterNeeds, Ctx, VerifiedBundle};

use crate::{Cli, Cmd, EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE, Fail, dirs};

const BRIDGE_PORT: u16 = 3128;

/// Absolute, with symlinks resolved in the nearest existing ancestor and the missing
/// tail re-appended, so a dir that does not exist yet compares in the form the kernel
/// will see once it does.
fn norm(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut tail = Vec::new();
    let mut base = abs.as_path();
    let mut out = loop {
        if let Ok(c) = std::fs::canonicalize(base) {
            break c;
        }
        match (base.file_name(), base.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                base = parent;
            }
            _ => break base.to_path_buf(),
        }
    };
    out.extend(tail.iter().rev());
    if cfg!(windows) {
        windows_form(&out.to_string_lossy())
    } else {
        out
    }
}

/// Windows paths compare without the verbatim `\\?\` prefix and case-insensitively.
fn windows_form(p: &str) -> PathBuf {
    let p = match p.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => p.strip_prefix(r"\\?\").unwrap_or(p).to_string(),
    };
    PathBuf::from(p.to_lowercase())
}

/// A writable root that contains warden's config or data dir, the trusted-keys file or
/// the policy bundle would let the harness rewrite adapters, trust its own signing key
/// or swap the bundle for later launches. The reverse (the data dir containing a root,
/// e.g. the harness homes) is fine.
fn refuse_roots_containing_warden_paths(read_write: &[PathBuf], cli: &Cli) -> Result<(), Fail> {
    for path in [
        dirs::config_dir(),
        dirs::data_dir(),
        dirs::trusted_keys_path(cli.trusted_keys.as_ref()),
        dirs::bundle_path(cli.policy.as_ref()),
    ] {
        let shown = path.display().to_string();
        let path = norm(&path);
        for root in read_write {
            if path.starts_with(norm(root)) {
                return Err(Fail::new(
                    EX_NOPERM,
                    format!(
                        "writable root {} contains warden's own path {shown}; run warden from a project directory",
                        root.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Revokes the issued credential exactly once: explicitly at exit, or on drop when an
/// early return skips that.
struct RevokeOnDrop<'a> {
    provider: &'a dyn Provider,
    cred: &'a warden_core::Credential,
    audit: &'a dyn AuditSink,
    done: bool,
}

impl RevokeOnDrop<'_> {
    fn revoke(&mut self) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let id = self.provider.id();
        match self.provider.revoke(self.cred) {
            Ok(()) => self
                .audit
                .emit(Event::new("credential.revoked").attr("provider", id)),
            Err(e) => {
                eprintln!("warden: could not revoke the credential ({e}); it lapses at its TTL");
                self.audit.emit(
                    Event::new("credential.revoke_failed")
                        .attr("provider", id)
                        .attr("error", e),
                );
            }
        }
    }
}

impl Drop for RevokeOnDrop<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.revoke();
            self.audit.flush(Duration::from_secs(2));
        }
    }
}

pub fn dispatch(cli: &Cli) -> Result<ExitCode, Fail> {
    match &cli.cmd {
        Cmd::Login => {
            let v = load_bundle(cli)?;
            let id = warden_identity::OidcDeviceFlow
                .login(&v.bundle.identity)
                .map_err(|e| Fail::new(EX_NOPERM, e))?;
            println!(
                "logged in as {} (groups: {})",
                id.subject,
                id.groups.join(", ")
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Logout => {
            let v = load_bundle(cli)?;
            warden_identity::OidcDeviceFlow
                .logout(&v.bundle.identity)
                .map_err(|e| Fail::new(EX_NOPERM, e))?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run {
            harness,
            model,
            dry_run,
            no_sandbox,
            args,
        } => launch(cli, harness, model.as_deref(), *dry_run, *no_sandbox, args),
        Cmd::Doctor => crate::doctor::run(cli),
        Cmd::MintServe {
            listen,
            litellm_url,
            master_key_env,
            teams,
            allow_dev_identity,
        } => {
            let master_key = std::env::var(master_key_env)
                .map_err(|_| Fail::new(EX_CONFIG, format!("{master_key_env} is not set")))?;
            let teams = teams
                .iter()
                .map(|t| {
                    t.split_once('=')
                        .map(|(g, id)| (g.to_string(), id.to_string()))
                        .ok_or_else(|| {
                            Fail::new(EX_USAGE, format!("--team expects GROUP=TEAM_ID, got `{t}`"))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            crate::mint::run(
                cli,
                crate::mint::Config {
                    listen: listen.clone(),
                    litellm_url: litellm_url.clone(),
                    master_key: SecretString::from(master_key),
                    teams,
                    allow_dev_identity: *allow_dev_identity,
                },
            )
        }
        Cmd::Policy { cmd } => crate::policy_cmd::dispatch(cli, cmd),
        Cmd::Provider {
            cmd: crate::ProviderCmd::SetKey { id },
        } => {
            let mut key = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut key)?;
            warden_provider::StaticProvider::set_key(id, key.trim())?;
            println!("stored key for provider `{id}` in the OS keychain");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Credential | Cmd::LinuxSandbox { .. } | Cmd::Probe { .. } => {
            unreachable!("handled in main")
        }
    }
}

// ---------------------------------------------------------------- shared loaders

pub fn load_bundle(cli: &Cli) -> Result<VerifiedBundle, Fail> {
    let keys =
        warden_policy::read_trusted_keys(&dirs::trusted_keys_path(cli.trusted_keys.as_ref()))
            .map_err(|e| Fail::new(EX_CONFIG, e))?;
    warden_policy::load(&dirs::bundle_path(cli.policy.as_ref()), &keys)
        .map_err(|e| Fail::new(EX_CONFIG, e))
}

pub fn identity(
    _cli: &Cli,
    bundle: &warden_policy::Bundle,
) -> Result<Identity, warden_core::IdentityError> {
    if bundle.defaults.allow_dev_identity
        && let Ok(raw) = std::env::var("WARDEN_DEV_IDENTITY")
    {
        #[derive(serde::Deserialize)]
        struct Dev {
            subject: String,
            #[serde(default)]
            email: Option<String>,
            #[serde(default)]
            groups: Vec<String>,
        }
        let d: Dev = serde_json::from_str(&raw).map_err(|e| {
            warden_core::IdentityError::Provider(format!("WARDEN_DEV_IDENTITY: {e}"))
        })?;
        return Ok(Identity {
            subject: d.subject,
            email: d.email,
            groups: d.groups,
            id_token: SecretString::from(format!("dev:{raw}")),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        });
    }
    warden_identity::OidcDeviceFlow.current(&bundle.identity)
}

pub fn vars() -> BTreeMap<String, String> {
    let ws = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    [
        ("workspace", ws),
        ("HOME", dirs::home().display().to_string()),
        ("WARDEN_DATA", dirs::data_dir().display().to_string()),
        ("WARDEN_CONFIG", dirs::config_dir().display().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

pub fn entities_for(
    v: &VerifiedBundle,
    id: &Identity,
    harness: &str,
    needs: &AdapterNeeds,
) -> Result<(warden_policy::Entities, Ctx), Fail> {
    let ents = v
        .evaluator
        .entities(&v.bundle, id, needs, harness, &vars())
        .map_err(|e| Fail::new(EX_CONFIG, e))?;
    let ctx = Ctx {
        harness: harness.into(),
        workspace: vars()["workspace"].clone(),
        os: dirs::os_name().into(),
        warden_version: env!("CARGO_PKG_VERSION").into(),
    };
    Ok((ents, ctx))
}

/// Minimal spec used by `doctor` to run preflight.
pub fn probe_spec(tmp: &Path) -> SandboxSpec {
    SandboxSpec {
        workspace: tmp.to_path_buf(),
        read_only: vec![],
        read_write: vec![tmp.to_path_buf()],
        deny_read: vec![],
        network: NetworkSpec {
            allow_hosts: vec![],
            proxy: warden_sandbox_proxy_handle(tmp),
            allow_local_binding: false,
        },
        env: BTreeMap::new(),
        cwd: tmp.to_path_buf(),
    }
}

fn warden_sandbox_proxy_handle(tmp: &Path) -> ProxyHandle {
    if cfg!(target_os = "linux") {
        ProxyHandle::Unix {
            path: tmp.join("proxy.sock"),
            port: BRIDGE_PORT,
        }
    } else {
        ProxyHandle::Tcp("127.0.0.1:1".parse().unwrap())
    }
}

fn audit_sink(cli: &Cli, bundle: &warden_policy::Bundle) -> Box<dyn AuditSink> {
    match cli.audit.as_deref() {
        Some("none") => Box::new(warden_audit::Null),
        Some("stderr") => Box::new(warden_audit::Stderr),
        _ => match &bundle.defaults.audit {
            #[cfg(feature = "otlp")]
            Some(a) => match warden_audit::otlp::Otlp::new(a.otlp_endpoint.as_str(), &a.headers) {
                Ok(s) => Box::new(s),
                Err(e) => {
                    eprintln!("warden: audit exporter unavailable ({e}); continuing without audit");
                    Box::new(warden_audit::Null)
                }
            },
            _ => Box::new(warden_audit::Null),
        },
    }
}

// ---------------------------------------------------------------- the launch

fn launch(
    cli: &Cli,
    harness: &str,
    model: Option<&str>,
    dry_run: bool,
    no_sandbox: bool,
    user_args: &[OsString],
) -> Result<ExitCode, Fail> {
    // 1–2. config + verified bundle
    let v = load_bundle(cli)?;
    let bundle = &v.bundle;
    let audit = audit_sink(cli, bundle);
    audit.emit(
        Event::new("policy.loaded")
            .attr("sha256", &v.sha256_hex)
            .attr("key", &v.verified_by)
            .attr("version", &bundle.meta.version),
    );

    // 3. identity
    let id = identity(cli, bundle).map_err(|e| Fail::new(EX_NOPERM, e))?;

    // 4. adapter
    let adapters = AdapterSet::load(Some(&dirs::config_dir().join("adapters")))?;
    let adapter = adapters.get(harness).map_err(|e| Fail::new(EX_USAGE, e))?;
    let located = adapter.locate().map_err(|e| Fail::new(EX_UNAVAILABLE, e))?;

    // 5. policy decisions
    let workspace = std::env::current_dir()?.canonicalize()?;
    let home = dirs::home();
    let needs = AdapterNeeds {
        hosts: adapter
            .net
            .iter()
            .map(|n| {
                (
                    n.host.clone(),
                    n.port,
                    n.purpose.clone(),
                    n.default == warden_core::adapter::NetDefault::Allow,
                )
            })
            .collect(),
        paths: adapter
            .fs
            .iter()
            .map(|f| {
                (
                    warden_core::adapter::expand_tilde(&f.path),
                    if f.access == warden_core::adapter::Access::Rw {
                        "rw"
                    } else {
                        "ro"
                    }
                    .to_string(),
                )
            })
            .collect(),
    };
    let (ents, ctx) = entities_for(&v, &id, harness, &needs)?;
    let ev = &v.evaluator;
    let principal = ev.user(&id);
    let launch_action = if no_sandbox {
        Action::LaunchUnsandboxed
    } else {
        Action::Launch
    };
    let d = ev.authorize(&ents, &principal, launch_action, &ev.harness(harness), &ctx);
    audit.emit(
        Event::new("policy.decision")
            .attr("action", launch_action.as_str())
            .attr("harness", harness)
            .attr("allowed", d.allowed)
            .attr("reason", &d.reason),
    );
    if !d.allowed {
        audit.flush(Duration::from_secs(2));
        return Err(Fail::new(
            EX_NOPERM,
            format!(
                "{} {harness} denied for {}: {}",
                launch_action.as_str(),
                id.subject,
                d.reason
            ),
        ));
    }
    let eff = ev.effective(bundle, &ents, &id, &needs, &ctx, &vars());

    let harness_formats = adapter.formats();
    let usable_models: Vec<String> = eff
        .models
        .iter()
        .filter(|m| {
            bundle
                .catalog
                .models
                .get(*m)
                .and_then(|me| bundle.providers.iter().find(|p| p.id() == me.provider))
                .is_some_and(|p| {
                    eff.providers.iter().any(|pid| pid == p.id())
                        && warden_provider::offered_formats(p)
                            .iter()
                            .any(|f| harness_formats.contains(f))
                })
        })
        .cloned()
        .collect();
    let model = match model {
        Some(m) if usable_models.iter().any(|u| u == m) => m.to_string(),
        Some(m) => {
            return Err(Fail::new(
                EX_NOPERM,
                format!(
                    "model `{m}` is not allowed for you with {harness}; allowed: {}",
                    usable_models.join(", ")
                ),
            ));
        }
        None => bundle
            .catalog
            .default_model
            .clone()
            .filter(|d| usable_models.contains(d))
            .or_else(|| usable_models.first().cloned())
            .ok_or_else(|| {
                Fail::new(
                    EX_NOPERM,
                    format!("no model is allowed for {} with {harness}", id.subject),
                )
            })?,
    };
    let provider_id = &bundle.catalog.models[&model].provider;
    let provider_cfg = bundle
        .providers
        .iter()
        .find(|p| p.id() == provider_id)
        .expect("checked above");
    let provider = warden_provider::from_config(
        provider_cfg,
        Some(warden_provider::LiteLlmHttp {
            timeout: Duration::from_secs(10),
            max_budget_usd: bundle.defaults.max_budget_usd,
        }),
    );
    audit.emit(
        Event::new("policy.effective")
            .attr("harness", harness)
            .attr("model", &model)
            .attr("provider", provider_id)
            .attr(
                "hosts",
                eff.hosts
                    .iter()
                    .map(|(h, p)| format!("{h}:{p}"))
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .attr(
                "denied_hosts",
                eff.denied_hosts
                    .iter()
                    .map(|(h, p)| format!("{h}:{p}"))
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .attr("rw", eff.read_write.join(",")),
    );

    // 6. credential (one bounded network call)
    let models_for_key: Vec<String> = usable_models
        .iter()
        .filter(|m| &bundle.catalog.models[*m].provider == provider_id)
        .cloned()
        .collect();
    let cred = if dry_run {
        warden_core::Credential {
            base_url: match provider_cfg {
                warden_core::ProviderConfig::Static { base_url, .. }
                | warden_core::ProviderConfig::Litellm { base_url, .. } => base_url.clone(),
            },
            format: *warden_provider::offered_formats(provider_cfg)
                .iter()
                .find(|f| harness_formats.contains(f))
                .unwrap(),
            secret: SecretString::from("<dry-run>"),
            expires_at: None,
            models: models_for_key.clone(),
        }
    } else {
        provider
            .issue(&IssueRequest {
                identity: &id,
                harness,
                formats: &harness_formats,
                models: &models_for_key,
                ttl: bundle.defaults.credential_ttl,
            })
            .map_err(|e| Fail::new(EX_UNAVAILABLE, e))?
    };
    audit.emit(
        Event::new("credential.issued")
            .attr("provider", provider_id)
            .attr("format", cred.format.as_str())
            .attr(
                "expires_at",
                cred.expires_at
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_default(),
            ),
    );

    // from here every early return revokes the key
    let mut revoker = (!dry_run).then(|| RevokeOnDrop {
        provider: &*provider,
        cred: &cred,
        audit: &*audit,
        done: false,
    });

    // 7. harness plan + environment
    let tmp = tempfile::Builder::new().prefix("warden-").tempdir()?;
    #[cfg(unix)]
    std::fs::set_permissions(
        tmp.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )?;
    let self_exe = std::env::current_exe()?;
    let proxy_url = match warden_sandbox::preferred_listen(tmp.path()) {
        warden_sandbox::proxy::Listen::Tcp => String::new(), // filled after the proxy binds
        warden_sandbox::proxy::Listen::Unix(_) => format!("http://127.0.0.1:{BRIDGE_PORT}"),
    };
    let cred_sock = tmp.path().join("cred.sock");
    let lctx = LaunchContext {
        executable: located.path.clone(),
        workspace: workspace.clone(),
        data_dir: dirs::data_dir(),
        config_dir: dirs::config_dir(),
        home_dir: home.clone(),
        format: cred.format,
        base_url: cred.base_url.clone(),
        secret: cred.secret.clone(),
        model: model.clone(),
        proxy_url: proxy_url.clone(),
        key_helper_cmd: if cfg!(unix) {
            Some(format!("{} __credential", self_exe.display()))
        } else {
            None
        },
        user_args: user_args.to_vec(),
    };
    let plan = adapter.plan(&lctx)?;
    if let Some(h) = &plan.home {
        std::fs::create_dir_all(h)?;
        #[cfg(unix)]
        std::fs::set_permissions(
            h,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )?;
    }
    for p in &plan.fs_rw {
        std::fs::create_dir_all(p)?;
    }

    // Start the proxy now so the real URL is known for the environment.
    let denied_log: warden_sandbox::proxy::DeniedHook = {
        let h = harness.to_string();
        Arc::new(move |host, port| {
            eprintln!("warden: blocked connection from {h} to {host}:{port}")
        })
    };
    let mut allow_hosts: Vec<HostRule> = eff
        .hosts
        .iter()
        .map(|(h, p)| HostRule {
            host: h.clone(),
            port: *p,
        })
        .collect();
    if let Some(gw) = cred.base_url.host_str() {
        allow_hosts.push(HostRule {
            host: gw.to_string(),
            port: cred.base_url.port_or_known_default().unwrap_or(443),
        });
    }
    let proxy = if dry_run {
        None
    } else {
        Some(warden_sandbox::proxy::ProxyServer::start(
            allow_hosts.clone(),
            warden_sandbox::preferred_listen(tmp.path()),
            denied_log,
        )?)
    };
    let proxy_url = match &proxy {
        Some(p) => p.url_for_child(BRIDGE_PORT),
        None => "http://127.0.0.1:<proxy>".into(),
    };

    let mut env = warden_core::env::base_from_parent(
        std::env::vars(),
        &bundle
            .defaults
            .passthrough_env
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    env.extend(warden_core::env::proxy_vars(&proxy_url));
    env.extend(plan.env.clone());
    env.insert(
        "WARDEN_SESSION_ID".into(),
        format!(
            "{:x}",
            warden_core::now_secs() ^ u64::from(std::process::id())
        ),
    );
    env.insert("AI_AGENT_LAUNCHER".into(), "warden".into());
    let helper_in_use = plan.secret_env.is_none();
    if helper_in_use {
        env.insert(
            warden_sandbox::credsock::ENV.into(),
            cred_sock.display().to_string(),
        );
    }

    let proxy_handle = match proxy.as_ref().map(|p| &p.bound) {
        Some(warden_sandbox::proxy::Bound::Tcp(a)) => ProxyHandle::Tcp(*a),
        Some(warden_sandbox::proxy::Bound::Unix(p)) => ProxyHandle::Unix {
            path: p.clone(),
            port: BRIDGE_PORT,
        },
        None => warden_sandbox_proxy_handle(tmp.path()),
    };
    let mut deny_read = warden_core::launch::default_deny_read(&home);
    deny_read.extend(eff.deny_read.iter().map(PathBuf::from));
    deny_read.retain(|d| d.exists());
    deny_read.sort();
    deny_read.dedup();
    let mut read_write: Vec<PathBuf> = plan.fs_rw.clone();
    read_write.extend(
        eff.read_write
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists()),
    );
    read_write.push(tmp.path().to_path_buf());
    if let Some(t) = env.get("TMPDIR").map(PathBuf::from).filter(|p| p.is_dir()) {
        read_write.push(t);
    }
    read_write.sort();
    read_write.dedup();
    refuse_roots_containing_warden_paths(&read_write, cli)?;
    let spec = SandboxSpec {
        workspace: workspace.clone(),
        read_only: plan.fs_ro.clone(),
        read_write,
        deny_read,
        network: NetworkSpec {
            allow_hosts,
            proxy: proxy_handle,
            allow_local_binding: false,
        },
        env: env.clone(),
        cwd: workspace.clone(),
    };

    if dry_run {
        print_plan(&plan, &spec, &located, &model, provider_id);
        return Ok(ExitCode::SUCCESS);
    }
    plan.write_emits()?;

    // 8. sandbox preflight
    let sandbox: Box<dyn Sandbox> = if no_sandbox {
        Box::new(warden_sandbox::unsandboxed::NoSandbox)
    } else {
        warden_sandbox::native()
    };
    if let Err(e) = sandbox.preflight(&spec) {
        audit.emit(
            Event::new("sandbox.preflight_failed")
                .attr("backend", sandbox.name())
                .attr("error", &e),
        );
        audit.flush(Duration::from_secs(2));
        return Err(Fail::new(EX_UNAVAILABLE, e));
    }
    if no_sandbox {
        eprintln!(
            "warden: WARNING running {harness} WITHOUT a sandbox (permitted by policy for {})",
            id.subject
        );
    }

    // credential socket (only when the harness uses the helper)
    #[cfg(unix)]
    let _cred_server = if helper_in_use {
        Some(warden_sandbox::credsock::CredentialServer::start(
            &cred_sock,
            cred.secret.clone(),
        )?)
    } else {
        None
    };

    // 9. spawn
    let mut argv = plan.argv.clone();
    argv[0] = located.path.clone().into();
    let mut spec = spec;
    spec.env = {
        let mut e = env;
        e.extend(plan.env_with_secret());
        e
    };
    let mut child = sandbox
        .spawn(&spec, &argv)
        .map_err(|e| Fail::new(EX_UNAVAILABLE, e))?;
    // before anything slow (the audit sink), so an early SIGTERM is relayed, not fatal
    #[cfg(unix)]
    install_signal_forwarding(child.pid, child.signal_fd);
    audit.emit(
        Event::new("harness.launch")
            .attr("harness", harness)
            .attr(
                "version",
                located.version.map(|v| v.to_string()).unwrap_or_default(),
            )
            .attr("model", &model)
            .attr("provider", provider_id)
            .attr("sandbox", sandbox.name())
            .attr("workspace", workspace.display())
            .attr("pid", child.pid),
    );

    // 10. supervise
    let status = sandbox.wait(&mut child).map_err(|e| Fail::new(1, e))?;

    // 11. exit
    if let Some(r) = &mut revoker {
        r.revoke();
    }
    #[cfg(unix)]
    let code = warden_sandbox::exit_code(status);
    #[cfg(not(unix))]
    let code = status.code().unwrap_or(1);
    audit.emit(
        Event::new("harness.exit")
            .attr("harness", harness)
            .attr("code", code),
    );
    audit.flush(Duration::from_secs(3));
    drop(proxy);
    Ok(ExitCode::from(code.clamp(0, 255) as u8))
}

fn print_plan(
    plan: &warden_core::HarnessPlan,
    spec: &SandboxSpec,
    located: &warden_core::adapter::Located,
    model: &str,
    provider: &str,
) {
    println!(
        "harness:   {} ({})",
        located.path.display(),
        located
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".into())
    );
    println!(
        "model:     {model} via provider {provider} ({})",
        plan.format.as_str()
    );
    println!(
        "argv:      {}",
        plan.argv
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("workspace: {}", spec.workspace.display());
    println!(
        "home:      {}",
        plan.home
            .as_ref()
            .map(|h| h.display().to_string())
            .unwrap_or_default()
    );
    println!("\nenv:");
    for (k, v) in &spec.env {
        println!("  {k}={v}");
    }
    if let Some((k, _)) = &plan.secret_env {
        println!("  {k}=<secret>");
    } else {
        println!(
            "  (credential served via {} helper socket, never in env)",
            warden_sandbox::credsock::ENV
        );
    }
    println!("\nwritable:");
    for p in &spec.read_write {
        println!("  {}", p.display());
    }
    println!("deny read:");
    for p in &spec.deny_read {
        println!("  {}", p.display());
    }
    println!("hosts:");
    for h in &spec.network.allow_hosts {
        println!("  {}:{}", h.host, h.port);
    }
    println!("emits:");
    for e in &plan.emits {
        println!(
            "  {} ({:?} {:?} key={:?})",
            e.path.display(),
            e.format,
            e.merge,
            e.key
        );
    }
    let _ = plan
        .secret_env
        .as_ref()
        .map(|(_, s)| s.expose_secret().len());
}

#[cfg(unix)]
fn install_signal_forwarding(pid: u32, signal_fd: Option<i32>) {
    use std::sync::atomic::{AtomicI32, Ordering};
    static CHILD: AtomicI32 = AtomicI32::new(0);
    static SIGNAL_FD: AtomicI32 = AtomicI32::new(-1);
    CHILD.store(pid as i32, Ordering::SeqCst);
    SIGNAL_FD.store(signal_fd.unwrap_or(-1), Ordering::SeqCst);
    extern "C" fn forward(sig: libc::c_int) {
        let fd = SIGNAL_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            // Linux: bwrap would die on the signal, so the in-sandbox helper relays it.
            let byte = sig as u8;
            // SAFETY: async-signal-safe write of one byte from a live local.
            unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
            return;
        }
        let pid = CHILD.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: async-signal-safe syscall with a pid we own.
            unsafe { libc::kill(pid, sig) };
        }
    }
    // SAFETY: installing plain handlers; `forward` only calls write(2) or kill(2).
    unsafe {
        libc::signal(libc::SIGTERM, forward as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, forward as *const () as libc::sighandler_t);
        // The tty delivers SIGINT to the whole foreground group; the harness handles it.
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_resolves_ancestors_of_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(dir.path()).unwrap();
        // missing tail under a (possibly symlinked, e.g. macOS /var) tempdir
        assert_eq!(
            norm(&dir.path().join("new/sub")),
            real.join("new").join("sub")
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
            assert_eq!(norm(&dir.path().join("link/new")), real.join("new"));
        }
        // relative paths become absolute
        let cwd = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(
            norm(Path::new("warden-missing/x")),
            cwd.join("warden-missing").join("x")
        );
    }

    #[test]
    fn windows_form_strips_verbatim_and_lowercases() {
        assert_eq!(
            windows_form(r"\\?\C:\Users\Me"),
            PathBuf::from(r"c:\users\me")
        );
        assert_eq!(windows_form(r"C:\Users\Me"), PathBuf::from(r"c:\users\me"));
        assert_eq!(
            windows_form(r"\\?\UNC\Srv\Share"),
            PathBuf::from(r"\\srv\share")
        );
    }
}
