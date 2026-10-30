use std::process::ExitCode;

use crate::{Cli, Fail, dirs, run};

fn line(ok: bool, what: &str, detail: impl std::fmt::Display) {
    println!("{} {what}: {detail}", if ok { "ok  " } else { "FAIL" });
}

pub fn run(cli: &Cli) -> Result<ExitCode, Fail> {
    let mut all_ok = true;
    println!(
        "warden {} on {}",
        env!("CARGO_PKG_VERSION"),
        dirs::os_name()
    );
    println!("config dir: {}", dirs::config_dir().display());
    println!("data dir:   {}", dirs::data_dir().display());

    let tk = dirs::trusted_keys_path(cli.trusted_keys.as_ref());
    match warden_policy::read_trusted_keys(&tk) {
        Ok(k) => line(
            true,
            "trusted keys",
            format!("{} key(s) in {}", k.len(), tk.display()),
        ),
        Err(e) => {
            all_ok = false;
            line(false, "trusted keys", e);
        }
    }
    let bundle = match run::load_bundle(cli) {
        Ok(v) => {
            line(
                true,
                "policy bundle",
                format!(
                    "v{} from {} (sha256 {}…)",
                    v.bundle.meta.version,
                    v.bundle.meta.issuer,
                    &v.sha256_hex[..12]
                ),
            );
            if v.is_past_not_after() {
                println!("warn policy bundle is past not_after; running on grace");
            }
            Some(v)
        }
        Err(e) => {
            all_ok = false;
            line(false, "policy bundle", e.msg);
            None
        }
    };
    if let Some(v) = &bundle {
        match run::identity(cli, &v.bundle) {
            Ok(id) => line(
                true,
                "identity",
                format!("{} groups={}", id.subject, id.groups.join(",")),
            ),
            Err(e) => line(false, "identity", e),
        }
    }

    let sb = warden_sandbox::native();
    let tmp = tempfile::tempdir()?;
    let mut spec = run::probe_spec(tmp.path());
    spec.sandbox_allow_degraded = bundle
        .as_ref()
        .is_some_and(|v| v.bundle.defaults.sandbox_allow_degraded);
    match sb.preflight(&spec) {
        Ok(()) => {
            line(true, "sandbox", sb.name());
            if let Some(w) = sb.degraded() {
                println!("warn sandbox: {w}");
            }
        }
        Err(e) => {
            all_ok = false;
            line(false, "sandbox", e);
        }
    }

    let adapters = warden_core::AdapterSet::load(Some(&dirs::config_dir().join("adapters")))?;
    for id in adapters.ids() {
        let a = adapters.get(id)?;
        match a.locate() {
            Ok(l) => line(
                true,
                &format!("harness {id}"),
                format!(
                    "{} {}",
                    l.path.display(),
                    l.version
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "(version unknown)".into())
                ),
            ),
            Err(e) => println!("--   harness {id}: {e}"),
        }
        for (_, inj) in &a.inject {
            for req in &inj.requires {
                if let Some(ext) = req.strip_prefix("extension:") {
                    let home = dirs::data_dir().join("homes").join(id);
                    let found = home.join("extensions").join(ext).exists()
                        || home.join("settings.json").exists()
                            && std::fs::read_to_string(home.join("settings.json"))
                                .unwrap_or_default()
                                .contains(ext);
                    println!(
                        "{}   harness {id}: extension {ext} {}",
                        if found { "ok" } else { "--" },
                        if found {
                            "installed"
                        } else {
                            "not installed in warden home"
                        }
                    );
                }
            }
        }
    }
    for (name, path) in native_managed_configs() {
        println!(
            "info {name} managed config {}: {}",
            path,
            if std::path::Path::new(path).exists() {
                "present"
            } else {
                "absent"
            }
        );
    }
    Ok(if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn native_managed_configs() -> Vec<(&'static str, &'static str)> {
    if cfg!(target_os = "macos") {
        vec![
            (
                "claude-code",
                "/Library/Application Support/ClaudeCode/managed-settings.json",
            ),
            ("codex", "/etc/codex/requirements.toml"),
        ]
    } else if cfg!(target_os = "linux") {
        vec![
            ("claude-code", "/etc/claude-code/managed-settings.json"),
            ("codex", "/etc/codex/requirements.toml"),
        ]
    } else {
        vec![
            (
                "claude-code",
                r"C:\Program Files\ClaudeCode\managed-settings.json",
            ),
            ("codex", r"C:\ProgramData\OpenAI\Codex\requirements.toml"),
        ]
    }
}
