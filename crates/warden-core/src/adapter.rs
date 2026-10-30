//! Harness adapters: declarative TOML describing how a harness is located, told
//! where its home is, given a base URL and key, kept quiet, and what extra files
//! and hosts it needs. Embedded at build time, overridable from disk.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use crate::template::{self, Vars};
use crate::types::{ApiFormat, HostRule};

pub const EMBEDDED: &[(&str, &str)] = &[
    (
        "claude-code",
        include_str!("../../../adapters/claude-code.toml"),
    ),
    ("codex", include_str!("../../../adapters/codex.toml")),
    ("opencode", include_str!("../../../adapters/opencode.toml")),
    ("pi", include_str!("../../../adapters/pi.toml")),
];

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("adapter `{id}`: {source}")]
    Parse { id: String, source: toml::de::Error },
    #[error("adapter `{id}`: {msg}")]
    Invalid { id: String, msg: String },
    #[error("unknown harness `{0}`")]
    Unknown(String),
    #[error("harness `{id}` executable `{exe}` not found; {hint}")]
    NotFound {
        id: String,
        exe: String,
        hint: String,
    },
    #[error("harness `{id}` version {found} is older than required {min}")]
    TooOld {
        id: String,
        found: String,
        min: String,
    },
    #[error("adapter `{id}` cannot inject any of the provider's formats {formats:?}")]
    NoInject { id: String, formats: Vec<ApiFormat> },
    #[error("template error in adapter `{id}`: {source}")]
    Template {
        id: String,
        source: template::TemplateError,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("emitted {path}: {msg}")]
    Emit { path: PathBuf, msg: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    pub harness: Harness,
    #[serde(default)]
    pub detect: Detect,
    pub home: Option<Home>,
    /// Keyed by API format; TOML table order is preserved for preference.
    #[serde(default)]
    pub inject: Vec<(ApiFormat, Inject)>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub fs: Vec<FsRule>,
    #[serde(default)]
    pub net: Vec<NetNeed>,
    #[serde(default)]
    pub emit: Vec<Emit>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Harness {
    pub id: String,
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub version_args: Vec<String>,
    pub min_version: Option<semver::Version>,
    pub install_hint: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    #[serde(default)]
    pub candidates: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Home {
    pub env: String,
    pub default: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inject {
    pub base_url_env: Option<String>,
    /// Appended to the provider's base URL for this harness, e.g. `/v1` when its SDK
    /// adds only `/messages` itself. Harnesses disagree on what "base URL" means.
    #[serde(default)]
    pub base_url_suffix: String,
    pub key_env: String,
    pub key_helper_env: Option<String>,
    #[serde(default)]
    pub extra_env: BTreeMap<String, String>,
    pub model_env: Option<String>,
    #[serde(default)]
    pub model_args: Vec<String>,
    pub native_api: Option<String>,
    #[serde(default)]
    pub requires: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Ro,
    Rw,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsRule {
    pub path: String,
    pub access: Access,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetNeed {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub purpose: String,
    pub default: NetDefault,
}

fn default_port() -> u16 {
    443
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetDefault {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Emit {
    pub path: String,
    pub format: EmitFormat,
    pub merge: Merge,
    pub key: Option<String>,
    pub template: String,
    /// Only emit when the chosen inject format is one of these; empty = always.
    #[serde(default)]
    pub when_format: Vec<ApiFormat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmitFormat {
    Json,
    Toml,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Merge {
    ReplaceKey,
    Overwrite,
    CreateIfMissing,
}

// TOML `[inject.<format>]` tables arrive as a map; keep file order.
impl<'de> Deserialize<'de> for InjectMap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw: toml::Table = Deserialize::deserialize(d)?;
        let mut out = Vec::new();
        for (k, v) in raw {
            let f: ApiFormat = k.parse().map_err(serde::de::Error::custom)?;
            let inj: Inject = v.try_into().map_err(serde::de::Error::custom)?;
            out.push((f, inj));
        }
        Ok(InjectMap(out))
    }
}
struct InjectMap(Vec<(ApiFormat, Inject)>);

impl std::str::FromStr for ApiFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        serde_json::from_value(serde_json::Value::String(s.into()))
            .map_err(|_| format!("unknown api format `{s}`"))
    }
}

impl Adapter {
    pub fn parse(id_hint: &str, text: &str) -> Result<Self, AdapterError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            harness: Harness,
            #[serde(default)]
            detect: Detect,
            home: Option<Home>,
            inject: Option<InjectMap>,
            #[serde(default)]
            env: BTreeMap<String, String>,
            #[serde(default)]
            fs: Vec<FsRule>,
            #[serde(default)]
            net: Vec<NetNeed>,
            #[serde(default)]
            emit: Vec<Emit>,
        }
        let raw: Raw = toml::from_str(text).map_err(|source| AdapterError::Parse {
            id: id_hint.into(),
            source,
        })?;
        let a = Adapter {
            harness: raw.harness,
            detect: raw.detect,
            home: raw.home,
            inject: raw.inject.map(|m| m.0).unwrap_or_default(),
            env: raw.env,
            fs: raw.fs,
            net: raw.net,
            emit: raw.emit,
        };
        a.validate()?;
        Ok(a)
    }

    fn validate(&self) -> Result<(), AdapterError> {
        let id = &self.harness.id;
        let bad = |msg: String| AdapterError::Invalid {
            id: id.clone(),
            msg,
        };
        if self.inject.is_empty() {
            return Err(bad(
                "at least one [inject.<format>] table is required".into()
            ));
        }
        for e in &self.emit {
            if e.merge == Merge::ReplaceKey && e.key.is_none() {
                return Err(bad(format!("emit {}: replace-key needs `key`", e.path)));
            }
            if e.template.contains("${key}") || e.template.contains("${secret}") {
                return Err(bad(format!(
                    "emit {}: templates may not reference the secret",
                    e.path
                )));
            }
        }
        for (f, inj) in &self.inject {
            let carried = inj.base_url_env.is_some()
                || inj.extra_env.values().any(|v| v.contains("${base_url}"))
                || self.emit.iter().any(|e| {
                    e.template.contains("${base_url}")
                        && (e.when_format.is_empty() || e.when_format.contains(f))
                });
            if !carried {
                return Err(bad(format!(
                    "inject.{}: nothing carries ${{base_url}} to the harness",
                    f.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Resolve the executable: `[detect].candidates` first, then PATH.
    pub fn locate(&self) -> Result<Located, AdapterError> {
        let exe = &self.harness.executable;
        let path = self
            .detect
            .candidates
            .iter()
            .map(|c| PathBuf::from(expand_tilde(c)))
            .find(|p| p.is_file())
            .or_else(|| find_on_path(exe))
            .ok_or_else(|| AdapterError::NotFound {
                id: self.harness.id.clone(),
                exe: exe.clone(),
                hint: self
                    .harness
                    .install_hint
                    .clone()
                    .unwrap_or_else(|| "install it and retry".into()),
            })?;
        let version = self.probe_version(&path);
        if let (Some(min), Some(v)) = (&self.harness.min_version, &version)
            && v < min
        {
            return Err(AdapterError::TooOld {
                id: self.harness.id.clone(),
                found: v.to_string(),
                min: min.to_string(),
            });
        }
        Ok(Located { path, version })
    }

    fn probe_version(&self, path: &Path) -> Option<semver::Version> {
        if self.harness.version_args.is_empty() {
            return None;
        }
        let out = std::process::Command::new(path)
            .args(&self.harness.version_args)
            .env("NO_COLOR", "1")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',')
            .filter_map(|t| semver::Version::parse(t.trim_start_matches('v')).ok())
            .next()
    }

    /// Pick the inject table for the first format (in adapter order) the provider offers.
    pub fn choose_inject(
        &self,
        offered: &[ApiFormat],
    ) -> Result<(ApiFormat, &Inject), AdapterError> {
        self.inject
            .iter()
            .find(|(f, _)| offered.contains(f))
            .map(|(f, i)| (*f, i))
            .ok_or_else(|| AdapterError::NoInject {
                id: self.harness.id.clone(),
                formats: offered.to_vec(),
            })
    }

    pub fn formats(&self) -> Vec<ApiFormat> {
        self.inject.iter().map(|(f, _)| *f).collect()
    }

    /// Build the concrete launch plan. Writes nothing; `HarnessPlan::write_emits` does.
    pub fn plan(&self, ctx: &LaunchContext) -> Result<HarnessPlan, AdapterError> {
        let id = self.harness.id.clone();
        let (format, inject) = self.choose_inject(&[ctx.format])?;
        let home = self
            .home
            .as_ref()
            .map(|h| expand_tilde(&h.default))
            .map(|d| template::expand(&d, &ctx.vars_base()))
            .transpose()
            .map_err(|source| AdapterError::Template {
                id: id.clone(),
                source,
            })?
            .map(PathBuf::from);

        let mut vars = ctx.vars_base();
        if let Some(h) = &home {
            vars.insert("home".into(), h.display().to_string());
        }
        vars.insert(
            "base_url".into(),
            format!(
                "{}{}",
                ctx.base_url.as_str().trim_end_matches('/'),
                inject.base_url_suffix
            ),
        );
        vars.insert("key_env".into(), inject.key_env.clone());
        vars.insert("model".into(), ctx.model.clone());
        vars.insert("api".into(), inject.native_api.clone().unwrap_or_default());
        let helper_active = inject.key_helper_env.is_some() && ctx.key_helper_cmd.is_some();
        let helper_cmd = ctx
            .key_helper_cmd
            .clone()
            .filter(|_| helper_active)
            .unwrap_or_default();
        vars.insert("key_helper_cmd".into(), helper_cmd.clone());
        vars.insert(
            "key_helper_json".into(),
            if helper_active {
                serde_json::Value::String(helper_cmd).to_string()
            } else {
                "null".into()
            },
        );
        let ex = |s: &str| {
            template::expand(s, &vars).map_err(|source| AdapterError::Template {
                id: id.clone(),
                source,
            })
        };

        let mut env = BTreeMap::new();
        for (k, v) in &self.env {
            env.insert(k.clone(), ex(v)?);
        }
        for (k, v) in &inject.extra_env {
            env.insert(k.clone(), ex(v)?);
        }
        if let (Some(h), Some(hp)) = (&self.home, &home) {
            env.insert(h.env.clone(), hp.display().to_string());
        }
        if let Some(e) = &inject.base_url_env {
            env.insert(e.clone(), vars["base_url"].clone());
        }
        if let Some(e) = &inject.model_env {
            env.insert(e.clone(), ctx.model.clone());
        }
        let secret_env = match (&inject.key_helper_env, &ctx.key_helper_cmd) {
            (Some(helper_env), Some(cmd)) => {
                env.insert(helper_env.clone(), cmd.clone());
                None
            }
            _ => Some((inject.key_env.clone(), ctx.secret.clone())),
        };

        let mut argv: Vec<OsString> = vec![ctx.executable.clone().into()];
        for a in &inject.model_args {
            argv.push(ex(a)?.into());
        }
        argv.extend(ctx.user_args.iter().cloned());

        let mut fs_rw = vec![ctx.workspace.clone()];
        let mut fs_ro = Vec::new();
        if let Some(h) = &home {
            fs_rw.push(h.clone());
        }
        for r in &self.fs {
            let p = PathBuf::from(ex(&expand_tilde(&r.path))?);
            match r.access {
                Access::Rw => fs_rw.push(p),
                Access::Ro => fs_ro.push(p),
            }
        }

        let emits = self
            .emit
            .iter()
            .filter(|e| e.when_format.is_empty() || e.when_format.contains(&format))
            .map(|e| {
                Ok(EmitFile {
                    path: PathBuf::from(ex(&expand_tilde(&e.path))?),
                    format: e.format,
                    merge: e.merge,
                    key: e.key.clone(),
                    content: ex(&e.template)?,
                })
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;

        Ok(HarnessPlan {
            format,
            argv,
            env,
            secret_env,
            home,
            fs_rw,
            fs_ro,
            net: self.net.clone(),
            emits,
            requires: inject.requires.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Located {
    pub path: PathBuf,
    pub version: Option<semver::Version>,
}

/// Everything `plan` needs from the launcher.
pub struct LaunchContext {
    pub executable: PathBuf,
    pub workspace: PathBuf,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub home_dir: PathBuf,
    pub format: ApiFormat,
    pub base_url: Url,
    pub secret: SecretString,
    pub model: String,
    pub proxy_url: String,
    /// Command the harness runs to fetch a fresh token; used when the inject table has `key_helper_env`.
    pub key_helper_cmd: Option<String>,
    pub user_args: Vec<OsString>,
}

impl LaunchContext {
    fn vars_base(&self) -> Vars {
        [
            ("workspace", self.workspace.display().to_string()),
            ("WARDEN_DATA", self.data_dir.display().to_string()),
            ("WARDEN_CONFIG", self.config_dir.display().to_string()),
            ("HOME", self.home_dir.display().to_string()),
            ("proxy_url", self.proxy_url.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }
}

#[derive(Debug, Clone)]
pub struct EmitFile {
    pub path: PathBuf,
    pub format: EmitFormat,
    pub merge: Merge,
    pub key: Option<String>,
    pub content: String,
}

pub struct HarnessPlan {
    pub format: ApiFormat,
    pub argv: Vec<OsString>,
    /// Non-secret environment.
    pub env: BTreeMap<String, String>,
    /// The one variable carrying the credential, kept apart so nothing prints it by accident.
    pub secret_env: Option<(String, SecretString)>,
    pub home: Option<PathBuf>,
    pub fs_rw: Vec<PathBuf>,
    pub fs_ro: Vec<PathBuf>,
    pub net: Vec<NetNeed>,
    pub emits: Vec<EmitFile>,
    pub requires: Vec<String>,
}

impl HarnessPlan {
    /// Full child environment including the secret. Call once, at spawn.
    pub fn env_with_secret(&self) -> BTreeMap<String, String> {
        let mut env = self.env.clone();
        if let Some((k, v)) = &self.secret_env {
            env.insert(k.clone(), v.expose_secret().to_string());
        }
        env
    }

    pub fn write_emits(&self) -> Result<(), AdapterError> {
        for e in &self.emits {
            write_emit(e)?;
        }
        Ok(())
    }

    pub fn host_rules(&self, allowed: impl Fn(&NetNeed) -> bool) -> Vec<HostRule> {
        self.net
            .iter()
            .filter(|n| allowed(n))
            .map(|n| HostRule {
                host: n.host.clone(),
                port: n.port,
            })
            .collect()
    }
}

fn write_emit(e: &EmitFile) -> Result<(), AdapterError> {
    if let Some(dir) = e.path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let exists = e.path.exists();
    if e.merge == Merge::CreateIfMissing && exists {
        return Ok(());
    }
    let out = match (e.format, e.merge) {
        (EmitFormat::Json, Merge::ReplaceKey) => {
            let mut doc: serde_json::Value = if exists {
                serde_json::from_str(&std::fs::read_to_string(&e.path)?).map_err(|err| {
                    AdapterError::Emit {
                        path: e.path.clone(),
                        msg: err.to_string(),
                    }
                })?
            } else {
                serde_json::json!({})
            };
            let val: serde_json::Value =
                serde_json::from_str(&e.content).map_err(|err| AdapterError::Emit {
                    path: e.path.clone(),
                    msg: err.to_string(),
                })?;
            set_json_path(&mut doc, e.key.as_deref().unwrap_or_default(), val);
            serde_json::to_string_pretty(&doc).expect("json") + "\n"
        }
        (EmitFormat::Toml, Merge::ReplaceKey) => {
            let mut doc: toml::Table = if exists {
                toml::from_str(&std::fs::read_to_string(&e.path)?).map_err(|err| {
                    AdapterError::Emit {
                        path: e.path.clone(),
                        msg: err.to_string(),
                    }
                })?
            } else {
                toml::Table::new()
            };
            let val: toml::Table =
                toml::from_str(&e.content).map_err(|err| AdapterError::Emit {
                    path: e.path.clone(),
                    msg: err.to_string(),
                })?;
            set_toml_path(
                &mut doc,
                e.key.as_deref().unwrap_or_default(),
                toml::Value::Table(val),
            );
            toml::to_string(&doc).expect("toml")
        }
        (EmitFormat::Json, _) => {
            serde_json::from_str::<serde_json::Value>(&e.content).map_err(|err| {
                AdapterError::Emit {
                    path: e.path.clone(),
                    msg: err.to_string(),
                }
            })?;
            e.content.clone()
        }
        (EmitFormat::Toml, _) => {
            toml::from_str::<toml::Table>(&e.content).map_err(|err| AdapterError::Emit {
                path: e.path.clone(),
                msg: err.to_string(),
            })?;
            e.content.clone()
        }
        (EmitFormat::Text, _) => e.content.clone(),
    };
    std::fs::write(&e.path, out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&e.path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// `key = "."` shallow-merges the template's top-level keys; a `null` value removes a key.
fn set_json_path(doc: &mut serde_json::Value, key: &str, val: serde_json::Value) {
    if key == "." {
        if !doc.is_object() {
            *doc = serde_json::json!({});
        }
        if let serde_json::Value::Object(m) = val {
            for (k, v) in m {
                set_json_path(doc, &k, v);
            }
        }
        return;
    }
    if val.is_null() {
        let (parent, last) = key.rsplit_once('.').unwrap_or(("", key));
        let target = if parent.is_empty() {
            Some(&mut *doc)
        } else {
            doc.pointer_mut(&format!("/{}", parent.replace('.', "/")))
        };
        if let Some(serde_json::Value::Object(m)) = target {
            m.remove(last);
        }
        return;
    }
    let mut cur = doc;
    let mut parts = key.split('.').peekable();
    while let Some(p) = parts.next() {
        if !cur.is_object() {
            *cur = serde_json::json!({});
        }
        let obj = cur.as_object_mut().expect("object");
        if parts.peek().is_none() {
            obj.insert(p.into(), val);
            return;
        }
        cur = obj.entry(p).or_insert_with(|| serde_json::json!({}));
    }
}

fn set_toml_path(doc: &mut toml::Table, key: &str, val: toml::Value) {
    if key == "." {
        if let toml::Value::Table(t) = val {
            for (k, v) in t {
                doc.insert(k, v);
            }
        }
        return;
    }
    let mut cur = doc;
    let mut parts = key.split('.').peekable();
    while let Some(p) = parts.next() {
        if parts.peek().is_none() {
            cur.insert(p.into(), val);
            return;
        }
        let next = cur
            .entry(p)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !next.is_table() {
            *next = toml::Value::Table(toml::Table::new());
        }
        cur = next.as_table_mut().expect("table");
    }
}

pub fn expand_tilde(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            Some(h) => format!("{}/{rest}", h.to_string_lossy()),
            None => p.to_string(),
        },
        None => p.to_string(),
    }
}

/// Names to try for `exe` in one PATH directory. On Windows the PATHEXT
/// spellings come first: npm installs both an extensionless sh shim `claude`
/// (not runnable by CreateProcess) and `claude.cmd`.
fn path_candidates(dir: &Path, exe: &str, pathext: Option<&str>) -> Vec<PathBuf> {
    pathext
        .into_iter()
        .flat_map(|exts| exts.split(';').filter(|e| !e.is_empty()))
        .map(|ext| dir.join(format!("{exe}{ext}")))
        .chain([dir.join(exe)])
        .collect()
}

fn find_on_path(exe: &str) -> Option<PathBuf> {
    let p = Path::new(exe);
    if p.is_absolute() {
        return p.is_file().then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    let pathext = cfg!(windows)
        .then(|| std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into()));
    std::env::split_paths(&path)
        .flat_map(|d| path_candidates(&d, exe, pathext.as_deref()))
        .find(|c| c.is_file())
}

/// All adapters: embedded, then `<dir>/*.toml` replacing by id.
pub struct AdapterSet {
    adapters: BTreeMap<String, Adapter>,
}

impl AdapterSet {
    pub fn load(overrides_dir: Option<&Path>) -> Result<Self, AdapterError> {
        let mut adapters = BTreeMap::new();
        for (id, text) in EMBEDDED {
            let a = Adapter::parse(id, text)?;
            adapters.insert(a.harness.id.clone(), a);
        }
        if let Some(dir) = overrides_dir
            && let Ok(rd) = std::fs::read_dir(dir)
        {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|e| e == "toml") {
                    let text = std::fs::read_to_string(&p)?;
                    let a = Adapter::parse(&p.display().to_string(), &text)?;
                    adapters.insert(a.harness.id.clone(), a);
                }
            }
        }
        Ok(Self { adapters })
    }

    pub fn get(&self, id: &str) -> Result<&Adapter, AdapterError> {
        self.adapters
            .get(id)
            .ok_or_else(|| AdapterError::Unknown(id.into()))
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.adapters.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(format: ApiFormat, tmp: &Path) -> LaunchContext {
        LaunchContext {
            executable: "/usr/bin/true".into(),
            workspace: tmp.join("ws"),
            data_dir: tmp.join("data"),
            config_dir: tmp.join("cfg"),
            home_dir: tmp.to_path_buf(),
            format,
            base_url: "https://gw.example.com/".parse().unwrap(),
            secret: SecretString::from("sk-secret"),
            model: "claude-sonnet-5".into(),
            proxy_url: "http://127.0.0.1:1".into(),
            key_helper_cmd: Some("/opt/warden __credential".into()),
            user_args: vec!["--foo".into()],
        }
    }

    #[test]
    fn every_embedded_adapter_parses() {
        let set = AdapterSet::load(None).unwrap();
        let ids: Vec<_> = set.ids().collect();
        assert_eq!(ids, ["claude-code", "codex", "opencode", "pi"]);
    }

    #[test]
    fn pi_litellm_plan_uses_key_helper_and_emits_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let pi = AdapterSet::load(None).unwrap().get("pi").unwrap().clone();
        let plan = pi.plan(&ctx(ApiFormat::Litellm, tmp.path())).unwrap();
        assert_eq!(plan.env["LITELLM_BASE_URL"], "https://gw.example.com");
        assert!(plan.secret_env.is_none(), "key must not be in env");
        assert_eq!(
            plan.env["LITELLM_API_KEY_HELPER"],
            "/opt/warden __credential"
        );
        assert_eq!(plan.env["LITELLM_STARTUP_KEY_HELPER"], "1");
        assert!(
            !plan.env.contains_key("PI_OFFLINE"),
            "litellm table must not go offline"
        );
        let argv: Vec<String> = plan
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into())
            .collect();
        assert_eq!(
            argv,
            [
                "/usr/bin/true",
                "--model",
                "litellm/claude-sonnet-5",
                "--foo"
            ]
        );
        assert!(plan.emits.is_empty());
        assert_eq!(
            plan.home.as_deref(),
            Some(tmp.path().join("data/homes/pi").as_path())
        );
    }

    #[test]
    fn pi_anthropic_plan_emits_models_json_without_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let pi = AdapterSet::load(None).unwrap().get("pi").unwrap().clone();
        let mut c = ctx(ApiFormat::AnthropicMessages, tmp.path());
        c.key_helper_cmd = None;
        let plan = pi.plan(&c).unwrap();
        let (k, _) = plan.secret_env.as_ref().unwrap();
        assert_eq!(k, "ANTHROPIC_API_KEY");
        assert_eq!(plan.emits.len(), 1);
        // pre-existing content survives replace-key
        let path = &plan.emits[0].path;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, r#"{"providers":{"other":{"baseUrl":"x"}}}"#).unwrap();
        plan.write_emits().unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(doc["providers"]["other"]["baseUrl"], "x");
        assert_eq!(doc["providers"]["warden"]["apiKey"], "$ANTHROPIC_API_KEY");
        assert_eq!(
            doc["providers"]["warden"]["baseUrl"],
            "https://gw.example.com"
        );
        assert!(!std::fs::read_to_string(path).unwrap().contains("sk-secret"));
    }

    #[test]
    fn claude_code_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let a = AdapterSet::load(None)
            .unwrap()
            .get("claude-code")
            .unwrap()
            .clone();
        let plan = a
            .plan(&ctx(ApiFormat::AnthropicMessages, tmp.path()))
            .unwrap();
        assert_eq!(plan.env["ANTHROPIC_BASE_URL"], "https://gw.example.com");
        assert_eq!(plan.env["ANTHROPIC_MODEL"], "claude-sonnet-5");
        assert_eq!(plan.env["DISABLE_AUTOUPDATER"], "1");
        assert!(plan.env.contains_key("CLAUDE_CONFIG_DIR"));
        // apiKeyHelper goes into emitted settings.json
        plan.write_emits().unwrap();
        let settings: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&plan.emits[0].path).unwrap()).unwrap();
        assert_eq!(settings["apiKeyHelper"], "/opt/warden __credential");
        assert!(plan.secret_env.is_none());
        // without a helper the key goes to env and the stale apiKeyHelper is removed
        let mut c = ctx(ApiFormat::AnthropicMessages, tmp.path());
        c.key_helper_cmd = None;
        let plan = a.plan(&c).unwrap();
        plan.write_emits().unwrap();
        let settings: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&plan.emits[0].path).unwrap()).unwrap();
        assert!(settings.get("apiKeyHelper").is_none(), "{settings}");
        assert_eq!(plan.secret_env.as_ref().unwrap().0, "ANTHROPIC_API_KEY");
    }

    #[test]
    fn codex_and_opencode_plans() {
        let tmp = tempfile::tempdir().unwrap();
        let set = AdapterSet::load(None).unwrap();
        let codex = set
            .get("codex")
            .unwrap()
            .plan(&ctx(ApiFormat::OpenaiResponses, tmp.path()))
            .unwrap();
        assert_eq!(codex.secret_env.as_ref().unwrap().0, "OPENAI_API_KEY");
        assert!(codex.env.contains_key("CODEX_HOME"));
        codex.write_emits().unwrap();
        let cfg = std::fs::read_to_string(codex.emits[0].path.clone()).unwrap();
        assert!(cfg.contains("[model_providers.warden]"), "{cfg}");
        assert!(cfg.contains("env_key = \"OPENAI_API_KEY\""));
        assert!(cfg.contains("model_provider = \"warden\""));
        assert!(cfg.contains("wire_api = \"responses\""));

        let oc = set
            .get("opencode")
            .unwrap()
            .plan(&ctx(ApiFormat::AnthropicMessages, tmp.path()))
            .unwrap();
        let content = &oc.env["OPENCODE_CONFIG_CONTENT"];
        let v: serde_json::Value = serde_json::from_str(content).unwrap();
        assert_eq!(
            v["provider"]["warden"]["options"]["apiKey"],
            "{env:ANTHROPIC_API_KEY}"
        );
        assert_eq!(v["provider"]["warden"]["npm"], "@ai-sdk/anthropic");
    }

    #[test]
    fn rejects_secret_in_template() {
        let text = r#"
[harness]
id = "x"
name = "x"
executable = "x"
[inject.openai-chat]
base_url_env = "B"
key_env = "K"
[[emit]]
path = "${home}/f"
format = "text"
merge = "overwrite"
template = "${key}"
"#;
        assert!(matches!(
            Adapter::parse("x", text),
            Err(AdapterError::Invalid { .. })
        ));
    }

    #[test]
    fn choose_inject_prefers_adapter_order() {
        let pi = AdapterSet::load(None).unwrap().get("pi").unwrap().clone();
        let (f, _) = pi
            .choose_inject(&[ApiFormat::AnthropicMessages, ApiFormat::Litellm])
            .unwrap();
        assert_eq!(f, ApiFormat::Litellm);
        assert!(pi.choose_inject(&[]).is_err());
    }

    #[test]
    fn path_candidates_prefer_pathext_over_the_bare_name() {
        let dir = Path::new("bin");
        assert_eq!(
            path_candidates(dir, "claude", Some(".EXE;.CMD;")),
            [
                dir.join("claude.EXE"),
                dir.join("claude.CMD"),
                dir.join("claude")
            ]
        );
        assert_eq!(path_candidates(dir, "claude", None), [dir.join("claude")]);
    }
}
