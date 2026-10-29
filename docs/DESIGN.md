# warden — design

Status: draft for review. Nothing here is implemented yet.

`warden` launches an agentic coding harness (Claude Code, Codex, OpenCode, Pi, …)
inside an OS sandbox, with provider credentials injected for the current user and
with every outbound connection forced through a local allowlisting proxy. The
harness is configured as little as possible; enforcement happens around it.

Sources consulted: local checkouts of `openai/codex` (commit `d2f6d23c6`),
`anomalyco/opencode` (`5f61d2148`), `badlogic/pi` (`7fbbd5f4a`) and the
Claude Code docs at code.claude.com (2026-10). File references below point into
those checkouts.

---

## 1. Crate layout

Six crates. The suggested `warden-adapters` crate is folded into `warden-core`:
the adapter schema is ~100 lines of serde structs and the launch orchestrator is
its only consumer, so a separate crate buys nothing.

```
Cargo.toml                   # workspace, edition 2024, resolver 3
crates/
  warden-cli/        bin `warden`: clap, subcommands, signal forwarding, doctor
  warden-core/       traits (§2), adapter schema + loader (§3), launch sequence (§5),
                     embedded adapters/*.toml (include_dir or build.rs)
  warden-identity/   OIDC device flow -> Identity
  warden-provider/   StaticProvider, LiteLlmProvider
  warden-sandbox/    SandboxSpec compiler, macOS Seatbelt, Linux bwrap/Landlock/seccomp,
                     Windows stub, egress proxy
  warden-policy/     bundle format, ed25519 verification, Cedar evaluation
  warden-audit/      OTLP exporter (feature-gated; `none` sink always available)
adapters/            claude-code.toml codex.toml opencode.toml pi.toml  (source of truth, embedded at build)
tests/
  sandbox/           integration tests: read/write/connect must be blocked (CI matrix)
  conformance/       per-harness: install latest release, run under warden, assert gateway traffic
docs/
  DESIGN.md THREAT_MODEL.md
THIRD_PARTY_NOTICES.md       # codex-rs attribution
```

Dependency direction: `cli -> core -> {identity, provider, sandbox, policy, audit}`.
The leaf crates do not depend on each other; they share only the types in `warden-core`.

Binary: one static executable. The same binary re-executes itself in helper roles
(`warden __proxy-bridge`, `warden __linux-sandbox`) using the arg0 trick codex uses
(`codex-rs/arg0/src/lib.rs`), so there is no second file to install.

### Dependencies (all permissive; nothing large beyond what the brief implies)

| Need | Crate | License | Note |
|---|---|---|---|
| CLI | `clap` | MIT/Apache | |
| async runtime | `tokio` | MIT | proxy + audit only; launch path is sync |
| OIDC | `openidconnect` | MIT | has discovery + device flow (`DeviceAuthorizationUrl`, `exchange_device_code`) |
| HTTP client | `reqwest` (rustls) | MIT/Apache | pulled in by openidconnect anyway |
| policy | `cedar-policy` 4.x | Apache-2.0 | `Authorizer`, `PolicySet`, `Entities`, `Request`, `Schema` |
| signatures | `ed25519-dalek` | BSD-3 | verify only |
| serde | `serde`, `serde_json`, `toml` | MIT/Apache | |
| sandbox (Linux) | `landlock` 0.4, `seccompiler` 0.5, `libc`, `nix` | MIT/Apache | same crates codex uses |
| sandbox (macOS) | none | | shells out to `/usr/bin/sandbox-exec` with a generated profile, like codex |
| proxy | `hyper` 1.x, `tokio` | MIT | CONNECT + SOCKS5, ~400 lines, no MITM |
| keychain | `keyring` | MIT/Apache | `static` provider only |
| audit | `opentelemetry`, `opentelemetry-otlp` | Apache-2.0 | behind `--features otlp`, default on |
| tests | `portable-pty` (dev-dep) | MIT | drives interactive harnesses in conformance tests |
| release | `cargo-dist` | MIT/Apache | see open question Q6 |

Not used: Docker, Node, Python, `srt` (TypeScript, needs Node), `cedar-policy-cli`.

---

## 2. The five traits

All live in `warden-core`. They are synchronous except where a network call is
unavoidable (`Identity::login`, `Provider::issue`), and those are never on the
`warden run` hot path except for provider credential issuance, which is bounded by a
timeout and cached (§5 step 6).

### 2.1 Identity

```rust
pub struct Identity {
    pub subject: String,              // OIDC `sub`
    pub email: Option<String>,
    pub groups: Vec<String>,          // from the configured claim, verbatim
    pub id_token: SecretString,       // for providers that exchange it (LiteLLM JWT auth)
    pub expires_at: SystemTime,
}

pub trait IdentityProvider {
    /// Interactive. Runs the device-authorization flow, prints the URL + code,
    /// polls, returns the identity. Stores the refresh token in the OS keychain.
    fn login(&self, cfg: &IdentityConfig) -> Result<Identity, IdentityError>;
    /// Non-interactive. Refreshes from the keychain; `Err(NotLoggedIn)` if nothing is cached.
    fn current(&self, cfg: &IdentityConfig) -> Result<Identity, IdentityError>;
    fn logout(&self, cfg: &IdentityConfig) -> Result<(), IdentityError>;
}

pub struct IdentityConfig {
    pub issuer: Url,                  // discovery at {issuer}/.well-known/openid-configuration
    pub client_id: String,
    pub scopes: Vec<String>,          // default ["openid", "profile", "email", "groups"]
    pub groups_claim: String,         // default "groups"; Entra uses "groups", Okta "groups", Keycloak "groups" or "realm_access.roles" (dotted path supported)
}
```

One implementation: `OidcDeviceFlow`. The refresh token goes to the keychain
(`keyring` crate, service `warden`, account `<issuer>|<client_id>`). The ID token is
held in memory only. `warden run` calls `current()`, which refreshes silently; if
the refresh fails the launch stops with "run `warden login`".

### 2.2 Provider

```rust
#[derive(Clone, Copy)]
pub enum ApiFormat {
    AnthropicMessages,
    OpenAiChat,
    OpenAiResponses,
    /// The harness has first-class LiteLLM support (e.g. Pi via pi-provider-litellm):
    /// base_url is the proxy root and the harness picks the wire protocol per model itself.
    LiteLlm,
}

pub struct Credential {
    pub base_url: Url,                // e.g. https://gw.example.com (format-specific path appended by adapter)
    pub format: ApiFormat,
    pub secret: SecretString,         // zeroized on drop; never Debug-printed
    pub expires_at: Option<SystemTime>,
    pub models: Vec<String>,          // what this credential may call; informs Cedar `useModel`
}

pub struct IssueRequest<'a> {
    pub identity: &'a Identity,
    pub harness: &'a str,
    pub formats: &'a [ApiFormat],     // what the harness can speak, in preference order
    pub models: &'a [String],         // models policy allowed for this user+harness
    pub ttl: Duration,                // from policy; provider may shorten
}

pub trait Provider {
    fn id(&self) -> &str;
    /// Mint or fetch a credential. Called once per launch; may do one HTTPS round trip.
    fn issue(&self, req: &IssueRequest) -> Result<Credential, ProviderError>;
    /// Best-effort revoke at harness exit. Errors are logged, not surfaced.
    fn revoke(&self, cred: &Credential) -> Result<(), ProviderError>;
}
```

Implementations:

- `StaticProvider` — base URL and format from the policy bundle, secret from the OS
  keychain (`warden provider set-key <id>` writes it). `expires_at = None`. For
  testing and small orgs.
- `LiteLlmProvider` — offers `LiteLlm` first, then the formats the gateway exposes
  (`/anthropic` and `/v1` paths). `POST {litellm_url}/key/generate` with
  `{"duration": "<ttl>", "models": [...], "max_budget": <from policy>, "user_id": <identity.subject>, "key_alias": "warden/<sub>/<harness>/<timestamp>", "metadata": {"harness": ..., "warden_version": ...}}`.
  Authentication to the management API is the user's OIDC ID token (LiteLLM JWT
  auth, `general_settings.enable_jwt_auth`); warden never holds a LiteLLM master key.
  See open question Q3. `revoke` calls `/key/delete`.

### 2.3 Sandbox

```rust
pub struct SandboxSpec {
    pub workspace: PathBuf,                      // canonicalised
    pub read_only: Vec<PathBuf>,                 // readable in addition to the platform base set
    pub read_write: Vec<PathBuf>,                // workspace, harness home, tmp, adapter extras
    pub deny_read: Vec<PathBuf>,                 // e.g. ~/.ssh, ~/.aws, ~/.gnupg, warden's own state
    pub network: NetworkSpec,
    pub env: BTreeMap<String, String>,           // the complete child environment; nothing inherited implicitly
}

pub struct NetworkSpec {
    pub allow_hosts: Vec<HostRule>,              // exact or `*.suffix`, with optional port
    pub proxy: ProxyHandle,                      // where the egress proxy listens (TCP loopback or UDS)
    pub allow_local_binding: bool,               // dev servers inside the sandbox; default false
}

pub struct LaunchedChild {
    pub pid: u32,
    // platform handle used by `wait` and `signal`
}

pub trait Sandbox {
    fn name(&self) -> &str;
    /// Check the platform can enforce this spec (sandbox-exec present, bwrap/user-ns available, …).
    /// Returning Err stops the launch (fail closed). Also used by `warden doctor`.
    fn preflight(&self, spec: &SandboxSpec) -> Result<(), SandboxError>;
    /// Spawn `argv` with inherited stdio inside the sandbox. Does not wait.
    fn spawn(&self, spec: &SandboxSpec, argv: &[OsString]) -> Result<LaunchedChild, SandboxError>;
    fn wait(&self, child: &mut LaunchedChild) -> Result<ExitStatus, SandboxError>;
    fn signal(&self, child: &LaunchedChild, sig: Signal) -> Result<(), SandboxError>;
}
```

The sandboxed child **inherits warden's stdio**. There is no PTY in warden. The
harness gets the real terminal, so resize (SIGWINCH goes to the foreground process
group), raw mode, mouse, colour and exit codes all work with zero code. Warden only
forwards SIGINT/SIGTERM/SIGHUP to the child's process group and exits with the
child's status (or 128+signal). This is how codex's `sandbox-exec` and `bwrap`
wrappers already run. `portable-pty` is a dev-dependency used by the conformance
tests to drive the TUI, not by the product.

Backends in milestone 1:

- `SeatbeltSandbox` (macOS): generates an SBPL profile and runs
  `/usr/bin/sandbox-exec -p <profile> -D … -- <argv>`. Base profile and the network
  profile are taken from
  `codex-rs/sandboxing/src/seatbelt_base_policy.sbpl` and
  `seatbelt_network_policy.sbpl` (Apache-2.0, attributed in `THIRD_PARTY_NOTICES.md`),
  with warden's own file and network rules appended: `(deny default)`, read
  allowances, `(allow file-write* (subpath …))` per `read_write`, `(deny file-read*
  (subpath …))` per `deny_read`, and `(allow network-outbound (remote ip
  "localhost:<proxy_port>"))` as the **only** network allowance. The proxy listens on
  127.0.0.1 outside the sandbox.
- `LinuxSandbox`: `bwrap` (bundled as a vendored static binary like codex's
  `bundled_bwrap.rs`, or the system one if present and new enough) with
  `--ro-bind / /`, `--bind` per `read_write`, `--tmpfs` over `deny_read` entries,
  `--unshare-net`, `--unshare-pid`, `--die-with-parent`, `--new-session`. Inside the
  new net namespace a loopback-only listener is needed for the proxy: warden passes
  the proxy's Unix socket into the sandbox (`--bind <uds> <uds>`) and runs
  `warden __proxy-bridge` as PID 1's helper which listens on `127.0.0.1:<port>` in
  the namespace and forwards to the UDS. This mirrors
  `codex-rs/linux-sandbox/src/proxy_routing.rs`. Landlock (fs) and a seccomp filter
  (deny `connect`/`sendto` to AF_INET/AF_INET6 except loopback — codex's
  `linux-sandbox/src/landlock.rs` installs the same) are applied in the re-exec'd
  helper before `exec` of the harness, as defence in depth under bwrap. Falls back to
  Landlock+seccomp only (no mount namespace, no net namespace) when user namespaces
  are disabled, and `preflight` then downgrades with an explicit warning only if
  policy sets `sandbox.allow_degraded = true`; otherwise refuses.
- `WindowsSandbox`: `preflight` returns `Err(Unsupported("Windows sandboxing lands
  in milestone 2; see docs/THREAT_MODEL.md"))`. Milestone 2 will port codex's
  `windows-sandbox-rs` approach (restricted token + ACL grants, elevated one-time
  setup).
- `NoSandbox`: only selectable when the policy bundle grants
  `Warden::Action::"launchUnsandboxed"`; prints a red banner. Exists so a
  group can be exempted explicitly rather than by patching the binary.

Future backends behind the same trait: `SrtSandbox` (Anthropic sandbox-runtime,
needs Node), `DockerSandbox`, microVM, remote workspace. The trait deliberately
exposes `spawn/wait/signal` rather than `run`, so a remote backend can stream.

### 2.4 Egress proxy

Part of `warden-sandbox`, not a trait: every backend uses the same proxy.

- Listens on `127.0.0.1:0` (macOS) or a Unix socket in a `0700` temp dir (Linux).
- Speaks HTTP `CONNECT`, plain HTTP forward (for `http://` package mirrors), and
  SOCKS5 (`CONNECT` only, hostname addressing). No TLS interception.
- Allow decision per connection: `host` (from CONNECT target, Host header or SOCKS
  hostname) matched against `NetworkSpec.allow_hosts`; port must be 443 or 80 unless
  the rule names a port. Literal IPs are denied unless a rule names them.
- Denied connections get `403` / SOCKS `0x02` and emit an audit event
  `sandbox.network_denied{host, port, harness}`. Every allowed connection emits
  `sandbox.network_allowed` at debug level only (volume).
- The child gets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY=` and the
  tool-specific variants codex also sets (`NPM_CONFIG_PROXY`, `PIP_PROXY`,
  `YARN_*`, `BUNDLE_*`, `DOCKER_*`, `GIT_*` via `http.proxy` in a generated
  `GIT_CONFIG_GLOBAL` include). Claude Code (documented), Codex, OpenCode (Bun) and
  Pi (documented) honour `HTTPS_PROXY`. A process that ignores the variables and
  dials directly simply fails: the sandbox blocks all non-loopback traffic.
- DNS: nothing inside the sandbox can resolve names (macOS: mDNSResponder mach
  lookup denied; Linux: no network). Clients must pass hostnames to the proxy, which
  all CONNECT/SOCKS5h clients do. Tools that insist on resolving first fail closed.

### 2.5 Harness adapters

Declarative; see §3 for the schema. The trait is on the loader, not the adapter:

```rust
pub struct AdapterSet { /* id -> Adapter */ }

impl AdapterSet {
    /// Embedded TOMLs, then `${WARDEN_CONFIG}/adapters/*.toml` overriding by id.
    pub fn load(overrides_dir: Option<&Path>) -> Result<Self, AdapterError>;
    pub fn get(&self, id: &str) -> Option<&Adapter>;
}

impl Adapter {
    pub fn locate(&self) -> Result<Located, AdapterError>;                   // executable path + version
    pub fn plan(&self, ctx: &LaunchContext) -> Result<HarnessPlan, AdapterError>;
}

pub struct HarnessPlan {
    pub argv: Vec<OsString>,
    pub env: BTreeMap<String, String>,
    pub fs_rw: Vec<PathBuf>,
    pub fs_ro: Vec<PathBuf>,
    pub net: Vec<NetNeed>,            // host + purpose + default; policy decides
    pub emits: Vec<EmitFile>,         // native config files to write into the harness home
}
```

### 2.6 Policy

```rust
pub struct PolicyBundle {
    pub meta: BundleMeta,                 // version, issued_at, not_after, issuer
    pub schema: cedar_policy::Schema,
    pub policies: cedar_policy::PolicySet,
    pub catalog: Catalog,                 // the universe of things policies can refer to (§4.2)
    pub identity: IdentityConfig,
    pub providers: Vec<ProviderConfig>,
    pub defaults: Defaults,               // credential TTL, budget, sandbox options
}

pub trait PolicySource {
    /// Load + verify. Any failure (missing file, bad signature, expired, schema
    /// validation error) is fatal for `warden run`.
    fn load(&self, trusted_keys: &[VerifyingKey]) -> Result<PolicyBundle, PolicyError>;
}

pub struct Decision { pub allowed: bool, pub policy_ids: Vec<String>, pub reason: String }

impl PolicyBundle {
    pub fn authorize(&self, principal: &Identity, action: Action, resource: &ResourceRef, ctx: &Context) -> Decision;
    /// Convenience: evaluate every catalog entry of one kind and return the allowed subset.
    pub fn allowed<T: CatalogEntry>(&self, principal: &Identity, action: Action, ctx: &Context) -> Vec<&T>;
}
```

One `PolicySource` in milestone 1: `FileBundle { path }`. The control plane later
adds `HttpBundle` that writes the same file.

---

## 3. Harness adapter TOML

### 3.1 Schema

```toml
[harness]
id = "pi"                       # used in `warden run pi` and as Cedar entity id
name = "Pi"
executable = "pi"               # name on PATH, or absolute
version_args = ["--version"]    # for doctor + audit; output captured, first semver-ish token kept
min_version = "0.60.0"          # optional; refuse older

[detect]                        # optional
candidates = ["~/.local/bin/pi"]  # checked before PATH

[home]                          # the harness's config/state dir, owned by warden per harness
env = "PI_CODING_AGENT_DIR"     # how the harness is told where its home is
default = "${WARDEN_DATA}/homes/pi"  # persistent across launches, so sessions/history survive
# omit [home] when the harness has no such override; then its real dirs are listed under [[fs]]

[inject.<api-format>]           # one table per format the harness speaks: litellm | anthropic-messages | openai-chat | openai-responses
                                # warden picks the first table (in file order) that the credential's provider offers
base_url_env = "…"              # optional; omit when the base URL must go via [[emit]]
key_env = "…"                   # required; the secret is put here, nowhere else
key_helper_env = "…"            # optional; env var naming a command the harness runs per request to get a fresh token.
                                # When set, warden puts `warden __credential` there and leaves key_env empty (§5 step 7, Q4)
extra_env = { … }               # optional constant env for this format
model_env = "…"                 # optional
model_args = ["--model", "${model}"]   # optional; prepended to user args
native_api = "…"                # optional; value used by [[emit]] templates (e.g. pi's "api" field)
requires = ["…"]                # optional; things `warden doctor` must find in the harness home before this
                                # table is usable (e.g. an extension package). Not installed by warden.

[env]                           # constant env for every launch; ${...} expanded
KEY = "value"

[[fs]]                          # extra paths beyond workspace/home/tmp
path = "~/.cache/pi"
access = "rw" | "ro"
reason = "…"

[[net]]                         # hosts the harness wants beyond the gateway
host = "pi.dev"                 # exact, or "*.github.com"
port = 443                      # optional, default 443
purpose = "update-check" | "telemetry" | "auth" | "share" | "catalog" | "plugins" | "other"
default = "allow" | "deny"      # applies when no Cedar policy mentions the host

[[emit]]                        # native config written before each launch, inside [home] or an [[fs]] rw path
path = "${home}/models.json"
format = "json" | "toml" | "text"
merge = "replace-key" | "overwrite" | "create-if-missing"
key = "providers.warden"        # for replace-key: dotted path replaced, rest of file preserved
template = '''…'''              # ${...} expanded; for json/toml the result must parse
```

Template variables: `${workspace}`, `${home}`, `${base_url}`, `${key_env}` (the
*name*, never the value), `${model}`, `${api}` (= `native_api`),
`${proxy_url}`, `${WARDEN_DATA}`, `${WARDEN_CONFIG}`, `${HOME}`. `$$` is a literal `$`.
Templates cannot reference the secret itself; the loader rejects a template that
contains `${key}` or `${secret}`.

Override: a file at `${WARDEN_CONFIG}/adapters/<id>.toml` replaces the embedded
one wholesale (no merging; simpler to reason about and to sign). The policy bundle
can pin `adapters.allowed_sha256` so an org can forbid local overrides.

### 3.2 Full example: Pi

Facts this encodes (from `packages/coding-agent/src/config.ts:542-578`,
`docs/environment-variables.md`, `docs/models.md`, `docs/providers.md`, and the
`balcsida/pi-provider-litellm` README):

- With the `pi-provider-litellm` extension installed, Pi reads `LITELLM_BASE_URL`
  and `LITELLM_API_KEY` (or `LITELLM_API_KEY_HELPER`, a command run per request),
  discovers models from the proxy's `/model/info` or `/v1/models`, exposes them as
  `litellm/<id>`, chooses Messages/Chat/Responses per model itself, and pins the
  credential to the proxy host. A saved `auth.json` credential would take precedence
  over the env vars, which is one more reason the harness home is warden-owned.
  The extension is loaded from the harness home (`pi install npm:pi-provider-litellm`
  writes it there); warden does not install it, `warden doctor` reports if it is
  missing, and the conformance job installs it before launching.
- Without the extension (a `static` provider with a plain Anthropic- or
  OpenAI-format gateway), Pi has no base-URL env var; custom endpoints go in
  `models.json` under its agent dir, where `apiKey` may be `"$ENV_NAME"` and is
  expanded at runtime. It reads `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`.
- `PI_OFFLINE`, `PI_SKIP_VERSION_CHECK` and `PI_TELEMETRY=0` stop Pi's own
  traffic (the extension's `/litellm-refresh` still works under `PI_OFFLINE`). It
  otherwise talks to `pi.dev` (catalog, version check), `api.github.com` (share via
  gist) and the npm registry (self-update); the extension talks only to the proxy
  unless `LITELLM_MODELS_DEV=1`.

```toml
[harness]
id = "pi"
name = "Pi"
executable = "pi"
version_args = ["--version"]
min_version = "0.99.2"           # pi-provider-litellm 3.5+ needs it

[home]
env = "PI_CODING_AGENT_DIR"
default = "${WARDEN_DATA}/homes/pi"

# Preferred: first-class LiteLLM support through the pi-provider-litellm extension.
[inject.litellm]
base_url_env = "LITELLM_BASE_URL"
key_env = "LITELLM_API_KEY"
key_helper_env = "LITELLM_API_KEY_HELPER"
model_args = ["--model", "litellm/${model}"]
extra_env = { LITELLM_MODELS_DEV = "0" }
requires = ["extension:pi-provider-litellm"]

# Fallbacks for non-LiteLLM gateways; these need the [[emit]] below.
[inject.anthropic-messages]
key_env = "ANTHROPIC_API_KEY"
native_api = "anthropic-messages"
model_args = ["--model", "warden/${model}"]

[inject.openai-chat]
key_env = "OPENAI_API_KEY"
native_api = "openai-completions"
model_args = ["--model", "warden/${model}"]

[inject.openai-responses]
key_env = "OPENAI_API_KEY"
native_api = "openai-responses"
model_args = ["--model", "warden/${model}"]

[env]
PI_OFFLINE = "1"
PI_SKIP_VERSION_CHECK = "1"
PI_TELEMETRY = "0"

[[fs]]
path = "~/.npm/_cacache"
access = "ro"
reason = "npx-installed pi reads its own package cache"

[[net]]
host = "pi.dev"
purpose = "catalog"
default = "deny"

[[net]]
host = "api.github.com"
purpose = "share"
default = "deny"

[[net]]
host = "registry.npmjs.org"
purpose = "update-check"
default = "deny"

[[emit]]
path = "${home}/models.json"
format = "json"
merge = "replace-key"
key = "providers.warden"
template = '''
{
  "name": "warden",
  "baseUrl": "${base_url}",
  "api": "${api}",
  "apiKey": "$$${key_env}",
  "models": [ { "id": "${model}", "name": "${model}", "reasoning": true } ]
}
'''
```

With `warden run pi` for a user whose policy allows `claude-sonnet-5` via the
`litellm` provider, this yields: `PI_CODING_AGENT_DIR=~/.local/share/warden/homes/pi`,
`LITELLM_BASE_URL=https://gw.example.com`, `LITELLM_API_KEY_HELPER="/path/to/warden __credential"`
(no key in the environment at all; see §5 step 7), the three `PI_*` vars, proxy
vars, and argv `pi --model litellm/claude-sonnet-5 <user args>`. No file is
emitted. The `[[emit]]` only runs when the chosen inject table is one of the
anthropic/openai ones, in which case `models.json` gets a `providers.warden` entry
with `"apiKey": "$ANTHROPIC_API_KEY"` (the file never holds the secret) and the
user's other providers in that file stay untouched but unreachable (their hosts are
not allowlisted).

### 3.3 The other three, in brief

| | Claude Code | Codex | OpenCode |
|---|---|---|---|
| executable | `claude` | `codex` | `opencode` |
| home | `CLAUDE_CONFIG_DIR` | `CODEX_HOME` | `OPENCODE_CONFIG_DIR` (config) + `~/.local/share/opencode`, `~/.cache/opencode` as `[[fs]]` rw |
| base URL | `ANTHROPIC_BASE_URL` env | `OPENAI_BASE_URL` env, or emitted `model_providers.warden` in `config.toml` (`base_url`, `env_key`, `wire_api`) | no env; emitted `OPENCODE_CONFIG_CONTENT` JSON with `provider.warden.options.baseURL` and `apiKey: "{env:WARDEN_API_KEY}"` |
| key | `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN` for Bearer) | `OPENAI_API_KEY` / `env_key` | env referenced from config |
| model | `ANTHROPIC_MODEL` + `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL` | `--model`/`-m` | `--model warden/<id>` |
| quiet | `DISABLE_AUTOUPDATER=1`, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | `[[net]]` deny `auth.openai.com`, `chatgpt.com`, `api.github.com` | `OPENCODE_DISABLE_AUTOUPDATE=1`, `OPENCODE_DISABLE_SHARE=1`, `OPENCODE_DISABLE_LSP_DOWNLOAD=1`; `[[net]]` `models.dev` (catalog, default allow), `api.github.com` deny |
| native managed config | `managed-settings.json` lives in a root-owned system dir, so warden cannot write it per launch; we emit user-level `settings.json` into the warden-owned home instead, and `warden doctor` reports whether a system managed file exists | `/etc/codex/requirements.toml` is root-owned, same story; emit `config.toml` into `CODEX_HOME` | none |

Note for Claude Code: pointing `ANTHROPIC_BASE_URL` away from `api.anthropic.com`
disables Anthropic's server-managed settings and Remote Control (documented); that
is the intended effect here.

---

## 4. Policy model

### 4.1 Entities and actions

Namespace `Warden`. Cedar schema (abridged):

```
namespace Warden {
  entity Group;
  entity User in [Group] { email?: String };
  entity HarnessSet;
  entity Harness in [HarnessSet] { version?: String };
  entity Provider { format: String, url: String };
  entity Model in [Provider] { tier?: String };
  entity PathSet;
  entity Path in [PathSet] { path: String, access: String };          // "ro" | "rw"
  entity HostSet;
  entity Host in [HostSet] { host: String, port: Long, purpose: String, harness?: Harness };

  action launch            appliesTo { principal: User, resource: Harness,  context: Ctx };
  action launchUnsandboxed appliesTo { principal: User, resource: Harness,  context: Ctx };
  action useProvider       appliesTo { principal: User, resource: Provider, context: Ctx };
  action useModel          appliesTo { principal: User, resource: Model,    context: Ctx };
  action readPath          appliesTo { principal: User, resource: Path,     context: Ctx };
  action writePath         appliesTo { principal: User, resource: Path,     context: Ctx };
  action connect           appliesTo { principal: User, resource: Host,     context: Ctx };

  type Ctx = { harness: Harness, workspace: String, os: String, warden_version: String };
}
```

Principal `User::"<sub>"` with parents `Group::"<claim value>"` for each group in
the ID token, built at launch; users and groups are never listed in the bundle.

### 4.2 Catalog

Cedar answers yes/no for a concrete request; it does not enumerate. So the bundle
carries a **catalog** of candidate resources and warden asks Cedar about each one:

```json
{
  "harnesses": ["claude-code", "codex", "opencode", "pi"],
  "harness_sets": { "approved": ["claude-code", "codex", "opencode", "pi"] },
  "providers": { "gw": { "format": "anthropic-messages", "url": "https://gw.example.com/anthropic" },
                 "gw-oai": { "format": "openai-chat", "url": "https://gw.example.com/v1" } },
  "models": { "claude-sonnet-5": { "provider": "gw", "tier": "standard" },
              "claude-opus-5-5": { "provider": "gw", "tier": "frontier" },
              "gpt-6-luna": { "provider": "gw-oai", "tier": "standard" } },
  "paths": { "workspace": { "path": "${workspace}", "access": "rw" },
             "home-ro":   { "path": "${HOME}", "access": "ro" },
             "ssh":       { "path": "${HOME}/.ssh", "access": "deny" },
             "cloud-creds": { "path": "${HOME}/.aws", "access": "deny" } },
  "hosts": { "gw": { "host": "gw.example.com", "purpose": "gateway" },
             "github": { "host": "github.com", "purpose": "git" },
             "npm": { "host": "registry.npmjs.org", "purpose": "packages" },
             "pypi": { "host": "pypi.org", "purpose": "packages" } },
  "host_sets": { "registries": ["npm", "pypi"], "git": ["github"] }
}
```

Adapter `[[net]]` and `[[fs]]` entries are added to the candidate set at launch as
`Host`/`Path` entities tagged with `harness`, so policies can say "no update checks
for anyone" without listing harness hostnames in the bundle. Their `default` applies
only when neither a `permit` nor a `forbid` matches.

Paths with `access = "deny"` are candidates for *neither* action; they become
`deny_read` in the sandbox spec. That gives a short, reviewable deny list for
secrets directories.

### 4.3 Example policies

```cedar
// Everyone in engineering may launch any approved harness.
permit(principal in Warden::Group::"engineering",
       action == Warden::Action::"launch",
       resource in Warden::HarnessSet::"approved");

// Codex is in pilot: only the pilot group, and never on Windows yet.
forbid(principal, action == Warden::Action::"launch", resource == Warden::Harness::"codex")
  unless { principal in Warden::Group::"codex-pilot" };
forbid(principal, action == Warden::Action::"launch", resource)
  when { context.os == "windows" };

// Models: standard tier for all; frontier tier for leads.
permit(principal, action == Warden::Action::"useModel", resource)
  when { resource.tier == "standard" };
permit(principal in Warden::Group::"ml-leads", action == Warden::Action::"useModel", resource)
  when { resource.tier == "frontier" };

// Providers follow models; still require an explicit grant.
permit(principal, action == Warden::Action::"useProvider", resource);

// Filesystem: workspace rw, home ro, nothing else. Secrets dirs are "deny" in the catalog.
permit(principal, action == Warden::Action::"writePath", resource == Warden::Path::"workspace");
permit(principal, action == Warden::Action::"readPath", resource in Warden::PathSet::"default-ro");

// Network: gateway always; registries and git for engineering; no telemetry/update
// traffic from any harness; contractors get no git hosts.
permit(principal, action == Warden::Action::"connect", resource == Warden::Host::"gw");
permit(principal in Warden::Group::"engineering", action == Warden::Action::"connect",
       resource in Warden::HostSet::"registries");
permit(principal in Warden::Group::"engineering", action == Warden::Action::"connect",
       resource in Warden::HostSet::"git")
  unless { principal in Warden::Group::"contractors" };
forbid(principal, action == Warden::Action::"connect", resource)
  when { resource.purpose == "telemetry" || resource.purpose == "update-check" };

// Escape hatch, auditable: platform team may run without a sandbox.
permit(principal in Warden::Group::"platform-admins",
       action == Warden::Action::"launchUnsandboxed", resource);
```

Cedar's `forbid` always wins over `permit`, and unmatched requests are denied, which
is the fail-closed default we want. The bundle is validated against the schema at
load; a bundle that fails validation is rejected.

### 4.4 Bundle format and signing

```
policy.bundle            # JSON: { meta, schema, policies: [cedar text], catalog, identity, providers, defaults }
policy.bundle.sig        # ed25519 signature over the exact bytes of policy.bundle (base64, with key id)
```

Trusted verifying keys: `${WARDEN_CONFIG_SYSTEM}/trusted-keys` (one base64 key per
line, `#` comments), i.e. `/etc/warden/trusted-keys`,
`/Library/Application Support/warden/trusted-keys`, `%ProgramData%\warden\trusted-keys`.
This file is the single piece of state an org installs per machine (MDM, image, or
the installer). No trusted keys => `warden run` refuses. A developer with admin can
replace the file; see THREAT_MODEL.md.

Bundle location, in order: `--policy <path>`, `WARDEN_POLICY`, `${WARDEN_CONFIG}/policy.bundle`,
system dir. `meta.not_after` is enforced with a configurable grace (default 7 days,
set in the bundle itself, min 0) so a laptop offline for a weekend keeps working but
a stale bundle eventually stops.

`warden policy show` prints meta, signature status, the policies and, if logged in,
the effective decisions for the current user (which harnesses, models, hosts, paths).
`warden policy sign` (admin tool, same binary) signs with a key from a file or the
keychain; key generation is `warden policy keygen`.

---

## 5. Launch sequence: `warden run <harness> [-- args]`

Everything before step 8 is local and must finish in well under a second on a warm
machine. Step 6 is the one network call and is bounded.

1. **Load config.** `${WARDEN_CONFIG}/config.toml` (optional; only `policy`, `audit`
   and `log` keys). Resolve data dir `${WARDEN_DATA}` (`~/.local/share/warden`,
   `~/Library/Application Support/warden`, `%LOCALAPPDATA%\warden`).
2. **Load and verify policy bundle.** Read trusted keys; read bundle + sig; verify;
   parse; validate Cedar schema and policies; check `not_after` + grace. Any failure
   => exit 78 (`EX_CONFIG`) with the reason. Nothing else has run yet, so no side
   effects.
3. **Identity.** `IdentityProvider::current()`. Refresh from keychain if the cached ID
   token has < 5 min left. Not logged in => exit 77 (`EX_NOPERM`), message says
   `warden login`. Build `User` entity with group parents.
4. **Adapter.** `AdapterSet::load()`; unknown harness => exit 64. `locate()` finds
   the executable and version; missing => exit 69 (`EX_UNAVAILABLE`) with install
   hint. If the bundle pins adapter hashes, check them.
5. **Policy decisions.** All local, in this order, each denial aborts with the
   policy ids that matched:
   1. `launch` on `Harness::<id>` (or `launchUnsandboxed` if `--no-sandbox`).
   2. `useModel` over the catalog, filtered to formats the adapter can inject;
      pick `--model` if given and allowed, else the bundle default, else the first
      allowed. Empty => deny.
   3. `useProvider` for the chosen model's provider.
   4. `readPath`/`writePath` over catalog paths + adapter `[[fs]]`; `deny` paths to
      `deny_read`.
   5. `connect` over catalog hosts + adapter `[[net]]`; gateway host added
      automatically from the chosen provider's URL.
   Emit one audit event `policy.decision` with the full allowed/denied sets.
6. **Credential.** `Provider::issue()` with TTL from `defaults.credential_ttl`
   (default 8h, max 24h) and the allowed model list. Timeout 10s; on failure exit 69
   unless a credential from a previous launch is still cached in memory of a running
   `warden` agent process (there is none in milestone 1, so: fail). The secret is
   held in a `SecretString`; it is never logged, never written, and is the only
   value that goes into `env` that cannot appear in `--dry-run` output.
7. **Harness plan.** `Adapter::plan()`: argv, env, fs, emits. Compose the child
   env from scratch: a minimal passthrough allowlist from the parent (`PATH`, `HOME`,
   `USER`, `LANG`/`LC_*`, `TERM`, `COLORTERM`, `SHELL`, `TMPDIR`, `SSH_AUTH_SOCK` only
   if policy allows, `EDITOR`/`VISUAL`), plus adapter `[env]`, inject vars, proxy vars,
   `WARDEN_SESSION_ID`, and `AI_AGENT_LAUNCHER=warden`. Provider-specific keys that
   happen to be in the parent environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
   `LITELLM_*`, …) are **not** inherited, so a user's personal key can't leak past
   the gateway.
   **Key helper path.** If the chosen inject table has `key_helper_env`, warden
   does not put the secret in the environment. It sets the helper variable to
   `<warden binary> __credential`, and keeps the secret in the parent process. The
   helper, when the harness runs it, connects to a Unix socket (`0600`, path in
   `WARDEN_CREDENTIAL_SOCK`, bind-mounted into the sandbox on Linux) and prints the
   current token; the parent can rotate it at will (Q4). Pi has this via
   `LITELLM_API_KEY_HELPER`; Claude Code via `apiKeyHelper` in settings (emitted
   into its home); Codex and OpenCode have no equivalent and get the plain env var.
   Write `emits` into the harness home (create `0700`). Create the harness home and
   workspace-local temp dir if missing.
8. **Sandbox preflight + proxy.** Build `SandboxSpec`; `Sandbox::preflight()`;
   start the egress proxy on a tokio runtime in a background thread; it owns the
   allowlist and the audit sender.
9. **Spawn.** `Sandbox::spawn()` with inherited stdio. Record pid. Emit
   `harness.launch` audit event (harness, version, model, provider id, sandbox
   backend, workspace, hash of the policy bundle; never the credential).
10. **Supervise.** Install handlers for SIGINT/SIGTERM/SIGHUP (forward to child's
    process group) and SIGCHLD. Block in `wait()`. If the credential has
    `expires_at` and the harness is still running 5 min before it, print one line to
    stderr ("credential expires in 5 min; save your work"); re-issuing into a
    running process is not possible with env-var injection (see Q4).
11. **Exit.** `Provider::revoke()` best-effort (2s timeout). Flush audit (bounded,
    3s; drop on timeout). Remove proxy socket/tempdir. Exit with the child's code, or
    `128 + signal`.

`warden run --dry-run <harness>` performs steps 1–7 with a fake credential and
prints the plan: argv, env (secret masked), fs rules, host allowlist, emitted files.
This is what conformance tests and `warden doctor` reuse.

`warden doctor`: steps 1–4 and 8's preflight, with everything reported rather than
aborted; plus platform checks (sandbox-exec present, bwrap/user-ns, keychain reachable,
trusted keys present, which harnesses are installed, whether system-level native
managed configs exist for each harness).

`warden login`: step 1–2 (bundle supplies issuer + client id), then
`IdentityProvider::login()`. Prints groups it received so a user can tell why a
launch was denied.

---

## 6. Audit

`warden-audit` exposes `AuditSink` with `emit(Event)` and `flush(Duration)`. Events
are structured (`serde` structs), mapped to OTel log records with
`event.name` and attributes; traces are not used in milestone 1. Sinks: `Otlp`
(grpc or http/protobuf, endpoint + headers from the bundle `defaults.audit`),
`Stderr` (JSON lines, for debugging), `Null`. A bounded channel (1024) feeds a
background task; when full, events are dropped and a counter is reported in the
next successful export. Never blocks launch. Event names:
`identity.login`, `policy.loaded`, `policy.rejected`, `policy.decision`,
`credential.issued`, `credential.revoked`, `harness.launch`, `harness.exit`,
`sandbox.network_denied`, `sandbox.preflight_failed`.

Note: the OTLP endpoint itself must be reachable from warden (outside the sandbox).
It is not subject to the harness allowlist.

---

## 7. Testing

- **Unit** (`cargo test`): adapter TOML parsing (every embedded adapter parses and
  validates; template variables resolve; secret-in-template rejected); Cedar
  evaluation against fixtures (allowed-set compilation, forbid precedence, group
  membership, context fields); bundle signature + expiry; env composition (parent
  keys dropped).
- **Sandbox integration** (`tests/sandbox`, CI matrix macOS 14/15 arm64, Ubuntu
  22.04/24.04 x86_64 + arm64, Alpine for musl): launches `warden run __probe` where
  `__probe` is a hidden subcommand of the same binary acting as the "harness". It
  tries to read a file outside the allowed set, write outside `read_write`, and
  `connect()` to a non-allowlisted host, both directly and via the proxy, and reports
  each result on stdout. Test asserts all three are blocked and that an allowlisted
  CONNECT through the proxy succeeds (against a local HTTPS listener run by the
  test, on the host side).
- **Conformance** (`tests/conformance`, scheduled nightly + on adapter changes): per
  harness, install the latest release (npm for Claude Code, OpenCode and Pi;
  GitHub release binary for Codex), start a mock gateway in-process that records
  requests and returns a canned streaming reply in the right format, write a bundle
  pointing at it, `warden run <harness> -- -p "say hi"` under a PTY
  (`portable-pty`), assert: the mock saw a request with the expected auth header
  and model, the proxy saw no denied connections except the ones the adapter
  declares as `deny` (asserted to be exactly those, so a new phone-home host fails the
  test), and the harness exited 0. Non-interactive modes used: `claude -p`,
  `codex exec`, `opencode run`, `pi -p`. The Pi job installs `pi-provider-litellm`
  into the warden-owned Pi home first and asserts discovery came from the mock's
  `/model/info`; the mock gateway therefore also serves `/model/info` and
  `/v1/models` in LiteLLM's shape.

---

## 8. Open questions

- **Q1 codex-rs reuse scope.** The codex sandbox crates are not on crates.io and
  pull in the codex workspace. Proposal: copy the two `.sbpl` files and the bwrap
  argument builder (`linux-sandbox/src/bwrap.rs`) with header attribution and a
  `THIRD_PARTY_NOTICES.md` entry, and write the rest (proxy, Landlock/seccomp
  setup) ourselves against the same crates. Alternative: git-dependency on
  `codex-network-proxy` and `codex-sandboxing` and accept the build weight. I
  recommend copying.
- **Q2 Proxy protocol.** CONNECT + SOCKS5 without MITM means we filter by hostname
  only; a allowlisted host can still be used to exfiltrate (e.g. a GitHub gist).
  MITM would let us inspect paths but needs a per-machine CA installed into every
  tool's trust store (codex and srt both do this). Milestone 1: no MITM.
- **Q3 LiteLLM minting auth.** Issuing virtual keys needs an authority. Options:
  (a) LiteLLM JWT auth so the user's ID token can call `/key/generate` for
  themselves, scoped by LiteLLM's JWT→team mapping; (b) a tiny minting service in
  front of LiteLLM holding the master key (that is the control plane, out of scope);
  (c) org pre-creates per-user keys and `static`-style lookup. I recommend (a) for
  milestone 1 and documenting the LiteLLM config it needs. Does your LiteLLM
  deployment allow (a)?
- **Q4 Credential renewal.** Env-var injection cannot rotate a key inside a running
  harness. Pi (via `LITELLM_API_KEY_HELPER`) and Claude Code (`apiKeyHelper`) can
  fetch a fresh token per request, so for them the key-helper socket in §5 step 7
  solves it and the key is never in the environment. Codex and OpenCode have no
  helper hook; for them either accept TTL >= 8h, or make the egress proxy the
  credential holder (rewrite the `Authorization`/`x-api-key` header on gateway
  requests, which requires TLS termination for the gateway host only; the harness
  then gets a dummy key). Proposal: key-helper in milestone 1, proxy rewrite later
  if long Codex/OpenCode sessions turn out to matter.
- **Q5 Model naming.** Harnesses show models by id; a gateway may expose the same
  model under different names per format. Catalog `models` map one warden model id
  to one provider; is a per-harness alias needed?
- **Q6 cargo-dist.** axodotdev's funding ended and maintenance has been sporadic.
  It still works; the alternative is a hand-written release workflow with
  `cross`. Proceed with cargo-dist and revisit if a toolchain bump breaks it?
- **Q7 Windows reads.** Milestone 2 only. Should `warden run` on Windows refuse
  (current plan) or launch with provider injection and the proxy but no sandbox
  when policy permits `launchUnsandboxed`? The latter gives Windows users the
  routing benefit today.
- **Q8 Harness home vs real home.** Giving each harness a warden-owned home
  (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `PI_CODING_AGENT_DIR`, `OPENCODE_CONFIG_DIR`)
  means existing user settings and sessions in `~/.claude` etc. are not visible
  under warden. Acceptable? The alternative, overlaying files into the real home,
  makes "what did warden change" much harder to answer.
- **Q9 Linux without user namespaces** (some hardened distros, older Docker-in-CI).
  Current plan is to refuse unless the bundle sets `sandbox.allow_degraded`. OK?
- **Q10 Name.** `warden` is taken on crates.io by an unrelated crate. Binary name can
  stay `warden`; the crate names can be `warden-*` only if those are free (they
  are, as of today), otherwise prefix with the org.
