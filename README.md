# warden

Harness-neutral launcher for agentic coding tools. One binary, one signed policy,
many harnesses: Claude Code, Codex, OpenCode, Pi (more via a TOML file).

```
warden login                      # OIDC device flow against your IdP
warden run pi -- -p "fix the failing test"
warden run claude-code
warden doctor                     # what is installed, enforced, and missing
warden policy show                # the signed bundle and your effective permissions
```

`warden run` does, in order: verify the signed policy bundle, resolve your identity
and groups, ask Cedar what you may launch, which models, hosts and paths you may
use, mint a short-lived gateway credential for you, start a local allowlisting
egress proxy, and launch the harness inside an OS sandbox whose only way out is
that proxy. The harness inherits your terminal, so interactive TUIs work unchanged.

Status: milestone 1 (macOS and Linux). Windows refuses to run until milestone 2.
Design: `docs/DESIGN.md`. Threat model: `docs/THREAT_MODEL.md`.

## What is enforced, and what is not

Warden is a client-side control. Be clear-eyed about what that means.

**Enforced on the endpoint, for the process tree warden launches:**

- Filesystem: writes only to the workspace, the harness's own warden-owned home
  and temp dirs; `.git/hooks` and `.git/config` inside the workspace stay
  read-only; the catalog's deny list (`~/.ssh`, `~/.aws`, …) is unreadable.
  Everything else on disk is readable, the same trade-off Codex makes so
  toolchains keep working.
- Network: no socket leaves the sandbox except to warden's proxy on loopback.
  The proxy allows CONNECT/SOCKS5 to allowlisted hostnames only. There is no
  DNS inside the sandbox. Linux uses a fresh network namespace; macOS uses
  Seatbelt rules.
- Credentials: per-launch, per-user, TTL-bound, scoped to the allowed models.
  Never written to disk by warden. For Claude Code the key never enters the
  environment at all; the harness fetches it per request from a socket warden
  owns. (Pi would support the same through pi-provider-litellm, but that
  extension does not run key helpers at startup yet, so Pi gets the env var.)
- Identity and policy: groups come from the IdP's signed token; the bundle is
  Ed25519-signed and validated against the Cedar schema; anything unverifiable
  means no launch.

**Not enforced by warden:**

- A developer with admin rights can run `claude` or `codex` directly, without
  warden, with a personal key. Warden cannot stop that. What does: blocking the
  public provider endpoints at your network edge and running a gateway that
  accepts only credentials it issued. Deploy warden assuming both exist.
- Exfiltration through an allowlisted host. If `github.com` is allowed for
  `git fetch`, a gist upload is also possible. Keep the allowlist short and
  prefer internal mirrors.
- Damage inside the workspace. The sandbox cannot tell a wanted edit from an
  unwanted one; use branch protection and review.
- Harness-native managed config (Claude Code `managed-settings.json`, Codex
  `requirements.toml`) is a useful second layer that warden does not write;
  `warden doctor` tells you whether it is present.

## Install

Releases ship static binaries for macOS (arm64, x86_64), Linux (x86_64, arm64,
musl) and Windows (x86_64), built with cargo-dist. From source: `cargo install
--path crates/warden-cli`.

Linux needs `bubblewrap` and unprivileged user namespaces. macOS uses the
system `sandbox-exec`.

## Set up an organisation

1. `warden policy keygen` → keep the private key in your secrets store; put the
   public key in `/etc/warden/trusted-keys` (Linux) or
   `/Library/Application Support/warden/trusted-keys` (macOS) on every machine,
   via MDM or your image.
2. Decide how keys are minted. With LiteLLM JWT auth, the client calls
   `/key/generate` with the user's ID token directly. Without it (OSS LiteLLM),
   run the mint service somewhere that can reach the proxy and the IdP, and set
   the provider's `mint_url` to it:
   ```
   LITELLM_MASTER_KEY=sk-... warden mint-serve --policy policy.bundle \
     --litellm-url https://gw.example.com --team engineering=team-eng --listen 0.0.0.0:8787
   ```
   It verifies the caller's ID token, re-checks the bundle's policy for that user,
   and mints a scoped, TTL-bound key. The master key never reaches a laptop.
3. Write a bundle. Start from `examples/policy.bundle`: identity provider,
   providers (a LiteLLM proxy, or a static gateway key), the catalog of harnesses,
   models, hosts and paths, and Cedar policies keyed on IdP groups.
4. `warden policy sign policy.bundle --key -` and distribute `policy.bundle` plus
   `policy.bundle.sig` to `~/.config/warden/` (or the system dir).
5. Developers run `warden login`, then `warden run <harness>`.

Harness adapters are TOML files in `adapters/`, embedded in the binary. Drop an
override in `~/.config/warden/adapters/<id>.toml` to change or add one.

For Pi, install `pi-provider-litellm` into the warden-owned Pi home once:
`PI_CODING_AGENT_DIR=~/.local/share/warden/homes/pi pi install npm:pi-provider-litellm`
(`warden doctor` reminds you).

## Development

```
cargo test                                   # unit + sandbox integration tests
WARDEN_CONFORMANCE=pi cargo test -p warden-cli --test conformance -- --nocapture
```

The conformance test launches the real, installed harness against a mock gateway
and checks that it used the injected base URL and key. CI runs it nightly for
every harness on macOS and Linux.

The `it_*` tests run warden against real services in Docker and skip unless their
environment is set: `it_litellm` (OSS LiteLLM behind `mint-serve`), `it_otlp` (an
OpenTelemetry Collector) and `it_oidc` (a Dex IdP; needs an unlocked OS keyring).
Each file's header lists its variables, `crates/warden-cli/tests/it/` holds the
container configs, and `.github/workflows/integration.yml` shows the full setup.

## License

Apache-2.0. The macOS and Linux sandbox profiles derive from
[openai/codex](https://github.com/openai/codex) (Apache-2.0); see
`THIRD_PARTY_NOTICES.md`.
