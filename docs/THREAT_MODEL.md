# warden — threat model

Read `DESIGN.md` first. This document says what warden protects against, what it
does not, and which control carries the weight in each case.

## The one-paragraph version

On a developer machine where the developer is an administrator, **the local
sandbox is a guided default, not a guarantee.** The developer can edit the trusted
keys file, replace the `warden` binary, run the harness without warden, or run
`sudo`. Nothing warden does on the endpoint survives a determined local admin. The
control that actually enforces "models only through our gateway" is **network-level
blocking of direct provider access** (`api.anthropic.com`, `api.openai.com`,
`generativelanguage.googleapis.com`, …) at the egress firewall, secure web gateway or
DNS layer, combined with the gateway accepting only credentials it issued. Warden's
job is to make the compliant path the easy path, to make the policy legible, and to
record what happened. Deploy warden assuming the network control exists; if it
doesn't, warden alone gives you hygiene and audit, not enforcement.

## Assets

1. **Provider credentials** issued per user and launch (LiteLLM virtual keys, static
   gateway keys). Compromise = spend on the org's account, data to the model under
   someone else's identity.
2. **Identity tokens** (OIDC ID/refresh token in the keychain). Compromise = acting
   as the user toward the gateway and toward any other relying party that trusts the
   same tokens.
3. **Source code and local secrets** on the developer machine (`~/.ssh`, `~/.aws`,
   browser profiles, other repos). The harness runs model-generated commands; the
   sandbox limits what those commands can read and change.
4. **Policy integrity**: that the harness runs under the bundle the org signed.
5. **Audit integrity**: that launch and denial events reach the collector.

## Actors

| Actor | Capability | Intent |
|---|---|---|
| A1 Cooperative developer | Admin on their machine, follows the happy path | Wants things to work; may be careless |
| A2 Circumventing developer | Admin, motivated to bypass (use a personal key, a disallowed model, skip the sandbox) | Convenience or policy disagreement |
| A3 Model-generated code | Runs *inside* the sandbox with the harness's privileges; can be prompt-injected by repo content, web pages or MCP tools | Arbitrary: exfiltrate, destroy, persist |
| A4 Malicious dependency / tool | Same position as A3, but deliberate | Same |
| A5 Network attacker | On-path between machine and gateway | Steal credentials, inject responses |
| A6 Compromised gateway/IdP admin | Controls the gateway or IdP | Out of scope for warden; noted for completeness |

Warden's primary target is **A3/A4 against A1's machine**, and **making A2's
bypass visible and inconvenient** rather than impossible.

## Controls and what they hold against

### C1 Egress proxy + sandbox network denial

All sockets from the sandboxed process tree are denied except loopback to the
proxy (macOS Seatbelt) or the process has no network namespace at all except a
loopback bridge to the proxy's Unix socket (Linux). The proxy allows CONNECT /
SOCKS5 to allowlisted hostnames only.

- Holds against A3/A4 dialling a provider directly, a C2 host, or a paste site:
  the connection never leaves the machine. Hostname allowlisting, not IP, so a
  tool cannot bypass it by resolving first (there is no DNS inside).
- Holds against A3/A4 reading a key from env and using it elsewhere *from inside
  the sandbox*; the only reachable upstream is the gateway, which is where the key
  is valid anyway.
- Does **not** hold against exfiltration *through an allowlisted host*: a GitHub
  gist, an npm publish, a PyPI upload, an issue comment. Allowlisting `github.com`
  for `git fetch` also allows `gh gist create`. Mitigations: keep the allowlist
  minimal; prefer internal mirrors; the MITM option (deferred) would allow path
  filtering. Treat this as the main residual risk of C1.
- Does **not** hold against A2: `claude` run without `warden` has no sandbox. See
  C7.
- Linux without user namespaces: `bwrap --unshare-net` is unavailable; warden
  refuses unless the bundle sets `sandbox.allow_degraded`, in which case only
  seccomp (deny non-loopback `connect`) remains. Document this per fleet.
- **Windows (phase A) does not hold for C1 at all.** A restricted token cannot block
  sockets, so the harness can connect anywhere; the proxy variables are advisory.
  `warden run` refuses on Windows unless the bundle sets
  `defaults.sandbox_allow_degraded`, and then prints a warning. Phase B (a sandbox
  user plus firewall rules scoped to it, needing admin once) is meant to close this.

### C2 Filesystem sandbox

Seatbelt / bwrap+Landlock. Workspace and harness home are writable; the rest of
the filesystem is readable except the catalog's `deny` paths (`~/.ssh`, `~/.aws`,
`~/.gnupg`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, warden's own data dir, the
keychain is not a file on macOS but `~/Library/Keychains` is denied anyway).

- Holds against A3/A4 deleting or modifying files outside the workspace, reading
  the listed secret stores, and planting persistence in shell rc files
  (`~/.zshrc` etc. are read-only).
- Does **not** hold against damage *inside* the workspace, including
  `.git/hooks` and `.git/config` (a hook that runs on the developer's next commit
  outside warden escapes the sandbox). Codex marks `.git` read-only inside writable
  roots for exactly this reason; warden does the same, always (there is no opt-out),
  and the harness's own `git commit` still works because git writes objects and refs,
  not hooks. On macOS and Linux the `.git` directory itself cannot be renamed or
  replaced either (so `mv .git .git.old` plus a planted hook fails), and a `.git` file
  (worktree or submodule `gitdir:` pointer) is read-only so it cannot be repointed at
  a fake git dir. Not covered: a `.git` created during the run, nested repos and
  submodules (`<root>/sub/.git`, `.git/modules/*/{hooks,config}`) and a symlinked
  `.git`. Launches whose writable root contains warden's config or data dir, the
  trusted-keys file or the policy bundle are refused, so the harness cannot rewrite
  adapters, trust its own signing key or swap the bundle.
- Does **not** hold against reading secrets that are *not* on the deny list.
  The default list is a start, not a census; orgs should extend it (browser
  profiles, password-manager caches, other repos). Readable home is a deliberate
  trade-off so that tools, SDKs and language toolchains work.
- macOS specifics: Seatbelt profiles are evaluated by the kernel; `sandbox-exec`
  is deprecated but functional through macOS 26 and is what Codex and Claude Code's
  own sandbox use. If Apple removes it, the macOS backend must move to an
  `Endpoint Security`-free alternative (likely a helper using the same
  `sandbox_init` API, or Apple's Containerization). Tracked as a platform risk.
- Windows (phase A): only a partial write limit holds (creating and modifying
  files, not deleting or renaming them, see below). A restricted token (`WRITE_RESTRICTED`,
  capability SIDs per writable root) stops writes outside the roots, and `.git\hooks`
  and `.git\config` get deny-write ACEs if they exist at launch. **Deny-read is not
  enforced**: the child runs as the developer and can read `~/.ssh` and the rest.
  Writes into a folder where Everyone, the logon SID or a restricting SID already
  has write access also succeed (codex documents the same). The ACL grants persist
  after the run on purpose, since descendants may outlive warden; the process tree
  itself is killed with warden (job object). Phase B adds deny-read through a
  separate sandbox user.
  - **Deleting and renaming are not limited.** A `WRITE_RESTRICTED` token checks the
    restricting SIDs only for write-class rights, and DELETE is not one. The child can
    delete or rename any file the developer can (`del`, `rd /s`, `ren`), inside or
    outside the roots, and deny ACEs for capability SIDs do not stop it. That includes
    renaming `.git` away and moving a copy with a planted hook back, which defeats the
    `.git\hooks` and `.git\config` denies. Verified on windows-2022 (the ignored tests
    in `sandbox_windows.rs`). Closing it needs phase B or a low-integrity token.
  - **Console injection.** The child shares the user's console and desktop. The job
    object blocks USER handles of other processes, desktop switching, global atoms and
    system-parameter changes, but the child can still write to the console input
    buffer (`WriteConsoleInput`), queueing keystrokes that the parent shell runs after
    warden exits. That is code execution outside the roots, the Windows analogue of
    TIOCSTI. It stays open until phase B's private desktop and ConPTY.
  - **Keychain token.** DESIGN §9 caches the OIDC ID token in the OS keychain, and
    deny-read is off on Windows, so the child (same user) can read it and mint
    further gateway keys until it expires.
  - **ACL side effects.** Grants and denies are written into the real ACLs of the
    workspace and persist (see above), and the first grant on a large tree rewrites
    every ACL below the root, which can take a long time. Later launches are fast.
  - **Same-user processes.** The child cannot open warden for `PROCESS_VM_WRITE`,
    `PROCESS_CREATE_THREAD` or `PROCESS_DUP_HANDLE` (tested). With the logon SID in
    every default DACL, two concurrent launches could open each other with all three
    (found on windows-2022); each launch now has a random SID in its restricting list
    and default DACL instead, and a test covers it. Reading another process is still
    allowed, as for any same-user process.
  - `.cmd`/`.bat` harnesses (npm shims) run through cmd.exe, which cannot be
    quoted safely, so arguments containing `"`, `%` or a line break are refused.
- `TMPDIR` and `/tmp` are writable; a tool can stage data there, but C1 keeps it
  on the machine.

### C3 Credential handling

- Minted per launch with a TTL and a model allowlist; bound to the user's identity
  at the gateway (`user_id`), so spend and logs attribute correctly.
- Never written to disk by warden. Passed by env var, or not at all when the
  harness supports a key-helper command (Pi, Claude Code): then the secret stays in
  the warden parent process and the child fetches it over a `0600` Unix socket.
- Child environment is built from an allowlist; the parent's `ANTHROPIC_API_KEY`
  and friends are not inherited.
- Holds against A1 leaking a key in a screenshot or shell history (it is not in
  their shell).
- Does **not** hold against A3/A4 reading the env var or calling the helper from
  inside the sandbox: that is the harness's privilege by design. What limits the
  blast radius is TTL, budget, model scope, and C1 (the key is only usable toward
  the gateway, and only the gateway is reachable). Revocation at exit is
  best-effort.
- Harnesses may still write their own credential files inside the harness home
  (`auth.json`, `.credentials.json`) if the user runs their native login. Those
  live in a warden-owned directory and are readable by the harness anyway; they do
  not grant anything the sandbox and allowlist do not already grant.

### C4 Identity

OIDC device-authorization flow; the refresh token in the OS keychain; group claims
taken from the ID token. Policy is evaluated against those groups.

- Holds against A2 claiming a group they are not in: groups come from the IdP's
  signed token. Warden validates the ID token signature against the issuer's JWKS
  via `openidconnect`.
- Does **not** hold against A2 editing the trusted-keys file and signing their own
  bundle (see C5), or against a stale group membership until the token refreshes
  (token lifetime bounds this; keep it short at the IdP).
- Group claims can be large (Entra emits an overage marker instead of groups past
  200). Warden must treat a missing groups claim as "no groups" and the launch
  will then be denied by default; document the IdP-side fix (group filtering /
  app roles).

### C5 Signed policy bundle

Ed25519 over the bundle bytes; trusted keys in a root-owned system file;
`not_after` with a bounded grace. Load failure = no launch.

- Holds against A3/A4 tampering with the bundle from inside the sandbox (the file
  is outside the writable set, and even if replaced, the signature fails).
- Holds against a developer *accidentally* running a stale or edited bundle.
- Does **not** hold against A2 with admin rights replacing `trusted-keys`, or
  pointing `--policy` at their own signed bundle after doing so. MDM-managed file
  integrity (or simply the fact that this is a loud, logged action, see C6) is
  the control here. Warden emits `policy.loaded` with the key id and bundle hash on
  every launch, so a rogue key shows up in the audit stream.

### C6 Audit

OTLP to the org collector, asynchronous, bounded queue, never blocks launch.

- Gives visibility into launches, denials, model use, sandbox network denials,
  and which bundle/key was in force.
- Does **not** guarantee delivery: events are dropped when the queue is full or
  the collector is unreachable at exit. The dropped count is reported in the next
  successful export. If audit must be lossless, that is a control-plane feature
  (persisted spool), not milestone 1.
- Audit events never contain credentials, prompts, or file contents.

### C6b The mint server (optional)

`warden mint-serve` holds the LiteLLM master key, so it is the most sensitive
component when deployed. It accepts only IdP-signed ID tokens (signature, issuer,
audience, expiry checked against the IdP's JWKS), re-evaluates the signed bundle
for that user, and never returns anything but a scoped virtual key. Run it on an
internal network, behind TLS, with the master key injected from a secret store;
its logs name the user, harness and models for every mint and never the key.
`/v1/revoke` is authenticated by possession of the virtual key alone and only deletes
keys with `metadata.issued_by = warden`; the server is otherwise reachable
unauthenticated, so put it behind ingress (network policy or an authenticating proxy).
Compromise of the host = compromise of the master key, exactly as for the proxy
host itself.

### C7 The bypass that warden cannot close

A developer can run `claude`, `codex`, `pi` or `opencode` directly, with a
personal API key, no sandbox, and no audit. Warden does not and cannot prevent
this. The controls that do:

1. **Network**: block direct provider endpoints at the egress firewall / SWG /
   DNS for managed devices. Without this, every other control is advisory for A2.
2. **Gateway**: the gateway accepts only credentials it issued (LiteLLM virtual
   keys, JWTs from the org IdP). A personal Anthropic key is useless toward the
   gateway, and the gateway is the only reachable endpoint.
3. **Harness-native managed config** as a second layer: Claude Code
   `managed-settings.json` (root-owned, can force `ANTHROPIC_BASE_URL`,
   disable auto-update and telemetry), Codex `/etc/codex/requirements.toml`
   (can force sandbox mode and a network allowlist). Warden's `doctor` reports
   whether these exist so the org can see gaps. Warden does not write them;
   they are deployed by MDM or the image.
4. **Visibility**: the gateway's own logs show which clients connect; a user
   agent that is not `warden` is a signal.

`README.md` must say this plainly.

## Residual risks, ranked

1. Exfiltration through an allowlisted host (gist, package publish, issue
   comment). Mitigate with a minimal allowlist and internal mirrors; MITM path
   filtering is a possible later control.
2. Local admin bypass (C7). Mitigate at the network and gateway.
3. Damage inside the workspace, and `.git` internals if protection is disabled.
   Mitigate with branch protection and review upstream; the sandbox cannot tell
   a wanted edit from an unwanted one.
4. Secrets in the readable part of the home directory not covered by the deny
   list. Mitigate by extending the catalog per org.
5. `sandbox-exec` deprecation on macOS. Mitigate by watching Apple's releases;
   the `Sandbox` trait makes a backend swap contained.
6. Lost audit events under collector outage. Accept for milestone 1.

## Explicit non-goals

- Protecting against the organisation's own gateway or IdP administrators.
- Preventing a developer with admin rights from running software without warden.
- Content inspection of prompts or completions (that belongs at the gateway).
- Anti-tamper of the `warden` binary itself (code signing and MDM do that).
- Windows network egress and deny-read enforcement before phase B; until then
  `warden run` on Windows needs `defaults.sandbox_allow_degraded`.
