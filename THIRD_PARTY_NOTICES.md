# Third-party notices

## openai/codex (Apache-2.0)

https://github.com/openai/codex. Attribution from its NOTICE file:

> OpenAI Codex
> Copyright 2025 OpenAI

The following files are derived from the `codex-rs` sandbox implementation:

- `crates/warden-sandbox/profiles/seatbelt_base.sbpl` from `codex-rs/sandboxing/src/seatbelt_base_policy.sbpl`
- `crates/warden-sandbox/profiles/seatbelt_network.sbpl` from `codex-rs/sandboxing/src/seatbelt_network_policy.sbpl`
- The bubblewrap argument layout in `linux.rs` and the proxy bridge in `proxy.rs` (`crates/warden-sandbox/src/`)
  follow `codex-rs/linux-sandbox/src/{bwrap.rs,proxy_routing.rs}`.

Used under the Apache License, Version 2.0; see `LICENSE`.
