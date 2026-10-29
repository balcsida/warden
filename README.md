# warden

Harness-neutral launcher for agentic coding tools (Claude Code, Codex, OpenCode, Pi).
One set of rules, enforced around the harness: provider routing through your
gateway, OS-level sandboxing, Cedar policy per identity-provider group.

Status: pre-alpha, under construction. See `docs/DESIGN.md` and `docs/THREAT_MODEL.md`.

## What is and isn't enforced

Warden is a client-side control. On a machine where the developer is an
administrator it is a guided default: the developer can run a harness without
warden, or edit the trusted-keys file. What makes "models only through the
gateway" hold is network-level blocking of direct provider endpoints plus a
gateway that accepts only credentials it issued. Deploy warden assuming those
exist. `docs/THREAT_MODEL.md` has the details.

## License

Apache-2.0. Parts of the macOS and Linux sandbox profiles derive from
[openai/codex](https://github.com/openai/codex) (Apache-2.0); see `THIRD_PARTY_NOTICES.md`.
