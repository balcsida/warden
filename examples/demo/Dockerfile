# Demo image: warden + Pi + a signed demo bundle. Build context is the repo root.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p warden-cli

FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap curl ca-certificates jq \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/warden /usr/local/bin/warden
ENV WARDEN_CONFIG=/etc/warden WARDEN_DATA=/var/lib/warden
RUN npm install -g @earendil-works/pi-coding-agent \
 && mkdir -p "$WARDEN_DATA/homes/pi" \
 && PI_CODING_AGENT_DIR="$WARDEN_DATA/homes/pi" pi install npm:pi-provider-litellm \
 # The demo gateway is plain http on a non-loopback host, which the extension refuses by default
 # (and its MCP registration refuses regardless, so turn that off instead of warning every run).
 && jq '.litellm.providers.litellm += {allowInsecureHttp: true, enableMcp: false}' "$WARDEN_DATA/homes/pi/settings.json" > /tmp/s.json \
 && mv /tmp/s.json "$WARDEN_DATA/homes/pi/settings.json"

# Demo bundle: the example policy, pointed at the compose services, dev identity on,
# plus the tiny `probe` harness. Signed with a throwaway key generated here.
COPY examples/demo/probe.toml $WARDEN_CONFIG/adapters/probe.toml
COPY examples/policy.bundle /tmp/policy.bundle
RUN jq '.defaults.allow_dev_identity = true \
      | .providers = [{kind:"litellm", id:"gw", base_url:"http://litellm:4000", mint_url:"http://mint:8787"}] \
      | .catalog.harnesses += ["probe"] | .catalog.harness_sets.approved += ["probe"]' \
      /tmp/policy.bundle > $WARDEN_CONFIG/policy.bundle \
 && warden policy keygen > /tmp/keys \
 && awk '/^public:/ {print $2}' /tmp/keys > $WARDEN_CONFIG/trusted-keys \
 && warden policy sign $WARDEN_CONFIG/policy.bundle --key "$(awk '/^private:/ {print $2}' /tmp/keys)" \
 && rm /tmp/keys /tmp/policy.bundle

WORKDIR /work
