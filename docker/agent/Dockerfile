# Image the reader agent runs in: one agent CLI, git, curl and harness-proxy, nothing else, since the agent
# has a shell while it reads a report that may be hostile.
#   docker build --target claude -t tamis-agent:claude docker/agent
#   docker build --target codex -t tamis-agent:codex docker/agent

# Each release tag sits beside the digest of its asset, as in scrutineer's Dockerfile.runner, so a version
# bump updates both and a mismatch fails sha256sum below.
ARG CLAUDE_AMD64_LOCK=v2.1.325@sha256:9686b0fb1eefbd7f2cc1f53f932516c29cd605e9d976223323a6c6e9a4c9c7fe
ARG CLAUDE_ARM64_LOCK=v2.1.325@sha256:2abe2bea8b802190a303f335b0fd09f95eb775457e99df5a4778b09dfab6bbd6
ARG CODEX_AMD64_LOCK=rust-v0.169.0@sha256:3b8ed091149cc63a59046b9f094bcfa21cdb4dda15ede441ce369bcee4a71ba0
ARG CODEX_ARM64_LOCK=rust-v0.169.0@sha256:c8d0b4ab2a97c595b70b10412d36d0d5464dcef1e1d3246b073d48017cdf5a4f
ARG HARNESS_VERSION=v0.1.21

FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS proxy
ARG HARNESS_VERSION
# The egress proxy runs beside every untrusted agent container.
RUN GOBIN=/out CGO_ENABLED=0 go install -trimpath github.com/alpha-omega-security/harness/cmd/harness-proxy@${HARNESS_VERSION}

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git ripgrep libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -ms /bin/bash agent
COPY --from=proxy /out/harness-proxy /usr/local/bin/harness-proxy

FROM base AS claude
ARG TARGETARCH
ARG CLAUDE_AMD64_LOCK
ARG CLAUDE_ARM64_LOCK
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) arch=x64;   lock="${CLAUDE_AMD64_LOCK}" ;; \
      arm64) arch=arm64; lock="${CLAUDE_ARM64_LOCK}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/claude.tgz "https://github.com/anthropics/claude-code/releases/download/${lock%@*}/claude-linux-${arch}.tar.gz"; \
    echo "${lock#*@sha256:}  /tmp/claude.tgz" | sha256sum -c -; \
    tar -xzf /tmp/claude.tgz -C /usr/local/bin claude; \
    rm /tmp/claude.tgz; \
    claude --version
USER agent

FROM base AS codex
ARG TARGETARCH
ARG CODEX_AMD64_LOCK
ARG CODEX_ARM64_LOCK
# The package archive installs the CLI with its version-matched code-mode host.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) triple=x86_64-unknown-linux-musl;  lock="${CODEX_AMD64_LOCK}" ;; \
      arm64) triple=aarch64-unknown-linux-musl; lock="${CODEX_ARM64_LOCK}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/codex.tgz "https://github.com/openai/codex/releases/download/${lock%@*}/codex-package-${triple}.tar.gz"; \
    echo "${lock#*@sha256:}  /tmp/codex.tgz" | sha256sum -c -; \
    tar -xzf /tmp/codex.tgz -C /tmp bin/codex bin/codex-code-mode-host; \
    install -m 0755 /tmp/bin/codex /tmp/bin/codex-code-mode-host /usr/local/bin/; \
    rm -rf /tmp/codex.tgz /tmp/bin; \
    codex --version
USER agent
