# Image the reader agent runs in: one agent CLI, git, curl and harness-proxy, nothing else, since the agent
# has a shell while it reads a report that may be hostile.
#   docker build --target claude -t tamis-agent:claude docker/agent
#   docker build --target codex -t tamis-agent:codex docker/agent

# Each release tag sits beside the digest of its asset, as in scrutineer's Dockerfile.runner, so a version
# bump updates both and a mismatch fails sha256sum below.
ARG CLAUDE_AMD64_LOCK=v2.1.319@sha256:8cf226393c8eca446d6ca60fa6bbe3fa7b5fa4de82a7b410d1edbd48689cd776
ARG CLAUDE_ARM64_LOCK=v2.1.319@sha256:2e7348ffc96d52ccb20e34c81240ebc92505edc84d7bf29182d62c29bf6fa066
ARG CODEX_AMD64_LOCK=rust-v0.167.0@sha256:3bbf75e83de6b58aed28f2cf6e33ad423ec31fd4700a1457b94be557ea5a7c6e
ARG CODEX_ARM64_LOCK=rust-v0.167.0@sha256:0de261ecf1e7f3028a7952f03fca2093f749277d38590b78bb32f8567756bbb7
ARG HARNESS_VERSION=v0.1.21

FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS proxy
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
