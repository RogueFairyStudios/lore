# SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
# SPDX-License-Identifier: MIT
#
# Build from the repository root (compatible with Docker BuildKit and Railway):
#   docker build -f contrib/oidc/roguefairy/bridge/Dockerfile -t rfs-lore-bridge .
FROM rust:slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libprotobuf-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY .cargo .cargo
COPY Cargo.toml build-helper.rs ./
COPY lore-base lore-base
COPY lore-error-set lore-error-set
COPY lore-error-set-macro lore-error-set-macro
COPY lore-io lore-io
COPY lore-macro lore-macro
COPY lore-proto lore-proto
COPY contrib/oidc/roguefairy/bridge/Cargo.toml contrib/oidc/roguefairy/bridge/Cargo.lock contrib/oidc/roguefairy/bridge/

RUN sed -i '/^members = \[/,/^\]/c\members = ["lore-base", "lore-error-set", "lore-error-set-macro", "lore-io", "lore-macro", "lore-proto"]' /build/Cargo.toml \
    && mkdir -p contrib/oidc/roguefairy/bridge/src \
    && printf '' > contrib/oidc/roguefairy/bridge/src/lib.rs \
    && printf 'fn main() {}\n' > contrib/oidc/roguefairy/bridge/src/main.rs \
    && cargo build --release --locked \
        --manifest-path /build/contrib/oidc/roguefairy/bridge/Cargo.toml \
        --bin rfs-lore-bridge \
    && cargo clean --release \
        --manifest-path /build/contrib/oidc/roguefairy/bridge/Cargo.toml \
        -p rfs-lore-bridge \
    && rm -rf /build/contrib/oidc/roguefairy/bridge/src

COPY contrib/oidc/roguefairy/bridge/src contrib/oidc/roguefairy/bridge/src

RUN cargo build --release --locked \
        --manifest-path /build/contrib/oidc/roguefairy/bridge/Cargo.toml \
        --bin rfs-lore-bridge \
    && cp /build/contrib/oidc/roguefairy/bridge/target/release/rfs-lore-bridge /build/rfs-lore-bridge-bin

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home rfsbridge \
    && mkdir -p /data /etc/rfs-lore-bridge \
    && chown -R rfsbridge:rfsbridge /data /etc/rfs-lore-bridge

COPY --from=builder /build/rfs-lore-bridge-bin /usr/local/bin/rfs-lore-bridge

RUN cat <<'EOF' > /usr/local/bin/docker-entrypoint.sh \
    && chmod 0755 /usr/local/bin/docker-entrypoint.sh
#!/bin/sh
set -eu
if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    chown rfsbridge:rfsbridge /data
    exec gosu rfsbridge /usr/local/bin/rfs-lore-bridge "$@"
fi
exec /usr/local/bin/rfs-lore-bridge "$@"
EOF

WORKDIR /data
EXPOSE 8190

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
