# syntax=docker/dockerfile:1.7
# solidus-node container image (v1 node: legacy single-node, HotStuff validator, full node).
#
#   docker build -t solidus-node .
#   docker run --rm solidus-node --help
#
# Runtime layout (see docs/container.md):
#   /etc/solidus   config.toml, genesis.json, node.key, bls.key   (read-only mount)
#   /data          RocksDB (set data_dir = "/data" in config.toml; persistent volume)

FROM rust:1-bookworm AS build
# librocksdb-sys runs bindgen (libclang) and builds RocksDB from source (C++ toolchain).
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev cmake \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# rust-toolchain.toml pins the toolchain; install it in its own layer.
COPY rust-toolchain.toml ./
RUN rustup toolchain install
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p solidus-node \
 && cp target/release/solidus-node /usr/local/bin/solidus-node

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin solidus \
 && mkdir -p /data /etc/solidus \
 && chown solidus:solidus /data
COPY --from=build /usr/local/bin/solidus-node /usr/local/bin/solidus-node
USER 10001
WORKDIR /data
VOLUME ["/data"]
# 9944 JSON-RPC, 30300 libp2p (validator / full node).
EXPOSE 9944 30300
ENTRYPOINT ["solidus-node"]
CMD ["run", "--consensus", "--config", "/etc/solidus/config.toml"]
