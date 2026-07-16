# Exact patch version, kept in sync with rust-toolchain.toml, so the image
# builds with the same compiler as CI and local reproductions. For a fully
# reproducible image, pin this and the runtime base below by `@sha256:<digest>`
# (see docs/REPRODUCIBLE_BUILDS.md).
FROM rust:1.97.0-slim AS builder
WORKDIR /build
# Copy the whole workspace: Cargo must load every member manifest to resolve the
# workspace (root Cargo.toml lists apps/* too), even though `-p vault-server`
# only compiles the server and its dependencies. Build context is the repo root
# (`docker build -f server/Dockerfile .`); .dockerignore trims target/, .git, …
COPY . .
RUN cargo build --release --locked -p vault-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /data vault
COPY --from=builder /build/target/release/vault-server /usr/local/bin/vault-server
USER vault
VOLUME /data
ENV BV_LISTEN_ADDR=0.0.0.0:8080 \
    BV_DB_PATH=/data/vault.db
EXPOSE 8080
ENTRYPOINT ["vault-server"]
