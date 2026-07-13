FROM rust:1.94-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY server ./server
RUN cargo build --release -p vault-server

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
