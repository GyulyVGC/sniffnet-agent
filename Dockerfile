FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/sniffnet-agent

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/sniffnet-agent/target/release/sniffnet-agent /usr/local/bin/sniffnet-agent

ENTRYPOINT ["sniffnet-agent"]
