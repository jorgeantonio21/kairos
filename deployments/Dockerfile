# Fallback Dockerfile for local development on macOS.
# For production/CI, use the Nix-built image: nix build .#dockerImage
FROM rust:1.90-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev protobuf-compiler libclang-dev \
    libbsd-dev uuid-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release --package node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libssl3 ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/node /usr/local/bin/kairos-node
ENTRYPOINT ["kairos-node"]
