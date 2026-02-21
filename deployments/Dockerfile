# Build stage
FROM rust:1.89-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --package node

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/node /usr/local/bin/kairos-node

ENTRYPOINT ["kairos-node"]
