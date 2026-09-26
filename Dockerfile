FROM rust:1.98-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf build-essential ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p boom-main

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home gateway
COPY --from=builder /src/target/release/boom-gateway /usr/local/bin/boom-gateway
USER gateway
WORKDIR /home/gateway
EXPOSE 4000
ENTRYPOINT ["boom-gateway"]
