FROM rust:1.85-slim as builder
RUN apt-get update && apt-get install -is pkg-config libpcap-dev -y
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -is libpcap0.8 -y && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ids_collector /usr/local/bin/
CMD ["IDS_collector"]