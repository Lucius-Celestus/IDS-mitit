FROM rust:1.86-slim as builder
RUN apt-get update && apt-get install -y pkg-config libpcap-dev libssl-dev
WORKDIR /usr/src/ids_project
COPY . .

RUN cargo build --release


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libpcap0.8 libssl3 && rm -rf /var/lib/apt/lists/*


COPY --from=builder /usr/src/ids_project/target/release/ids_collector /usr/local/bin/ids_collector


RUN chmod +x /usr/local/bin/ids_collector


ENTRYPOINT ["/usr/local/bin/ids_collector"]