FROM rust:slim-bookworm

# Устанавливаем всё необходимое для gRPC и eBPF
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libpcap-dev \
    clang \
    llvm \
    libelf-dev \
    build-essential \
    linux-headers-amd64 \
    linux-libc-dev \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем всё содержимое корня в /app
COPY . .

# Переходим в папку core, где лежит Cargo.toml
WORKDIR /app/core

RUN clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c ebpf/filter.bpf.c -o ebpf/filter.bpf.o
# Собираем бинарник
RUN cargo build --release --features production

# Запуск
CMD ["./target/release/aegis-core"]