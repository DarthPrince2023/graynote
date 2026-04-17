FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies - this is the caching Docker layer!
FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# We do not need the Rust toolchain to run the binary!
FROM debian:latest
COPY --from=builder /app/target/release/graynote /usr/local/bin/graynote
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash graynote && \
    chown graynote /usr/local/bin/graynote && \
    mkdir -p /usr/local/bin/trace && \
    chown graynote /usr/local/bin/trace
USER graynote
VOLUME [ "/usr/local/bin/trace" ]

ENTRYPOINT ["/usr/local/bin/graynote"]