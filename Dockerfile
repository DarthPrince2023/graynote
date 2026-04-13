FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# We do not need the Rust toolchain to run the binary!
FROM debian:latest
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/graynote /usr/local/bin/graynote
RUN useradd -m -s /bin/bash graynote && \
    chown graynote /usr/local/bin/graynote
USER graynote
ENTRYPOINT ["/usr/local/bin/graynote"]