FROM rust:1.85 AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/codex-gitlab-code-review /usr/local/bin/codex-gitlab-review
ENTRYPOINT ["/usr/local/bin/codex-gitlab-review"]
