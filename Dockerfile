FROM rust:1.93 AS builder
ARG CODEXUSAGE_VERSION=0.2.0
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN cargo install --locked --version ${CODEXUSAGE_VERSION} codexusage
RUN rm -rf src
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/codex-gitlab-code-review /usr/local/bin/codex-gitlab-review
COPY --from=builder /usr/local/cargo/bin/codexusage /usr/local/bin/codexusage
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/codex-gitlab-review"]
