# Pinned by digest-able tag rather than :latest so a rebuild of an old commit
# produces the same binary.
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /build

# Dependencies first, as their own layer: they change far less often than the
# source, so an edit to src/ does not re-download and rebuild the tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Touch so cargo notices the real main.rs replaced the stub above; without this
# it can consider the binary fresh and ship the placeholder.
RUN touch src/main.rs && cargo build --release --locked

# Runtime needs libssl and CA certificates for TLS to Postgres. rustls is
# vendored, but the CA bundle is not.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root, and no home directory to write into. The service holds no state.
RUN useradd --system --uid 1000 --no-create-home --shell /usr/sbin/nologin registry
USER 1000

COPY --from=builder /build/target/release/harness-registry /usr/local/bin/harness-registry

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/harness-registry"]
