# syntax=docker/dockerfile:1

# ---- build: static musl binary (SQLite is compiled in via rusqlite "bundled") ----
FROM rust:1.98-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
# Build dependencies first so they are cached as a separate layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src
COPY src ./src
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked \
 && cp target/release/metriccupid-push /metriccupid-push
# Empty data dir, copied with nonroot ownership (distroless has no shell).
RUN mkdir /data

# ---- runtime: no shell, no package manager, non-root ----
# TLS roots are compiled in (webpki-roots), so no system CA bundle is needed.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /metriccupid-push /usr/local/bin/metriccupid-push
# v2 SQLite database (WAL). The only writable path; the root FS stays read-only.
COPY --from=builder --chown=65532:65532 /data /data
VOLUME ["/data"]
USER nonroot:nonroot
EXPOSE 8080
ENV BIND=0.0.0.0:8080 \
    DATA_DIR=/data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/metriccupid-push", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/metriccupid-push"]
