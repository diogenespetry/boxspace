# ---- build ----
FROM rust:1-slim-bookworm AS build
# aws-lc (TLS for outgoing webhooks) needs a C toolchain and cmake.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake make gcc g++ perl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Cache dependencies separately from the application code.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src console && echo 'fn main() {}' > src/main.rs && touch console/index.html \
 && cargo build --release --locked \
 && rm -rf src console

COPY src src
COPY console console
RUN touch src/main.rs && cargo build --release --locked \
 && mkdir -p /out/data \
 && cp target/release/boxspace /out/boxspace

# ---- runtime ----
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="BoxSpace" \
      org.opencontainers.image.description="Servidor de armazenamento de objetos compatível com S3" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/diogenespetry/boxspace"

COPY --from=build /out/boxspace /usr/local/bin/boxspace
# The data directory must be writable by the non-root user (uid 65532).
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
VOLUME ["/data"]
EXPOSE 9000 9001

ENTRYPOINT ["/usr/local/bin/boxspace"]
CMD ["server", "--address", ":9000", "--console-address", ":9001", "/data"]
