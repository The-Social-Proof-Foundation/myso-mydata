# Bookworm, same as the runtime image. Bullseye links OpenSSL 1.1 (libssl.so.1.1);
# bookworm only ships libssl.so.3, so a bullseye binary cannot start there.
FROM rust:1.90-bookworm AS builder

ARG PROFILE=release

WORKDIR /work

COPY ./crates ./crates
COPY ./Cargo.toml ./Cargo.lock ./

ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION

# --locked keeps allocative 0.3.4 with hashbrown 0.14. starlark_map 0.13.0
# does not compile against allocative 0.3.6's hashbrown 0.16 HashTable.
RUN cargo build --locked --bin key-server --profile $PROFILE --config net.git-fetch-with-cli=true
FROM debian:bookworm-slim AS runtime

EXPOSE 2024 8080

# bullseye-security 404s these packages. bookworm-slim has no bash; the entrypoint shebang needs it.
RUN apt-get update && apt-get install -y \
    bash \
    cmake \
    clang \
    libssl3 \
    libpq5 \
    ca-certificates \
    libpq-dev \
    postgresql \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /work/target/release/key-server /opt/key-server/bin/

# Entrypoint: export env vars, generate config from env if CONFIG_PATH points to missing file, then start
RUN echo '#!/bin/bash\n\
set -e\n\
for var in $(env | cut -d= -f1); do export "$var"; done\n\
\n\
# If CONFIG_PATH is set but file does not exist, generate config from env vars (Railway-friendly)\n\
if [ -n "${CONFIG_PATH}" ] && [ ! -f "${CONFIG_PATH}" ]; then\n\
  if [ -z "${KEY_SERVER_OBJECT_ID}" ]; then\n\
    echo "ERROR: KEY_SERVER_OBJECT_ID must be set when config file does not exist at ${CONFIG_PATH}" >&2\n\
    exit 1\n\
  fi\n\
  mkdir -p $(dirname "${CONFIG_PATH}")\n\
  cat > "${CONFIG_PATH}" << EOF\n\
network: ${NETWORK:-Testnet}\n\
node_url: ${NODE_URL:-http://fullnode.testnet.mysocial.network:9000}\n\
server_mode: !Open\n\
  key_server_object_id: '\''${KEY_SERVER_OBJECT_ID}'\''\n\
EOF\n\
  echo "Generated config from env vars at ${CONFIG_PATH}"\n\
fi\n\
\n\
exec /opt/key-server/bin/key-server "$@"' > /opt/key-server/entrypoint.sh && \
    chmod +x /opt/key-server/entrypoint.sh

ENTRYPOINT ["/opt/key-server/entrypoint.sh"]
