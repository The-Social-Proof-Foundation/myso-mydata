# Start with a Rust base image
FROM rust:1.90-bullseye  AS builder

ARG PROFILE=release

WORKDIR work

COPY ./crates ./crates
COPY ./Cargo.toml ./

ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION

RUN cargo build --bin key-server --profile $PROFILE --config net.git-fetch-with-cli=true
FROM debian:bullseye-slim AS runtime

EXPOSE 2024 8080

RUN apt-get update && apt-get install -y cmake clang libpq5 ca-certificates libpq-dev postgresql

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
node_url: ${NODE_URL:-https://fullnode.testnet.mysocial.network:443}\n\
server_mode: !Open\n\
  key_server_object_id: '\''${KEY_SERVER_OBJECT_ID}'\''\n\
EOF\n\
  echo "Generated config from env vars at ${CONFIG_PATH}"\n\
fi\n\
\n\
exec /opt/key-server/bin/key-server "$@"' > /opt/key-server/entrypoint.sh && \
    chmod +x /opt/key-server/entrypoint.sh

ENTRYPOINT ["/opt/key-server/entrypoint.sh"]
