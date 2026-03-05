#!/bin/sh
set -e
# Export all environment variables
for var in $(env | cut -d= -f1); do
    export "$var"
done

# Copy config from staging (volume at /app/config overlays COPY'd files at runtime)
cp /opt/mydata-proxy/config/mydata-proxy-config-railway.yaml /app/config/mydata-proxy-config-railway.yaml

# Override remote-write URL from REMOTE_WRITE_URL env if set (Railway deployment)
# Use awk to avoid sed quoting issues in some shell environments
if [ -n "${REMOTE_WRITE_URL}" ]; then
  awk -v url="${REMOTE_WRITE_URL}" '/^  url:/{print "  url: \"" url "\""; next}1' /app/config/mydata-proxy-config-railway.yaml > /tmp/mydata-proxy-config.yaml && mv /tmp/mydata-proxy-config.yaml /app/config/mydata-proxy-config-railway.yaml
fi

# Generate bearer tokens YAML file from environment variables
cat > /app/config/bearer-tokens-railway.yaml << EOF
- name: key-server-1
  token: ${KEY_SERVER_1_TOKEN:-key-server-1-token}
- name: key-server-2
  token: ${KEY_SERVER_2_TOKEN:-key-server-2-token}
- name: key-server-3
  token: ${KEY_SERVER_3_TOKEN:-key-server-3-token}
- name: sample-client
  token: ${SAMPLE_CLIENT_TOKEN:-sample-client-token}
EOF

exec /opt/mydata-proxy/bin/mydata-proxy --config=/app/config/mydata-proxy-config-railway.yaml --bearer-tokens-path=/app/config/bearer-tokens-railway.yaml "$@"
