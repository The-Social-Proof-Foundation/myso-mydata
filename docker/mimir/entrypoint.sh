#!/bin/sh
set -eu

# Write GCP service account JSON to file for GOOGLE_APPLICATION_CREDENTIALS.
# Avoids embedding JSON in config (which can cause "invalid character '-' in numeric literal"
# when env expansion or YAML parsing corrupts the value).
CREDS_FILE="/tmp/gcp-credentials.json"
if [ -n "${GCP_SERVICE_ACCOUNT_JSON:-}" ]; then
  echo "${GCP_SERVICE_ACCOUNT_JSON}" > "${CREDS_FILE}"
  export GOOGLE_APPLICATION_CREDENTIALS="${CREDS_FILE}"
fi

exec mimir -config.file=/etc/mimir/config.yaml -config.expand-env=true "$@"
