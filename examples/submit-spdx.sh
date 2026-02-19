#!/usr/bin/env bash
# Submit an SPDX SBOM document to scittish for signing and logging.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER="${SCITTISH_SERVER:-http://localhost:8080}"
PAYLOAD="$SCRIPT_DIR/payloads/sample-spdx.json"

echo "=== Submitting SPDX SBOM ==="
echo "Server:  $SERVER"
echo "Payload: $PAYLOAD ($(wc -c < "$PAYLOAD") bytes)"
echo

scittish-cli push "$PAYLOAD" \
  --subject "example:spdx-sbom" \
  --no-prompt \
  --show-receipt
