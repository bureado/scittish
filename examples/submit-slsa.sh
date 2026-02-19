#!/usr/bin/env bash
# Submit a SLSA provenance statement to scittish for signing and logging.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER="${SCITTISH_SERVER:-http://localhost:8080}"
PAYLOAD="$SCRIPT_DIR/payloads/sample-slsa.json"

echo "=== Submitting SLSA provenance statement ==="
echo "Server:  $SERVER"
echo "Payload: $PAYLOAD ($(wc -c < "$PAYLOAD") bytes)"
echo

scittish-cli push "$PAYLOAD" \
  --subject "example:slsa-provenance" \
  --no-prompt \
  --show-receipt
