#!/usr/bin/env bash
# Submit a pre-computed SHA-256 hash to scittish (no file upload).
# This demonstrates submitting a hash reference without the original payload.
set -euo pipefail

SERVER="${SCITTISH_SERVER:-http://localhost:8080}"

# Compute hash of /usr/bin/env as a reproducible example
TARGET="/usr/bin/env"
HASH="sha256:$(sha256sum "$TARGET" | awk '{print $1}')"

echo "=== Submitting pre-computed hash ==="
echo "Server:  $SERVER"
echo "Target:  $TARGET"
echo "Hash:    $HASH"
echo

scittish-cli push "$HASH" \
  --subject "example:hash-env" \
  --no-prompt \
  --show-receipt
