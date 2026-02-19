#!/usr/bin/env bash
# Run all scittish-cli examples in sequence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

for example in submit-slsa.sh submit-spdx.sh submit-binary.sh submit-hash.sh; do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Running: $example"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  "$SCRIPT_DIR/$example"
  echo
done

echo "All examples completed."
