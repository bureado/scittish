#!/usr/bin/env bash
# Submit a random system binary to scittish for indirect signing and logging.
set -euo pipefail

SERVER="${SCITTISH_SERVER:-http://localhost:8080}"

# Pick a random binary from common system directories
CANDIDATES=()
for dir in /usr/bin /bin; do
  if [ -d "$dir" ]; then
    while IFS= read -r f; do
      CANDIDATES+=("$f")
    done < <(find "$dir" -maxdepth 1 -type f -executable 2>/dev/null | head -50)
  fi
done

if [ ${#CANDIDATES[@]} -eq 0 ]; then
  echo "No executable binaries found in /usr/bin or /bin" >&2
  exit 1
fi

BINARY="${CANDIDATES[$((RANDOM % ${#CANDIDATES[@]}))]}"
BINARY_NAME="$(basename "$BINARY")"
BINARY_SIZE="$(wc -c < "$BINARY")"

echo "=== Submitting random binary for indirect signing ==="
echo "Server:  $SERVER"
echo "Binary:  $BINARY ($BINARY_SIZE bytes)"
echo

scittish-cli push "$BINARY" \
  --subject "example:binary-${BINARY_NAME}" \
  --no-prompt \
  --show-receipt
