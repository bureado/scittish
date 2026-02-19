# scittish-cli examples

Interactive examples for testing end-to-end submission of different payload
types through scittish for signing and transparent logging.

## Prerequisites

These examples assume:
- scittish server running on `http://localhost:8080` (default)
- SCITT ledger running on `https://localhost:8000`
- scittish-cli installed and configured (`scittish-cli set server http://localhost:8080`)
- OCI registry on `localhost:5000` (for receipt indexing)

## Examples

| Script | Description |
|--------|-------------|
| `submit-slsa.sh` | Submit an in-toto SLSA provenance statement |
| `submit-spdx.sh` | Submit an SPDX SBOM document |
| `submit-binary.sh` | Submit a random binary from the system PATH |
| `submit-hash.sh` | Submit a pre-computed SHA-256 hash (no file upload) |
| `submit-all.sh` | Run all examples in sequence |

## Usage

```bash
# Run a single example
./examples/submit-slsa.sh

# Run all examples
./examples/submit-all.sh

# Override the server URL
SCITTISH_SERVER=http://myserver:8080 ./examples/submit-slsa.sh
```

## Payloads

The `payloads/` directory contains sample attestation documents:

- **sample-slsa.json** — SLSA v0.2 provenance (in-toto statement)
- **sample-spdx.json** — SPDX 2.3 SBOM
