# scittish

A simple REST API for SCITT signing and submission operations, designed to run in a Docker container. Supports remote attestation on Azure Confidential Container Instances (C-ACI).

## Building

```bash
docker buildx build -t scittish:latest .
```

## Running

```bash
docker run -p 8080:8080 \
  -v scittish-certs:/var/lib/scittish/certs \
  -v scittish-cache:/var/cache/scittish \
  -e SCITT_URL=https://your-scitt-ledger:8000 \
  scittish:latest
```

**Note:** `SCITT_URL` must point to a running SCITT ledger instance. The container will sign payloads and submit them to this ledger. You can run your own ledger using [scitt-ccf-ledger](https://github.com/microsoft/scitt-ccf-ledger) (virtual mode is available if you don't have confidential compute hardware).

This persists certificates and the receipt cache across container restarts. The certificate chain is printed to the container logs on startup.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCITT_URL` | `https://localhost:8000` | SCITT ledger URL |
| `MAA_ENDPOINT` | `sharedeus.eus.attest.azure.net` | Microsoft Azure Attestation endpoint |
| `ALLOW_FAKE_ATTESTATION` | `false` | Allow fake attestation reports for testing on non-SNP systems |

## API Usage

### Get service properties

```bash
curl http://localhost:8080/properties
```

Returns the certificate chain and SCITT ledger URL.

### Sign a payload

Sign any file directly using `--data-binary`:

```bash
# Sign a JSON file
curl -X POST --data-binary '@artifact.json' \
  -H "Content-Type: application/json" \
  -H "X-Scittish-Subject: product:myproduct:v1" \
  http://localhost:8080/sign

# Sign a binary file (SBOM, firmware, etc.)
curl -X POST --data-binary '@firmware.bin' \
  -H "Content-Type: application/octet-stream" \
  http://localhost:8080/sign

# Sign by hash only (not yet implemented)
curl -X POST \
  -H "X-Scittish-Payload-Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  http://localhost:8080/sign
```

Request:
- **Body**: Raw payload bytes (required unless `X-Scittish-Payload-Hash` is provided)
- **Content-Type**: The content type of the payload (used in the signed statement)

Request headers:
- `X-Scittish-Subject`: Optional subject string used as the SCITT feed
- `X-Scittish-Payload-Hash`: SHA256 hash of the payload (64-character hex string). If provided, body is ignored. (Not yet implemented)

Response:
```json
{"transparent_statement": "<base64-encoded receipt>"}
```

The receipt (also known as a [transparent statement](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)) is a COSE signed statement with an embedded receipt from the SCITT ledger.

Response headers include `X-Scittish-Cache-Hit: true/false` to indicate if the response was served from cache.

### Get attestation token

```bash
curl -X POST http://localhost:8080/attest \
  -H "Content-Type: application/json" \
  -d '{"nonce": "<base64-encoded-nonce>"}'
```

Request body:
- `nonce`: Optional base64-encoded nonce for freshness guarantee
- `maa_endpoint`: Optional MAA endpoint (defaults to `sharedeus.eus.attest.azure.net`)

Response:
```json
{"token": "<MAA JWT token>"}
```

The token is an Entity Attestation Token (EAT) from [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview). It contains claims about the SEV-SNP hardware environment and includes the nonce (if provided) and a signature over the nonce using scittish's signing key, proving key control.

**Note:** This endpoint requires running on SEV-SNP enabled hardware (e.g., Azure Confidential Container Instances). On non-SNP systems, it will return an error unless `ALLOW_FAKE_ATTESTATION=true` is set (for testing only - MAA will reject fake reports).

Response headers include `X-Scittish-Cache-Hit: true/false`. Tokens are cached based on nonce and MAA endpoint until they expire.

### Health check

```bash
curl http://localhost:8080/health
```