# scittish

A simple REST API for SCITT signing and submission operations, designed to run in a Docker container. Supports remote attestation on Azure Confidential Container Instances (C-ACI).

## Development

### Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r api/requirements.txt -r requirements-dev.txt
```

### Running tests

```bash
pytest
```

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

Signing is asynchronous. Submit a payload and receive a job ID, then poll until complete.

**Step 1: Submit payload**

```bash
curl -X POST --data-binary '@artifact.json' \
  -H "Content-Type: application/json" \
  -H "X-Scittish-Subject: product:myproduct:v1" \
  http://localhost:8080/sign
```

Response (`202 Accepted`):
```json
{"job_id": "abc123...", "status": "pending"}
```

The `Location` header contains the polling URL.

**Step 2: Poll for completion**

```bash
curl http://localhost:8080/sign/{job_id}
```

Response while processing (`202 Accepted`):
```json
{"job_id": "abc123...", "status": "processing"}
```

Response when complete (`200 OK`):
- Raw COSE bytes (`application/cose` content type)

**One-liner with polling:**

```bash
# Submit and poll until done
JOB=$(curl -s -X POST --data-binary '@artifact.json' \
  -H "Content-Type: application/json" \
  http://localhost:8080/sign | jq -r '.job_id')

while true; do
  RESP=$(curl -s -w "%{http_code}" -o /tmp/receipt.cose http://localhost:8080/sign/$JOB)
  [ "$RESP" = "200" ] && break
  sleep 1
done
# Receipt is now in /tmp/receipt.cose
```

Request headers:
- `X-Scittish-Subject`: Optional subject string used as the SCITT feed
- `X-Scittish-Payload-Hash`: SHA256 hash of the payload (64-character hex string). If provided, body is ignored. (Not yet implemented)

The receipt (also known as a [transparent statement](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)) is a COSE signed statement with an embedded receipt from the SCITT ledger.

**Caching:** If the same payload (and subject) was previously signed, the receipt is returned immediately with `200 OK` and `X-Scittish-Cache-Hit: true`.

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