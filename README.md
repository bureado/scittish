# scittish

A simple REST API for SCITT signing and submission operations, designed to run in a Docker container.

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

## API Usage

### Get service properties

```bash
curl http://localhost:8080/properties
```

Returns the certificate chain and SCITT ledger URL.

### Sign a payload

```bash
curl -X POST http://localhost:8080/sign \
  -H "Content-Type: application/json" \
  -d '{"payload": {"name": "my-artifact", "version": "1.0.0"}, "subject": "product:myproduct:v1"}'
```

Request body:
- `payload`: The JSON payload to sign (required unless `payload_hash` is provided)
- `payload_hash`: SHA256 hash of the payload as a 64-character hex string (not yet implemented)
- `subject`: Optional subject string used as the SCITT feed

Response:
```json
{"transparent_statement": "<base64-encoded receipt>"}
```

The receipt (also known as a [transparent statement](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)) is a COSE signed statement with an embedded receipt from the SCITT ledger.

Response headers include `X-Scittish-Cache-Hit: true/false` to indicate if the response was served from cache.

### Health check

```bash
curl http://localhost:8080/health
```