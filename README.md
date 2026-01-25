# scittish

A simple REST API for SCITT signing operations, designed to run in a Docker container.

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

This persists certificates and receipt cache across container restarts. The certificate chain is printed to the container logs on startup.

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

Response headers include `X-Scittish-Cache-Hit: true/false` to indicate if the receipt was served from cache.

### Health check

```bash
curl http://localhost:8080/health
```