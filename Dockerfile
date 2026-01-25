# Stage 1: Build Go attest-helper
FROM golang:1.21-alpine AS go-builder

WORKDIR /build

# Copy Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy Go source
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/

# Build attest-helper
RUN CGO_ENABLED=0 GOOS=linux go build -o attest-helper ./cmd/attest-helper

# Stage 2: Python application
FROM python:3.12-slim

WORKDIR /app

# Install pyscitt dependencies first (these are heavier)
# These match pyscitt's setup.py requirements
RUN pip install --no-cache-dir \
    ccf==6.* \
    cryptography==44.* \
    httpx \
    cbor2==5.8.* \
    pycose==1.1.0 \
    pyjwt \
    jwcrypto==1.5.* \
    azure-identity \
    azure-confidentialledger==1.* \
    loguru

# Install oras CLI for OCI registry indexing
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sLO https://github.com/oras-project/oras/releases/download/v1.2.0/oras_1.2.0_linux_amd64.tar.gz \
    && tar -xzf oras_1.2.0_linux_amd64.tar.gz -C /usr/local/bin oras \
    && rm oras_1.2.0_linux_amd64.tar.gz \
    && apt-get remove -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy pyscitt module
COPY pyscitt/pyscitt /app/pyscitt

# Install API dependencies
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY api/app.py api/certs.py ./
COPY api/resolvers ./resolvers
COPY api/indexers ./indexers

# Copy Go binary from builder
COPY --from=go-builder /build/attest-helper /app/attest-helper

# Create directories for certs, cache, and jobs
RUN mkdir -p /var/cache/scittish /var/lib/scittish/certs /var/cache/scittish/jobs

ENV SCITT_CACHE_DIR=/var/cache/scittish
ENV SCITT_CERTS_DIR=/var/lib/scittish/certs
ENV SCITT_JOBS_DIR=/var/cache/scittish/jobs
ENV SCITT_URL=https://localhost:8000
ENV MAA_ENDPOINT=sharedeus.eus.attest.azure.net
ENV ATTEST_HELPER_PATH=/app/attest-helper
ENV ALLOW_FAKE_ATTESTATION=false
ENV OCI_REGISTRY=
ENV OCI_NAMESPACE=scittish/subjects
ENV ORAS_PATH=/usr/local/bin/oras
ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
