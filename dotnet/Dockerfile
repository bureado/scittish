# Stage 1: Build Go attest-helper (commented out - not used currently)
# FROM golang:1.21-alpine AS go-builder
#
# WORKDIR /build
#
# # Copy Go modules
# COPY ../go.mod ../go.sum ./
# RUN go mod download
#
# # Copy Go source
# COPY ../cmd/ ./cmd/
# COPY ../pkg/ ./pkg/
#
# # Build attest-helper
# RUN CGO_ENABLED=0 GOOS=linux go build -o attest-helper ./cmd/attest-helper

# Stage 2: Build .NET application with CoseSignTool libraries
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS dotnet-builder

WORKDIR /src

# Clone CoseSignTool v1.7.1 for library references
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && git clone --depth 1 --branch v1.7.1 https://github.com/microsoft/CoseSignTool.git /src \
    && rm -rf /src/.git \
    && apt-get remove -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Copy scittish API source into the tree (sibling to CoseSignTool projects)
COPY *.csproj *.cs appsettings*.json /src/Scittish.Api/
COPY Services/ /src/Scittish.Api/Services/
COPY Models/ /src/Scittish.Api/Models/
COPY Resolvers/ /src/Scittish.Api/Resolvers/
COPY Indexers/ /src/Scittish.Api/Indexers/
COPY Properties/ /src/Scittish.Api/Properties/

# Publish the API (project references to CoseSignTool libs resolve automatically)
RUN dotnet publish /src/Scittish.Api/Scittish.Api.csproj -c Release -o /app/publish

# Stage 3: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0

WORKDIR /app

# Install oras CLI for OCI registry indexing
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates openssl \
    && curl -sLO https://github.com/oras-project/oras/releases/download/v1.2.0/oras_1.2.0_linux_amd64.tar.gz \
    && tar -xzf oras_1.2.0_linux_amd64.tar.gz -C /usr/local/bin oras \
    && rm oras_1.2.0_linux_amd64.tar.gz \
    && apt-get remove -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy .NET application
COPY --from=dotnet-builder /app/publish .

# Copy Go binary from builder (commented out - not used currently)
# COPY --from=go-builder /build/attest-helper /app/attest-helper

# Create directories for certs, cache, and jobs
RUN mkdir -p /var/cache/scittish /var/lib/scittish/certs /var/cache/scittish/jobs

ENV SCITT_CACHE_DIR=/var/cache/scittish
ENV SCITT_CERTS_DIR=/var/lib/scittish/certs
ENV SCITT_JOBS_DIR=/var/cache/scittish/jobs
ENV SCITT_URL=https://localhost:8000
ENV SCITT_DEVELOPMENT=true
ENV MAA_ENDPOINT=sharedeus.eus.attest.azure.net
ENV ALLOW_FAKE_ATTESTATION=false
ENV OCI_REGISTRY=
ENV OCI_NAMESPACE=scittish/subjects
ENV ORAS_PATH=/usr/local/bin/oras
ENV ASPNETCORE_URLS=http://0.0.0.0:8080

EXPOSE 8080

ENTRYPOINT ["dotnet", "Scittish.Api.dll"]
