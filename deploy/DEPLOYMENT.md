# Scittish C-ACI Deployment Notes

## Overview

This directory contains the artifacts needed to deploy the **scittish** stack as a
[Confidential Azure Container Instance (C-ACI)](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-tutorial-deploy-confidential-containers-cce-arm)
container group. The container group runs three containers sharing a `localhost` network
(similar to a Kubernetes pod):

| Container   | Image                                          | Port  | Purpose |
|-------------|------------------------------------------------|-------|---------|
| `scitt`     | `<your-acr>.azurecr.io/scitt-virtual-init`   | 8000  | SCITT CCF ledger (scitt-ccf-ledger with bootstrap governance) |
| `registry`  | `<your-acr>.azurecr.io/registry`              | 5000  | Local OCI registry for SCITT subjects and referrers |
| `scittish`  | `<your-acr>.azurecr.io/scittish-dotnet`       | 8080  | Scittish API (signing, submission, indexing) — **publicly exposed** |

Only port **8080** is exposed to the internet. The SCITT ledger and OCI registry are
internal to the container group.

## Prerequisites

### Azure Resources

- **Subscription**: `<subscription-id>`
- **Resource group**: `<resource-group>` (southcentralus)
- **ACR**: `<your-acr>.azurecr.io` (Standard SKU, southcentralus)

### Managed Identities

Two managed identities are involved:

1. **VM identity** (`ops01`, principal `<vm-principal-id>`)
   - Used to run `az` commands from this machine
   - Needs: `AcrPush` + `AcrPull` on the ACR (for building/pushing images)
   - Needs: `Azure Container Instances Contributor Role` on the resource group (for deploying)
   - Needs: `Managed Identity Operator` on the `scittish-aci-puller` identity (to assign it to the container group)

2. **Container group identity** (`scittish-aci-puller`, client ID `<identity-client-id>`)
   - Resource ID: `/subscriptions/<subscription-id>/resourcegroups/<resource-group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/scittish-aci-puller`
   - Assigned to the C-ACI container group at deploy time
   - Needs: `AcrPull` on the ACR (so the container group can pull images)

### Required Role Assignments

| Identity               | Role                                  | Scope           |
|------------------------|---------------------------------------|-----------------|
| `ops01` (VM)           | AcrPush                               | ACR             |
| `ops01` (VM)           | AcrPull                               | ACR             |
| `ops01` (VM)           | Azure Container Instances Contributor | Resource group  |
| `ops01` (VM)           | Managed Identity Operator             | `scittish-aci-puller` |
| `scittish-aci-puller`  | AcrPull                               | ACR             |

### CLI Extensions

```bash
az extension add --name confcom    # For CCE policy generation
```

## Container Images

### Building and Pushing

```bash
# scittish-dotnet (from ~/scittish, feature/dotnet branch)
# Build context is repo root because Dockerfile references Go source at root level
cd ~/scittish
docker buildx build -t scittish-dotnet:library -f dotnet/Dockerfile .
docker tag scittish-dotnet:library <your-acr>.azurecr.io/scittish-dotnet:library
docker push <your-acr>.azurecr.io/scittish-dotnet:library

# scitt-virtual-init (from ~/scittish-deployment/scitt-init)
cd ~/scittish-deployment/scitt-init
docker build -t scitt-virtual-init:latest .
docker tag scitt-virtual-init:latest <your-acr>.azurecr.io/scitt-virtual-init:latest
docker push <your-acr>.azurecr.io/scitt-virtual-init:latest

# registry (standard Docker Hub image)
docker pull registry:latest
docker tag registry:latest <your-acr>.azurecr.io/registry:latest
docker push <your-acr>.azurecr.io/registry:latest
```

### Image Details

- **scittish-dotnet:library** — .NET 9 API with CoseSignTool library integration
  (indirect signing via `IndirectSignatureFactory`) and a Go `attest-helper` binary
  for TEE attestation via MAA. Built from `~/scittish/dotnet/Dockerfile`.

- **scitt-virtual-init** — Wrapper around the upstream `scitt-virtual` image. Adds
  Python + pyscitt, auto-generates member keys, starts `cchost`, and runs governance
  (activate member, set SCITT config, open service). Built from `~/scittish-deployment/scitt-init/`.

- **registry** — Vanilla Docker registry v2. Used as the local OCI registry for
  SCITT subject manifests and transparency receipt referrers.

## ARM Template (`deploy.json`)

The ARM template deploys a single `Microsoft.ContainerInstance/containerGroups`
resource with:

- **SKU**: `Confidential` (required for C-ACI with CCE policy enforcement)
- **OS**: Linux
- **Restart policy**: `Never` (containers don't persist state; reboot reinitializes)
- **Public IP**: Yes, with DNS label `scittish-caci` → `scittish-caci.southcentralus.azurecontainer.io`
- **Exposed port**: 8080 (TCP)
- **Identity**: User-assigned (`scittish-aci-puller`) for ACR image pull
- **Image registry credentials**: Uses the managed identity (no passwords in template)

### Environment Variables (scittish container)

| Variable                 | Value                      | Purpose |
|--------------------------|----------------------------|---------|
| `SCITT_URL`              | `https://localhost:8000`   | Internal SCITT ledger URL |
| `SCITT_DEVELOPMENT`      | `true`                     | Skip TLS verification for self-signed SCITT cert |
| `OCI_REGISTRY`           | `localhost:5000`           | Internal OCI registry |
| `OCI_INSECURE`           | `true`                     | Use HTTP for OCI registry |
| `ALLOW_FAKE_ATTESTATION` | `true`                     | Allow attest-helper to run without real SNP device |

### Resource Allocation

| Container  | CPU | Memory |
|------------|-----|--------|
| scitt      | 1   | 2 GB   |
| registry   | 0.5 | 0.5 GB |
| scittish   | 1   | 1.5 GB |

## CCE Policy Generation

The Confidential Computing Enforcement (CCE) policy ensures that only the expected
container images (by layer hash) can run in the container group. **The policy must be
regenerated every time any container image changes.**

### Generate the policy

```bash
cd ~/scittish-deployment

# The images must be available locally in Docker (for layer hashing)
# If not already local, pull them:
docker pull <your-acr>.azurecr.io/scitt-virtual-init:latest
docker pull <your-acr>.azurecr.io/registry:latest
docker pull <your-acr>.azurecr.io/scittish-dotnet:library

# Reset the ccePolicy field (optional, acipolicygen overwrites it)
python3 -c "
import json
with open('deploy.json') as f: t = json.load(f)
t['resources'][0]['properties']['confidentialComputeProperties']['ccePolicy'] = ''
with open('deploy.json', 'w') as f: json.dump(t, f, indent=2)
"

# Generate and inject the policy into deploy.json
az confcom acipolicygen -a deploy.json --debug-mode
```

**Important notes:**
- `--debug-mode` generates a permissive policy (allows `exec`, stdio, etc.). Remove
  for production deployments, but note that this restricts interactive debugging.
- The tool hashes every layer of every image. It prefers local Docker images (fast)
  and falls back to remote pull (slow, can hang for large images).
- If generation hangs, ensure images are available locally via `docker images | grep <your-acr>`.
- The policy is injected as a base64-encoded Rego policy into the `ccePolicy` field
  of the ARM template. Different policy = different base64 string.
- The policy length changes when images change (e.g., 16896 → 16988 after adding
  the attest-helper binary to scittish-dotnet).

## Deployment

### Deploy

```bash
cd ~/scittish-deployment

# Delete existing container group (if any)
az container delete --name scittish-caci --resource-group <resource-group> --yes

# Deploy
az deployment group create \
  --resource-group <resource-group> \
  --template-file deploy.json \
  --name scittish-caci-deploy
```

Deployment takes ~3-5 minutes. The `scitt` container needs ~20 seconds after start
to bootstrap (generate keys, start cchost, run governance).

### Verify

```bash
# Check container states
az container show --name scittish-caci --resource-group <resource-group> \
  --query "containers[].{name:name,state:instanceView.currentState.state}" -o table

# Test scittish
curl http://scittish-caci.southcentralus.azurecontainer.io:8080/properties

# View container logs
az container logs --name scittish-caci --resource-group <resource-group> --container-name scittish
az container logs --name scittish-caci --resource-group <resource-group> --container-name scitt
```

### Use with scittish-cli

```bash
scittish-cli set server http://scittish-caci.southcentralus.azurecontainer.io:8080
scittish-cli status
scittish-cli push examples/payloads/sample-slsa.json
```

## Attestation (`/attest` endpoint)

The `/attest` endpoint invokes a Go binary (`attest-helper`) that:

1. Checks for `/dev/sev-guest` (AMD SEV-SNP device) — present on real C-ACI
2. Fetches a hardware attestation report via ioctl (or generates a fake if `ALLOW_FAKE_ATTESTATION=true`)
3. Reads THIM (Trusted Hardware Identity Management) certificates from the platform
   security context directory (`/security-context-*/host-amd-cert-base64`), which
   contains the VCEK cert + certificate chain needed by MAA
4. Reads UVM reference info (endorsements) from `/security-context-*/reference-info-base64`
5. Sends all of the above + runtime data (containing the signing certificate chain)
   to Microsoft Azure Attestation (MAA) at the configured `MAA_ENDPOINT`
6. Returns the MAA JWT token

**Current status**: Working on C-ACI. The token contains claims about the TEE
environment including compliance status (`azure-compliant-uvm`) and whether the
VM is debuggable.

## Persistence

There is **no persistent storage**. All three containers use ephemeral local
filesystems:
- SCITT ledger state is lost on container restart
- OCI registry contents are lost on container restart
- Scittish signing certificates are regenerated on each boot
- Scittish job cache is ephemeral

This is acceptable for development/demo. For production, consider Azure File Shares
or persistent volumes for the SCITT ledger and OCI registry.

## Troubleshooting

### Policy mismatch errors

If deployment fails with `denied by policy: deviceHash not found`, the CCE policy
doesn't match the current image layers. Regenerate the policy (see above).

### Image pull failures

If deployment fails with `InaccessibleImage`, verify:
- The `scittish-aci-puller` identity has `AcrPull` on the ACR
- The VM identity has `Managed Identity Operator` on `scittish-aci-puller`
- Images are pushed to the ACR with the expected tags

### SCITT not ready

The scittish container may start before the SCITT ledger finishes bootstrapping.
The signing worker retries SCITT submissions, so requests submitted during this
window will eventually succeed once the ledger is open.
