# ARC sidecar deployment references

Reference deployment manifests for running the ARC (Chio) kernel as a sidecar
alongside an application container on managed multi-container platforms.

All manifests assume the sidecar listens on `:9090` and exposes `GET /arc/health`.
The application talks to the kernel over `http://localhost:9090`.

See `docs/protocols/CLOUD-SIDECAR-INTEGRATION.md` for the architectural
rationale, env var catalogue, and receipt-sink options.

## Files

| Path | Purpose |
|------|---------|
| `cloud-run/service.yaml` | Google Cloud Run Knative-style multi-container service |
| `ecs/task-definition.json` | AWS ECS Fargate task definition (two containers, `dependsOn: HEALTHY`) |
| `azure/container-app.bicep` | Azure Container Apps Bicep template with startup/liveness probes |
| `sidecar/Dockerfile` | Multi-stage build producing a distroless nonroot ARC sidecar image |

## Placeholders

These manifests are reference infrastructure -- they are not deploy-ready.
Search and replace the following before applying:

| Placeholder | Meaning |
|-------------|---------|
| `APP_IMAGE_PLACEHOLDER` | Your application container image |
| `ghcr.io/backbay/arc-sidecar:latest` | ARC sidecar image you have built and pushed |
| `PROJECT_ID`, `REGION` | GCP project and region (Cloud Run) |
| `ACCOUNT_ID` | AWS account ID (ECS) |
| `EFS_FILESYSTEM_ID` | ECS EFS volume containing `/arc-config/kernel.yaml` and `/arc-config/spec/openapi.yaml` |
| Key Vault / Secret Manager ARNs | Pre-created secret references |

## Required secrets

Each manifest wires the following as secret references (never inline):

- `ARC_SIGNING_KEY` -- Ed25519 signing key for receipts
- `ARC_CAPABILITY_AUTHORITY_URL` -- URL of the capability authority

Additional non-secret configuration:

- `ARC_KERNEL_CONFIG_PATH` (default `/etc/arc/kernel.yaml`) -- kernel config file inside the image
- `ARC_POLICY_SOURCE` -- policy bundle location (bundled, `gs://`, `s3://`, `https://`)
- `ARC_RECEIPT_SINK` -- receipt destination (BigQuery, DynamoDB, Cosmos DB, stdout, ...)
- `ARC_LISTEN_ADDR` (default `0.0.0.0:9090`)
- `ARC_HEALTH_PATH` (default `/arc/health`)

## Startup ordering

All three platforms enforce that the app container cannot serve traffic until
the sidecar is healthy:

- **Cloud Run** -- `run.googleapis.com/container-dependencies` annotation plus
  sidecar `startupProbe` on `:9090/arc/health`.
- **ECS Fargate** -- the app waits for the sidecar process to start, and the
  sidecar uses the mounted `/etc/arc/spec/openapi.yaml` plus its own
  `healthCheck` on `:9090/arc/health`. This avoids a startup deadlock where
  spec auto-discovery would need the app healthy before the sidecar could
  report healthy.
- **Azure Container Apps** -- sidecar `startupProbe` plus `readinessProbe` on
  `:9090/arc/health`; the app's own `startupProbe` ensures it does not report
  healthy until it can reach the sidecar.

## Fail-closed behaviour

If the sidecar cannot load `ARC_KERNEL_CONFIG_PATH` or the policy bundle, it
exits non-zero. The platform then marks the container unhealthy (ECS, Azure)
or fails the revision (Cloud Run), which prevents the app container from
starting. The restart policies are configured to `always` so transient
failures recover automatically while permanent misconfigurations stay down.

## Quickstart

### Cloud Run

```bash
gcloud run services replace deploy/cloud-run/service.yaml --region us-central1
```

### ECS

```bash
aws ecs register-task-definition \
  --cli-input-json file://deploy/ecs/task-definition.json
```

### Azure Container Apps

```bash
az deployment group create \
  --resource-group my-rg \
  --template-file deploy/azure/container-app.bicep \
  --parameters \
      managedEnvironmentId=/subscriptions/.../managedEnvironments/my-env \
      userAssignedIdentityId=/subscriptions/.../userAssignedIdentities/arc-mi \
      arcSigningKeySecretUri=https://my-kv.vault.azure.net/secrets/arc-signing-key \
      arcCapabilityAuthoritySecretUri=https://my-kv.vault.azure.net/secrets/arc-cap-authority-url
```

### Sidecar image

```bash
docker build -f deploy/sidecar/Dockerfile -t ghcr.io/backbay/arc-sidecar:latest .
docker push ghcr.io/backbay/arc-sidecar:latest
```
