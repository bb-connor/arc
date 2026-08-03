# Docker Quickstart Example

This example is the deployable local onboarding path for Chio. It starts:

- a one-shot provisioner that creates a reviewed signed manifest, signed cage
  launch policy, exact migration ledger, and independent verifier keys, then
  exports only the material needed at runtime
- a one-shot TLS provisioner whose CA signing key is never mounted into a
  long-running service
- `chio trust serve` behind a private-CA TLS endpoint on
  `https://127.0.0.1:8940`
- `chio mcp serve-http` on `http://127.0.0.1:8931`
- the wrapped demo MCP tool server behind that hosted edge

## Quickstart

From this directory:

```bash
export CHIO_AUTH_TOKEN="$(openssl rand -hex 32)"
export CHIO_ADMIN_TOKEN="$(openssl rand -hex 32)"
export CHIO_SERVICE_TOKEN="$(openssl rand -hex 32)"
export CHIO_DASHBOARD_READ_TOKEN="$(openssl rand -hex 32)"
test "${CHIO_AUTH_TOKEN}" != "${CHIO_ADMIN_TOKEN}"
test "${CHIO_AUTH_TOKEN}" != "${CHIO_SERVICE_TOKEN}"
test "${CHIO_ADMIN_TOKEN}" != "${CHIO_SERVICE_TOKEN}"
test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_AUTH_TOKEN}"
test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_ADMIN_TOKEN}"
test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_SERVICE_TOKEN}"
docker compose up -d --build --wait --wait-timeout 180
CHIO_EDGE_TOKEN="${CHIO_AUTH_TOKEN}" \
CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN}" \
CHIO_DASHBOARD_READ_TOKEN="${CHIO_DASHBOARD_READ_TOKEN}" \
  python3 smoke_client.py
```

The stack has no built-in credentials. The edge-client, edge-admin,
trust-control, and dashboard-read variables must be explicit, nonempty, and
pairwise distinct. Keep them in the current shell until you run
`docker compose down -v`; do not commit them to an environment file.

The smoke script performs one governed `echo_text` call through the hosted
edge, exchanges the dashboard-read credential for a short-lived cookie, queries
the resulting receipt, signs out, and prints the receipt id. It copies the
public demo CA from the TLS container into a temporary directory and uses it as
an exclusive trust root. It never places a credential in a URL or sends the
dashboard-read credential as a bearer. The CA private key remains in a separate
Docker volume that no long-running container or host-side client mounts.

To inspect the TLS endpoint directly, copy the public CA and pass it explicitly:

```bash
docker compose cp \
  chio-trust-tls:/var/lib/chio-tls-public/demo-ca.pem \
  ./demo-ca.pem
curl --cacert ./demo-ca.pem \
  -H "Authorization: Bearer ${CHIO_SERVICE_TOKEN}" \
  https://127.0.0.1:8940/health
rm ./demo-ca.pem
```

Direct browser navigation requires importing `demo-ca.pem` into a dedicated
browser trust store first. Open the trust-service origin and exchange
`CHIO_DASHBOARD_READ_TOKEN` through the login form. Do not put any credential in
the browser URL or browser storage. The quickstart smoke client and `curl`
commands are the supported authenticated paths without browser trust-store
changes.

When you are done:

```bash
docker compose down -v
```

## Services

- `chio-security-init`: transactional signed launch-material provisioner
- `chio-trust-demo`: trust service plus receipt dashboard viewer
- `chio-tls-init`: one-shot private CA and server-certificate provisioner
- `chio-trust-tls`: bounded TLS reverse proxy that receives the server key but
  never the CA signing key
- `chio-mcp-demo`: hosted Chio edge that wraps the demo MCP subprocess and points
  at the final HTTPS trust endpoint through `--control-url`

The generated migration stage is `Disabled`. This is signed,
legacy-authorized demo mode, not cage containment. A production deployment must
advance the reviewed migration ledger to `Enforced` or `LegacyRemoved` and pass
the designated Linux cage gates before claiming native process isolation.
Within this demo, the fixed root-owned launcher verifies the Python and tool
digests, erases the inherited environment, closes unrelated descriptors, and
drops the wrapped tool to UID/GID 10002. The edge's root-owned private state is
not readable by that UID. Provisioning-only manifest, policy, and migration
signing seeds are destroyed with the one-shot initializer rather than copied
into any runtime volume.

## Files

- `compose.yaml`: local-build Docker topology for the trust service and hosted edge
- `mock_mcp_server.py`: tiny wrapped MCP demo server
- `policy.yaml`: permissive starter policy for the demo
- `tools.json`: reviewed upstream tool inventory committed into the manifest
- `mcp_demo_entrypoint.py`: exact signed input and target-command launcher
- `mcp_demo_launcher.c`: digest-verifying fixed privilege-drop launcher
- `tls_demo_entrypoint.sh`: one-shot TLS provisioner and read-only serve validator
- `tls_reverse_proxy.py`: bounded TLS termination for the internal trust service
- `smoke_client.py`: end-to-end governed call plus receipt lookup
