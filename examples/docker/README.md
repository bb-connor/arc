# Docker Quickstart Example

This example combines the trust service with an optional hosted native MCP edge:

- `chio trust serve` with the receipt dashboard on `http://127.0.0.1:8940`
- `chio mcp serve-http` on `http://127.0.0.1:8931`
- the wrapped demo MCP tool server behind that hosted edge

## Quickstart

From this directory:

```bash
docker compose up -d --build chio-trust-demo
```

The hosted MCP edge is in the `enforced-native` profile. Configure the
[enforcing host inputs](../../docs/security/native-launch-examples.md) and supply
a qualified host-specific Compose override that mounts those exact paths and
supports native cage enforcement. The stock topology does not establish those
host properties. Then run:

```bash
docker compose -f compose.yaml -f /path/to/qualified-native-host.yaml \
  --profile enforced-native up -d --build
python3 smoke_client.py
```

The edge provisions an Enforced policy and confines discovery. Existing authority
and session keys are retained on process restart. Disabled and Shadow policies
cannot launch tools. The example signers stay in the private container storage;
operator-managed persistent storage is required for custody across replacement.

The stack runs with four distinct demo credentials: `demo-token` for clients
of the hosted edge, `demo-admin-token` for the edge's admin routes,
`demo-control-token` for the trust service, and `demo-workload-token` for the
edge's calls to the trust service's authority. Override them with
`CHIO_AUTH_TOKEN`, `CHIO_ADMIN_TOKEN`, `CHIO_SERVICE_TOKEN`, and
`CHIO_WORKLOAD_TOKEN`; the edge refuses to start when any two share a value.
The `chio-trust-demo` entrypoint writes a trust-control access configuration
holding only the SHA-256 digests of `CHIO_SERVICE_TOKEN` (a credential with
every caller scope) and the workload token, passed to the container as
`CHIO_AUTHORITY_WORKLOAD_TOKEN` (a credential with `authority:read` and
`capabilities:issue`), and starts `chio trust serve --access-config` with it.
See [Trust-Control Access Configuration](../../docs/reference/TRUST_CONTROL_ACCESS.md).

These defaults are public strings, so every port is published on 127.0.0.1
only. Set your own tokens before changing that binding. The `chio-trust-demo`
image accepts the demo tokens only with `CHIO_DEMO=1`, which this compose file
sets; without it the container refuses to start unless both trust tokens are
set to other values. Outside the demo the listener needs `CHIO_TLS_CERT` and
`CHIO_TLS_KEY` (owned by the image's `chio` user, UID 10001, with an owner-only
key), or `CHIO_ALLOW_PLAINTEXT=1` when a proxy protects it.

Then open:

```text
http://127.0.0.1:8940/
```

Enter `demo-control-token` (or your configured `CHIO_SERVICE_TOKEN`) in the **Bearer token** field and select **Log in**.

The smoke script performs one governed `echo_text` call through the hosted
edge, queries the resulting receipt from the trust service, and prints the
viewer URL plus the receipt id to look for in the dashboard.

When you are done:

```bash
docker compose down -v
```

## Services

- `chio-trust-demo`: trust service plus receipt dashboard viewer
- `chio-mcp-demo`: hosted Chio edge that wraps the demo MCP subprocess and points
  at the trust service through `--control-url`

## Files

- `compose.yaml`: local-build Docker topology for the trust service and hosted edge
- `mock_mcp_server.py`: tiny wrapped MCP demo server
- `policy.yaml`: permissive starter policy for the demo
- `smoke_client.py`: end-to-end governed call plus receipt lookup
