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

The stack runs with three distinct demo credentials: `demo-token` for clients
of the hosted edge, `demo-admin-token` for the edge's admin routes, and
`demo-control-token` for the trust service. Override them with
`CHIO_AUTH_TOKEN`, `CHIO_ADMIN_TOKEN`, and `CHIO_SERVICE_TOKEN`; the edge
refuses to start when any two share a value.

Then open:

```text
http://127.0.0.1:8940/?token=demo-control-token
```

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
