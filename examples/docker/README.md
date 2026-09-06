# Docker Quickstart Example

This example is the deployable local onboarding path for Chio. It starts:

- `chio trust serve` with the receipt dashboard on `http://127.0.0.1:8940`
- `chio mcp serve-http` on `http://127.0.0.1:8931`
- the wrapped demo MCP tool server behind that hosted edge

## Quickstart

From this directory:

```bash
docker compose up -d --build
python3 smoke_client.py
```

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
