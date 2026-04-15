# Summary 287-01

Phase `287` shipped ARC's first container packaging baseline.

## Delivered

- Added a repo-root [Dockerfile](/Users/connor/Medica/backbay/standalone/arc/Dockerfile) with:
  - `arc`: minimal Alpine runtime for the `arc` CLI
  - `arc-mcp-demo`: Alpine runtime plus Python and the example MCP server
- Added [.dockerignore](/Users/connor/Medica/backbay/standalone/arc/.dockerignore) to keep Docker build context small.
- Added [examples/docker](/Users/connor/Medica/backbay/standalone/arc/examples/docker/README.md) with:
  - [compose.yaml](/Users/connor/Medica/backbay/standalone/arc/examples/docker/compose.yaml)
  - [mock_mcp_server.py](/Users/connor/Medica/backbay/standalone/arc/examples/docker/mock_mcp_server.py)
  - [policy.yaml](/Users/connor/Medica/backbay/standalone/arc/examples/docker/policy.yaml)
  - [smoke_client.py](/Users/connor/Medica/backbay/standalone/arc/examples/docker/smoke_client.py)

## Verification

- `docker build --target arc -t arc:phase287 .`
- `docker run --rm arc:phase287 --help`
- `docker compose -f examples/docker/compose.yaml up --build -d`
- `python3 examples/docker/smoke_client.py`

The smoke client completed a real initialize -> `tools/list` -> `tools/call`
flow through `arc mcp serve-http`, proving the Compose example wraps a working
policy-enforced MCP server.
