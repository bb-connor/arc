# Shared Fixtures

This directory holds shared conformance assets such as:

- policy files
- manifests
- mock transcripts
- reusable upstream server fixtures

The first executable slice is `wave1/`:

- `mock_mcp_server.py`
  Minimal stdio MCP server used by the live remote HTTP harness.
- `policy.yaml`
  ARC policy that grants the wrapped Wave 1 fixture tool, resource, and prompt access.
