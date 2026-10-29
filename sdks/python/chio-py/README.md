# `chio-sdk`

Stable Python SDK for Chio hosted MCP sessions, receipt queries, and invariant
verification.

## Installation

```bash
pip install chio-sdk
```

The distribution name is `chio-sdk`. The import package is `chio`.

## Quickstart

```py
from chio import ChioClient, ReceiptQueryClient

client = ChioClient.with_static_bearer("http://127.0.0.1:8931", "demo-token")
session = client.initialize()

try:
    tools = session.list_tools()
    print(tools)

    receipts = ReceiptQueryClient("http://127.0.0.1:8940", "demo-token").query(
        {"toolServer": "wrapped-http-mock", "limit": 5}
    )
    print(receipts["totalCount"])
finally:
    session.close()
```

## API Reference

- `ChioClient` initializes authenticated Chio MCP HTTP sessions.
- `ChioSession` exposes typed helpers for tools, resources, prompts, logging,
  tasks, and explicit JSON-RPC envelopes.
- `ReceiptQueryClient` wraps `GET /v1/receipts/query` with typed parameters and
  pagination helpers.
- `chio.invariants` provides canonical JSON, hashing, signing, capability,
  receipt, and manifest verification helpers.
- `chio.mcp` verifies the `_meta.chioEvidence` a Chio MCP edge attaches to
  every `tools/call` result (`pip install "chio-sdk[mcp]"` for the session
  wrapper). `verify_mcp_result` checks the receipt against an operator-pinned
  kernel key and returns only the output the receipt commits to.
  `VerifiedMcpSession` wraps an open `mcp.ClientSession`, sends a fresh
  `_meta.chioRequestId` per call and never retries.

```python
from chio.mcp import VerifiedMcpSession

verified = VerifiedMcpSession(
    session,  # an initialized mcp.ClientSession connected to a Chio edge
    trusted_signers=[KERNEL_PUBLIC_KEY_HEX],
    server_id="wrapped-http-mock",
)
result = await verified.call_tool("echo_text", {"message": "hello"})
print(result.allowed, result.output, result.receipt["id"])
```

Streamed results, pending approvals and incomplete calls raise
`McpEvidenceError`, as do missing or tampered evidence. The rendered `content`
and `structuredContent` are never read as signed data.

The full public reference lives in [docs/reference/SDK_PYTHON_REFERENCE.md](../../../docs/reference/SDK_PYTHON_REFERENCE.md).

## Official Example

The package-local governed example expects a running Chio hosted edge and trust
service:

```bash
CHIO_BASE_URL=http://127.0.0.1:8931 \
CHIO_CONTROL_URL=http://127.0.0.1:8940 \
CHIO_AUTH_TOKEN=demo-token \
CHIO_ADMIN_TOKEN=demo-admin-token \
CHIO_CONTROL_TOKEN=demo-control-token \
python sdks/python/chio-py/examples/governed_hello.py
```

For a repo-local end-to-end verification run that boots those services
automatically, use:

```bash
./scripts/check-sdk-publication-examples.sh
```

## Canonical Example Links

- `../../../docs/guides/WEB_BACKEND_QUICKSTART.md`
- `../../../examples/hello-openapi-sidecar/README.md`
- `../../../examples/hello-fastapi/README.md`

## Release Checks

```bash
./scripts/check-chio-py.sh
./scripts/check-chio-py-release.sh
```

Release process details live in [RELEASING.md](./RELEASING.md).
