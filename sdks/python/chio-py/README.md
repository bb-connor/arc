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

## Verify execution through an existing MCP session

The 0.2.0 source package adds an optional `mcp` extra and a framework-independent
verified client. Supply an initialized official MCP `ClientSession` connected to
Chio's MCP edge, and keep it open for the duration of your work:

```python
from chio.mcp import VerifiedMcpSession

verified = VerifiedMcpSession(
    session,
    server_id="journal",
    trusted_signers=[operator_pinned_kernel_public_key],
)
result = await verified.call_tool("append_note", {"note": "hello"})
if result.allowed:
    print(result.output)  # Exact output committed by the kernel receipt.
else:
    print(result.receipt["decision"])
```

`VerifiedMcpSession` requests a signed receipt and binds it to a fresh invocation
ID, tool, server, arguments, and output. The signer must be pinned through a trusted
channel. Missing or altered evidence raises `McpReceiptError`; uncertain transport
outcomes are not retried. Only complete value results are supported. A verified
allowance attests mediation and observed output, not independent proof of an
external side effect. Check `result.tool_error` for a signed upstream MCP failure.

The [LangChain kernel example](../../../examples/langchain-kernel/README.md) boots
the real Rust kernel and a real MCP tool server using these primitives. Existing
hosted session APIs above retain their current behavior; verification is explicit
through this wrapper. The source checkout does not require publishing to PyPI.

## API Reference

- `ChioClient` initializes authenticated Chio MCP HTTP sessions.
- `ChioSession` exposes typed helpers for tools, resources, prompts, logging,
  tasks, and explicit JSON-RPC envelopes.
- `ReceiptQueryClient` wraps `GET /v1/receipts/query` with typed parameters and
  pagination helpers.
- `chio.invariants` provides canonical JSON, hashing, signing, capability,
  receipt, and manifest verification helpers.

The full public reference lives in [docs/reference/SDK_PYTHON_REFERENCE.md](../../../docs/reference/SDK_PYTHON_REFERENCE.md).

## Official Example

The package-local governed example expects a running Chio hosted edge and trust
service:

```bash
CHIO_BASE_URL=http://127.0.0.1:8931 \
CHIO_CONTROL_URL=http://127.0.0.1:8940 \
CHIO_AUTH_TOKEN=demo-token \
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
