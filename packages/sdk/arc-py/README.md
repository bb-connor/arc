# `arc-sdk`

Stable Python SDK for ARC hosted MCP sessions, receipt queries, and invariant
verification.

## Installation

```bash
pip install arc-sdk
```

The distribution name is `arc-sdk`. The import package remains `arc`.

## Quickstart

```py
from arc import ArcClient, ReceiptQueryClient

client = ArcClient.with_static_bearer("http://127.0.0.1:8931", "demo-token")
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

- `ArcClient` initializes authenticated ARC MCP HTTP sessions.
- `ArcSession` exposes typed helpers for tools, resources, prompts, logging,
  tasks, and explicit JSON-RPC envelopes.
- `ReceiptQueryClient` wraps `GET /v1/receipts/query` with typed parameters and
  pagination helpers.
- `arc.invariants` provides canonical JSON, hashing, signing, capability,
  receipt, and manifest verification helpers.

The full public reference lives in [docs/SDK_PYTHON_REFERENCE.md](../../../docs/SDK_PYTHON_REFERENCE.md).

## Official Example

The package-local governed example expects a running ARC hosted edge and trust
service:

```bash
ARC_BASE_URL=http://127.0.0.1:8931 \
ARC_CONTROL_URL=http://127.0.0.1:8940 \
ARC_AUTH_TOKEN=demo-token \
python packages/sdk/arc-py/examples/governed_hello.py
```

For a repo-local end-to-end verification run that boots those services
automatically, use:

```bash
./scripts/check-sdk-publication-examples.sh
```

## Release Checks

```bash
./scripts/check-arc-py.sh
./scripts/check-arc-py-release.sh
```

Release process details live in [RELEASING.md](./RELEASING.md).
