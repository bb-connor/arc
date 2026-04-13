# Python SDK Reference

The `arc-sdk` distribution provides Python bindings for ARC hosted MCP
sessions, receipt queries, auth discovery helpers, and invariant verification.

## Installation

```bash
pip install arc-sdk
```

Import the package as `arc`:

```python
from arc import ArcClient, ReceiptQueryClient
```

## Public API

### Error Types

- `ArcError`: base SDK exception
- `ArcTransportError`: network or transport-level failure
- `ArcQueryError`: non-success HTTP response from the receipt query endpoint
- `ArcRpcError`: JSON-RPC error returned by the hosted MCP edge
- `ArcInvariantError`: invariant parsing or verification failure

### ArcClient

```python
from arc import ArcClient

client = ArcClient.with_static_bearer("http://localhost:8931", "token")
session = client.initialize()
```

`ArcClient.initialize()` creates an authenticated ARC MCP HTTP session and
returns an `ArcSession`.

### ArcSession

`ArcSession` exposes convenience helpers over the Streamable HTTP MCP surface:

- `list_tools()`
- `call_tool(name, arguments=None)`
- `list_resources()`
- `read_resource(uri)`
- `list_prompts()`
- `get_prompt(name, arguments=None)`
- `list_tasks()`
- `get_task(task_id)`
- `get_task_result(task_id)`
- `cancel_task(task_id)`
- `close()`

It also exposes `request()`, `request_result()`, `notification()`, and
`send_envelope()` for lower-level control.

### ReceiptQueryClient

`ReceiptQueryClient` wraps `GET /v1/receipts/query` and injects the `Bearer`
token automatically.

```python
from arc import ReceiptQueryClient

client = ReceiptQueryClient("http://localhost:8940", "token")
response = client.query({"toolServer": "wrapped-http-mock", "limit": 5})
```

Supported query parameters:

- `capabilityId`
- `toolServer`
- `toolName`
- `outcome`
- `since`
- `until`
- `minCost`
- `maxCost`
- `agentSubject`
- `cursor`
- `limit`

Response shape:

```python
{
    "totalCount": 1,
    "nextCursor": 42,
    "receipts": [...],
}
```

Use `paginate()` to iterate automatically across pages:

```python
for page in client.paginate({"toolServer": "wrapped-http-mock"}):
    for receipt in page:
        print(receipt["id"])
```

## Invariants

The `arc.invariants` module exposes canonical JSON, SHA-256 hashing,
Ed25519 signing and verification, receipt verification, capability
verification, and signed-manifest verification helpers.

## Official Example

See [packages/sdk/arc-py/examples/governed_hello.py](../packages/sdk/arc-py/examples/governed_hello.py).
