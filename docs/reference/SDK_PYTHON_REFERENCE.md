# Python SDK Reference

The `chio-sdk` distribution provides Python bindings for Chio hosted MCP
sessions, receipt queries, auth discovery helpers, and invariant verification.

## Installation

```bash
pip install chio-sdk
```

Import the package as `chio`:

```python
from chio import ChioClient, ReceiptQueryClient
```

## Public API

### Error Types

- `ChioError`: base SDK exception
- `ChioTransportError`: network or transport-level failure
- `ChioQueryError`: non-success HTTP response from the receipt query endpoint
- `ChioRpcError`: JSON-RPC error returned by the hosted MCP edge
- `ChioInvariantError`: invariant parsing or verification failure

### ChioClient

```python
from chio import ChioClient

client = ChioClient.with_static_bearer("http://localhost:8931", "token")
session = client.initialize()
```

`ChioClient.initialize()` creates an authenticated Chio MCP HTTP session and
returns an `ChioSession`.

### ChioSession

`ChioSession` exposes convenience helpers over the Streamable HTTP MCP surface:

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
from chio import ReceiptQueryClient

client = ReceiptQueryClient("http://localhost:8940", "token")
response = client.query({"toolServer": "wrapped-http-mock", "limit": 5})
```

The constructor also accepts keyword-only `client` (an injected HTTP client),
`max_attempts` (total attempts including the first, default `5`, a positive
integer) and `retry_budget_seconds` (retry budget per `query` call, default
`30.0`, finite and nonnegative). Invalid values raise `ValueError`, or
`TypeError` for a non-numeric budget. Set `max_attempts=1` or
`retry_budget_seconds=0` to disable retries.

Supported query parameters:

- `capabilityId`
- `toolServer`
- `toolName`
- `outcome`
- `since`
- `until`
- `minCost`
- `maxCost`
- `costCurrency`
- `agentSubject`
- `cursor`
- `limit`

Python integers preserve the full unsigned 64-bit cost domain. Either cost
bound requires `costCurrency` as a three-letter uppercase string.

Response shape:

```python
{
    "snapshot": {
        "id": "01929a7c3f4e7d2a8b1c5e6f7a8b9c0d:42",
        "throughEntrySeq": 120345,
        "checkpointSeq": 1203,
        "observedAt": 1760000000123,
        "recertifiedAt": 1759996400456,
    },
    "totalCount": 1,
    "nextCursor": 42,
    "receipts": [...],
}
```

The response is typed as `ReceiptQueryResponse`, and `snapshot` as
`ReceiptQuerySnapshot`; both are exported from `chio`. `snapshot` names the
authenticated snapshot version that answered. It is absent when the server
predates snapshots, and `checkpointSeq` is `None` before the store's first
checkpoint. `totalCount` is exact for that version and can change between
pages.

`query()` retries only a `503` whose body carries one of the server codes
`receipt_query_snapshot_building`, `receipt_query_snapshot_stale` or
`receipt_query_busy`. It sleeps for the server's `Retry-After` (integer
seconds or an HTTP date; 1 second when absent or unreadable) and retries while
attempts remain and the wait ends within the retry budget. The budget applies
to one `query()` call, that is, to one page, not to a whole pagination. It
does not retry `422`, `500`, `receipt_query_snapshot_unavailable`, or a `503`
without one of those codes.

The budget bounds retry admission and waits, not blocking I/O. Each request
uses a timeout of at most 5 seconds and at most the remaining budget, but the
default `urllib` transport applies it as a socket inactivity timeout, and an
injected `client` keeps its own timeout and buffering behavior. A successful
response that arrives after the budget expired raises `ChioTransportError`.

On a non-success response `query()` raises `ChioQueryError` after any retries.
`status` is the HTTP status of the last response, and `server_code` is the
server's `code` when the error body carries one, otherwise `None`.

Use `paginate()` to iterate automatically across pages:

```python
for page in client.paginate({"toolServer": "wrapped-http-mock"}):
    for receipt in page:
        print(receipt["id"])
```

Each page goes through `query()`, so each page gets its own retry budget. A
page can hold fewer than `limit` receipts while more remain; `paginate()`
continues until `nextCursor` is `None` and does not yield empty pages. It
raises `ChioQueryError` when a cursor repeats or a `nextCursor` does not
advance.

## Invariants

The `chio.invariants` module exposes canonical JSON, SHA-256 hashing,
Ed25519 signing and verification, receipt verification, capability
verification, and signed-manifest verification helpers.

## Official Example

See [sdks/python/chio-py/examples/governed_hello.py](../../sdks/python/chio-py/examples/governed_hello.py).
