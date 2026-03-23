# Receipt Query API

The receipt query API provides multi-filter, cursor-paginated access to the kernel's signed tool receipt log. It is available both as an HTTP endpoint served by the trust-control server and as a CLI subcommand.

## HTTP Endpoint

```
GET /v1/receipts/query
```

All parameters are query string parameters. All filters are combined with AND semantics. The server requires a `Bearer` token in the `Authorization` header.

### Filter Parameters

All parameters are optional. Omitting a parameter disables that filter.

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilityId` | string | Exact match on capability ID |
| `toolServer` | string | Exact match on tool server name (`server_id`) |
| `toolName` | string | Exact match on tool name |
| `outcome` | string | Decision outcome: `"allow"`, `"deny"`, `"cancelled"`, or `"incomplete"` |
| `since` | u64 | Include only receipts with `timestamp >= since` (Unix seconds, inclusive) |
| `until` | u64 | Include only receipts with `timestamp <= until` (Unix seconds, inclusive) |
| `minCost` | u64 | Include only receipts with `cost_charged >= minCost` (minor units). Receipts without financial metadata are excluded when this filter is set. |
| `maxCost` | u64 | Include only receipts with `cost_charged <= maxCost` (minor units). Receipts without financial metadata are excluded when this filter is set. |
| `agentSubject` | string | Filter by agent subject public key (hex-encoded Ed25519). Resolved through the capability lineage table. |
| `cursor` | u64 | Pagination cursor: return only receipts with `seq > cursor` (exclusive). |
| `limit` | usize | Maximum results per page. Capped server-side at `MAX_QUERY_LIMIT` (200). Default: 50. |

The parameter names follow `camelCase` in the HTTP query string (matching the `ReceiptQueryHttpQuery` struct's `serde(rename_all = "camelCase")` attribute).

### Response Body

```json
{
  "totalCount": 1024,
  "nextCursor": 47,
  "receipts": [ ...PactReceipt objects... ]
}
```

`totalCount` reflects the count of all receipts matching the filters, independent of the page limit and cursor. It can be used to show "N total" in a UI without fetching all pages.

`nextCursor` is the `seq` value of the last receipt in this page. Pass it as `cursor` on the next request to get the following page. When `nextCursor` is `null` (or absent), this is the last page.

`receipts` is an array of `PactReceipt` objects ordered by `seq ASC`.

### Cursor-Based Pagination

The cursor is the `seq` column value from the last receipt in a page. Pagination is forward-only.

```
# Page 1
GET /v1/receipts/query?toolServer=shell&limit=50

# Response includes nextCursor: 147

# Page 2
GET /v1/receipts/query?toolServer=shell&limit=50&cursor=147
```

When `nextCursor` is absent in the response, all matching receipts have been fetched.

### Example Request and Response

```
GET /v1/receipts/query?outcome=deny&since=1700000000&limit=2
Authorization: Bearer my-service-token
```

```json
{
  "totalCount": 8,
  "nextCursor": 23,
  "receipts": [
    {
      "id": "receipt-001",
      "timestamp": 1700000100,
      "capability_id": "cap-abc",
      "tool_server": "filesystem",
      "tool_name": "write_file",
      "decision": { "deny": { "reason": "path outside allowed prefix", "guard": "path_allowlist" } },
      "content_hash": "...",
      "policy_hash": "...",
      "evidence": [],
      "signature": "..."
    },
    {
      "id": "receipt-002",
      "timestamp": 1700000250,
      "capability_id": "cap-abc",
      "tool_server": "shell",
      "tool_name": "exec",
      "decision": { "deny": { "reason": "budget exhausted", "guard": "monetary_budget" } },
      "metadata": {
        "financial": {
          "grant_index": 0,
          "cost_charged": 0,
          "currency": "USD",
          "budget_remaining": 0,
          "budget_total": 10000,
          "delegation_depth": 0,
          "root_budget_holder": "agent-root",
          "settlement_status": "denied",
          "attempted_cost": 500
        }
      },
      "content_hash": "...",
      "policy_hash": "...",
      "evidence": [],
      "signature": "..."
    }
  ]
}
```

### Agent-Scoped Convenience Endpoint

A shorter URL is also available for per-agent receipt lookup:

```
GET /v1/agents/{subject_key}/receipts?limit=50&cursor=0
```

This is equivalent to calling `/v1/receipts/query?agentSubject={subject_key}`. It accepts only `limit` and `cursor` query parameters.

## CLI Usage: pact receipt list

The `pact receipt list` subcommand wraps the HTTP endpoint.

```
pact receipt list [OPTIONS]

Options:
  --capability <ID>      Filter by capability ID
  --tool-server <NAME>   Filter by tool server name
  --tool-name <NAME>     Filter by tool name
  --outcome <OUTCOME>    Filter by outcome (allow/deny/cancelled/incomplete)
  --since <UNIX_SECS>    Filter by minimum timestamp (inclusive)
  --until <UNIX_SECS>    Filter by maximum timestamp (inclusive)
  --min-cost <UNITS>     Minimum cost in minor currency units
  --max-cost <UNITS>     Maximum cost in minor currency units
  --limit <N>            Page size (default: 50)
  --cursor <SEQ>         Pagination cursor (seq value)
  --control-url <URL>    Trust-control server URL
  --control-token <TOK>  Bearer token for the trust-control server
  --receipt-db <PATH>    Path to receipt SQLite file (local mode)
```

Each matching receipt is printed as a JSON object on its own line (NDJSON). Example:

```bash
pact receipt list \
  --outcome deny \
  --since 1700000000 \
  --control-url http://localhost:7391 \
  --control-token my-token
```

To paginate programmatically, capture `nextCursor` from the HTTP response and pass it as `--cursor` on the next invocation.
