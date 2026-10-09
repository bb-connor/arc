# TypeScript SDK Reference

The `@chio-protocol/sdk` package provides TypeScript bindings for agent-side Chio operations: signing DPoP proofs, querying receipts, and working with Chio types.

## Installation

```bash
npm install @chio-protocol/sdk
# or
yarn add @chio-protocol/sdk
```

**Requirements:** Node.js >= 22. The package uses ES module format (`"type": "module"` in `package.json`). All entry points export TypeScript source directly; compile with `tsc` before shipping to a consumer that requires `.js` output.

## Package Exports

| Export | Entry Point |
|--------|-------------|
| `@chio-protocol/sdk` | Main surface: errors, DPoP, receipt query client, types, transport, auth |
| `@chio-protocol/sdk/invariants` | Low-level canonical JSON, hashing, signing invariants |
| `@chio-protocol/sdk/transport` | Session and message transport types |

## API Stability

The package follows semantic versioning. The current version is `1.0.0`. All exports from the main entry point are considered stable public API. Exports under `./invariants` and `./transport` are public but lower-level; breaking changes there will carry a semver major bump.

## Error Hierarchy

All SDK errors extend `ChioError`:

```typescript
class ChioError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: ErrorOptions)
}
```

Concrete error classes:

```typescript
class DpopSignError extends ChioError {
  // code: "dpop_sign_error"
  // Thrown when agentSeedHex is invalid or Ed25519 signing fails.
}

class QueryError extends ChioError {
  // code: "query_error"
  readonly status: number | undefined;
  constructor(message: string, status?: number, options?: ErrorOptions)
  // Thrown when the server returns a non-2xx HTTP status.
}

class TransportError extends ChioError {
  // code: "transport_error"
  // Thrown when the fetch itself fails (network error, DNS failure, etc.).
}
```

`ChioInvariantError` (exported from `./invariants`) is a separate lower-level error type and does NOT extend `ChioError`. Catch it separately if you use the invariants layer directly.

## signDpopProof

Signs a DPoP proof for a single tool invocation. The proof body is serialized as RFC 8785 canonical JSON before signing, ensuring compatibility with `chio-kernel`'s `verify_dpop_proof`.

```typescript
import { signDpopProof } from "@chio-protocol/sdk";

interface SignDpopProofParams {
  capabilityId: string;   // token ID of the capability being used
  toolServer: string;     // server_id of the target tool server
  toolName: string;       // name of the tool being invoked
  actionArgs: unknown;    // the tool arguments (will be canonicalized + SHA-256'd)
  agentSeedHex: string;   // hex-encoded 32-byte Ed25519 seed (private key seed)
  nonce?: string;         // default: 16 random bytes hex-encoded
  issuedAt?: number;      // default: Math.floor(Date.now() / 1000)
}

interface DpopProof {
  body: DpopProofBody;
  signature: string;      // hex-encoded Ed25519 signature over canonical JSON of body
}
```

Usage:

```typescript
const proof = signDpopProof({
  capabilityId: "cap-abc123",
  toolServer: "filesystem",
  toolName: "read_file",
  actionArgs: { path: "/app/config.json" },
  agentSeedHex: process.env.AGENT_SEED_HEX!,
});

// Attach proof to your invocation request
const request = {
  capability_id: "cap-abc123",
  tool_name: "read_file",
  arguments: { path: "/app/config.json" },
  dpop_proof: proof,
};
```

The `action_hash` in the proof body is the SHA-256 hex of the canonical JSON of `actionArgs`. It must match what the kernel derives from the same arguments.

Throws `DpopSignError` if `agentSeedHex` is invalid or signing fails.

## ReceiptQueryClient

Wraps `GET /v1/receipts/query` with TypeScript types and automatic `Bearer` token injection.

```typescript
import { ReceiptQueryClient } from "@chio-protocol/sdk";

const client = new ReceiptQueryClient(
  "http://localhost:7391",  // trust-control base URL
  "my-service-token",       // Bearer token
);
```

An optional third argument accepts a custom `fetch` implementation for testing or non-browser environments. An optional fourth argument sets the retry policy:

```typescript
interface ReceiptQueryClientOptions {
  maxAttempts?: number;   // total attempts including the first; default 5
  retryBudgetMs?: number; // retry budget per query call; default 30000
}
```

`maxAttempts` must be a positive integer and `retryBudgetMs` a finite,
nonnegative number; otherwise the constructor throws `RangeError`. Set
`maxAttempts: 1` or `retryBudgetMs: 0` to disable retries.

### query

```typescript
interface ReceiptQueryParams {
  capabilityId?: string;
  toolServer?: string;
  toolName?: string;
  outcome?: string;
  since?: number;
  until?: number;
  minCost?: bigint;
  maxCost?: bigint;
  costCurrency?: string;
  agentSubject?: string;
  cursor?: number;
  limit?: number;
}

interface ReceiptQueryResponse {
  totalCount: number;
  nextCursor?: number | null;
  receipts: ChioReceipt[];
  snapshot?: ReceiptQuerySnapshot;
}

interface ReceiptQuerySnapshot {
  id: string;
  throughEntrySeq: number;
  checkpointSeq: number | null;
  observedAt: number;
  recertifiedAt: number;
}

async query(
  params?: ReceiptQueryParams,
  options?: { signal?: AbortSignal },
): Promise<ReceiptQueryResponse>
```

Parameters map to the HTTP query string camelCase names documented in `docs/RECEIPT_QUERY_API.md`. All are optional.

Cost bounds use `bigint` so values through `18446744073709551615n` are encoded
without JavaScript number rounding. Either bound requires a three-letter
uppercase `costCurrency`.

`snapshot` names the authenticated snapshot version that answered. It is
absent when the server predates snapshots, and `checkpointSeq` is `null`
before the store's first checkpoint. `totalCount` is exact for that version
and can change between pages.

`query` retries only a `503` whose body carries one of the server codes
`receipt_query_snapshot_building`, `receipt_query_snapshot_stale` or
`receipt_query_busy`. It waits for the server's `Retry-After` (integer seconds
or an HTTP date; 1 second when absent or unreadable) and retries while
attempts remain and the wait ends within the retry budget. The budget applies
to one `query` call, that is, to one page, not to a whole pagination. It does
not retry `422`, `500`, `receipt_query_snapshot_unavailable`, or a `503`
without one of those codes. Each attempt is bounded by the remaining budget
and by 30 seconds (30 seconds when the budget is 0). Aborting `signal` cancels
both the in-flight request and any retry wait.

Throws `QueryError` on non-2xx responses, after any retries. `status` is the
HTTP status of the last response, and `serverCode` is the server's `code`
when the error body carries one; `code` stays `query_error`. Throws
`TransportError` on network-level failures, and when the budget expires before
a successful response with no earlier `QueryError` to report.

### paginate

An async generator that iterates through all pages automatically:

```typescript
async *paginate(
  params?: ReceiptQueryParams,
  options?: { signal?: AbortSignal },
): AsyncGenerator<ChioReceipt[]>
```

Each yielded value is one page of receipts. Every page goes through `query`, so each page gets its own retry budget. A page can hold fewer than `limit` receipts while more remain; the generator continues until `nextCursor` is `null` or absent, and does not yield empty pages. It throws `QueryError` if a `nextCursor` does not advance past the cursor it was requested with.

```typescript
for await (const page of client.paginate({ toolServer: "filesystem" })) {
  for (const receipt of page) {
    console.log(receipt.id, receipt.decision);
  }
}
```

### Example: Fetch All Denied Receipts in a Time Range

```typescript
const client = new ReceiptQueryClient("http://localhost:7391", token);

const all: ChioReceipt[] = [];
for await (const page of client.paginate({
  outcome: "deny",
  since: 1700000000,
  until: 1700086400,
})) {
  all.push(...page);
}
console.log(`Found ${all.length} denied receipts`);
```

### Error Handling

```typescript
import { QueryError, TransportError } from "@chio-protocol/sdk";

try {
  const result = await client.query({ capabilityId: "cap-xyz" });
} catch (err) {
  if (err instanceof QueryError) {
    console.error("HTTP error", err.status, err.message);
  } else if (err instanceof TransportError) {
    console.error("Network error", err.message);
  }
}
```
