# Phase 10: Receipt Query API and TypeScript SDK 1.0 - Research

**Researched:** 2026-03-22
**Domain:** Rust SQLite query extension, axum HTTP API, clap CLI, TypeScript SDK hardening, DPoP proof generation, npm publishing
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Receipt Query API Design**
- Cursor-based pagination using receipt seq (receipt_store already uses seq for delta queries); response includes next_cursor
- Budget impact filtering via min_cost and max_cost as separate optional params (range queries)
- Flat list response with total_count and next_cursor -- grouping deferred to Phase 12 dashboard
- Query module lives in receipt_query.rs in arc-kernel, co-located with receipt_store for direct SQLite access
- Filter parameters: capability_id, tool_server, tool_name, time_range (since/until), outcome, min_cost, max_cost

**CLI Receipt List UX**
- Default output format: JSON lines (one receipt per line) -- pipeable, machine-readable
- Auto-paginate with --limit (default 50) and --cursor for manual cursor-walking
- Filter flags map 1:1 to query API: --capability, --tool, --since, --until, --outcome, --min-cost, --max-cost
- HTTP API endpoint: GET /receipts on existing trust-control axum server

**TypeScript SDK 1.0 Scope**
- Typed error classes extending ArcError base: DpopSignError, QueryError, TransportError with error codes
- Explicit signDpopProof(params) function returning signed proof object -- not auto-middleware
- ReceiptQueryClient class included in SDK for querying receipts via HTTP API
- npm package name: @arc-protocol/sdk
- SDK version bumped from 0.1.0 to 1.0.0 with semantic versioning

### Claude's Discretion
- Internal receipt_query.rs struct layout and SQL query construction
- CLI help text and flag descriptions
- TypeScript SDK internal module organization
- ReceiptQueryClient pagination helper implementation details
- Error code numbering and message formatting

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PROD-01 | Receipt query API supports filtering by capability, tool, time range, outcome, and budget impact | receipt_query.rs extends SqliteReceiptStore.list_tool_receipts with seq cursor + timestamp range + cost range; existing indexed columns cover all filters |
| PROD-06 | TypeScript SDK published to npm at 1.0 with stable API contract and semantic versioning | SDK rename from @arc/sdk to @arc-protocol/sdk, version bump to 1.0.0, typed ArcError hierarchy, DPoP helpers, ReceiptQueryClient, npm publish pipeline |
</phase_requirements>

---

## Summary

Phase 10 is a product surface and developer experience phase with no new enforcement logic. It extends the existing receipt storage infrastructure with richer filtering, adds a new GET /receipts HTTP endpoint to the trust-control axum server, introduces a `arc receipt list` CLI subcommand, and hardens the TypeScript SDK to 1.0 stability with typed errors, DPoP proof generation helpers, and a ReceiptQueryClient.

The Rust side is well-scoped because `SqliteReceiptStore` already has the indexed columns (`capability_id`, `tool_server`, `tool_name`, `decision_kind`, `timestamp`) and an existing `list_tool_receipts` query pattern using parameterized IS NULL OR clauses. The new `receipt_query.rs` adds two missing filter dimensions: time range (via the existing `timestamp` column) and budget impact (via JSON extraction from `raw_json` against `metadata.financial.cost_charged`). Cursor pagination reuses the `seq` AUTOINCREMENT primary key -- the same approach used by `list_tool_receipts_after_seq` and the SIEM delta queries. The existing `ReceiptDeltaQuery.after_seq` pattern is a direct model.

The TypeScript SDK rename and hardening is the most procedural part of the phase. The package is currently named `@arc/sdk` at `0.1.0` and is marked `private: true`, so it has never been published. Renaming to `@arc-protocol/sdk`, removing `private: true`, writing a proper build pipeline (tsc, declarations), and adding a typed error hierarchy are all prerequisite steps before the DPoP and ReceiptQueryClient additions.

**Primary recommendation:** Build receipt_query.rs as a thin layer that composes parameterized WHERE clauses in SQL -- do not deserialize receipts to filter in Rust memory. The JSON extraction for cost filtering should use SQLite's `json_extract(raw_json, '$.metadata.financial.cost_charged')` -- no new indexed column needed for the initial implementation.

---

## Standard Stack

### Core (Rust)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| rusqlite | workspace | SQLite access with parameterized queries | Already in workspace; `json_extract` via SQLite 3.38+ built-in JSON functions |
| axum | 0.8 | HTTP endpoint for GET /receipts | Already used for all trust-control endpoints |
| clap | 4 (derive) | New `arc receipt list` subcommand | Already used for all CLI subcommands |
| serde / serde_json | workspace | Query struct serialization and URL-encoding | Already used everywhere |
| serde_urlencoded | 0.7 | Query param encoding for TrustControlClient | Already present in arc-cli Cargo.toml |

### Core (TypeScript SDK)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| node:crypto | built-in | Ed25519 signing/verification | Already used in crypto.ts for all ARC signing |
| TypeScript | 5.x | Typed declarations, build output | Already in use; needs tsc output for npm |
| @noble/ed25519 | optional | Browser-compatible fallback | Only if browser support is required -- Node crypto sufficient for 1.0 |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| npm / bun publish | - | Package publication pipeline | For the 1.0 release of @arc-protocol/sdk |

**Installation (new packages -- none required):**
All dependencies are already present in the workspace. No new Cargo.toml entries are needed.

---

## Architecture Patterns

### receipt_query.rs Layout

The new module lives at `crates/arc-kernel/src/receipt_query.rs` and is declared in `crates/arc-kernel/src/lib.rs`. It takes a read-only `&SqliteReceiptStore` reference (the SQLite connection is on the store, not behind a trait lock).

```
crates/arc-kernel/src/
├── receipt_store.rs      -- existing SqliteReceiptStore; unchanged except pub re-exports
├── receipt_query.rs      -- NEW: ReceiptQuery struct, query_receipts(), ReceiptQueryResult
└── lib.rs                -- pub mod receipt_query; pub use receipt_query::*
```

**Key struct:**
```rust
// Source: derived from existing ToolReceiptQuery in trust_control.rs
#[derive(Debug, Default, Clone)]
pub struct ReceiptQuery {
    pub capability_id: Option<String>,
    pub tool_server: Option<String>,
    pub tool_name: Option<String>,
    pub outcome: Option<String>,       // maps to decision_kind column
    pub since: Option<u64>,            // Unix seconds
    pub until: Option<u64>,            // Unix seconds
    pub min_cost: Option<u64>,         // minor units; NULL if no financial metadata
    pub max_cost: Option<u64>,
    pub cursor: Option<u64>,           // seq to start after (exclusive)
    pub limit: usize,                  // page size; capped at MAX_QUERY_LIMIT
}

#[derive(Debug)]
pub struct ReceiptQueryResult {
    pub receipts: Vec<StoredToolReceipt>,  // seq + ArcReceipt pairs
    pub total_count: u64,                  // COUNT(*) with same filters, no limit
    pub next_cursor: Option<u64>,          // last seq in results if more exist
}
```

### SQL Pattern for receipt_query.rs

The SQL uses the IS NULL OR parameterized pattern established in `list_tool_receipts`, extended with timestamp range and JSON cost extraction:

```sql
-- Source: derived from existing patterns in receipt_store.rs
SELECT seq, raw_json
FROM arc_tool_receipts
WHERE (?1 IS NULL OR capability_id = ?1)
  AND (?2 IS NULL OR tool_server = ?2)
  AND (?3 IS NULL OR tool_name = ?3)
  AND (?4 IS NULL OR decision_kind = ?4)
  AND (?5 IS NULL OR timestamp >= ?5)
  AND (?6 IS NULL OR timestamp <= ?6)
  AND (?7 IS NULL OR CAST(json_extract(raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
  AND (?8 IS NULL OR CAST(json_extract(raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
  AND (?9 IS NULL OR seq > ?9)
ORDER BY seq ASC
LIMIT ?10
```

The count query uses the same WHERE clause without ORDER BY / LIMIT.

**Important:** `json_extract` returns NULL for receipts without financial metadata. The IS NULL OR pattern means `min_cost/max_cost` filters automatically exclude non-financial receipts when set. This is correct behavior: a cost range filter only matches receipts that have cost data.

### Cursor Semantics

- Cursor is the `seq` value of the last returned receipt (exclusive: `seq > cursor`)
- Page forward: take last `seq` from results, pass as `--cursor` on next call
- `next_cursor` in response is `Some(last_seq)` if `results.len() == limit`, `None` if last page
- Direction is always `ORDER BY seq ASC` (oldest-first within a filter set)
- This aligns with SIEM delta pull semantics (`list_tool_receipts_after_seq`) intentionally

### HTTP API Pattern

New constant and route added to `trust_control.rs`:

```rust
const RECEIPTS_PATH: &str = "/receipts";
// Added to router:
.route(RECEIPTS_PATH, get(handle_list_receipts))
```

New query struct (superset of existing `ToolReceiptQuery`):
```rust
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptListQuery {
    pub capability_id: Option<String>,
    pub tool_server: Option<String>,
    pub tool_name: Option<String>,
    pub outcome: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub min_cost: Option<u64>,
    pub max_cost: Option<u64>,
    pub cursor: Option<u64>,
    pub limit: Option<usize>,
}
```

Response shape:
```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryResponse {
    pub total_count: u64,
    pub next_cursor: Option<u64>,
    pub receipts: Vec<serde_json::Value>,  // serialized ArcReceipts
}
```

### CLI Subcommand Pattern

New `Receipt` command added to `Commands` enum, then a `ReceiptCommands` sub-enum with `List`:

```rust
// Added to Commands enum in main.rs
Receipt {
    #[command(subcommand)]
    command: ReceiptCommands,
},

// New enum
enum ReceiptCommands {
    List {
        #[arg(long)]
        capability: Option<String>,
        #[arg(long)]
        tool: Option<String>,       // "server/name" or just name
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        until: Option<u64>,
        #[arg(long)]
        outcome: Option<String>,
        #[arg(long)]
        min_cost: Option<u64>,
        #[arg(long)]
        max_cost: Option<u64>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        cursor: Option<u64>,
    },
}
```

CLI output: one JSON object per line (NDJSON / JSON Lines). Auto-paginate means `--limit` controls page size; the CLI can optionally loop internally when a `next_cursor` is returned.

**Implementation path for CLI:** The CLI routes through `TrustControlClient` (when `--control-url` is set) or opens `SqliteReceiptStore` directly. This matches how `trust revoke` / `trust status` work. Given the CONTEXT.md says the endpoint is GET /receipts, the simplest path is to call through `TrustControlClient.get_json_with_query(RECEIPTS_PATH, &query)` -- same pattern as `list_tool_receipts`.

### TypeScript SDK 1.0 Architecture

The SDK currently lives at `packages/sdk/arc-ts/` with package name `@arc/sdk` at `0.1.0` marked `private: true`. Phase 10 requires:

1. Rename to `@arc-protocol/sdk` in package.json
2. Remove `private: true`
3. Add TypeScript compilation + declaration output for npm publication
4. Add typed error hierarchy
5. Add `signDpopProof()` function
6. Add `ReceiptQueryClient` class
7. Version to `1.0.0`

**Error hierarchy:**
```typescript
// New file: src/errors.ts
export class ArcError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ArcError";
    this.code = code;
  }
}

export class DpopSignError extends ArcError {
  constructor(message: string, options?: ErrorOptions) {
    super("dpop_sign_error", message, options);
    this.name = "DpopSignError";
  }
}

export class QueryError extends ArcError {
  readonly status?: number;
  constructor(message: string, status?: number, options?: ErrorOptions) {
    super("query_error", message, options);
    this.name = "QueryError";
    this.status = status;
  }
}

export class TransportError extends ArcError {
  constructor(message: string, options?: ErrorOptions) {
    super("transport_error", message, options);
    this.name = "TransportError";
  }
}
```

**DPoP proof generation -- exact schema match with arc-kernel:**

The `DpopProofBody` struct in `crates/arc-kernel/src/dpop.rs` requires these exact fields in canonical JSON order (RFC 8785 -- alphabetical key order):
- `action_hash`: SHA-256 hex of serialized tool arguments
- `agent_key`: hex-encoded Ed25519 public key
- `capability_id`: string
- `issued_at`: u64 Unix seconds
- `nonce`: string
- `schema`: `"arc.dpop_proof.v1"`
- `tool_name`: string
- `tool_server`: string

The TypeScript `signDpopProof` function must:
1. Build a `DpopProofBody` JS object with these fields
2. Serialize to canonical JSON (using the existing `canonicalizeJson` from `invariants/json.ts`)
3. Sign with Ed25519 using the agent's seed (using existing `signEd25519Message` from `invariants/crypto.ts`)
4. Return `{ body: DpopProofBody, signature: string }` where `signature` is hex-encoded

```typescript
// New file: src/dpop.ts
import { canonicalizeJson } from "./invariants/json.ts";
import { signEd25519Message, sha256Hex } from "./invariants/crypto.ts";
import { DpopSignError } from "./errors.ts";

export const DPOP_SCHEMA = "arc.dpop_proof.v1";

export interface DpopProofBody {
  action_hash: string;
  agent_key: string;
  capability_id: string;
  issued_at: number;
  nonce: string;
  schema: string;
  tool_name: string;
  tool_server: string;
}

export interface DpopProof {
  body: DpopProofBody;
  signature: string;
}

export interface SignDpopProofParams {
  capabilityId: string;
  toolServer: string;
  toolName: string;
  actionArgs: unknown;  // will be sha256'd after canonical JSON
  agentSeedHex: string;
  nonce?: string;       // auto-generated if omitted
  issuedAt?: number;    // auto-set to Date.now()/1000 if omitted
}

export function signDpopProof(params: SignDpopProofParams): DpopProof {
  // ...
}
```

**ReceiptQueryClient:**
```typescript
// New file: src/receipt_query_client.ts
export interface ReceiptQueryParams {
  capabilityId?: string;
  toolServer?: string;
  toolName?: string;
  outcome?: string;
  since?: number;
  until?: number;
  minCost?: number;
  maxCost?: number;
  cursor?: number;
  limit?: number;
}

export interface ReceiptQueryResponse {
  totalCount: number;
  nextCursor?: number;
  receipts: ArcReceipt[];
}

export class ReceiptQueryClient {
  constructor(baseUrl: string, authToken: string, fetchImpl?: typeof fetch);
  async query(params?: ReceiptQueryParams): Promise<ReceiptQueryResponse>;
  async *paginate(params?: ReceiptQueryParams): AsyncGenerator<ArcReceipt[]>;
}
```

### Anti-Patterns to Avoid

- **Deserializing receipts into Rust structs to filter in memory:** `json_extract` in SQLite is faster and keeps the query at the database layer. Only deserialize what you return.
- **Adding a new SQLite index for cost filtering:** The `json_extract` path is acceptable for the initial implementation; Phase 12 dashboard can add a virtual column + index if query performance becomes an issue.
- **Auto-injecting DPoP proof in middleware:** CONTEXT.md is explicit that `signDpopProof` is an explicit function, not middleware. Middleware would hide what's being signed.
- **Using fetch-based HTTP in the TypeScript SDK for cursor pagination by looping internally:** The SDK should expose a `paginate()` async generator so callers control iteration -- do not auto-exhaust pages in `query()`.
- **Publishing the SDK as CommonJS only:** The package is already `"type": "module"`. Maintain ESM-first and provide CommonJS via a separate build output if needed (optional for 1.0).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Canonical JSON | Custom serializer | `canonicalizeJson` in `src/invariants/json.ts` | Already RFC 8785 compliant, tested |
| Ed25519 signing | Custom Web Crypto wrapper | `signEd25519Message` in `src/invariants/crypto.ts` | Already correct PKCS8 encoding path |
| SHA-256 hashing | Manual hash | `sha256Hex` from `src/invariants/crypto.ts` | Already correct node:crypto path |
| SQL null-OR pattern | Custom query builder | Parameterized `?N IS NULL OR col = ?N` | Established pattern in receipt_store.rs |
| Cursor pagination | Offset-based | seq-based `seq > cursor` | Offset is O(n); seq is indexed, stable |
| URL query encoding | Manual string concat | `serde_urlencoded::to_string` | Already used in TrustControlClient |

**Key insight:** Both the Rust signing primitives and the TypeScript signing primitives are already validated against cross-language test vectors (`test/vectors.test.ts`). The DPoP implementation must extend these primitives, not bypass them.

---

## Common Pitfalls

### Pitfall 1: json_extract Returns NULL for Non-Financial Receipts
**What goes wrong:** A `min_cost` filter of `0` silently excludes all non-financial receipts because `json_extract(raw_json, '$.metadata.financial.cost_charged')` returns NULL, and `NULL >= 0` evaluates to NULL (falsy) in SQLite.
**Why it happens:** SQLite's NULL semantics: any comparison with NULL returns NULL, not TRUE.
**How to avoid:** Document that `min_cost`/`max_cost` filters only match receipts with financial metadata. This is correct behavior. A `min_cost = 0` query is "receipts that had a cost of at least 0" which necessarily implies financial metadata exists.
**Warning signs:** Test queries with min_cost=0 to verify they only return financial receipts.

### Pitfall 2: total_count Is Expensive Without Index
**What goes wrong:** COUNT(*) with timestamp range and json_extract filters scans the full table.
**Why it happens:** `json_extract` cannot use standard column indexes.
**How to avoid:** Compute `total_count` in the same query call for now. Document that it is a full-table scan for cost-filtered queries. This is acceptable for Phase 10; Phase 12 can optimize.

### Pitfall 3: DPoP canonical JSON Field Order
**What goes wrong:** The Rust `DpopProofBody` uses RFC 8785 canonical JSON (alphabetical key order when serializing). The TypeScript implementation must produce the SAME byte sequence for the signature to verify.
**Why it happens:** JSON key ordering is not guaranteed by default serializers.
**How to avoid:** Always use `canonicalizeJson(body)` (the existing invariant) to produce the bytes that are signed. Never use `JSON.stringify(body)` directly. The `canonicalizeJson` function already sorts keys alphabetically.
**Warning signs:** Add a cross-language vector test: sign in TypeScript, verify in Rust (or vice versa). The existing `test/vectors.test.ts` is the right place.

### Pitfall 4: next_cursor Off-by-One
**What goes wrong:** Using `seq >= cursor` (inclusive) instead of `seq > cursor` (exclusive) returns the last item of the previous page as the first item of the next page.
**Why it happens:** Confusion between "cursor is the seq of last item" and "cursor is the seq to start after."
**How to avoid:** Cursor semantics = `WHERE seq > ?cursor`. The `next_cursor` in the response IS the `seq` of the last item returned, not `seq + 1`.

### Pitfall 5: SDK Package Name Collision
**What goes wrong:** `@arc/sdk` conflicts with existing npm packages in the `@arc` scope.
**Why it happens:** The `@arc` scope is not controlled by the ARC project.
**How to avoid:** The locked decision is `@arc-protocol/sdk`. Verify the `@arc-protocol` npm organization is registered before publishing.

### Pitfall 6: clap Subcommand Collision with Existing Trust Commands
**What goes wrong:** Adding `Commands::Receipt` alongside `Commands::Trust` and `Commands::Mcp` could conflict with the global `--receipt-db` flag name.
**Why it happens:** clap argument parsing across subcommand levels.
**How to avoid:** Use `arc receipt list` as the subcommand, with filter flags (not `--receipt-db`) that are local to the `list` subcommand. The `--receipt-db` global flag already controls which DB to open.

### Pitfall 7: SDK has no Build Step for npm
**What goes wrong:** The current `package.json` exports `./src/index.ts` directly (TypeScript source). This is fine for bun-based local use but does not work for npm consumers expecting compiled JavaScript.
**Why it happens:** `"exports": { ".": "./src/index.ts" }` -- acceptable in a monorepo with bun/strip-types, but not for npm publication.
**How to avoid:** Add a `build` script using `tsc` that outputs to `dist/` with `.d.ts` declarations. Update `exports` to point to `./dist/index.js`. This is required before npm publish.

---

## Code Examples

### receipt_query.rs: Core Query Function

```rust
// Source: extends patterns from crates/arc-kernel/src/receipt_store.rs
pub fn query_receipts(
    store: &SqliteReceiptStore,
    query: &ReceiptQuery,
) -> Result<ReceiptQueryResult, ReceiptStoreError> {
    let limit = query.limit.min(MAX_QUERY_LIMIT);

    let mut stmt = store.connection.prepare(
        r#"
        SELECT seq, raw_json
        FROM arc_tool_receipts
        WHERE (?1 IS NULL OR capability_id = ?1)
          AND (?2 IS NULL OR tool_server = ?2)
          AND (?3 IS NULL OR tool_name = ?3)
          AND (?4 IS NULL OR decision_kind = ?4)
          AND (?5 IS NULL OR timestamp >= ?5)
          AND (?6 IS NULL OR timestamp <= ?6)
          AND (?7 IS NULL OR CAST(json_extract(raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
          AND (?8 IS NULL OR CAST(json_extract(raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
          AND (?9 IS NULL OR seq > ?9)
        ORDER BY seq ASC
        LIMIT ?10
        "#,
    )?;
    // ... query_map with params
}
```

Note: The `connection` field on `SqliteReceiptStore` is currently private. `receipt_query.rs` must either be in the same module (`mod receipt_query` declared inside `receipt_store.rs`) OR `connection` must be made `pub(crate)`. The cleanest approach is to add `query_receipts` as a method on `SqliteReceiptStore` itself, keeping `connection` private.

### TypeScript signDpopProof

```typescript
// Source: matches DpopProofBody in crates/arc-kernel/src/dpop.rs
export function signDpopProof(params: SignDpopProofParams): DpopProof {
  const nonce = params.nonce ?? generateNonce();
  const issuedAt = params.issuedAt ?? Math.floor(Date.now() / 1000);

  // sha256 of canonical JSON of action args
  const actionCanonical = canonicalizeJson(params.actionArgs);
  const actionHash = sha256Hex(Buffer.from(actionCanonical, "utf8"));

  // derive public key from seed
  const signed = signEd25519Message("placeholder", params.agentSeedHex);
  const agentKey = signed.public_key_hex;

  // build body -- fields must match DpopProofBody exactly
  const body: DpopProofBody = {
    action_hash: actionHash,
    agent_key: agentKey,
    capability_id: params.capabilityId,
    issued_at: issuedAt,
    nonce,
    schema: DPOP_SCHEMA,
    tool_name: params.toolName,
    tool_server: params.toolServer,
  };

  // sign canonical JSON of body
  const bodyCanonical = canonicalizeJson(body);
  const { signature_hex } = signEd25519Message(
    Buffer.from(bodyCanonical, "utf8"),
    params.agentSeedHex,
  );

  return { body, signature: signature_hex };
}
```

### CLI: arc receipt list output pattern

```
// JSON Lines output (one receipt per line):
{"id":"rcpt-001","timestamp":1710000000,"capability_id":"cap-1",...}
{"id":"rcpt-002","timestamp":1710000001,"capability_id":"cap-1",...}
// stderr (not stdout) for pagination metadata:
// next_cursor: 42  (if more pages exist)
```

### ReceiptQueryClient.paginate()

```typescript
// Source: pattern from ArcSession in src/session/session.ts
async *paginate(params: ReceiptQueryParams = {}): AsyncGenerator<ArcReceipt[]> {
  let cursor: number | undefined = params.cursor;
  while (true) {
    const response = await this.query({ ...params, cursor });
    if (response.receipts.length > 0) {
      yield response.receipts;
    }
    if (response.nextCursor === undefined) {
      break;
    }
    cursor = response.nextCursor;
  }
}
```

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| Offset-based pagination | Cursor (seq) pagination | Stable, no drift under inserts |
| `@arc/sdk` private package | `@arc-protocol/sdk` public 1.0 | npm-publishable |
| Plain `Error` throws | Typed `ArcError` subclasses | Catchable by error code, not string matching |
| No DPoP client helpers | `signDpopProof()` explicit function | Agent can prove possession without building its own signing stack |

**No deprecated APIs affected:** All existing `SqliteReceiptStore` methods are unchanged. The new `query_receipts` (or `query_tool_receipts`) method is additive.

---

## Open Questions

1. **`connection` field access in receipt_query.rs**
   - What we know: `connection: Connection` is a private field on `SqliteReceiptStore`
   - What's unclear: Whether to (a) add `query_receipts` as a method on `SqliteReceiptStore`, (b) make `connection` `pub(crate)`, or (c) declare `receipt_query` as a submodule of `receipt_store`
   - Recommendation: Add `query_receipts` as a public method on `SqliteReceiptStore` directly, keeping the connection private. This is the simplest and cleanest.

2. **nonce generation in TypeScript signDpopProof**
   - What we know: Nonces must be unique within the TTL window (default 300s); `DpopNonceStore` uses `(nonce, capability_id)` as the key
   - What's unclear: Whether to use `crypto.randomUUID()`, `randomBytes(16).toString("hex")`, or another approach
   - Recommendation: Use `crypto.randomBytes(16).toString("hex")` from `node:crypto` (already imported in crypto.ts). This produces 32 hex chars of randomness, sufficient for replay prevention.

3. **npm org registration**
   - What we know: The locked package name is `@arc-protocol/sdk`
   - What's unclear: Whether the `@arc-protocol` npm org exists and is accessible
   - Recommendation: Verify org ownership before the publish task in plan 10-03. If org is unavailable, fall back to `arc-protocol-sdk` (unscoped) -- but this is a plan-level decision to note.

4. **total_count semantics under concurrent writes**
   - What we know: Count and list are two separate queries; a write between them will cause total_count to be stale
   - What's unclear: Whether this is acceptable for Phase 10
   - Recommendation: This is acceptable. Document in the HTTP API response that `total_count` is a snapshot estimate, not a transactional guarantee. Phase 12 can add ETags or versioning if needed.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust: `cargo test` (built-in); TypeScript: `node --experimental-strip-types --test` |
| Config file | Rust: none (workspace `Cargo.toml`); TS: none (package.json scripts) |
| Quick run command | `cargo test -p arc-kernel receipt_query` |
| Full suite command | `cargo test --workspace && node --experimental-strip-types --test packages/sdk/arc-ts/test/*.test.ts` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PROD-01 | query_receipts filters by capability_id | unit | `cargo test -p arc-kernel test_query_filter_capability` | Wave 0 |
| PROD-01 | query_receipts filters by time range (since/until) | unit | `cargo test -p arc-kernel test_query_filter_time_range` | Wave 0 |
| PROD-01 | query_receipts filters by outcome | unit | `cargo test -p arc-kernel test_query_filter_outcome` | Wave 0 |
| PROD-01 | query_receipts filters by min_cost/max_cost | unit | `cargo test -p arc-kernel test_query_filter_cost_range` | Wave 0 |
| PROD-01 | query_receipts cursor pagination advances correctly | unit | `cargo test -p arc-kernel test_query_cursor_pagination` | Wave 0 |
| PROD-01 | GET /receipts returns filtered results over HTTP | integration | `cargo test -p arc-cli --test trust_cluster receipts_http_endpoint` | Wave 0 |
| PROD-01 | arc receipt list CLI returns JSON lines | integration | `cargo test -p arc-cli --test receipt_list_cmd` | Wave 0 |
| PROD-06 | signDpopProof produces proof verifiable by arc-kernel | unit | `node --experimental-strip-types --test packages/sdk/arc-ts/test/dpop.test.ts` | Wave 0 |
| PROD-06 | ArcError subclasses have correct name and code | unit | `node --experimental-strip-types --test packages/sdk/arc-ts/test/errors.test.ts` | existing |
| PROD-06 | ReceiptQueryClient.paginate() yields all pages | unit | `node --experimental-strip-types --test packages/sdk/arc-ts/test/receipt_query_client.test.ts` | Wave 0 |
| PROD-06 | SDK package.json exports resolve correctly | smoke | `node -e "import('@arc-protocol/sdk')"` | Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p arc-kernel` (receipt_query unit tests)
- **Per wave merge:** `cargo test --workspace && node --experimental-strip-types --test packages/sdk/arc-ts/test/*.test.ts`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `crates/arc-kernel/src/receipt_query.rs` -- new module, all tests live here
- [ ] `crates/arc-cli/tests/receipt_list_cmd.rs` -- integration test for CLI subcommand
- [ ] `packages/sdk/arc-ts/test/dpop.test.ts` -- signDpopProof cross-language verification
- [ ] `packages/sdk/arc-ts/test/receipt_query_client.test.ts` -- ReceiptQueryClient pagination
- [ ] `packages/sdk/arc-ts/src/errors.ts` -- ArcError hierarchy (replaces/extends existing errors.ts)
- [ ] `packages/sdk/arc-ts/src/dpop.ts` -- signDpopProof function

---

## Sources

### Primary (HIGH confidence)
- Direct code inspection: `crates/arc-kernel/src/receipt_store.rs` -- existing SQL query patterns, indexed columns, cursor semantics
- Direct code inspection: `crates/arc-kernel/src/dpop.rs` -- DpopProofBody field names and types, DPOP_SCHEMA constant, verify_dpop_proof steps
- Direct code inspection: `crates/arc-cli/src/trust_control.rs` -- existing axum handler pattern, ToolReceiptQuery, ReceiptListResponse, router structure
- Direct code inspection: `crates/arc-cli/src/main.rs` -- TrustCommands enum, clap derive patterns, configure_receipt_store
- Direct code inspection: `packages/sdk/arc-ts/src/invariants/crypto.ts` -- signEd25519Message, sha256Hex implementations
- Direct code inspection: `packages/sdk/arc-ts/src/invariants/json.ts` -- canonicalizeJson RFC 8785 implementation
- Direct code inspection: `packages/sdk/arc-ts/src/invariants/errors.ts` -- existing ArcInvariantError base class
- Direct code inspection: `packages/sdk/arc-ts/package.json` -- current name (@arc/sdk), version (0.1.0), private flag
- Direct code inspection: `crates/arc-core/src/receipt.rs` -- FinancialReceiptMetadata fields including cost_charged

### Secondary (MEDIUM confidence)
- SQLite json_extract function: standard in SQLite 3.38+ (2022); WAL-mode SQLite already in use -- json_extract available
- npm scoped packages: standard npm behavior for `@org/package` -- requires org registration

### Tertiary (LOW confidence)
- None

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all dependencies already in workspace, patterns already established
- Architecture: HIGH -- directly derived from reading existing code patterns
- Pitfalls: HIGH -- sql NULL semantics and canonical JSON ordering are verifiable facts; SDK build gap is observable from package.json
- DPoP cross-language compatibility: HIGH -- exact field names read from dpop.rs source; signing primitives read from crypto.ts source

**Research date:** 2026-03-22
**Valid until:** 2026-05-22 (stable, no fast-moving ecosystem dependencies)
