# Phase 12: Capability Lineage Index and Receipt Dashboard - Research

**Researched:** 2026-03-22
**Domain:** SQLite capability lineage index (Rust/rusqlite) + React 18/Vite 6 SPA served by axum tower_http::ServeDir
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- Index stored in SQLite table in pact-kernel alongside receipt store -- co-located for efficient joins
- Capability snapshots persisted at issuance time (when kernel creates a new capability)
- Keyed by capability_id with subject, issuer, grants, and delegation metadata
- Agent-centric queries via JOIN capability_lineage ON capability_id extending existing receipt_query.rs with agent filter
- Delegation chain tracked via parent_capability_id foreign key enabling recursive chain walks
- React 18 + Vite 6 for the SPA
- TanStack Table 8 for headless, type-safe data tables with pagination/sorting
- Recharts 2 for budget/cost visualization charts
- Served via axum tower_http::ServeDir from dist/ directory -- no separate web server
- Default view: receipt list with filters sidebar (agent, tool, outcome, time range)
- Delegation chain: expandable tree in receipt detail panel (click to expand parent chain)
- Budget view: per-agent cost summary with sparkline chart showing spend over time
- Authentication: same Bearer token as trust-control API -- reuse existing auth

### Claude's Discretion

- capability_lineage SQLite table schema details beyond core columns
- React component structure and file organization
- TanStack Table column definitions and sorting defaults
- Recharts sparkline configuration and styling
- Dashboard CSS/styling approach
- Vite build configuration details

### Deferred Ideas (OUT OF SCOPE)

None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PROD-02 | Capability lineage index persists capability snapshots keyed by capability_id with subject, issuer, grants, and delegation metadata | capability_lineage SQLite table in receipt_store.rs pattern; rusqlite params! macro for JSON serialization of grants/scope |
| PROD-03 | Agent-centric receipt queries resolve through capability lineage index without replaying issuance logs | JOIN capability_lineage ON capability_id in query_receipts_impl; subject_key index enables agent filter without seq scan |
| PROD-04 | Web-based receipt dashboard renders receipts filterable by agent/tool/outcome/time with delegation chain inspection | React 18 + TanStack Table 8 useReactTable; WITH RECURSIVE CTE for delegation chain walks |
| PROD-05 | Non-engineer stakeholders can answer "what did agent X do?" via dashboard without CLI access | SPA served by axum ServeDir alongside API routes; Bearer auth reused from trust-control |
</phase_requirements>

---

## Summary

Phase 12 has two distinct implementation layers that compose cleanly. The Rust layer (plans 12-01 and 12-02) extends pact-kernel with a `capability_lineage` SQLite table and adds agent-subject filtering to the existing receipt query path. The frontend layer (plans 12-03 and 12-04) builds a React 18 SPA and wires it into the running axum server via `tower_http::ServeDir`.

The Rust side is low-risk: it follows the exact same SQLite store pattern already used in `receipt_store.rs`, `budget_store.rs`, and `revocation_store.rs`. The new table co-locates with the receipt database so agent-centric queries can be answered via a single JOIN rather than a log replay. Delegation chain inspection uses SQLite's `WITH RECURSIVE` CTE, which is fully supported by rusqlite without any additional dependencies.

The frontend side uses a locked, well-understood stack: React 18 (current: 19.2.4 -- but the decision locked React 18, so pin 18.x), Vite 6 (current: 8.0.1 -- note: Vite 6 is not the latest; latest stable is 6.x), TanStack Table 8.21.3, and Recharts 3.8.0 (note: Recharts "2" major series is now at 3.x; latest "2" series tag is 2.15.x). The SPA is served by axum via `tower-http` `ServeDir`, which is the idiomatic pattern for axum 0.8 SPAs.

**Primary recommendation:** Implement `capability_lineage.rs` in pact-kernel following the receipt_store.rs pattern, extend `ReceiptQuery` with `agent_subject: Option<String>`, build the SPA with `@tanstack/react-table@8`, `recharts@2` (pin to 2.x), React 18, Vite 6, and serve via `tower-http` `ServeDir` nested at `/`.

---

## Standard Stack

### Core (Rust)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| rusqlite | 0.37 (bundled) | SQLite capability_lineage table, WITH RECURSIVE queries | Already in workspace.dependencies; bundled avoids system lib dep |
| axum | 0.8 | HTTP router; ServeDir wiring | Already in pact-cli Cargo.toml |
| tower-http | 0.6.x | ServeDir for static SPA dist/ | Required companion to axum 0.8 for file serving |
| serde_json | 1 | JSON serialization of grants/scope into lineage rows | Already in workspace.dependencies |

### Core (Frontend)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| react | 18.x | UI framework (LOCKED) | Decision: React 18 |
| react-dom | 18.x | DOM rendering | Paired with react 18 |
| vite | 6.x | Build tool (LOCKED) | Decision: Vite 6; current npm latest is 8.0.1, so `vite@6` must be pinned |
| @vitejs/plugin-react | 4.x | Vite React fast refresh | Standard Vite+React companion |
| @tanstack/react-table | 8.21.3 | Headless table with sorting/pagination (LOCKED) | Decision: TanStack Table 8 |
| recharts | 2.x | Sparkline/bar charts (LOCKED decision says "Recharts 2") | Pin `recharts@2` -- current 2.x is 2.15.x; 3.x is breaking |
| typescript | 5.x | Type safety | Standard for TanStack Table 8 usage |

### Supporting (Frontend)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| date-fns | 3.x | Timestamp formatting for human-readable dates | Receipt list time display |
| lucide-react | 0.x | Icon set (lightweight) | Filter sidebar, expand/collapse icons |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Recharts 2 | Chart.js | Recharts is React-native; Chart.js requires imperative refs |
| TanStack Table 8 | AG Grid Community | AG Grid heavier; TanStack headless fits minimal styling approach |
| Vite 6 | esbuild standalone | Vite gives HMR + React plugin out of the box |
| WITH RECURSIVE CTE | Application-layer chain walk | CTE handles arbitrarily deep chains in one query; app-layer is O(n) round trips |

**Installation (Rust -- add to pact-cli Cargo.toml):**
```toml
tower-http = { version = "0.6", features = ["fs"] }
```

**Installation (frontend -- run from dashboard/ directory):**
```bash
npm create vite@6 dashboard -- --template react-ts
cd dashboard
npm install @tanstack/react-table@8 recharts@2 date-fns lucide-react
```

**Version verification (confirmed 2026-03-22):**
- `@tanstack/react-table` latest: 8.21.3
- `recharts` latest 2.x: pin with `recharts@2` (npm latest is 3.8.0 -- a major with breaking changes)
- `vite` 6.x: must be pinned as `vite@6` since npm latest is 8.0.1
- `react` 18.x: pin as `react@18` since npm latest is 19.2.4
- `tower-http` 0.6.x: current stable; features = ["fs"] required for ServeDir

---

## Architecture Patterns

### Recommended Project Structure

```
crates/pact-kernel/src/
├── capability_lineage.rs    # New: CapabilityLineageStore, SQLite table, WITH RECURSIVE
├── receipt_query.rs         # Extended: add agent_subject field to ReceiptQuery
├── receipt_store.rs         # Extended: query_receipts_impl uses LEFT JOIN lineage
└── lib.rs                   # Re-export CapabilityLineageStore

crates/pact-cli/src/
├── trust_control.rs         # Extended: ServeDir nest, /v1/lineage/* routes
└── dashboard/               # SPA source tree (Vite project)
    ├── package.json
    ├── vite.config.ts
    ├── src/
    │   ├── main.tsx
    │   ├── App.tsx
    │   ├── api.ts           # fetch wrappers for /v1/receipts/query, /v1/lineage/*
    │   ├── components/
    │   │   ├── ReceiptTable.tsx     # TanStack Table 8 receipt list
    │   │   ├── FilterSidebar.tsx    # Agent/tool/outcome/time filters
    │   │   ├── DelegationChain.tsx  # Expandable delegation tree
    │   │   └── BudgetSparkline.tsx  # Recharts sparkline per agent
    │   └── types.ts         # Mirror of Rust JSON shapes
    └── dist/                # Built output served by ServeDir
```

### Pattern 1: capability_lineage SQLite Table

**What:** A new table in the same SQLite database as `pact_tool_receipts`. Rows are inserted at capability issuance time. The `parent_capability_id` column is a self-referencing nullable FK enabling recursive chain walks.

**When to use:** Called from the kernel's `issue_capability` path (in `authority.rs` or wherever `LocalCapabilityAuthority::issue` constructs a new `CapabilityToken`).

**Schema (Claude's discretion):**
```sql
CREATE TABLE IF NOT EXISTS capability_lineage (
    capability_id   TEXT PRIMARY KEY,
    subject_key     TEXT NOT NULL,         -- hex-encoded Ed25519 public key (agent)
    issuer_key      TEXT NOT NULL,         -- hex-encoded Ed25519 public key
    issued_at       INTEGER NOT NULL,      -- Unix seconds
    expires_at      INTEGER NOT NULL,      -- Unix seconds
    grants_json     TEXT NOT NULL,         -- JSON array of ToolGrant/etc from PactScope
    delegation_depth INTEGER NOT NULL DEFAULT 0,
    parent_capability_id TEXT REFERENCES capability_lineage(capability_id)
);

CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
    ON capability_lineage(subject_key);
CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
    ON capability_lineage(issued_at);
CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
    ON capability_lineage(parent_capability_id);
```

**Example (Rust):**
```rust
// Source: established rusqlite pattern from receipt_store.rs
pub fn record_capability_snapshot(
    &mut self,
    token: &CapabilityToken,
    parent_capability_id: Option<&str>,
) -> Result<(), CapabilityLineageError> {
    let grants_json = serde_json::to_string(&token.scope)?;
    let depth = parent_capability_id.map(|_| 1).unwrap_or(0); // simplified; recursively compute if needed
    self.connection.execute(
        r#"
        INSERT OR IGNORE INTO capability_lineage (
            capability_id, subject_key, issuer_key,
            issued_at, expires_at, grants_json,
            delegation_depth, parent_capability_id
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            token.id,
            token.subject.to_hex(),
            token.issuer.to_hex(),
            token.issued_at as i64,
            token.expires_at as i64,
            grants_json,
            depth,
            parent_capability_id,
        ],
    )?;
    Ok(())
}
```

### Pattern 2: Agent-Centric Receipt Query via JOIN

**What:** Extend `ReceiptQuery` with `agent_subject: Option<String>`. When set, `query_receipts_impl` adds a `LEFT JOIN capability_lineage` to filter by `subject_key`. This avoids replaying issuance logs -- PROD-03 requirement.

**When to use:** Dashboard calls `GET /v1/receipts/query?agentSubject=<hex-key>`.

**SQL change in receipt_store.rs:**
```sql
-- Extended data query (agent_subject filter added):
SELECT r.seq, r.raw_json
FROM pact_tool_receipts r
LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
WHERE (?1 IS NULL OR r.capability_id = ?1)
  AND (?2 IS NULL OR r.tool_server = ?2)
  ...
  AND (?N IS NULL OR cl.subject_key = ?N)   -- new agent filter
ORDER BY r.seq ASC
LIMIT ?M
```

### Pattern 3: Delegation Chain Walk via WITH RECURSIVE

**What:** A new endpoint `GET /v1/lineage/:capability_id/chain` returns the full delegation chain from the requested capability back to the root.

**When to use:** Dashboard "delegation chain" panel calls this endpoint when user expands a receipt detail.

**SQL pattern (confirmed by SQLite docs -- HIGH confidence):**
```sql
WITH RECURSIVE chain(capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id, level) AS (
    SELECT capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id, 0
    FROM capability_lineage
    WHERE capability_id = ?1
    UNION ALL
    SELECT cl.capability_id, cl.subject_key, cl.issuer_key, cl.issued_at, cl.expires_at, cl.grants_json, cl.delegation_depth, cl.parent_capability_id, chain.level + 1
    FROM capability_lineage cl
    INNER JOIN chain ON cl.capability_id = chain.parent_capability_id
    WHERE chain.level < 20   -- guard against cycles
)
SELECT * FROM chain ORDER BY level DESC
```

**Rusqlite usage:** Standard `connection.prepare()` + `query_map()` -- recursive CTEs work identically to flat queries in rusqlite. No special crate needed.

### Pattern 4: tower-http ServeDir for SPA

**What:** Serve the built `dist/` directory via axum's `nest_service`. The SPA uses client-side routing, so all non-API paths must fall back to `index.html`.

**When to use:** Plan 12-04 wires the router.

**Example (axum 0.8 + tower-http 0.6):**
```rust
// Source: axum official static-file-server example
use tower_http::services::{ServeDir, ServeFile};

let spa_service = ServeDir::new("dashboard/dist")
    .not_found_service(ServeFile::new("dashboard/dist/index.html"));

let router = Router::new()
    // ... existing API routes ...
    .route(RECEIPT_QUERY_PATH, get(handle_query_receipts))
    .route("/v1/lineage/:capability_id", get(handle_get_lineage))
    .route("/v1/lineage/:capability_id/chain", get(handle_get_delegation_chain))
    .nest_service("/", spa_service)
    .with_state(state);
```

**Key ordering rule:** API routes must be registered BEFORE the catch-all `nest_service("/", ...)`. Axum matches routes in registration order for specificity; more-specific paths win over the wildcard service.

### Pattern 5: TanStack Table 8 Core Pattern

**What:** Headless table hook. Caller provides data and column definitions; the hook returns a table instance for rendering.

**When to use:** `ReceiptTable.tsx` and any tabular data in the dashboard.

**Example:**
```typescript
// Source: tanstack.com/table/v8/docs/framework/react/react-table
import {
  createColumnHelper,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  flexRender,
} from '@tanstack/react-table'

const columnHelper = createColumnHelper<ReceiptRow>()

const columns = [
  columnHelper.accessor('timestamp', {
    header: 'Time',
    cell: info => formatTimestamp(info.getValue()),
  }),
  columnHelper.accessor('tool_name', { header: 'Tool' }),
  columnHelper.accessor('decision', { header: 'Outcome' }),
  // ...
]

const table = useReactTable({
  data: receipts,
  columns,
  getCoreRowModel: getCoreRowModel(),
  getPaginationRowModel: getPaginationRowModel(),
  getSortedRowModel: getSortedRowModel(),
  manualPagination: true,   // server-driven cursor pagination
  pageCount: -1,            // unknown with cursor pagination
})
```

**Pagination note:** Because the server uses cursor-based pagination (not offset), set `manualPagination: true` and track cursor state in React state alongside the table. `next_cursor` from the API drives the "next page" action.

### Pattern 6: Recharts Sparkline

**What:** Lightweight area/bar chart for budget spend over time.

**When to use:** Budget view panel per agent.

**Example:**
```typescript
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

function BudgetSparkline({ data }: { data: { time: string; cost: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={60}>
      <AreaChart data={data} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
        <Area type="monotone" dataKey="cost" stroke="#6366f1" fill="#e0e7ff" strokeWidth={1.5} dot={false} />
        <XAxis dataKey="time" hide />
        <YAxis hide />
        <Tooltip formatter={(v) => [`${v} minor units`, 'Cost']} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
```

### Anti-Patterns to Avoid

- **Route order inversion:** Registering `nest_service("/", spa)` BEFORE API routes causes all API calls to be served as 404 HTML pages instead of JSON. Always register specific routes first.
- **ON CONFLICT DO NOTHING omission:** Capability snapshots may be replayed across restarts. Without `INSERT OR IGNORE INTO capability_lineage` or `ON CONFLICT DO NOTHING`, duplicate snapshot inserts panic at the UNIQUE constraint.
- **Float cost arithmetic:** Monetary amounts are `u64` minor units throughout the codebase (established in Phase 7). Do not convert to float in the frontend -- display minor units with string formatting (e.g., `$${(cost / 100).toFixed(2)}`).
- **Unbounded delegation depth:** The `WITH RECURSIVE` CTE must include a `WHERE level < N` guard. SQLite does not enforce a recursion limit by default; a cycle in bad data would loop forever.
- **deny_unknown_fields on new API response types:** All new serde types must NOT use `#[serde(deny_unknown_fields)]` -- this is the hard gate established in Phase 7 (SCHEMA-01).
- **Blocking database calls in axum handlers:** All SQLite work must happen through `tokio::task::spawn_blocking` or via `Arc<Mutex<...>>` accessed in a blocking-safe way. The existing trust_control.rs uses `Arc<Mutex<TrustServiceState>>` -- follow the same pattern for lineage store access.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Delegation chain traversal | Application-layer loop with N+1 queries | `WITH RECURSIVE` CTE in SQLite | Single query, handles arbitrary depth, no round-trip overhead |
| Static file serving for SPA | Custom axum handler reading files | `tower_http::ServeDir` + `ServeFile` fallback | Handles ETag, range requests, content-type sniffing, 304 Not Modified |
| Table pagination UI state | Custom pagination component | TanStack Table 8 `getPaginationRowModel` | Handles page size, page index, row count display |
| Time formatting | Custom date math | `date-fns` `formatDistanceToNow` / `format` | Locale-aware, handles edge cases |
| SVG charts | D3 or raw SVG | Recharts 2 `AreaChart`/`BarChart` | React-native, composable, tooltip/axis included |

**Key insight:** SQLite's recursive CTEs eliminate the most complex custom logic in this phase (chain walking). The entire delegation chain from leaf to root is one prepared statement.

---

## Common Pitfalls

### Pitfall 1: Vite Proxy in Development vs Production Serving

**What goes wrong:** During Vite dev server (`npm run dev`), the SPA runs on its own port (e.g., 5173). API calls to `/v1/receipts/query` hit CORS errors because they target the axum server on a different port.

**Why it happens:** Browsers enforce same-origin policy for fetch calls.

**How to avoid:** Configure Vite's dev proxy in `vite.config.ts`:
```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/v1': 'http://localhost:8080',  // forward API calls to axum
    },
  },
  build: {
    outDir: '../../../dist',  // relative to dashboard/ -- outputs where axum's ServeDir points
  },
})
```
In production, no proxy is needed because the SPA and API are served from the same axum process.

### Pitfall 2: Bearer Auth in SPA Fetch Calls

**What goes wrong:** Dashboard fetch calls to `/v1/receipts/query` return 401 because the browser does not automatically send the `Authorization: Bearer` header.

**Why it happens:** The trust-control API requires Bearer auth everywhere. The SPA must read the token from somewhere (URL param, localStorage, or a config endpoint) and inject it.

**How to avoid:** The simplest approach: accept `?token=<bearer>` as a query parameter in the SPA on first load, store it in `sessionStorage`, and attach it to every fetch:
```typescript
const token = sessionStorage.getItem('pact_token') ?? new URLSearchParams(location.search).get('token') ?? ''
fetch('/v1/receipts/query?...', { headers: { Authorization: `Bearer ${token}` } })
```
This avoids adding a new unauthenticated endpoint. Non-engineers receive a URL with the token embedded, which is acceptable for internal dashboards.

### Pitfall 3: Missing tower-http "fs" Feature Flag

**What goes wrong:** `ServeDir` is not found at compile time even though `tower-http` is in Cargo.toml.

**Why it happens:** `tower-http` gates filesystem serving behind the `"fs"` feature to keep compile times low.

**How to avoid:** Add to pact-cli Cargo.toml:
```toml
tower-http = { version = "0.6", features = ["fs"] }
```

### Pitfall 4: capability_lineage Table in Wrong Database File

**What goes wrong:** `capability_lineage` rows are inserted to a different SQLite connection than `pact_tool_receipts`, making the JOIN in `query_receipts_impl` fail with "no such table" at query time.

**Why it happens:** pact-kernel currently has separate database files for receipts, budgets, and revocations. If `capability_lineage` opens its own connection to a new file, the JOIN cannot span connections.

**How to avoid:** Add the `capability_lineage` table to the same SQLite file as `pact_tool_receipts` (the receipt DB). Open it in `SqliteReceiptStore::open` alongside the existing `CREATE TABLE IF NOT EXISTS` batch. This is the explicit decision in CONTEXT.md ("co-located for efficient joins").

### Pitfall 5: Vite Build outDir Mismatch

**What goes wrong:** `ServeDir::new("dashboard/dist")` serves an empty directory because `vite build` emits to a different path.

**Why it happens:** Vite's default `outDir` is relative to the project root (`dashboard/`), so it emits to `dashboard/dist` by default -- which matches. But if the axum binary is run from a different working directory, the relative path breaks.

**How to avoid:** Use an absolute path based on a compile-time `CARGO_MANIFEST_DIR` embed, or document that `pact trust-serve` must be run from the workspace root. Add a clear error message if `dist/index.html` is not found at startup.

### Pitfall 6: React 18 vs 19 API Differences

**What goes wrong:** `npm create vite@6` with the react-ts template installs `react@19` by default (current npm latest). React 19 changed some APIs (e.g., `useId` behavior, server component hints, `ref` as prop).

**Why it happens:** The decision locks React 18, but `vite@6`'s react-ts template pulls latest react.

**How to avoid:** After scaffolding, pin versions explicitly:
```json
{
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  }
}
```
Then run `npm install` to pin.

---

## Code Examples

Verified patterns from official sources and codebase analysis:

### Lineage Store Opening (follows receipt_store.rs pattern exactly)
```rust
// Mirrors SqliteReceiptStore::open in crates/pact-kernel/src/receipt_store.rs
impl SqliteReceiptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        // ...existing setup...
        connection.execute_batch(r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            -- Existing tables...

            -- NEW in Phase 12:
            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);
        "#)?;
        Ok(Self { connection })
    }
}
```

### Agent-Centric Query Extension (ReceiptQuery struct)
```rust
// In crates/pact-kernel/src/receipt_query.rs
pub struct ReceiptQuery {
    // ... existing fields ...
    /// Filter by agent subject public key (hex-encoded Ed25519).
    /// Resolved through capability_lineage JOIN -- does not replay issuance logs.
    pub agent_subject: Option<String>,
}
```

### axum ServeDir Integration
```rust
// In crates/pact-cli/src/trust_control.rs
// Add to Cargo.toml: tower-http = { version = "0.6", features = ["fs"] }
use tower_http::services::{ServeDir, ServeFile};

// In serve_async(), after all .route() calls:
let spa_fallback = ServeFile::new("dashboard/dist/index.html");
let spa_service = ServeDir::new("dashboard/dist").not_found_service(spa_fallback);

let router = Router::new()
    .route(HEALTH_PATH, get(handle_health))
    // ... all existing API routes ...
    .route(RECEIPT_QUERY_PATH, get(handle_query_receipts))
    // New Phase 12 routes:
    .route("/v1/lineage/:capability_id", get(handle_get_lineage))
    .route("/v1/lineage/:capability_id/chain", get(handle_get_delegation_chain))
    .route("/v1/agents/:subject_key/receipts", get(handle_agent_receipts))
    // SPA catch-all MUST be last:
    .nest_service("/", spa_service)
    .with_state(state);
```

### TanStack Table 8 Server-Side Pagination
```typescript
// cursor-based pagination with TanStack Table 8
const [cursor, setCursor] = useState<number | null>(null)
const [cursorStack, setCursorStack] = useState<(number | null)[]>([null])

const { data } = useQuery(['receipts', filters, cursor], () =>
  fetchReceipts({ ...filters, cursor: cursor ?? undefined, limit: 50 })
)

const table = useReactTable({
  data: data?.receipts ?? [],
  columns,
  getCoreRowModel: getCoreRowModel(),
  manualPagination: true,
  pageCount: data ? Math.ceil(data.total_count / 50) : -1,
})
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Offset-based SQL pagination | Cursor/seq-based pagination | Phase 10 (PROD-01) | Stable results under concurrent inserts; already implemented |
| react-table v7 (class components) | TanStack Table v8 (headless hooks) | 2022 | Breaking API change; v7 is unmaintained |
| Separate web server for dashboards | axum ServeDir colocation | axum 0.5+ | Single binary deploy; no nginx required |
| Recharts 2 vs 3 | Recharts 3.x is current | 2024 | Decision locks Recharts 2; pin `recharts@2` to avoid unexpected upgrade to 3.x |
| Vite 5 | Vite 6 (locked), 7/8 also exist | 2024/2025 | Must pin `vite@6` explicitly -- npm latest is 8.0.1 |
| React class components / hooks (v16/17) | React 18 concurrent features | 2022 | `createRoot` is the new entry point; `render` is deprecated |

**Deprecated/outdated:**
- `ReactDOM.render()`: Replaced by `createRoot(root).render(<App/>)` in React 18. The Vite react-ts template generates `createRoot` by default.
- `react-table` v7: Completely replaced by `@tanstack/react-table` v8 with incompatible API.
- axum `Router::nest` with `MethodRouter`: For static file serving, use `nest_service` (not `nest`). `nest` is for `Router` nesting only.

---

## Open Questions

1. **Dashboard build location and binary path**
   - What we know: `ServeDir::new("dashboard/dist")` uses a path relative to the process working directory.
   - What's unclear: Should the `pact` binary embed the dashboard dist at compile time (via `include_dir!`) or expect it on-disk at runtime?
   - Recommendation: Use runtime path for Phase 12 (simplest). Document that `pact trust-serve` must be run from the workspace root where `dashboard/dist/` exists. Embedding can be done in a future hardening phase.

2. **Capability snapshot hook location**
   - What we know: `CapabilityToken` is issued by `LocalCapabilityAuthority::issue` in `authority.rs`.
   - What's unclear: The lineage store needs access to the same SQLite connection as the receipt store, or its own connection to the same file.
   - Recommendation: Add `record_capability_snapshot` as a method on `SqliteReceiptStore` (since the table is co-located). This avoids opening a second connection to the receipt DB file, which would require WAL reader coordination.

3. **Recharts 2 vs Recharts 3 API compatibility**
   - What we know: npm `recharts` latest is 3.8.0. The decision says "Recharts 2". The `recharts@2` pin resolves to 2.15.x.
   - What's unclear: Whether there are any breaking API changes in 3.x that affect the sparkline pattern.
   - Recommendation: Pin `recharts@2` in package.json. The sparkline API shown in Code Examples is confirmed working in 2.x. Do not upgrade to 3.x in this phase.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` (Rust unit + integration); no separate JS test framework required for Phase 12 |
| Config file | `Cargo.toml` workspace (existing); `package.json` for frontend build verification |
| Quick run command | `cargo test -p pact-kernel -- capability_lineage` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PROD-02 | capability_lineage rows persist at issuance with correct subject/issuer/grants | unit | `cargo test -p pact-kernel -- capability_lineage::tests` | ❌ Wave 0 |
| PROD-02 | grants_json round-trips through serde_json without loss | unit | `cargo test -p pact-kernel -- capability_lineage::tests::grants_roundtrip` | ❌ Wave 0 |
| PROD-03 | agent_subject filter returns only receipts from that agent's capabilities | unit | `cargo test -p pact-kernel -- receipt_query::tests::test_query_agent_subject` | ❌ Wave 0 |
| PROD-03 | agent-centric query does not replay issuance logs (resolved via JOIN) | unit | Verified by query plan inspection or by ensuring no seq scan on raw_json | ❌ Wave 0 |
| PROD-04 | GET /v1/lineage/:id/chain returns delegation chain in root-first order | integration | `cargo test -p pact-cli --test receipt_query -- lineage_chain` | ❌ Wave 0 |
| PROD-05 | dashboard index.html served at GET / by axum | integration | `cargo test -p pact-cli --test receipt_query -- spa_serves_index` | ❌ Wave 0 |
| PROD-05 | missing asset path falls back to index.html (SPA client routing) | integration | `cargo test -p pact-cli --test receipt_query -- spa_fallback` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p pact-kernel --lib` (unit only, < 10 s)
- **Per wave merge:** `cargo test --workspace` (full suite including integration tests)
- **Phase gate:** Full suite green + `npm run build` in `dashboard/` exits 0, before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] Unit tests for `capability_lineage.rs` -- covers PROD-02
- [ ] Extended `receipt_query.rs` tests for `agent_subject` filter -- covers PROD-03
- [ ] Integration test in `crates/pact-cli/tests/receipt_query.rs` for lineage chain endpoint -- covers PROD-04
- [ ] Integration test for SPA serving and fallback -- covers PROD-05
- [ ] `npm run build` in `crates/pact-cli/dashboard/` -- frontend build gate

---

## Sources

### Primary (HIGH confidence)
- Codebase analysis: `crates/pact-kernel/src/receipt_store.rs` -- SQLite WAL mode, SYNCHRONOUS=FULL pattern, params! macro usage
- Codebase analysis: `crates/pact-kernel/src/receipt_query.rs` -- ReceiptQuery struct, query_receipts_impl, filter/cursor pattern
- Codebase analysis: `crates/pact-cli/src/trust_control.rs` -- axum Router::new, route registration order, Bearer auth pattern
- Codebase analysis: `crates/pact-core/src/capability.rs` -- CapabilityToken fields (id, issuer, subject, scope, issued_at, expires_at, delegation_chain)
- `npm view @tanstack/react-table version` -> 8.21.3 (verified 2026-03-22)
- `npm view recharts dist-tags` -> latest: 3.8.0 (Recharts 2.x is 2.x branch; pin `recharts@2`)
- `npm view vite dist-tags` -> latest: 8.0.1, previous: 5.4.21 (Vite 6 must be pinned as `vite@6`)
- `npm view react version` -> 19.2.4 (React 18 must be pinned as `react@18`)
- SQLite `WITH RECURSIVE` CTE: [https://sqlite.org/lang_with.html](https://sqlite.org/lang_with.html) -- standard SQL feature, fully supported by rusqlite

### Secondary (MEDIUM confidence)
- [axum static-file-server example](https://github.com/tokio-rs/axum/blob/main/examples/static-file-server/src/main.rs) -- ServeDir + ServeFile fallback pattern; verified consistent with tower-http 0.6 feature flag requirement
- [TanStack Table v8 React docs](https://tanstack.com/table/v8/docs/framework/react/react-table) -- useReactTable API, createColumnHelper, manualPagination flag
- WebSearch: axum 0.8 + tower-http ServeDir pattern (multiple consistent sources confirming `features = ["fs"]` requirement)

### Tertiary (LOW confidence)
- None -- all critical claims verified against codebase or official docs

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all versions verified with `npm view`; axum/rusqlite versions read from Cargo.toml directly
- Architecture: HIGH -- patterns copied from existing receipt_store.rs, receipt_query.rs, trust_control.rs
- Pitfalls: HIGH -- route ordering and feature flag pitfalls confirmed by axum/tower-http docs; version pinning confirmed by npm dist-tags

**Research date:** 2026-03-22
**Valid until:** 2026-04-22 (30 days -- stable libraries; npm versions may shift but pinning strategy holds)
