# Stack Research

**Domain:** Rust protocol workspace — agent economy economic primitives
**Researched:** 2026-03-21
**Confidence:** HIGH (Rust crates verified via crates.io/docs.rs and project source; LOW only where noted)

---

## Context

This document covers ONLY the additions and changes needed for the PACT v2.0 milestone.
The existing stack (Rust 1.93 MSRV, Ed25519/SHA-256/canonical JSON, SQLite via rusqlite 0.37,
tokio 1, axum 0.8, serde/serde_json 1, thiserror 1, uuid 1, chrono 0.4) is validated and
NOT re-researched here.

New feature areas:
1. Monetary budget enforcement (new types in `pact-core`, new store methods in `pact-kernel`)
2. Receipt query API + capability lineage index (SQLite FTS5, structured queries)
3. DPoP proof-of-possession (porting from ClawdStrike, no third-party DPoP crate needed)
4. Velocity guard (token-bucket rate limiting in `pact-guards`)
5. SIEM exporters (new `pact-siem` crate, HTTP fan-out to 6 targets)
6. Receipt dashboard (static SPA served by the existing axum server)
7. Merkle checkpoint wiring (already in `pact-core::merkle`; needs schema + persistence)

---

## Recommended Stack

### Core Technologies (Existing — No Change)

| Technology | Version | Purpose | Status |
|------------|---------|---------|--------|
| Rust | 1.93 MSRV | Workspace language | Validated v1.0 |
| rusqlite | 0.37 (bundled) | SQLite receipt/budget stores | Validated v1.0 |
| tokio | 1 | Async runtime | Validated v1.0 |
| axum | 0.8 | HTTP server for kernel API and dashboard serving | Validated v1.0 |
| serde / serde_json | 1 | Serialization | Validated v1.0 |
| ed25519-dalek | 2 | Ed25519 signing | Validated v1.0 |
| sha2 | 0.10 | SHA-256 hashing | Validated v1.0 |
| chrono | 0.4 | Timestamps in policy crate | Validated v1.0 |
| uuid | 1 (v7) | Time-ordered IDs | Validated v1.0 |

### New Libraries Required

#### 1. Monetary Budget Enforcement

No new Rust crates are needed. The AGENT_ECONOMY.md design uses `u64` minor-unit arithmetic
(e.g. cents for USD, satoshis for BTC) as plain integers. This avoids floating-point precision
bugs and eliminates the need for `rust_decimal` or `steel-cent`.

**Decision:** Represent `MonetaryAmount { units: u64, currency: String }` in `pact-core` as
pure Rust structs with arithmetic guarded by checked_add/checked_sub. This fits the existing
pattern of avoiding extra dependencies in `pact-core`.

**What NOT to add:** `rust_decimal` (adds 70+ KB to binary, unnecessary for single-currency
integer arithmetic), `steel-cent` (abandoned, last release 2019).

#### 2. Receipt Query API and SQLite FTS5

FTS5 is already present in the bundled SQLite 3.50.2 shipped by `rusqlite 0.37 { bundled }`.
No additional crate is needed.

Enable FTS5 virtual table in the receipt store migration:

```sql
CREATE VIRTUAL TABLE receipt_fts USING fts5(
    capability_id, tool_server, tool_name, decision, content=receipts
);
```

Queries use standard `MATCH` syntax via rusqlite's existing `conn.execute()` / `conn.query_row()`
API. No new dependency required.

**Confidence:** HIGH — rusqlite 0.37 bundles SQLite 3.50.2 with `-DSQLITE_ENABLE_FTS5` enabled
by default when the `bundled` feature is active (verified: rusqlite GitHub releases).

#### 3. DPoP Proof-of-Possession

Do NOT pull in a third-party DPoP crate. PACT's DPoP is NOT RFC 9449 OAuth DPoP (which is
JWT-based and HTTP-scoped). It is an Ed25519-based proof bound to capability invocations, not
HTTP token requests. The atproto-oauth crate implements RFC 9449 JWT DPoP; it is incompatible
with PACT's Ed25519 invocation-proof model.

**Decision:** Port `validate_dpop_binding()` and companion types from ClawdStrike's
`clawdstrike-brokerd/src/capability.rs` as described in `docs/CLAWDSTRIKE_INTEGRATION.md`.
All required crypto primitives (`pact_core::crypto::{Keypair, PublicKey, Signature}`,
`pact_core::hashing::sha256_hex`) already exist.

One new dependency IS needed: a nonce replay store for freshness/anti-replay. A simple
`HashMap<(thumbprint, nonce), u64>` with LRU eviction is sufficient. Use the `lru` crate:

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| lru | 0.12 | Nonce replay prevention for DPoP proof freshness | Bounded-size HashMap with O(1) eviction. No tokio required — replay store is accessed under `std::sync::Mutex` in the kernel's synchronous evaluation path. Zero external dependencies. |

**Confidence:** HIGH for lru crate selection (widely used, 0 dependencies, compatible with MSRV 1.65+).

#### 4. Velocity Guard (Token-Bucket Rate Limiter)

The ClawdStrike source implements a custom `TokenBucket` struct (68 lines). The design note in
`CLAWDSTRIKE_INTEGRATION.md` specifies that `pact_kernel::Guard::evaluate()` is synchronous,
so the guard must use `try_acquire` (deny immediately) rather than async waiting.

Options evaluated:
- **governor** (GCRA, no background thread): good for global limits; per-key with HashMap
  wrapper requires extra plumbing. Adds ~30KB to binary.
- **leaky-bucket**: async-only; requires tokio, incompatible with synchronous `Guard::evaluate()`.
- **Custom port from ClawdStrike**: 68-line `TokenBucket`, zero dependency cost, already
  adapted for PACT's synchronous guard interface in the integration plan.

**Decision:** Port the `TokenBucket` directly from ClawdStrike as `pact-guards/src/velocity.rs`.
No new crate dependency. Use `std::sync::Mutex<TokenBucket>` per `(AgentId, grant_index)` key
in a `HashMap`.

**What NOT to add:** `governor` (overkill for this use case, async-oriented API), `leaky-bucket`
(async-only, incompatible with synchronous guard path).

#### 5. SIEM Exporters (`pact-siem` crate)

This is the one area where significant new dependencies are required.

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| reqwest | 0.13 | Async HTTP client for Splunk HEC, Elasticsearch, Datadog, Sumo Logic, webhook endpoints | reqwest 0.13 is current stable (rustls default TLS, no openssl required). Already used in pact-cli at 0.12; upgrade to 0.13 consolidates to a single version. Connection pooling and retry-friendly via tower-compatible middleware. |
| tower | 0.5 | Timeout and retry middleware for exporter HTTP calls | Already transitive dep via axum. Provides `ServiceBuilder` for adding timeout/retry layers to reqwest clients without custom backoff code. |
| tokio | 1 (existing) | Async runtime for SIEM fan-out tasks | Already workspace dep. Each exporter runs as a spawned tokio task. |
| serde_json | 1 (existing) | Event payload serialization (Splunk HEC JSON, ECS, OCSF) | Already workspace dep. |

**Schema formats** (ECS, CEF, OCSF, Native):
- **ocsf-schema-rs**: unofficial, generated from OCSF JSON Schema via Typify. Useful as
  reference but heavy (generated types for entire OCSF schema). Do NOT add as dependency.
  Instead, define a minimal `OcsfApiActivity` struct containing only the fields PACT receipts
  map to. This is what ClawdStrike's `clawdstrike-ocsf` crate does.
- **rust-cef**: provides a trait to serialize structs to ArcSight CEF strings. LOW confidence
  this crate is maintained (last checked 2025). Given CEF is simple key=value format, implement
  the CEF serializer directly (< 50 lines) rather than taking the dependency.

**Dead Letter Queue:** filesystem-backed, size-capped. Use `std::fs` with atomic file writes
(write to `.tmp`, rename). No new crate needed.

**Batching / flush timer:** `tokio::time::interval` for flush triggers. No new crate needed.

**Confidence:** HIGH for reqwest 0.13 (verified current stable on crates.io).
MEDIUM for tower 0.5 retry layer usage (axum uses tower but SIEM retry pattern needs testing).

#### 6. Receipt Dashboard (SPA)

The receipt dashboard is a static web app served by the existing axum server via
`tower_http::services::ServeDir`. The SPA calls the receipt query API (JSON endpoints on the
axum server) and renders results.

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| React | 18 | UI component framework | Standard, TypeScript-first, well-typed. The TS SDK (`packages/sdk/pact-ts`) is already TypeScript; shared types for receipts can be generated or handwritten once. |
| Vite | 6 | Build tool and dev server | Sub-second HMR, zero-config TypeScript, outputs static files deployable from `tower_http::ServeDir`. Standard for SPA tooling in 2026. |
| TypeScript | 5 | Type safety | Consistent with existing TS SDK. Catches mismatches against the receipt JSON shape at compile time. |
| TanStack Table | 8 | Receipt list with sorting/filtering/pagination | Headless (no imposed styles), handles large receipt sets with virtualization, works with any CSS approach. Best choice for a filterable audit log table. |
| Recharts | 2 | Time-series charts (spend over time, deny rate trends) | React-native, SVG-based, minimal dependencies, well-maintained. Appropriate for the receipt throughput and budget-utilization charts needed in the dashboard. |
| TanStack Query | 5 | Data fetching and cache management for receipt API | Eliminates polling boilerplate for receipt lists. Pairs naturally with TanStack Table. Keeps the SPA reactive without a heavyweight state manager. |
| Tailwind CSS | 4 | Utility-first styling | Zero runtime, purges unused classes at build time. Appropriate for a developer-facing audit dashboard where design fidelity is secondary to function. |

**What NOT to add:**
- **Next.js / Remix**: SSR is unnecessary for an audit dashboard accessed by operators on demand.
  Static SPA avoids a Node server process. Vite + React is the right weight.
- **Material UI / Ant Design**: Heavy component libraries add 200-500 KB. Tailwind + headless
  components (TanStack Table) give sufficient functionality at a fraction of the size.
- **D3.js directly**: Recharts wraps D3; using D3 directly would require manual SVG management.
  Recharts is sufficient for the 3-5 chart types needed (time series, bar, donut).
- **Redux / Zustand**: State management overhead is unjustified for a data-fetching dashboard.
  TanStack Query handles server state; React useState handles UI state.

**Build integration:** The SPA builds to `pact-dashboard/dist/`. The pact-cli server adds a
route: `GET /dashboard` -> `tower_http::ServeDir::new("pact-dashboard/dist")`. In development,
`vite --proxy /api http://localhost:PORT` handles CORS. No axum changes required beyond the
one `ServeDir` route.

**Confidence:** HIGH for React/Vite/TypeScript/TanStack Table/Recharts (all widely used and
current). MEDIUM for build integration pattern (axum ServeDir is straightforward but exact
path embedding strategy depends on deployment target — verified pattern exists via web search).

---

## Summary of New Dependencies by Crate

### Workspace-level `Cargo.toml` additions

```toml
[workspace.dependencies]
lru = "0.12"
reqwest = { version = "0.13", default-features = false, features = ["json", "rustls-tls"] }
tower = { version = "0.5", features = ["timeout", "retry"] }
tower-http = { version = "0.6", features = ["fs", "cors", "trace"] }
```

Note: `reqwest` is already in `pact-cli/Cargo.toml` at 0.12. Upgrade to 0.13 and move to
workspace. `tower-http` is already a transitive dep via axum; promote to explicit workspace dep
for the `ServeDir` dashboard route.

### New crate: `crates/pact-siem/Cargo.toml`

```toml
[dependencies]
pact-core = { path = "../pact-core" }
pact-kernel = { path = "../pact-kernel" }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
reqwest = { workspace = true }
tower = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
```

### Changes to `crates/pact-guards/Cargo.toml`

```toml
# No new dependencies — velocity guard uses std::sync::Mutex + std::time::Instant
# (already available in std)
```

### Changes to `crates/pact-kernel/Cargo.toml`

```toml
lru = { workspace = true }  # for DPoP nonce replay store
```

### Changes to `crates/pact-cli/Cargo.toml`

```toml
# Upgrade reqwest from 0.12 to workspace 0.13
reqwest = { workspace = true }
tower-http = { workspace = true }  # for ServeDir dashboard route
```

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| u64 minor-unit integers for monetary amounts | `rust_decimal` | Only if multi-currency exchange-rate conversion is needed (deferred to Q4 2026) |
| Custom token-bucket port from ClawdStrike | `governor` crate | If PACT adopts async guard evaluation; `governor` is excellent for global async rate limiting |
| reqwest 0.13 | `ureq` 2.x (sync) | pact-siem requires async fan-out to multiple endpoints; ureq's blocking model would require spawning threads per exporter, which is inferior to tokio tasks |
| TanStack Table | AG Grid Community | AG Grid is appropriate when Excel-like features (column groups, pivoting) are needed; audit log tables do not require this complexity |
| Recharts | Chart.js | Chart.js is canvas-based (not React-native); Recharts SVG output is easier to style with Tailwind and more accessible |
| Vite + React SPA | Leptos / Yew (Rust WASM) | Rust WASM UI frameworks have poor ecosystem maturity for data tables and charts; TS SDK team already works in TypeScript — reuse that expertise |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `rust_decimal` for monetary amounts | Unnecessary for u64 minor-unit arithmetic; adds compile time and binary size for zero gain at single-currency scope | Plain `u64` with `checked_add` / `checked_sub` |
| `atproto-oauth` for DPoP | Implements RFC 9449 JWT/HTTP DPoP, not PACT's Ed25519 invocation-proof model | Port DPoP verifier from ClawdStrike source |
| `ocsf-schema-rs` as full dependency | Generated types for entire OCSF schema (~2000 types); PACT only needs ~10 fields from `api_activity` class | Define minimal OCSF structs inline in `pact-siem::event` |
| `rust-cef` for CEF format | Maintenance uncertain; CEF format is simple enough (50 lines) to implement inline | Inline `CefFormatter` in `pact-siem::exporters::elastic` |
| `leaky-bucket` for velocity guard | Async-only API; incompatible with `pact_kernel::Guard::evaluate()` synchronous contract | Port `TokenBucket` from ClawdStrike (68 lines, zero deps) |
| Next.js or Remix for dashboard | SSR overhead with no benefit for an operator audit dashboard; adds Node server process | Vite + React SPA, served statically via `tower_http::ServeDir` |
| Redux / Zustand for dashboard state | Unnecessary for a data-fetching dashboard; introduces boilerplate | TanStack Query for server state, `useState` for UI state |
| OpenSSL via `reqwest` default-features | OpenSSL requires system library, complicates cross-compilation and Alpine Docker builds | reqwest with `rustls-tls` feature (default in 0.13) |

---

## Stack Patterns by Variant

**If the receipt dashboard needs offline/local-only deployment (air-gapped environments):**
- Bundle the SPA assets into the binary using `include_dir!` macro
- Serve via `axum::Router` with an in-memory bytes handler instead of `ServeDir`
- This avoids filesystem path coupling in deployment

**If SIEM exporter volume exceeds 10K events/sec:**
- Add `tokio::sync::mpsc` bounded channel between receipt store and exporter manager
  (already in scope from ClawdStrike `ExporterManager` design)
- Consider upgrading to `reqwest` HTTP/2 multiplexing (`http2` feature) for Elasticsearch
  bulk API batching
- This is a Q3 optimization, not a Q2 prerequisite

**If monetary budget enforcement needs cross-node consistency:**
- The existing `SqliteBudgetStore` WAL replication pattern (seq-based LWW) already handles
  multi-node budget sync; monetary budgets extend the same column set
- No new infrastructure needed for single-currency; cross-currency would require a consensus
  layer (deferred to Q4 2026 per PROJECT.md)

---

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| reqwest 0.13 | tokio 1, rustls (default) | rustls-tls is now the default TLS; remove old `rustls-tls` feature flag from pact-cli, it is now implicit |
| lru 0.12 | Rust MSRV 1.65+ | Compatible with project MSRV of 1.93 |
| rusqlite 0.37 bundled | SQLite 3.50.2, FTS5 enabled | FTS5 available without separate feature flag when `bundled` is active |
| axum 0.8 | tower 0.5, tower-http 0.6, tokio 1 | Path parameter syntax changed to `{param}` in 0.8; already in use per pact-cli Cargo.toml |
| TanStack Table 8 | React 18, TypeScript 5 | Headless; no peer dep conflicts with Recharts or Tailwind |
| Recharts 2 | React 18 | Recharts 3 is in beta as of 2026-Q1; use stable 2.x until 3.x stabilizes |

---

## Sources

- [rusqlite releases — GitHub](https://github.com/rusqlite/rusqlite/releases) — verified 0.37 bundles SQLite 3.50.2 with FTS5 (HIGH confidence)
- [reqwest 0.13.2 — docs.rs](https://docs.rs/crate/reqwest/latest) — verified 0.13 is current stable with rustls default TLS (HIGH confidence)
- [axum 0.8.8 announcement — tokio.rs](https://tokio.rs/blog/2025-01-01-announcing-axum-0-8-0) — axum 0.8 current stable (HIGH confidence)
- [lru — crates.io](https://crates.io/crates/lru) — verified as zero-dep, actively maintained (HIGH confidence)
- [TanStack Table v8 — tanstack.com](https://tanstack.com/table/latest) — headless table library, React 18 compatible (HIGH confidence)
- [Recharts — GitHub](https://github.com/recharts/recharts) — React + D3 SVG charts, v2 stable (HIGH confidence)
- [RFC 9449 — IETF](https://www.rfc-editor.org/rfc/rfc9449.html) — DPoP is JWT/HTTP-scoped; not applicable to PACT's Ed25519 invocation model (HIGH confidence)
- [ocsf-schema — crates.io](https://crates.io/crates/ocsf-schema-rs) — confirmed exists but full schema is too large to depend on wholesale (MEDIUM confidence; crate maturity unverified)
- [rust-cef — crates.io](https://crates.io/crates/rust-cef) — exists, maintenance uncertain (LOW confidence; inline implementation preferred)
- PACT project source: `docs/CLAWDSTRIKE_INTEGRATION.md`, `docs/AGENT_ECONOMY.md`, workspace `Cargo.toml` — authoritative for existing stack and port decisions (HIGH confidence)

---

*Stack research for: PACT v2.0 agent economy economic primitives*
*Researched: 2026-03-21*
