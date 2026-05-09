# M09 P5 Lineage Phase Plan

Date: 2026-04-30
Scope: implementation-ready whole-phase plan for M09 P5 lineage readiness.
This is research and sequencing guidance only. It does not implement code,
update tickets, touch execution ledgers, edit Cargo files, or open a PR.

## Phase-Grain Rule

P5 must execute as one phase-grain work package after the W4 gates open. Do
not split this into ticket-grain work orders, ticket-grain branches, or
ticket-grain PRs. The ticket files are briefing material and gate definitions,
not the dispatch unit.

Recommended eventual implementation branch:

```text
wave/W4/m09/p5.phase-lineage-genesis
```

Current research write set:

```text
.planning/trajectory-2/research/m09/P5-LINEAGE-PHASE-PLAN.md
```

No other files are owned by this readiness task.

## Live Blockers Observed

Implementation remains blocked.

- Trajectory state still reports `current_wave: "W1"`, while M09 is assigned
  to W4 and remains `ticket files authored` / `ready_for_p0`.
- P5 depends on all prior M09 phases through `M09.P4.T7`, so P0 through P4
  must land before any P5 implementation starts.
- `crates/chio-lineage/` is absent in this checkout. P0 scaffolding has not
  landed, so P5 cannot compile or test.
- `Cargo.toml` has no `chio-lineage` workspace member and
  `crates/chio-store-sqlite/Cargo.toml` has no `lineage` feature in the local
  source checked for this plan.
- Live GitHub blocker pass on 2026-04-30 showed open unstable upstream PRs:
  PR #342 `wave/W1/m01/p2.bundle-domain-migration`, PR #349
  `wave/W2/m04/p0.bundle-oracle-scaffold` (draft), PR #359
  `wave/W3/m08/p0.t1-open-audit-doc-and-snapshot-prereqs`, and PR #360
  `codex/m02-p5-closeout-bookkeeping`.
- Local `main` is divergent from `origin/main` with `git rev-list
  --left-right --count origin/main...HEAD` reporting `12 1`. Do not cut a W4
  implementation branch from this checkout until the orchestrator reconciles
  local and remote main.

## Inputs Read

- `.planning/trajectory-2/09-economic-layer-and-lineage.md`
- `.planning/trajectory-2/research/RESEARCH-M09.md`
- `.planning/trajectory-2/research/m09/P0-P1-PHASE-PLAN.md`
- `.planning/trajectory-2/tickets/M09/README.md`
- `.planning/trajectory-2/tickets/M09/P2.yml`
- `.planning/trajectory-2/tickets/M09/P3.yml`
- `.planning/trajectory-2/tickets/M09/P4.yml`
- `.planning/trajectory-2/tickets/M09/P5.yml`
- `.planning/trajectory-2/EXECUTION-STATE.json`
- `.planning/trajectory-2/EXECUTION-BOARD.md`
- `.planning/trajectory-2/WAVE-OPENER-STRATEGY.md`
- `.planning/trajectory-2/decisions.yml`
- `Cargo.toml`
- `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs`
- `crates/chio-store-sqlite/src/receipt_store.rs`
- `crates/chio-store-sqlite/src/receipt_store/support.rs`
- `crates/chio-store-sqlite/src/capability_lineage.rs`
- `crates/chio-otel-receipt-exporter/src/{lib,ingress,sink}.rs`
- `crates/chio-core-types/src/receipt.rs`
- `crates/chio-kernel/src/{checkpoint,evidence_export}.rs`
- `crates/chio-store-sqlite/src/evidence_export.rs`
- `crates/chio-anchor/src/lib.rs`
- `crates/chio-cli/src/{main,guard,reputation}.rs`
- `spec/PROTOCOL.md`

## Locked Decisions

- D21 remains binding: M09 activates existing economic crates as-is and adds no
  new economic primitives. P5 must not invent a new economics layer while
  adding lineage.
- D22 remains binding: `chio-lineage` is a SQLite-backed recursive-CTE indexer,
  not a graph database. `petgraph` is only an in-memory query or diff window.
- Protocol evidence classes are normative: `asserted`, `observed`, and
  `verified`. P5 must preserve those classes in schema, query output, CLI, and
  viewer JSON.
- Checkpoint and anchor language must stay bounded. Current checkpoint proofs
  support local audit and `transparency_preview` claims unless a qualified
  trust-anchor binding is present.

## Source Facts P5 Must Respect

- `chio_tool_receipts` is the immutable signed receipt store. Inserts use
  `ON CONFLICT(receipt_id) DO NOTHING`, and triggers reject update/delete.
- Existing receipt-store bootstrap already creates `request_lineage`,
  `receipt_lineage_statements`, `session_anchors`, `kernel_checkpoints`, and
  `capability_lineage`.
- `capability_lineage` already has a bounded recursive CTE for delegation
  chains with `level < 20`. P5 can reuse the pattern but must not reuse the
  exact truncation semantics blindly, because P5 needs explicit graph
  truncation markers in output.
- `receipt_lineage_statements` carries request, session, anchor, parent
  request, parent receipt, evidence class, evidence source JSON, verification
  booleans, and raw JSON. Treat this as the strongest existing receipt-to-
  receipt edge source.
- The OTEL receipt exporter produces canonical `ChioReceipt` values through
  `CanonicalChioReceipt`, validates span ids, strips denied attributes, and
  appends receipts through a `CanonicalReceiptSink`.
- Evidence export already bundles tool receipts, child receipts, capability
  lineage, checkpoints, inclusion proofs, uncheckpointed markers, and
  retention metadata. P5 lineage export should reuse those ids and classes
  instead of creating parallel proof truth.
- `ChioReceipt` already contains receipt id, timestamp, capability id, tool
  server, tool name, action, decision, content hash, policy hash, guard
  evidence, metadata, optional tenant id, kernel key, signing algorithm, and
  signature.
- `ReceiptLineageStatement` and `ChildRequestReceipt` already exist in
  `chio-core-types`. P5 schema should model them as first-class lineage
  artifacts.
- `chio-cli` already has split modules for larger command groups such as
  `guard` and `reputation`; P5 should follow that pattern with
  `crates/chio-cli/src/lineage.rs`.

## Dependency Gates Before Any P5 Branch

All gates below must be true before implementation begins.

1. W4 gate: W1, W2, and W3 are merged or explicitly waived by the
   orchestrator.
2. M09 phase gate: P0, P1, P2, P3, and P4 are merged, including
   `M09.P4.T7` market demo end-to-end.
3. Crate gate: `crates/chio-lineage/` exists, is a workspace member, and builds
   with no P5 behavior yet.
4. Feature gate: `crates/chio-store-sqlite` exposes the default-off `lineage`
   feature from P0/P1, and P5 keeps lineage query additions behind it where
   required by the ticket gate.
5. M04 gate: revocation oracle and deterministic corpus artifacts are merged
   and have stable file/schema locations for P5 ingest tests.
6. M06 gate: `CanonicalBytes` is available as the byte source for lineage
   frontier hashing.
7. M03 gate: hybrid signing backend is available for anchor pinning, or the
   P5 anchor command exits cleanly and records that signing is unavailable.
8. OTEL gate: trajectory-1 M10 `chio-otel-receipt-exporter` frame shape is
   still compatible with current `CanonicalChioReceipt`.
9. CLI gate: P4 market commands are merged so `arc lineage` can be added
   without rebasing over the same `main.rs` command enum.
10. Audit path gate: confirm whether the closing audit path remains
    `.planning/audits/M09-economic-layer-and-lineage.md`, since ticket owner
    globs point there while trajectory-2 audit files usually live under
    `.planning/trajectory-2/audits/`.
11. Branch hygiene gate: local main is reconciled with `origin/main`; no other
    worker owns P5 write paths.
12. Manifest/preflight gate:

```bash
cargo xtask trajectory regen-manifest --check
bash .planning/trajectory-2/scripts/validate-manifest.sh
bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh
```

## Future Implementation Write Set

This is the intended P5 write set after dependencies open. It is not touched by
this readiness task.

Core lineage crate:

- `crates/chio-lineage/src/lib.rs`
- `crates/chio-lineage/src/schema.rs`
- `crates/chio-lineage/src/ingest_otel.rs`
- `crates/chio-lineage/src/ingest_replay_corpus.rs`
- `crates/chio-lineage/src/query.rs`
- `crates/chio-lineage/src/diff.rs`
- `crates/chio-lineage/src/anchor.rs`
- `crates/chio-lineage/schemas/lineage-graph.v1.json`
- `crates/chio-lineage/tests/guard_version_diff.rs`
- `crates/chio-lineage/tests/anchor_pinning.rs`
- Additional focused `crates/chio-lineage/tests/*.rs` only when needed to
  cover whole-phase invariants.

SQLite query surface:

- `crates/chio-store-sqlite/src/lineage_cte.rs`
- `crates/chio-store-sqlite/src/lib.rs`
- Additive bootstrap exports only if needed to expose prepared CTE helpers.
  Do not alter existing receipt immutability triggers.

CLI:

- `crates/chio-cli/src/lineage.rs`
- `crates/chio-cli/src/main.rs`

Static viewer:

- `docs/demo/lineage/index.html`
- `docs/demo/lineage/lineage.css`
- `docs/demo/lineage/lineage.js`
- `docs/demo/lineage/README.md`

Audit closeout:

- `.planning/audits/M09-economic-layer-and-lineage.md`

Do not include these in the P5 write set unless a dependency gate is formally
re-scoped:

- `Cargo.toml`
- `Cargo.lock`
- ticket files
- `.planning/trajectory-2/EXECUTION-STATE.json`
- `.planning/trajectory-2/EXECUTION-LOG.ndjson`
- unrelated crates

## DAG Schema Plan

`lineage-graph.v1.json` should describe the JSON dump consumed by the CLI and
static viewer. It should be stable enough that a dumped graph from one version
can be loaded by a later viewer without changing evidence class semantics.

Top-level shape:

```json
{
  "schema": "chio.lineage_graph.v1",
  "generated_at": 0,
  "query": {},
  "root": "node-id",
  "nodes": [],
  "edges": [],
  "truncation": [],
  "warnings": []
}
```

Required node kinds:

- `prompt`: request prompt or prompt fingerprint, never raw sensitive prompt
  text by default.
- `request`: `request_lineage` row keyed by session id and request id.
- `capability`: `capability_lineage` row keyed by capability id.
- `guard`: guard verdict and guard evidence from receipt decision metadata.
- `tool_call`: tool server, tool name, action, and policy/content hashes.
- `receipt`: signed `ChioReceipt` row from `chio_tool_receipts`.
- `child_receipt`: signed `ChildRequestReceipt` when present.
- `receipt_lineage_statement`: signed receipt lineage statement when present.
- `session_anchor`: `chio.session_anchor.v1` source.
- `checkpoint`: kernel checkpoint or inclusion proof source.
- `anchor`: P5 lineage frontier pinning record.
- `truncation_marker`: explicit query-depth boundary.

Required edge kinds:

- `prompt_to_request`
- `request_parent`
- `request_to_capability`
- `capability_parent`
- `capability_to_receipt`
- `receipt_to_guard`
- `receipt_to_tool_call`
- `receipt_parent`
- `receipt_to_checkpoint`
- `checkpoint_to_anchor`
- `receipt_to_lineage_statement`
- `lineage_statement_to_parent_receipt`

Every node and edge must carry:

- stable id
- kind
- evidence_class: `asserted`, `observed`, or `verified`
- source_table or source_artifact
- source_id
- optional `json_sha256`
- optional `canonical_sha256`
- optional `redaction` metadata

The truncation marker is pinned by the ticket and must be emitted exactly in
place of a deeper subtree when a recursive query exceeds its bound:

```json
{"truncated": true, "depth_reached": 20, "limit": 20}
```

Schema invariants:

- Missing receipt-lineage statements do not upgrade asserted caller context to
  verified truth.
- Raw prompt text is optional and disabled by default. Prompt fingerprints are
  preferred in CLI and viewer examples.
- Receipt ids and capability ids remain source ids, not rewritten graph-local
  ids. Graph-local ids may wrap them but must preserve source ids.
- Canonical hashes use `CanonicalBytes` where available.
- Unknown future node kinds must fail closed in Rust parsing unless the caller
  explicitly opts into permissive display mode for the viewer.

## OTEL Ingest Plan

`ingest_otel.rs` should ingest the trajectory-1 M10 OTEL receipt stream by
consuming canonical receipt frames, not by reparsing arbitrary span attributes
as proof.

Implementation shape:

1. Define an input enum for `CanonicalChioReceipt`, raw NDJSON `ChioReceipt`,
   and file path inputs used by CLI tests.
2. Validate schema/version markers before insertion. Reject unknown schema
   versions unless a test fixture explicitly asks for permissive parsing.
3. Convert each receipt to a lineage receipt node plus guard/tool/capability
   edges.
4. Use receipt id as the idempotency key. A repeated OTEL frame with identical
   canonical bytes is a no-op; same receipt id with different canonical hash is
   a conflict.
5. Preserve denied attribute stripping from the exporter. Do not use stripped
   attributes as lineage truth.
6. Attach `observed` evidence class for local receipt rows and `verified` only
   when the signed receipt or lineage statement verifies.

Tests:

- identical NDJSON replay is idempotent
- same receipt id with different canonical bytes fails
- unknown schema version rejects
- deny verdict still creates a receipt node but does not imply tool execution
- tenant id from receipt is preserved

## M04 Corpus Ingest Plan

`ingest_replay_corpus.rs` should reconstruct offline lineage from the M04
deterministic corpus without inventing runtime facts.

Implementation shape:

1. Read M04 corpus manifest and receipt artifacts from the finalized M04 path.
   Do not hard-code the path until M04 closes.
2. Import receipts, request lineage records, receipt lineage statements,
   capability snapshots, revocation roots, and checkpoint artifacts if present.
3. Mark corpus facts as `verified` only if their signed artifact verifies or
   the corpus manifest hash verifies under the M04 published root. Otherwise
   use `observed` or `asserted` according to source.
4. Preserve revocation epoch and publisher credential ids for later diff mode.
5. Emit a deterministic import summary with counts for receipts, request nodes,
   receipt-lineage edges, capability edges, revoked publishers, and rejected
   frames.

Tests:

- offline corpus import produces stable node and edge counts
- revoked publisher input is represented as a lineage fact and diff input
- malformed corpus artifact fails closed
- missing optional checkpoint creates an unanchored warning, not a fake proof

## Recursive CTE Query Plan

`lineage_cte.rs` in `chio-store-sqlite` should own SQL-heavy traversal, while
`chio-lineage/src/query.rs` should own Rust query API, output shaping, and
schema conversion.

Query modes:

- forward from prompt/request/capability/receipt root
- reverse from tool call, guard verdict, receipt, checkpoint, or anchor root
- roots: list lineage graph roots by time window, tenant, capability, tool, or
  checkpoint coverage
- bounded neighborhood: both directions within a max depth

SQL design:

- Use `WITH RECURSIVE` over existing tables: `request_lineage`,
  `receipt_lineage_statements`, `chio_tool_receipts`, `capability_lineage`,
  `kernel_checkpoints`, and any additive P5 lineage index tables created by
  P0/P5.
- Track `(node_kind, source_id, depth, path)` to avoid cycles.
- Enforce a hard depth limit in SQL and re-check in Rust.
- Return an explicit truncation row when more rows exist beyond the limit.
- Keep ordering deterministic: root first, depth ascending, then node kind,
  then source id.
- Avoid recursive scans over raw JSON when indexed columns already exist.

Suggested Rust API:

```rust
pub struct LineageQuery {
    pub root: LineageRoot,
    pub direction: LineageDirection,
    pub max_depth: u16,
    pub tenant_id: Option<String>,
    pub include_asserted: bool,
}

pub enum LineageDirection {
    Forward,
    Reverse,
    Neighborhood,
}
```

Query invariants:

- Default max depth is bounded. Recommended default is 20 to align with the
  existing capability chain guard.
- User-supplied max depth above the hard cap fails unless a future explicit
  admin flag is introduced.
- Reverse queries never imply causality when only a time-window child receipt
  context exists.
- Query output must show uncheckpointed receipt markers as unanchored, not as
  anchor failures.

## Differential Mode Plan

`diff.rs` compares lineage roots across two guard versions or two corpus roots.
The purpose is to answer "what changed in the provenance graph when a guard
version or publisher state changed?"

Inputs:

- left root id and right root id
- optional left/right guard package refs
- optional guard publisher credential ids
- optional revocation epoch from M04
- optional time window or tenant scope

Output:

- added nodes
- removed nodes
- changed nodes by canonical hash
- added edges
- removed edges
- evidence class changes
- guard verdict changes
- anchor/checkpoint coverage changes
- publisher revocation impacts

Diff invariants:

- Diff keys are stable source ids plus node kind, not array indexes.
- Redacted fields do not produce false changes. Compare canonical redacted
  forms when redaction is active.
- Evidence class upgrades and downgrades are first-class changes.
- A missing stronger proof form is not equivalent to a verified negative.
- Revoked guard publisher state from M04 must be visible in output when it
  changes path eligibility.

Tests:

- same graph diff is empty
- guard version change with identical receipts only changes guard package refs
- revoked publisher changes eligibility and is reported
- asserted-to-verified upgrade is reported even when receipt ids match

## Anchor Pinning Plan

`anchor.rs` should hash the lineage frontier through canonical bytes and use
the M03 hybrid signing backend when present.

Frontier input:

- graph schema id
- root id
- sorted node canonical hashes
- sorted edge canonical hashes
- query parameters
- truncation markers
- checkpoint ids or uncheckpointed markers

Pinning behavior:

1. Build canonical frontier payload with `CanonicalBytes`.
2. Hash the payload with SHA-256 or the repo-standard hash wrapper.
3. If M03 hybrid backend is present, sign the frontier statement.
4. If signing is unavailable, return a structured skipped result and non-zero
   only when the caller requested `--require-signature`.
5. Persist or emit the anchor proof without mutating source receipts,
   checkpoints, or existing anchor records.

Anchor invariants:

- Anchor pinning is over the lineage frontier, not over raw arbitrary JSON.
- Truncated queries can be pinned only if truncation markers are included in
  the payload.
- An anchored lineage root does not upgrade unverified upstream facts. It only
  proves this graph output existed with these evidence classes.
- M10 P5 model-card anchoring consumes this surface, so output schema and
  verification errors must be stable before P5 closes.

## CLI Plan

Add `arc lineage {query,diff,roots}` in `crates/chio-cli/src/lineage.rs` and
wire it through `main.rs`.

Commands:

```text
arc lineage query --receipt-db <path> --root <id> [--forward|--reverse|--neighborhood] [--max-depth N] [--json-out <path>]
arc lineage diff --receipt-db <path> --left <id> --right <id> [--guard-left <ref>] [--guard-right <ref>] [--json-out <path>]
arc lineage roots --receipt-db <path> [--tenant <id>] [--tool <server/name>] [--from <ts>] [--to <ts>] [--json-out <path>]
```

CLI behavior:

- Default output is compact human text with evidence class labels.
- `--json-out` writes `chio.lineage_graph.v1`.
- Raw prompt text is hidden unless a future explicit unsafe/debug flag is
  introduced.
- Unknown roots return a typed lineage-domain error.
- Depth overflow returns graph output with truncation markers, not a panic.
- `--require-anchor` or `--pin` must fail cleanly if the signing backend is not
  available.

## Static Viewer Plan

The viewer lives under `docs/demo/lineage/` and has no build step.

Files:

- `index.html`
- `lineage.css`
- `lineage.js`
- `README.md`

Constraints:

- Plain HTML, CSS, and JavaScript.
- No import map.
- No transpiler.
- No CDN requirement.
- Load JavaScript with:

```html
<script type="module" src="./lineage.js"></script>
```

Viewer behavior:

- Load a local JSON dump produced by `arc lineage query`.
- Render nodes and edges with stable colors by evidence class.
- Highlight truncation markers.
- Show anchor/checkpoint status without claiming public append-only proof.
- Provide search by receipt id, capability id, tool name, and guard id.
- Work from `file://` for local demo and from static docs hosting.

Viewer invariants:

- It is a viewer only. It must not verify signatures or recalculate trust.
- It must not contact remote services.
- It must not show raw prompt text by default.
- It must tolerate unknown future node kinds by displaying them as unknown,
  while Rust parsing remains stricter.

## Commit Order Inside One Phase Branch

Keep commits reviewable but land them through one phase branch and one PR after
all local gates pass.

1. `feat(m09): define lineage graph schema`
   - Adds schema module and JSON schema.
   - Pins node, edge, evidence class, and truncation marker shapes.
2. `feat(m09): ingest otel receipt lineage frames`
   - Adds OTEL ingest and idempotency tests.
3. `feat(m09): ingest m04 replay corpus lineage`
   - Adds offline corpus ingest after M04 artifact paths are confirmed.
4. `feat(m09): add sqlite recursive lineage queries`
   - Adds `lineage_cte.rs`, query API, depth caps, and truncation behavior.
5. `feat(m09): add lineage diff mode`
   - Adds guard-version and corpus-root diff.
6. `feat(m09): pin lineage frontier anchors`
   - Adds canonical frontier hashing and hybrid signing integration or clean
     skipped behavior.
7. `feat(cli): add arc lineage commands`
   - Adds `query`, `diff`, and `roots` CLI commands.
8. `docs(m09): add static lineage viewer`
   - Adds no-build viewer and README.
9. `docs(m09): close lineage audit counts`
   - Updates M09 audit with closing counts for lineage LOC, recursive CTE
     count, anchored roots, and marketplace manifests.

## Whole-Phase Invariants

- No implementation before W4 and P0-P4 gates open.
- No ticket-grain branches or PRs for P5.
- SQLite remains the persistent store. No graph database.
- Existing signed receipts remain immutable.
- Existing receipt bytes, checkpoint leaves, and claim-log projections are not
  rewritten.
- All ingestion is idempotent by receipt id and canonical hash.
- Same receipt id with different canonical bytes is a conflict.
- Evidence classes are preserved and never silently upgraded.
- Recursive queries are bounded and emit explicit truncation markers.
- Diff output is deterministic across runs.
- Anchor pinning signs the canonical lineage frontier only.
- Static viewer is no-build and offline-capable.
- CLI defaults avoid raw prompt disclosure.
- M10 P5 can consume P5 anchor proofs without schema churn.

## Pre-PR Gates For The Eventual P5 Branch

Run narrow gates as commits land, then run the whole-phase gate set before one
P5 PR.

```bash
cargo test -p chio-lineage --quiet
cargo clippy -p chio-lineage -- -D warnings
test -f crates/chio-lineage/schemas/lineage-graph.v1.json
cargo test -p chio-store-sqlite --features lineage --quiet
cargo test -p chio-lineage --test guard_version_diff
cargo test -p chio-lineage --test anchor_pinning
cargo build -p chio-cli --quiet
cargo test -p chio-cli --quiet
test -f docs/demo/lineage/index.html
test -f docs/demo/lineage/lineage.css
test -f docs/demo/lineage/lineage.js
test -f docs/demo/lineage/README.md
grep -q 'closing counts' .planning/audits/M09-economic-layer-and-lineage.md
grep -q 'anchored roots' .planning/audits/M09-economic-layer-and-lineage.md
cargo fmt --all -- --check
git diff --check
cargo xtask trajectory regen-manifest --check
bash .planning/trajectory-2/scripts/validate-manifest.sh
bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh
```

If process limits or Cargo lock contention appear, run these serially with the
warmed target directory. Do not start parallel verification that competes with
other active workers.

## Open Questions For Implementation Day

- What exact M04 corpus paths and schema names are final after M04 closes?
- Does P0/P1 create only a skeletal `chio-lineage`, or does it already expose
  shared error and config types P5 should reuse?
- Does P4 marketplace output include guard publisher credential ids in a form
  P5 diff can consume directly?
- Should P5 persist lineage index rows, or should it build graph output purely
  from existing receipt-store tables and only keep per-query in-memory
  `petgraph` windows?
- Is `.planning/audits/M09-economic-layer-and-lineage.md` the final audit path,
  or should the ticket owner glob be corrected before P5 opens?
