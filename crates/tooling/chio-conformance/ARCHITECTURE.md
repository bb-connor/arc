# chio-conformance architecture

## Responsibility and boundary

The public surface combines fixture loading, compatibility rendering, peer
lockfile handling, native fixtures, and cross-language orchestration.
`ScenarioDescriptor` describes expected coverage; `ScenarioResult` records
one peer, deployment mode, transport, and outcome. `CompatibilityReport`
collects both lists for Markdown rendering.

The crate owns test inputs and test artifacts. Kernel authorization,
cryptographic verification, persistence, and tool isolation come from the
Chio implementations exercised by a particular suite. A recorded pass alone
carries no authenticated proof of the process that produced it.

## Structure

- `load.rs` recursively collects JSON files and deserializes scenarios/results.
- `model.rs` defines categories, transport/deployment labels, and result states.
- `report.rs` groups results into compatibility columns and failure sections.
- `peers.rs` parses, validates, selects, and partitions peer lock entries.
- `runner.rs` provisions native MCP security, starts an HTTP edge, and runs peers.
- `runner/native_launch.rs` reads explicit cage paths, grants, and execution IDs.
- `native_suite.rs` dispatches artifact, stdio, and HTTP fixture drivers and
  captures signed runtime revocation traces.
- `econsim.rs` validates and signs typed economic simulation matrices.
- `fuzz.rs` exposes a lockfile parser/query target behind the `fuzz` feature.
- `src/bin/` contains report, cross-language, native runner, native fixture,
  and economic simulation entrypoints.
- `verdict_matrix/` carries a separate tuple corpus, oracle, and driver registry.

## Data and control flow

The offline loaders walk a directory tree in sorted file order.
Scenario loading requires at least one JSON descriptor and sorts by ID.
Result loading first tries an array, then a single record, and sorts by
scenario ID, peer, deployment mode, and transport.
The renderer derives columns from results and places them under scenario
categories. Duplicate records for the same displayed column resolve through
a map insertion; callers must curate their input corpus.

`run_conformance_harness` validates credentials and cage configuration,
replaces its results directory, locates or builds the Chio executable,
provisions the wrapped mock upstream, and starts the remote edge.
It runs selected peer processes sequentially, reloads their result files,
requires nonempty results, and writes the Markdown report.

The native suite selects a driver for each descriptor and compares fixture
responses or artifacts against assertion specifications. Its runtime trace
capture uses a real kernel and SQLite revocation state; artifact fixtures
also contain deterministic keys and synthetic messages.

## Trust and invariants

Directory walkers reject symlinked roots and encountered symlinks.
They use ordinary filesystem reads after traversal and have no input byte
ceiling or atomic snapshot guarantee. Typed deserialization checks the JSON
shape; imported results remain caller-supplied evidence.

`PeersLock::load` and `parse_str` only parse. `validate` separately enforces
schema and entry constraints. The HTTPS check is a string-prefix check;
artifact digest verification belongs to the consuming download path.
Checkout discovery validates an absolute root, workspace membership,
package identity, and repository fixture layout. An invalid explicit
`CHIO_CHECKOUT_ROOT` prevents fallback discovery of another checkout.

The `in-repo-fixtures` feature is declared but currently has no source gate.
Runtime checkout discovery and packaged-fixture fallback determine defaults.
`econsim` validators check case consistency, coverage, and provenance fields;
signing rejects missing targets and unresolved high or critical findings.
Provenance fields must be nonempty; library validation does not prove their truth.

## Dependencies

`chio-core-types` supplies native wire and signed artifact types.
`chio-kernel` and `chio-store-sqlite` support real runtime trace capture;
`chio-trace-validate` projects trace artifacts into validator inputs.
`serde_json` and `toml` decode fixtures and peer locks.
`reqwest` and `tiny_http` support local HTTP fixture traffic.
`tempfile` holds temporary runtime state.
Optional `chio-selective-disclosure` and `chio-workflow` support BBS tests.
The larger dev-dependency graph exposes production crates to regression tests.

## Verification

Loader tests cover empty/missing directories, JSON records, and symlink refusal.
Report tests cover category grouping and expected-failure rendering.
Peer tests cover validation, filtering, partitioning, and checkout discovery.
Native tests exercise signed nonvacuous traces, dropped admission callbacks,
revocation retention, trace mutations, and fixture metadata.
The deployment-shape smoke target checks registry metadata and source presence;
it does not invoke a Lambda deployment.

Run `cargo test -p chio-conformance --lib` for library checks and
`cargo test -p chio-conformance --test deployment_shape_smoke` for registration.
Set `CHIO_CHECKOUT_ROOT` to this checkout when using an external target directory.
Live cross-language execution additionally requires peer SDKs and reviewed cage
configuration; its result artifacts identify the peers and surfaces exercised.
