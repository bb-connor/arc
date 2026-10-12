# chio-runtime-harness architecture

## Responsibility and boundary

The harness executes local runtime scenarios and assembles proof-regeneration output.
Its public entrypoints accept paths, evaluation time, and optional static baseline JSON.
`RuntimeLoopbackError` wraps parsing, filesystem, runtime, and verification failures.
The native kernel still owns capability admission, effects, and signed receipts.
The harness owns deterministic fixture composition and output manifests.
Fixture evidence and artificial authority identities define its test-support boundary.

## Structure

- `lib.rs` loads baselines, qualifies the platform, and creates stores.
- `scenario.rs` parses and normalizes scenario steps.
- `kernel.rs` constructs the local kernel and fixture tool connection.
- `admission_loop.rs` evaluates runtime admission and invokes local tool calls.
- `treaty.rs` constructs signed treaty context for the fixture.
- `buyer_closure.rs` prepares buyer-side closure evidence.
- `proof_assembly.rs` binds runtime outputs to proof artifacts.
- `proof_parity.rs` compares regenerated evidence with the static baseline.
- `evidence_io.rs` validates paths, writes files, and computes artifact hashes.

## Data and control flow

`run_runtime_loopback_scenario` loads built-in proof and verifier fixtures.
`run_runtime_loopback_scenario_with_static_artifacts` parses caller baselines first.
Both delegate to one baseline runner.
A process-local mutex serializes runs that use the artificial authority identity.
Scenario normalization precedes store and output directory creation.
The runner checks that SQLite authority serving is supported on this platform.
It prepares private store directories and provisions a SQLite authority.
It opens the receipt store and waits for the writer's durable head verification.
The admission loop inserts each step's bundle and prepares signed policy inputs.
Runtime admission produces reports; local kernel execution produces live receipts.
Assembly combines those receipts, treaty evidence, buyer closure, and baseline proofs.
The result includes workflow reports, proof-regeneration artifacts, and an evidence manifest.

## Trust and invariants

Malformed baseline JSON fails before the runner opens scenario or output paths.
The supported-platform check precedes authority provisioning.
Unix store directories receive mode 0700.
Successful receipt startup is required before evaluation begins.
`validate_runtime_relative_path` rejects absolute paths, traversal components,
backslashes, colons, repeated separators, and surrounding whitespace.
`write_runtime_json_artifact_string` adds a newline, hashes the actual bytes,
and records the byte count alongside each relative evidence path.
Canonical hashes identify structured runtime artifacts separately from file hashes.
Step admission binding validates counts and exact indexes.
Baseline parity checks reject regenerated package drift.
A rejected run may already have emitted evidence files and failure reports.
These checks support reproducible local evidence; operators supply deployment trust.

## Dependencies

`chio-runtime-core` supplies admission, policy, and proof report structures.
`chio-kernel` mediates local tool effects.
`chio-store-sqlite` supplies authority and receipt persistence.
`chio-attest-loopback` supplies fixture baselines.
`chio-attest-buyer-core` parses and verifies buyer-facing evidence.
`chio-federation` supplies treaty artifacts; Tokio drives local asynchronous execution.

## Verification

Unit tests in `lib.rs` cover startup rejection before path mutation,
step-binding cardinality and exact indexing, and report-hash preservation.
They also check native output schemas, static-package drift rejection,
and semantic determinism of regenerated proof packages.
Run `cargo test -p chio-runtime-harness` from the workspace root.
Successful scenarios create local stores and evidence files.
The README sample only exercises malformed-baseline parsing and creates no files.
Platform-dependent authority support is checked at runtime.
