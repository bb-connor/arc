# chio-trace-validate architecture

## Responsibility and boundary

The crate owns signed observation capture, authenticated decoding, revocation
projection, checker invocation, and trace-validation reports.
`ObservationBody`, `ObservationEvent`, and `SignedObservation` describe
revocation commits and evaluated requests with signed receipts.
`ValidatedTrace` retains authenticated observations and the input digest.
`RevocationProjection` exposes model events, coverage, bounds, and ITF bytes.

The implemented model scope is `RevocationPropagation`.
Caller-supplied trusted observer keys authenticate the observation stream.
Capture provenance and observer custody remain caller responsibilities;
signed observations do not establish that every deployment was instrumented.

## Structure

| Module | Responsibility |
|--------|----------------|
| `observation` | Body validation and observer signing/verification. |
| `capture` | `RuntimeTraceRecorder` implementation of kernel callbacks. |
| `decode` | Canonical NDJSON decoding and `ValidatedTrace`. |
| `intern` | Deterministic bounded authority and capability indexes. |
| `map::revocation` | Receipt verification, model events, and coverage. |
| `itf` | Explicit states, synthetic transitions, and typed ITF encoding. |
| `apalache` | Pinned checker protocol and witness validation. |
| `report` | Status, divergence details, and evidence digests. |
| `lib` | File validation, stable reads, and artifact writes. |
| `main` | CLI arguments, report output, and failure exit handling. |

There are no declared Cargo features. Both library and binary targets are
unpublished workspace tooling.

## Data and control flow

`RuntimeTraceRecorder` pairs admission callbacks with receipt appends by the
signed request ID and requires matching capability IDs. `finish` consumes its
single finalization opportunity, rejects incomplete callback accounting,
sorts events by kernel source sequence, and signs the resulting observations.
It rejects revocation of a checked capability or ancestor between admitted
evaluation and receipt append. Hidden mutation modes calibrate negative traces
for duplicate receipt times, excessive depth, and future revocation epochs.

`decode_observations` checks each record and the complete log.
`project_revocation_trace` verifies embedded receipts and converts authority
and capability identifiers into model indexes. A seen ancestor revocation
projects onto that exact source capability. ITF construction adds attenuation
and propagation states where required by the projected model.
Receipt time in the projection is a calibrated model value carried by the
observer. The embedded signed receipt also retains its wall-clock timestamp.

`validate_file` reads a stable input, decodes, projects, checks requested action
floors, and requires all four invariant witness classes. It optionally writes
the ITF, evaluates invariants using Apalache, and retains the evaluation witness.
If invariant evaluation passes, it checks full-prefix reachability.
For an unreachable trace, binary prefix search locates the first divergence.

`validate_projection_with` performs that reachability search using any
`ReachabilityOracle`. It omits the file validator's action floors, witness
requirements, and separate invariant evaluation. Its reports list the model
invariants but initially have empty checker-binary and evaluation-witness
digests; `validate_file` binds those fields after real invariant evaluation.

## Trust and invariants

Observation bodies reject unknown fields, invalid schema, malformed identifiers,
zero sequence values, and invalid declared bounds. Evaluation subjects must
be unique, begin with the receipt capability, and match the declared depth.
The source must belong to that lineage and exist exactly when the seen epoch
is nonzero. Rejected admission requires a source and a deny receipt.

The decoder accepts at most 64 MiB and 500 visible events.
Visible source sequences must increase, admission sequences must precede their
appends, and their combined unique count must match the runtime event count.
`Interner` limits each identifier class to 64 values.
Projection verifies the receipt kernel key, signature, action hash, and decision;
seen epochs must refer to previously observed revocations.

`ApalacheOracle::new` requires version 0.50.1 and a positive timeout.
It hashes the resolved checker and timeout executables and checks them around
each invocation. The protocol requires exact exit/output combinations and
validates witness structure, state correspondence, types, and Boolean results.
Reachability is witnessed by the deliberate `TraceNotAccepted` counterexample;
an ordinary checker success means that prefix was unreachable.

Input reads reject symlink components and use `O_NOFOLLOW` on Unix.
Reads are limited to 64 MiB plus one byte and compare file metadata afterward.
Artifact writes reject symlinks, sync a temporary file, and persist it.
These checks do not lock the filesystem against concurrent writers.
Reports bind log, observer set, models, ITF, checker executables, and witness
digests for the full file path. Reports themselves are unsigned JSON.

## Dependencies

`chio-core-types` supplies signatures, canonical JSON, receipts, and hashing.
`chio-kernel` supplies runtime observation callbacks.
`serde` and `serde_json` handle observation, ITF, and report data; `thiserror`
defines `TraceError`. `clap` supplies CLI parsing and `tempfile` isolates
checker runs and output writes. Unix `libc` supplies `O_NOFOLLOW`.
The three TLA+ model sources are embedded from the repository at compile time.

## Verification

The integration tests cover canonical decoding, tampering, ordering, lineage
source rules, deterministic projection, callback capture, artifact symlinks,
and first-divergence reporting. Checked-fixture tests compare retained traces
with deterministic builders. Apalache protocol tests use stub executables to
exercise accepted results and incomplete witness rejection.
Unit tests cover bounded file reads, exact checker markers, and duplicate-key
ITF rejection. Run `cargo test -p chio-trace-validate` for these tests.

[check-receipt-trace.sh](../../../scripts/check-receipt-trace.sh) runs the
real checker lane with retained artifacts. Real model execution and its bound
evidence are required when assessing model-validation claims for a candidate.
