# chio-quarantine architecture

## Responsibility and boundary

The crate owns bounded temporal-rule loading and orchestration of correlation,
response approval, state changes, scheduling, apply, and rollback. It re-exports
the pure response model while attaching stores and effect ports.
`TemporalCorrelator` consumes verified events; `ResponseExecutor` consumes
scheduled work and retained response records.

Authoritative event admission, durable response transactions, host enforcement,
receipt persistence, and alert delivery come from injected ports. This crate
contains no concrete security-event database or operating-system effect adapter.
A parsed rule or constructed response plan carries no live execution authority.
Callers establish producer authenticity before supplying verification records.

## Structure

- `rules.rs` validates temporal stages, group keys, timing, bounds, and hashes.
- `correlation.rs` partitions event histories, advances watermarks, journals
  outcomes, creates findings, and emits detector-health evidence.
- `blast.rs` resolves causal lineage and validates exact affected sets and fences.
- `approval.rs` validates governed requests and reservation lifecycles.
- `state_machine.rs` stores projections from `chio-response-model` with CAS.
- `scheduler.rs` claims work, validates leases, renews fences, and handles retries.
- `executor.rs` and its effect-journal include implement effect execution and
  recovery; `executor_proof.rs` checks retained dispatch and execution evidence.
- `native_receipts.rs` constructs receipt material. `fuzz.rs` is exposed for tests or the `fuzz` feature.

## Data and control flow

`TemporalRule::parse_json` decodes at most 1 MiB with the strict signed-JSON
reader. Rules use one of five grouping keys. The first stage has no predecessor
or window; each later stage names an earlier stage and a positive bounded window.
The canonical document produces a domain-separated rule-version hash.

`TemporalCorrelator::ingest` validates the event and producer trust class, checks
policy version, and chooses a tenant/rule/group partition. Store admission,
event indexing, and outcome publication preserve replay identities. Event time
and bounded lateness drive watermarks; idle-watermark observations can finalize
a deferred tail. Corruption and resource exhaustion produce detector-health
outcomes with automatic response suppression.

`CausalBlastRadiusResolver` obtains bounded lineage evidence and checks affected
set hashes, commit completeness, approved expiry, and scheduler fencing before
accepting a causal fence. Failure to establish an exact result prevents its
use as an approved scope.

Governed responses pass through approval prepare, reconstruct, commit, and
cancel. Reconstruction must reproduce the retained reservation exactly.
`ResponseStateMachine::create` accepts `FreshLiveAdmission` and stores the
initial projection. State and effect mutations use generation-aware store CAS.

`ResponseScheduler::claim` observes the clock and asks the store for a bounded
ordered batch with leases. `process` validates work before passing it to the
executor. `ResponseExecutor::execute` requires live execution, validates work,
reconciles receipts and durable effects, and advances apply or rollback progress.
Journals retain requested, applied, failed, rollback-requested, restored, and
rollback-failed phases so a retry can reconcile an interrupted operation.

## Trust and invariants

Default rule limits permit 32 stages, a 24-hour stage window, 1,024 groups,
and 65,536 estimated state entries. The estimate multiplies groups, partial
matches, and stages with checked arithmetic. Unknown document fields and invalid
stage references reject during loading.

Correlation checks the canonical body hash, identities, trust class, and time
fields against `SecurityEventVerificationRecord`. Internal detectors are permitted; verified receipt
producers require an explicit policy switch. Health and advisory outcomes carry
suppression state so unavailable evidence cannot silently authorize response.

Governed approval checks plan/request/reservation identity and hashes before
calling the authority port. Fresh dispatch and execution require live mode;
simulation models dry-run overlays without calling live effect ports.
Scheduling uses owner identity, expiry, fencing tokens, and store-owned leases.
Effect journals and receipts expose ambiguous failures for recovery and rollback.
The supplied stores and ports must honor idempotency and atomic commit contracts.

## Dependencies

`chio-response-model` supplies pure projections, authorization validation, and
simulation. `chio-security-types` supplies findings, plans, evidence, and port
contracts. `chio-core-types` supplies canonical JSON and hashes. `serde` and
`serde_json` encode retained state; `thiserror` describes typed failures and
`tracing` records orchestration events. Tests use kernel fixtures and `proptest`.

## Verification

`tests/rules.rs` exercises graph and bound rejection. Correlation tests cover
lateness permutations, partition isolation, restart replay, outcome journals,
and capacity suppression using fixture stores. Response tests cover approval
binding, live-mode rejection, leases, effect recovery, rollback budgets, and
snapshot simulation. Run `cargo test -p chio-quarantine` for these suites;
`cargo test -p chio-quarantine --features fuzz` also exposes harness support.
The README sample parses and canonicalizes a rule without applying it.

[README](README.md) | [Decoy](../chio-decoy/README.md)
