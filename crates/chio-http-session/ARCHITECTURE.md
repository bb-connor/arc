# chio-http-session Architecture

## Boundary

`chio-http-session` owns the per-session journal shared by session-aware guards.
It is not an HTTP transport implementation. Its responsibility is to provide an
append-only, hash-chained record of tool invocations plus cumulative guard state
for data-flow, behavioral-sequence, and advisory checks.

The crate depends only on serialization, hashing, hex encoding, and error
types. Downstream crates such as `chio-guards` depend on it for session history
without reaching into kernel or transport internals.

## Module Boundaries

- `JournalEntry` is the persisted/auditable entry shape.
- `RecordParams` is the append input boundary used by callers.
- `CumulativeDataFlow` is the running data-flow summary used by guards.
- `SessionJournal` owns synchronization, append-only mutation, hash-chain
  construction, and read APIs.
- `SessionJournalError` is the fail-closed error surface for poisoned locks,
  invalid record fields, and integrity violations.

The crate is currently a compact single-file crate. Splitting files is not
useful until additional journal backends or persistence boundaries exist.

## Pain Points

- Guard-facing state was exposed through several independent getters:
  `data_flow()`, `tool_sequence()`, and `tool_counts()`.
- Each getter acquires the journal lock separately. A guard that reads more than
  one view can combine state from different instants if another thread records
  an invocation between calls.
- `AnomalyAdvisoryGuard` needs both invocation counts and maximum delegation
  depth, so it was the clearest downstream consumer of an inconsistent read
  boundary.

## Security And API Constraints

- The journal must remain append-only.
- Hash-chain semantics and the documented entry hash field order must not
  change in this slice.
- Denied invocations must continue contributing to invocation totals and tool
  sequences.
- Cumulative byte counters must keep saturating arithmetic.
- Public compatibility must be preserved. Existing getters remain available.
- Lock poisoning must continue to fail closed.

## Affected Dependents

Direct dependents include `chio-guards` and conformance tests that seed
session journals for cumulative exfiltration and behavioral sequence coverage.
This slice keeps the existing public API and adds a coherent snapshot API.
`chio-guards` can then read one snapshot per evaluation instead of stitching
together multiple independently locked views.

## Planned Improvement

Add `SessionJournalSnapshot`, an immutable guard-read model captured under one
journal lock. Use it in `chio-guards` session-aware guards so each evaluation
observes one coherent view of cumulative data flow, tool sequence, tool counts,
entry count, and journal head hash.

The change is architectural because it introduces a real read boundary for
session guard state. It reduces downstream coupling to individual journal
indexes while preserving the existing append and hash-chain contracts.
