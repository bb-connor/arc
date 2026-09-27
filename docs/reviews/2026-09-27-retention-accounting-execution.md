# Retention and accounting execution

Packet 3 implementation starts from `4c35ce7867` on
`packet/3-retention-accounting`, with one implementer and focused owning checks.
This checkpoint does not close the historical retention hang or qualify the
million-entry append and history-recovery campaigns.

## Changes

- Retention has a configurable caller deadline (`RetentionConfig.rotation_timeout`,
  default 300 seconds) covering queueing and response wait. Zero or unrepresentable
  deadlines reject before admission. Timeout does not cancel accepted work: the
  writer keeps its in-flight ownership, reports the unresolved timeout through
  liveness, and clears it on completion. Retrying the same cutoff after completion
  observes the durable watermark. SQLite I/O itself is not preempted.
- Full-verification writer-routed receipt writes validated the claim log by
  opening a second transaction inside the actor's existing IMMEDIATE transaction.
  Valid indexed appends failed with `cannot start a transaction within a
  transaction`. The actor now uses the existing transaction-aware validator,
  retaining both the full audit and its original snapshot.
- Archives install and validate the canonical immutable security-evidence index,
  including both update/delete guards. Previously archive creation copied only
  the table, leaving the logical identity mutable. A substituted guard with the
  expected name now rejects before payload copy or watermark advancement.
- Charged and attempted cost attribution totals, including root/leaf totals,
  and per-currency underwriting premium totals use checked addition. A sum beyond
  `u64::MAX` returns a named error instead of a successful clamped report. The
  signed evidence remains intact. This does not redesign currency grouping.

## Owning coverage

The timeout regression gates the actual writer with channels, enqueues a public
rotation, observes its timeout and retained ownership, then releases the writer.
It requires exactly one archived prefix, a healthy drained writer and a no-op
retry. The invalid-deadline regression requires no accepted command or archive.
The existing SQLite write-lock test still checks a rotation already in progress.

Signed flow-denial evidence exercises exact logical-ID lookup and replay before
and after retention, live restart, archive reopen and schema-v5 migration to the
current v6 schema. Both verification modes must work. Conflicting signed
envelopes cannot remap an existing identity. The index's guards reject updates
and deletes, and schema creation refuses a substituted trigger.

Corruption tests warm archive verification, then delete or corrupt the payload
in the same inode, or replace the archive path with an unrelated valid Chio
database. Both lookup and retry must reject. Payload-table corruption and
checkpoint-prefix corruption have distinct refusal boundaries: the archive's
claim log retains its own signed canonical bytes. The tests check the actual
domain error at each boundary and require no recreated live payload.

## Arithmetic review checkpoint

[`2026-09-27-arithmetic-inventory.tsv`](2026-09-27-arithmetic-inventory.tsv)
retains all 638 matching source lines from the base commit, including tests and
formal/conformance code. Reproduce that base inventory with:

```sh
rg -n 'saturating_|wrapping_' crates/security crates/kernel \
  crates/platform/chio-store-sqlite -g '*.rs' -g '*.inc'
```

The recorded classifications cover 45 sites: seven repaired monetary additions,
16 receipt/event counters, two SQL subset subtractions, four replication sequence
increments protected by checked `i64` storage conversion, one intentional SQL
work-budget exhaustion clamp, and 15 forged-identity/PRNG test or conformance
mutations. The retained production clamps have bounds or exhaustion semantics
documented at their owning call sites. The other **593 sites remain pending**;
this is not a completed accounting audit. Snapshot import floors, writer counter
ownership and kernel quota/deadline paths still need individual dispositions.

## Historical liveness boundary

The current original property is already enabled and uses a direct 24-case
runner; its source is unchanged by this batch. The issue's older quarantine
description is stale. A read-only refresh of issue #1045 still reports the
historical 2.5-hour and six-hour hosted stalls, without blocked stacks or a
confirmed owner. Prior real slow-sync evidence is retained in
[`retention-diagnostic-2026-09-26.md`](../security/retention-diagnostic-2026-09-26.md).
The caller deadline and nested-transaction repairs are demonstrated defects,
not an explanation of those historical stalls.

## Verification evidence

Local profile: Linux aarch64, `umask 022`, locked dependencies,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, one Cargo owner and
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch` with the existing lane-d target.

- `/tmp/chio-packet3-focused.log` retains the first compile failure: the new
  fixture requested an unsupported SQLite `u64` count. The fixture now reads
  SQLite's signed count type.
- `/tmp/chio-packet3-focused-2.log` retains 24 passes and two failures. One
  exposed the nested transaction in full-verification mode. The other used a
  checkpoint-error expectation for missing payload bytes whose signed claim-log
  copy was still valid. The corrected assertion names the actual payload-read
  refusal; production authentication was not weakened.

- `/tmp/chio-packet3-focused-3.log`: 28 passed, zero failed/ignored, 11.49 seconds.
  Includes the eight new regressions, migration/readback cases, existing normal
  report aggregates and both full-verification corruption refusals.
- `/tmp/chio-packet3-retention-original.log`: six passed, zero failed/ignored,
  74.37 seconds. Runs the unchanged original retention property with
  `PROPTEST_RNG_SEED=20260926` and the CI environment's `PROPTEST_CASES=256`
  (the property's explicit runner still uses 24 cases). The other five cases
  cover archive snapshot/path races, refusal of incomplete co-archival, exact
  late atomic append and concurrent writer accounting. No sync delay was added.
- Final touched-file formatting, `git diff --check`, Rust file hygiene and weak
  negative-assertion gates passed. The 638 inventory lines were checked against
  their actual base-commit source. No size cap or assertion baseline was relaxed.

These are 34 distinct selected passing tests. Full workspace, privileged x86_64,
hosted, million-entry and release acceptance remain separate gates. No hosted
qualification or merge is claimed here.
