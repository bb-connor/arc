# Checked budget accounting

This batch continues `8288bd56be` on the isolated
`packet/3-retention-accounting` branch. It implements the budget portion of
Packet 8, inline, without subagents or compatibility wrappers. The original
source checkout and its preexisting work remain untouched.

## Production changes

- `chio-kernel-core::accounting` owns private-field `ExposureUnits`,
  `InvocationCount` and `ExposureBalance`. Amounts retain the full unsigned
  64-bit domain; counts retain the unsigned 32-bit domain. Checked addition and
  subtraction return distinct overflow/underflow errors. Balance construction
  and settlement validate the combined exposure/spend total, and settlement
  cannot spend more than its own reservation.
- In-memory and SQLite charge, capture, release, reversal and reconciliation
  use those types. In-memory capture and reversal calculate every quota and
  cumulative-approval update before publishing any participant. The prepared
  updates have an infallible apply step under the existing store lock.
- SQLite monetary writers compare the stored counters with their read snapshot
  and check affected-row counts. Hold consumption requires sufficient exposure
  and the exact resulting remainder; terminal composite writes consume the
  exact hold snapshot. Quota and approval-account updates require the preceding
  version, and quota writes enforce reserved plus captured within the maximum.
  A refused write rolls back the usage, hold, quotas, approval account and journal
  together. The existing checked SQLite INTEGER range remains in force.
- Snapshot floor and provenance predecessors use checked subtraction directly.
  These already rejected invalid zero sequences; this removes their remaining
  dependence on a separate subtraction guard.
- The six migrated transition files have no unchecked arithmetic operators.
  Their 43-site allowance is removed. The lexical gate now records 12 sites in
  seven other modules, with no new exemptions or extended expiries. The
  in-memory assembled-module cap shrinks from 4,064 to 4,024 lines. Its new
  accounting module owns preflight and publication rather than an include fragment.

Wire and storage records still contain primitive integers. Arithmetic crosses
the checked-type boundary before publication. This is a budget mutation contract,
not a claim that every counter or lease owner in the workspace has migrated.

## Verification

Evidence is retained in `/tmp/chio-checked-budget-20260927/`. Cargo used one
owner, `--locked -j 2`, `CARGO_INCREMENTAL=0`, the existing lane-d target cache,
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`, `RUST_TEST_THREADS=1` and property
seed `20260927`.

The library run passed 154 tests: 10 kernel budget tests, three checked-type
tests and 141 SQLite budget tests. Both existing stateful property targets
passed all six tests. A final four-test snapshot-boundary rerun passed after
the predecessor changes. The final SQL boundary run is recorded separately in
`sql-boundaries-final.log`, including the direct writer test that bypasses Rust
release validation; all five cases passed. Across the completed runs there are
161 distinct passing tests, including eight new tests. Counts overlap across
reruns and are not added again.

The new coverage exercises competing partial releases, full-u64 in-memory
settlement, overflow refusal without new state, SQLite range refusal, and a
write-refusal matrix across usage, hold, quota and cumulative-account updates.
Immediate refusal compares every budget table. Reopen compares authoritative
tables, excluding the three proof caches rebuilt from the unchanged journal.
Contention uses independent SQLite connections for scalar holds and competing
handles of the provisioned owner for composite holds.

Three Kani harnesses passed over arbitrary full-width inputs, with unwinding
checks enabled: exact exposure arithmetic, invocation counts, and partial-spend
reconciliation conservation against the extracted reservation ledger. The
standalone driver imports the actual production `accounting.rs` and
`formal_aeneas.rs` sources; it does not copy their implementations. The harnesses
also belong to the normal `chio-kernel-core` Kani build. `kani-final.log` records
three successful harnesses and zero failures. The scalar Aeneas algorithm is
unchanged; its guarded subtraction is explicitly linked to this refinement.
No new Lean extraction or complete workspace proof sweep is claimed. Direct
compilation of the accounting source in a `no_std` crate also passed.

Source hygiene, accounting arithmetic, weak-negative-assertion and touched
formatting/diff checks pass. The arithmetic gate's negative self-tests pass
against a synthetic temporary baseline, so removing production debt no longer
breaks the gate's own fixture. The weak-assertion baseline remains 1,287.

Retained failures explain the corrections: `owners.log` and
`refusal-diagnostic.log` show an unprovisioned composite test and a reopen
comparison that included derived caches. No production check was relaxed.
`hygiene-initial.log` records the module-cap refusal before staged accounting
received its own module. The original arithmetic self-test failure and the
temporary-fixture setup failure remain in their respective logs.

## Plan reconciliation and remaining boundaries

The tracked hardening-toolchain spec had become empty in `f928453692`. It is
restored from `07e963e8f5`, labeled with its historical measurement base and
current execution directives. The engineering plan now records delivered gates,
authority types, measurements, exact reporting and recovery helpers separately
from unfinished acceptance work. Its legacy-plan migration proposal is withdrawn
in accordance with the user's no-compatibility directive.

The original saturating/wrapping inventory retains all 638 base coordinates.
Seven bounded model/fixture sites were classified, bringing it to 130 classified,
including 66 previously fixed sites, with 508 pending. This batch's replacement
of raw guarded arithmetic is tracked by the separate arithmetic gate; it does
not inflate the original inventory's fixed count.

Remaining work includes broader quota/lease type adoption, the shared clock port,
response lifecycle verification, unclassified arithmetic, historical retention
liveness, stable-candidate scale evidence and privileged x86_64 qualification.
There is no fresh workspace-Clippy, hosted, merge, publication or operator
acceptance claim in this batch.
