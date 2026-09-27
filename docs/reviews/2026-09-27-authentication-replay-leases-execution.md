# Authentication, replay accounting and runtime lease execution

This is the next local Packet 3 / Correction 3A implementation batch after
`995b9f1c74`, on `packet/3-retention-accounting` in
`/tmp/arc-security-launch`. It covers session authentication epochs, approval
and DPoP validity arithmetic, replay capacity accounting, and durable runtime
lease/scheduler transactions. The source checkout and preexisting `output/`
artifacts are preserved. No subagents were used.

## Authentication and signed validity

Session authentication setters now return `Result` and share a single
transition implementation with persisted updates. The lifecycle lock covers
validation, persistence and publication. Closed sessions refuse authentication
updates. Epoch increments are checked, with `u64::MAX` reserved for a terminal
anonymous anchor: the last valid active epoch can still close and revoke its
authentication. Failed persistence leaves the previous anchor and context
intact. Direct callers use the fallible API; there is no compatibility wrapper.
Session inspection clones lifecycle and authentication under the same lifecycle
read lock, preventing an active snapshot from inheriting a terminal epoch.

New approval requests require a positive TTL within the existing approval
lifetime cap and an exactly representable deadline before either the store or
notification channel sees them. Inverted signed token windows receive a
specific refusal regardless of verifier time. Resolved-request reconstruction
uses the token's signed issue/expiry window rather than a fresh default TTL.

DPoP verification checks the proof deadline before invoking the existing
freshness predicate or reserving a nonce. The saturated future-skew comparison
remains an intentional upper bound. The production hook adds a checked
representability precondition; the core/Aeneas/Lean predicate is unchanged.
This batch makes no new formal equivalence or proof-regeneration claim.

## Replay accounting

Pruning and owned cancellation first compute the complete byte/count release
plan, then delete markers and publish the totals. An underflow or missing
accounting entry preserves the markers and latches a refusal on later mutation
and replay-source export. Wrong-owner cancellation releases nothing. Admission
checks the per-capability increment before inserting a marker.

Agent-Web global and per-scope live-plus-batch totals now use nonnegative checked
addition inside the existing SQLite transaction. Existing duplicate, capacity,
concurrency, exact-reservation and reopen coverage exercises those owners.
Boundary tests cover counts too large to materialize as actual database rows.
Replay clock and source revision fences retain their existing refusal semantics;
the no-partial-publication claim concerns replay markers and authority state.

## Runtime leases and scheduler ownership

Lease acquisition validates positive TTL, representable expiry and positive
persisted fencing tokens. Successors use checked SQLite-range arithmetic, so
exhaustion cannot reuse a fencing token. Heartbeats run in an IMMEDIATE
transaction from ownership read through validation and guarded update. They
reject backward clocks, stale owners, expired leases, invalid tokens and invalid
time ordering before writing.

Scheduler expiration, active-capacity accounting, pending selection, lease
claims, report validation and tick persistence now share one IMMEDIATE
transaction. Only an actual lease conflict can become a skipped claim. Other
failures roll back the whole tick, including earlier claims and expirations.
An optional stale cutoff avoids falsely expiring heartbeat zero before the
configured timeout has elapsed. Existing leases above a reduced capacity
intentionally leave zero admission slots. This serializes capacity among
scheduler callers; direct lease acquisition does not carry a supervisor profile.

The new database regressions compare every lease and tick column on refusal,
inject a late SQLite write failure, cover exhausted fencing after an earlier
claim, reopen persisted state, and race independent scheduler/acquisition
handles behind barriers. No timing sleeps are used for contention tests.

## Arithmetic inventory

The [inventory](2026-09-27-arithmetic-inventory.tsv) preserves its 638 original
source anchors at `4c35ce7867`. This batch classifies 22 additional sites:
19 repaired sites and three intentional bounds. Cumulative status is
**123 classified, including 66 repaired sites; 515 pending**. Source anchors
in the affected files were checked against the base commit. Checked raw
increments and the former unchecked resolved-approval addition extend beyond
the original saturation/wrapping search.

## Verification

Local profile: Linux aarch64, `umask 022`, locked dependencies, one Cargo owner,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`,
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`, and the existing lane-d target.
Logs are retained under `/tmp/chio-auth-replay-leases-20260927/`.

- `kernel-sqlite.log`: 107 kernel tests passed and two new replay fixtures
  failed. The fixtures supplied Unix time 1000 to a store initialized with the
  current clock, so the rollback guard correctly rejected them before pruning.
  The fixtures now start from the store's current clock domain. SQLite tests
  were not reached in that attempt.
- `kernel-sqlite-final.log`: 117 kernel and 47 SQLite tests passed, zero
  failed or ignored. Build: 3m 02s. Execution: 0.63s and 86.95s. The filters also
  selected durable-admission session/DPoP and threshold-approval integration
  cases. All completed successfully.
- `session-caller.log`: an isolated package selection caused a redundant
  rebuild. That owned invocation was terminated (exit 143), not counted as a
  pass. The follow-up restores the original package selection.
- `session-caller-sqlite.log`: the direct session API caller and all 23
  Agent-Web replay tests passed after replacing a new test unwrap with the
  repository assertion helper.
- `runtime.log`: all eight new lease boundary tests and 12 existing lease,
  scheduler, recovery and status tests passed, zero failed or ignored. Build:
  1m 43s. Execution: 0.78s and 1.01s.
- `fmt-final.log`, `hygiene-final.log`, `negative-final.log` and `diff-final.log`:
  all checks exited zero. The negative-assertion baseline remains 1287; no file
  size cap or baseline was increased. No workspace test, build or lint was run.
- `session-final.log`: 39 session and direct-caller tests passed after the
  atomic clone correction, zero failed or ignored. Execution: 0.16s. The SQLite
  binary selected zero tests in this session-only recheck.

Across these completed focused runs, 185 distinct tests passed, including all
20 new regressions. The final changed session boundary was rechecked after its
last edit; this is local owning evidence, not exact-candidate release qualification.

Focused test commands (using the environment above):

```sh
cargo test --locked -j 2 -p chio-kernel -p chio-store-sqlite --lib -- \
  session:: dpop:: approval:: kernel::tests::hitl_ \
  kernel::tests::approval_deadlines kernel::tests::governed_approval \
  kernel::tests::governed_call_chain agent_web_replay_store::
cargo test --locked -j 2 -p chio-kernel -p chio-store-sqlite --lib -- \
  kernel::tests::cross_kernel_continuation_token_verifies_parent_receipt_hash_and_session_anchor \
  agent_web_replay_store::
cargo test --locked -j 2 -p chio-runtime-core \
  --test lease_boundaries --test runtime_ops -- \
  lease heartbeat fencing scheduler runtime_ops_status runtime_ops_recovery
cargo test --locked -j 2 -p chio-kernel -p chio-store-sqlite --lib -- \
  session::auth_epoch_tests session::tests \
  kernel::tests::cross_kernel_continuation_token_verifies_parent_receipt_hash_and_session_anchor
```

Packet 3 and Correction 3A remain partial. The historical retention runner
stall, original stable-candidate scale campaigns, remaining arithmetic sites
and Packet 2 native qualification remain open. No workspace-wide qualification,
hosted, merge, publication or release claim is made by this batch.
