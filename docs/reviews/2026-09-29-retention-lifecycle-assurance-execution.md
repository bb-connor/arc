# Retention ownership and durable lifecycle assurance

September 29, 2026. Worktree `/tmp/arc-security-launch`, branch
`packet/3-retention-accounting`, base `7177be5092`. Local aarch64 Linux,
Rust 1.94.1, incremental compilation disabled. This is local engineering
evidence, not hosted qualification, deployment authorization or release approval.

## Delivered boundaries

1. **Retention capture:** an RAII observation spans the entire delegated SQLite
   `xSync`, including the parent filesystem callback. It records the syncing
   thread, file, elapsed duration, WAL write/checkpoint ownership and an entry
   stack captured on that thread. Stack symbolization happens outside the
   diagnostic mutex; the mutex is never held over delegated I/O. Open, health,
   receipt reads and teardown are watched. The bounded driver records exact
   case completion, child exit and executable hash, and rejects incomplete or
   reordered progress even if a success line is present. The entry stack is not
   the current instruction pointer of a blocked kernel syscall. No ptrace
   permission is required for this capture.
2. **Durable lifecycle linkage:** metadata-only debug observations follow real
   response commits, native session-throttle command commits and native signed
   receipt persistence/verification. Connection guards are released before
   emitting SQLite observations. The initial dispatch commits generations 0
   and 1 atomically; subsequent mutation commits cover one generation each.
   Observations confer no authority and are not a concurrent global commit log.
   The real executor fixture drops and reopens both stores and all backend
   owners, recovers after effect/receipt acknowledgement loss, replays activation,
   expires the plan, removes its throttle, and verifies final reopened state.
   Each of three scenarios has ten signed generations, nine response commit
   events, two independently read native command rows and two owner restarts.
3. **Revocation progress:** the new source-pinned gate checks inductive progress
   obligations with four authorities, eight capabilities and unbounded integer
   epochs. Seven positive obligations are UNSAT; four deliberately broken
   variants produce SAT counterexamples. Every premise is separately SAT.
   The pending-message rank strictly falls on revocation/propagation and cannot
   increase otherwise. SMT-LIB queries, solver verdicts, counterexamples and
   source/implementation hashes are retained. The existing four finite TLC
   liveness/witness cases remain required.

The durable checker independently verifies Ed25519 signatures with the pinned
public test key, content-addressed evidence, native command bindings and results,
commit/receipt order, truthful acknowledgements, restart placement and final
snapshot hashes. Twenty-four corruptions of the actual emitted artifact must fail.
The workflow now requires that artifact; it cannot quietly omit durable linkage.
The capture test runs in a bounded child process to avoid tracing-core's shared
callsite registration interacting with subscriber-free parallel tests.

## Verification and limits

The owning retention test first failed for absent active-sync evidence, then
all five tests passed with two generated cases plus deterministic replay and
3 ms injected sync latency (7.29 seconds). The bounded standalone runner passed
its two-case calibration plus replay in 6.847 seconds. Its executable hash and
terminal counts are preserved; this is not source-build attestation or the
historical property RNG/seed.

The durable Rust fixture first failed for missing commit observations. Its
standalone three-scenario run passed in 4.95 seconds. A wider parallel test run
then exposed the tracing capture interaction (43 passed, capture failed); the
isolated-child repair and final adjacent qualification are recorded in the
final verification section below. The serial diagnostic passed all 44 selected
tests, confirming the capture failure depended on parallel callsite use.

The finite lifecycle checker passes its positive model and eight named negative
controls with the durable artifact required. The revocation gate passes seven
positive obligations, four calibrated SMT mutants, two verdict-refusal tests and
four finite TLC cases. Each SMT query has a ten-second timeout; unknown or
vacuity cannot pass. The eleven obligations completed in under one second on
this host. Focused Clippy passed before the final capture isolation change;
the final verification record states the post-repair result separately.

The [artifacts](artifacts/2026-09-29-retention-lifecycle-assurance/) preserve
terminal evidence. No full-workspace build, release campaign or long 256-case
retention rerun was needed for this implementation batch.

## Claims still open

- Retention issue 1045's historical root cause and original-scale gate remain
  open. The earlier 242/256 progressing timeout is unchanged. The new current-
  owner entry-stack capture makes a future blocked attempt diagnosable; it does
  not establish a reproduction or production ownership repair.
- The durable fixture covers one native effect kind, a single worker and orderly
  owner restarts. Other effect families, concurrent workers, process/power-loss
  cutpoints and full Rust/TLA refinement remain separate work. The test key is
  public; these artifacts are regression evidence, not trusted operator capture.
- The original length-24 temporal query remains timed out/unverified. The new
  gate replaces the expensive operational rerun; it is not a passing result for
  that old query. Source-to-projection correspondence, action symmetry and the
  well-founded weak-fairness argument are documented manual obligations in
  [the progress argument](../../formal/revocation-progress.md).
- Hosted CI, native x86_64 enforcement, supply-chain audits, publication and M11
  operator acceptance were not established by this local batch.

## Next substantial implementation batch

Continue item 2 of the remaining-work queue through `chio-mcp-edge`,
`chio-mcp-adapter`, `chio-a2a-adapter` and `chio-openai-adapter`: semantic decoder
and authority-result disposition, shared clock/deadline/quota ownership, typed
error sources and precise refusal regressions. Update the inventories with real
contracts and repaired boundaries. Keep the unresolved retention experiment and
candidate-wide qualification as separately bounded acceptance work.

## Final verification

The [fresh review](artifacts/2026-09-29-retention-lifecycle-assurance/final-review.md)
found two Important checker gaps: unchecked native command authority/identifiers
and intermediate commit hashes. Six failing refusal regressions reproduced them.
One fix pass derives command identities, binds their full authority and expiry
to the signed request, and captures/verifies every committed snapshot and exact
mutation prefix without retaining store owners.

Post-fix evidence is terminal:

- All 25 response tests pass in parallel, including isolated real-port capture
  (6.06 seconds); the 19 adjacent receipt/effect adapter tests passed separately.
- All 24 corruptions of the actual emitted artifact reject, including the six
  review reproductions, missing snapshots and substituted mutation prefixes.
- The finite lifecycle positive model and eight named counterexamples pass with
  that artifact required. Every recorded production-hook hash and trace digest
  matches the final source/artifact bytes.
- `cargo clippy --locked --offline -p chio-control-plane --lib --tests -- -D warnings`
  passes after the fix (52.73 seconds). Changed Rust files pass rustfmt and the
  diff passes whitespace checks.
- A one-second synthetic driver calibration prints a success line and then
  stalls. The retention runner terminates it with SIGTERM, preserves the summary
  and refuses qualification. This is a runner control, not workload evidence.

Both Important findings are fixed, with no deferred minors. The workflow uses
one fresh review and one tested fix pass; there was no second review. The
[execution ledger](artifacts/2026-09-29-retention-lifecycle-assurance/execution-ledger.md)
records the five explicit scope rulings and their costs. The branch and worktree
remain local; preexisting `output/` is preserved.
