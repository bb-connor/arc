# CI and authority-time repair execution

This batch continues the authorized regression recovery from
`122414b48ef1bc7999a9e32c7ae303d561fcd429` on
`packet/3-retention-accounting`. It implements the
[CI and authority-time plan](../superpowers/plans/2026-10-01-ci-authority-time-repair.md).
The checkout also contains the local documentation-only compliance review commit
`8c6ef0a98fef8faafdea0e2b0d7370cdaac0e7f1`; publication will preserve it in history.
Local qualification is complete. Hosted native execution remains pending; no
merge, milestone or release acceptance is asserted.

## Implemented boundaries

| Task | Change | Acceptance |
| --- | --- | --- |
| RC1 | Sample the injected challenge clock immediately before coordinator submission, after body upload, parsing and blocking-pool wait | Late upload and unavailable-clock controls plus the complete challenge suite |
| AC1 | Remove public ambient authority-time override; receipt identifiers have their own thread-bound scope; owners receive explicit Clock ports | Kernel, durable clock, recovery and runtime harness suites |
| Clippy | Repair the 26 recorded diagnostics without new lint allowances | Original all-target owner command and changed owner checks |
| Structural CI | Repair custody fixtures, generated Docker inputs, source contracts and inventories; extract the pure response model from quarantine so the kernel cannot depend on the executor | Complete 99-gate step and hostile controls |
| CLI fixtures | Fresh private seeds/directories, current process schema, separate anchor/read scopes, signed launch arguments, real Enforced provisioning | Complete affected targets and native compilation; real native acceptance requires the designated host |
| Proof/report | Fixed public diagnostic reasons with retained private typed causes; explicit complete capability-filtered budget query before display truncation | Owner controls and complete proof/report integration targets |

All-target Clippy passed with warnings denied for all 30 selected crates, including
the native-enforcement feature. The final sweep exposed three additional cleanup
owners beyond the original 26 diagnostics: the remote MCP test-support dependency,
safety-comment placement in enforced discovery, and an extracted helper doc comment.
All were corrected without lint allowances; the failed run remains retained.

The first complete 99-gate sweep retained four failed outcomes from three causes:
the MSRV cache test omitted the newly required native-fixture step, the security
image/checker lock digest preceded the final workspace test dependency, and a clock
fixture migration changed an older weak assertion's identity. The cache test now
binds all three steps to the same directory. Both lockfiles' external package
records were compared before updating the exact workspace lock pin. The rollback test
now requires the specific behind-anchor rejection and passed; its one weak
baseline entry was retired with the expiry unchanged. An initial test selector
matched zero tests and is retained as compilation-only evidence, superseded by
the passing exact owner test.

The new `chio-response-model` contains existing validation, projection and
simulation code. Quarantine retains store, scheduler and effect orchestration.
The dependency gate checks direct and transitive isolation. Existing strict
Clippy rules are retained by the extracted crate, and existing public quarantine
reexports preserve source callers. Parsed comparisons of both lockfiles against
the batch base confirm that all external package records are unchanged.

Clock fixtures now initialize time before constructing an owner. Restoring a
clock below a reading already observed by its fence is a real regression and
must fail. Rollback controls assert that stable clock error while preserving
history and callback refusal. Expired-claim controls keep observed time monotonic
and distinguish short expired claims from still-live claims. Native join controls
commit while the lease is live, then prove expiry cannot append another mutation. The deterministic runtime harness serializes its
artificial store/lease identity to avoid overlapping process-local ownership;
production mutation exclusion remains unchanged.

The filtered budget regression reproduced HTTP 500 because `usize::MAX` could
not be represented as a checked SQLite LIMIT. The replacement queries all rows
for the requested capability and computes totals before truncating displayed
rows. The integer conversion remains checked.

Process integration also exposed a preexisting promotion flaw: an unversioned
partial journal could receive the current runtime binding before failing on its
missing attempt column. A new refusal control reproduced the promotion. Opening
a nonempty journal now checks its existing version and authority binding before
WAL or schema initialization, and rechecks the binding in the initialization
transaction. Both missing-table and missing-row controls preserve database bytes
and leave no WAL/SHM files. All 19 process tests pass, including a separate current
journal first-dispatch identity and exact-replay control.
Byte preservation here covers the supplied rollback-mode fixtures. Existing WAL
or hot-journal recovery and comprehensive validation of already-versioned schemas
are outside this repair.

## Independent review

One fresh read-only reviewer found three Important issues in the combined patch:
an overbroad archive-loop cleanup, a test-ancestor egress exemption that could
hide a production alias, and a native CI checker that did not bind containing-job
conditions or reject soft failure. All three were repaired. The egress and CI
bypasses received failing then passing hostile controls. A minor misplaced helper
comment was moved with its function.

The reviewer found no further production security defect in the reviewed repair,
compared all 32 extracted state helper bodies, and verified retained Python runtime
hashes. The review did not substitute for pending qualification. Existing aggregate
saturation, broader clock owners and older generic test-path exemptions remain
separate review work.

The same reviewer inspected the subsequent journal preflight fix and found no
Critical or Important issues. Binding checks precede explicit WAL/schema changes;
the immediate initialization transaction rechecks the binding before commit.
Concurrent first initialization was assessed from source, not a new race test.

## Native qualification

The existing fixture action omitted mandatory read grants. It now packages the
bounded Python runtime first and forwards its exact paths to authority preparation.
The fixture runs before required workspace/MSRV consumers, and the process workflow
runs native MCP/auth/HTTP/conformance targets before replacing the Python grants with
static report-tool grants. Host, identity, helper, independent anchor and terminal
probe checks remain mandatory. The CI contract rejects 70 hostile mutations,
including disabled and optional containing jobs.

The native fixture uses the existing conformance 64 MiB per-artifact ceiling in place
of the ineffective Disabled fixture's 1 MiB value. The retained local Python closure
contains a 10.3 MB standard-library archive and a 7.8 MB interpreter. This is a bounded
fixture configuration change; production limits and source-size caps are unchanged.
Compilation and artifact checks on the local Linux aarch64 machine do not establish
Linux x86_64 native enforcement.

## Evidence and publication

The 14 affected non-native CLI integration targets have now passed all 340 tests
across their terminal runs. The original combined run had four failures in three
targets; complete reruns of those targets passed all 128 tests. The new direct
proof error mapper control also passed, including private cause retention and
stable schema exit status. Five native integration targets compiled with the
real-enforcement feature; native execution remains a separate requirement.

The complete admission namespace ran 530 tests: 521 passed and nine older clock
fixtures failed. Those failures identified clock initialization and time reversal
errors in the fixtures. The corrected owner run passed 163 tests with one existing subprocess helper
ignored as a direct test. It covers all nine failing cases, all assignment cases,
clock controls and serving-owner checks. The failed sweep remains retained and
is not labeled passing. All 22 runtime-harness tests passed after the
artificial-identity serialization correction, including semantic proof-package
determinism. The complete kernel suite passed all 1,493 tests after correcting
the delivery fixtures to initialize time before construction. Both kernel durable
admission and settlement integration targets passed all 16 tests. Both runtime
admission and store integration targets passed all 155 tests.

The final structural sweep passed all 99 gates with zero failures. Final all-target
Clippy, workspace formatting, Rust file hygiene and diff checks also passed.

Terminal command outcomes, log hashes and the final source manifest are recorded
in the [compact qualification artifact](artifacts/2026-10-01-ci-authority-time-repair/qualification.json) beside the
[structural review](artifacts/2026-10-01-ci-authority-time-repair/structural-gate-review.json).
Raw logs remain outside Git. Failed, interrupted and superseded runs retain their
actual statuses. Publication and exact-candidate hosted qualification remain separate.

Local verification permits publication of the existing security branch. Native
host execution and publication are tracked separately. No merge or operator
activation is included in this batch.

## Next queue

Reconcile the remaining operational regressions before resuming broad reader work:
PB3 and PR3 clock-fault recovery, PR5 certificate input bounds, NC2 repeated provider
response headers, and TR2 unknown-URL behavior. Follow with AC2/AC3 explicit clock
ownership and SF1/CA2 producer-specific decode contracts inside the TCB. Historical
finding documents are evidence, not proof that a finding remains open at a later SHA;
each next repair starts with a current reproducer.

| Finding | Next acceptance boundary |
| --- | --- |
| PB3 | Exercise the actual MCP serve loop with a faulting clock, both idle and with pending work. Preserve the session while refusing time-dependent dispatch, then prove safe recovery. |
| PR3 | Define and exercise clock recovery across API-protect, its kernel and replay owners. Recovery must not freeze expiry or extend a capability's lifetime; simply clamping a regressed wall clock is insufficient evidence. |
| PR5 | Give certificate collection its own bounded session contract and prove a long valid session can be certified. Isolate demonstrably unrelated corrupt rows without silently omitting rows whose session membership or completeness cannot be established. |
| NC2 | Preserve permitted repeated response headers and their value order through real broker dispatch and durable replay. Retain credential stripping, size limits and deterministic evidence; prove the provider executes once. |
| TR2 | Represent VirusTotal's documented unseen-result outcome separately from transport or malformed-response failure. Prove repeated unseen results do not open the failure circuit and actual provider failures retain their configured denial behavior. |
