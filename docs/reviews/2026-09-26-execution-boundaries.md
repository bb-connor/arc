# Response and keyring execution checkpoint

> Superseded response compatibility decision (September 27): execution bindings are
> required for all plans and recovery. The unshipped legacy path and retirement
> queue are removed. See [production response simulation](2026-09-27-production-response-simulation.md).

This batch continues from `c7a20fe626` in the isolated
`/tmp/arc-security-launch` worktree. Implementation was inline, with one
independent reviewer reused for dependency and synchronization follow-ups. The
source checkout at `/home/connor/backbay/arc` remains outside this change.

## Implemented behavior

Fresh response state creation and fresh dispatch preparation now require
`FreshLiveAdmission`. Three compile-fail regressions first demonstrated that the
old APIs accepted a bare plan or a caller-selected recovery mode. They now reject
those programs. Rust callers import `prepare_response_dispatch` and
`ResponseDispatchPreparationRequest` from `chio_kernel`, construct the plan with
`FreshLiveAdmission::new`, and no longer supply `commit_mode`.

Recovery preparation belongs to the kernel. Its immutable execution request
derives the preparation mode from its private, verified origin. A committed
admission can prepare its owed dispatch; a committed dispatch must use exact
readback and cannot prepare a replacement. The control-plane executor validates
and prepares through the same immutable request. Quarantine retains the shared
pure transition and record projections, with no second approval verifier.

This is a high-level construction and admission guarantee. The lower-level
mutable, serializable `ResponseDispatchCommitRequest` remains a trusted
persistence interface. The review found no untrusted production route through
that interface to execution authority. This checkpoint does not claim that
arbitrary trusted-store writes are unforgeable. Test-only construction helpers
are behind the existing `admission-test-support` feature.

The legacy recovery regression exposed a real defect: the shared pure transition
validator applied the fresh Live rule while projecting a verified historical
admission. The Live check now sits on direct persisted transitions into
`Applying`. Pure projection preserves lifecycle and timing validation and lets
the kernel construct the dispatch authorized by the retained commitment. Direct
legacy and dry-run transitions still fail without changing their stored state.

The new real kernel/SQLite regression seeds the historical durable boundary
after admission commitment and before dispatch creation. It verifies one
unresolved admission, zero dispatches and zero effects, restores the changed
receipt schema boundary to v5, runs the v6 migration, and reconstructs the kernel
and executor from cold stores. Recovery creates one dispatch and executes one
effect. A second cold reconstruction replays the completed commitment without
another effect. The fixture supplies its retained plan and binding directly and
uses synthetic historical approval data; it does not run an older binary or
establish automatic startup discovery or a complete obligation inventory.

Keyring's shared bounded canonical reader now compares the original input bytes
with canonical serialization before returning the decoded record. Noncanonical
encodings of signed records, including whitespace, escaped strings and reordered
keys, are rejected. Canonical writers and full-width unsigned integers retain
their existing wire representation. The
signed timestamp regression covers `2^53 - 1`, `2^53`, `2^53 + 1` and `u64::MAX`.
The remaining readers stay listed in the
[signed JSON inventory](../security/signed-json-boundaries.md).

The final keyring rerun also exposed a concurrent-read defect in the autonomous
auditor. It fetched a synchronization page and then fetched the operator head
and stage separately. A rotation between those reads made a valid empty page
look stalled against a newer head, causing a fatal `made no progress` error.
The store now returns `KeyLogSyncSnapshot`: the page's history, full head,
signing epoch and stage come from one SQLite read transaction. The transaction
ends before full-history signature verification, replay and page encoding. The
auditor consumes that coherent result, and the existing response API uses the
same snapshot.

A deterministic two-connection regression commits a rotation during the read
through the existing injected clock. The old sequence failed with the new head
paired with the previous page; the repaired sequence retains the previous
head/page and observes the rotation on its next read. This regression uses no
sleep or retry and changes no production timing bound.

## Dependency review

The normal dependency direction is kernel to quarantine; the reverse dependency
exists only for tests. The privileged-broker budget correctly detected growth
from 478 to 479 packages on the locked `x86_64-unknown-linux-musl` normal graph.
Comparing the baseline and candidate graphs found exactly one addition:
`chio-quarantine 0.1.0`. No external package or version was added.

The kernel needs those shared lifecycle projections so recovery authority
construction remains private. This architectural cost is recorded beside the
479 ceiling. The independent reviewer accepted the measured change. Deny lists
and gate failure conditions are unchanged; the budget gate and its negative
self-tests passed. This measures the dependency graph, not binary size or
runtime cost.

## Local qualification

The response checkpoint is `3f279844e4`; the combined source checkpoint including
keyring is `a9ae42ed69`. All 41 changed source, fixture, manifest and gate paths
match the frozen candidate hashes in `code-files-workspace-candidate.json`.
The workspace build and test run began before these commits; the committed
source bytes match that candidate. Release-artifact qualification remains separate.
The workspace sweep was intentionally stopped on 2026-09-27 at the user's
direction to prioritize implementation and focused checks. Completed test groups
recorded 3,552 passes, zero failures and 19 ignored tests; the active 1,158-test
control-plane group was incomplete. The command exited 143 after SIGTERM. This
is partial evidence, not a workspace test pass. Workspace Clippy and the final
workspace formatting command were not reached. The focused checks above remain
the qualification for these source commits; no broad rerun is scheduled.
Evidence, including original failures and command exit codes, is retained under
`/tmp/chio-execution-batch-20260926/`.

Top-level Cargo verification commands use `--locked -j2`, `CARGO_INCREMENTAL=0`,
`RUST_TEST_THREADS=1`, `CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch` and
`CARGO_TARGET_DIR=/home/connor/chio-lanes-target/lane-d` on this aarch64 host.

| Command scope | Terminal result | Evidence log |
|---|---|---|
| Full `chio-quarantine` crate | 116 passed | `quarantine-full.log` |
| Kernel `active_response` library tests and new preparation compile-fail doctests | 5 and 2 passed | `kernel-response.log`, `kernel-api-doc.log` |
| Control-plane response executor, real adapter, and migration regression | 33, 2, and 1 passed | `control-response.log`, `real-adapter.log`, `legacy-migration.log` |
| Control-plane recovery and issuance-freeze integration targets | 17 passed | `control-integration.log` |
| SQLite dispatch, issuance-freeze and security-state contract targets | 47 passed | `store-dispatch.log` |
| Active-defense conformance | 10 passed | `conformance-response.log` |
| Full `chio-keyring` crate after snapshot repair | 79 passed | `keyring-snapshot-full.log` |
| Strict all-target Clippy for kernel, quarantine, control-plane, SQLite, conformance and keyring; keyring rechecked after the snapshot repair | Passed | `strict-clippy.log`, `keyring-snapshot-clippy.log` |
| Workspace build | Passed (961.82 seconds) | `workspace-build.log` |

The final owning groups contain 312 passing tests, with no failures or ignored
tests. File hygiene, negative-assertion, domain-separation and wire-schema gates
passed after the snapshot repair without changing their baselines. The locked
dependency-budget gate and its negative self-tests also passed. Graphify's final
AST refresh completed; its graph output remains ignored.

Original failures are retained separately. `authority-api-red.log` records the
three old programs compiling when they should fail; `legacy-dispatch-red.log`
records verified legacy recovery being refused; `keyring-canonical-red.log`
records acceptance of noncanonical signed-record encodings. The migration fixture's
first detailed run, `legacy-recovery-detail.log`, correctly refused a historical
authorization timestamp ahead of the store's trusted clock. The fixture now
uses the plan's creation time for that past authorization; no store clock check
was relaxed.

`keyring-final.log` preserves the original autonomous-auditor failure.
`keyring-snapshot-red.log` isolates the inconsistent head/page with a real
concurrent writer; `keyring-snapshot-green.log` passes after repair. Removing
only the read transaction fails the same regression with inconsistent history
ranges (`keyring-snapshot-mutation.log`). The mutation runner restored the source
in a `finally` block and recorded its hash before the passing full crate run.

The independent reviewer found no blocking correctness or security regression in
the implementation and accepted the bounded high-level authority contract. This
does not establish full workspace, hosted, native-runner, release or operational
acceptance.

## Remaining acceptance work

The migration regression completes one required recovery scenario from 1C.
Cross-store discovery must still inventory admission commitments without a
dispatch, dispatches in flight, retained preparations and cleanup obligations.
Historical reconciliation must not retire until every obligation is terminal or
explicitly migrated. Neither a zero dispatch count nor an elapsed horizon is a
retirement condition.

The production simulation/dry-run and signed report remain unimplemented. The
remaining signed-input census, retention scale/native work, production-linked
formal and fuzz gates, external dependency audits, hosted qualification and
release/operator gates remain in the
[resumption queue](2026-09-26-resumed-execution.md#remaining-acceptance-work).
