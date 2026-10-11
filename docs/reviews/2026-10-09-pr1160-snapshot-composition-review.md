# PR 1160 composed snapshot security review

Reviewed immutable range: `3b0760cfe7c8bdd286fac137663872ab6ebc1e1d..104df9bba82b01aae94f6a135cc189d690a11df7`.
Reviewed head tree: `d8664782e84d542b1f1417c091ce601c53674c76`.
Worktree: `/home/connor/lanes/pr1160-v25-integration`.

Read-only source review. No Cargo, builds, runtime regressions, or subagents were run. Findings below are confirmed source paths with concrete schedules; a dynamically failing regression remains a separate acceptance step. The two initially dirty issuer-fetch test overlays were excluded from production review. The worktree later advanced to `0d919c3e582afd2bf47d862ccf412c9c51d9589a` with only the three Task 8 test files changed; findings were rechecked using `git show` at the immutable reviewed head. Later integrator fixes are outside this verdict.

## Actionable findings

### P1: publish checkpoint-covered extension rows only after checkpoint validation

Location: `crates/platform/chio-store-sqlite/src/receipt_query_snapshot/extend.rs:49-54`; supporting publication at `receipt_query_snapshot/service.rs:473-478` and delayed authentication at `extend.rs:63-69`.

`extend_cycle` authenticates every newly copied entry with `checkpoint = None`, even if a covering checkpoint already exists in its pinned observation. It then inserts the rows directly into the served snapshot. `PublishedSink::commit` advances `through_entry_seq` and the generation and wakes readers; the phase remains Ready. The covering checkpoint's chain, signer, and Merkle root are checked afterwards.

Concrete scenario: pause extension at E, append a checkpointed batch, then replace one not-yet-ingested claim and its matching source row with another validly signed receipt. Resume extension and interleave a read after the row commit but before checkpoint settlement. A positive point read of the replacement ID succeeds immediately: it skips the head wait, fetch matches the newly owned replacement leaf, and no invalidation has advanced the lease epoch. Pages can also return that row once E reaches H0, or under the stated staleness allowance during a longer batch. Eventual root/signature mismatch invalidates the lineage after the answer has escaped.

This violates A1/A10 and design section 5.5's requirement that checkpointed ranges be accepted only when the streamed root equals the signed root. Reporting the old checkpoint sequence does not authenticate the newly published replacement. The existing `substitute` fixture helper models the claim/source substitution. `extension_serves_new_receipts_and_accepts_new_checkpoints` currently serves the new rows before waiting for the checkpoint, and the late-corruption refusal control only covers the unpublished build.

Required repair: stage new rows that the observed checkpoints cover until their covering chain, signer, and complete batch root are established, then publish an authenticated contiguous prefix. Preserve service of the previous safe version while work proceeds. Add a deterministic pause between the current row commit and checkpoint validation; assert no page, count, or positive point read can expose the substitution, then assert Invalid and no lineage revival.

### P2: keep receipt response materialization inside the admitted blocking task

Location: `crates/platform/chio-control-plane/src/trust_control/receipt_query_service.rs:58-61` and `:71-74`; response work at `receipt_handlers.rs:293-310`, also `:52-67`, `:89-115`, and `:966-983`.

`query` and `load` return decoded payloads from `run_bounded`, dropping the HTTP lane permit at worker completion. All three receipt routes then call `serde_json::to_value` and eager `Json::into_response` on an async worker, outside that lane. The export path already has `run_bounded_response` to prevent the same gap.

Concrete scenario: a tenant reads an accepted large signed receipt. Single-row pages may explicitly exceed 16 MiB up to the 128 MiB row cap. Once the snapshot call returns, its permit is free while the handler converts and serializes the payload; another wave can enter the four-permit lane while previous pages consume executor time and heap. Cancellation during finalization has no read permit left to retain. This is the new V25 receipt response path, separate from the deferred generic verifier GET store work.

Required repair: run payload conversion and final `IntoResponse` in the same blocking closure and HTTP permit as the snapshot operation. A current-thread paused-finalizer control should demonstrate unrelated executor progress, a fifth request should get Busy while four builders remain paused, and aborting a page or point request should retain its permit until the builder ends. Reviewed-head admission tests hold permits externally; the paused-finalization control covers export only.

### P2: validate lineage rows before refreshing subject filters

Location: `crates/platform/chio-store-sqlite/src/receipt_query_snapshot/walk.rs:1301-1307`; use at `receipt_query_snapshot/extend.rs:90-95`.

`copy_lineage` reads only rowid, capability ID, and raw subject. Refresh therefore bypasses `get_lineage_on_connection -> snapshot_from_row -> validate_for_local_read`, which build, recertification, and the previous retained projection use. That validator authenticates SignedToken rows and validates SyntheticAnchor rows.

Concrete scenario: build Ready with an archived receipt carrying no signed subject and no lineage. An out-of-band SQL writer inserts a new lineage row claiming `signed_token` provenance with NULL or invalid `signed_capability_json`, or a subject mismatching its valid token. Extension fills the receipt's subject and maintained subject counts from that row. A subject-filtered query now returns the receipt while the existing full retained read rejects the malformed lineage through archive projection validation. Build and recertification also reject it through `SignedToolProjection::derive`. A purely live old query does not always invoke the lineage validator; the archived scenario establishes the precise regression. Recertification eventually refuses, after the unauthenticated refresh was served.

This does not challenge the accepted LegacyProjection unsigned-subject boundary. It preserves the existing rejection boundary for rows that claim stronger provenance. Required repair: measure all variable-length fields before allocation, then use the existing local-row decoder/validator under the bounded transaction before refreshing. Cover malformed SignedToken, mismatched token projection, malformed SyntheticAnchor, and unchanged legacy acceptance. Existing refresh tests operate directly on `SnapshotDb` and do not validate this source boundary.

## Acceptance boundaries and remaining coverage

- The reviewed source has fixed indexed plans, exact maintained counts, transactional row/count updates, a full build bijection check, canonical leaf-bound fetches, poisoned-writer checks, and latched read invalidation. No additional concrete flaw was identified in those paths or Linux descriptor custody. This is a source assessment, not a claim that all acceptance controls passed.
- The three findings need genuine original failures and composed renewal. In particular, C8b's Building test does not close the checkpointed-extension publication interval, and the HTTP paused-finalization controls do not cover receipt pages or points at this head.
- C20's reviewed count check is twelve deterministic append/refresh generations. It lacks the specified randomized invalidation/rebuild campaign. The reported full capacity count comparisons are additional evidence, not that property campaign.
- Task 8 was reported terminal by the integrator: 1M signed Linux two passes in 2644.75 s and 10M synthetic memory two passes in 864.7 s, from a test-only handoff against `f24`. No runtime execution or exact composed capacity qualification was performed here. Rotation started during the signed contended build and completed after it; this does not establish successful mid-build archive relocation.
- `receipt-snapshot-local-checkpoint-20261009.json` is historical staged evidence. Its source, staged head, capacity-running entry, and explicit `candidate_qualified=false` cannot qualify this reviewed tree. The owning-suite summaries and running full CP campaign supplied by the parent remain separate from this source review. The mandatory real-SHA Kani timeout is unresolved proof evidence, not a passing verdict.
- AUTHORITY-READONLY is an existing tracked P1 repair, not a duplicate finding here. The generic verifier GET blocking family remains the explicit post-merge P2 boundary. No hosted, merge, release, or activation readiness is claimed.

## Requested temporary-directory check

Normal production teardown invokes `snapshots.shutdown()` on the blocking pool at `trust_control/service_runtime/init.rs:338-343`; shutdown joins the walker at `receipt_query_snapshot/service.rs:755-761`. Backing Drop closes SQLite before custody Drop removes the held entries. Service Drop at `service.rs:765-771` intentionally cancels and detaches, matching design section 9.

A test process exiting before a detached walker finishes can leave a directory; abrupt production termination can too. A payload-maintenance shutdown error at `init.rs:328-335` also returns before explicit snapshot shutdown. These are plausible cleanup races, not a proven cause of the 44 observed empty-schema directories. The supplied capacity run preserved the directory count before/after explicit shutdown, and normal graceful production cleanup is present. No P1 directory leak is established by the available evidence.
