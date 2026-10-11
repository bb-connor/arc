# PR #1160 repair-delta review 4

Reviewed `16c36036de95db2eaaee7d30654db4fb56c94782..4bb3208f447b7e7734acca2f26e5fe5f7b16d30d`: 72 commits and 177 changed paths. All source locations below refer to the latter Git object, not the advancing branch or working tree. Review completed 2026-10-11 UTC.

**Result: 0 P0, 0 P1, 3 P2, and 1 P3.** R2-023's resource bounds are repaired, but its accepted final expiry-refusal contract remains incomplete. Two new test regressions affect broker and issuer-pool qualification. The other requested repairs satisfy their accepted source contracts, subject to the evidence limits below. Native latency has a narrower source correction; the full 10-second acceptance objective remains open.

This was a read-only review. No builds, tests, formal tools, repair scripts, source edits, checkout changes, commits, pushes, or GitHub posts were performed. Existing test logs were inspected rather than rerun. The report is the only requested published output. Reviewers independently checked all three P2 findings; no P0/P1 candidate survived synthesis.

The prior review was verified as `/home/connor/lanes/review3-pr1160/findings.md`, SHA-256 `6fb67cc79f5876e9ffa26cc02c9a5f2222eeb267773a70968f434603920374c4`. Findings and accepted refinements were deduplicated against that report, Review2, and the coordination board and mailboxes. The four known native-MCP cutpoint failures, `proof_cli_contract` fixture failure, unavailable x86-only cases, and already assigned broker fixture/lint failures are not new findings here. Failed, pending, and unavailable evidence remains in those states.

## Findings

### R4-001 [P2] Take the final trusted-time sample after acquiring the parent registry lock

**Location:** `crates/kernel/chio-kernel/src/kernel/validation/lineage.rs:154-156`.

**Classification:** Incomplete R2-023 repair contract, not a newly demonstrated dispatch bypass. The expiry-aware helper was introduced by `9c55261da07d656c910be8edb54574b9111a9e42` and moved unchanged by `e9c1f8e15136f88bc22a170ebb39159507b7a208`. Earlier registration could also finish after expiry; the new accepted refinement expressly requires refusing a newly expired parent across validation-to-registration delay.

The helper samples trusted time and then calls `budget_registry_for_setup()`, which blocks on the registry mutex at line 171. A real competing holder exists: public `evaluate_portable_verdict` holds the same mutex through evaluation (`kernel/validation/portable.rs:94-128`), including caller-provided synchronous guards (`crates/kernel/chio-kernel-core/src/evaluate.rs:471-472`). Their duration is not bounded by this API.

A correctly signed, previously unregistered parent expires at second 100. Registration validates it and samples second 99, then waits behind a portable guard until second 101. With the registry watermark at most 99, `register_expiring_parent` receives 99 and inserts the already-expired parent, returning success. Its `max(now, watermark)` rule cannot repair this stale observation because portable evaluation does not advance that watermark.

The hard parent, edge, and byte caps remain enforced. A later fresh registration can reclaim expired zero-holder entries when capacity requires it. This finding does not establish fresh invocation authority, permanent exhaustion, or premature reclamation, which limits severity to P2.

**Regression gap:** `kernel/tests/budget_parent_expiry.rs:33` checks recorded expiry, and `:46` checks a failing final clock read. Neither holds the registry mutex across forward clock movement. Core registry tests only exercise explicitly supplied times. All can pass with this ordering defect.

**Correction:** Acquire the existing registry guard first, take the final fenced trusted-time reading while holding it, then register. Clock failure must leave the registry untouched. Add a deterministic held-lock/clock-advance control that requires refusal and absence of the new parent. No clock abstraction, worker, or compatibility path is needed.

**Independent verifier:** `/root/verify_cage_bounds` confirmed the reachable interleaving, provenance, and P2 limits against the pinned source, independently of `/root/kernel`. Source-established; no new runtime reproduction was executed.

### R4-002 [P2] Update the helper-lifetime inventory when enrolling the fourth release test group

**Changed location:** `scripts/check-secret-broker-boundary.sh:389-394`.

**Stale assertion:** `scripts/tests/check-broker-helper-lifetime.test.py:81-84`.

**Classification:** New regression introduced by `4627cd6b103ddaeb3815b47c919c0643c147f574`. This is distinct from the previously repaired four-versus-six observation mismatch.

The release block now contains four `run_tests` groups at lines 374, 383, 389, and 395. The existing helper-lifetime fixture invokes every group twice, once to list and once to execute (`check-broker-helper-lifetime.test.py:71-74`). Its fake Cargo records one observation per invocation at lines 54-55. Correct execution therefore produces eight observations, while line 83 still requires exactly six.

`BrokerHelperLifetimeTests.test_release_helpers_survive_intervening_candidate_commands` deterministically fails even when all five helpers survive every invocation. The parent container-boundary suite invokes it unconditionally at `scripts/tests/run-security-execution-container.test.py:2579` and propagates the failure. This needs neither native enforcement nor Docker to reach the assertion.

The hosted parent runs from a separately authorized tooling checkout selected by `CHIO_AUTHORIZED_SECURITY_SOURCE_SHA`. The candidate SHA alone does not establish that hosted CI currently consumes this affected pair. This is a concrete local/qualification-suite regression with a conditional hosted consumer, not an asserted current required-CI P1.

**Regression/counterfactual:** Removing only the new group restores three list/run pairs and six observations. Keeping it produces eight. This count was traced directly from source; the fixture was not executed during this review.

**Correction:** Change the expected count to eight, retain exact equality and all helper-preservation checks, and keep the startup control enrolled. Do not weaken the assertion, dynamically accept any count, or add another test framework.

**Independent verifier:** `/root/verify_async_adapter` confirmed the count, parent caller, authorization-pin caveat, and new provenance independently of `/root/ci_scripts`.

### R4-003 [P2] Synchronize queue progress before submitting the issuer-pool drain barrier

**Location:** `crates/platform/chio-control-plane/src/trust_control/config_and_public/portable_issuer_fetch_tests.rs:525-526`.

**Shared helper:** `crates/platform/chio-control-plane/src/bounded_worker_pool_tests.rs:38-41`.

**Classification:** New test race. The whole-fetch control added by `f48583a28134790c4685e29ef5e30a31bd1a9ba2` combines an occupied queue with the one-shot drain helper introduced in this range.

`stalled_fetch_holds_its_worker_but_not_the_fetch_permit` has one worker and one queue slot. The first job is running behind a release channel. The second job times out while still occupying the queue. The test then sends the first job's release and immediately calls `drain(&pool)`.

Sending release does not acknowledge that the worker ran, finished its first job, or dequeued the expired second job. If the test thread continues first, the drain marker encounters the still-full queue. Production correctly uses `try_send` and returns `DeadlinePassed` immediately (`bounded_worker_pool.rs:79`); the helper panics on that result. Its 30-second deadline does not wait for admission. The intended final assertion that expired queued work never starts is never reached.

**Observed evidence:** `/home/connor/lanes/claude-pr1160-evidence/r2-c3-issuer-dns/c5-green-tests.log` records 29 passed, 1 failed, with this test failing at `bounded_worker_pool_tests.rs:41:52`: `expected Ok(..), got Err(DeadlinePassed)`. The whole run took 3.47 seconds, below the helper's 30-second guard. SHA-256: `33e7eb6385a28cae7343daae22a217a736cf19141ebc64d9803a41a5ba2b97d1`.

The driver identifies producer `39bcbef87671d3f273fe6832694de9dd860bae32` and records `green exit=101` before applying the later reconstruction. The pool implementation, pool tests, and fetch tests have identical Git blobs at that producer and `4bb3208f44`; the fetch implementation changes only a comment. The packet lacks a full pre-run dirty-source manifest, so its head attribution is component evidence, not exact-workspace qualification. The pinned source independently establishes the same race.

**Correction:** Make the existing test-only drain admit its barrier under one unchanged absolute hang guard, retrying only a full queue and failing on disconnection, or explicitly acknowledge the expired callback's dequeue/destruction before submitting it. Preserve the no-start assertion and production's nonblocking admission. Do not add a guessed sleep, enlarge timeouts/queues, accept the drain failure, or change production to blocking send.

**Independent verifier:** `/root/runtime` confirmed the interleaving and retained evidence independently of `/root/verify_provider_gate`. This is a flaky qualification control, not a production DNS/TLS deadline bypass.

## Short P3

**R4-004 [P3] The cold-map duplicate-row assertion fails on row count before testing duplicates.** `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/cold/tree_tests.rs:597-601` appends one row to a valid three-row Grant, making four. `cold/encoding.rs:215` validates shape before the duplicate guard at line 218, and lines 302-308 permit only three or five Grant rows. Removing duplicate rejection therefore leaves this assertion green. Use a valid five-row shape with duplicated identity/outbox rows so only duplication causes refusal; retain the separate canonical-order assertions. Introduced in `f9c733a2238`, independently confirmed by `/root/quarantine_response`. The encoder is currently correct and the entire component is explicitly test-only preparation without live activation, so this is a limited coverage defect rather than a production security-gate P1.

## Repair-by-repair assessment

“Source closed” below means the accepted implementation contract survived source review. It does not mean the complete repaired SHA, all owning tests, native execution, or hosted CI passed. “Original” means unchanged predecessor production with an appropriate test overlay; reconstructed semantics, reverted guards, setup failures, and empty logs are identified separately.

### R2-002: source closed, durable budget ownership and unsupported configuration

`crates/products/chio-api-protect/src/proxy/state.rs:396-400` refuses durable receipts combined with either external budget DB or control URL before signer, store, and listener effects. The internal `MediationBudget` alternatives keep kernel/state on one accounting domain. `proxy/state/tests/proxy_builder.rs:247` exercises early refusal; `:283` proves healthy durable reservation followed by exhaustion. The old builder admits the unsupported configuration, so the refusal control discriminates it.

The retained genuine Original records reservation and nonce despite an exhausted external DB; its initial missing-control-token setup failure is not credited. Later component passes do not make the combined broker/CLI/API campaign green. Example changes remove incompatible flags without introducing compatibility semantics. The underlying accounting defect predates the PR on main; the reviewed repair is in this delta.

### R2-003: source closed, keyring startup after seed removal

`crates/platform/chio-control-plane/src/trust_control/service_types/config.rs:135-141` separates bootstrap seed validation from runtime validation. `service_runtime/init.rs:65` applies the stronger check before effects, and initialization still erases the seed. Later cluster/runtime validation can accept the sanitized configuration without weakening signing custody.

`crates/security/chio-secret-broker/src/process_boundary_tests/native_keyring_trust.rs:14` starts real witnessed keyring/trust services and reads authenticated admin receipts. It cannot pass on constructing a configuration alone. Its bounded retries accept only the typed Building response. Retained unchanged-production Original fails startup; repaired component passes. The release enrollment is correct in purpose but introduces R4-002's separate inventory mismatch.

### R2-008: source closed under the accepted separate preparation/execution budgets

`crates/security/chio-secret-broker/src/generic_https.rs:473-527` captures one absolute preparation deadline, capped by the signed timeout and the named five-second server cap. Four non-secret resolver slots remain occupied until their actual worker exits. Late buffered answers refuse at `:538-551`. Preparation uses the checked destination once; execution does not resolve it again. `service/custody/registration.rs:99-108` does the blocking preflight before the custody mutex, and `service/authorization.rs:73-122` refreshes authority time after waits.

Tests cover the actual prepare lookup count (`service/tests/custody_cases.rs:36`), stalled resolution (`generic_https.rs:1383`), deterministic at/after-deadline success rejection (`:1415`), and retained capacity (`:1445`). The old double lookup and late-result acceptance fail those respective controls under compatible wiring. All seven named DNS controls passed in the retained matching-component run; the owning campaign still failed elsewhere. The reported late-answer Original was not independently recovered as a raw packet. The accepted DNS preparation deadline is separate from execution's unchanged connect/TLS/I/O deadline and is not an end-to-end authorization latency guarantee.

### R2-010: source closed, pre-capture reclaim and queue cancellation

`crates/security/chio-secret-broker/src/service/custody/registration.rs:215-245` reclaims only after acquiring the existing nonblocking operation gate and winning the exact Registered/Prepared-to-Failed transition. It removes only the matching retained attempt. Busy, captured, later-state, and orphan entries remain owned; orphan evidence produces an integrity refusal after other eligible cleanup. Sweeping precedes the incoming request's own gate. The existing daemon idle worker supplies cadence without another worker or wire operation.

`service/tests/custody_cases.rs:172` enters the real external-capture/local-Prepared window before invoking reclaim, and `:290` invokes it during the actual preparation retry. Both assert that the hooks ran and that real work succeeds. These would expose removal without the shared gate; they cannot pass by missing the overlap. The retained expired-prepare Original fails correctly, while later race Originals are not credited solely from an unexecuted patch. A 117-pass focused result is component evidence, not final owner qualification. The known fault-injection FK setup failure and assigned lints stay separate.

The companion `kernel_admission/capture/connection/mcp.rs:151-164` abort guard prevents queued, unstarted authority work after caller cancellation. Its channel-gated test at `:184` would detect the old detached queue execution. Started work retains its original ownership and unknown-outcome semantics.

### R2-011: source closed, JSON write/read size agreement

`crates/kernel/chio-runtime-core/src/store/json_file.rs:21-38` serializes with the final newline and checks the same 64 MiB ceiling used by reopen before filesystem effects. All twelve affected mutators validate/persist a candidate before assigning live state. Tests `tests/runtime_store/json_store_bounds.rs:58,63` require exact oversize refusal, unchanged file/cache, and successful reopen. The actual Original returns success and fails both assertions.

Retained composed library/integration coverage reports 309 passes, with separate Criterion and strict checks. The earlier command that forwarded test arguments to Criterion still failed and is not relabeled. These changes do not claim atomic replacement or repair inherited partial-write/crash durability. One shared bounded serializer is justified; no new store abstraction or compatibility reader appears.

### R2-014: source closed, repeated simulated effects

`crates/core/chio-response-model/src/simulation.rs:56-63` validates every base against the immutable captured state, then applies effects in order to a working copy at `:85-108`. `crates/security/chio-quarantine/tests/response_dry_run.rs:128` requires two real WouldApply outcomes, distinct resulting hashes, and a combined final state; a genuinely stale second base still refuses. The retained Original fails with `simulation.stale_state` on the valid repeated-effect case. No parallel simulator, schema workaround, or reordered effect semantics was added. Full wave2 owning qualification is not established by that Original.

### R2-016: source closed, initial Anthropic stream content

`crates/protocol/chio-anthropic-tools-adapter/src/streaming.rs:112-130` rejects present nonempty or nonarray initial content before forwarding output or evaluating tools; absent content and an empty array remain valid. `tests/streaming.rs:482,509` exercises tool content, text, null, exact Malformed refusal, no evaluation, and byte-preserving healthy lifecycle. The genuine Original forwards initial tool data without mediation and fails the refusal assertion. The inspected producer Green log is empty, not evidence of success. The check is local to stream lifecycle and adds no fallback parser.

### R2-017: source closed, CLI Start authority pin

`crates/products/chio-cli/src/cli/dispatch/mod.rs:470` forwards the parsed pin to `runtime.rs:567,600-603`, reusing the existing trusted-issuer constructor. `tests/start_control_authority_pin.rs:110,119` launches the real binary and contrasts accepted pinned authority with refusal without a pin. Before the fix, Start drops the key and the positive case cannot validate. Source membership checking remains exact; the test does not separately exercise a wrong key.

The retained composed `cf46d03851` log runs both final controls successfully, and all three relevant files are byte-identical through `4bb3208f44`. The whole CLI command nevertheless exits 101 for separate failures. The Original log was empty, so the old behavior is a source counterfactual, not an observed Original here. Child ownership, output drainage, and fixed fixture times avoid incidental process/clock failures.

### R2-018: source closed, tamper tests isolate reflected-binding validation

`crates/security/chio-security-kernel/tests/issuance_freeze.rs:167-182` and `tests/capability_set_suspension.rs:220-241` now return otherwise-allowing tampered replies and assert the precise integrity/binding refusal. Legitimate active restrictions and unavailable stores remain distinct controls. Removing the reflected-binding validator now permits the tampered reply and fails the intended assertion; the old tests could deny for another reason. Production is unchanged, and small existing fixtures replace the masked oracle without a new harness. Partial Green is not evidence of a completed removed-validator campaign or both full owning targets.

### R2-019: source closed, private staged decoy publication and locking

`crates/security/chio-decoy/src/materialize.rs:401-453` holds a fresh per-call staging-directory lock through final verification. Stage custody requires the same owner/device and private directory permissions, including native Darwin ACL checks. Authentication precedes body writes, durable stage precedes no-replace publication, both parent directories are synced, and final bytes are verified. Nonempty untagged stages and unproven finals are preserved and refused. Explicit guard unlock at `:334-342` handles retained duplicate descriptors on ordinary return; it does not promise lock release after process death while another process still owns that description.

Concurrency tests at `src/materialize/concurrency_tests.rs:47-57` pause the actual durable pre-publication path and prove competing retries refuse without replacing its stage, including the same materializer instance and inherited descriptor case. Retained Originals observe the incorrect competing success or subsequent WouldBlock. Integration tests at `tests/materialize.rs:211` reconstruct interrupted stage states; they are not four actual power-loss experiments. The corrected-domain Darwin packet matches current production source and reports 70 passes plus five reruns/strict checks. Earlier Linux evidence predates the domain correction; its renewal remains pending. Shared file-custody extraction removes the old implementation rather than leaving an alias.

### R2-020: production source closed under the bounded-worker contract; regression campaign failed

`crates/platform/chio-control-plane/src/trust_control/config_and_public/portable_issuer_fetch.rs:62-102` passes one absolute deadline to one whole-fetch job. DNS, pinned HTTP, and bounded decoding run in one worker job; the caller waits only until its absolute deadline and accepts only a timely observed result. `bounded_worker_pool.rs:69-93` refuses expired admission, skips expired queued callbacks, and rejects outcomes first observed at/after expiry. Sixteen workers and sixteen queue slots bound retained fetch work. Started resolver/TLS work may remain on a worker after caller timeout. Initial Tokio blocking-queue delay is outside this accepted deadline; neither hard cancellation nor full-handler latency is claimed.

The same crate-private pool serves the existing receipt writer. Later explicit authorization permits queued unstarted writes to expire; started writes retain ownership, errors retain their types, and timeout mapping is unchanged. No nested pool submission or compatibility executor remains.

Pool tests at `bounded_worker_pool_tests.rs:51,64,70,91` distinguish passed deadlines, final observation equality, expired queue work, and started completion. The fetch late-success test at `portable_issuer_fetch_tests.rs:534` may return by receive timeout and alone cannot discriminate deletion of the final-observation check; the direct helper test plus source wiring supplies that coverage. The blocked-worker fixture models TLS occupation, not a live trickling TLS exchange. R4-003 must be fixed before the retained 29-pass/1-fail run can be called Green. Its later 18-pass/9-fail “Original” edits final production under final APIs and is a semantics reconstruction, not an unchanged-production Original. The driver's final zero exit does not override either test exit 101.

### R2-022: source closed, successor channel reuse

`crates/platform/chio-store-sqlite/src/channel_lifecycle_store/prepared.rs:323-339` and `reservation.rs:547-552` remove only the hardcoded record-version-one restriction. Exact observed state version, lifecycle fence, identity, head/checkpoint, and live-state comparisons remain. Existing transaction and trigger increments are unchanged.

`channel_lifecycle_store_tests/reservation/terminal.rs:792` performs a real terminal projection followed by public successor reservation/publication and checks the second sequence and evolved versions. The corrected Original fails with AuthorityVerification; the initial malformed fixture and cancelled attempt are not credited. Restoring either old guard prevents the intended successor path. This does not promise protection against arbitrary out-of-band SQL replacement, and full owning acceptance remains distinct.

### R2-023: bounds closed; final expiry refusal incomplete

`crates/kernel/chio-kernel-core/src/budget_split/registry.rs` and the per-parent implementation enforce 10,000 children/1 MiB child IDs per parent and global 10,000 parents/100,000 edges/16 MiB owned IDs. Counts include actual owned copies. Exact idempotence and live lease ownership remain intact; only expired zero-holder parents can be reclaimed. Boundary/registry tests exercise zero-share retention, aggregate limits, strings, and holder preservation, so old unbounded storage does not satisfy them.

The concrete expiring method preserves the legitimate nonexpiring operator API. Moving kernel setup into its existing lineage module is organizational, not a new abstraction. However, R4-001 leaves the final kernel wrapper's current-time refusal incomplete. Core 90-pass evidence and supplied-time expiry tests cannot close that mutex boundary. Earlier compile/setup failures are not behavioral Originals.

### R2-024: Rust source closed, mobile selected-grant refusal

`crates/kernel/chio-kernel-mobile/src/lib.rs:352-358,453-457` checks the verified matched grant before mobile Allow and refuses unsupported DPoP, invocation, and spend-accounting requirements. Missing or out-of-range match information denies. The accepted portable contract is the selected authoritative grant, not the native route's separately stricter all-matching-grants rule.

`tests/ffi_roundtrip.rs:184-235` signs otherwise healthy capabilities for all four unsupported forms and checks the exact reason/index through the real Rust FFI, with ordinary and delegated Allow controls retained. The old Allow branch fails this source counterfactual. Its inspected Original log was empty. The committed Swift XCFramework remains an older unchanged artifact, so this review does not establish updated packaged-native behavior or binding qualification.

### R2-025: source closed, retained error causes

`crates/platform/chio-control-plane/src/passport_verifier.rs:248-255` exposes the existing `CliError` for Load, Refused, and Persist, and preserves cause-free Busy/Unsupported. Tests at `:1913,1928` cover all variants. Retained logs show the intended missing-source failure and two repaired passes, but no whole-control-plane qualification is inferred. This is a small trait correction, not a new error framework; current boundary conversions remain unchanged.

### R3-001: source closed, relay capacity refusal stays incomplete after drain

`sdks/python/chio-hermes/src/chio_hermes/model_relay_limits.py:129` synchronously informs the capture owner before sending 503. One sticky omission flag at `:225-227` keeps completion false at `:263-266`; snapshot appends one fixed marker within the existing reserved terminal budget. `model_relay.py:349-351` wires the real owner, and finalization waits for the serving loop before deciding capture status.

`tests/test_model_relay_limits.py:77-105` fills all four handlers, observes the fifth refusal, closes peers, waits for actual drain, and checks incomplete finalization and the exact marker without a paid call. The genuine Original incorrectly finalizes true. Retained matching package coverage reports 299 passes, four live-sidecar unavailable tests, and Ruff. There is no unbounded omission log or new per-refusal handler.

### Custody election: source closed, ranking remains separate from serving authority

`crates/platform/chio-control-plane/src/trust_control/cluster/consensus.rs:470-483` sorts eligible reachable candidates by current signing custody, then URL. Inspection errors advertise no custody. The boolean only changes preference; existing liveness, history, quorum, and serving admission still decide authority. `cluster/authority_evidence.rs:254` observes the post-admission peer status before stability checks, so changed identity or lost custody de-ranks the peer.

Tests `cluster_and_reports_tests/custody_election.rs:78,96,116,180,187` use a real signing custodian and public-state-only followers, test no-custodian budget liveness with signing refusal, and gate the actual second status response for late changes. The healthy fixture requires admitted authority on all nodes and cannot pass on an ignored sync error. Initial and late-rank Originals fail the intended comparisons. The read-error Original first fails initial ranking, so it is not an independent witness for the later corruption step. The retained owner run was 55 passes/1 old fixture failure; the test-only successor preserves the assertions, but final family renewal is not established.

### Native latency: narrower cadence correction accepted; full objective remains open

`crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/cadence.rs:7,38` lowers the maintenance trigger from 20 events to five. `crates/platform/chio-control-plane/src/security/adapters/tests/native_flow/support/participant_history_cadence.rs:439-524` measures actual verification walks and final custody across sixteen calls. Its assertion rejects the old observed second-call maximum of 11 against the new bound of six; zero/absent observer data cannot satisfy the calibration.

The documented guarantee is only the sequential maintenance observation. Later concurrent appends, partial histories, current snapshot size, archive growth, and total native latency are excluded. The native 10,000 ms fence is unchanged. Historical red/green walk measurements lack complete exact-source/environment pins; a later 5-to-20 reversion is a reconstruction, not an unchanged-parent Original. No accepted terminal pinned replay or full enforcing eight-receipt latency acceptance was established. This known open work is not a new finding.

## Architecture, additional changes, and coverage limits

- The new `chio-file-custody` leaf crate owns the unchanged descriptor/ACL implementation for six direct consumers. The prior SQLite location is removed; manifests and the relevant root, fuzz, and deployment locks follow the move. No compatibility delegate or duplicate implementation is retained.
- The bounded pool has two real owners, portable fetch and receipt writes. The shared JSON serializer also replaces duplicated enforcement. These abstractions have concrete callers and do not warrant a one-caller or generic-framework finding.
- The new cold authenticated map is entirely `cfg(test)` preparation. Its six files separate encoding, tree operations, tests, and finite vectors; production activation, durable root attachment, and cold-state/G5 qualification remain explicitly false. Its component/mutant evidence does not prove those future properties. R4-004 is the narrow new oracle gap.
- Custody reclaim uses existing operation gates and the idle daemon worker. Decoy serialization uses one actual directory-lock boundary. Neither introduces a second lifecycle system or background coordinator. Selected typed refusals and exact tamper assertions improve error provenance; no additional stringly typed or dead-code P2 was established in this delta.
- Changed CI inventories and reader enrollments were checked against the owning tests. The concrete uncovered drift is R4-002. The relay, DNS, custody, election, decoy, persistence, and mobile controls were traced to production boundaries rather than credited from names or `.is_err()` alone.
- Documentation/audit claims were checked for source-only versus runtime/native/hosted scope. Started issuer workers, reconstructed decoy interruption states, and sequential cadence limits must retain their stated qualifications. Historical snapshots and empty logs were not treated as current passes.

All 177 changed destinations were assigned across subsystem and cross-cutting lanes, including manifests, examples, test-only preparation, scripts, and audit documentation. This is a repair-delta review with direct boundary reads, not another full audit of unchanged PR code. It cannot certify absence of every defect, final hosted status, merge readiness, or operational security acceptance.

## Retained evidence index

These are selected raw records inspected by the review team. None was executed by this review. Hashes bind files, not unrecorded build environments.

| Record | Path and observed result |
| --- | --- |
| R2-002 actual Original | `/home/connor/lanes/claude-pr1160-evidence/r2-c7-durable-budget/original-red.log`; 0 pass/1 intended failure. SHA-256 `91e6826b0007a00fb40ac9e5d7eb9bdfec97ddbc2618a5a9877fa9ce0c1a7144`. |
| R2-003 startup Original/Green | `/home/connor/lanes/claude-pr1160-evidence/r2-train-2/b/e2e-r2003-original.log` and `e2e-r2003-green.log`; 0/1 and 1/0. Hashes `ffaba997d644acfa1ee8e5975a61254f703190e9683943c3e202fc302dee2fc6` and `1532f8f25e771cdcca5608d707826c05d5cb27222fe05bf3a0f91a9a2a2dc070`. |
| R2-010 expiry Original/focused | `/home/connor/lanes/claude-pr1160-evidence/r2-blocking-dns/original-010.log`, `focused-010-run1.log`; 1 pass/1 intended failure and 117 passes respectively. Later race patch alone is not executed evidence. |
| R2-011 persistence evidence | `/home/connor/lanes/claude-pr1160-evidence/r2-c2-persistence/r2-011-original.log`, `originals.sh`, `r2-011-green.log`; the overlay and actual assertions distinguish rejection from setup failure. Composed summaries under `/tmp/pr1160-ci-batch-20261010/review2-011-composed/` and `review2-011-bench-lint/` retain component and wrapper outcomes separately. |
| R2-014 and R2-016 Originals | `/home/connor/lanes/claude-pr1160-evidence/r2-c5-sim-anthropic/r2-014-original.log`, `r2-016-original.log`; intended stale-state and forwarded-content failures. Hashes `5756dae920a3227077d53d2b2d1a3ddbbd711fd7dc2b4361a79274002fc6a123` and `d56d543b32c6c193ced42172f0b73dcab01f6008c6afc31cc5e95b8feaf64d6f`. |
| R2-017 final component Green | `/tmp/pr1160-ci-batch-20261010/composed-broker-cli-api-cf46/04-chio-cli-owning/output.log:2622-2628`; both pin controls pass, overall command exits 101. Log SHA-256 `b7669bf2fdfeec8042e031507acbfea2bd5ff587df0a7d43ed8c202df8094358`. |
| R2-019 corrected-domain native packet | `/home/connor/lanes/claude-pr1160-evidence/r2-darwin-native/75b5/SHA256SUMS` and listed logs; matching materializer source, native 70 passes plus five reruns/strict. Overlay provenance retained; Linux renewal not inferred. |
| R2-020 failed Green/reconstruction | `/home/connor/lanes/claude-pr1160-evidence/r2-c3-issuer-dns/c5-green-tests.log`, `c5-original-tests.log`, `c5-run.log`, `c5-run.sh`, `c3_original.py`; Green 29/1, reconstruction 18/9, both exit 101. Reconstruction log SHA-256 `174291d3eeeaad525272ab16ecc1c81b8245db908cacfa3ee29efd9896e7faae`. Driver `ticket exit=0` is not test success. |
| R2-022 corrected Original | `/home/connor/lanes/claude-pr1160-evidence/r2-c6-preexisting/r2-022-original.log`; 0/1 AuthorityVerification, distinct from invalid-seed/cancelled attempts. SHA-256 `275b20cfaec0ddfeb6693a0f56a6ed2c45ca15573523aa7f10997214d9da7fac`. |
| R3-001 Original and package | `/home/connor/lanes/claude-pr1160-evidence/r2-c4-copy-bounds/hermes-capacity-RED-final.log`; actual incorrect complete finalization. Package evidence `/tmp/pr1160-ci-batch-20261010/review3-relay-composed/result.json` retains 299 passed/4 unavailable and source correspondence. |

Detailed owning and independent verification drafts, source manifests, captured rulings, and the 177-path accounting remain under `/tmp/review4-pr1160-4bb3208f44/`. They support this report without widening its fixed source range. No coordination mailbox or integration worktree was modified.
