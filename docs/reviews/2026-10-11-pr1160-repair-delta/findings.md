# PR #1160 repair-delta review

Review date: 2026-10-11 UTC. Reviewed `974f22914bd339a62933831650c3d55dbaf76987..16c36036de95db2eaaee7d30654db4fb56c94782`, the requested cutoff on `fix/pr1160-landing-final`. The delta contains 167 files, 8,183 additions and 1,135 deletions. All code references below refer to the latter commit, not the workstation checkout or later repair branches.

**Result: 0 new P0, 0 new P1, 1 new P2.** Eleven R2 IDs have production repairs in this cutoff: ten satisfy their source-level repair contracts; R2-009 fixes its resource exhaustion but leaves the new capture defect below. Fifteen R2 IDs have no production repair here. This is not full-candidate qualification.

Reviewers read the pinned source, current coordination rulings, normative protocol, regression oracles and retained Original/repaired evidence. Original means production behavior without the relevant fix, with the regression present. Actual assertion failures were distinguished from compilation failures, preservation tests, static counterfactuals and unavailable platform execution. No builds, tests, repository scripts, formal tools, network requests or source changes were performed during this review. Existing logs and hashes were inspected; they were not rerun. Separate subsystem reviewers and a cross-cutting test reviewer supplied the assessments. The sole new finding also received independent source verification.

## R3-001 - P2: capacity refusals disappear from a supposedly complete relay capture

**Primary location:** `sdks/python/chio-hermes/src/chio_hermes/model_relay_limits.py:121-132`.

The new connection-capacity branch sends HTTP 503, removes the socket from live accounting and returns without recording the refusal or latching incomplete capture. Evidence begins only inside `Handler.do_POST` at `model_relay.py:260-265`, which this rejected connection never reaches. After admitted handlers drain, `EvidenceLog.complete` at `model_relay_limits.py:247-250` and `ModelRelay.evidence_complete` at `model_relay.py:362-364` can both return true. `restricted.py:456-467` then permits publication of `outcome="completed"` with exit 0, and line 470 saves a relay log that omits the emitted refusal.

A concrete scenario uses the default four permits and stays within all other limits:

1. Send four authenticated, correctly routed POSTs with Content-Length 2 and only the first body byte `{`. Wait until their handlers are reading the remainder. They own four permits and four pending evidence records; none has reached paid admission.
2. Send a fifth complete POST to `/refused`. The new capacity path returns 503 without creating a fifth record or an omission marker.
3. Complete the first four bodies with `}`. Each `{}` fails ordinary request validation, records its refusal and releases its permit. Wait for those releases.
4. Finalize capture. No handlers or pending records remain and the evidence budget was never exhausted, so capture reports complete. With an otherwise successful host and resolved gateway journals, the launcher can publish a completed run while retaining only four of the five refusals.

**Introduction and contract:** introduced by `989e1f85c33b9787e447f0fa4135babab90cc7e6` in this delta. Before the repair, the fifth parsed POST received its own handler and recorded refusal. The coordination ruling at `/home/connor/lanes/pr1160-coord/to-claude.md:5909` explicitly rejects silently unrecorded future refusals as complete evidence; the after-head repair plan at `docs/superpowers/plans/2026-10-11-pr1160-review2-repairs.md:148-154` requires bounded capture including refusals. This is a new reporting defect within R2-009's repair, not a repeat of its original resource exhaustion.

**Severity:** P2. Provider admission and paid accounting remain fail-closed. No authorization bypass, credential leak, refund or uncertain external tool effect was established. The defect is a misleading completeness result and failure-evidence omission. Incomplete headers that never reached the earlier application capture boundary are excluded from this finding.

**Regression gap:** `sdks/python/chio-hermes/tests/test_model_relay_limits.py:76-98`, `test_connection_capacity_refuses_before_a_fifth_handler_starts`, correctly proves the 503, four-handler limit and unchanged paid budget. It stops before asserting refusal capture after drain. The launcher test supplies a fake completeness boolean and cannot detect this producer omission. Extend the existing synchronized capacity case through finalization; require the refusal to be retained or capture to remain explicitly incomplete, with no paid admission.

**Minimal correction:** let the refusal owner record a fixed bounded refusal summary or latch a reserved, sticky incomplete marker describing omitted capacity refusals. Preserve the nonqueued permit limit, byte/count ceilings and denial. Do not spawn another handler or add an unbounded refusal log. The existing marker for active handlers at finalization would give the wrong reason here.

**Independent verifier:** confirmed P2 from exact after-head source by `verify_broker`, independently of `sdk_bindings`; Root agrees. The counterexample is source-established, not newly executed. Existing retained relay tests remain meaningful for their narrower resource boundaries.

## Included repairs

The following are source-closure verdicts. Retained component results do not mean the complete requested head passed hosted or native qualification.

### R2-001: supervisor Darwin credential custody - closed

`crates/products/chio-cli/src/supervise/credentials.rs:173-176` and `descriptor_credentials.rs:89-92` now share the private custody predicate. Its ACL inspection at `credentials.rs:214-217` precedes the owner/mode fast path. Allow or unknown ACL entries and inspection errors refuse; deny-only ACLs and genuine Linux systemd handling remain supported.

In `credentials/darwin_tests.rs`, `environment_loader_refuses_native_allow_acl` (:63), `descriptor_loader_refuses_native_allow_acl` (:75) and their allow-after-deny counterparts (:104, :114) fail at the intended assertions with unchanged production. Retained native Original: 2 preservation passes, 4 failures. Repaired: 6/6; supervisor owner 24/24. The initial rustix compilation failure is separate, not credited as an Original. Native sources plus disclosed unrelated compilation overlays match the reviewed custody files.

One shared supervisor predicate removes duplicate logic. The existing ACL inspector was moved to the existing leaf crate; no keyring compatibility delegate or copied FFI remains. This validates the credential gate, not a recreated administrative-endpoint exploit.

### R2-004: cage directory scan bounds - closed

`crates/security/chio-cage/src/linux.rs:72-108` adds finite aggregate entry and name-byte budgets. Both read and forbidden walks share their respective budget across roots and descendants. `push_directory_name` at :385-402 charges before copying a name; enumeration returns before sorting on overflow. Skipped symlinks and vanished entries consume budget. Refusal returns the existing exact resource-limit error rather than a partial permission set.

`linux/scan_bounds_tests.rs:6`, `read_directory_scan_refuses_excess_entries_even_when_every_child_is_skipped`, uses 4,097 symlinks; unchanged production accepts them and fails the refusal assertion. Retained Original: 1 pass/1 fail. Repaired: all 8 scan controls, including exact capacity, pre-copy byte refusal, vanished entries and cross-root accounting. The six later boundary controls use new private seams and have source-level counterfactuals, not claimed runtime Originals on the predecessor.

The private budget and preallocation helper are proportionate. The independent 64-retained-grant cap remains unchanged. Updated cage inventory adds exactly ten tests across R2-004/012. Retained owning evidence is 35 pass/1 ignored plus strict lint on aarch64; it does not qualify native x86 confinement.

### R2-005: correlation intermediate expansion - closed

`crates/security/chio-quarantine/src/correlation.rs:1250-1304` removes the uncapped intermediate extension vector and checks every distinct insertion before growing the bounded working set or findings map. Overflow uses the existing clear/suppress/no-findings path. Duplicate replacement at exact capacity remains accepted; healthy matching, ordering, watermark and durable CAS behavior are preserved.

`correlation/expansion_tests.rs:137`, `fan_out_reuse_expansion_overflows_before_exceeding_linear_clone_budget`, genuinely fails before the repair: six stages clone 31 candidates against the allowed budget of 18. Corrected Original: 3 passes/1 intended assertion failure; an earlier accessor compilation failure is separately retained. Repaired controls cover healthy two- and three-stage reuse, exact-capacity duplicates and suppression. Retained owner evidence is 133 passes; the later real temporal runner executes all 51 tests across ten inventories.

The test-only equivalent Clone implementation and thread-local counter measure the dangerous intermediate growth without an OOM experiment. They do not replace the production algorithm or make the Original fail artificially. Final extraction uses ordinary Rust modules, removing the initial include! assembly. No public API, schema, fallback or enlarged production limit was added.

### R2-006: kernel-owned throttle attempt identity - source closed; final qualification pending

`crates/kernel/chio-kernel/src/kernel/guard_invocation_attempt.rs:6-39` defines private attempt identity. Existing in-flight records receive random identity in `session.rs:198-263` and retain it through nonce/approval waits. `kernel/session_ops/request_claim.rs:50-65` obtains it only from the actual owned request claim. Durable operation identity takes priority; direct evaluations otherwise get fresh identity. Selection occurs once outside the grant loop and survives guard offloads. No new lock is held across a wait.

`crates/security/chio-security-kernel/src/session_throttle.rs:74-85` requires this private kernel observation. Missing identity denies before consuming the store; caller request text cannot mint it. The same acquired request keeps one unit across legitimate retry, while a fresh kernel reusing session/request names consumes a new unit.

In `tests/session_throttle_kernel.rs`, `repeated_unowned_read_only_request_is_denied_before_a_second_dispatch` (:295) and `fresh_kernel_reusing_session_and_request_names_consumes_a_new_throttle_attempt` (:559) have genuine retained Originals: actual Allow/two effects instead of Deny/one effect. The second Original rejected the first textual-identity repair. Preservation controls exercise alternative grants, real nonce preflight/retry and actual durable replay. Public standalone contexts cannot manufacture identity.

Frozen records at the requested cutoff still have the final v2 campaign pending. Later inspected completed commands at `a4282db2517d08a7cf01b64061e2fc5a30e15e6e` cover 6 real throttle, 6 guard, 5 transport/durable and 1 approval control, plus 85 security-kernel and 1,668 kernel-library passes. Reviewed implementation/test/Cargo families are byte-identical to the cutoff. The campaign had no terminal summary when inspected; PQ/strict completion and exact-head hosted acceptance were not established.

The 40-line private helper and fixed-size field on existing bounded state are proportionate. Broad GuardContext fixture edits are required to enforce private construction, not a compatibility layer. No second replay store or caller retry flag was introduced.

### R2-007: blocking adapter cancellation and nested queue - closed

`crates/kernel/chio-kernel/src/runtime/blocking_connection.rs:72-81` owns queued work through the shared abort-on-drop helper; all adapter handoffs use it. A private, single-use scope installed on the existing physical blocking worker at `kernel/dispatch.rs:1751-1752` avoids the one-slot nested-pool deadlock. One absolute deadline covers queue and callback admission; `blocking_connection.rs:63-67` refuses expired work before entering the inline callback.

`runtime/blocking_connection/cancellation_tests.rs:314-344` explicitly occupies the sole worker, polls each adapter future to Pending, drops it, releases the blocker and drains the queue before checking zero starts. Seven queued/drop/expiry cases fail before the repair with one unexpected callback. `healthy_adapter_through_kernel_completes_with_one_blocking_slot` (:430) also fails before the repair with timed-out Deny. Corrected Original: 3 preservation passes/8 intended failures; repaired: 14 new and 6 existing focused controls plus strict lint. Later single-use, deadline and unwind-restoration controls have concrete source counterfactuals, not claimed Original execution.

The RAII scope and shared abort helper remove duplicated handoff handling. They do not confer authority or promise to interrupt already-started synchronous work. Started work retains existing ambiguous-outcome treatment and reservations. The inline panic diagnostic changes from nested ToolServerError to outer Internal, as disclosed, without refunding or claiming nonexecution.

### R2-009: Hermes relay resource bounds - partial closure

The original resource defects are fixed. `sdks/python/chio-hermes/src/chio_hermes/model_relay_limits.py:118-143` bounds actual handlers before spawning them; :44-79 enforces one accept-to-validated-body deadline; :164-254 bounds retained records and serialized bytes, reserves terminal capacity and exposes failed faithful updates. Handler permits remain held through started provider work. `model_relay.py:374-393` bounds finalization and marks unfinished admitted work incomplete.

The first three controls in `tests/test_model_relay_limits.py` (:76, :101, :118) genuinely fail on unchanged relay production for fifth-handler admission, unbounded refusal metadata and stalled-body response. Retained composed owner result: 299 passes/4 unavailable live-sidecar skips, with Ruff passing and the three final production hashes matching this head. Later helper/launcher controls are not mislabeled drop-in Originals when they require the new module/API.

The limits module separates connection, deadline and evidence ownership without a new worker framework or compatibility path. However, its new capacity refusal is outside the evidence owner. R3-001 prevents accepting the full explicit capture contract. Paid/provider admission remains closed.

### R2-012: cage special-file opener - closed

`crates/security/chio-cage/src/linux.rs:749-779` adds NONBLOCK and NOCTTY to helper, target and runtime-file opens. Descriptor kind checks reject FIFOs before reads; strict resolution and retained inode/content validation remain. Directory handling is unchanged.

`linux/runtime_open_tests.rs:35`, `runtime_artifacts_reject_fifo_without_waiting_for_writer`, runs the actual opener for all three roles in isolated child probes. Unchanged production blocks in all three; the bounded parent guard kills/reaps its owned probes and the intended assertion fails. Retained Original: 1 healthy pass/1 failure; repaired: both tests pass with successful child results. The regular-file replacement control (:86) proves the retained descriptor still reads the original inode. The subprocess guard is justified by the original indefinite open, not a general testing framework.

### R2-013: mobile SQLite descriptor custody - closed

`crates/trust/chio-custody-hw/src/mobile_challenge/sqlite.rs:36-74` rechecks retained parent identity and database ACL. Initial custody preparation at :602-708 binds opened parent/database descriptors; ACL errors or authority grants refuse through :711-743. Every existing store operation checks custody before and after execution at :191-205. Owner, link, mode and inode checks remain.

`sqlite/darwin_tests.rs:57-85` checks initial database/parent grants and post-open ACL changes before mutation. Retained native Original: 2 preservation passes/4 intended failures; repaired: 6/6, with identical reviewed source/test bytes. Deny-only and no-ACL controls remain accepted. Linux owner/no-default and Rust 1.93 identity evidence are separate from Darwin runtime evidence.

Retaining one parent descriptor directly serves custody binding. It adds no second FFI implementation, reverse dependency, compatibility alias or mobile MSRV increase.

### R2-015: Go manifest size preflight - closed

`sdks/go/chio-go-http/manifest_validation.go:17-20` refuses oversized input before allowed-field collection or decoding. It shares the private byte ceiling and error sentinel with `protocol_validation.go`. Valid presence, duplicate, null, trailing-data and domain checks remain unchanged.

`manifest_validation_test.go:16`, `TestManifestSizeRefusesBeforeAllowedFieldCopy`, requires the size error and untouched destination; the genuine renewed Original instead returns missing-signature error, proving it reached the later preflight. The exact-size boundary control (:31) preserves valid input. Final sentinel-based tests require new identifiers, so the retained earlier assertion form is the behavioral Original, not a claim of verbatim drop-in compatibility. Retained result: 55 top-level and 79 subtest passes, vet success, stable final inputs. This is a minimal early check with one shared constant/sentinel.

### R2-021: CI host-copy metadata and producer bounds - closed

`scripts/run-security-execution-container.py:38-42` adds 100,000-entry and 12 MiB raw-listing limits while preserving existing blob limits. `read_tree_listing` at :440-486 uses one monotonic deadline across producer/read/wait, selector-driven bounded reads, pre-append byte refusal, visible kill/reap errors and inner-finally stdout closure. Entry overflow refuses before retaining the excess tuple at :517-519; materialization receives only the bounded inventory.

`scripts/tests/run-security-execution-container.test.py:452`, `tree_bound_tests`, uses eight real empty blobs and reduced caps. Retained Original accepts the oversize tree and reaches the intended assertion failure. Its overlay used create=True for constants absent from old source; the final test correctly requires the real constants and is not claimed as an unchanged drop-in Original. `tree_listing_stream_tests` (:486) rejected the intermediate blocking-read repair with a real stalled-pipe fuse, then passed the corrected reader. Final runner/helper/contract results and source hashes agree; the later full structural mutation result is separately pinned to its actual source.

The extension stays in the existing runner. Updating the helper-lifetime expected observation count from four to six matches three actual list/run pairs and retains exact equality. No new qualification tool, weakened inventory, compatibility fallback or silent cleanup failure was added.

### R2-026: MCP resume HMAC key-file custody - closed

`crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs:576-589` checks descriptor ACL before accepting key bytes. Root/current-owner handling, genuine Linux systemd behavior, bounded reading and final metadata stability remain unchanged. Inspector errors, allow tags and unknown tags refuse.

`session_resume_darwin_tests.rs:40` and :50 exercise allow and allow-after-deny ACLs against the real raw-byte reader, avoiding unrelated parsing rejection. Retained native Original: 2 preservation passes/2 failures; repaired: 4/4 with matching source/test hashes. Deny-only/no-ACL controls remain accepted. This sibling was added by the maintainers after the original R2 report's 25 entries. It shares the leaf ACL inspector while preserving its distinct allowed-owner policy.

## Known repairs absent from this cutoff

These are not new R3 findings. Each named owning implementation was checked against the before tree and is unchanged for the finding. Isolated handoffs and later repair work are not substituted for the requested source.

| ID | Finding and applicable ruling | Delta status |
| --- | --- | --- |
| R2-002 | Durable API Protect ignores configured budget authority. Current ruling requires configuration refusal for unsupported external budget combinations and honest durable mediation. Provenance is inherited on main, correcting the original R2 introduction claim. | No repair in proxy mediated/state/config or admission-operation store. |
| R2-003 | Keyring startup revalidates stripped bootstrap seed configuration. Split bootstrap/runtime validation and retain a genuine healthy serve_async control. | Trust-control init/config and cluster consensus unchanged. |
| R2-008 | Broker DNS preparation can block without a bounded resolver. Latest ruling permits separate absolute preparation-DNS and execution connect/TLS/I/O budgets, preserving signed timeout semantics. | Generic HTTPS transport/registration unchanged. |
| R2-010 | Abandoned prepared secrets require idle expiry via existing worker and precise Registered/Prepared CAS, preserving captured or held work. | Registration unchanged; prepared.rs receives only a platform-gated test import. |
| R2-011 | JSON stores can write beyond their reopen ceiling. Validate candidate serialized state including newline before write and assignment. | Runtime-core JSON/trust-floor stores unchanged. |
| R2-014 | Simulation compares sequential effects against already modified state instead of immutable captured base. Preserve ordered effects plus real stale-base refusal. | Core response simulation unchanged; SQLite file loses only an unused import. |
| R2-016 | Populated Anthropic initial tool content can escape the intended gate. Reject before forwarding; preserve empty starts. | Streaming implementation unchanged. |
| R2-017 | CLI Start drops the current authority pin. Pass it through the actual command-to-config path. | CLI dispatch/runtime implementation unchanged. |
| R2-018 | Issuance-freeze and suspension tamper tests need otherwise-allowing controls and precise integrity refusal. | Both test files unchanged; throttle tests do not repair them. |
| R2-019 | Decoy interrupted publication requires the approved private staging directory, custody/tag checks, no-replace publication, recovery and parent syncs. | Materializer/registry unchanged. Only four Darwin ACL Original tests were added; native notes report 2 pass/2 intended fail. There is no repaired native result or staging implementation here. |
| R2-020 | Portable issuer DNS must consume the same total fetch budget and keep its permit until the resolver actually finishes. | Portable issuer fetch unchanged. Broker R2-008's split-budget ruling does not apply to this single fetch operation. |
| R2-022 | Sequential channel reuse must use the observed monotonic lifecycle version while retaining state/fence/snapshot binding. | Prepared/reservation/terminal lifecycle files unchanged. |
| R2-023 | Zero-share/global registry retention needs aggregate limits and trusted signed-expiry reclamation, without reclaiming live holders. | Kernel-core budget split/evaluation unchanged. Latest global parent/edge/owned-ID-byte ruling supersedes the per-parent-only proposal. |
| R2-024 | Mobile must refuse authoritative Allow when required proof/usage constraints cannot be enforced. | Kernel-core evaluation and mobile kernel unchanged. |
| R2-025 | Preserve Error::source through retained passport registry causes. Existing P3 item. | Passport verifier unchanged. |

The decoy test-only addition is intentionally capable of failing the current native target. It must not be described as a repaired or qualified R2-019. Its first two tests, `crates/security/chio-decoy/tests/materialize_darwin_acl.rs:81` and :92, require an ACL rejection absent from current `src/materialize.rs:765-776`; deny-only/no-ACL controls preserve healthy behavior. This known pending implementation is not a new production regression.

## Other changed code and design assessment

The shared Darwin inspector now has one implementation in `crates/platform/chio-sqlite-file-identity/src/darwin_acl.rs`. Keyring and broker map its I/O errors into their own existing error types. Native keyring tests remain against the actual keyring validators; moving them into the leaf would create the wrong dependency. Cargo changes add local dependency edges, not package-version/source/checksum changes. Apple-only direct edges replace the broker's heavier keyring dependency. No unnecessary public compatibility delegate survives.

The owned hex encoder in `crates/core/chio-core-types/src/crypto/encoding.rs:29-44` preserves checked capacity, ASCII rules and exact wire bytes with one owned String and a shared nibble-pair helper. Its goal is solver cost, not a runtime output bug. Runtime compatibility tests correctly pass the predecessor. The relevant Original is the retained 1,800-second proof timeout; the unchanged focused receipt-mismatch harness later completed on native aarch64. The broader proof campaign remains separate. No formal tool was run by this review, and the audit's numeric claim of two successful unwinding checks was not independently traceable to named result properties, so that count is not relied upon.

All 24 changed SQLite security-state files only remove the same unused Darwin import. Control-plane/broker platform cfg changes match existing Linux-only production or test consumers. The non-Linux Host.keyring annotation preserves an owned custody lifetime rather than concealing removable data. The MSRV assertion change adds the already-approved --no-fail-fast flag to exact command equality; it does not remove work. These cleanup edits do not need artificial runtime RED tests.

No additional significant dead code, duplicate implementation, poor module boundary, blocking-on-async-worker regression or unnecessary compatibility mechanism was established in this delta. The FIFO subprocess containment, correlation clone counter, cancellation synchronization and exact CI inventories are justified by the specific regressions they detect. They are not approved as generic new harness infrastructure. The principal design defect found is the disconnected refusal/evidence ownership in R3-001.

## Evidence and limits

Retained evidence was checked against exact Git blobs and, where available, raw log hashes. The principal committed records are under `docs/security/audits/` at the reviewed head:

| Record | Bounded conclusion used |
| --- | --- |
| `review2-native-qualified-20261011.json` | 37 native artifact hashes and eight exact custody implementation/test bindings; genuine Original assertions, repaired controls and disclosed compilation overlays. |
| `review2-cage-qualified-20261011.json` | Actual skipped-entry/FIFO Originals, ten focused repaired tests and limited owning/platform evidence. |
| `review2-local-components-20261011.json` | Correlation, blocking adapter and relay component results with initial errors kept separate. |
| `review2-repairs-20261011.json` | Go Original and final owning evidence references; used for those results, not its superseded R2-002 provenance wording. |
| `review2-tree-qualified-20261011.json` | Empty-blob Original, intermediate pipe-read regression and corrected runner/source pins. |
| `review2-composed-structural-20261011.json` | Real 51-test temporal execution and full structural mutations at their recorded source; later threshold enrollment checked separately. |
| `receipt-mismatch-proof-cost-20261011.json` | Preserved Original timeout, byte-equivalent encoder and completed focused proof, without broad qualification. |

For R2-006, both genuine Original logs and completed commands in `/tmp/pr1160-ci-batch-20261010/review2-006-green/` were inspected separately because the after-head audit still records qualification in progress. Their exact source correspondence does not establish the unfinished campaign's final result.

Exact inventory checks account for cage's ten additions and temporal's five additions. The later approval-identity test is enrolled in the threshold job; actual PQ execution remains a separate acceptance boundary. The approval observer requires nonempty, equal identities but does not assert at least two observations. Current source executes both relevant passes, and real nonce/retry plus durable controls supply additional evidence; this is a limited supplemental oracle, not an established vacuous security test or new P2.

This review establishes the source findings and repair assessments above. It does not establish full workspace, native x86, native decoy, live Hermes/provider, final PQ/strict campaign, hosted exact-head, landing or release acceptance. Known absent repairs retain their existing obligations. No repair, source commit, coordination post, integration, push or merge was made by this review.
