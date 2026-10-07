# Evidence and product closeout implementation plan

> For agentic workers: use Superpowers TDD and systematic debugging. The user authorizes execution with bounded 6.1 Sol max agents. Keep ownership disjoint, coordinate thin shared-file hooks, and preserve final native/trusted/hosted acceptance.

**Goal:** Repair the remaining concrete EV2/EV3/EV4 and certificate EV6/EV8 defects, and make KG12 protection claims match the exposed product paths.

**Architecture:** Reuse the joint admission serving owner, kernel receipt authority, authenticated retained-history reader and existing default guard profile. Add narrowly scoped helpers and version the ACP-Client certificate body where an authenticated receipt-set commitment is necessary. Do not introduce another evidence service or general retention framework.

**Tech stack:** Existing Rust kernel/control-plane/protocol/product crates and SQLite. No new external service.

**Spec:** The six corresponding requirements in docs/security/landing-ledger.json and docs/reviews/2026-10-01-compliance-product-truth-review.md. Baseline analysis uses `d0496c14d824a327f00b98576132834306ff6694`; preserve the ongoing resource/error/privacy repairs during integration. The parent closeout plan controls source freeze and qualification ordering.

## Global constraints

- Preserve fail-closed admission, existing fencing, canonical signed commitments and independent verification pins.
- A refusal report cannot authorize execution, consume an execution nonce, settle or release holds, terminalize an existing admission, or assert that a tool executed.
- Erasing mutable payload bytes does not erase immutable digests, backups, already delivered outputs or every other payload table.
- Missing optional guards are not an authorization bypass. The claim must identify the constructor and the boundary actually exercised.
- None of these source repairs alone supplies final hosted/native/trusted qualification. Freeze and requalify the final composition after integration.

## Review focus

1. FullBundle with None, an empty bundle, a same-sized substituted bundle, duplicates or reordered receipts must refuse.
2. Interleaved sessions, archived prefixes and later appends must not make a complete snapshot appear empty, continuous or complete by accident.
3. Payload deletion must preserve live/shared-owner custody, stale-fence refusal and recovery/replay safety across restart.
4. Authenticated MCP refusals must survive restart without tool dispatch; persistence failure must remain a refusal and must not masquerade as retained evidence.
5. Caller-execution reservation cannot establish output sanitization of an external response the kernel never observed.

## Confirmed pre-execution source observations and ownership

This table records the `d0496c14d824a327f00b98576132834306ff6694`
pre-execution baseline. Its writer boundaries describe the concurrent lanes when
this plan was prepared, not the current repair status. Current source results,
original failures and remaining qualification are reconciled in the
[landing ledger](../../security/landing-ledger.md).

| Obligation | Concrete baseline | Baseline concurrent writer boundary |
| --- | --- | --- |
| EV2 | tool_outcome.rs:526 serializes the complete ToolCallRequest. SqliteToolOutcomeStore::compact_retained_invocation_blobs at tool_outcome_store.rs:144 exists; every located caller is a test. It clears raw-output-owned envelopes only, after all owners are terminal. | Storage writer owns suspension/report work, not these files or maintenance. |
| EV3 | MCP tool_calls.rs:364 rejects unmatched capabilities using a client logging notification; capabilities.rs:20 discards matcher errors. No durable refusal is produced there. | MCP writer owns ingress accounting/deadlines/inboxes, not refusal evidence. Runtime integration must wait for that handoff. |
| EV4 | remote http_service.rs:302 returns SessionCredential::validate_message's error before edge processing; session_credentials.rs:498 emits a bare 403 for disallowed tools/methods. | session_credentials.rs is outside that writer's edits; http_service.rs/factory/session input are shared with the ingress writer. |
| EV6/EV8 | ACP-Client compliance.rs:570 falls back to Lightweight when FullBundle receives None; :592/:603 accept Some([]). Full mode checks individual authority but not count, ordered set commitment, sequence or time coverage. | Diagnostics writer changes compliance.rs error presentation and cert.rs error classification only. Semantics remain unchanged. |
| EV8 collector/claims | cert/session_receipts.rs:83 requires legacy chio_receipts; actual store uses chio_tool_receipts plus claim_receipt_log_entries. cert.rs:43 hardcodes empty guard/scope checks. compliance.rs:395 interprets claimed resource scopes as tool-name prefixes. | Collector and retained_read.rs are untouched. Separate new modules can be developed before the thin shared-file integration hooks. |
| KG12 | wrap.rs:380 and API Protect mediated.rs:129 build kernels without the shared default profile. Control-plane lib.rs:196 already installs default_runtime_guard_profile, including SanitizerHook. API Protect mediated.rs:589 reserves caller execution rather than observing the external output. | Wrap/mediation files are untouched. Dirty control-plane guard files require root coordination; their secret/diagnostic edits do not install these product pipelines. |

## Packet 1: Minimize raw requests and activate terminal raw-payload maintenance

**Files:** kernel/admission_operation/retained_request.rs, kernel/tool_outcome.rs; control-plane/durable_admission.rs and a new durable_admission/payload_maintenance.rs; SQLite tool_outcome_store.rs and its tests. Product configuration hooks follow after the owner exists.

**Existing interfaces:** RetainedToolAdmissionRequestV1::request_without_transient_credentials; SqliteToolOutcomeStore::compact_retained_invocation_blobs(cutoff: u64, fence: &StoreMutationFence, trusted_now: u64); DurableAdmissionRuntime::local_authority_store(); SqliteAuthorityStore::tool_outcome_store() and mutation_fence().

- [ ] Factor the explicit credential-stripping constructor into crate-visible use and use it for newly retained raw request JSON. Preserve capability/material identity, arguments and security-context binding; remove the same transient credential fields already omitted from retained admission requests. Do not rewrite existing committed blobs or manufacture a new request identity.
- [ ] Add a production maintenance method on the existing local DurableAdmissionRuntime, supplied an explicit terminal raw-payload TTL and interval. Use the existing authority's outcome store, mutation fence and trusted clock. A remote runtime must be maintained by its server owner, not by a client opening another SQLite authority.
- [ ] Before periodic activation, add compact_retained_invocation_blobs_page(cutoff, fence, trusted_now, after_digest, max_rows), returning compacted count, live-owner count for this page and next digest. The present UPDATE and retained_live COUNT are global scans. Preserve terminal/shared-owner checks and the transaction/anchor path; a LIMIT alone is not evidence that verification work is bounded.
- [ ] Follow the existing owned-worker shutdown/health pattern: stop and join before serving authority retirement; surface compaction failures and fencing; resume safely after restart. Do not couple raw-payload deletion to receipt archival or accept client time/cutoffs.

**Acceptance:** A durable side-effecting call containing transient proof/token sentinels persists none of those transient fields in new raw request JSON. Advance the injected authority clock through one actual maintenance tick: terminal raw bytes become NULL, digest/size/outcome/receipt commitments survive, live and shared-live-owner blobs remain, stale fences refuse, restart/replay never reinvokes the tool because bytes were compacted, and maintenance error/row-budget tests exercise the production owner.

**Scope:** This closes newly retained transient-credential duplication and bounded terminal raw-envelope retention. The separate retained admission request still carries capability/material, and resolved-output blobs use different references to the same blob table. Full EV2 payload erasure remains open until those owners have explicit deletion and replay contracts; do not call this universal erasure or PHI/PCI compliance.

## Packet 2: Persist scoped nonauthorizing MCP refusal evidence

**Files:** new kernel/session_ops/protocol_refusal.rs with a thin session_ops module hook; MCP edge runtime/protocol/capabilities.rs and tool_calls.rs; remote session_credentials.rs, then coordinated http_service.rs/session worker hooks. Use dedicated tests beside existing protocol-boundary tests.

**Proposed narrow kernel interface:** record_session_protocol_refusal(&OperationContext, &ProtocolRefusalSummary) -> Result<ChioReceipt, KernelError>. Summary has a fixed refusal-reason enum, bounded method/target identifiers and a request digest. It contains no capability token, approval, DPoP proof, raw arguments or arbitrary error text. A validated session context supplies tenant/session/epoch, never caller metadata.

- [ ] Reuse the boot signing floor, ensure_receipt_persistence_ready and record_chio_receipt_without_settlement pattern from session_ops/reports.rs:61. Emit TraceObservation, DetectOnly, decision=None, a typed refusal metadata block, and no financial or execution result. Reserve its metadata namespace so caller extensions cannot spoof the typed block. Do not call normal admission with an invented or unrelated capability.
- [ ] Change capability selection to return typed matcher errors rather than unwrap_or(false). At the real tool/resource/prompt refusal branch, record the reason before returning the existing denial. Use a bounded server-side diagnostic and refusal metric independently of client logging/setLevel.
- [ ] For EV4, authenticate and resolve the credential-bound session before requesting the same recorder. Submit a host-only control command through the actual session worker, with its existing ingress accounting and an acknowledgement after persistence. Do not expose a client-callable method that can manufacture refusal reasons or bypass credential validation. Integrate only after the active inbox writer freezes that interface.

**Acceptance:** With client logging disabled, constrained/model-metadata mismatches and restricted authenticated-session tool/method refusals produce exactly one verifiable durable report after reopen; tool dispatch counter remains zero; tenant/epoch substitution, spoofed report metadata, persistence failure and duplicate retry tests cannot mint authority, settle/release an admission or claim successful persistence. Invalid/unknown anonymous credentials remain outside this session-scoped receipt contract unless a separate operator ingress contract is deliberately implemented. Document that boundary instead of claiming every HTTP rejection is receipted.

## Packet 3: Make FullBundle an actual authenticated set check

**Files:** new ACP-Client compliance/bundle.rs and bundle_tests.rs; thin hooks and versioned body fields in compliance.rs after diagnostic edits settle. The separate kernel and Mercury certificate/proof formats are outside this packet.

**Existing interfaces:** generate_compliance_certificate(session_id, entries, config, keypair, clock) and verify_compliance_certificate(cert, mode, entries, config). Preserve validate_compliance_receipt and independent trusted_kernel_keys.

- [ ] Refuse FullBundle + None and every empty bundle. Require exact positive receipt_count, unique IDs, ordered sequence identities, consistent kernel/session/tenant and valid signed receipt/action IDs.
- [ ] Version the ACP-Client signed body to commit the ordered receipt set, including each entry's retained sequence and canonical signed receipt bytes. Full verification recomputes this commitment and exact count, first/last timestamps and policy checks. Do not accept a same-count substituted bundle merely because each new receipt is individually valid.
- [ ] Require monotonic timestamps and first <= last <= issued_at. Reuse the complete validation logic used by generation instead of maintaining a weaker second loop. Legacy certificates without the set commitment cannot pass FullBundle; any retained Lightweight support must explicitly describe its limited verification.
- [ ] Distinguish a session's ordered receipt set from the store's global sequence: interleaved other sessions legitimately create global gaps. Do not renumber rows or interpret adjacency of selected global sequence numbers as a complete-session proof.

**Acceptance:** Dedicated tests reject None, [], count mismatch, duplicate/reordered entries, same-count replacement, wrong session/tenant/kernel, altered sequence/time/policy commitment and untrusted signer. An authenticated complete interleaved-session snapshot succeeds. Missing set/coverage fields never silently downgrade full verification. Focused future command: cargo test -p chio-acp-proxy --lib compliance_bundle.

## Packet 4: Replace the legacy collector and expose honest configured claims

**Files:** new SQLite receipt_store/session_certificate_read.rs and tests; minimal receipt_store module/export hooks; CLI cert/session_receipts.rs and session_receipts_tests.rs; then cert.rs, cli/types.rs and cli/dispatch/certify_cert.rs after diagnostics handoff.

**Existing core:** with_retained_snapshot/RetainedSnapshot in retained_read.rs:35, authenticated live/archive projection, decode_verified_chio_receipt, explicit ReceiptReadContext, and claim sequence lookup. These should own the collection, not bespoke CLI SQL over an unsigned session index.

**Proposed interface:** collect_retained_session_receipts_read_only(path: &Path, session_id: &str, read_context: &ReceiptReadContext, trusted_key: &PublicKey) -> Result<RetainedSessionReceipts, ReceiptStoreError>. Return stored receipts plus the exact authenticated snapshot coverage; keep the store independent of ACP-Client types.

- [ ] Collect in one authenticated read-only live/archive snapshot, using signed session membership, bounded original-byte decoding and existing archive/checkpoint validation. Preserve the current 100,000-receipt/128-MiB session limits and 1-MiB selected-receipt bound; refuse overflow instead of truncating. Do not instantiate a serving writer, migrate/create tables, claim another owner or substitute unsigned JSON-extracted membership.
- [ ] Label coverage as complete retained history through the pinned snapshot boundary. Later receipts require a new certificate. Whole-lifetime session completeness requires a verified session closure boundary; absence of one is not silently terminal completeness.
- [ ] Add an explicit compliance profile input for generation/full verification and bind its canonical digest in the certificate. Scope/guard/budget claims must be evaluated against that profile. With no profile, expose integrity-only coverage and NotEvaluated scope/guard results; do not emit vacuously true compliance claims. The existing tool-name-prefix check must be described as such or replaced by actual resource semantics; it cannot certify filesystem/network scope.
- [ ] Commit refusal/trace rows in the receipt set while evaluating scope/guard requirements only for the profile's applicable mediated calls. An authenticated nonauthorizing report is not a guard bypass or a spent invocation. Keep the current receipt-count ceiling distinct from monetary-spend proof.

**Acceptance:** CLI generate/full verify works on a genuine SqliteReceiptStore containing multiple interleaved sessions and an archived prefix. Include a 4,097-entry selected session, conflicting signed membership, unsigned index substitution, missing/replaced archive, over-limit refusal, snapshot later-append isolation, and configured scope/guard negatives. A no-profile run never says scope/guard compliance passed. Focused future command: cargo test -p chio-cli --lib session_receipts, followed by the CLI certificate integration test.

## Packet 5: Reuse the default product profile, then qualify only observed boundaries

**Files:** CLI cli/mcp/wrap.rs and product-path tests; API Protect proxy/mediated.rs and reservation tests; their README/consumer-support statements. Avoid editing the actively dirty control-plane guard configuration files.

**Existing interface:** chio_guards::default_runtime_guard_profile() supplies InternalNetworkGuard, AgentVelocityGuard, AdvisoryPipeline and SanitizerHook; kernel.add_guard and set_post_invocation_pipeline install it.

- [ ] Install that existing profile in the direct constructors, preserving execution-nonce and admission configuration. Bind the installed profile to the product's policy identity; do not claim an optional detector was installed.
- [ ] Through the real wrap transport, test pre-invocation denial with no dispatch and secret output sanitization with verifiable hook evidence. Advisory evidence must retain advisory semantics.
- [ ] For API Protect, test the actual caller-reservation boundary and no nonce on guard refusal. Clearly state that this endpoint does not inspect the caller's later external HTTP response. Installing a post hook there does not prove external-response protection. Any such stronger guarantee needs a separately owned output-observation path and tests, not a claim based on a constructor.

**Acceptance:** Product constructor and end-to-end tests identify installed defaults, reject the applicable pre-invocation negative, sanitize wrap output, preserve optional-guard absence as a support limit and keep caller-execution output claims bounded. No authority-bypass finding is inferred solely from an absent optional guard.

## Dependency order and independent work

1. Packet 3's pure bundle module/tests can proceed independently now; merge its compliance.rs hook only after the diagnostics writer hands off. This is the smallest concrete certificate fix.
2. Packet 4's dedicated store reader/module can proceed beside SR2/SR3/SR4 reporting work; coordinate its small receipt_store/lib exports. Its CLI hook waits for cert.rs diagnostics, and its signed coverage feeds Packet 3's final completeness acceptance.
3. Packet 1's credential minimization and existing-owner maintenance module are outside the active storage/diagnostic files. Coordinate configuration hooks with root. Production activation requires the bounded compaction/recovery tests, not merely the old method's presence.
4. Packet 2's kernel recorder can proceed independently; edge/remote integration waits for the MCP accounting/inbox handoff. EV4 can share this recorder without weakening session restrictions.
5. Packet 5's wrap construction is independent. Coordinate API Protect shared product wiring with root and retain its caller-execution limitation. Certificate guard claims depend on real product evidence, not Packet 5's implementation alone.

EV6's signed package/pin/archive repairs are already present and must be preserved. Independent child inclusion, Mercury's separate proof format and deployment signer custody remain separate acceptance obligations. This plan does not mark EV2 or EV6 fully closed, does not declare complete-history/compliance acceptance before the outlined tests, and does not replace final exact-source review or hosted/native/trusted qualification. The preparatory design ran no Cargo checks. Record every implementation regression, owning suite, remaining limitation and exact candidate qualification separately.
