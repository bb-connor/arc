# PR #1160 work board

Status values: `open`, `in-progress`, `ready` (commit waiting for integration), `integrated`, `disputed`, `wontfix`, `deferred`.
Scope: `now` must land in #1160; `later` goes to a follow-up PR after landing.
Owners are claude's initial proposal from 2026-10-06; codex may contest any row by setting `disputed` and explaining in `to-claude.md`.
`codex-id` maps an item to the readiness-plan IDs (RP2, PB4, SR2, ...) where they overlap.

| ID | Sev | Owner | Scope | Status | Commit | codex-id | Item |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F001 | P0 | claude | now | open | | | Fix Darwin ACL scan: acl_get_entry returns 0 on success, so ACLs pass (`crates/security/chio-keyring/src/lib.rs:581`) |
| F002 | P1 | claude | now | open | | | Complete pre-dispatch compensation for settled prepayments and Settling releases (`crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs:1788`); proposed: codex may keep it (adjacent to its terminal.rs batch) |
| F003 | P1 | claude | now | open | | | Stop one unrecoverable admission from failing every later tool call (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs:358`); proposed: codex may keep it (adjacent to its terminal.rs batch) |
| F004 | P1 | claude | now | open | | | Replay durable settlement from the persisted disposition, not a live FX quote (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs:93`); proposed: codex may keep it (adjacent to its terminal.rs batch) |
| F005 | P1 | claude | now | open | | | Settle over-reported or unconvertible costs instead of failing finalization (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs:103`); proposed: codex may keep it (adjacent to its terminal.rs batch) |
| F006 | P1 | claude | now | open | | | Stop a post-commit clock error from permanently closing the receipt writer (`crates/platform/chio-store-sqlite/src/receipt_store/writer_accounting.rs:174`) |
| F007 | P1 | claude | now | open | | | Stop a backed-off declassification receipt from halting response planning (`crates/platform/chio-control-plane/src/security/scheduler_worker/outbox.rs:228`) |
| F008 | P1 | claude | now | open | | | Reject weak Ed25519 lifecycle keys and verify key-log signatures strictly (`crates/security/chio-keyring/src/event.rs:739`) |
| F009 | P1 | claude | now | open | | | Late witness signature on an activated checkpoint bricks the key-log store (`crates/security/chio-keyring/src/sqlite_parts/part_01.rs:362`) |
| F010 | P1 | claude | now | open | | | Witness ignores retained gossip when deciding whether to sign a candidate (`crates/security/chio-keyring/src/witness.rs:277`) |
| F011 | P1 | claude | now | open | | | Stop treating a missing or disabled credential as a fatal broker fault (`crates/security/chio-secret-broker/src/encrypted_blob_backend.rs:412`) |
| F012 | P1 | claude | now | open | | | Reject hard-linked descendants of forbidden directories at admission (`crates/security/chio-cage/src/lib.rs:1131`) |
| F013 | P1 | claude | now | open | | | Assemble Cohere tool calls from content instead of trusting tool-call-end (`crates/protocol/chio-cohere-tools-adapter/src/streaming.rs:38`) |
| F014 | P1 | claude | now | open | | | Gate every client-executed Responses tool item, not only function_call (`crates/protocol/chio-openai-adapter/src/streaming.rs:166`) |
| F015 | P1 | claude | now | open | | | Stop following host-planted symlinks when writing Hermes launcher evidence (`sdks/python/chio-hermes/src/chio_hermes/restricted.py:430`) |
| F016 | P2 | codex | now | open | | | Process bounded active-response recovery batches instead of refusing them (`crates/kernel/chio-kernel/src/kernel/admission_cleanup.rs:305`) |
| F017 | P2 | codex | now | open | | | Keep a released DPoP proof spent for every other operation (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/dpop_custody.rs:39`) |
| F018 | P2 | codex | now | open | | | Refuse a second native capture after a failed attempt (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/capture.rs:65`) |
| F019 | P2 | codex | now | open | | | Select caller start and report operations by operation id, not bare request_id (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs:95`) |
| F020 | P2 | codex | later | open | | | Release the admission mutation lock before payment rail and oracle calls (`crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs:188`) |
| F021 | P2 | codex | now | open | | | Verify a durably bound execution nonce at its binding time after approval (`crates/kernel/chio-kernel/src/kernel/credential_reservation/native_dispatch.rs:221`) |
| F022 | P2 | codex | now | open | | | Run pre-dispatch cleanup even when the deny timestamp read fails (`crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs:1274`) |
| F023 | P2 | codex | now | open | | | Terminalize the dispatch-committed operation when its return cannot be recorded (`crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs:1892`) |
| F024 | P2 | codex | now | open | | | Reserve chio_runtime metadata so host input cannot drive reservation release (`crates/kernel/chio-kernel/src/kernel/mod.rs:152`) |
| F025 | P2 | codex | now | open | | | Enforce reserved receipt metadata on session tool-call entrypoints (`crates/kernel/chio-kernel/src/kernel/session_ops.rs:819`) |
| F026 | P2 | codex | now | open | | | Restore the threshold claim when a session tool call is cancelled (`crates/kernel/chio-kernel/src/kernel/session_ops/nested_tool_call.rs:147`) |
| F027 | P2 | codex | now | open | | | Retire or harden the legacy public governed active-response commit path (`crates/kernel/chio-kernel/src/governed_active_response.rs:249`) |
| F028 | P2 | codex | now | open | | | Do not compensate an existing governed operation on a transient prepare error (`crates/kernel/chio-kernel/src/kernel/active_response_coordinator.rs:144`) |
| F029 | P2 | codex | now | open | | | Enforce the active-response enable flag on admission and execution paths (`crates/kernel/chio-kernel/src/kernel/active_response_policy.rs:339`) |
| F030 | P2 | codex | now | open | | | Reconcile approval-committed operations before startup recovery compensates them (`crates/kernel/chio-kernel/src/kernel/admission_cleanup.rs:661`) |
| F031 | P2 | codex | now | open | | | Restore the loom gate on receipt_store so the kernel loom lane compiles (`crates/kernel/chio-kernel/src/lib.rs:130`) |
| F032 | P2 | claude | now | open | | | Take mailbox lease time from the kernel authority clock, not SystemTime (`crates/kernel/chio-process/src/mailboxes/mod.rs:281`) |
| F033 | P2 | claude | now | open | | | Deliver verdict and receipt when a worker response exceeds the frame cap (`crates/kernel/chio-process/src/worker.rs:333`) |
| F034 | P2 | claude | now | open | | | Bound swarm graph size before recursive DFS and before signature check (`crates/kernel/chio-swarm-authority/src/verifier/graph.rs:271`) |
| F035 | P2 | claude | now | open | | | Create the security-state database privately instead of with umask permissions (`crates/platform/chio-store-sqlite/src/security_state.rs:237`) |
| F036 | P2 | claude | now | open | | | Refuse symlinked or hard-linked security-state paths before migrating them (`crates/platform/chio-store-sqlite/src/security_state.rs:245`) |
| F037 | P2 | claude | now | open | | | Bind session throttle windows to the store's trusted clock and reject regressions (`crates/platform/chio-store-sqlite/src/security_state/session_throttle.rs:884`) |
| F038 | P2 | codex | later | open | | | Index the caller sibling-share snapshot instead of verifying every live operation (`crates/platform/chio-store-sqlite/src/admission_operation_store/caller_budget.rs:24`) |
| F039 | P2 | codex | now | open | | | Add compaction or rotation before the native journal cap halts native security (`crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/history/ordered.rs:71`) |
| F040 | P2 | codex | later | open | | | Restore a SQL bound on the recovery page scan (`crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs:1186`) |
| F041 | P2 | codex | later | open | | | Surface exhausted SIEM alerts and drive delivery from the host (`crates/platform/chio-control-plane/src/security/adapters/native_evidence.rs:972`) |
| F042 | P2 | codex | later | open | | | Let correlation ingress survive producer key rotation and poison events (`crates/platform/chio-control-plane/src/security/event_consumer/ingress.rs:78`) |
| F043 | P2 | codex | later | open | | | Move full-history SQLite audits, IPC and signing out of per-event readiness (`crates/platform/chio-control-plane/src/security/event_consumer/recovery.rs:1082`) |
| F044 | P2 | codex | later | open | | | Pin receipt-backed event producers to a policy version (`crates/platform/chio-control-plane/src/security/event_consumer/verification.rs:264`) |
| F045 | P2 | codex | later | open | | | Reject producer tenants that the single-tenant scheduler cannot expire (`crates/platform/chio-control-plane/src/security/orchestration.rs:792`) |
| F046 | P2 | claude | now | open | | | Stop the per-tick Running state from masking a degraded worker in readiness (`crates/platform/chio-control-plane/src/security/scheduler_worker/worker.rs:132`) |
| F047 | P2 | codex | now | open | | | Authenticate before json_ingress buffers and DOM-parses 128 MiB bodies (`crates/platform/chio-control-plane/src/trust_control/json_ingress.rs:221`) |
| F048 | P2 | codex | now | open | | | Pass the kernel authority clock into the pinned remote capability authority (`crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_authority.rs:57`) |
| F049 | P2 | claude | now | open | | | Reject weak Ed25519 cage-policy signers and verify the policy strictly (`crates/products/chio-cli/src/cli/mcp/cage_policy.rs:885`) |
| F050 | P2 | claude | now | open | | | provision flag silently re-provisions an empty witness when its DB is missing (`crates/security/chio-keyring/src/bin/chio-keylog-witness.rs:44`) |
| F051 | P2 | claude | now | open | | | Authenticate witness and audit socket peers; chmod-after-bind leaves a window (`crates/security/chio-keyring/src/ipc.rs:1477`) |
| F052 | P2 | claude | now | open | | | Witness persists checkpoints past an already-decided candidate and cannot restart (`crates/security/chio-keyring/src/witness.rs:244`) |
| F053 | P2 | claude | now | open | | | Preallocate the outbound request head so the credential is never reallocated (`crates/security/chio-secret-broker/src/generic_https/rustls_transport.rs:216`) |
| F054 | P2 | claude | now | open | | | Contain authority and lookup failures inside one privileged audit session (`crates/security/chio-secret-broker/src/privileged_audit.rs:760`) |
| F055 | P2 | claude | now | open | | | Reclaim expired mobile challenges before refusing issuance at capacity (`crates/trust/chio-custody-hw/src/mobile_challenge/sqlite.rs:261`) |
| F056 | P2 | claude | now | open | | | Validate the broker IPC socket type before granting sendto and sendmsg (`crates/security/chio-cage/src/lib.rs:910`) |
| F057 | P2 | claude | now | open | | | Create missing write grants owned by the target execution identity (`crates/security/chio-cage/src/linux.rs:456`) |
| F058 | P2 | claude | now | open | | | Reject group- or other-writable runtime files regardless of mode bits (`crates/security/chio-cage/src/linux.rs:527`) |
| F059 | P2 | claude | now | open | | | Close the absolute-path execveat bypass of the fd-255 exec rule (`crates/security/chio-cage/src/seccomp.rs:116`) |
| F060 | P2 | claude | later | open | | | Feed tool arguments to the credential, file, cookie, and hostname tripwires (`crates/security/chio-security-kernel/src/tripwire.rs:286`) |
| F061 | P2 | claude | now | open | | | Keep external-guard breaker and cache on monotonic time across wall-clock steps (`crates/guards/chio-guards/src/external/cache.rs:38`) |
| F062 | P2 | codex | now | open | | | Decode unsigned ACP envelopes with document semantics, not signed-number rules (`crates/protocol/chio-acp-proxy/src/input.rs:15`) |
| F063 | P2 | claude | now | open | | | Use Gemini FunctionCall.id instead of the tool name as request identity (`crates/protocol/chio-gemini-tools-adapter/src/adapter.rs:263`) |
| F064 | P2 | claude | now | open | | | Validate the Gemini model segment before building the request path (`crates/protocol/chio-gemini-tools-adapter/src/transport.rs:46`) |
| F065 | P2 | codex | now | open | | | Stop the unauthenticated MCP rate limiter from locking out all new clients (`crates/protocol/chio-mcp-remote/src/rate_limit.rs:72`) |
| F066 | P2 | codex | now | open | | | Close POST streams when the session worker dies instead of waiting forever (`crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs:481`) |
| F067 | P2 | codex | now | open | | | Bound remote MCP durable records at write time to the 8 MiB reopen limit (`crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials.rs:586`) |
| F068 | P2 | claude | now | open | | | Reconcile response.completed output with the evaluated tool calls (`crates/protocol/chio-openai-adapter/src/streaming.rs:290`) |
| F069 | P2 | claude | now | open | | | Reject mistyped x-chio security extensions instead of ignoring them (`crates/protocol/chio-openapi/src/extensions.rs:99`) |
| F070 | P2 | claude | later | open | | | Specify the newly enforced bind_security_context caveat in the protocol (`crates/core/chio-core-types/src/capability/caveat.rs:88`) |
| F071 | P2 | claude | later | open | | | Align the active-response plan schema with the tightened Rust validator (`crates/core/chio-core-types/src/capability/governance.rs:987`) |
| F072 | P2 | codex | now | open | | | Register the error URNs that new error types emit (`crates/kernel/chio-kernel/src/dpop/error.rs:60`) |
| F073 | P2 | codex | now | open | | | Fix admin override audit: mirror contexts never exist on the real merge commit (`.github/workflows/admin-override-audit.yml:36`); landing blocker L2 |
| F074 | P2 | codex | now | open | | | Stop routine CI cancellations and advisory lanes from tombstoning authority (`.github/workflows/ci.yml:29`) |
| F075 | P2 | codex | later | open | | | Vendor or snapshot apk inputs so the trusted image survives Alpine updates (`deploy/docker/Dockerfile.security-evidence-runner:7`) |
| F076 | P2 | codex | now | open | | | Replace default-allow seccomp denylist with Docker's default plus restrictions (`deploy/docker/security-evidence-seccomp.json:2`) |
| F077 | P2 | codex | now | open | | | Verify that required contexts posted on the test merge commit can gate a PR (`docs/security/committed-linux-evidence.md:325`) |
| F078 | P2 | codex | now | open | | | Reconcile documented ruleset with the required merge-commit landing (`docs/security/committed-linux-evidence.md:351`); landing blocker L1 |
| F079 | P2 | codex | now | open | | | Drop the nine [patch.crates-io] forks that no lockfile selects (`Cargo.toml:254`) |
| F080 | P2 | codex | later | open | | | Gate fork integrity by reconstruction and run live fork regressions in CI (`scripts/check-linux-enforcement-stack.py:120`) |
| F081 | P2 | codex | now | open | | | Stop expiring size allowlists on vendored regress tests (`scripts/check-rust-file-hygiene.py:568`) |
| F082 | P2 | claude | now | open | | | Correct supply-chain reviews that claim unused forks are selected (`supply-chain/reviews/regress-0.11.1.md:24`) |
| F083 | P2 | claude | now | open | | | Bind Docker quickstart ports to loopback or drop well-known default tokens (`examples/docker/compose.yaml:12`) |
| F084 | P2 | claude | now | open | | | Decode Go ReceiptRecord with the strict protocol decoder like other primitives (`sdks/go/chio-go-http/types_generated_test.go:65`) |
| F085 | P2 | claude | now | open | | | Raise chio-hermes floor to the chio-sdk-python release it now requires (`sdks/python/chio-hermes/pyproject.toml:34`) |
| F086 | P2 | claude | later | open | | | Add known_outcome_only and prepare_invocation to the TS process client (`sdks/typescript/packages/process/index.mjs:41`) |
| F087 | P3 | codex | later | open | | | Delete the unreferenced recovery .inc and the cfg(any()) blocks (`crates/kernel/chio-kernel/src/kernel/admission_cleanup/recovery_and_compensation.inc:1`) |
| F088 | P3 | codex | later | open | | | Report a missing execution nonce as a nonce denial, not an internal bug (`crates/kernel/chio-kernel/src/kernel/nonce_admission.rs:236`) |
| F089 | P3 | codex | later | open | | | Remove the duplicated cfg attribute on security_admission_operation (`crates/kernel/chio-kernel/src/lib.rs:93`) |
| F090 | P3 | codex | later | open | | | Fix the stale comment that says NULL-tenant receipts are visible in compat mode (`crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/schema.rs:546`) |
| F091 | P3 | claude | later | open | | | Remove 24 unused macOS-only imports that fail clippy -D warnings on macOS (`crates/platform/chio-store-sqlite/src/security_state/lineage_fence.rs:2`) |
| F092 | P3 | codex | later | open | | | Remove or wire the duplicate security admission operation store (`crates/platform/chio-store-sqlite/src/admission_operation_store/part_01.inc:109`) |
| F093 | P3 | codex | later | open | | | Let the per-capability usage listing use the primary-key index (`crates/platform/chio-store-sqlite/src/budget_store/store.rs:1117`) |
| F094 | P3 | codex | later | open | | | Drop deny_unknown_fields from Serialize-only signing structs (`crates/platform/chio-control-plane/src/security/active_response_authority.rs:253`) |
| F095 | P3 | codex | later | open | | | Use the OS RNG for authority request ids instead of generating a keypair (`crates/platform/chio-control-plane/src/security/active_response_authority/client.rs:187`) |
| F096 | P3 | codex | later | open | | | Replace the hand-rolled lowercase hex decoder with the hex crate (`crates/platform/chio-control-plane/src/security/active_response_validation.rs:22`) |
| F097 | P3 | codex | later | open | | | Zeroize authority seed material in the keyring seed handoff (`crates/platform/chio-control-plane/src/keyring_runtime.rs:1326`) |
| F098 | P3 | codex | later | open | | | Check DT_NEEDED objects against --runtime-file as the doc comment promises (`crates/products/chio-cli/src/cli/mcp/provision.rs:554`) |
| F099 | P3 | codex | later | open | | | Chmod provisioned artifacts through the open handle, not the path (`crates/products/chio-cli/src/cli/mcp/provision.rs:1824`) |
| F100 | P3 | claude | later | open | | | Replace tautological file-mode test with a call into the validator (`crates/security/chio-keyring/src/lib.rs:767`) |
| F101 | P3 | claude | later | open | | | Wipe witness seed with zeroize on every path and check mode before reading (`crates/security/chio-keyring/src/service.rs:116`) |
| F102 | P3 | claude | later | open | | | Use one half-open expiry interval for proofs, nonces and key windows (`crates/security/chio-secret-broker/src/proof.rs:121`) |
| F103 | P3 | claude | later | open | | | Restore default signal dispositions before target exec (`crates/security/chio-cage-init/src/sandbox.rs:7`) |
| F104 | P3 | claude | later | open | | | Constrain ioctl requests in the target seccomp profiles (`crates/security/chio-cage/src/seccomp.rs:30`) |
| F105 | P3 | codex | later | open | | | Validate structured-classification field paths with document number semantics (`crates/guards/chio-data-guards/src/structured_classification.rs:183`) |
| F106 | P3 | claude | later | open | | | Refuse plaintext provider base URLs when credentials are attached (`crates/protocol/chio-provider-adapter-core/src/http.rs:411`) |
| F107 | P3 | claude | later | open | | | Fix map_http_status docs that claim Retry-After is honored (`crates/protocol/chio-provider-adapter-core/src/http.rs:654`) |
| F108 | P3 | codex | later | open | | | Refresh stale generated-header path and Kani MSRV comments (`crates/core/chio-core-types/Cargo.toml:7`) |
| F109 | P3 | codex | later | open | | | Use fixed-width integers for MerkleConsistencyProof sizes on the wire (`crates/core/chio-core-types/src/merkle.rs:373`) |
| F110 | P3 | codex | later | open | | | List dpop_proof in the WIRE_PROTOCOL AgentMessage field table (`spec/WIRE_PROTOCOL.md:121`) |
| F111 | P3 | codex | later | open | | | Restore or retire the dropped PR-tier loom protocol-primitive gate (`.github/workflows/ci.yml:99`) |
| F112 | P3 | codex | later | open | | | Match secret references structurally in the CI contract checker (`scripts/check-security-ci-contract.py:1694`) |
| F113 | P3 | codex | later | open | | | Attribute the shipped seccompiler fork in NOTICE (`NOTICE:24`) |
| F114 | P3 | claude | later | open | | | Make reference-swarm post-run bundle verification affect the result (`examples/reference-swarm/src/main.rs:156`) |
| F115 | P3 | claude | later | open | | | Record an event instead of hot-requeueing Jobs with invalid subject keys (`sdks/k8s/controller/internal/reconciler/job_reconciler.go:236`) |
