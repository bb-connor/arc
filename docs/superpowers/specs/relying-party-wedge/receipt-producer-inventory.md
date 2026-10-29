# Receipt producer and signed-artifact inventory

Inventoried at origin/main 30f8df80615ba73efa8b2039647a83bf12727856

Planning material for the relying-party wedge (spec sections 7.0, 7.6 item 3, 7.8, 10.3 "M0 task" and 12 "producer inventory checked in"). Nothing here is live. Every `file:line` below refers to the commit above.

## Method

The three raw lists come from the plan's Task 2 commands, run in the worktree at the commit above:

```bash
git grep -n -E "sign_receipt(_with_handle|_relaying_trusted_body)?\(|ChioReceipt::sign(_with_backend|_with_handle|_with_backend_using_handle|_with_bbs|_prepared_with_bbs)?\(" origin/main -- crates sdks ':!**/tests/**' ':!*_tests.rs'
git grep -n "RedactionMode::\(Summary\|Redacted\)" origin/main -- crates sdks ':!**/tests/**'
git grep -n -E "sign_canonical_with_backend|sign_shared_canonical_with_backend|sign_canonical_bytes|sign_canonical\(" origin/main -- crates ':!**/tests/**'
```

plus `git grep -n -E "sign_bytes_with_identity\(|sign_bytes_for_identity\("` for the identity-signing entry points named in the wrapper table scope.

Each hit was classified as test or non-test. A hit is test code when its path is under `tests/`, `benches/`, `examples/` or `fixtures/`, its file is `tests.rs`, `*_test(s).rs` or under a `*_tests/` directory, or it sits inside an item gated by `#[cfg(test)]`, `#[test]` or `#[tokio::test]`, including a module whose `mod` declaration in the parent file carries `#[cfg(test)]`.

First grep at the commit above: 244 hits. 104 are in test paths, 47 sit in in-file test modules, 1 is in a parent-gated test module (`chio-control-plane/src/trust_control/cluster_and_reports.rs:142`, gated at `trust_control.rs:309`), and 27 are not Rust (bindings, generated Swift headers, TypeScript wrappers, READMEs, demo files). That leaves 65 non-test Rust hits. 11 of them are function definitions (`chio-kernel-browser/src/wasm.rs:76,91`, `chio-kernel-core/src/receipts.rs:71,131,225`, `chio-kernel-mobile/src/lib.rs:551,585`, `chio-kernel/src/kernel/evaluator.rs:102`, `chio-kernel/src/kernel/responses/receipt_persistence.rs:80`, `chio-http-core/src/authority.rs:1082`, `chio-acp-proxy/src/interceptor.rs:791`). The remaining 54 are the distinct non-test call sites, and `## Receipt producers` has exactly 54 rows.

The regex also matches `build_and_sign_receipt(` and `self.sign_receipt(`, so kernel response builders and two wrapper methods appear as call sites. Calls reached only through a `use ... as` alias do not match; they are listed under `## Receipt producers outside the first grep`.

## Receipt producers

"Commit order" is the order of commit groups inside the single M1 item 2 PR. `ChioReceiptBody` is one struct, so the format change and every producer land in one squash-merged PR (see Spec gaps, G1): 1 core types and the portable signer, 2 hosted kernel, 3 FFI, WASM and mobile relays, 4 security, control-plane, HTTP and proxy producers, 5 observability, products, harnesses and fixture producers.

"Holds content preimage" is `yes` when the bytes that `content_hash` is computed from are in scope at the signing call; `no` when the producer receives an already-computed hash.

| producer | crate:file:line | signing entry point | holds content preimage (yes/no) | salt source (spec 7.8 row) | commit order |
|---|---|---|---|---|---|
| Portable WYSIWYS signer (recompute then relay) | chio-kernel-core:crates/kernel/chio-kernel-core/src/receipts.rs:99 | `sign_receipt` -> `sign_receipt_relaying_trusted_body` | yes | Portable core: host-supplied `Rng` | 1 |
| Trusted-body relay signer | chio-kernel-core:crates/kernel/chio-kernel-core/src/receipts.rs:189 | `ChioReceipt::sign_with_backend` | no | Portable core: host-supplied `Rng` | 1 |
| Handle-bound signer | chio-kernel-core:crates/kernel/chio-kernel-core/src/receipts.rs:236 | `sign_receipt_with_handle` -> `sign_receipt` | yes | Portable core: host-supplied `Rng` | 1 |
| Compensation terminal receipt | chio-kernel:crates/kernel/chio-kernel/src/kernel/admission_terminal_receipt.rs:175 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Active-response completion terminal receipt | chio-kernel:crates/kernel/chio-kernel/src/kernel/admission_terminal_receipt.rs:418 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Effect obligation failure receipt | chio-kernel:crates/kernel/chio-kernel/src/kernel/effect_obligation.rs:510 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Effect obligation recovery flush | chio-kernel:crates/kernel/chio-kernel/src/kernel/effect_obligation/recovery.rs:489 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Pre-dispatch cleanup fault receipt | chio-kernel:crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs:436 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Reserved-authorization reconciliation | chio-kernel:crates/kernel/chio-kernel/src/kernel/reconciliation.rs:408 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Allow response | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs:110 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Execution-nonce preflight allow | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs:174 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Monetary deny | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs:99 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Pre-execution monetary deny | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs:234 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Local v1 fail-closed deny | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs:297 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Deny response with recording | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs:619 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Pending approval response | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/pending_responses.rs:47 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Kernel receipt builder (authority variant) | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:132 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Cancelled response | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/terminal_responses.rs:57 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Cancelled response (payee binding branch) | chio-kernel:crates/kernel/chio-kernel/src/kernel/responses/terminal_responses.rs:126 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Resource read deny | chio-kernel:crates/kernel/chio-kernel/src/kernel/session_ops.rs:302 | `build_and_sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Session protocol refusal | chio-kernel:crates/kernel/chio-kernel/src/kernel/session_ops/protocol_refusal.rs:271 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Session report | chio-kernel:crates/kernel/chio-kernel/src/kernel/session_ops/reports.rs:145 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Signing task (mpsc channel) | chio-kernel:crates/kernel/chio-kernel/src/kernel/signing_task.rs:1026 | `chio_kernel_core::sign_receipt_with_handle` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Backend receipt signer (hybrid and PQ path) | chio-kernel:crates/kernel/chio-kernel/src/receipt_support/signing.rs:118 | `chio_kernel_core::sign_receipt` | yes | Hosted kernel: OS RNG through the `Rng` seam | 2 |
| Browser WASM public signer | chio-kernel-browser:crates/kernel/chio-kernel-browser/src/pure.rs:174 | `core_sign_receipt` (alias of `chio_kernel_core::sign_receipt`) | yes | Browser and Workers WASM | 3 |
| Mobile UniFFI public signer | chio-kernel-mobile:crates/kernel/chio-kernel-mobile/src/lib.rs:565 | `core_sign_receipt` (alias of `chio_kernel_core::sign_receipt`) | yes | Mobile (UniFFI): OS RNG | 3 |
| C ABI public signer | chio-cpp-kernel-ffi:crates/sdk/chio-cpp-kernel-ffi/src/lib.rs:520 | `core_sign_receipt` (alias of `chio_kernel_core::sign_receipt`) | yes | C ABI: OS RNG inside the library | 3 |
| Cage receipt | chio-cage:crates/security/chio-cage/src/receipt.rs:287 | `ChioReceipt::sign_with_backend_using_handle` | yes | Security producers: host `Rng` | 4 |
| Keyring enterprise receipt projection | chio-control-plane:crates/platform/chio-control-plane/src/keyring_runtime.rs:1145 | `ChioReceipt::sign_with_backend` | yes | Security producers: host `Rng` | 4 |
| Native active-defense evidence receipt | chio-control-plane:crates/platform/chio-control-plane/src/security/adapters/native_evidence.rs:123 | `ChioReceipt::sign_with_backend` | yes (body in scope; `content_hash` is its body digest) | Security producers: host `Rng` | 4 |
| Response simulation receipt | chio-control-plane:crates/platform/chio-control-plane/src/security/response_simulation.rs:312 | `ChioReceipt::sign_with_backend` | yes (report in scope; `content_hash` is its body hash) | Security producers: host `Rng` | 4 |
| SCIM deprovision receipt | chio-control-plane:crates/platform/chio-control-plane/src/trust_control/config_and_public.rs:1536 | `ChioReceipt::sign` (Keypair) | yes | Other std processes: OS RNG through the `Rng` seam (G3) | 4 |
| Verified-fix evidence receipts | chio-control-plane:crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs:1315 | `ChioReceipt::sign` (Keypair) | no | Other std processes: OS RNG through the `Rng` seam (G3) | 4 |
| HTTP decision receipt (`HttpReceipt`, not `chio.receipt.v1`) | chio-http-core:crates/platform/chio-http-core/src/authority.rs:879 | `self.sign_receipt` -> `HttpReceipt::sign` (authority.rs:1117) | no | Other std processes: OS RNG through the `Rng` seam (G3) | 4 (signs `chio.receipt.v1` directly, G4) |
| HTTP final receipt (`HttpReceipt`, not `chio.receipt.v1`) | chio-http-core:crates/platform/chio-http-core/src/authority.rs:895 | `self.sign_receipt` -> `HttpReceipt::sign` (authority.rs:1117) | no | Other std processes: OS RNG through the `Rng` seam (G3) | 4 (signs `chio.receipt.v1` directly, G4) |
| HTTP receipt projection to `ChioReceipt` | chio-http-core:crates/platform/chio-http-core/src/receipt.rs:350 | `ChioReceipt::sign` (Keypair) | yes (projection canonical bytes) | Other std processes: OS RNG through the `Rng` seam (G3) | 4 (deleted, G4) |
| `api protect` sidecar evaluation | chio-api-protect:crates/products/chio-api-protect/src/proxy/sidecar.rs:1133 | `ChioReceipt::sign` (Keypair) | yes | Hosted kernel (`api protect`) | 4 |
| ACP-Client session update (tool call) | chio-acp-proxy:crates/protocol/chio-acp-proxy/src/interceptor.rs:621 | `self.sign_receipt` -> `sign_acp_receipt` | no (relays the audit entry hash) | Other std processes: OS RNG through the `Rng` seam (G3) | 4 |
| ACP-Client session update (tool call update) | chio-acp-proxy:crates/protocol/chio-acp-proxy/src/interceptor.rs:641 | `self.sign_receipt` -> `sign_acp_receipt` | no (relays the audit entry hash) | Other std processes: OS RNG through the `Rng` seam (G3) | 4 |
| ACP-Client kernel signer | chio-acp-proxy:crates/protocol/chio-acp-proxy/src/kernel_signer.rs:554 | `ChioReceipt::sign` (Keypair) | no (relays `entry.content_hash`) | Other std processes: OS RNG through the `Rng` seam (G3) | 4 |
| OTel span receipt exporter | chio-otel-receipt-exporter:crates/observability/chio-otel-receipt-exporter/src/sink.rs:284 | `ChioReceipt::sign` (Keypair) | yes | Other std processes: OS RNG through the `Rng` seam (G3) | 5 |
| Runtime loopback treaty proof receipt | chio-runtime-harness:crates/kernel/chio-runtime-harness/src/treaty.rs:102 | `ChioReceipt::sign` (Keypair) | yes (synthetic outcome label) | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |
| Proof fixture commerce event receipt | chio-cli:crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:2071 | `ChioReceipt::sign` (Keypair) | no (copies `event_sha256`) | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |
| Proof fixture settlement anchor reseal | chio-cli:crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:2955 | `ChioReceipt::sign` (Keypair) | yes | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |
| Proof fixture agent-web re-sign | chio-cli:crates/products/chio-cli/src/cli/dispatch/proof/fixture_agent_web.rs:151 | `ChioReceipt::sign` (Keypair) | no (copies a recorded hash) | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |
| `chio run` call evidence export | chio-cli:crates/products/chio-cli/src/cli/process_host/call_evidence/export.rs:212 | `ChioReceipt::sign` (Keypair) | yes | Hosted kernel (`chio run`) | 5 |
| `chio run` call outcomes export | chio-cli:crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes_export.rs:106 | `ChioReceipt::sign` (Keypair) | yes | Hosted kernel (`chio run`) | 5 |
| `chio run` run evidence export | chio-cli:crates/products/chio-cli/src/cli/process_host/run_evidence/export.rs:197 | `ChioReceipt::sign` (Keypair) | yes | Hosted kernel (`chio run`) | 5 |
| `chio run` swarm bootstrap | chio-cli:crates/products/chio-cli/src/cli/process_host/swarm/requests.rs:30 | `ChioReceipt::sign` (Keypair) | yes | Hosted kernel (`chio run`) | 5 |
| Mercury step receipt | chio-mercury:crates/products/chio-mercury/src/commands/shared/builders.rs:102 | `ChioReceipt::sign` (Keypair) | yes | Other std processes: OS RNG through the `Rng` seam (G3) | 5 |
| Wall receipt | chio-wall:crates/products/chio-wall/src/commands.rs:420 | `ChioReceipt::sign` (Keypair) | yes | Other std processes: OS RNG through the `Rng` seam (G3) | 5 |
| Native conformance suite receipt | chio-conformance:crates/tooling/chio-conformance/src/native_suite.rs:1720 | `ChioReceipt::sign` (Keypair) | yes (fixed literal) | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |
| Attest loopback issuance request | chio-attest-loopback:crates/trust/chio-attest-loopback/src/lib.rs:458 | `ChioReceipt::sign` (Keypair) | yes (vendor output label) | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |
| Attest loopback proof package | chio-attest-loopback:crates/trust/chio-attest-loopback/src/package.rs:54 | `ChioReceipt::sign` (Keypair) | yes (vendor output label) | Harness and fixture: seeded `Rng`, fixture material (G3) | 5 |

Producers marked "no" in the preimage column receive the preimage over their existing channel in M1 item 2; no signing path accepts a caller-supplied hash (spec 2.5 G3). Fixture producers that copy a recorded hash are regenerated from the recorded preimage.

## Receipt producers outside the first grep

Relay paths, exported FFI surfaces and out-of-workspace emitters that the first grep does not reach as Rust call sites. Not counted in the completeness check above.

| producer | file:line | entry point | note |
|---|---|---|---|
| Browser trusted-body relay | crates/kernel/chio-kernel-browser/src/pure.rs:206 | `core_relay_trusted_body` (alias of `sign_receipt_relaying_trusted_body`, imported at pure.rs:12) | holds no preimage; replaced by the preimage-taking relay (spec 7.8) |
| Browser WASM exports | crates/kernel/chio-kernel-browser/src/wasm.rs:76, wasm.rs:91 | `#[wasm_bindgen] sign_receipt`, `sign_receipt_relaying_trusted_body` | call `sign_receipt_pure` and `sign_receipt_relaying_trusted_body_pure` (wasm.rs:99) |
| Mobile trusted-body relay | crates/kernel/chio-kernel-mobile/src/lib.rs:596 | `core_relay_trusted_body` (alias imported at lib.rs:100) | UniFFI export defined at lib.rs:585; UDL at crates/kernel/chio-kernel-mobile/src/chio_kernel_mobile.udl:69,79 |
| C ABI trusted-body relay | crates/sdk/chio-cpp-kernel-ffi/src/lib.rs:545 | `core_relay_trusted_body` (alias imported at lib.rs:23) | holds no preimage |
| TypeScript Workers, Edge and Deno wrappers | sdks/typescript/packages/workers/src/index.ts:46, sdks/typescript/packages/edge/src/index.ts:49, sdks/typescript/packages/deno/src/index.ts:88 | `sign_receipt(bodyJson, signingSeedHex)` over the browser WASM | follow the browser relay change (spec 10.3) |
| Swift bindings | sdks/swift/Sources/chio_kernel_mobile/chio_kernel_mobile.swift:898,908 | UniFFI `sign_receipt`, `sign_receipt_relaying_trusted_body` | generated; regenerated with the mobile change |
| Lambda extension | sdks/lambda/chio-lambda-extension/src/main.rs:392, main.rs:403 | unsigned `EvaluateResponse` with `receipt_kind: "trace_observation"` buffered as `ReceiptRecord` to DynamoDB | emits no signed `chio.receipt.v1`; spec 10.3 "adopt the format or delete the receipt path" applies to an unsigned record |
| HTTP decision and final receipts, second construction path | crates/platform/chio-http-core/src/authority.rs:951, authority.rs:977 | `HttpReceipt::sign` | same artifact as the authority.rs:879 and :895 rows (G4) |
| C ABI bindings (`chio-bindings-ffi`) | crates/sdk/chio-bindings-ffi/src/lib.rs:379, lib.rs:388 | `chio_verify_receipt_json`, `chio_verify_receipt_json_with_trusted_signers` | verifier only; no producer |

## RedactionMode mapping

Every non-test `RedactionMode::Summary` or `RedactionMode::Redacted` site from the second grep (13 sites). Producer rows fix the mode in the signed body; reader rows refuse a receipt whose mode differs. With `RedactionMode` deleted (spec 7.6 item 3), each reader drops its mode check in the same commit as its producer. No producer below has a root policy, so every target is fully committed (spec 7.4, "Producers without a root policy ... emit fully committed receipts").

| file:line | current mode | target (fully committed, or committed with inline fields after inline disclosure exists) | reason |
|---|---|---|---|
| crates/core/chio-core-types/src/receipt/metadata.rs:63 | `Summary` (producer: `ReceiptSemanticFields::trace_detect_only`) | fully committed | constructor used by the ACP-Client kernel signer (crates/protocol/chio-acp-proxy/src/kernel_signer.rs:457); no root policy |
| crates/core/chio-core-types/src/receipt/metadata.rs:75 | `Redacted` (producer: `ReceiptSemanticFields::advisory_only`) | fully committed | no non-test caller at the inventoried commit; the field is deleted with the constructor's mode member |
| crates/kernel/chio-kernel/src/kernel/active_response_coordinator/execution_validation.inc:494 | `Redacted` (reader: `verify_active_response_completion_receipt`) | fully committed | verifies active-defense completion receipts from the native evidence producer; the full body travels in `metadata.active_defense_body`, so the label never meant hidden content |
| crates/kernel/chio-kernel/src/kernel/active_response_coordinator/execution_validation.inc:675 | `Redacted` (reader: `validate_active_response_terminal_executor_receipt`) | fully committed | same producer and reasoning as line 494 |
| crates/kernel/chio-kernel/src/response_simulation_report.rs:130 | `Redacted` (producer: `ResponseSimulationReport::receipt_body`) | fully committed | signed through response_simulation.rs:312; the report rides in `metadata`; no root policy |
| crates/observability/chio-lineage/src/ingest_active_defense.rs:199 | `Redacted` (reader: active-defense lineage ingest) | fully committed | reader of the native evidence receipts |
| crates/observability/chio-otel-receipt-exporter/src/sink.rs:268 | `Summary` (producer: `canonical_receipt_for_span`) | fully committed | sanitized span attributes are the content preimage; no root policy |
| crates/platform/chio-control-plane/src/keyring_runtime.rs:1129 | `Redacted` (producer: `key_enterprise_receipt_to_chio_receipt`) | fully committed | projection of a signed keyring enterprise receipt; no root policy |
| crates/platform/chio-control-plane/src/security/adapters/native_evidence.rs:112 | `Redacted` (producer: `build_signed_receipt`) | fully committed | active-defense evidence receipt; the body digest is the content preimage hash; no root policy |
| crates/platform/chio-control-plane/src/security/adapters/native_evidence.rs:584 | `Redacted` (reader: `verify_native_security_receipt`) | fully committed | reader of the line 112 producer |
| crates/platform/chio-control-plane/src/security/event_consumer/verification.rs:319 | `Redacted` (reader: `verify_receipt_event`, security-event projection) | fully committed | only test code produces this shape at the inventoried commit (event_consumer/tests.rs:318); external receipt-backed producers must emit fully committed receipts |
| crates/security/chio-cage/src/receipt.rs:345 | `Summary` (producer: `prepare_cage_receipt`) | fully committed | cage receipts have no root policy (spec 7.4) |
| crates/security/chio-cage/src/receipt.rs:421 | `Summary` (reader: cage receipt verification) | fully committed | reader of the line 345 producer |

Producers that copy a mode from another value instead of naming a variant, so the second grep does not list them; each loses the member in the same PR: crates/protocol/chio-acp-proxy/src/kernel_signer.rs:507 (`semantics.redaction_mode`), crates/platform/chio-http-core/src/receipt.rs:206,236,316 (`HttpReceipt` field), crates/products/chio-cli/src/cli/dispatch/proof/fixture_agent_web.rs:140 (copied from a recorded receipt), crates/observability/chio-siem/src/sink_projection.rs:217 (`source_redaction_mode` projection field). Generated SDK models also carry the field: crates/core/chio-core-types/src/_generated/chio_wire_v1.rs:32591, sdks/python/chio-sdk-python/src/chio_sdk/_generated/receipt/record_schema.py:249, sdks/typescript/chio-ts/src/invariants/receipt.ts:45, sdks/typescript/packages/ai-sdk/src/client.ts:49.

## Wrapper schema ids

One row per signed canonical-JSON artifact type reached through `Keypair::sign_canonical`, `sign_canonical_with_backend*`, `sign_shared_canonical_with_backend`, `sign_canonical_bytes` or `sign_bytes_with_identity` / `sign_bytes_for_identity` over canonical bytes, at non-test call sites. "yes" means the exact id is in `spec/schemas/registry.json`. "assign" means M1 registers the id with the Rust type: an existing id the artifact already carries (a `schema` member, const or literal), or a new `chio.<name>.v1` id where the artifact carries none. Call sites in `chio proof fixture` generators are listed last.

| signed artifact type | signing helper or call site | wrapper schema_id | registered in registry.json (yes / assign) |
|---|---|---|---|
| `CapabilityToken` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/capability/token.rs:493, token.rs:534, token.rs:699 | `chio.capability.v1` | yes |
| `DelegationLink` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/capability/attenuation.rs:126 | `chio.delegation-link.v1` | assign (new) |
| `GovernedUpstreamCallChainProof` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/capability/governance.rs:272 | `chio.governed-upstream-call-chain-proof.v1` | assign (new) |
| `CallChainContinuationToken` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/capability/governance.rs:453 | `chio.call_chain_continuation.v1` | assign (existing member) |
| `GovernedApprovalToken` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/capability/governance.rs:1364 | `chio.governed-approval-token.v1` | assign (new) |
| `ThresholdApprovalProposal` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/capability/governance.rs:1667 | `chio.threshold-approval-proposal.v1` | yes |
| `SignedDeclassificationGrant` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/core/chio-core-types/src/declassification.rs:47 | `chio.declassification-grant.v1` | yes |
| `ToolManifest` (chio-core-types) | `Keypair::sign_canonical` at crates/core/chio-core-types/src/manifest.rs:75 | none: type deleted in M1 item 1, `chio.manifest.v1` is the one signed manifest | deleted (G9) |
| `ChioReceipt` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/receipt/body.rs:296, body.rs:390, body.rs:417; `sign_canonical_with_backend_for_identity` at body.rs:310; `sign_shared_canonical_with_backend` at crates/kernel/chio-kernel/src/receipt_support/signing.rs:330 | `chio.receipt.v1` | yes |
| `ChildRequestReceipt` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/receipt/lineage.rs:129 | `chio.child-request-receipt.v1` | assign (new) |
| `ReceiptLineageStatement` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/receipt/lineage.rs:356 | `chio.receipt_lineage_statement.v1` | yes |
| `SignedExportEnvelope<T>` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/receipt/lineage.rs:429; `sign_bytes_with_identity` at lineage.rs:439 | the schema id of `T` | per `T` |
| `SignedRecoveryGrant`, `SignedAuthorityCoverageAttestationV1`, `SignedRecoveryProviderFinalityV1` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/core/chio-core-types/src/recovery/authority.rs:68 (`signed_authority!` macro) | `chio.recovery.grant.v1`, `chio.recovery.authority-coverage.v1`, `chio.recovery.provider-finality.v1` | yes |
| `SignedSecurityEvent` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/core/chio-core-types/src/security_event.rs:40 | `chio.signed-security-event.v1` | yes (see G8) |
| `SessionAnchor` | `Keypair::sign_canonical` at crates/core/chio-core-types/src/session/anchor.rs:169 | `chio.session_anchor.v1` | assign (existing member) |
| `AnchorBatch` | `Keypair::sign_canonical` at crates/economy/chio-anchor/src/batch.rs:76 | `chio.anchor_batch.v1` | yes |
| `SignedClearingEnvelopeV1<T>` | `Keypair::sign_canonical` at crates/economy/chio-credit/src/clearing/mod.rs:75 | the `CLEARING_*_SCHEMA` id of `T` (crates/economy/chio-credit/src/clearing/mod.rs:23-35) | yes (every `T`) |
| `SignedAssignmentAgreementV1` | `Keypair::sign_canonical` at crates/economy/chio-credit/src/factor/authorization.rs:700 | `chio.factor.assignment-agreement.v1` | yes |
| `IouEnvelope` | `sign_canonical_with_backend` at crates/economy/chio-credit/src/local_account.rs:186 | `chio.credit.iou-envelope.v1` | assign (existing member) |
| `SignedCreditFacilityBindV1` | `Keypair::sign_canonical` at crates/economy/chio-credit/src/obligation/credit_facility_bind.rs:408 | `chio.credit.facility-bind.v1` | yes |
| `SignedReceivableIou` | `sign_canonical_with_backend` at crates/economy/chio-credit/src/receivable_iou.rs:452 | `chio.credit.receivable-iou-envelope.v1` | yes |
| `Finding` | `Keypair::sign_canonical` at crates/economy/chio-finding/src/validate.rs:353; `sign_canonical_with_backend` at validate.rs:373 | `chio.finding.v1` | yes |
| `ChannelSignatureV1` | `Keypair::sign_canonical` at crates/economy/chio-settle/src/channel/signed.rs:76 | `chio.channel.signature.v1` | assign (existing domain member; no non-test caller) |
| `OracleConversionEvidence` | `Keypair::sign_canonical` at crates/economy/chio-web3/src/anchors.rs:227 | `chio.oracle-conversion-evidence.v1` | yes |
| `SignedAdmissionTerminalProjectionV1` | `Keypair::sign` over domain-prefixed canonical bytes at crates/kernel/chio-kernel/src/admission_operation/remote_projection.rs:291 | `chio.signed-admission-terminal-projection.v1` | assign (existing member) |
| `SignedAuthorityTransition` | `Keypair::sign_canonical` at crates/kernel/chio-kernel/src/authority/replication.rs:225 | `chio.authority-lifecycle.v1` | assign (existing member) |
| `SignedAuthoritySnapshot` | `Keypair::sign_canonical` at crates/kernel/chio-kernel/src/authority/replication.rs:317 | `chio.authority-snapshot.v1` | assign (existing member) |
| `SessionComplianceCertificate` | `sign_canonical_with_backend` at crates/kernel/chio-kernel/src/compliance_certificate.rs:159 | `chio.session-compliance-certificate.v1` | assign (new) |
| `DpopProof` (Chio DPoP) | `sign_canonical_with_backend` at crates/kernel/chio-kernel/src/dpop.rs:148; `Keypair::sign` over canonical bytes at dpop.rs:135 | `chio.dpop_proof.v1` | yes (`chio.dpop_proof.v2` is removed after #1489 in the parallel lead's lane; see G10) |
| `SignedExecutionNonce` | `Keypair::sign_canonical` at crates/kernel/chio-kernel/src/execution_nonce.rs:152; `Keypair::sign` over canonical bytes at crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs:1377 | `chio.execution_nonce.v1` | assign (existing member) |
| `ActiveResponseSubmissionProof` | `sign_bytes_for_identity` over domain-prefixed canonical bytes at crates/kernel/chio-kernel/src/kernel/active_response_admission.rs:100 | `chio.active-response-submission.v1` | assign (existing member) |
| `ActiveResponseArtifactAuthorityAttestation` | `sign_bytes_for_identity` over domain-prefixed canonical bytes at crates/kernel/chio-kernel/src/kernel/active_response_artifact.rs:144 | `chio.active-response-artifact-authority-attestation.v1` | assign (existing member) |
| `SignedContainerLaunchRecord` | `Keypair::sign_canonical` at crates/kernel/chio-process/src/container_launch.rs:108 | `chio.process.container-launch.v1` | assign (existing member) |
| Swarm delegation-witness hop signature | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:249 | `chio.swarm.delegation-witness-hop-signature.v1` | assign (existing const) |
| `SwarmTaskGraph` | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:272 | `chio.swarm.task-graph.v1` | yes |
| `SwarmContinuationToken` | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:295 | `chio.swarm.continuation-token.v1` | yes |
| `SwarmJoinReceipt` | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:373 | `chio.swarm.join-receipt.v1` | yes |
| `SwarmRoutePlanReceipt` | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:552 | `chio.swarm.route-plan-receipt.v1` | yes |
| `SwarmRevocationEpoch` | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:575 | `chio.swarm.revocation-epoch.v1` | yes |
| `SwarmTerminalGraphReceipt` | `Keypair::sign_canonical` at crates/kernel/chio-swarm-authority/src/verifier.rs:598 | `chio.swarm.terminal-graph-receipt.v1` | yes |
| `SignedCertificationCheck` | `Keypair::sign_canonical` at crates/platform/chio-control-plane/src/certify/artifact.rs:286 | `chio.certify.check.v1` | assign (existing const) |
| `FederationPolicyDocument` | `Keypair::sign_canonical` at crates/platform/chio-control-plane/src/evidence_export.rs:971 | `chio.federation-policy.v1` | assign (existing const) |
| `SignedActiveResponseAuthorityRequest` | `sign_bytes_for_identity` over domain-prefixed canonical bytes at crates/platform/chio-control-plane/src/security/active_response_authority/client.rs:197 | `chio.active-response-policy-authority-request.v1` | assign (new; see G6) |
| `SignedActiveResponseAuthorityResponse` | `sign_bytes_for_identity` over domain-prefixed canonical bytes at crates/platform/chio-control-plane/src/security/active_response_authority/protocol.rs:298 | `chio.active-response-policy-authority-response.v1` | assign (new; see G6) |
| `HttpReceipt` | `Keypair::sign_canonical` at crates/platform/chio-http-core/src/receipt.rs:193 | none: type deleted in M1 item 2, HTTP calls sign `chio.receipt.v1` | deleted (G4) |
| `SignedManifest` (chio-manifest `ToolManifest`) | `Keypair::sign_canonical` at crates/platform/chio-manifest/src/lib_parts/part_01.inc:575 | `chio.manifest.v1` | yes |
| `SignedBudgetSnapshotAnchorCommitment` | `Keypair::sign_canonical` at crates/platform/chio-store-sqlite/src/authority.rs:293 | `chio.budget-snapshot-anchor-commitment.v1` | assign (existing literal) |
| `EnterpriseMigrationTransition` | `Keypair::sign_canonical` at crates/platform/chio-store-sqlite/src/enterprise_migration_state.rs:265 | `chio.enterprise-migration-transition.v1` | assign (existing `signature_domain` value) |
| `TransactionPassport` | `Keypair::sign_canonical` at crates/platform/chio-transaction-passport/src/minimal.rs:165 | `chio.transaction-passport.v1` | yes |
| `Signed<Subdivision>`, `Signed<WorkOffer>`, `Signed<Selection>`, `Signed<DispatchPermit>` | `Keypair::sign` over canonical `(DOMAIN, signer, body)` at crates/platform/chio-workflow/src/delegation/types.rs:233 | `chio.work-subdivision.v1`, `chio.work-offer.v1`, `chio.work-selection.v1`, `chio.work-dispatch-permit.v1` | assign (existing `DOMAIN` values, types.rs:198-220) |
| `WorkflowReceipt` and its vendor co-signature | `Keypair::sign_canonical` at crates/platform/chio-workflow/src/receipt.rs:184, receipt.rs:242 | `chio.workflow-receipt.v1` | assign (existing const) |
| `FederatedDelegationPolicyDocument` | `Keypair::sign_canonical` at crates/products/chio-cli/src/admin.rs:699 | `chio.federated-delegation-policy.v1` | assign (existing const) |
| Proof-room trust roots and guard report | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:1332, crates/products/chio-cli/src/cli/dispatch/proof/export.rs:524 | `chio.proof.first-run.trust-roots.v1`, `chio.proof.first-run.guard-report.v1` | yes |
| `SignedMcpCageLaunchPolicy` | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/mcp/cage_policy.rs:510 | `chio.mcp.cage-launch-policy.v1` | yes |
| `SignedProfile` (swarm profile) | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/process_host/swarm.rs:274 | `chio.process.swarm-profile.v1` | assign (existing const) |
| `AgUiReceipt` | `Keypair::sign_canonical` at crates/protocol/chio-ag-ui-proxy/src/receipt.rs:92 | `chio.ag-ui-receipt.v1` | assign (existing const, not a body member) |
| Operator approval `SignedRecord` | `Keypair::sign_canonical` at crates/protocol/chio-mcp-remote/src/remote_mcp/approvals.rs:132 | `chio.mcp.operator-approval.v1` | assign (existing const) |
| Session credential row | `Keypair::sign_canonical` at crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials.rs:329 | `chio.mcp.session-credential.v1` | assign (existing const) |
| Session credential call row | `Keypair::sign_canonical` at crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials.rs:612 | `chio.mcp.session-credential-call.v1` | assign (existing literal) |
| `SignedProvenance` | `sign_canonical_with_backend` at crates/protocol/chio-tool-call-fabric/src/provenance.rs:95 | `chio.provenance-stamp.v1` | assign (new) |
| SDK JSON signer (`sign_json_str_ed25519`) | `Keypair::sign_canonical` at crates/sdk/chio-binding-helpers/src/signing.rs:59 | supplied by the caller, must be registered | none of its own (API gains a schema id argument; see G7) |
| `SignedWatermarkEnvelope` | `sign_bytes` over domain-prefixed canonical bytes at crates/security/chio-decoy/src/watermark.rs:331 | `chio.signed-watermark-envelope.v1` | assign (existing envelope const) |
| `SignedKeyLogCheckpoint` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/checkpoint.rs:203 | `chio.key-log.checkpoint.v1` | yes |
| `SignedKeyActivationCommit` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/checkpoint.rs:345 | `chio.key-log.activation-commit.v1` | yes |
| Key-log witness signature | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/checkpoint.rs:386 | `chio.key-log.witness-statement.v1` | assign (existing const) |
| `SignedKeyEnterpriseReceipt` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/enterprise_receipt.rs:347 | `chio.key-log.enterprise-receipt.v1` | yes |
| `SignedKeyLogEvent` authorizations | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/event.rs:295, event.rs:328 | `chio.key-log.event.v1` | yes |
| `WitnessServiceReadinessProof` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/ipc.rs:261 | `chio.key-log.witness-readiness.v1` | yes |
| `AuditServiceReadinessProof` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/ipc.rs:496 | `chio.key-log.audit-readiness.v1` | yes |
| `KeyringArtifactSignature` fence statement | `sign_bytes_for_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/router.rs:410 | `chio.keyring.artifact-signature.v1` | yes |
| `SignedArtifactTimeAnchor` | `sign_bytes_with_identity` over domain-prefixed canonical bytes at crates/security/chio-keyring/src/time.rs:57 | `chio.key-log.artifact-time-anchor.v1` | yes |
| `SignedBrokerAuditRunnerAuthorization` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/audit.rs:300 | `chio.broker-audit-runner-authorization.v1` | yes |
| `SignedBrokerAuditComparison` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/audit.rs:806 | `chio.broker-audit-comparison.v1` | yes |
| `SignedAuthorityRequest` (broker authority RPC) | `sign_bytes_for_identity` at crates/security/chio-secret-broker/src/authority_ipc.rs:671 | `chio.broker-authority-request.v1` | yes (the artifact's `schema` member carries the unregistered `chio.broker-authority-rpc.v1`, authority_ipc.rs:35; see G6) |
| `SignedAuthorityResponse` (broker authority RPC) | `sign_bytes_for_identity` at crates/security/chio-secret-broker/src/authority_ipc.rs:756 | `chio.broker-authority-response.v1` | yes (same member mismatch as the request; see G6) |
| `SignedBrokerCapability` | `sign_bytes_for_identity` at crates/security/chio-secret-broker/src/capability.rs:31 | `chio.broker-capability.v1` | yes |
| `SignedBrokerPrivilegedAuditChallenge` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/privileged_audit.rs:325 | `chio.broker-privileged-audit-challenge.v1` | yes |
| `RequestProof` | `Keypair::sign_canonical` at crates/security/chio-secret-broker/src/proof.rs:80 | `chio.broker-request-proof.v1` | yes |
| `SignedAdminMutationReceipt` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/provision.rs:115 | `chio.broker-admin-mutation-receipt.v1` | yes |
| `SignedAdminControlReceipt` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/provision.rs:235 | `chio.broker-admin-control-receipt.v1` | yes |
| `SignedBrokerReceipt` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/receipt.rs:336 | `chio.broker-execution-receipt.v1` | yes |
| `SignedBrokerFailureReceipt` | `sign_bytes_with_identity` at crates/security/chio-secret-broker/src/receipt.rs:403 | `chio.broker-execution-failure-receipt.v1` | yes |
| `SignedRegisterAttemptAuthorization` | `sign_bytes_for_identity` at crates/security/chio-secret-broker/src/registration.rs:192 | `chio.broker-register-attempt-authorization.v1` | yes |
| `SignedObservation` | `Keypair::sign_canonical` at crates/tooling/chio-trace-validate/src/observation.rs:207 | `chio.trace-observation.v1` | assign (existing const) |
| `ReputationCredential` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/challenge.rs:171 | `chio.reputation-credential.v1` | assign (new) |
| `SignedCrossIssuerMigration` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/cross_issuer.rs:146 | `chio.cross-issuer-migration.v1` | assign (existing const) |
| `SignedPublicIssuerDiscovery` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/discovery.rs:187 | `chio.public-issuer-discovery.v1` | assign (existing const) |
| `SignedPublicVerifierDiscovery` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/discovery.rs:259 | `chio.public-verifier-discovery.v1` | assign (existing const) |
| `SignedPublicDiscoveryTransparency` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/discovery.rs:322 | `chio.public-discovery-transparency.v1` | assign (existing const) |
| `FinancialCredentialEnvelope` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/financial.rs:332 | the family id from crates/economy/chio-fincred/src/lib.rs:17-25 (five `chio.fincred.*.v1` ids) | yes (all five) |
| `FinancialPassportPresentationResponse` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/financial/agent_passport.rs:533 | `chio.financial-agent-passport-presentation-response.v1` | assign (existing const) |
| `PassportPresentationResponse` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/presentation.rs:21 | `chio.agent-passport-presentation-response.v1` | assign (existing const) |
| `SignedPassportVerifierPolicy` | `Keypair::sign_canonical` at crates/trust/chio-credentials/src/registry.rs:19 | `chio.passport-verifier-policy.v1` | assign (existing const) |
| `PasskeyCapability` | `sign_bytes` over canonical bytes at crates/trust/chio-custody-hw/src/mint.rs:56 | `chio.passkey-capability.v1` | assign (new) |
| `DisclosureCryptoContextReport` | `Keypair::sign_canonical` at crates/trust/chio-disclosure-lineage/src/verifier.rs:159 | `chio.disclosure.crypto-context-report.v1` | yes |
| `DkgPackage` transport signature | `Keypair::sign` over domain-prefixed canonical bytes at crates/trust/chio-federation-authority/src/frost_ceremony.rs:917 | `chio.frost.dkg-package.v1` | assign (existing const) |
| `RelayAlertAssuranceArchivePackageManifest` | `Keypair::sign_canonical` at crates/trust/chio-pheromone-relay/src/archive/package.rs:176 | `chio.pheromone.relay-alert-assurance-archive-package-manifest.v1` | yes |
| `RelayAlertAssuranceExportManifest` | `Keypair::sign_canonical` at crates/trust/chio-pheromone-relay/src/assurance/export.rs:147 | `chio.pheromone.relay-alert-assurance-export-manifest.v1` | yes |
| `PeerDirectoryBundleDocument` | `Keypair::sign_canonical` at crates/trust/chio-pheromone-relay/src/directory.rs:279 | `chio.pheromone.peer-directory-bundle.v1` | yes |
| `PheromoneRelayHttpRequest` | `Keypair::sign_canonical` at crates/trust/chio-pheromone-relay/src/http_signing.rs:152 | `chio.pheromone.relay-http-request.v1` | yes |
| `PheromoneDeposit` | `Keypair::sign` over canonical bytes at crates/trust/chio-pheromone/src/lib.rs:499 | `chio.pheromone-deposit.v1` | yes |
| `TeeBlessAuditEntry` | `Keypair::sign_canonical` at crates/trust/chio-replay-corpus/src/audit.rs:150 | `chio.tee-bless-audit.v1` | assign (new) |
| Proof fixture swarm join receipt | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:722 | `chio.swarm.join-receipt.v1` | yes |
| Proof fixture tool-server ack | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:801 | `chio.runtime.tool-server-ack-signature.v1` | assign (existing literal) |
| Proof fixture terminal receipt (JSON value) | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:2185 | `chio.receipt.v1` | yes |
| Proof fixture public settlement proof bundle | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:2809 | `chio.web3-settlement-proof-bundle.v1` | yes |
| Proof fixture checkpoint statement | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:3022 | `chio.checkpoint_statement.v1` | assign (existing const) |
| Proof fixture payment lifecycle | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:3340 | `chio.commerce.payment-lifecycle.v1` | yes |
| Proof fixture provider-trust artifacts | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:3359 | `chio.commerce.provider-passport.v1`, `chio.commerce.reputation-snapshot.v1`, `chio.commerce.federation-trust-bundle.v1` | yes |
| Proof fixture enterprise approval case | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:5230 | `chio.enterprise.approval-case.v1` | yes |
| Proof fixture risk comptroller report | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:5255 | `chio.risk.comptroller-report.v1` | yes |
| Proof fixture trust-market artifacts | `Keypair::sign_canonical` at crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:5278 | the ten ids listed at fixture.rs:1995-2009 | yes |
| Proof fixture agent-web envelope | `Keypair::sign` over canonical bytes at crates/products/chio-cli/src/cli/dispatch/proof/fixture_agent_web.rs:414 | `chio.agent-web-proof-envelope.v1` | yes |

Helpers and forwarders that carry no artifact type of their own (the wrapper is implemented in or passed through them): crates/core/chio-core-types/src/crypto.rs:205,221 (`Keypair::sign_canonical`, `Keypair::sign_shared_canonical`), crypto.rs:976,990 (trait defaults), crypto.rs:1006,1017,1029,1040 (`sign_canonical_with_backend*`, `sign_shared_canonical_with_backend`), crates/core/chio-core-types/src/signer_binding.rs:32, crates/kernel/chio-kernel/src/kernel/signing_authority.rs:176,184,191, crates/platform/chio-control-plane/src/keyring_runtime.rs:83,94,106, crates/security/chio-keyring/src/router.rs:408 (`sign_bytes_bound`, signs caller bytes verbatim), router.rs:651,658,673, crates/security/chio-secret-broker/src/kernel_admission/registration.rs:252,256.

Test-only sites under `src/` excluded from the table: crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs:1665,1725,1783,2092,2510 (inside `mod tests` at line 1295) and crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_evidence_test_support.rs:176,348 (module gated `#[cfg(test)]`).

Signing-bytes forms at the inventoried commit (input to G5; spec 2.5 drops every prefix below and keeps the `signer` member of the workflow tuple inside the canonical body): plain canonical JSON for most rows; a byte prefix ending in NUL before canonical JSON for chio-keyring, chio-decoy, `SignedDeclassificationGrant`, `SignedSecurityEvent`, the recovery macro, `SignedAdmissionTerminalProjectionV1`, the two kernel active-response artifacts, `SignedBrokerAuditRunnerAuthorization` and `DkgPackage`; canonical JSON of a `{domain, body}` object for the other chio-secret-broker rows and the control-plane active-response authority request and response; canonical JSON of a `(DOMAIN, signer, body)` tuple for chio-workflow `Signed<T>`.

### Signing sites outside the named helpers

Non-test `Keypair::sign` and `SigningBackend::sign_bytes` calls that are not reached through the helpers above. Bytes are named as written at the call site. The resolution column applies spec 2.5 G2: every site signs the wrapper unless its bytes are an exempt external format. Where the column says "per naming rule", M1 item 1 takes the id from the signed type in this order: its existing schema member or constant; else its existing signature-domain string without the NUL when it already has the `chio.<area>.<payload>.v<N>` shape; else `chio.<kebab-case type name without a Signed prefix>.v1`. "unreg." marks an id M1 item 1 registers (G11).

| file:line | signed bytes at the call site | resolution (spec 2.5 G2) |
|---|---|---|
| crates/core/chio-core-types/src/capability/aggregate_invocation.rs:121 | `domain_message(ROOT_SIGNATURE_DOMAIN, &body)` | `chio.aggregate-budget-root.v1` |
| crates/core/chio-core-types/src/capability/cumulative_approval.rs:124 | `domain_message(ROOT_SIGNATURE_DOMAIN, &body)` | `chio.cumulative-approval-root.v1` |
| crates/core/chio-core-types/src/economic_continuity.rs:910 | `self.signing_bytes()` | `chio.economy.state-batch.v1` |
| crates/core/chio-core-types/src/economic_continuity/anchor.rs:256, anchor.rs:1055 | `signing_bytes()` | `chio.economy.anchor-view.v1`; `chio.economy.effect-dispatch-commit.v1` |
| crates/economy/chio-anchor/src/witness/rekor.rs:941 | Rekor envelope (P-256, external format) | exempt (Sigstore Rekor) |
| crates/kernel/chio-kernel/src/admission_operation/execution_nonce/profile.rs:78 | `bytes` | `chio.operation_execution_nonce.v1` (unreg.) |
| crates/kernel/chio-kernel/src/caller_delivery.rs:143, caller_delivery.rs:243 | `bytes`; `bounded_canonical(&body, MAX_REPORT_BYTES)` | `chio.caller-dispatch-authorization.v1`; `chio.caller-delivery-report.v1` |
| crates/kernel/chio-kernel/src/checkpoint/builders.rs:213 | `body_bytes` (kernel checkpoint) | `chio.checkpoint_statement.v1` (unreg.) |
| crates/kernel/chio-kernel/src/stop/config.rs:155, config.rs:285 | `approval_message(config_digest)`; `message` | `chio.stop-operator-config-approval.v1` over the approval object without its signature; `chio.stop-operator-config.v1` (both unreg.) |
| crates/kernel/chio-kernel/src/tool_outcome/release/terminal.rs:255 | `body.signing_bytes()` | the existing `CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA` id |
| crates/platform/chio-control-plane/src/fiscal_runtime_readiness.rs:133 | `.sign(policy, anchor_key)` | per naming rule (fiscal runtime readiness) |
| crates/platform/chio-control-plane/src/security/adapters/native_evidence.rs:134 | `RECEIPT_READINESS_DOMAIN` (fixed readiness probe) | `chio.signer-readiness-probe.v1` (unreg.) over `{"probe": "native_security_receipt", "schema": ...}` |
| crates/platform/chio-control-plane/src/security/response_simulation.rs:234 | `b"chio.response-simulation.readiness.v1\0"` (fixed readiness probe) | `chio.signer-readiness-probe.v1` over `{"probe": "response_simulation", "schema": ...}` |
| crates/platform/chio-control-plane/src/trust_control/finding_operator_purchase.rs:850 | `ask_digest.as_bytes()` | wrapper over the ask body that `ask_digest` is computed from; per naming rule |
| crates/platform/chio-store-sqlite/src/finding_pool_ledger/qualification.rs:535 | `challenge` | `chio.finding-pool.store-identity-proof.v1` (unreg.) over a canonical challenge object |
| crates/platform/chio-store-sqlite/src/fiscal_store.rs:432 | `.sign(proposal, current_charter, signer)` | per naming rule (fiscal proposal admission) |
| crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:1267, crates/products/chio-cli/src/cli/dispatch/proof/export.rs:721 | `signed_payload` | exempt (DSSE PAE, proof-room bundle) |
| crates/products/chio-cli/src/guards/sign.rs:53 | `message` | per naming rule over a canonical module statement replacing the newline-joined `chio-wasm-guard-v1` message; the verifier in chio-wasm-guards changes with it |
| crates/protocol/chio-acp-proxy/src/compliance.rs:514 | `body_bytes` | `chio.compliance.certificate.v1` (unreg.) |
| crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/helpers.rs:36 | JWS signing input (local AS; exempt per spec 7.0) | exempt (JWS) |
| crates/sdk/chio-binding-helpers/src/signing.rs:39 | UTF-8 message from the caller | deleted with `sign_utf8_message_ed25519` (G7) |
| crates/security/chio-keyring/src/router.rs:292 | `canonical` | the schema id of the artifact passed in (the router takes it as an argument) |
| crates/trust/chio-credentials/src/oid4vp.rs:1079, crates/trust/chio-credentials/src/portable_sd_jwt.rs:378 | JWS signing input (exempt per spec 7.0) | exempt (JWS) |
| crates/trust/chio-disclosure-lineage/src/verifier.rs:144 | `digest.as_bytes()` | wrapper over the lineage subgraph body instead of its digest; per naming rule |
| crates/trust/chio-federation-authority/src/frost_ceremony/sealing.rs:322 | `sealed.signing_bytes()` | per naming rule (sealed DKG share) |
| crates/trust/chio-federation/src/bilateral.rs:223, crates/trust/chio-federation/src/bilateral_dsse/sign.rs:69,72,136,139,227, crates/trust/chio-federation/src/bilateral_dsse/typestate_handlers.rs:94, crates/trust/chio-federation-transport-iroh/src/lanes/bilateral.rs:757 | DSSE PAE bytes | exempt (DSSE PAE) |
| crates/trust/chio-federation/src/trust_establishment.rs:396 | `bytes` | `chio.federation-kernel-handshake.v1` (unreg.) |
| crates/trust/chio-revocation-oracle/src/signer.rs:166 | `message` | per naming rule (epoch root); the `chio-revocation-oracle:v1:epoch-root` prefix is dropped |
| crates/trust/chio-tee/src/capture.rs:182 | `payload` | per naming rule (capture frame) |

## Spec gaps found

Each gap below is decided in spec section 2.5 (Decided 2026-10-17, coordinator call; founder may override). The one-line decision follows each gap.

- G1. Spec 13.3 step 2 says committed receipts land "producer by producer in the M0 inventory order, with the format change itself in one PR". `ChioReceiptBody` and `ToolCallAction` are single structs used by all 54 call sites, so changing the fields breaks every producer at compile time. Producer-by-producer PRs are possible only after the format PR, and only for behavior that does not change the struct. This inventory therefore reads "commit order" as commit groups inside the one item 2 PR.
  Decided: one squash-merged PR, commit groups as above, each producer's salt-source wiring in its own commit.
- G2. Spec 7.0 covers "every Chio signature over a canonical-JSON body", but the plan's Task 2 helper list (`sign_canonical_with_backend*`, `sign_shared_canonical_with_backend`, `sign_canonical_bytes`, `sign_bytes_with_identity`, `Keypair` canonical signing) misses raw `Keypair::sign` and `sign_bytes` over canonical or domain-prefixed bytes, including the kernel checkpoint (crates/kernel/chio-kernel/src/checkpoint/builders.rs:213), which spec 7.0 names. Those sites are listed under "Signing sites outside the named helpers". M1 item 1 has to resolve each to an artifact type and an id. The spec also does not say whether DSSE PAE signatures (chio-federation bilateral), detached digest or challenge signatures, and fixed readiness probes are exempt like JWS or must be wrapped.
  Decided: wrap every signature over Chio-defined bytes; exempt only JWS, DSSE PAE, Sigstore Rekor and RFC 9421 HTTP message signatures; readiness probes use `chio.signer-readiness-probe.v1`; the raw-site table above carries each resolution.
- G3. The spec 7.8 salt-source table has no row for these producers: chio-acp-proxy, chio-http-core, chio-otel-receipt-exporter, chio-mercury, chio-wall, chio-runtime-harness, chio-conformance native suite, chio-attest-loopback, the `chio proof fixture` generators, and the trust-control SCIM and verified-fix receipts. Each needs a salt source, or a decision that it is deleted or becomes a test fixture.
  Decided: salts come from the signing process's `Rng` seam (OS RNG in std processes, seeded `Rng` in harness and fixture producers); hash-only producers receive the preimage.
- G4. `HttpReceipt` (crates/platform/chio-http-core/src/receipt.rs:190) is a separate signed artifact. It carries `content_hash` and `redaction_mode` and has no schema id. Spec 7.6 changes `chio.receipt.v1` "protocol-wide" but does not say whether `HttpReceipt` changes the same way or is deleted in favor of its `ChioReceipt` projection (receipt.rs:350). The ACP-Client proxy and SCIM paths have the same problem: they relay or compute hashes without the preimage the committed format needs.
  Decided: `HttpReceipt` is a receipt and is deleted; HTTP calls sign `chio.receipt.v1` directly with the request as parameter preimage and the response as content preimage.
- G5. Spec 7.0 says `canonical_body` is "exactly the bytes signed today". For the domain-prefixed rows (byte prefix, `{domain, body}` object or `(DOMAIN, signer, body)` tuple), the bytes signed today are not canonical JSON of the artifact body. The spec has to choose: keep each legacy prefix inside the wrapped body, or drop the prefixes and let the wrapper's schema id carry separation. "No legacy" points to dropping them, but the spec does not say so.
  Decided: drop every signature prefix; the wrapper's schema id is the only signature domain; the workflow tuple's `signer` stays in the canonical body.
- G6. Two request and response pairs share one `schema` member value and are separated today only by their domain strings: the control-plane active-response authority (`chio.active-response-policy-authority.v1`) and the secret-broker authority RPC (`chio.broker-authority-rpc.v1`, unregistered, while the registry already lists `chio.broker-authority-request.v1` and `chio.broker-authority-response.v1` at registry.json:2510,2517). If G5 drops the prefixes, the wrapper needs distinct ids for request and response. The table uses the registered broker ids and assigns `chio.active-response-policy-authority-request.v1` and `...-response.v1`. The four `SignedKeyLogEvent` authorization roles sign the same body under one id; that is safe only if the role is a member of the signed body.
  Decided: request and response get distinct ids (registered broker ids; new active-response authority ids); `schema` members change to match; the four key-log roles keep `chio.key-log.event.v1`.
- G7. `chio-binding-helpers` `sign_json_str_ed25519` (signing.rs:59) signs arbitrary caller JSON for the FFI and SDK bindings. Under the wrapper it needs a schema id argument, and verifiers on the other side must agree on it. The spec does not cover generic SDK signing.
  Decided: the generic signer takes a registered schema id; the raw UTF-8 signer is deleted.
- G8. The registry lists both `chio.security-event-body.v1` and `chio.signed-security-event.v1` for one signature. Spec 7.0 says "the artifact's registered schema id", which is ambiguous here. The table uses the signed-artifact id, following the `chio.receipt.v1` precedent.
  Decided: `chio.signed-security-event.v1`; M0 PR 4 removes the `chio.security-event-body.v1` registry row.
- G9. Two different `ToolManifest` types are signed: chio-core-types (no schema id, manifest.rs:75) and chio-manifest (`chio.manifest.v1`, part_01.inc:575). The table assigns the core type its own id. Collapsing the two types would follow the no-dual-API rule better than registering a second id.
  Decided: delete the core-types `ToolManifest`; `chio.manifest.v1` is the one signed manifest.
- G10. The registry still lists `chio.dpop_proof.v2` beside `chio.dpop_proof.v1` (registry.json:2712,2718). #1489 is open at the inventoried commit, so the DPoP row uses `chio.dpop_proof.v1` and must be rechecked when #1489 lands.
  Decided: `chio.dpop_proof.v1`; the v2 removal follows #1489 in the parallel lead's lane.
- G11. 37 rows of the wrapper table carry a schema id that is not in `registry.json` (35 outside the proof fixtures), and 13 rows get a new id: 11 artifact types that carry no id at all, plus the two active-response authority messages that share one (G6). Spec 7 says new signed ids are registered; it does not say that existing unregistered ids are registered before the wrapper lands. The wrapper cannot bind an unregistered id.
  Decided: register every missing id with its Rust type and schema in M1 item 1, in the wrapper PR, not in M0.
- G12. The verdict-matrix reason codes proposed in plan Task 3 use URN domains (`root-exchange`, `root-anchor`, `root-policy`, `receipt`, `export`) that are not among the 20 domains in `spec/errors/registry.yaml`. Revocation-store failures report the non-URN code `CHIO-KERNEL-REVOCATION-STORE` (crates/kernel/chio-kernel/src/kernel/error.rs:788), so no "existing revocation-store error code" URN exists. See `verdict-matrix/README.md`.
  Decided: no new domain; codes move into `transport`, `capability`, `policy` and `attest`; `CHIO-KERNEL-REVOCATION-STORE` becomes `urn:chio:error:kernel:revocation-store` in M1 item 5.
