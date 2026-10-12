# chio-kernel architecture

## Responsibility and boundary

`ChioKernel` owns native host mediation state and coordinates capability
verification, guard evaluation, invocation custody, registered tool dispatch,
output handling and signed receipt projection. `KernelConfig` carries signing
identity, trusted CA keys, policy hash, stream limits, persistence requirements,
memory limits and deadlines. `try_new` validates deadline configuration.

Public integration contracts include `Guard`, `ToolServerConnection`,
`CapabilityAuthority`, `BudgetStore`, `ReceiptStore`, `RevocationStore` and
`AdmissionOperationStore`. Hosts install implementations and configure trusted
security context. `ToolCallRequest` enters mediation; `ToolCallResponse` contains
the verdict, receipt and permitted output. `KernelError` represents failures
that cannot be returned as a completed decision.

The host owns process isolation, transport authentication, authority selection,
store deployment and connector implementation. Registering a connection does
not sandbox its implementation. Portable cryptographic verification and budget
registry primitives live in `chio-kernel-core`.

## Structure

- `kernel/kernel_struct.rs` defines configuration, deadline and memory limits.
- `kernel/construction.rs` builds the kernel and installs stores, guards,
  connections, signing and settlement runtimes.
- `kernel/validation.rs` implements verifier integration, revocation checks,
  grant/budget helpers and receipt-log access.
- `kernel/governed_validation.rs` validates approval, assurance, transaction,
  autonomy and metered billing inputs.
- `kernel/evaluation/` owns normal and nested mediation, credential preparation,
  dispatch commitment, caller execution and return recording.
- `kernel/dispatch.rs` implements dispatch and payment-related helpers.
- `kernel/responses/` builds decisions, finalizes output and persists receipts.
- `admission_operation`, `security_admission_operation`, `caller_delivery`,
  `execution_nonce` and `dpop` define retained admission and credential custody.
- `session` tracks logical sessions, requests and terminal-state admission.
- `receipt_support`, `checkpoint`, `receipt_store` and `evidence_export` support
  signing, evidence storage, Merkle checkpoints and export.
- `payment`, `budget_store` and private `settlement_routing` handle financial
  authorization, accounting and receipt-triggered settlement observation.

Under `cfg(loom)`, only the real session module remains compiled. Runtime-bearing
modules and their dependencies are excluded from that concurrency model.

## Data and control flow

`evaluate_tool_call` enters the scoped async evaluation pipeline. Admission
checks include emergency stop, resource pressure, persistence readiness,
capability verification, subject/grant binding, revocation, governed constraints,
credential handling and applicable runtime/security hooks. Input guards produce
evidence that becomes part of the signed decision.

Budget and credential custody follow the selected admission profile. Durable
operations retain original request bindings and state transitions. Dispatch
revalidates current authority and session state before invoking a registered
connection. `ToolInvocationContext` binds a connector invocation to admitted
identity and request information without exposing signing material.

Returned values or bounded streams pass through output handling and
`PostInvocationPipeline`. Receipt signing binds the selected policy, decision,
evidence and content preimage. Errors after an external effect require retained
outcome and recovery handling appropriate to the configured admission profile;
a failed acknowledgement does not prove that an effect or write never occurred.

## Trust and invariants

The portable signer recomputes `content_hash` from canonical content bytes and
refuses mismatches before signing. Value outputs use RFC 8785 canonical JSON;
stream receipts use their chunk-digest preimage. Signing identity and capability
issuance authority have separate configuration and verification responsibilities.

Strict settings require receipt and revocation readiness before tool effects.
Construction uses an in-memory budget store and leaves durable admission runtime,
receipt store and settlement observer uninstalled. Ephemeral opt-ins permit local
scaffolds. They do not establish persistence across restart.

`record_chio_receipt_during_trace_transition` serializes receipt writes. When a
store exists, append acknowledgement precedes insertion into the bounded local
mirror. Eligible settlement receipts atomically append the receipt and seed a
pending observation. `finish_record_chio_receipt` emits trace evidence and then
claims pending work before invoking the settlement hook with an idempotency key.
Claim misses and failures remain visible as unresolved work. Local receipt
mirrors are bounded views; durable retained history is queried separately.

`set_settlement_observer_runtime` validates retry configuration and checks any
installed receipt store. Required capabilities include timed atomic projection
and matching durable store bindings. Later store installation must satisfy the
same checks. Local durability precedes federation co-signing; a co-sign failure
cannot undo the local append. A serving-closed receipt store can yield a local
signed denial without persisting through the failed writer.

`validate_metered_billing_context` checks quote identity, validity, units, caps
and currency consistency. Its verified-outcome validator always rejects that
pricing profile after shape checks. Construction does not install a metering
engine or settlement runtime.

Native flow join, egress and dispatch-ledger APIs retain preparation history.
The default-off native capture checkpoint exercises actual custody and capture
but stops before connector execution. Historical preparation or capture cannot
mint fresh execution authority. Finding purchase/recovery enforcement requires
`finding-market`; marked grants deny when the lane is compiled out.

## Dependencies

`chio-core` and `chio-core-types` provide signed protocol artifacts and canonical
serialization. `chio-security-types` supplies trusted clock and security types;
`chio-kernel-core` supplies verification and signing primitives. `chio-manifest`
provides tool metadata. `chio-settle` defines settlement hooks, outcome stores and
retry policy; `chio-link` supplies price conversion without its default features.
`chio-credit`, `chio-underwriting` and `chio-appraisal` support governed financial
artifacts. Tokio and futures provide async execution; bounded collections and
locks constrain shared state. Storage adapters implement the crate's contracts.

## Verification

`kernel/tests/capability_validation.rs` checks authority separation and crypto
floor rejection. `kernel/tests/guard_pipeline.rs` checks denial and signed guard
evidence. `kernel/tests/receipts.rs` checks dead-writer refusal before effects
and serving-closed denial behavior. `kernel/tests/settlement_routing.rs` exercises
atomic projection, store bindings and receipt visibility at claim/hook time.
Durable admission tests cover capture, recovery and caller/native boundaries.

Run `cargo test -p chio-kernel` for the default configuration. PQ integration
tests require `--features pq`; console smoke requires `tokio-console-smoke`.
`tests/replay_proptest.rs` checks replay properties; `tests/loom_concurrency.rs`
models session interleavings under its dedicated cfg. Criterion benchmarks
measure verifier, guard, budget, dispatch and receipt components. These suites
provide bounded implementation evidence for the tested profiles.
