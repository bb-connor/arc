# Phase 33: Governed Transaction Intents and Approval Tokens - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 33 adds the canonical governed-transaction contract that the later
payment-rail phases depend on: structured intent data, approval artifacts, and
receipt-visible evidence that can flow through policy evaluation, kernel
runtime checks, and operator tooling without changing the truth model for
execution or settlement.

</domain>

<decisions>
## Implementation Decisions

### Intent Contract
- Governed transaction intent should be a first-class additive data model in
  `arc-core`, not an ad hoc JSON convention in `arc-cli` or docs.
- The intent model should bind the actor, target tool surface, economic
  purpose, and bounded spend attributes needed by x402 and ACP follow-on work.
- The runtime request path should carry governed intent as an optional field so
  existing calls remain backward-compatible when no governed flow is required.
- Receipt metadata should expose governed intent and approval evidence under a
  dedicated nested object rather than overloading the existing `"financial"`
  metadata block.

### Approval Model
- Approval should stay stateless from the kernel's perspective: the kernel
  validates a signed approval artifact or denies with an approval-needed reason,
  but it does not own a mutable approval workflow store in this phase.
- Approval artifacts should be explicit optional inputs on the runtime request,
  scoped to a concrete governed intent or request ID to prevent replay across
  unrelated calls.
- High-cost or explicitly governed actions should fail closed when approval is
  missing or invalid instead of silently degrading to plain monetary grants.
- Approval evidence should be visible on allow and deny receipts so operator
  tooling can trace why a governed call was or was not permitted.

### Layering and Compatibility
- Canonical types belong in `arc-core`; enforcement and validation belong in
  `arc-kernel`; policy loading and operator-facing issuance/inspection belong in
  `arc-cli`.
- All phase 33 changes should be additive and backward-compatible for existing
  non-governed capability and receipt flows.
- Existing monetary settlement semantics remain the source of truth for payment
  state; phase 33 adds intent and approval semantics, not rail-specific
  settlement logic.
- The initial phase 33 surface should favor a minimal but real end-to-end path
  over a broad speculative schema that later phases would need to unwind.

### Claude's Discretion
Claude may choose the exact governed-intent field names and approval-artifact
shape as long as they are canonical, additive, serializable, and clearly
separate intent/approval evidence from settlement metadata.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-core/src/capability.rs` already carries tool-grant monetary
  ceilings and the `Constraint` enum that can be extended for approval-related
  rules.
- `crates/arc-kernel/src/runtime.rs` defines `ToolCallRequest`, which is the
  narrow request seam for threading governed intent and approval artifacts.
- `crates/arc-kernel/src/lib.rs` already owns monetary pre-charge,
  authorization, deny-response construction, and receipt metadata injection.
- `crates/arc-kernel/src/payment.rs` already defines the payment-adapter
  substrate and canonical receipt-side settlement mapping used by later bridge
  phases.
- `crates/arc-cli/src/policy.rs` is the main operator-facing policy loading
  surface and the likely place to expose governed-intent configuration once the
  core model exists.

### Established Patterns
- Security-sensitive behavior is additive, typed, and fail-closed rather than
  driven by free-form JSON or CLI-only conventions.
- Shared domain types live in `arc-core`, while runtime decision logic and
  receipt signing stay in `arc-kernel`.
- Receipts carry nested structured metadata blocks rather than flattening new
  domains into top-level fields.
- Runtime changes are typically covered by focused unit tests in the owning
  crate plus higher-level integration coverage where operator flows matter.

### Integration Points
- `crates/arc-core/src/capability.rs`
- `crates/arc-kernel/src/runtime.rs`
- `crates/arc-kernel/src/lib.rs`
- `crates/arc-core/src/receipt.rs`
- `crates/arc-cli/src/policy.rs`
- `spec/PROTOCOL.md`

</code_context>

<specifics>
## Specific Ideas

- Align the governed-intent contract with the deep-research direction: treat
  intent as the intersection of capability scope, transaction context, and
  approval-to-spend semantics rather than inventing a rail-specific object.
- Reuse the `RequireApprovalAbove` concept from `docs/AGENT_ECONOMY.md`, but
  make the approval artifact and receipt evidence real code instead of doc-only
  design.
- Keep denial reasons structured enough that later CLI or API surfaces can
  surface an approval request token without reparsing ad hoc prose.

</specifics>

<deferred>
## Deferred Ideas

- Stateful approval workflow persistence and approval inboxes.
- Rail-specific x402 or ACP payload formats beyond the canonical governed
  intent and approval contract.
- Multi-dimensional budgets and reconciliation queues, which belong to phase
  36.

</deferred>
