# Phase 7: Schema Compatibility and Monetary Foundation - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Remove `deny_unknown_fields` from 18 serializable types in pact-core (capability.rs, receipt.rs, manifest.rs) and add MonetaryAmount type with cost fields on ToolGrant plus cost-reduction attenuation variants. This is a pure schema/type-system change -- no kernel enforcement logic, no guard changes, no new APIs.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase. Key constraints from research:
- The 18 `deny_unknown_fields` annotations must be removed or replaced with a forward-compatible strategy
- New fields (max_cost_per_invocation, max_total_cost) must use `#[serde(default, skip_serializing_if = "Option::is_none")]`
- MonetaryAmount uses u64 minor-unit integers (cents, not dollars) to avoid floating-point issues
- Currency is a String field (ISO 4217 code)
- Cross-version round-trip tests must prove old tokens work on new kernels AND new tokens with unknown fields are tolerated by old kernels (deserialization succeeds, unknown fields ignored)
- Existing tests must not regress

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `pact-core/src/capability.rs` -- ToolGrant struct (line 162), Attenuation enum (line 396), PactScope (line 121)
- `pact-core/src/receipt.rs` -- PactReceipt, PactReceiptBody, ChildRequestReceipt, Decision, GuardEvidence
- `pact-core/src/manifest.rs` -- ToolManifest, ToolDefinition
- `pact-core/src/crypto.rs` -- canonical JSON signing

### Established Patterns
- All serializable types use `#[serde(rename_all = "snake_case")]`
- Optional fields use `#[serde(default, skip_serializing_if = "Option::is_none")]`
- Canonical JSON (RFC 8785) for all signed payloads
- `is_subset_of` method on PactScope/ToolGrant for attenuation validation

### Integration Points
- ToolGrant.max_invocations pattern is the template for max_cost_per_invocation and max_total_cost
- Attenuation::ReduceBudget pattern is the template for ReduceCostPerInvocation and ReduceTotalCost
- BudgetStore will need try_charge_cost in Phase 8 (not this phase)

</code_context>

<specifics>
## Specific Ideas

- Reference docs/AGENT_ECONOMY.md Section 3.1 for the proposed MonetaryAmount type and ToolGrant field design
- Reference docs/CLAWDSTRIKE_INTEGRATION.md for the deny_unknown_fields migration strategy
- The STRATEGIC_ROADMAP.md notes this as a Q2 2026 Must Do item

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
