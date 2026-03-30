---
phase: 07-schema-compatibility-and-monetary-foundation
plan: "02"
subsystem: arc-core
tags:
  - monetary-types
  - capability-schema
  - attenuation
  - is_subset_of
  - serde
  - backward-compat
dependency_graph:
  requires:
    - "07-01 (deny_unknown_fields removal -- MonetaryAmount fields now safe to add)"
  provides:
    - "MonetaryAmount type with u64 minor-unit amounts and ISO 4217 currency string"
    - "ToolGrant with optional max_cost_per_invocation and max_total_cost fields"
    - "Attenuation::ReduceCostPerInvocation and Attenuation::ReduceTotalCost variants"
    - "is_subset_of monetary enforcement with currency matching"
    - "Backward-compatible v1.0 token deserialization (no monetary fields -> None)"
  affects:
    - crates/arc-kernel (Phase 8 monetary budget enforcement target)
    - crates/arc-mcp-adapter
    - crates/arc-bindings-core
tech_stack:
  added: []
  patterns:
    - "Optional serde fields with skip_serializing_if for backward/forward compatible wire schema"
    - "Minor-unit integer monetary amounts (u64 cents for USD) to avoid float precision issues"
    - "Currency matching in is_subset_of -- mismatched currencies are incomparable, return false"
key_files:
  created:
    - crates/arc-core/tests/monetary_types.rs
  modified:
    - crates/arc-core/src/capability.rs
    - crates/arc-core/src/lib.rs
    - crates/arc-core/tests/forward_compat.rs
    - crates/arc-core/src/message.rs
    - crates/arc-core/src/session.rs
    - crates/arc-guards/tests/integration.rs
    - crates/arc-kernel/src/authority.rs
    - crates/arc-kernel/src/lib.rs
    - crates/arc-kernel/src/transport.rs
    - crates/arc-mcp-adapter/src/edge.rs
    - crates/arc-policy/src/compiler.rs
    - crates/arc-cli/src/policy.rs
    - crates/arc-bindings-core/src/capability.rs
    - crates/arc-bindings-core/tests/vector_fixtures.rs
    - formal/diff-tests/src/generators.rs
    - tests/e2e/tests/full_flow.rs
decisions:
  - "MonetaryAmount uses u64 minor-unit integers -- no floating-point, no rounding errors; matches AGENT_ECONOMY.md reference design exactly"
  - "Currency matching in is_subset_of uses string equality (child.currency == parent.currency) -- incomparable currencies return false, consistent with fail-closed posture"
  - "Two new None fields added to all 40+ ToolGrant construction sites rather than using struct update syntax -- explicit is clearer and caught by exhaustiveness checking in future changes"
  - "Updated forward_compat test to use truly unknown v3 field names (v3_billing_ref, v3_priority) instead of monetary field names that are now known -- preserves original test intent"
metrics:
  duration: "17 minutes"
  completed_date: "2026-03-21"
  tasks_completed: 2
  files_changed: 17
---

# Phase 7 Plan 02: Monetary Types Foundation Summary

Added MonetaryAmount type, monetary budget fields to ToolGrant, cost-reduction Attenuation variants, and monetary enforcement in is_subset_of -- the data foundation for Phase 8 monetary budget enforcement.

## What Was Built

**Task 1: MonetaryAmount, ToolGrant extension, Attenuation extension, is_subset_of (feat commit 44b350a)**

Added to `crates/arc-core/src/capability.rs`:

```rust
pub struct MonetaryAmount {
    pub units: u64,
    pub currency: String,
}
```

Extended `ToolGrant` with two new optional fields using `#[serde(default, skip_serializing_if = "Option::is_none")]`:
- `max_cost_per_invocation: Option<MonetaryAmount>`
- `max_total_cost: Option<MonetaryAmount>`

Extended `is_subset_of` with monetary cap checks:
- If parent has `max_cost_per_invocation`, child must have it too with `units <= parent.units` and matching currency.
- If parent has `max_total_cost`, same logic applies.
- Currency mismatch returns `false` (incomparable amounts are never a valid subset).

Added two new `Attenuation` variants:
- `ReduceCostPerInvocation { server_id, tool_name, max_cost_per_invocation: MonetaryAmount }`
- `ReduceTotalCost { server_id, tool_name, max_total_cost: MonetaryAmount }`

Updated `lib.rs` to re-export `MonetaryAmount`.

Fixed all 40+ `ToolGrant` construction sites across 16 files with `max_cost_per_invocation: None, max_total_cost: None`.

Also updated `crates/arc-core/tests/forward_compat.rs` test `v2_token_with_unknown_fields_accepted` to inject truly unknown field names instead of `max_cost_per_invocation` (now a real known field), preserving the test's original intent.

**Task 2: Monetary integration tests (test commit 21d862c)**

Created `crates/arc-core/tests/monetary_types.rs` with 13 integration tests:

| Test | What it proves |
|------|----------------|
| monetary_amount_serde_roundtrip | MonetaryAmount round-trips via JSON with canonical stability |
| tool_grant_with_monetary_fields_roundtrip | ToolGrant with both monetary fields set round-trips |
| tool_grant_without_monetary_fields_backward_compat | v1.0 JSON (no monetary keys) deserializes with None |
| monetary_fields_skip_when_none | None monetary fields omitted from serialized JSON |
| attenuation_reduce_cost_per_invocation_roundtrip | ReduceCostPerInvocation variant round-trips |
| attenuation_reduce_total_cost_roundtrip | ReduceTotalCost variant round-trips |
| subset_monetary_child_within_parent | child 500 USD <= parent 1000 USD passes |
| subset_monetary_child_exceeds_parent | child 1500 USD > parent 1000 USD fails |
| subset_monetary_uncapped_child_of_capped_parent | child None, parent Some -- fails |
| subset_monetary_capped_child_of_uncapped_parent | child Some, parent None -- passes |
| subset_monetary_currency_mismatch | child EUR, parent USD -- fails |
| subset_per_invocation_cost | all 5 variants for max_cost_per_invocation |
| signed_token_with_monetary_grant_roundtrip | CapabilityToken with monetary grant round-trips with valid signature |

## Verification Results

```
grep "pub struct MonetaryAmount" crates/arc-core/src/capability.rs  ->  match (PASS)
grep "ReduceCostPerInvocation" crates/arc-core/src/capability.rs    ->  match (PASS)
grep "ReduceTotalCost" crates/arc-core/src/capability.rs            ->  match (PASS)
grep "MonetaryAmount" crates/arc-core/src/lib.rs                    ->  match (PASS)
cargo test -p arc-core                                              ->  143 passed (PASS)
cargo test -p arc-core --test monetary_types                        ->  13 passed (PASS)
cargo test --workspace                                               ->  0 failed across all crates (PASS)
cargo clippy --workspace -- -D warnings                             ->  0 warnings (PASS)
cargo fmt --all -- --check                                          ->  clean (PASS)
```

## Decisions Made

1. **u64 minor-unit integers, not Decimal or f64.** AGENT_ECONOMY.md reference design uses u64 for monetary units. This avoids all floating-point precision issues and matches the pattern used by Stripe (cents), x402 (smallest unit), and EVM tokens (wei). No external decimal library needed.

2. **Currency matching uses string equality in is_subset_of.** When parent has `max_total_cost` in USD and child has EUR, the amounts are incomparable -- return false. This is fail-closed: ambiguous cases deny rather than permit. No currency conversion logic is needed at this layer.

3. **All 40+ ToolGrant construction sites updated explicitly.** Using `..parent.clone()` struct update syntax would work for the test code but not for all construction sites. Explicit `max_cost_per_invocation: None, max_total_cost: None` is clearer and caught by the Rust exhaustiveness checker for future field additions.

4. **forward_compat test updated to use genuinely unknown field names.** The test previously injected `max_cost_per_invocation` as a simulation of a future monetary field. Now that field is real, injecting it with the correct schema would change the token body and break signature verification. The test now injects `v3_billing_ref` and `v3_priority` (genuinely unknown), preserving the original test's invariant.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] forward_compat test v2_token_with_unknown_fields_accepted broke**

- **Found during:** Task 1 (after adding MonetaryAmount)
- **Issue:** Test injected `grant["max_cost_per_invocation"] = {"amount": 100, "currency": "USDC"}` as a "simulated future field". Once MonetaryAmount was real, serde tried to deserialize this as `Option<MonetaryAmount>` and failed on the `amount` vs `units` field name mismatch.
- **Fix 1:** Changed injection to use correct schema `{"units": 100, "currency": "USDC"}`. This fixed deserialization but broke signature verification (now-known field was included in body canonical bytes, changing the hash).
- **Fix 2:** Changed injection to use truly unknown field names `v3_billing_ref` and `v3_priority` -- these remain unknown to the current schema, unknown fields are ignored during deserialization, and the body bytes are unchanged, so signature verification passes.
- **Files modified:** `crates/arc-core/tests/forward_compat.rs`
- **Commit:** 44b350a (included in Task 1 commit)

## Self-Check: PASSED
