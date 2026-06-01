# chio-kernel Architecture Notes

## Boundary

`chio-kernel` is the hosted enforcement layer. It validates capabilities,
matches tool grants, applies budget and governed-admission checks, runs guards,
performs runtime admission, dispatches registered tools, reconciles budget
holds, signs receipts, and persists receipt evidence. Portable verifier logic
lives in `chio-kernel-core`; durable storage implementations live in storage
crates such as `chio-store-sqlite`.

## Current Pain Point

The pre-execution budget path currently passes `Option<BudgetChargeResult>`
through later denial gates. That option only describes monetary holds. It does
not distinguish a non-monetary invocation increment from the absence of any
budget mutation. Rollback callers therefore have to infer whether `None` means
"reverse an invocation increment" or "no rollback needed", which is unsafe for
unlimited grants and for stores that do not materialize no-limit increments.

## Security And API Constraints

- Deny paths must remain fail-closed and must keep producing signed deny
  receipts.
- Monetary holds must be reversed before pre-dispatch denials become receipts.
- Non-monetary invocation limits must still roll back if a later pre-execution
  gate denies the call.
- Unlimited grants must not depend on synthetic zero-cost reversals.
- Public kernel APIs and receipt JSON compatibility should remain unchanged.

## Affected Dependents

The owning-crate change is internal to `chio-kernel`, but it protects every
`BudgetStore` implementation reachable through the kernel, including the
in-memory store, SQLite store, and remote trust-control store. No dependent API
change is planned.

## Planned Improvement

Replace the overloaded internal rollback signal with an explicit pre-execution
budget mutation state. The kernel should record whether validation performed no
budget mutation, an invocation-budget increment, or a monetary hold. Denial
paths can then reverse only the mutation that actually happened.
