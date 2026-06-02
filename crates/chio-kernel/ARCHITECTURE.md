# chio-kernel Architecture Notes

## Boundary

`chio-kernel` is the hosted enforcement layer. It validates capabilities,
matches tool grants, applies budget and governed-admission checks, runs guards,
performs runtime admission, dispatches registered tools, reconciles budget
holds, signs receipts, and persists receipt evidence. Portable verifier logic
lives in `chio-kernel-core`; durable storage implementations live in storage
crates such as `chio-store-sqlite`.

## Current Pain Point

Runtime admission hooks can reserve external runtime capacity after guards pass
but before dispatch begins. If a later pre-dispatch gate denies the call, such
as sibling-sum admission or payment authorization, the kernel must release
those reservations, reverse any pre-execution budget mutation, and still sign a
denial receipt that preserves the original denial.

The direct and nested-flow dispatch paths currently hand-roll that same
sequence. The behavior is mostly correct, but duplication makes this a fragile
security boundary: future fixes to release-failure metadata, budget reversal,
or monetary denial metadata can land in one path and drift from the other.

## Security And API Constraints

- Deny paths must remain fail-closed and must keep producing signed deny
  receipts.
- Monetary holds must be reversed before pre-dispatch denials become receipts.
- Non-monetary invocation limits must still roll back if a later pre-execution
  gate denies the call.
- Unlimited grants must not depend on synthetic zero-cost reversals.
- Runtime admission reservations must be released on provably pre-dispatch
  denials, but release failures must be evidence on the denial receipt rather
  than a replacement for the denial.
- Direct and nested-flow dispatch must share the same pre-dispatch cleanup and
  denial receipt path.
- Public kernel APIs and receipt JSON compatibility should remain unchanged.

## Affected Dependents

The owning-crate change is internal to `chio-kernel`, but it protects runtime
admission integrations that reserve destructive leases or treaty-continuation
slots. HTTP, ACP, A2A, and product callers should continue to receive ordinary
deny responses for pre-dispatch denials instead of transport-level kernel
errors.

## Improvement In This Slice

Move runtime-admission release, pre-execution budget reversal, monetary denial
metadata construction, and signed denial response creation behind one internal
pre-dispatch cleanup boundary. Both sibling-sum and payment denials in direct
and nested-flow dispatch use that boundary. Add nested-flow coverage for a
runtime-admission release failure so the shared behavior stays explicit.
