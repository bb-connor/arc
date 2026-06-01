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
but before dispatch begins. If a later pre-dispatch gate denies the call
(sibling-sum admission or payment authorization), the kernel attempts to release
those reservations before returning the denial. Today a release failure bubbles
out as `KernelError`, which masks the original fail-closed denial and prevents a
signed denial receipt from being recorded for a request that never reached the
tool server.

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
- Public kernel APIs and receipt JSON compatibility should remain unchanged.

## Affected Dependents

The owning-crate change is internal to `chio-kernel`, but it protects runtime
admission integrations that reserve destructive leases or treaty-continuation
slots. HTTP, ACP, A2A, and product callers should continue to receive ordinary
deny responses for pre-dispatch denials instead of transport-level kernel
errors.

## Planned Improvement

Make runtime-admission reservation release best-effort at the pre-dispatch
denial boundary. The kernel should still attempt release, record release
failure metadata on the signed denial receipt, and preserve the original denial
reason and budget rollback evidence.
