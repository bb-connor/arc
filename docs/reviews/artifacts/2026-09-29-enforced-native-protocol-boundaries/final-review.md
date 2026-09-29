# Independent review and author disposition

Reviewed candidate: `93fbf2eb4d`, base `150f7bea8e`.
Reviewer: `enforced_native_final_review`, one fresh read-only context; no child
agents or reviewer Cargo runs. These are review findings on the candidate,
not an independent qualification of the later fixes.

## P1: uncaged provisioning discovery

Disabled/Shadow discovery still selected a raw native child for non-root
callers. Although the path predated this batch, it contradicted the new
preparation-only contract. Reviewer requested removal of the uncaged child.

Author disposition: removed that backend and enum branch, removed the Disabled
CLI discovery option, and reject Shadow discovery before launching the target.
Both stage regressions assert no target marker and no published output. Reviewed
fixture preparation still succeeds and reruns idempotently. The native discovery
directory joins the no-bypass source gate; existing enforced discovery tests
retain the positive protocol surface oracle on the privileged host.

## P2: A2A dispatch loses typed local causes

Original JSON parsing returned typed errors, but later DTO, canonical-argument
and clock failures were projected into JSON-RPC payloads and dropped. Reviewer
requested retaining a local cause alongside the redacted response.

Author disposition: `A2aJsonRpcResponse::local_error()` exposes the retained
cause. Notification suppression removes only the wire response. Public original-
byte tests exercise malformed DTOs, unsafe integers and clock failure, verify
source chains and redaction, and assert zero tool invocations.

## Withdrawn clock replay suggestion

The reviewer initially proposed that a final task deadline observation on a
clone could permit a later rollback. Following the kernel implementation showed
its global `ClockFence` already denies the same-kernel sequence. The reviewer
withdrew this as a confirmed vulnerability. The author additionally retained
final observations in the actual task and removes a task that expires exactly
at the pre-dispatch check. The targeted regression covers that final check.

## Review boundary

The candidate verdict was request changes for P1 and P2. The author repaired
both and records terminal focused verification separately. No second review
was performed, and no minor findings were deferred. Privileged native execution,
hosted deployment and independent test success were not qualified by the
reviewer. Remote ambient clocks were outside this batch and remain queued.
