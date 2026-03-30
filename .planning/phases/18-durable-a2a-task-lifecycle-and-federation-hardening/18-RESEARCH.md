# Phase 18: Durable A2A Task Lifecycle and Federation Hardening - Research

**Researched:** 2026-03-25
**Domain:** Rust A2A task recovery, persisted lifecycle correlation, and
partner-bound follow-up validation
**Confidence:** HIGH

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| A2A-03 | Long-running A2A task flows preserve capability binding and truthful receipts across retries, reconnects, and delayed completion | A file-backed registry can bind task IDs to tool, server, interface, and binding context across restarts |
| A2A-04 | Push-notification and follow-up state can be correlated and validated against explicit lifecycle rules | The adapter already centralizes task operations, so validation and recording can happen before and after each lifecycle call |
| A2A-05 | Operators can apply per-partner federation and request-shaping isolation for A2A peers | Stored task binding plus configured partner policy prevents reuse of a task ID across the wrong peer or interface |

</phase_requirements>

## Summary

The lifecycle hardening seam is local persistence, not a new network protocol.
The adapter already emits the task IDs and receives enough state transitions to
record a truthful local binding contract. The missing work is durable storage
plus validation of every follow-up path against that stored contract.

The registry can stay lightweight and still satisfy the phase: a versioned JSON
file is enough because the need is restart-safe correlation and fail-closed
validation, not distributed consensus.

## Recommended Architecture

### Persisted Registry
- store task ID, tool name, server ID, selected interface URL, binding, and
  last-observed state
- open the registry during adapter discovery when configured
- write updates after send/get/cancel/stream events

### Validation Rules
- reject follow-up operations for unknown task IDs
- reject mismatched tool, server, interface, or binding context
- report lifecycle validation failures before making the outbound request

### Operator Contract
- document the optional registry path as the operator's durability switch
- keep errors specific enough to distinguish stale task IDs from wrong-partner
  follow-up attempts

## Validation Strategy

- `cargo test -p arc-a2a-adapter --lib -- --nocapture`

## Conclusion

Phase 18 does not need a new remote substrate. The right hardening is a local,
fail-closed registry that binds long-running task IDs to the exact mediated A2A
context that created them.
