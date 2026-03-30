# Phase 18: Durable A2A Task Lifecycle and Federation Hardening - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 18 hardens long-running A2A task handling so follow-up and push-style
operations remain bound to the original mediated task across reconnects and
restarts. The phase also keeps lifecycle recovery isolated to the partner,
server, interface, and binding that created the task.

</domain>

<decisions>
## Implementation Decisions

### Durable Task Registry
- Lifecycle state is persisted in a versioned JSON registry file when the
  operator opts in.
- The registry records task ID, tool name, server ID, selected interface, and
  protocol binding.
- The adapter updates registry state from send, get-task, cancel-task, and
  stream events.

### Fail-Closed Follow-Up Validation
- Follow-up operations validate the stored task binding before network calls are
  made.
- Unknown tasks and mismatched partner/interface bindings are rejected locally.
- Restart recovery reopens the registry and reuses the stored task contract.

### Federation Hardening
- Partner isolation is preserved through the stored binding contract instead of
  trusting caller-supplied task IDs alone.
- Lifecycle diagnostics name the operation and binding that failed validation.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 18 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `A2A-03`, `A2A-04`, `A2A-05`
- `crates/arc-a2a-adapter/src/lib.rs` -- task registry and lifecycle
  validation
- `docs/A2A_ADAPTER_GUIDE.md` -- durable task-correlation docs

</canonical_refs>

<code_context>
## Existing Code Insights

- The alpha adapter already knew how to do `GetTask`, `CancelTask`,
  `SubscribeToTask`, and push-notification config CRUD.
- The missing hardening was durable correlation across restarts and explicit
  validation that a follow-up task belongs to the same mediated partner path.
- The adapter's existing test harness already had long-running task fixtures,
  making restart-safe validation straightforward to prove.

</code_context>

<deferred>
## Deferred Ideas

- distributed or multi-node lifecycle state replication
- remote operator dashboards for task-registry contents
- richer lifecycle retention and garbage-collection policies

</deferred>

---

*Phase: 18-durable-a2a-task-lifecycle-and-federation-hardening*
*Context gathered: 2026-03-25*
