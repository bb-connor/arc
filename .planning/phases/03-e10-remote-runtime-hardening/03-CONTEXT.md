# Phase 3: E10 Remote Runtime Hardening - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the hosted remote MCP runtime reconnect-safe, resumable where intended, and scalable beyond the current one-subprocess-per-session implementation.

This phase is not a new auth federation program and it is not a distributed-control redesign. It is about making the existing hosted Streamable HTTP runtime operationally credible.

</domain>

<decisions>
## Implementation Decisions

### Resume must be explicit and bounded
- Treat resume as a bounded session/runtime contract, not an unbounded durability guarantee.
- If the runtime cannot prove continuity for a replay window, it should fail closed and require a new session rather than guessing.

### Auth and capability continuity
- Any reconnect or reattach path must preserve the authenticated session identity and capability context already bound to that session.
- A resumed stream must never silently adopt a different bearer or principal.

### One ownership model across POST and GET
- The remote runtime needs one authoritative event-ownership model even if both POST-coupled and GET-based streams are supported.
- Handoff and supersession rules must be deterministic so operators and tests can reason about duplicate or lost events.

### Broader hosting without weaker isolation
- Session isolation, auditability, and receipt semantics stay mandatory even if provider ownership broadens beyond one subprocess per session.
- Prefer explicit session-owned metadata and routing over ambient shared worker state.

### Claude's Discretion
- Exact replay-window size and lease TTLs
- Whether replay state is stored as retained events, cursor metadata, or both
- Whether broader hosted ownership lands as a provider pool, worker manager, or native service owner, as long as the isolation boundary is explicit and test-covered

</decisions>

<specifics>
## Specific Ideas

- `RemoteSession` already has a monotonic event id source and a single-stream mutex; those can seed a real replay / ownership model but are not sufficient on their own.
- `handle_initialize_post()` already delays session insertion until initialize succeeds, which is a good starting point for terminal-state rules.
- The kernel already knows `Initializing`, `Ready`, `Draining`, and `Closed`; the remote runtime should reuse that vocabulary rather than inventing a second unrelated lifecycle language.
- The current HTTP tests already prove session issuance, reuse, isolation, and nested sampling, so Phase 3 should extend that suite instead of creating a disconnected harness.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Closing-cycle scope
- `docs/POST_REVIEW_EXECUTION_PLAN.md`
- `docs/epics/E10-remote-runtime-hardening.md`
- `docs/research/01-current-state.md`

### Remote runtime implementation
- `crates/pact-cli/src/remote_mcp.rs`
- `crates/pact-cli/tests/mcp_serve_http.rs`
- `crates/pact-mcp-adapter/src/edge.rs`
- `crates/pact-mcp-adapter/src/transport.rs`

### Session lifecycle substrate
- `crates/pact-kernel/src/session.rs`
- `crates/pact-core/src/session.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `RemoteSession::next_stream_event_id()` already provides ordered per-session event ids.
- `BroadcastJsonRpcWriter` already turns edge output into per-session `RemoteSessionEvent`s.
- `handle_initialize_post()` already ensures only successful initialize responses allocate a durable `MCP-Session-Id`.
- `mcp_serve_http.rs` already covers session issuance, reuse, delete semantics, multi-session isolation, and nested sampling over HTTP SSE.

### Missing Pieces
- `GET /mcp` does not open a stream today.
- There is no `Last-Event-ID`, replay window, or retained event history for reconnects.
- `RemoteSessionFactory::spawn_session()` still creates a fresh wrapped server, kernel, edge, and worker thread per session.
- Session deletion only removes the session from the map; there is no explicit drain, expiry, or shutdown protocol.

### Integration Points
- Resume and replay semantics will likely require new metadata on `RemoteSession` plus transport changes in `remote_mcp.rs`.
- Standalone GET/SSE support and stream ownership rules belong primarily in `remote_mcp.rs` with tests in `mcp_serve_http.rs`.
- Broader hosted ownership likely requires refactoring `RemoteSessionFactory` and the wrapped transport/bootstrap path.
- Lifecycle diagnostics and operator-facing rules likely belong in the admin/debug HTTP surface alongside existing trust/admin endpoints.

</code_context>

<deferred>
## Deferred Ideas

- Full external IdP or user-federation work
- Distributed consensus for hosted session ownership
- Unbounded event durability or general-purpose queueing
- Performance-first optimization outside what is needed to land a credible hosted lifecycle contract

</deferred>

---
*Phase: 03-e10-remote-runtime-hardening*
*Context gathered: 2026-03-19*
