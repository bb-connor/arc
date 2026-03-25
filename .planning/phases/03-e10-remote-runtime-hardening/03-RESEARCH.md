# Phase 3 Research: E10 Remote Runtime Hardening

## Goal

Make the hosted remote MCP runtime reconnect-safe, resumable where intended, and operationally credible beyond the current one-subprocess-per-session shape.

## Current State

### Remote HTTP admission and request handling already exist

- `crates/pact-cli/src/remote_mcp.rs` exposes `/mcp` as `POST`, `GET`, and `DELETE`, but only `POST` currently handles MCP traffic; `GET` returns `405 Method Not Allowed` with `Allow: POST, DELETE`.
- `handle_post()` authenticates the request, requires `Accept` to contain both `application/json` and `text/event-stream`, requires `Content-Type: application/json`, and parses exactly one JSON-RPC message per request.
- `initialize` is special-cased: `handle_initialize_post()` spawns a new session, buffers the initialization event stream until the terminal response, and only then inserts the session into the in-memory map and returns `MCP-Session-Id`.
- Post-initialize requests require `MCP-Session-Id`, matching auth context, and matching negotiated protocol version before they are routed into the session worker.

### Streaming is POST-coupled, not resumable

- Request/response streaming is attached to the POST that submitted the JSON-RPC request.
- For JSON-RPC requests (`id` present), `handle_post()` takes an `active_request_stream` lock and opens an SSE stream until the terminal response for that request arrives.
- For notifications, the runtime opportunistically collects session events until idle and returns them as SSE only if it can acquire the same lock; otherwise it returns `202 Accepted`.
- `RemoteSession` emits monotonically increasing event ids like `{session_id}-{n}`, but those ids are only generated for live broadcast delivery. There is no retained backlog, `Last-Event-ID` support, replay window, or reconnect contract.

### Session ownership is per-session and process-heavy

- `RemoteSessionFactory::spawn_session()` creates a fresh `AdaptedMcpServer::from_command(...)`, a fresh kernel, a fresh `PactMcpEdge`, fresh capability issuance, and a dedicated thread running `edge.serve_message_channels(...)` for every remote session.
- Session state is stored in `RemoteAppState.sessions: HashMap<String, Arc<RemoteSession>>`.
- Deleting a session only removes it from that map. There is no explicit drain handshake, worker shutdown signal, lease expiry, or stale-session sweep in the remote runtime.

### Test coverage is good for the current transport, not for the missing hardening work

- `crates/pact-cli/tests/mcp_serve_http.rs` already covers initialize/session issuance, auth enforcement, session reuse, delete semantics, multi-session isolation, nested sampling over HTTP SSE, control-service integration, roots negotiation, and authority rotation behavior.
- There is no coverage for standalone GET-based SSE streams, replay/resume cursors, stale-session expiry, drain windows, or hosted ownership broader than one wrapped subprocess per session.

## Concrete Gaps

### Gap 1: no explicit reconnect or resume contract

The runtime can reuse a session id across POST requests, but that is not the same as a resume model. Missing pieces:

- what a client may resume after a dropped SSE connection
- whether replay is best-effort, bounded, or unsupported after certain terminal states
- how session auth, capabilities, and roots interact with any resumed stream
- how operators and tests distinguish active, recoverable, draining, expired, and deleted sessions

### Gap 2: no standalone GET/SSE stream surface

`GET /mcp` is intentionally unimplemented today. That blocks compatibility with clients that expect a dedicated event stream and makes reconnect semantics awkward because the stream is always coupled to a POST lifecycle.

### Gap 3: no session lease / drain / expiry machinery

Kernel sessions have `Initializing`, `Ready`, `Draining`, and `Closed`, but the remote HTTP runtime does not currently expose or drive a comparable lifecycle:

- no idle lease or expiry timestamp
- no server-driven drain state before deletion/shutdown
- no stale-session cleanup loop
- no administrative session listing that explains which sessions are live versus recoverable

### Gap 4: hosted ownership is still one wrapped subprocess per session

That is simple and isolates well, but it is expensive and constrains hosted scaling. E10 needs one broader ownership model for serious deployments:

- a pool or shared provider owner for wrapped/native services
- clear session isolation over that broader owner
- deterministic cleanup so pooled workers do not leak session state

## Most Relevant Files

### Remote runtime / transport

- `crates/pact-cli/src/remote_mcp.rs`
- `crates/pact-cli/tests/mcp_serve_http.rs`
- `crates/pact-mcp-adapter/src/edge.rs`
- `crates/pact-mcp-adapter/src/transport.rs`

### Session / lifecycle substrate

- `crates/pact-kernel/src/session.rs`
- `crates/pact-core/src/session.rs`

### Scope / plan docs

- `docs/epics/E10-remote-runtime-hardening.md`
- `docs/POST_REVIEW_EXECUTION_PLAN.md`
- `docs/research/01-current-state.md`

## Recommended Slice Sequencing

### 03-01: freeze the remote session lifecycle and reconnect contract

Define one explicit model first:

- remote session states (`initializing`, `ready`, `draining`, `closed`, `expired`)
- which events and request classes are resumable
- replay window rules and terminal-state rules
- auth-context continuity requirements on resumed or reattached streams

This should produce both docs and code-facing primitives so later transport work does not invent semantics ad hoc.

### 03-02: add GET/SSE streams and bounded replay / handoff behavior

Implement the new transport surface after the lifecycle contract exists:

- dedicated `GET /mcp` event stream
- event backlog or replay window keyed by event id
- deterministic POST/GET ownership rules
- duplicate-suppression / handoff rules

### 03-03: broaden hosted ownership

Refactor remote session creation so a serious hosted deployment can avoid one wrapped subprocess per session while preserving session isolation and auditability.

### 03-04: lifecycle cleanup, diagnostics, and docs

Once the transport and ownership model exist, add:

- stale-session cleanup
- drain/shutdown semantics
- admin/diagnostic visibility
- operator docs for hosted runtime behavior

## Key Risks

### Risk 1: replay semantics fight the actual transport implementation

The current event source is a broadcast channel with live fan-out only. If E10 promises durable replay without adding retained event history, the contract will be false.

Recommendation:

- make replay explicitly bounded and tie it to retained per-session event history rather than live broadcast alone

### Risk 2: GET/POST dual-stream ownership duplicates or drops events

The current `active_request_stream` mutex is a minimal single-stream guard, not a full ownership model.

Recommendation:

- define one authoritative stream owner per session/event window and one explicit handoff rule

### Risk 3: broader hosting weakens isolation

If pooled workers leak state across sessions, the runtime hardening effort will regress the core least-privilege story.

Recommendation:

- preserve session-owned auth context, capability issuance, roots, and terminal history even if provider execution broadens

### Risk 4: cleanup remains opportunistic

Deleting a session from the map is not enough for operationally credible drain/shutdown semantics.

Recommendation:

- add explicit remote session lifecycle metadata plus cleanup loops and admin visibility

## Planning Assumptions To Make Explicit

- Resume is a bounded runtime contract, not an unbounded durability promise.
- Reconnect must preserve the original session auth context; a resumed stream cannot silently switch principals.
- GET/SSE support should complement POST handling, not create a second incompatible session model.
- Hosted ownership can broaden only if session isolation remains explicit and testable.
- E10 should avoid solving full distributed ownership or external IdP federation; it is a runtime-hardening phase, not a new platform program.

## Proposed Planning Focus For 03-01

The next plan should produce:

- one explicit remote session state machine and reconnect/resume contract
- one code-facing location for remote session lease, replay, and terminal-state metadata
- one test matrix for initialize, reattach, stale session, and non-resumable terminal cases
- one clear boundary between transport replay, session ownership, and broader hosted worker ownership
