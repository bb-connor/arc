# chio-a2a-adapter Architecture Note

## Current Boundaries

- `lib.rs` is the crate facade. It exposes the public A2A adapter types by including config, protocol, invocation, mapping, discovery, auth, transport, task-registry, and optional fuzz modules into one crate module.
- `config.rs` owns builder-style adapter configuration: agent-card URL, auth material, TLS material, egress contract, partner policy, and durable task-registry path.
- `protocol.rs` owns the local serde model for A2A Agent Cards, JSON-RPC envelopes, messages, tasks, push-notification configuration, and selected protocol bindings.
- `mapping.rs` owns projection from discovered A2A skills into Chio `ToolManifest` tool definitions and parsing of Chio tool input into adapter-local A2A operations.
- `invoke.rs` owns the runtime adapter: discovery, auth resolution, request construction, SendMessage, task follow-up operations, streaming calls, and `ToolServerConnection` integration.
- `auth.rs` owns HTTP dispatch, redirect validation, OAuth/OpenID token exchange, TLS construction, response-size enforcement, and typed `HttpEgressContract` checks.
- `transport.rs` owns SSE parsing, redirect header stripping helpers, auth URL composition, and response body accounting.
- `task_registry.rs` owns durable A2A task correlation for follow-up operations after restart.

## Pain Points

- The crate is still include-driven, so module boundaries are not visible to rustdoc or downstream readers. That is a broader cleanup target, but this slice should avoid churn for churn's sake.
- The task registry is a security boundary, not just a cache. Once a task id is recorded, later `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification operations can use it as follow-up authority.
- `A2aTaskRegistry::record_from_value` currently extracts task ids directly from arbitrary JSON values and relies on callers to have already validated response or stream-event shape. That is too brittle for a durable correlation boundary.
- The normal invoke and stream paths validate task responses today, but the registry should fail closed if a future call path or test helper tries to persist malformed observations.

## Security And API Constraints

- Public API compatibility must be preserved. This slice should not expose new public types or change `A2aAdapterConfig` / `A2aAdapter` signatures.
- Every outbound HTTP dispatch must continue to require `HttpEgressContract` unless a test explicitly supplies a permissive test contract.
- Follow-up task operations must remain bound to the original tool, server id, interface URL, binding, tenant, and partner.
- No raw tokens, API keys, cookies, OAuth secrets, or mTLS private keys may be written to durable task-registry data or error output.
- No generated code is in scope.

## Affected Dependents

- `chio-kernel` sees this crate as a `ToolServerConnection`; the outward behavior should stay as `KernelError::ToolServerError` for adapter failures.
- `chio-a2a-edge` and cross-protocol docs rely on the A2A bridge preserving task lifecycle and receipt semantics; no transitive public schema change is planned.
- Integration tests under `crates/chio-a2a-adapter/tests` exercise discovery and invocation over loopback fake A2A servers; they should keep using the existing public API.

## Planned Material Improvement

Move task-observation extraction into a small internal registry boundary that validates recognized A2A task payloads before persistence. Malformed `task`, `statusUpdate`, or `artifactUpdate` observations should fail closed and leave the registry unchanged. This is architectural because it makes durable follow-up correlation self-defensive instead of dependent on all upstream call sites remembering to validate first.

## Input Mode Slice

### Current Boundary

- `protocol.rs` preserves Agent Card `defaultInputModes` and per-skill `inputModes` as provider-supplied strings.
- `mapping.rs` is the only place that interprets those strings into the internal `A2aSkillInputSurface` used by both manifest projection and send-path admission.
- `invoke.rs` must not re-parse Agent Card mode strings; it should only consume the already-normalized surface when deciding whether to send text or JSON parts.

### Pain Point

`A2aSkillInputSurface::from_modes` currently recognizes only exact `text/plain` and `application/json` tokens after trim and ASCII lowercase. Agent Cards can carry MIME-style parameters such as `application/json; charset=utf-8`; treating those as unknown rejects valid JSON/text surfaces during discovery and can deny runtime sends that match the remote card's advertised media type.

### Security And API Constraints

- Preserve public API compatibility and keep mode parsing internal to the crate.
- Do not widen arbitrary media types into JSON or text. Only recognized aliases and MIME essences should project.
- Continue failing closed when no projectable input mode remains after normalization.
- Keep the generated A2A part media types canonical: outbound text remains `text/plain`, outbound structured data remains `application/json`.

### Affected Dependents

- `build_manifest` depends on the parsed surface to decide whether the generated tool schema exposes `message`, `data`, or both.
- `A2aAdapter::build_send_message_request` depends on the same surface to admit text and data parts before kernel-mediated dispatch.
- No downstream crate needs a schema or public API change if the normalization boundary is kept internal.

### Planned Material Improvement

Add a small internal normalization step for skill input modes that strips MIME parameters before alias classification. Prove the boundary through both manifest projection and send-path tests so discovery and invocation stay aligned.

## Stream Registry Persistence Slice

### Current Boundary

- `transport.rs` parses A2A SSE events, unwraps JSON-RPC stream results when needed, validates every stream response, and returns a `ToolServerStreamResult`.
- `invoke.rs` records task observations from completed stream chunks after the stream has already been parsed and accepted.
- `task_registry.rs` owns durable follow-up authority. It must reject malformed observations and preserve existing task bindings.

### Pain Point

The stream path currently treats any registry persistence failure as a fatal invocation error even after the SSE parser has accepted the stream chunks. A stale or conflicting local registry entry can therefore convert an otherwise valid streaming response into `ToolServerError`, even though the safe fallback is to return the already-authorized stream and leave future follow-up authority denied by the unchanged registry.

### Security And API Constraints

- Preserve public API compatibility and keep the registry internals private.
- Keep malformed stream chunks fail-closed. Stream data must still pass the same A2A stream-response validation before registry persistence is considered.
- Do not overwrite conflicting task bindings. Future follow-up operations must remain denied unless the registry has a valid binding for the requested tool, server, interface, binding, tenant, and partner.
- Do not expose secrets in registry persistence warnings.

### Affected Dependents

- `chio-kernel` should continue to receive stream output for valid A2A streaming calls instead of a late local persistence error.
- Follow-up operations in this crate continue to depend on `A2aTaskRegistry::validate_follow_up`; no downstream schema or public API change is planned.

### Planned Material Improvement

Introduce a stream-specific recording boundary that first re-validates accepted chunks as A2A stream responses, then treats registry persistence failures as non-fatal for the current stream while preserving the registry unchanged. This keeps current stream delivery aligned with parser validation and keeps future follow-up authority fail-closed.
