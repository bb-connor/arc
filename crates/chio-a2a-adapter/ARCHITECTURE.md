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
