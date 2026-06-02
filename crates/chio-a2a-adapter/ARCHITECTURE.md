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

## Stream Registry Error Classification Slice

### Current Boundary

- `record_stream_task_activity` is the only stream path that decides whether a registry recording error is fatal for the current invocation.
- `task_registry.rs` reports malformed payloads, corrupted registry files, unsupported registry versions, poisoned locks, write failures, and binding conflicts through `AdapterError`.
- Follow-up operations still call `validate_follow_up`, so a task with no valid durable binding fails closed later.

### Pain Point

The current stream recording path swallows every registry error after stream validation. That is too broad: a stale binding conflict is safe to keep non-fatal because it leaves future follow-up denied by the unchanged binding, but a malformed or unreadable durable registry means the adapter cannot prove the local follow-up authority state it is preserving.

### Security And API Constraints

- Preserve the public `A2aAdapter` and `AdapterError` API.
- Keep valid-stream binding conflicts non-fatal for the current stream.
- Keep malformed stream chunks and unreadable durable registry state fail-closed.
- Do not log or persist request credentials while reporting registry errors.

### Affected Dependents

- `chio-kernel` should continue to receive a `ToolServerError` when A2A stream recording cannot establish a safe durable boundary.
- Existing A2A stream conflict tests must continue to prove that conflicting task ids do not overwrite the old binding and do not abort the current valid stream.

### Completed Material Improvement

Classify stream registry recording errors at the registry boundary with an
internal typed result. Only actual task rebind conflicts stay non-fatal for the
current valid stream; validation, parsing, unsupported-version, lock, and
storage errors return an adapter error so the current tool call fails closed
instead of hiding an untrusted durable-authority state. This also prevents
diagnostic text, file paths, or unrelated lifecycle errors from accidentally
matching the rebind-conflict path.

## Blocking Registry Error Classification Slice

### Current Boundary

- Blocking `SendMessage`, `GetTask`, and `CancelTask` calls validate the remote
  A2A payload before converting it into a Chio tool result.
- `record_task_activity` observes accepted blocking responses and writes durable
  task correlation through `A2aTaskRegistry::record_from_value`.
- `A2aTaskRegistry::validate_follow_up` remains the fail-closed gate for later
  task operations.

### Pain Point

The blocking path still treats every registry recording error as fatal after a
remote A2A operation has already succeeded. A stale local rebind conflict can
therefore turn a valid current `SendMessage`, `GetTask`, or `CancelTask`
response into `ToolServerError`, while streaming already classifies the same
conflict as non-fatal and preserves the unchanged registry so future follow-up
authority stays denied.

### Security And API Constraints

- Preserve public API compatibility and `ToolServerConnection` behavior.
- Keep malformed task observations, corrupted registry files, unsupported
  registry versions, lock failures, and write failures fail-closed.
- Do not overwrite conflicting task bindings or widen follow-up authority.
- Do not expose credentials in registry warnings.

### Affected Dependents

- `chio-kernel` should receive the accepted current blocking A2A response for a
  stale rebind conflict instead of a late local persistence error.
- Future A2A follow-up operations continue to depend on
  `A2aTaskRegistry::validate_follow_up`; no downstream public schema change is
  planned.

### Completed Material Improvement

Routed blocking response recording through the same internal classified registry
boundary used by streams. Rebind conflicts should be warning-only for the
current accepted response, while fatal registry errors continue to abort the
current invocation fail-closed.

## Task Registry Id Canonicalization Follow-up

### Current Boundary

- `task_registry.rs` extracts task ids from accepted `task`, `statusUpdate`,
  and `artifactUpdate` payloads before writing durable follow-up authority.
- The same registry later looks up exact task-id keys when tool calls perform
  follow-up operations.

### Pain Point

The observation validators reject all-whitespace task ids, but task ids are
provider-controlled protocol values. Normalizing them at persistence time can
collapse two distinct provider-observed task authorities into one local durable
key. Follow-up lookup must therefore use the exact observed id, including
whitespace, after validation has proved the id is non-empty.

### Completed Material Improvement

Preserve observed task ids exactly at the registry observation boundary while
continuing to reject empty or malformed observations. This keeps durable
follow-up authority keyed to the precise provider value and prevents unrelated
task ids from being collapsed by local canonicalization.

## Follow-up Partner Binding Slice

### Current Boundary

- `task_registry.rs` stores the partner label with each task observation and
  rejects partner changes when the same task id is re-observed.
- `invoke.rs` computes the partner label from the configured partner policy,
  falling back to the Agent Card host when no explicit partner id is present.
- `A2aTaskRegistry::validate_follow_up` is the durable gate for later
  `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification operations.

### Pain Point

The registry already treats partner as part of the recorded task binding, but
follow-up validation currently omits partner comparison. Two adapter instances
that share a task registry, selected tool, server id, interface, binding, and
tenant can therefore validate follow-up authority for the same task even if
their configured partner identities differ.

### Security And API Constraints

- Preserve public API compatibility. This slice must keep the partner binding
  internal to adapter and registry internals.
- Preserve exact task-id lookup and all existing tool, server, interface,
  binding, and tenant checks.
- Do not persist request credentials or include auth material in errors.
- Keep follow-up operations fail-closed when partner identity does not match the
  recorded task authority.

### Affected Dependents

- `chio-kernel` still sees the denial as a tool-server lifecycle failure through
  the existing `ToolServerConnection` path.
- `chio-a2a-edge` and conformance surfaces should not need public schema
  changes because partner comparison stays internal to this crate.
- Existing registry tests need only pass the same partner label they already
  record.

### Completed Material Improvement

Pass the resolved partner label into durable follow-up validation and reject
task operations whose partner differs from the recorded task authority. Prove
the boundary with an adapter-level restart-style test that records a task under
one partner and denies follow-up through another partner using the same durable
registry.

## Batch Rebind Persistence Slice

### Current Boundary

- `task_registry.rs` extracts all task observations from one accepted A2A
  payload, then persists them under one durable registry lock.
- Registry rebind conflicts are classified separately from fatal registry
  failures because blocking and streaming invoke paths can deliver the accepted
  current response while keeping future follow-up authority fail-closed.
- Malformed task, status-update, or artifact-update observations remain fatal
  validation errors before registry mutation starts.

### Pain Point

The current persistence loop returns immediately on the first rebind conflict
and saves nothing from that payload. If an earlier observation in the same
payload recorded a new valid task id, the warning-only conflict later in the
batch discards that valid task authority even though the invoke path still
delivers the remote response.

### Security And API Constraints

- Preserve public API compatibility and the internal classified error shape.
- Do not overwrite or mutate conflicting task records.
- Keep malformed observations, corrupted registry state, poisoned locks, and
  write failures fatal for the current invocation.
- Preserve warning-only classification for actual rebind conflicts after all
  non-conflicting observations have been durably saved.

### Affected Dependents

- `chio-kernel` should still receive accepted blocking or streaming responses
  for stale rebind conflicts.
- Later `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification calls
  should retain follow-up authority for non-conflicting task ids observed in the
  same accepted payload.
- No downstream crate or public schema change is planned.

### Completed Material Improvement

Continue scanning a validated observation batch after rebind conflicts, persist
all non-conflicting records, and then return the rebind-conflict classification
for caller warning behavior. Prove the boundary with a registry test that
combines one new valid task observation and one conflicting existing task in the
same payload.
