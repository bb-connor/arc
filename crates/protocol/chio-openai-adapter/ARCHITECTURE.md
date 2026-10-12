# chio-openai-adapter architecture

## Responsibility and boundary

`ChioOpenAiAdapter` owns manifest aggregation, function bindings, OpenAI tool
export, native call extraction, and kernel dispatch preparation.
`OpenAiExecutionContext` supplies capability, agent identity, DPoP proof,
per-call execution nonces, governed approval artifacts, supplemental authorization,
and model metadata. The caller owns the authenticity of this host context.

The optional `OpenAiAdapter` owns Responses-to-fabric projection.
`OpenAiHttpTransport` sends native requests through shared HTTP primitives.
Kernel receipt authority belongs to admitted dispatch, not provider captures
or syntactically valid function-call bytes.

## Structure

lib.rs defines the default adapter, public wire types, and execution helpers.
input.rs implements bounded original JSON and argument validation.
src/tests.rs exercises the default manifest and kernel execution surface.

With provider-adapter enabled, adapter.rs defines native lift/lower and
organization provenance. streaming.rs implements Responses lifecycle gating.
transport.rs handles Responses and Chat Completions HTTP conversion.
These modules use optional tool-call-fabric and provider-adapter-core dependencies.

## Data and control flow

Construction combines manifest tools and records each function's server binding.
The first occurrence of a duplicate function name retains its binding.
The resulting aggregate manifest passes validate_manifest before publication.
Flow-required tools reject here because this constructor cannot install their
verified cross-protocol host boundary.

extract_tool_calls and extract_responses_api_calls convert provider content
into OpenAiToolCall values. execute_tool_call validates the request, resolves
its binding, prepares cross-protocol dispatch, and invokes kernel evaluation.
The returned ToolCallResult retains decision and receipt information when present.
Batch execution rejects request-bound authorization artifacts that cannot safely
be reused across multiple calls. Execution nonces are keyed by native call id.

The optional provider adapter accepts captured Responses envelopes, parses
object arguments, canonicalizes them, and stamps organization provenance.
HTTP Chat Completions responses are converted into the same Responses shape.
Buffered SSE tracks output-item identity and argument completion before evaluation.
Original tool-frame bytes are released only on an accepted verdict path.

## Trust and invariants

The default extraction helpers reject malformed call identity and arguments.
The input reader bounds provider documents at 16 MiB and arguments at 1 MiB;
original duplicate JSON keys reject before projection.
Capability and execution authority come from the kernel and host context.
A pre-admission error is represented as a denied result without inventing a receipt.

OpenAiAdapter::new creates a raw projection without manifest admission.
new_with_registry binds tool security sidecars. The SSE gate can invoke a
caller evaluator on a raw projection, so the host must enforce admission before
authoritative execution. The API snapshot check rejects configured version drift.
Trusted Clock errors propagate through the optional provider surface.
Allow verdicts requesting streaming redactions reject before successful forwarding.

OpenAiTransport classifies HTTP status before native extraction. Status 403
maps to ContentPolicy; status 400 maps to BadToolArgs even when an error body
contains content_policy_violation. Body error codes do not override status.

## Dependencies

chio-manifest validates aggregate manifests and supplies registry admission.
chio-cross-protocol prepares the route for kernel-owned dispatch.
chio-kernel evaluates capability-bound calls and signs admitted receipts.
chio-core-types and chio-security-types carry authorization and request data.
serde_json handles native JSON; thiserror provides adapter errors.
Optional provider-adapter-core supplies transport, SSE, and parser primitives.

## Verification

Run cargo test -p chio-openai-adapter for the default surface.
Run cargo test -p chio-openai-adapter --features provider-adapter for native
adapter, transport, and streaming integration tests.
tests/adapter_lift.rs checks registry binding and bounded provider inputs.
tests/adapter_lower.rs checks output identity and redactions.
tests/streaming.rs covers lifecycle, argument identity, and denial behavior.
tests/transport.rs uses scripted and local HTTP transports.

The feature-gated error_taxonomy_doctest target reads the README table directly.
benches/verdict_latency.rs measures the local gated path with Criterion.
These checks establish bounded local behavior; hosted qualification requires
separate evidence for credentials, provider behavior, and deployment wiring.

## Navigation

- [Usage and feature table](README.md)
- [Kernel architecture](../../kernel/chio-kernel/ARCHITECTURE.md)
- [Shared provider core](../chio-provider-adapter-core/ARCHITECTURE.md)
