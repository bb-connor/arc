# chio-mistral-tools-adapter architecture

## Responsibility and boundary

`MistralAdapter` converts Mistral native traffic to the shared
`ToolInvocation` representation. `MistralAdapterConfig` holds server metadata,
the API identifier, and the configured project_id provenance label.
The adapter owns parsing and projection. The host owns kernel evaluation,
tool execution, credentials, and the lifecycle of authoritative receipts.
Provider labels and captured verdicts do not independently establish authority.

`send_chat_completion` connects the configured transport to batch lifting.
`lower_function_response` converts an evaluator result into native output.
The synchronous lift and lower APIs support recorded inputs without services.

## Structure

lib.rs owns MistralChatRequest, admission, lifting, and lowering.
response.rs extracts native calls and classifies content-filter finishes.
streaming.rs delegates chunk assembly to the shared OpenAI-compatible gate.
transport.rs owns outbound provider request wiring and mock transport support.
loaded_weights.rs implements the explicit unavailable-model-bytes contract.
Native wire types live in native.rs and are serialized with serde.

The adapter retains its configuration and an Arc-owned transport.
Registry construction adds admitted bridge-security metadata for exposed tools.
Cloned handles retain the configured transport and admission snapshot.

## Data and control flow

choices[].message.tool_calls entries carry ids and function arguments. Results use tool-role responses with the matching call id.

Original provider bytes pass through bounded JSON ingress before projection.
Batch extraction constructs native tool-call values, validates required fields,
canonicalizes object arguments, and stamps provider provenance.
The resulting invocation carries registry metadata when admission is installed.
A caller then routes it to evaluation and execution using the fabric contract.

Buffered streaming assembles tool-call content before returning forwardable bytes.
The evaluator receives a complete invocation rather than a partial argument delta.
An error or denied verdict terminates the gate with no successful output value.
Allow verdicts requesting stream redactions are rejected because original
forwarded bytes cannot represent those requested modifications safely.
Batch lowering can apply supported redactions to structured results.

## Trust and invariants

The basic constructor produces projections without manifest authority.
new_with_registry binds the admitted manifest and tool security sidecars.
Streaming evaluation requires these registry coordinates before invoking the evaluator.

Registry construction matches configured name, version, and public key to the
admitted server. Native names and arguments remain untrusted provider input.
Canonical JSON stabilizes argument bytes; it does not sign the invocation.
The provider principal in provenance is distinct from Chio capability authority.

MistralChatRequest::to_json_bytes rejects a blank model or empty messages.
The transport targets /v1/chat/completions using bearer authentication.
Batch content-filter responses reject before extraction. Stream assembly
uses the shared tool-call gate and requires admitted security sidecars.

## Dependencies

chio-tool-call-fabric defines invocation, provenance, verdict, and error types.
chio-provider-adapter-core supplies bounded ingress and shared transport or
stream helpers. chio-core-types supplies canonical encoding and loaded-weight
contracts. chio-manifest supplies admitted tool security and manifest validation.
serde and serde_json handle native projection; thiserror defines local errors.

## Verification

Run `cargo test -p chio-mistral-tools-adapter` for the package's default test surface.
The source includes live_transport.rs, registry_security.rs, and src/tests.rs.
`tests/error_taxonomy_doctest.rs` reads README markers and native JSON examples.
Preserve that table's four columns when editing error documentation.

Local transport tests and captured streams exercise parser and conversion behavior.
They do not establish hosted-provider reliability or production acceptance.
Use the provider-conformance fixture feature for deterministic corpus replay.

## Navigation

- [Usage and status](README.md)
- [Shared provider primitives](../chio-provider-adapter-core/ARCHITECTURE.md)
- [Protocol authority boundary](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
