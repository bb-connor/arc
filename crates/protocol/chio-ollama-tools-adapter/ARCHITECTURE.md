# chio-ollama-tools-adapter architecture

## Responsibility and boundary

`OllamaAdapter` converts Ollama native traffic to the shared
`ToolInvocation` representation. `OllamaAdapterConfig` holds server metadata,
the API identifier, and the configured org_id provenance label.
The adapter owns parsing and projection. The host owns kernel evaluation,
tool execution, credentials, and the lifecycle of authoritative receipts.
Provider labels and captured verdicts do not independently establish authority.

`chat` connects the configured transport to batch lifting.
`lower_tool_message` converts an evaluator result into native output.
The synchronous lift and lower APIs support recorded inputs without services.

## Structure

lib.rs owns configuration, admission, lifting, and lowering.
response.rs extracts assistant tool calls and refusal responses.
streaming.rs parses NDJSON records and requires a terminal done frame.
transport.rs owns outbound provider request wiring and mock transport support.
loaded_weights.rs implements the explicit unavailable-model-bytes contract.
Native wire types live in native.rs and are serialized with serde.

The adapter retains its configuration and an Arc-owned transport.
Registry construction adds admitted bridge-security metadata for exposed tools.
Cloned handles retain the configured transport and admission snapshot.

## Data and control flow

message.tool_calls entries contain function names and object arguments. The adapter synthesizes request ids from tool names and call indexes.

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

The default endpoint is http://localhost:11434/api/chat. OLLAMA_HOST can
override it and OLLAMA_API_KEY can attach bearer authentication.
org_id is used as an Ollama host provenance label. The loaded-weights
implementation returns an explicit unavailable result even for a local daemon.
OllamaLoadedWeights can hash bytes supplied separately by the caller; it does
not retrieve or authenticate those bytes from the daemon.

## Dependencies

chio-tool-call-fabric defines invocation, provenance, verdict, and error types.
chio-provider-adapter-core supplies bounded ingress and shared transport or
stream helpers. chio-core-types supplies canonical encoding and loaded-weight
contracts. chio-manifest supplies admitted tool security and manifest validation.
serde and serde_json handle native projection; thiserror defines local errors.

## Verification

Run `cargo test -p chio-ollama-tools-adapter` for the package's default test surface.
The source includes localhost_replay.rs and src/tests.rs.
`tests/error_taxonomy_doctest.rs` reads README markers and native JSON examples.
Preserve that table's four columns when editing error documentation.

Local transport tests and captured streams exercise parser and conversion behavior.
They do not establish hosted-provider reliability or production acceptance.
Use the provider-conformance fixture feature for deterministic corpus replay.

## Navigation

- [Usage and status](README.md)
- [Shared provider primitives](../chio-provider-adapter-core/ARCHITECTURE.md)
- [Protocol authority boundary](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
