# chio-bedrock-converse-adapter architecture

## Responsibility and boundary

`BedrockAdapter` converts Bedrock native traffic to the shared
`ToolInvocation` representation. `BedrockAdapterConfig` holds server metadata,
the API identifier, and the configured caller_arn provenance label.
The adapter owns parsing and projection. The host owns kernel evaluation,
tool execution, credentials, and the lifecycle of authoritative receipts.
Provider labels and captured verdicts do not independently establish authority.

`converse` connects the configured transport to batch lifting.
`lower_tool_result` converts an evaluator result into native output.
The synchronous lift and lower APIs support recorded inputs without services.

## Structure

adapter.rs owns native content conversion and the ProviderAdapter implementation.
iam_principals.rs loads signed mappings and resolves caller identities.
streaming.rs validates captured ConverseStream event sequences.
transport.rs owns outbound provider request wiring and mock transport support.
loaded_weights.rs implements the explicit unavailable-model-bytes contract.
Native wire types live in native.rs and are serialized with serde.

The adapter retains its configuration and an Arc-owned transport.
Registry construction adds admitted bridge-security metadata for exposed tools.
Cloned handles retain the configured transport and admission snapshot.

## Data and control flow

toolUse blocks carry toolUseId, name, and object input. toolConfig declarations, when supplied, constrain accepted names.

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

The basic constructor projects provider traffic without manifest authority.
Use a registry constructor before evaluation and signed IAM construction
when caller identity must come from authenticated mapping data.

Registry construction matches configured name, version, and public key to the
admitted server. Native names and arguments remain untrusted provider input.
Canonical JSON stabilizes argument bytes; it does not sign the invocation.
The provider principal in provenance is distinct from Chio capability authority.

BedrockAdapterConfig::validate checks the API pin and us-east-1 region.
BedrockAdapter::new also checks the transport region. Signed IAM constructors
verify mappings and resolve caller identity; their registry variants add
manifest admission. Supplied caller ARN fields alone do not authenticate AWS identity.

Converse SDK ThrottlingException maps to RateLimited with a 1000 ms retry.
InternalServerException maps to Upstream5xx 500 and ServiceUnavailableException
to 503. Captured stream exception records instead reject as Malformed.
Guardrail-only batch responses without toolUse also return Malformed; this
adapter has no native ContentPolicy mapping.

## Dependencies

chio-tool-call-fabric defines invocation, provenance, verdict, and error types.
chio-provider-adapter-core supplies bounded ingress and shared transport or
stream helpers. chio-core-types supplies canonical encoding and loaded-weight
contracts. chio-manifest supplies admitted tool security and manifest validation.
serde and serde_json handle native projection; thiserror defines local errors.

## Verification

Run `cargo test -p chio-bedrock-converse-adapter` for the package's default test surface.
The source includes batch.rs, streaming.rs, principal.rs, and sdk_transport.rs.
`tests/error_taxonomy_doctest.rs` reads README markers and native JSON examples.
Preserve that table's four columns when editing error documentation.

Local transport tests and captured streams exercise parser and conversion behavior.
They do not establish hosted-provider reliability or production acceptance.
Use the provider-conformance fixture feature for deterministic corpus replay.

## Navigation

- [Usage and status](README.md)
- [Shared provider primitives](../chio-provider-adapter-core/ARCHITECTURE.md)
- [Protocol authority boundary](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
