# chio-provider-adapter-core architecture

## Responsibility and boundary

This crate owns reusable provider ingress, response projection, HTTP plumbing,
and buffered stream assembly. The Provider trait identifies adapter families.
GatedStream carries forwarded bytes, invocations, and verdicts after gating.
Provider-specific callers supply native decode closures and evaluator callbacks.
The crate does not own capability issuance, kernel dispatch, or receipt signing.

GatedStream::new is a data constructor. It accepts its three vectors directly,
so callers must preserve their order and correspondence when constructing it.
The gated APIs establish stronger conditions while constructing their results.

## Structure

http.rs defines AuthScheme, HttpTransportConfig, HttpTransport,
ProviderHttpTransport, MockHttpTransport, and transport error classification.
input.rs defines bounded JSON, argument decoding, and invocation validation.
response.rs handles response envelopes and OpenAI-compatible call projection.
sse.rs parses event frames while retaining their raw bytes.
streaming.rs assembles tool calls and invokes the evaluator.
streaming/assembly.rs holds the assembly state and consistency checks.
lib.rs exports shared types and unavailable-loaded-weight helpers.

## Data and control flow

HTTP configuration supplies endpoint, authentication, headers, and timeout.
HttpTransport validates request construction and buffers response bytes.
The transport supports JSON, SSE, and NDJSON response paths.
MockHttpTransport records requests and consumes scripted responses for tests.

Original JSON passes through UntrustedJsonText before typed decoding.
Nested argument strings receive a separate bound and object-shape check.
Response helpers project accepted documents into provider-native values.
input::invocation calls ToolInvocation::validate on normalized invocations.

parse_sse_frames separates event metadata, JSON data, and terminator frames.
Options can infer event names from JSON type and check agreement with event fields.
The OpenAI-compatible gate assembles complete calls, invokes the caller's native
projection closure, and then evaluates each invocation before returning output.
Original bytes remain available for exact forwarding when gating succeeds.

## Trust and invariants

JSON documents are bounded at 16 MiB and argument objects at 1 MiB.
The SSE reader bounds streams at 16 MiB, frames at 1 MiB, and frame count at 16,384.
Original ambiguous JSON rejects before serde projection or canonical encoding.
input::typed assumes its Value originated from already validated ingress.

ensure_streaming_allow_no_redactions accepts only Allow with an empty
redaction list. Denial and evaluator errors terminate stream gating.
map_http_status and map_transport_error distinguish status rejection,
timeout, upstream failure, and structured transport errors.
HTTP status 429 maps to retry_after_ms equal to zero; Retry-After is not parsed.
Credential validation and provider identity are separate from kernel authority.

The loaded-weights helper produces explicit unavailability, allowing remote
adapters to implement the core contract without manufacturing model bytes.
None of these helpers signs evidence or installs registry tool permissions.

## Dependencies

chio-core-types supplies canonical JSON ingress and loaded-weight contracts.
chio-tool-call-fabric supplies invocation, verdict, and provider error types.
reqwest supplies the HTTP client and TLS transport.
async-trait supports object-safe asynchronous transport interfaces.
serde_json handles projections; tokio supports asynchronous mock plumbing.
thiserror retains typed local error chains.

## Verification

Run cargo test -p chio-provider-adapter-core for the local suite.
Inline tests cover SSE options, CRLF preservation, duplicate argument rejection,
argument append limits, and response shape validation.
http/boundary_tests.rs checks redacted public errors and retained local causes.
http/sse_mime_tests.rs checks streamed response content types with local mocks.
These tests exercise shared boundaries; each adapter must test its native lifecycle.

## Navigation

- [Usage](README.md)
- [Tool-call fabric](../chio-tool-call-fabric/ARCHITECTURE.md)
- [Replay verification](../chio-provider-conformance/ARCHITECTURE.md)
