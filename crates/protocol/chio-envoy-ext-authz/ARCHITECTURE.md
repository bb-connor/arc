# chio-envoy-ext-authz architecture

## Responsibility and boundary

`ChioExtAuthzService<K>` owns a supplied `EnvoyKernel` implementation and maps one
unary Check RPC at a time. The evaluator owns policy and capability validation;
Envoy owns upstream request capture and enforcement.

Implements Envoy ext_authz gRPC request translation and response mapping around a
caller-provided authorization evaluator.

## Structure

`translate` defines request, identity, and verdict types. `service` implements the
generated Authorization trait. `response` builds allowed and denied responses;
`metadata` builds dynamic metadata; `error` defines failures. `proto` includes
generated bindings.

`EnvoyKernel` is a Send + Sync asynchronous evaluator trait. `ToolCallRequest`
carries method/path-derived tool identity, selected headers, body binding, request
id, and caller identity. `Verdict` drives response status and dynamic metadata
without constructing a Chio receipt in this crate.

## Data and control flow

The service extracts the protobuf request, translates HTTP method/path and selected
headers, invokes the evaluator, and maps its verdict. Bearer credentials become
hashes. Body hashing uses raw bytes when present, then text; length comes from Envoy
metadata. Translation or evaluator failures return a stable client-visible denial
reason.

Identity precedence is x-chio-capability-token, then a nonempty Bearer token, then
Envoy source.principal, then anonymous. Capability and bearer labels are unverified.
A source principal receives verified=true because Envoy asserted it; no certificate
validation occurs here. `choose_request_id` prefers x-request-id over http.id and
otherwise returns an empty string.

## Trust and invariants

Caller identity is an assertion derived from Envoy fields. Capability and bearer
credentials remain unverified by this adapter. A nonempty peer principal is marked
verified because Envoy asserted it; the service does not validate its certificate.
Capability identifiers remain present in request identity fields although stripped
from the selected header map. Body capture limits and gRPC limits belong to
deployment wiring.

`Authorization::check` returns a denied HTTP 500 response on translation or
evaluator errors. `check_request_to_tool_call` rejects missing request components
and invalid method shape. The evaluator owns actual authorization.

Selected request headers omit credential presentation even though the separate
identity field retains the capability id or bearer hash. Raw body bytes take
precedence over text for SHA-256 binding. Body length comes from the nonnegative
Envoy size field, so length metadata can differ from captured bytes. Translation
errors skip the evaluator; evaluator errors produce the same stable fail-closed
response.

## Dependencies

Tonic and prost supply gRPC and protobuf types. Vendored protoc and tonic-build
generate bindings at build time. SHA-256 and hex encode body and bearer bindings. No
Chio authorization crate is linked directly.

## Verification

`tests/translate.rs` and inline translation/response tests cover method validation,
identity precedence, secret header handling, body hashing, path escaping, and denial
response encoding.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-envoy-ext-authz
```

`kernel_error_fails_closed_with_500` checks evaluator errors.
`missing_attributes_fails_closed_without_kernel_call` checks translation ordering.
`kernel_error_redacts_internal_message_from_denied_response` checks wire secrecy.
`bearer_token_populates_caller_identity_hint` checks the credential-derived label
without asserting credential authenticity.
