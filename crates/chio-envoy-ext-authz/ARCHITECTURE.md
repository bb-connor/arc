# chio-envoy-ext-authz architecture note

## Boundaries

- `lib.rs` owns the public surface, generated proto re-exports, and stable adapter types re-exported for downstream wiring.
- `translate.rs` owns the trust-boundary projection from Envoy `CheckRequest` into the local `ToolCallRequest`. It strips raw secrets, hashes bearer and body bytes, derives `http.<method>.<path>` tool identities, and returns `TranslateError` for malformed Envoy input.
- `service.rs` owns the tonic `Authorization` implementation and should only coordinate translation, kernel evaluation, logging, and response conversion.
- `error.rs` owns public error types. `TranslateError` is part of the crate API, so new variants are avoided unless the security value justifies a public compatibility break.

## Pain points

- `service.rs` currently mixes RPC orchestration with Envoy `CheckResponse` construction. That makes the RPC boundary harder to audit because allow, deny, and fail-closed response semantics are embedded beside tonic plumbing.
- Fail-closed responses include the internal translation or kernel error text in the client-visible denial body and header. Logs should carry the specific fault; ext_authz clients should only receive a stable fail-closed reason.
- `translate.rs` is the largest file and contains multiple private concerns. It is still cohesive enough to leave intact for this slice because changing translation shape would carry broader API and compatibility risk.

## Constraints

- Fail closed on malformed input and kernel errors.
- Do not forward raw bearer tokens or capability tokens.
- Preserve the public `EnvoyKernel`, `ToolCallRequest`, `Verdict`, and `TranslateError` API in this slice.
- Preserve existing deny verdict behavior: policy denial reason and guard name remain visible to the downstream client.
- Do not edit generated protobuf output directly.

## Dependents

- `examples/istio-ext-authz` depends on the adapter's header names and fail-closed behavior, but not on private response helpers.
- Research and operations docs describe the adapter as the Envoy HTTP ext_authz boundary. This slice does not alter the documented crate role.
- No Rust crate currently imports private `service.rs` response helpers.

## Planned improvement

Split Envoy response construction into its own internal module and make fail-closed response bodies and headers use a stable generic reason. This is architectural because it narrows `service.rs` to RPC orchestration, creates a distinct response boundary for audit, and prevents internal kernel or translation faults from crossing the ext_authz trust boundary while preserving public API shape.
