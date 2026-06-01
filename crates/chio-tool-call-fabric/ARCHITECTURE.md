# chio-tool-call-fabric Architecture

## Boundaries

- `lib.rs` is the public crate facade and should only own crate docs plus reexports.
- `types.rs` owns provider ids, principals, provenance stamps, invocation values, redactions, receipt ids, deny reasons, verdict results, and value-level validation.
- `adapter.rs` owns opaque provider request/response/result byte wrappers and the `ProviderAdapter` trait.
- `error.rs` owns the shared provider error taxonomy consumed by provider adapters.
- `stream.rs` owns the provider stream state machine and buffering limits.
- `provenance.rs` owns detached provenance signing and verification.
- `tests/` owns property invariants, lift/lower fixture byte stability, and public stream transition behavior.

## Pain Points

- The root module currently mixes public data model, error taxonomy, adapter trait, byte wrappers, and unit tests, making the crate facade the de facto implementation module.
- `ToolInvocation` documents canonical-JSON argument bytes, but the crate has no public validation API that can fail closed on non-JSON, non-canonical, or provider-mismatched invocations.
- Existing property generators cover all principal variants but only three provider ids in the provider-id generator, so newer provider enum variants can drift from generated invariants.

## Security And API Constraints

- Preserve all root-level public type paths and serialized wire shapes.
- Keep `ProviderAdapter` dyn-compatible and preserve the async trait signature.
- Preserve canonical JSON byte stability for lift/lower fixtures and signed provenance.
- Validation must be additive; existing public structs remain constructible for compatibility, but callers can explicitly fail closed before trusting an invocation.
- Do not weaken fail-closed provider error taxonomy or streaming state machine behavior.

## Affected Dependents

- Provider adapters construct `ToolInvocation` and consume `ProviderError`.
- Provider conformance replays compare adapter output against captured invocation bytes.
- CLI replay validation parses `ToolInvocation` from trace artifacts.
- Tee frame tests include lift/lower fixture bytes.

## Planned Improvement

Move the public facade into explicit implementation modules, add `ToolInvocation::validate`, and use that contract in provider conformance replay before comparing adapter invocations. This makes the fabric boundary materially clearer while turning a documented invariant into executable validation.
