# Phase 277 Panic Audit

Baseline audit date: 2026-04-12

## Summary

- Literal `panic!` sites in `crates/arc-kernel/src`: 22
- Production literal `panic!` sites before any `#[cfg(test)]` module: 0
- Production `unwrap()`, `expect()`, `unreachable!`, `todo!` before any
  `#[cfg(test)]` module: 0
- Input-dependent literal panic sites in production: 0
- Remaining work implied by the audit:
  - remove the 22 test-only `panic!` assertions from kernel source hygiene
  - harden and test the real external-input surface at the transport and
    deserialization boundary

## Classification Legend

- `classification`: `invariant-violation` or `input-dependent`
- `action`: `convert` for production input paths that must become typed errors,
  `harden` for invariant or test-only assertions

## Audit Table

| # | File | Line | Triggering Condition | Classification | Action | Rationale |
|---|------|------|----------------------|----------------|--------|-----------|
| 1 | `crates/arc-kernel/src/transport.rs` | 230 | transport roundtrip test decodes anything other than `AgentMessage::ToolCallRequest` | invariant-violation | harden | inside `#[cfg(test)]`; asserts test fixture shape only |
| 2 | `crates/arc-kernel/src/transport.rs` | 270 | transport roundtrip test decodes anything other than `KernelMessage::ToolCallResponse` | invariant-violation | harden | inside `#[cfg(test)]`; no production input path |
| 3 | `crates/arc-kernel/src/transport.rs` | 302 | stream chunk roundtrip test decodes anything other than `KernelMessage::ToolCallChunk` | invariant-violation | harden | inside `#[cfg(test)]`; assertion-only |
| 4 | `crates/arc-kernel/src/payment.rs` | 740 | payment adapter test receives an error variant other than `PaymentError::InsufficientFunds` | invariant-violation | harden | inside `#[cfg(test)]`; checks expected test result mapping |
| 5 | `crates/arc-kernel/src/lib.rs` | 6590 | session-operation test returns anything other than `SessionOperationResponse::ToolCall` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 6 | `crates/arc-kernel/src/lib.rs` | 6615 | capability-list test returns anything other than `SessionOperationResponse::CapabilityList` | invariant-violation | harden | inside `#[cfg(test)]`; no production panic path |
| 7 | `crates/arc-kernel/src/lib.rs` | 6665 | roots-list test returns anything other than `SessionOperationResponse::RootList` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 8 | `crates/arc-kernel/src/lib.rs` | 7073 | nested-flow test receives non-value tool output | invariant-violation | harden | inside `#[cfg(test)]`; output-shape assertion |
| 9 | `crates/arc-kernel/src/lib.rs` | 7271 | elicitation acceptance test receives non-value tool output | invariant-violation | harden | inside `#[cfg(test)]`; output-shape assertion |
| 10 | `crates/arc-kernel/src/lib.rs` | 7601 | incomplete-stream test receives non-tool-call session response | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 11 | `crates/arc-kernel/src/lib.rs` | 7729 | stream-byte-limit test receives non-stream output | invariant-violation | harden | inside `#[cfg(test)]`; output-shape assertion |
| 12 | `crates/arc-kernel/src/lib.rs` | 7764 | stream-duration-limit test receives non-incomplete stream result | invariant-violation | harden | inside `#[cfg(test)]`; output-shape assertion |
| 13 | `crates/arc-kernel/src/lib.rs` | 7880 | resource-list test returns anything other than `SessionOperationResponse::ResourceList` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 14 | `crates/arc-kernel/src/lib.rs` | 7920 | resource-read allow test returns anything other than `SessionOperationResponse::ResourceRead` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 15 | `crates/arc-kernel/src/lib.rs` | 7986 | filesystem resource-read allow test returns anything other than `SessionOperationResponse::ResourceRead` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 16 | `crates/arc-kernel/src/lib.rs` | 8017 | signed resource-read deny test does not produce `KernelMessage::ToolCallResponse` with policy denial details | invariant-violation | harden | inside `#[cfg(test)]`; deny-path assertion |
| 17 | `crates/arc-kernel/src/lib.rs` | 8064 | resource-template deny test does not produce the expected signed denial response | invariant-violation | harden | inside `#[cfg(test)]`; deny-path assertion |
| 18 | `crates/arc-kernel/src/lib.rs` | 8186 | prompt-list test returns anything other than `SessionOperationResponse::PromptList` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 19 | `crates/arc-kernel/src/lib.rs` | 8205 | prompt-get test returns anything other than `SessionOperationResponse::PromptGet` | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 20 | `crates/arc-kernel/src/lib.rs` | 8267 | completion test returns anything other than `SessionOperationResponse::Completion` for resource completion | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 21 | `crates/arc-kernel/src/lib.rs` | 8293 | completion test returns anything other than `SessionOperationResponse::Completion` for prompt completion | invariant-violation | harden | inside `#[cfg(test)]`; response-shape assertion |
| 22 | `crates/arc-kernel/src/lib.rs` | 10496 | governed streaming test receives value output instead of streamed partial output | invariant-violation | harden | inside `#[cfg(test)]`; partial-stream assertion |

## Conclusion

Phase 277 found no production literal panic sites to convert. The real hardening
surface for phases 278-280 is:

1. ensure transport and message parsing return structured errors for malformed
   or truncated input
2. remove the 22 test-only `panic!` macros from `arc-kernel/src` so source
   scans are production-meaningful going forward
