# chio-acp-proxy Architecture Notes

## Module Boundaries

`lib.rs` currently flattens the crate with `include!` so public ACP wire types,
guards, kernel integration traits, telemetry helpers, transport, and tests all
share one crate-root namespace. The practical boundaries are still visible:
`protocol.rs` owns ACP JSON-RPC wire shapes and method discrimination,
`interceptor.rs` owns request routing and fail-closed policy decisions,
`fs_guard.rs` and `terminal_guard.rs` own built-in local guards,
`kernel_checker.rs` and `kernel_signer.rs` adapt live ACP operations into
kernel-backed authorization and receipt flows, and `transport.rs` plus
`proxy.rs` own subprocess stdio orchestration.

## Pain Points

The guarded fs, terminal, lifecycle, and receipt-producing session-update
paths now validate boundary identifiers before they become capability,
pending-context, and receipt correlation keys. The remaining weak point is
`session/request_permission`: it still treats malformed params as best-effort
logging input and forwards the request, so empty `sessionId` or option ids can
cross into the editor/user decision boundary without a trustworthy ACP
correlation key.

## Security and API Constraints

The public root exports must remain source-compatible because downstream crates
consume the flattened ACP proxy types directly. The proxy must keep fail-closed
guard ordering: live capability checker first when present, then built-in path
or command guard, then forwarding. Canonical JSON hashes for authorization
params and ACP audit entries must remain byte-stable. Standalone unsigned mode
must remain available, but it cannot silently treat malformed session or tool
identifiers as useful compliance evidence.

## Affected Dependents

`chio-kernel` and tests using `KernelCapabilityChecker`, `KernelReceiptSigner`,
`AcpCapabilityRequest`, `AcpToolCallAuditEntry`, and `MessageInterceptor` rely
on the existing public type names. No transitive crate edits are planned unless
focused gates reveal downstream breakage from stricter malformed-message
handling.

## Planned Material Improvement

Extend the existing ACP boundary identifier validation in `protocol.rs` to
`session/request_permission` and have `MessageInterceptor` require valid params
whenever the request supplies them. Non-empty `sessionId` remains required for
guarded operations, non-empty `toolCallId` remains required before ACP
`session/update` can generate a receipt-bearing audit entry, and permission
requests with option lists must carry non-empty option ids before they cross the
user decision boundary. This keeps no-params compatibility while rejecting
malformed permission correlation evidence without changing the public root API
shape.
