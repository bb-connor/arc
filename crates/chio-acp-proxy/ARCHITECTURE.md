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

The interceptor decodes method-specific params in each handler, but the ACP
request boundary does not centralize validation of identifiers that later
become capability, pending-context, and receipt correlation keys. Empty
`sessionId` or `toolCallId` values can therefore cross from JSON-RPC parsing
into guard and receipt logic unless a later subsystem happens to reject them.

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

Move ACP boundary identifier validation into `protocol.rs` and have
`MessageInterceptor` use it before guarded fs, terminal, lifecycle, and
receipt-producing session-update paths. Non-empty `sessionId` is required for
guarded operations, and non-empty `toolCallId` is required before an ACP
`session/update` can generate a receipt-bearing audit entry. This makes the
session and receipt correlation invariants explicit at the protocol boundary
without changing the public root API shape.
