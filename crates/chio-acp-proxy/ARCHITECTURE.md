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

## Completed Permission Boundary Slice

The guarded fs, terminal, lifecycle, receipt-producing session-update, and
permission paths now validate boundary identifiers before they become
capability, pending-context, receipt, or user-decision correlation keys.
Earlier versions treated malformed `session/request_permission` params as
best-effort logging input and forwarded the request, so empty `sessionId` or
option ids could cross into the editor/user decision boundary without a
trustworthy ACP correlation key.

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

## Completed Material Improvement

Extend the existing ACP boundary identifier validation in `protocol.rs` to
`session/request_permission` and have `MessageInterceptor` require valid params
whenever the request supplies them. Non-empty `sessionId` remains required for
guarded operations, non-empty `toolCallId` remains required before ACP
`session/update` can generate a receipt-bearing audit entry, and permission
requests with option lists must carry non-empty option ids before they cross the
user decision boundary. This keeps no-params compatibility while rejecting
malformed permission correlation evidence without changing the public root API
shape.

## Session Update Params Boundary Slice

### Current Boundary

`session/update` is the agent-to-client notification path that can produce ACP
tool-call audit entries and signed Chio receipts. `interceptor.rs` parses it
into `SessionUpdateNotification`, validates the `sessionId`, then parses
security-relevant `toolCall` and `toolCallUpdate` updates before receipt
generation.

### Pain Point

The interceptor currently treats missing or malformed `session/update` params as
an uninteresting update and forwards the message unchanged. That is too weak for
a receipt boundary: a recognized method with invalid params should not cross the
proxy as unaudited traffic just because parsing failed.

### Security and API Constraints

The public flattened root API and ACP wire structs must remain unchanged.
Unknown methods can still forward for forward compatibility. Recognized
`session/update` messages must fail closed when their params are absent or do not
decode into the ACP notification shape, while valid non-tool updates continue to
forward without receipts.

### Affected Dependents

Only the owning crate tests are expected to change. Downstream crates observe the
same `AcpProxyError::Protocol` error shape already used by guarded ACP methods
with missing or invalid params.

### Completed Material Improvement

Route `session/update` through the same params-required decoding boundary used
by guarded fs, terminal, and permission methods. Missing params and malformed
params should return protocol errors before forwarding; valid non-tool updates
should still pass through, and valid tool updates should preserve the existing
receipt behavior.
