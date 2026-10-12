# chio-acp-proxy architecture

## Responsibility and boundary

`AcpProxy` owns subprocess transport and an interceptor. `MessageInterceptor` owns
local guards, audit logging, optional attestation hooks, and authorization
correlation state. The embedding application owns the message relay loop and kernel
configuration.

Intercepts ACP JSON-RPC messages between an editor and agent, applies file and
terminal guards, and records tool-call audit entries with optional kernel
attestation.

## Structure

Crate-scope fragments define protocol, configuration, guards, permissions, receipts,
attestation, kernel adapters, compliance, telemetry, interception, and transport.
`input` owns original-byte parsing and bounded framing; `clock` supplies audit time.

`Direction` distinguishes ClientToAgent from AgentToClient. `InterceptResult` has
Forward, Block, and ForwardWithReceipt variants. The receipt variant carries a boxed
AcpToolCallAuditEntry alongside the forwardable JSON message; it does not send
either object automatically.

## Data and control flow

The transport exchanges newline-delimited JSON with a child process. The caller
passes decoded messages to interception in their actual direction. File and terminal
requests pass optional capability checks and local guards. Tool-call updates produce
audit entries and can be promoted by a receipt signer. The caller forwards only the
returned permitted message.

`process_client_message` selects ClientToAgent; `process_agent_message` selects
AgentToClient. The interceptor guards agent-to-client filesystem, terminal
create/kill/release, permission requests, and session updates. Unguarded methods
forward unchanged. `session/cancel` clears retained capability correlations in
either direction.

## Trust and invariants

The default constructor installs neither signer nor capability checker. Empty local
allowlists deny guarded operations. The frame reader caps messages at 8 MiB and
closes permanently after framing failure. Pending authorization contexts are capped
at 32 per session; ambiguous matches produce audit-only context. Filesystem checks
resolve existing symlinks but do not make later external file operations atomic.

`AcpMessage::decode` validates original bytes before interception. `FsGuard` rejects
empty, relative, traversing, and out-of-prefix paths. `TerminalGuard` applies an
explicit command allowlist. `MessageInterceptor::with_kernel` installs optional
capability checking and receipt signing.

`AcpAttestationMode::Required` blocks tool-call updates when signing fails.
`KernelReceiptSigner` requires receipt-store append success before returning a
signed receipt. Checkpoint failures are tracked as health warnings after the append
succeeds. Hosts must observe that checkpoint health surface.

Forward carries a permitted destination message. Block carries an error response for
the sender. ForwardWithReceipt adds an audit entry to the permitted message. The
relay must branch on these variants rather than forward a Block response as the
original operation. Pending correlation state evicts its oldest entry when the
per-session bound is exceeded.

## Dependencies

`chio-core` supplies strict authority decoding and receipt types, `chio-kernel`
supplies injected adapters, `chio-security-types` supplies clocks, and `sha2` binds
operation parameters. The transport uses standard-library subprocess pipes.

## Verification

`src/tests/core_guards.rs`, `core_interceptor.rs`, `attestation_denials.rs`, and
`input_document_tests.rs` cover local guards, hook behavior, denial paths, and
original-byte parsing.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-acp-proxy
```

core_interceptor.rs checks direction-sensitive dispatch and forwarded messages.
attestation_denials.rs checks required-signing failures. core_guards.rs checks
filesystem prefixes and command allowlists. input_document_tests.rs checks original
JSON ambiguity before message decoding.
