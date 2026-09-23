# Prepared broker execution connections

A confined tool needs its broker descriptor before launch. Kernel readiness is
followed by fresh authorization, durable capture and dispatch commitment, so an
ordinary idle IPC connection can expire before the tool may execute. The host
uses `BrokerIpcClient::prepare_dispatch_connection` to authenticate the actual
broker process and prepare the original registered request on that descriptor.
The tool receives the descriptor without the privileged registration signer.

`prepare_connection` uses the existing signed preparation authorization and
original registration checks. The daemon acknowledges the exact registration
and request before retaining the connection. There is one prepared slot across
preparation, waiting and execution. A second preparation fails before dispatch.
A dedicated fixed worker services the slot independently of normal control and
privileged audit workers; accepting clients never creates additional workers.

The prepared lifetime ends at the earliest of 30 seconds, signed capability
expiry and registered proof nonce expiry. It is an absolute monotonic deadline,
not an idle timeout. The first execution byte starts the configured ordinary
frame read budget, also capped by the remaining prepared lifetime. Trickled
bytes cannot renew either budget. EOF, expiry, malformed input, or completion
closes the descriptor and releases its slot. Response write budgets are
unchanged.

The retained binding hashes the complete canonical execution frame, including
the operation, tenant, proof and request. Only that one frame may execute.
The production daemon then validates current parent and revocation authority,
the original native capture and provider deduplication before accessing a
credential. Preparation alone grants no permission to dispatch.

`BrokerMcpConnection` checks original kernel caller context and captured physical
custody before invoking its selected `BrokerMcpToolConnection`. That transport
must retain the supplied descriptor for the corresponding dispatch and complete
its cage readiness before returning. The MCP result must contain only a signed
broker response in structured content, with empty content and no error flag.
The wrapper verifies both the response signature and its original capture
metadata. A lost or invalid completion leaves the kernel's captured accounting
in its unknown-outcome state; this layer neither retries nor refunds it.

Completion evidence and receipts use v2. The signed evidence includes
`responseHeadersSha256`, the SHA-256 of the domain
`chio.broker-response-headers.v1\0` followed by the RFC 8785 encoding of the
exact sanitized header vector. Names, values, ordering, additions and omissions
are covered. Live clients, the MCP wrapper, durable replay and receipt-store
readback reject a header vector that differs from this commitment. The receipt
signature domain is `chio.broker-execution-receipt-signature.v2\0`.

The v1 schemas and fixtures remain available for historical decoding. Current
completion verification requires v2 and does not infer header authentication
from v1 signatures. Legacy stored evidence cannot authorize redispatch or a
refund. New signatures are never fabricated for old stored completions.

Native completion time must be at or after the original parent issuance and
broker capability activation, and no later than the trusted receiver's observed
time. Live delivery samples that clock after receiving the response. Historical
verification does not require the original capabilities to remain unexpired and
does not create new execution authority.

Local host composition uses `DurableAdmissionRuntime::local_authority_store()`
to share the same serving owner, mutation fence, physical captures and quotas
already attached to the kernel. The broker reader and authority handler use
that retained store. Remote authority profiles return `None` and cannot supply
this local composition. `DurableAdmissionRuntime::attach` still requires the
kernel's signing key to match its persisted authority identity.

The optional `native-mcp` feature provides `NativeBrokerMcpTool`, a connection
owned for one invocation. It uses the production stdio adapter after preparing
the broker descriptor. The selected factory must return an enforced brokered
cage, retain the same open socket and match discovery to the signed manifest.
Plain invocation, unbound caller context and connection reuse refuse delivery.
The caller keeps this connection inside `BrokerMcpConnection` and drops its owner
after a pre-dispatch refusal. Completion and failure shut down the child through
the adapter's terminal-receipt path. Cancellation drops that same child owner;
neither cancellation nor a failed terminal receipt permits redispatch.

`NativeMcpLaunchFactory::prepare_broker_launch` refuses by default. The CLI's
signed policy factory implements it by consuming the prepared descriptor. It
checks the signed socket endpoint, the actual kernel peer credentials and the
policy's enforcing migration state, without opening a replacement connection.
An inherited-FD-only policy cannot be substituted for this signed endpoint.
Native cage enforcement currently supports Linux x86_64; other architectures
retain the existing refusal.

`chio-broker-mcp` is the tool-side executable for this connection. Its arguments
are `--tenant-scope`, `--tool-name` and `--receipt-signer`; all three are public
configuration bound by the signed launch policy. It adopts the inherited socket
at BrokeredNativeV1 slot 8 without duplicating it, opening a socket or changing
the host's deadlines. No credential or registration signer is passed to it.
`PreparedBrokerMcpConfig::tool_definition()` returns the exact discovery surface
to include in the publisher-signed manifest.

The executable requires initialization and discovery before accepting one
`tools/call`. Input frames and pre-call message counts are bounded. It passes
the original signed request to the broker and verifies the signed response
before returning empty content plus structured completion. It then closes the
channel and exits. Queued replay, malformed input, a failed broker exchange or
invalid completion cannot trigger another request. Diagnostics contain fixed
codes only. These stdio and inherited-descriptor process tests do not establish
native confinement by themselves.

The existing process regression still uses a child broker client and a real TLS
peer through an MCP-shaped connection. Qualification of the new production
stdio/cage composition, keyring composition, process cutpoints and complete
artifact verification remain separate M6 requirements. The generic process host
continues to refuse flow-required tools until their full runtime is installed.
