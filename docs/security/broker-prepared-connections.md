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

## Process host composition

`NativeBrokerMcpRouter` registers a persistent factory with the kernel. Each
admitted invocation gets its own prepared `NativeBrokerMcpTool` connection. The
kernel checks that it preserves the registered server, tools, cost accounting
and read-only classification, then retains it through final authorization and
dispatch. Completion, denial and cancellation drop that invocation's owner.
The original call receipt binds the exact persisted cage enforcement receipt.

An ordinary `chio process` host can select this route with `native_broker` in
its configuration. This profile requires Linux, one broker server, an explicit
aggregate invocation budget, and a signed Enforced BrokeredNativeV1 launch
policy. Matching invocation grants in the capability policy must also select
a positive `max_invocations`. Initialization rejects missing or unbounded
grant quotas before creating host state. Mailboxes and dynamic spawn templates
are refused in this profile.
The host installs the native flow resolver, explicit structured classifier,
broker quota verifier and supplemental admission participant on its original
durable authority. Worker input cannot select the tenant, isolation epoch,
session, principal or lineage. Changing the selected security profile cannot
replay an operation under a different flow identity.
Before each evaluation, including the executable request after nonce issuance,
the process runtime refreshes the mutable flow generation from the same fenced
kernel authority. The writer still checks it independently. This read preserves
the original identity and cannot erase a committed input label.

The profile contains these operator selections:

```json
{
  "security": {"tenant_id": "tenant", "isolation_epoch_id": "epoch-1", "generation": 1},
  "quota": {
    "issuer": "BROKER_CAPABILITY_ISSUER_PUBLIC_KEY",
    "audience": "BROKER_AUDIENCE",
    "server_id": "native-broker",
    "tool_name": "send",
    "provider_adapter_id": "PROVIDER_ADAPTER_ID",
    "provider_adapter_version": 1,
    "credential_placement": "bearer_authorization"
  },
  "broker_identity": "BROKER_RECEIPT_PUBLIC_KEY",
  "authority_seed_file": "/private/host-authority.seed",
  "authority_public_key": "HOST_AUTHORITY_PUBLIC_KEY",
  "revocation_authority_domain": "REVOCATION_DOMAIN",
  "ipc_timeout_ms": 3000,
  "fence_ttl_ms": 10000,
  "operator_input_floor": {"kind": "known", "owners": {}, "compartments": []},
  "classifier": {
    "id": "operator-classifier",
    "version": "1",
    "rules": [{"category": "private", "expression": "PRIVATE_INPUT", "confidence_basis_points": 10000}],
    "category_labels": {"private": {"kind": "known", "owners": {}, "compartments": ["private"]}}
  }
}
```

Replace every uppercase placeholder with independently selected configuration.
Classifier rules must describe the application's actual sensitive inputs. The
example maps private findings to a compartment outside this public-only route's
clearance. Every configured rule needs an explicit category mapping; incomplete
maps are rejected at load. Classification covers the original envelope
and the decoded HTTP request or response body, with body findings attributed
to the original JSON field and envelope digest. A malformed body is refused.
The authority seed is a 32-byte hex seed in a
private regular file owned by the host. Its public key must match the explicit
pin; it is distinct from the host's automatically provisioned receipt key.

Provision the signed tool launch policy with
`chio security provision-reference-runtime --broker-binding PATH ...` before
starting the host and broker. The binding selects the broker's actual planned
PID, UID and GID. A future socket is accepted only beneath a canonical, private,
operator-owned directory. The launch still authenticates the live descriptor;
provisioning a pathname does not authenticate a future process. This permits a
supervised broker to wait behind a start gate while its host is provisioned.

Initialize with `chio process init --config HOST --state STATE
--aggregate-invocations COUNT`. Obtain the broker capability from its selected
issuer, bound to the actual process capability and subject in the signed
`STATE/process-bootstrap.json`. Prepare its original call while the host is
stopped:

```sh
chio process prepare-broker-call --state STATE --process PROCESS \
  --operation-key OPERATION --capability BROKER_CAPABILITY.json \
  --request PROVIDER_REQUEST.json --out PREPARED_CALL.json
```

The command uses the process's retained private proof key and original request
identity. Its output is the arguments for the selected worker tool call. The
worker receives no signing key or provider credential. The output file is
created privately and existing files are refused. Start `chio process serve`
before releasing the broker's start gate. Configure the broker's authority
socket as `STATE/broker-authority.sock` and pin `authority_public_key` above.
The service reads original custody under the host's existing owner and closes
before the host lease is released. Host restart preserves completed replay;
uncertain effects retain their original captured accounting.

After stopping the host, `process attest-call` exports a
`chio.process.call-observation.v3` artifact through the existing call evidence
command. It binds the signed broker response, original composite quota capture,
cage launch and terminal receipts, original execution nonce when required, and
kernel receipt-log inclusion. `process verify-call` requires
`--trusted-broker-host-config` in addition to the original request, context,
kernel key and runtime pins. Retain the normalized `config` from `STATE/host.json`
independently at provisioning; do not obtain that pin from the observed artifact.

This is authenticated historical host readback. It does not independently prove
the provider's physical effects or complete the keyring and full M6 acceptance
joins. Legacy v1/v2 observations keep their existing explicit claim boundaries.
Hosts without this explicit broker profile continue to refuse flow-required
tools. The real Linux broker gate exercises the shipped CLI, confined tool,
original TLS provider request, restart replay and v3 verification together.
