# ADR-0007: DPoP Binding Format

- Status: Accepted
- Decision owner: protocol and enforcement lanes

## Context

Chio capability tokens are Bearer-style credentials: any holder can present
them. This creates a stolen-token risk: if an agent's token is captured in
transit or on disk, an attacker can replay it until expiry.

The standard mitigation is Demonstration of Proof-of-Possession (DPoP), where
the holder proves they control the private key corresponding to the subject
field in the token. RFC 9449 defines DPoP for HTTP, binding proofs to HTTP
method and URI. Chio does not use HTTP for agent-to-kernel communication (it
uses an anonymous pipe or Unix domain socket), so RFC 9449's HTTP-shaped
binding fields are not applicable.

## Decision

Chio implements its own DPoP format, `chio.dpop_proof.v1`, designed for the
Chio wire protocol rather than HTTP.

### Proof Body (9 fields)

```rust
pub struct DpopProofBody {
    pub schema:        String,    // Must equal "chio.dpop_proof.v1"
    pub replay_authority: DpopReplayAuthority, // Independently selected replay domain
    pub capability_id: String,    // ID of the capability token being used
    pub tool_server:   String,    // server_id of the target tool server
    pub tool_name:     String,    // Name of the tool being called
    pub action_hash:   String,    // SHA-256 hex of the serialized tool arguments
    pub nonce:         String,    // Caller-chosen random string (replay prevention)
    pub issued_at:     u64,       // Unix seconds when the proof was created
    pub agent_key:     PublicKey, // Hex-encoded Ed25519 public key of the signer
}
```

The proof body is serialized to canonical JSON (RFC 8785) and signed with
Ed25519 by default, or the configured signing backend. The signature covers
all 9 fields; none are mutable after signing. `replay_authority` binds the
destination store UUID, authority ID, source expectation digest, proof TTL
and maximum clock skew. The verifier selects this authority independently
and requires its durable activation before accepting an invocation.

### Verification Checks

1. **Resource bounds** -- replay identities must fit the configured byte bounds.
2. **Schema and authority** -- `schema` must equal `"chio.dpop_proof.v1"`, and
   `replay_authority` must equal the independently configured, activated domain.
   Unknown schemas and missing or mismatched authority are rejected.
3. **Sender constraint** -- `agent_key` must equal `capability.subject`. This
   binds the proof to the key the CA authorized.
4. **Binding fields** -- `capability_id`, `tool_server`, `tool_name`, and
   `action_hash` must all match the actual invocation context. A stolen proof
   cannot be replayed for a different tool or different arguments.
5. **Freshness** -- `issued_at + proof_ttl_secs >= now` and
   `issued_at <= now + max_clock_skew_secs`, using the authority's policy and
   trusted clock. An unrepresentable validity deadline is rejected.
6. **Signature** -- signature verification over canonical JSON of the proof body.
7. **Durable replay custody** -- admission must acquire an operation-owned
   claim for the authority, capability and nonce, bound to the exact proof,
   invocation and admitted grant. A spent identity cannot authorize a different
   operation.

All seven checks must pass. The first failure returns an error; the Kernel denies
fail-closed.

### Durable Replay Custody

`verify_dpop_proof_stateless` checks the signed evidence against a supplied
authority. The kernel's permission preview also verifies that authority's
activation. Neither step claims a nonce. Dispatch requires the durable
admission operation's exact replay claim; release before dispatch retains the
spent proof history, and dispatch commit retains custody across restart.

`DpopNonceStore` retains bounded source inventory for explicit sealing and
import. Its insertion APIs enforce marker, per-capability and byte capacity,
and preserve live markers under pressure. Signed markers expire only after
both wall and monotonic deadlines; local TTL markers use their monotonic
deadline. Sealing binds the exact instance and inventory and
forbids further insertion or pruning. Source inventory carries no dispatch
owner or release handle; an imported marker remains conservative blocking
evidence. A source seal alone does not activate an authority or grant dispatch.

### DPoP Opt-In

DPoP is optional per grant. `ToolGrant::dpop_required: Option<bool>` controls
whether the Kernel requires a proof for invocations under that grant. `None`
and `Some(false)` both mean DPoP is not required. `Some(true)` means the
Kernel will reject any invocation that does not include a valid proof.

## Why Not RFC 9449

RFC 9449 binds proofs to HTTP method, URI, and optional access token hash.
These fields are HTTP-specific and meaningless in Chio's pipe/UDS transport.
Chio binds proofs to `capability_id`, `tool_server`, `tool_name`, and
`action_hash`, which provide equivalent or stronger binding for the Chio
invocation model.

## Consequences

### Positive

- Prevents stolen-token replay without requiring mTLS on the agent-kernel
  channel (typically a local pipe or UDS that is not TCP).
- Binding to `action_hash` means a proof cannot be replayed for a different
  set of arguments, even with the same token.
- The signed replay domain binds every proof to one activated durable authority.

### Negative

- Agents must generate an Ed25519 keypair per session and sign a proof for
  every invocation where `dpop_required = true`. This adds latency for
  CPU-constrained agents.
- DPoP-required dispatch needs an activated durable store. Missing authority,
  unavailable custody, and capacity exhaustion deny the invocation.

## Required Follow-up

- Provide reference DPoP proof construction in SDK clients (Rust, TypeScript,
  Python).
- Document authority provisioning, source sealing, activation and restart
  fencing in operator security guidance.
