# Kernel signing authority

`ChioKernel::with_hybrid_signing_backend` installs one immutable backend and its
boot signing floor after the existing self-quote gate accepts the configuration.
Default construction shares one Ed25519 backend. Hybrid construction shares the
same Ed25519 plus ML-DSA-65 backend across the following paths:

| Path | Authority and checks |
| --- | --- |
| Cumulative threshold proposal | Boot-selected backend; current proposal policy and capability floor |
| Ordinary inline decision receipt | Boot-selected backend and boot receipt floor; exact content-preimage verification |
| Receipt signing queue | Same backend, exact caller-supplied signing identity and content preimage |
| Queue-count or aggregate-byte fallback | Same backend and signing primitive; no classical fallback |
| Durable terminal projection and replay | Current receipt authority, retained operation binding and original signed receipt |

The queue still enforces its count, per-request and aggregate-byte limits. Boot
reconfiguration preserves those limits and terminal shutdown state. A rejected
quote or unavailable required key leaves the installed authority, floor and
signing task unchanged. Configure signing before serving requests. Reconfiguration
is not a witnessed key-rotation protocol, and it does not revoke a previously
returned signing handle.

## Identity and compatibility

`receipt_signing_public_key()` exposes the ordinary receipt identity without
exposing private key material. `public_key()` continues to return the classical
local capability authority. Installing a receipt signer does not add it to the
capability issuer set or to separately configured active-response authorities.

`set_capability_crypto_floor` only changes capability and threshold validation.
It neither constructs a receipt signer nor changes the previously installed boot
receipt floor. Use the boot configuration to install hybrid receipt signing.
Setting a capability-only floor is not evidence of an all-artifact PQ runtime.

Classical canonical receipt encoding is unchanged. Hybrid signatures are
randomized, so fresh signatures over the same canonical body need not be equal.
Inline and channel signing must preserve the same canonical body and produce
independently valid signatures. Durable replay returns the original complete
signed envelope byte-for-byte; it does not mint a fresh equivalent signature.

Queue callers must construct a body naming the current receipt signing key.
Stale keys and mismatched content preimages reject, including on the inline
fallback. The kernel never rewrites a supplied identity to make signing succeed.

The finding-pool mutation signer remains a separately pinned authority. An
`AllowHybrid` boot does not replace that key. A `PqRequired` boot rejects a
classical pool signer instead of substituting the ordinary kernel signer.

## Recovery and remaining qualification

Durable receipt qualification uses the same authority as receipt construction.
Replay verifies its signature under the boot receipt floor as well as the exact
retained operation, output, decision, metadata and tenant bindings. Changing the
signer does not implicitly preserve authority for old receipts or re-sign them.
Restoring a compatible original authority can resume retained state.

This integration does not complete enterprise key custody. The roadmap still
requires production composition through `KeyringSigningRouter`, with shared
signing-epoch fencing, durable artifact anchoring, independent services, witnessed
activation and qualified old-key history. The existing boxed boot return is a
compatibility API, not the final enterprise custody boundary.

Capability issuance, child receipts, session anchors, execution nonces,
checkpoints and other separately owned artifacts still require their own signing
integration and qualification. Production authenticated approval collection and
complete pending-operation cancellation/recovery remain open too.

Local quote-verifier fixtures, in-memory durable-operation fixtures and signing
queue tests do not establish physical process-crash recovery, real TEE evidence,
native cage enforcement, hosted exact-head qualification or operational-pilot
completion. These boundaries remain explicit launch gates.
