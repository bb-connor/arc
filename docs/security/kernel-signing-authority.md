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
exposing private key material. `public_key()` returns the kernel's classical
identity, which the default local authority deliberately uses. Configuring a
different capability authority removes that implicit issuer relationship.
Installing a receipt signer does not add it to the capability issuer set,
approver roster or separately configured active-response authorities.

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
integration and qualification. Ordinary tool approvals now require the separate
roster and exact invocation binding described in
[approval collection](threshold-approval-collection.md). Complete
pending-operation cancellation/recovery remains open.

Local quote-verifier fixtures, in-memory durable-operation fixtures and signing
queue tests do not establish physical process-crash recovery, real TEE evidence,
native cage enforcement, hosted exact-head qualification or operational-pilot
completion. These boundaries remain explicit launch gates.

## Compliance and product-truth review (October 1, 2026)

The [compliance and product-truth review](../reviews/2026-10-01-compliance-product-truth-review.md) re-verified at `122414b48e` the product defects behind the repository's compliance, security and supply-chain claims: 69 findings, 3 High. The October 2 [issuer and approval execution record](../reviews/2026-10-02-issuer-lifecycle-approval-authority-execution.md)
locally accepts KG2/KG3 within its Linux and operator boundaries. Current
dispositions against key custody and issuer trust:

- **KG1, High, source repair.** Both cluster import paths now require an
  authenticated chain rooted in an operator-pinned checkpoint. Off-loopback
  plaintext peers reject. The [execution record](../reviews/2026-10-02-identity-authority-release-closure-execution.md)
  owns local acceptance; deployed migration and hosted qualification remain separate.
- **KG2, Medium, locally accepted source repair.** SQLite lifecycle now has
  signed rotation, retirement, revocation and independent-root recovery; live
  keyring projection enforces `verify_until`. Receipt, capability and approval
  authority are separate. See [issuer lifecycle](issuer-lifecycle.md) for the
  protocol, CLI, legacy migration and explicit custody-handover limits.
- **KG3, Medium, locally accepted source repair.** Linux authority stores
  require private directories, database and sidecars before seed writes and
  recheck ownership and identity. Other OS implementations fail closed. Seeds
  remain plaintext. See [filesystem custody](authority-sqlite-custody.md).
- **KG14, Low.** Remote signing reaches only the finding-market hosted profile.
- **AP9, Medium.** API protect signs with a fresh `Keypair::generate()` on every start without a seed.

## Signed cluster authority replication (KG1)

Authority replication uses a named, operator-pinned checkpoint and a canonical
Ed25519 chain. Each rotation is signed by the previous head and commits to the
exact predecessor, next generation, next key and complete issuer set. The final
head signs a live snapshot envelope with a maximum five-minute lifetime. The
receiver rejects future-issued and expired envelopes, unsigned input, changed
history, generation conflicts, unpinned streams and unhealthy or regressing time.

Both incremental pulls and full cluster recovery use the same SQLite import.
Signature checks and the durable predecessor comparison run under an immediate
write transaction. The issuer set, public head, retained chain, envelope and clock
floor commit together. A rejected import changes none of those rows. An exact
replay is idempotent. A follower may relay a still-fresh envelope already accepted
from its custodian; it cannot sign a fresh envelope without that head's key.

Local seeds stay local. Reopening a follower never adds its private-key identity
back to the verification set. A follower with a mismatched seed cannot issue or
rotate the replicated authority. Peer transport tokens do not grant issuer trust.
HTTPS uses the HTTP client's normal certificate and hostname verification. HTTP
peers must use literal loopback IP addresses; the local-address override does not
permit plaintext elsewhere, and peer snapshot clients do not follow redirects.

### Provisioning and unsigned-state migration

Provision offline, before starting peer replication. Initialize the source's
current public state as an explicit checkpoint:

```bash
chio federation authority replication-init \
  --database /private/source-authority.db \
  --stream-id production-cluster-1:capability-authority \
  --out authority-anchor.json
```

The command prints the canonical checkpoint digest. Transfer the public anchor
file and authenticate that digest through an independent operator channel. On a
follower, pin the checkpoint before enabling cluster traffic:

```bash
chio federation authority replication-pin \
  --database /private/follower-authority.db \
  --anchor authority-anchor.json \
  --expected-anchor-digest "$AUTHENTICATED_ANCHOR_DIGEST"
```

The command rejects a mismatched digest before opening the follower database.
Pinning replaces the follower's public verification set and preserves its private
seed. Repeating the same checkpoint is idempotent; changing a stored pin rejects.
Review every issuer in a legacy checkpoint before distributing it. This operation
asserts operator trust in the current state; it does not manufacture signatures
for old rotations. Unconfigured databases continue local use but refuse authority
network import and export. Schema revision 3 makes older store binaries refuse the
upgraded database rather than reopening unsigned or lifecycle-unaware paths.

An existing database whose current head is absent from its persisted issuer
history refuses to open. This includes incomplete legacy initialization with a
missing or empty history table. Opening never repairs that state by adding the
local seed's key. Stop the service, retain the database for investigation, and
restore a known-good authenticated backup before checkpointing. If no trustworthy
history exists, provision a new authority database and distribute its checkpoint
explicitly; do not treat the old seed as evidence for missing history.

Upgrade and provision every receiving peer before relying on this boundary.
Unsigned older peers cannot participate in the authenticated stream. Local
checks do not establish that a deployed cluster has completed this migration.

A stream permits at most 1,024 signed transitions after its pinned checkpoint and
4,096 retained issuers, with bounded persisted records. Reaching a bound denies a
further rotation atomically and requires an explicit new-stream provisioning plan.
Automatic checkpoint replacement and custody handover remain operator acceptance
work. Signed retirement, revocation and recovery are described in
[issuer lifecycle](issuer-lifecycle.md). These commands do not activate a cluster
or qualify a release.

See the [protocol design](../superpowers/specs/2026-10-02-authority-replication-design.md)
and [execution plan](../superpowers/plans/2026-10-02-identity-authority-release-closure.md)
for the acceptance controls and remaining qualification.
