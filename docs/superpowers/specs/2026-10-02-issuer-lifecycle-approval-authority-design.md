# Issuer lifetime, private custody and exact approvals

This implements the approved KG2/KG3/AP2/AP3 batch from source
`a617c0b02f182afac6acab2df89a2cd9270e4923`. The security boundaries are independent
of the receipt signer: capability issuers authorize capabilities, configured
approvers authorize exact invocations, and receipt keys attest decisions.

## Issuer lifecycle

Authority history retains every public key for inspection and signature evidence.
Admission uses a separate current-time projection. An active head may issue.
Rotation makes its predecessor verification-only. The issuance cutoff is inclusive
at whole-second precision, preserving tokens legitimately issued in the rotation
second; the verification deadline is exclusive. The default grace is one hour;
operators may request a shorter deadline. Retired and revoked keys never grant
live authority and cannot return to an active or verification-only state. Historical
receipt signature verification does not consult this live capability trust set.

Version 2 authority transitions extend KG1 with explicit rotation, retirement,
revocation and recovery operations. They bind the existing stream, immutable
anchor, predecessor commitment, strictly increasing generation, transition time
and complete issuer-state digest. Rotation/retire/revoke require the current
head's signature. Retirement and revocation target historical keys; current-head
removal requires an atomic successor transition, preventing an unusable stream.

An optional independent recovery public key is pinned only at stream creation.
Recovery uses that key, atomically revokes all old issuers and selects a newly
generated local head. Without an independently pinned recovery key, recovery
fails closed. No network message changes the recovery root or distributes seeds.
Loss of both current custody and configured recovery custody requires explicit
offline provisioning of a new stream and independent operator redistribution.

Legacy KG1 checkpoints and rotation signatures keep their original canonical
bytes. Absent lifecycle fields are interpreted conservatively: the current head
is active; each historical key's cutoff is its successor's activation, with at
most one hour of verification grace. The first v2 operation materializes these
states in the signed history. A v1 operation cannot follow a v2 state. Old
envelopes cannot roll back a receiver's committed v2 prefix. Existing anchors are
immutable, so adding recovery custody to an old stream requires a new explicitly
provisioned stream, not an in-place trust expansion.

SQLite checks time and lifecycle while holding the transaction that reads or
changes authority. A durable observed-time floor prevents restart from reviving
expired keys. Issuance signs under the same transaction that validates custody
and current head. Authority read failures return no trusted keys; a cached key
is never an admission fallback. Schema versioning prevents older binaries from
opening a lifecycle-aware store and bypassing the new rules.

The kernel stops adding its receipt key to the issuer set. Its deliberately
configured default local authority still authorizes that key. Managed authority
lifecycle checks also constrain issuance timestamps; explicit static CA pins do
not silently override a managed issuer's retirement. Witnessed keyring live-key
projection takes explicit current time and excludes expired verification-only
records. An untimed projection exposes active keys only.

## Filesystem custody

The authority store prepares private directories and a private empty database
before SQLite can write a seed. Existing paths require validated ownership,
permissions, file type, link count and descriptor identity. WAL, SHM and journal
sidecars receive the same custody checks; checks run again on subsequent opens.
The store retains its original path identity and rejects replacement or unsafe
permission changes. URI parsing cannot redirect custody to an unchecked path or
enable SQLite modes that bypass it. The detailed platform contract and offline
migration are in [the custody reference](../../security/authority-sqlite-custody.md).

These checks protect local access permissions. They do not encrypt seeds, provide
HSM custody or protect against an administrator or compromised owning process.

## Execution-bound approvals

Approval submission carries the signed capability, server/tool identity, actual
arguments and a valid requester public key. The server assigns request identity
and constructs `BoundToolInvocation`, including canonical argument and capability
bindings plus the current policy and configured approval tenant. A caller's raw
parameter hash or unbound intent cannot authorize a tool call.

Only an explicitly configured approver roster grants approval authority. Neither
CA membership nor possession of the sidecar's receipt key implies approval.
Responding requires an approver-signed token over the exact server-built intent
and requester. Persisted decisions retain the approver, signed token and original
request. Legacy rows missing that evidence can be inspected but not redeemed.

Evaluation reconstructs the binding from the presented capability, route,
arguments, request, tenant and current policy. It uses the existing durable
operation-owned approval source and admission replay commitment, preserving the
authenticated-executor boundary. An approval succeeds at most once; substitution,
expiry, revoked authority, changed policy/roster, replay and competing redemption
deny before dispatch. Invalid requester keys are rejected without substitution.

Terminal approval decisions are immutable. Revocation is enforced by revoking the
capability or removing the signer from the current approver roster; there is no
independent per-token revocation endpoint.

Unsupported dual-approval and policy fields must fail policy loading rather than
silently weaken enforcement. Public policy examples and SDK requests describe the
implemented contract. Positive router tests must complete submit, signed response
and actual authorized evaluation; all-deny behavior is not successful integration.

## Acceptance

Controls execute the actual kernel, SQLite owners, routers and policy loader.
They cover honest rotation/recovery, deadlines, retire/revoke, malformed or stale
replication, competing writes, rollback, restart, clock failure, private-file
refusal, exact approval binding and replay. Cargo graphs are serialized and Rust
edits pause during each graph. One bounded independent review precedes source
publication. Local evidence does not establish hosted checks, deployment,
operator migration, release publication or completion of the whole roadmap.
