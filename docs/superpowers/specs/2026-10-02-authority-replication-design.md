# Authenticated capability authority replication

This implements KG1 in the approved identity, authority and release closure plan.
The service token identifies a peer transport caller. It never authorizes a new
capability issuer.

## Trust bootstrap and migration

An operator initializes a named authority stream from the current local authority
checkpoint. The checkpoint contains the exact head, generation, rotation time and
complete issuer history. Its canonical digest is the initial chain commitment.
Every follower pins that same checkpoint through a local provisioning operation.
Neither HTTP handler nor peer client can invoke that operation. Existing unsigned
history is an explicitly approved checkpoint, never represented as signed history.

A store can be pinned once. Repeating the identical pin is idempotent; replacing
it is rejected. Pinning replaces the public verification set, preserving the
local private seed. A follower whose private seed differs from the replicated
head cannot issue or rotate that authority. Copying private seeds is not part of
replication. Unconfigured stores retain local issuance and rotation but reject
all network authority imports and exports.

## Signed contracts

All bodies use canonical JSON, explicit versioned schema domains and strict
Ed25519 verification. The stream identifier and pinned checkpoint digest bind
every transition and envelope to one operator-selected trust domain.

Each rotation records the exact prior commitment and generation, the new head,
rotation time and complete issuer-set digest. The prior head signs the transition.
The next generation is exactly the prior generation plus one. The only permitted
change is appending that new head; history cannot be inserted, rewritten or
removed. Retirement and recovery remain KG2.

An export carries the complete signed chain from the pinned checkpoint and the
final public snapshot. A fresh envelope signed by the final head binds its state
digest and final chain commitment, issued time and expiration. Retained transitions
may be old; only the envelope is a current liveness assertion. The envelope lifetime
is at most five minutes, with no future-issued allowance. Consumers sample their
owned authority clock and reject expired, future-issued or unhealthy time. The
stream has bounded identifiers, keys, transitions and encoded bytes.

## Atomic acceptance

Under one SQLite immediate transaction the receiver loads its pinned checkpoint,
durable commitment and clock floor, verifies every transition and envelope, checks
the current local state matches the corresponding signed chain prefix, and rejects
regression or divergence. Exact head replay is idempotent. An older chain cannot
add even a historical key. Only after verification may the public head, complete
issuer set, signed chain, accepted envelope and clock floor be committed. Rejection
leaves those tables and cached authority views unchanged. Concurrent competing
imports compare against durable state after acquiring the write lock.

Rotation records its signed transition in the same transaction as the private
seed replacement and public head. Failed writes roll back every part. Reopening
does not add a follower's local private-key identity to the replicated issuer set.

## Network composition

Incremental authority pulls and full cluster snapshots share the same signed
store import. Export handlers share the service's injected clock. Unsigned legacy
wire input has no fallback. HTTPS retains normal certificate and hostname
verification; HTTP is permitted only for literal loopback addresses. The existing
local-address override does not enable off-loopback plaintext or unverified TLS.

## Evidence

Controls cover both network import paths, honest multi-rotation replication,
signature and identity substitution, history insertion, stale or conflicting
generation, future and expired envelopes, unavailable or regressing clocks,
restart, concurrent conflicts, rollback after injected SQL failure, and actual
kernel denial of capabilities from refused issuers. Local controls do not claim
hosted deployment, key custody, retirement or release acceptance.
