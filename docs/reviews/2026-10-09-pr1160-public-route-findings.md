# Public route findings during PR 1160 snapshot composition

Reviewed source: `3b0760cfe7c8bdd286fac137663872ab6ebc1e1d`.
Landing destination: PR #1160. This record preserves finding identity and
acceptance. Consult the canonical landing ledger for current repair and
qualification status; this document does not report a merged candidate.

## OID4VP-ISSUER-FETCH (P1, repair before landing)

The public OID4VP direct-post handler resolves keys for an unverified issuer
before enforcing issuer trust. An empty request allowlist accepts remote
issuers. The synchronous remote fetch also lacks strict destination and
resource controls and occupies an async worker. A remote wait can carry
acceptance past credential, holder or request expiry when the initial time
is reused. These defects are confirmed at the reviewed source; the issuer
fetch behavior also predates this PR.

Required repair: local issuer keys or an explicit issuer in the stored signed
request; empty allowlist means local-only. Remote HTTPS must validate and pin
all resolved addresses, refuse redirects and private destinations, bound
transport and response bytes, and avoid reflecting remote or panic text.
Admission precedes blocking work and remains held through cancellation.
Revalidate the complete response at trusted final acceptance time after both
issuer and lifecycle waits, then consume atomically with that same time.

Evidence: original untrusted-issuer and expiry tests fail; residual final
credential-expiry and panic-reflection tests fail before their repairs.
The owner retains exact logs and hashes in
`/home/connor/lanes/claude-pr1160-evidence/vfix/oid4vp-issuer-fetch/`.
Composed owning tests, strict lint and shared scanners remain separate gates.

## PUBLIC-WORKER-ISOLATION (P2, repair before landing)

Public passport challenge verification and finding search execute synchronous
storage or adapter work on async workers. A blocked dependency stalls unrelated
requests. The original current-thread controls demonstrate both stalls.

Required repair: separate bounded, nonqueued admission for each route family,
with the permit acquired before offload and retained until response
materialization finishes, including cancellation. Preserve search and challenge
semantics. Cover saturation, executor progress and permit custody. Generic
verifier GET offloading remains a recorded follow-up and is not claimed fixed
by this bounded repair.

## AUTHORITY-READONLY (P1, repair before landing)

Unauthenticated metadata, discovery and JWKS reads open the writable SQLite
authority and persist the observed-time floor during status inspection. Some
responses repeat this work while loading signing keys. Public read traffic
therefore competes for immediate write transactions and fsync with issuance
and rotation, which can fail with SQLITE_BUSY. This write amplification is
partly introduced by this PR and is distinct from generic worker offloading.

Required repair: inspect existing authority state through a validated read-only
connection. Public reads must not create a database, seed or parent directory,
bootstrap or migrate schema, or write authority data or its time floor.
Validate custody, descriptor identity, schema, lifecycle and clock regression
against the persisted floor. Observe current rotations without a stale cache.
Ordinary SQLite read-lock/WAL shared-memory bookkeeping is permitted; disabling
WAL visibility with immutable mode is not. Preserve authorized startup/admin
provisioning and writable mutation behavior. Cover public status and signing
key reads, including generic listings and health where they share this path.

Acceptance requires genuine write-observing original failures, successful
zero-authority-write public responses, absent-state refusal without creation,
rotation/lifecycle visibility, custody and clock controls, and owning/strict
qualification. The owner is repairing this finding on an isolated branch;
no completed repair is asserted here.
