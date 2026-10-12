# chio-pheromone-runtime architecture

## Responsibility and boundary

`PheromoneReceiver` combines a `PheromoneRuntimeStore`, a
`WorkflowContextResolver`, and receiver-owned `PheromoneReceiverConfig`.
Its public operations receive a batch or query concentration at the time
captured in that configuration. Transport authentication and periodic policy
refresh remain caller responsibilities.

`SqlitePheromoneRuntimeStore` owns deposit, replay, scarcity, pair/diversity,
passport history, and receive-report persistence. `open` creates parent
folders and a persistent database; `open_in_memory` uses an ephemeral database.
The crate provides no HTTP listener or automatic kernel-verdict integration.

## Structure

| Module or asset | Responsibility |
|-----------------|----------------|
| `lib` | Receiver, trust wrappers, policy import, peer weights, proof resolver |
| `input` | Bounded duplicate-aware wire JSON projection |
| `store` | SQLite migration, scoped admission, report custody, concentration |
| `schemas/transit-policy.schema.json` | Signed policy's required field shape |
| `schemas/peer-weights.schema.json` | Weight document shape and ranges |

The public workflow wrappers keep proof package, trust bundle, and verification
context parsing behind Chio-owned types. `PheromoneReceiveReport` distinguishes
accepted, rejected, and partial batches with per-frame codes and counts.

## Data and control flow

1. Import the signed transit/admission policy with trusted verifier issuer keys
   and trusted time. Check the schema, issuer key pins, policy hash bindings,
   explicit scarcity policies, and overlapping windows.
2. Build a workflow resolver from a package verified against its trust bundle
   and verification context. Retain package/trust/context digests.
3. Begin a receive transaction and authenticate the batch envelope against the
   configured recipient and authenticated sender.
4. Verify each frame's transit policy, then resolve any workflow reference.
5. Admit that deposit for the frame's exact treaty under a savepoint. An invalid
   frame rolls back its state, while valid frames remain eligible to commit.
6. Persist the report and commit all accepted state in the same transaction.
7. Query concentration using persisted passport history and supplied weights.

A malformed envelope yields a persisted rejected report. Storage failures
return errors or rejected frame codes at their respective boundary; they cannot
produce a committed acceptance when report persistence fails.

## Trust and invariants

The default `PheromoneRuntimeStore::receive_batch` rejects implementations that
lack atomic receive/report persistence. The default scoped deposit method also
rejects; custom stores must implement the treaty-specific live boundary.

Policy issuer keys must occur in both verifier trust roots and admission roots.
An envelope cannot authorize itself by embedding a new key. Local policy and
peer weights must come from verifier-owned configuration. Weight import rejects
duplicate kernel ids; an unknown configured peer uses weight 1.0 in the static
provider, while a mismatched epoch or invalid numeric weight rejects on lookup.

SQLite replay identity is keyed by kernel, passport hash, and nonce until its
window expires. Quota buckets include epoch, scarcity window, treaty, namespace,
and class. File-backed state survives reopening, including passport admission
history used for newcomer discount.

Receive-report recovery lookup uses both batch digest and authenticated sender.
It prefers committed acceptance/partial evidence over later replay rejection so
relay recovery can retain the original admitted result. A query report is an
observation result; a runtime policy consumer separately chooses its effect.

## Dependencies

`chio-federation` validates gossip envelopes and transit frames.
`chio-pheromone` supplies deposit validation, scarcity, decay, and discounts.
`chio-attest-buyer-core` verifies workflow proof packages behind public wrappers.
`chio-core-types` supplies canonical commitments; `jsonschema` checks imported
policy shapes; `rusqlite` supplies transactional persistence.

## Verification

Run `cargo test -p chio-pheromone-runtime` from the workspace root.
`tests/runtime_receiver.rs` covers signed-policy import, overlapping windows,
frame treaty scope, rollback on report failure, replay after reopening, workflow
mismatch, partial batches, and persisted newcomer history.
`tests/public_surface.rs` checks resolver names and public error ownership.
The README opens SQLite in memory and imports weights without network access.
