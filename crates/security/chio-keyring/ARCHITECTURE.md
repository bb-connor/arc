# chio-keyring architecture

## Responsibility and boundary

The crate owns authority-key lifecycle evidence, verified history replay,
transactional key selection, artifact-signing evidence, witnesses, and pinned
verifiers. Public artifact types expose canonical encoding and explicit
verification. `SqliteKeyLogStore` owns durable operator history and its selector;
`KeyringSigningRouter` owns the active signing backend and pending backend lease.

`KeyLogState` is an in-memory verified projection. Replaying it neither writes a
database nor starts services. Durable operator, witness, and verifier stores are
separate objects. Embedding authorities supply signing backends, protected seeds,
service endpoints, trust roots, a clock, and receipt forwarding.

## Structure

- `event.rs` defines identifiers, lifecycle operations, authorizations, and hashes.
- `checkpoint.rs` defines operator checkpoints, witness signatures, and commits.
- `state.rs` validates policy roots, witnessed activation sets, and replay.
- `store.rs`, `sqlite.rs`, `sqlite_parts/`, and `sqlite/` implement persisted
  heads, schema, event transactions, opening, and synchronization snapshots.
- `router.rs` binds artifact signatures to selected keys and signing epochs.
- `runtime.rs` coordinates pending rotation, witnesses, activation, and receipts.
- `witness.rs`, `verifier.rs`, `sync.rs`, and `gossip.rs` manage authenticated
  history synchronization, pins, witness decisions, and conflict evidence.
- `time.rs` verifies trusted artifact-time anchors; `enterprise_receipt.rs`
  binds lifecycle outcomes to signed operator receipts.
- `service.rs`, `ipc.rs`, and `ipc/listener.rs` implement service inputs,
  readiness, bounded exchanges, deadlines, and Unix socket lifecycle.
- `provisioning.rs` serializes one-time store creation. Two binaries run the
  witness and audit services.

## Data and control flow

A signed event commits log and authority identities, sequence, predecessor,
introduced key, operation, and times. Genesis uses bootstrap authorization.
Rotation uses the active key's authorization and new-key proof of possession.
Recovery checks the configured recovery threshold and introduced-key possession.

`SqliteKeyLogStore::append_event` verifies replay and creates the event, pending
checkpoint, enterprise receipt, and materialized state in an immediate SQLite
transaction. Witness signatures advance checkpoint stage when the configured
quorum is reached. `WitnessedActivationSet` authenticates checkpoint and commit
bindings before replay can activate a pending key.

`WitnessedRotationRuntime` stages the backend, synchronizes witness candidates,
waits for independent auditor confirmation, activates the selector, and confirms
the activated history. A post-activation retry resumes confirmation and receipt
forwarding without rotating the selector again.

`KeyringSigningRouter` checks its retained backend against the durable key and
signing epoch. It signs the artifact and separate fence evidence, verifies both,
and persists the result before returning it. Enterprise signing also persists
an artifact-time anchor. Exact artifact retries use retained evidence and check
that it still belongs to the active epoch.

Witnesses and pinned verifiers synchronize authenticated contiguous history.
They retain conflict evidence and pins in their own SQLite stores. Artifact
verification uses key status, witnessed history, artifact-time evidence, and
retained signing evidence to decide whether a historical key is acceptable.

## Trust and invariants

Canonical record decoders cap input at 1 MiB and require canonical bytes.
`validate_common` checks schema, sequence, predecessor, identities, ordering,
algorithm, weak Ed25519 keys, and derived key ID. `verify_genesis` checks the
genesis authorization set and signature; callers use common validation or replay
for the remaining event invariants.

`KeyLogPolicy::new` requires a nonempty bounded witness roster and rejects
aliased independent role keys. Its witness threshold is a strict majority.
The enterprise readiness composition requires three witnesses and two auditors,
matching configured roots, distinct processes and storage, and signed challenges.
These checks supplement the general policy constructor's broader roster bounds.

Store opening binds policy commitments and retained file identity, checks trusted
parent/file custody, takes a selector-writer file lock, and configures WAL with
`FULL` synchronization. `SigningTopology::MultiWorker` is rejected.
`open_observer` opens a read-only query-only connection without the writer fence.
SQLite persistence depends on filesystem synchronization and locking semantics.

Unix service endpoints authenticate peers and enforce bounded request deadlines.
Socket and credential custody must be maintained by the host. Trusted time is
supplied through configured roots and the owning clock; caller timestamps alone
cannot substitute for authenticated artifact-time evidence.

## Dependencies

`chio-core-types` supplies signing backends, canonical JSON, hashes, and Merkle
operations. `chio-security-types` supplies clocks and shared contracts.
`rusqlite` implements transactions and durable projections; `rustix` supplies
file custody and locks. `chio-secure-ipc` supplies shared credential checks.
Apple builds use `chio-file-custody` for descriptor ACL inspection.

## Verification

Event and checkpoint tests cover canonical envelopes, authorization sets, weak
keys, signature tampering, and quorum. State/history tests cover activation and
recovery; SQLite/router tests cover restarts, writer fencing, and stale epochs.
Witness synchronization tests cover foreign-log rejection, forks, rollback, and
pinned storage identity. Independent-service and deadline tests exercise local
service topology and bounded accepted streams. Run `cargo test -p chio-keyring`
on the service host. The README validates one signed genesis event offline.

[README](README.md) | [Secure IPC](../chio-secure-ipc/README.md)
