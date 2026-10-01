# chio-keyring

`chio-keyring` provides the durable authority-key transparency log used by Chio enterprise runtimes. It binds signed key events, operator checkpoints, witness signatures, activation commits, artifact signing epochs, trusted-time anchors, and enterprise rotation receipts into one verified history.

## Supported platforms

The storage, replay, checkpoint, witness, router, and verification APIs are portable Rust. The production service topology uses Unix domain sockets and is supported on Unix platforms. The `chio-keylog-witness` and `chio-keylog-audit` binaries fail closed on platforms without Unix domain sockets.

## Production trust roots

A production deployment has these independently configured roots:

- One bootstrap public key for genesis authorization.
- One operator public key and a mode-0600 Ed25519 seed file for checkpoint, activation, and enterprise-receipt signatures.
- Exactly three witness public keys, each paired with a separate witness socket and durable SQLite database. Activation requires signatures from at least two witnesses.
- Exactly two distinct auditor public keys, each paired with a separate auditor socket, mode-0600 seed file, and durable SQLite database. Both auditors sign fresh readiness challenges.
- One non-empty set of artifact-time public keys.
- Recovery public keys and a recovery threshold when recovery authorization is enabled.

The versioned key-log policy owns exactly two auditor roots and commits their identifiers and public keys through `chio.key-log.auditor-policy-binding.v1` into the configuration binding. The runtime rejects duplicate auditor roots, roots aliased to bootstrap, operator, witness, recovery, artifact-time, active, pending, or prior lifecycle keys, shared durable storage identities, repeated service identities, stale challenges, conflicting witness views, and topology maps that do not exactly match the policy-owned roots.

## Deployment

Provision the operator database once, then run three `chio-keylog-witness` services and two `chio-keylog-audit` services under separate operating-system identities. Keep every seed, database, and socket on a distinct absolute path. Socket parent directories and seed files must be private. Auditors open the operator database read-only and poll all three witnesses.

The control-plane runtime configuration supplies the operator database and seed paths, active authority seed, all witness and auditor roots, all five service endpoints, recovery policy, and artifact-time roots. Startup requires signed readiness from all five services. A normal Chio receipt store is also required; signed key-enterprise receipts are forwarded into that store as signed trace-observation receipts.

Activate the composition on `chio trust serve` with
`--authority-keyring-config`, the global `--authority-seed-file`, a durable
`--receipt-db`, and a distinct `--authority-workload-token`. The profile is
single-node: `--authority-db` and cluster peer URLs are rejected because the
keyring selector lease does not share the trust-control cluster consensus
domain. The runtime opens and verifies the complete topology before binding its
HTTP listener. It exposes canonical contiguous history at
`POST /v1/authority/key-log/sync` to callers authenticated with the
administrative service token.

Once loaded, the keyring is the sole owner of the authority seed. Capability
issuance and authority rotation use its generation-fenced signing backend.
Other trust-control routes that still require a directly loaded seed are
unavailable in this profile and fail closed; they do not fall back to raw seed
signing.

The operator SQLite store acquires an operating-system file lock beside the database for the lifetime of its single writer. Read-only auditors use `SqliteKeyLogStore::open_observer` and do not acquire the writer fence. A restart at a pending rotation tail boots from the latest accepted checkpoint, retains the pending operator head for synchronization, and resumes only when the supplied pending backend matches the durable pending key.

## Key recovery

Normal rotation requires authorization by the active key plus proof of possession by the new key. Recovery events require the configured recovery threshold and remain subject to the same operator checkpoint, witness quorum, activation-commit, auditor, and replay checks. Recovery changes authority-key state; it does not replace the operator, witness, auditor, or artifact-time roots in the loaded policy.

## Residual risks

- Loss of the operator seed prevents new checkpoints and activations.
- Loss of two witness services prevents activation. This is an intentional availability tradeoff.
- Loss of either auditor prevents production readiness and audited activation completion.
- Compromise of the active authority key can authorize a rotation, but the new key must still prove possession and the checkpoint must cross the witness and auditor gates.
- Compromise of the operator key can sign checkpoints and receipts, but it cannot forge bootstrap, active-key, new-key, recovery, witness, auditor, or artifact-time signatures.
- Operating-system file locks depend on correct host and filesystem lock semantics. The writer also verifies that its lock path is a private, singly linked regular file.
- SQLite durability depends on the underlying filesystem honoring synchronous writes and atomic rename and lock behavior.
