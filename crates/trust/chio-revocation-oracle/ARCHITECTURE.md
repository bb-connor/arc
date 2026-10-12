# chio-revocation-oracle architecture

## Responsibility and boundary

The crate owns revocation-key indexing, Merkle proof material, signed epoch
roots, age checks, and conversion of passport revocation events into keys.
It also owns a distinct 256-level sparse map keyed by finding IDs.
Consumers provide persistence, signer provisioning, transport, and admission.

`RevocationOracle` separates insertion and lookup from signing and broadcasting.
`EpochRootSigner` holds the signing role; `EpochRootVerifier` provides the
verify-only role with a pinned identity and public key.

## Structure

| Module | Responsibility |
| --- | --- |
| `api` | Key, epoch, signature, proof, trait, and error definitions. |
| `sparse_merkle` | Append-only in-memory revocation log and local absence checks. |
| `signer` | Domain-separated canonical root signing and verification. |
| `freshness` | Root age and offline-grace policy. |
| `epoch` | Signed-root carrier, manual tick, bounded broadcaster queue. |
| `passport_bridge` | Validated events and revocation-key conversion. |
| `finding_status_sparse` | Portable sparse inclusion and empty-leaf absence proofs. |

## Data and control flow

`InMemoryRevocationOracle::insert` hashes a length-prefixed subject and big-endian
nonce, appends a leaf, updates tree layers, and records the key's index.
It increments the epoch with saturation and clamps issuance time to its prior
maximum. An empty log uses a zero root hash.

Inclusion proof production returns the key, leaf position, current root, and
sibling bytes. Verification reconstructs the key hash and uses `rs_merkle` to
check membership against the root carried in that proof.

`SignedEpochRoot::sign` signs a supplied root. `tick_and_broadcast` signs and
publishes to each sink sequentially; a later sink failure leaves earlier
publications in place. The constant tick interval does not start a scheduler.
The bounded queue drains FIFO and discards its oldest entry at capacity.

## Trust and invariants

Root signatures cover a fixed domain prefix followed by RFC 8785 canonical
root bytes. Verification authenticates the root using a pinned key and signer
ID. It does not check freshness, epoch rollback, or correspondence with a
separately supplied inclusion proof; the consumer must bind these checks.

`verify_fresh_epoch_root` rejects future issuance and age beyond the saturating
sum of staleness and grace. `FreshnessConfig::default` accepts age zero only.
Caller-provided time determines this decision.

General non-inclusion material contains a key, root, and checked timestamp.
`verify_non_inclusion` compares the root to current local state and checks key
absence. It does not authenticate the checked timestamp or provide a portable
Merkle absence path.

Finding-status proofs hash the exact finding ID and require 256 siblings.
Inclusion binds a retraction-intent digest; absence starts from the canonical
empty leaf. The consumer separately authenticates the supplied root and its
status-authority lifecycle.

The passport event constructor validates text and a nonzero timestamp.
`apply_passport_revocation` does not rerun constructor validation.
Its key uses subject and a salted timestamp, so passport IDs with equal subject
and timestamp collide. Repeated keys return `AlreadyApplied` without advancing
state. This bridge does not itself change credential lifecycle records.

## Dependencies

`rs_merkle` supplies proof verification and SHA-256 tree operations.
`chio-core-types` supplies canonical signing and key primitives; `sha2` supports
the finding-status map. Serde encodes carriers; `thiserror` names oracle errors.

## Verification

Run `cargo test -p chio-revocation-oracle` for membership, absence, signatures,
freshness, epoch monotonicity, finding-status paths, and bridge fixtures.
Run `cargo test -p chio-revocation-oracle --features delegation` for the in-process
swarm latency and receipt-chain checks using federation and kernel caches.
`cargo bench -p chio-revocation-oracle --bench oracle_throughput` measures insert
and proof production at 10,000 baseline subjects and asserts a fixture budget.
These checks use local state and do not measure deployed network propagation.
