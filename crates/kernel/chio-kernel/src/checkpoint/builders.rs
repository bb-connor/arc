//! Checkpoint issuance with explicit service-owned time.
use super::*;

/// Explicit signer and issuance time for a checkpoint authority owner.
/// The caller obtains the reading from its fallible, fenced service clock.
pub struct CheckpointSigningContext<'a> {
    pub keypair: &'a Keypair,
    pub issued_at: chio_security_types::clock::UnixMillis,
}

/// Build a signed kernel checkpoint from a batch of canonical receipt bytes.
///
/// `receipt_canonical_bytes_batch` must not be empty. The first checkpoint of
/// a chain (`checkpoint_seq == 1`) commits a single-leaf chain; a detached
/// checkpoint at a later sequence is issued without a chain commitment.
pub fn build_checkpoint(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_previous(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        keypair,
        None,
        &[],
    )
}

/// Build a signed kernel checkpoint that explicitly links to the previous
/// checkpoint when provided.
///
/// `prior_chain_leaf_hashes` must hold the chain leaf of every prior
/// checkpoint in sequence order (see [`checkpoint_chain_leaf_hash`]); the new
/// body then carries a `chain_root` extending them, and the leaves are
/// cross-checked against the predecessor's own commitment when it has one. An
/// empty slice is valid only with no previous checkpoint.
pub fn build_checkpoint_with_previous(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&KernelCheckpoint>,
    prior_chain_leaf_hashes: &[Hash],
) -> Result<KernelCheckpoint, CheckpointError> {
    use chio_security_types::clock::{Clock, SystemClock};
    build_checkpoint_with_previous_at(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        CheckpointSigningContext {
            keypair,
            issued_at: SystemClock.unix_millis()?,
        },
        previous_checkpoint,
        prior_chain_leaf_hashes,
    )
}

/// Build with the issuance time supplied by the owning service.
pub fn build_checkpoint_with_previous_at(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    signing: CheckpointSigningContext<'_>,
    previous_checkpoint: Option<&KernelCheckpoint>,
    prior_chain_leaf_hashes: &[Hash],
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_chain_frontier_at(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        signing,
        previous_checkpoint,
        &CheckpointChainFrontier::from_leaves(prior_chain_leaf_hashes),
    )
}

/// Build a signed kernel checkpoint from the chain frontier rather than from
/// every prior leaf.
///
/// This is the hot path: a long-lived writer keeps the frontier and extends
/// it, so issuing a checkpoint costs O(log n) hashes instead of rehashing the
/// whole chain. The predecessor's signed `chain_root` is still checked, at the
/// same O(log n) cost, so the integrity guarantee is unchanged.
pub fn build_checkpoint_with_chain_frontier(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&KernelCheckpoint>,
    prior_chain: &CheckpointChainFrontier,
) -> Result<KernelCheckpoint, CheckpointError> {
    use chio_security_types::clock::{Clock, SystemClock};
    build_checkpoint_with_chain_frontier_at(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        CheckpointSigningContext {
            keypair,
            issued_at: SystemClock.unix_millis()?,
        },
        previous_checkpoint,
        prior_chain,
    )
}

/// Build with the issuance time supplied by the owning service.
pub fn build_checkpoint_with_chain_frontier_at(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    signing: CheckpointSigningContext<'_>,
    previous_checkpoint: Option<&KernelCheckpoint>,
    prior_chain: &CheckpointChainFrontier,
) -> Result<KernelCheckpoint, CheckpointError> {
    let CheckpointSigningContext { keypair, issued_at } = signing;
    let tree = MerkleTree::from_leaves(receipt_canonical_bytes_batch)?;
    let merkle_root = tree.root();
    let covered_entries = batch_end_seq
        .checked_sub(batch_start_seq)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            CheckpointError::Invalid(format!(
                "invalid checkpoint entry range {batch_start_seq}-{batch_end_seq}"
            ))
        })?;
    if usize::try_from(covered_entries).ok() != Some(tree.leaf_count()) {
        return Err(CheckpointError::Invalid(format!(
            "receipt batch length {} does not match covered entry count {} for range {}-{}",
            tree.leaf_count(),
            covered_entries,
            batch_start_seq,
            batch_end_seq
        )));
    }

    let own_chain_leaf = checkpoint_chain_leaf_hash_from_parts(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        merkle_root,
    )?;
    let chain_root = match previous_checkpoint {
        None => {
            if prior_chain.leaf_count() != 0 {
                return Err(CheckpointError::Invalid(
                    "prior chain leaves supplied without a previous checkpoint".to_string(),
                ));
            }
            (checkpoint_seq == 1)
                .then(|| checkpoint_chain_root(&[own_chain_leaf]))
                .transpose()?
        }
        Some(previous) => {
            validate_checkpoint(previous)?;
            validate_checkpoint_successor_position(previous, checkpoint_seq, batch_start_seq)?;
            if prior_chain.leaf_count() != previous.body.checkpoint_seq {
                return Err(CheckpointError::Continuity(format!(
                    "prior chain covers {} leaves but predecessor is checkpoint {}",
                    prior_chain.leaf_count(),
                    previous.body.checkpoint_seq
                )));
            }
            // When the predecessor committed a chain, the frontier must
            // reproduce exactly that commitment: this is what stops a stale or
            // foreign frontier from being extended into a signed root.
            if let Some(previous_chain_root) = previous.body.chain_root {
                if prior_chain.root() != Some(previous_chain_root) {
                    return Err(CheckpointError::Continuity(format!(
                        "predecessor {} chain_root does not match the supplied chain",
                        previous.body.checkpoint_seq
                    )));
                }
            } else if prior_chain.last_leaf != Some(checkpoint_chain_leaf_hash(&previous.body)?) {
                return Err(CheckpointError::Continuity(format!(
                    "legacy predecessor {} is not the final supplied chain leaf",
                    previous.body.checkpoint_seq
                )));
            }
            let mut chain = prior_chain.clone();
            chain.append(own_chain_leaf);
            chain.root()
        }
    };

    let body = KernelCheckpointBody {
        schema: CHECKPOINT_SCHEMA.to_string(),
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        tree_size: tree.leaf_count(),
        merkle_root,
        issued_at: issued_at.as_secs(),
        kernel_key: keypair.public_key(),
        previous_checkpoint_sha256: previous_checkpoint
            .map(|checkpoint| checkpoint_body_sha256(&checkpoint.body))
            .transpose()?,
        chain_root,
    };
    let body_bytes =
        canonical_json_bytes(&body).map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    let signature = keypair.sign(&body_bytes);
    Ok(KernelCheckpoint { body, signature })
}
