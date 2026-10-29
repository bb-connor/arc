//! Checkpoint issuance with explicit service-owned time.
use super::*;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::checkpoint::CHECKPOINT_SCHEMA;

/// Explicit signer and issuance time for a checkpoint authority owner.
/// The caller obtains the reading from its fallible, fenced service clock.
pub struct CheckpointSigningContext<'a> {
    pub keypair: &'a Keypair,
    pub issued_at: chio_security_types::clock::UnixMillis,
}

/// Build with the issuance time supplied by the owning service.
pub fn build_checkpoint_with_previous_at(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    signing: CheckpointSigningContext<'_>,
    previous_checkpoint: Option<&VerifiedCheckpoint<'_>>,
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

/// Build with the issuance time supplied by the owning service.
pub fn build_checkpoint_with_chain_frontier_at(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    signing: CheckpointSigningContext<'_>,
    previous_checkpoint: Option<&VerifiedCheckpoint<'_>>,
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
            validate_checkpoint_statement(previous)?;
            validate_checkpoint_successor_position(previous, checkpoint_seq, batch_start_seq)?;
            if prior_chain.leaf_count() != previous.body.checkpoint_seq {
                return Err(CheckpointError::Continuity(format!(
                    "prior chain covers {} leaves but predecessor is checkpoint {}",
                    prior_chain.leaf_count(),
                    previous.body.checkpoint_seq
                )));
            }
            // The frontier must reproduce the predecessor's signed
            // commitment exactly, so a stale or foreign frontier is never
            // extended into a signed root.
            let Some(previous_chain_root) = previous.body.chain_root else {
                return Err(CheckpointError::Continuity(format!(
                    "predecessor {} carries no chain commitment to extend",
                    previous.body.checkpoint_seq
                )));
            };
            if prior_chain.root() != Some(previous_chain_root) {
                return Err(CheckpointError::Continuity(format!(
                    "predecessor {} chain_root does not match the supplied chain",
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
    let canonical = CanonicalBytes::from_serializable(&body)
        .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    let signature = keypair
        .sign_wrapped(CHECKPOINT_SCHEMA, &canonical)
        .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    Ok(KernelCheckpoint { body, signature })
}
