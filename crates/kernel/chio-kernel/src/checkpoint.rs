//! Checkpoint issuance stamped with the host clock.
//!
//! Verification, transparency derivation and issuance with caller-supplied
//! time live in `chio_kernel_core::evidence_verify`; this module only adds
//! the `SystemClock` reading.

use chio_core::crypto::Keypair;
use chio_core::hashing::Hash;
use chio_core::receipt::checkpoint::KernelCheckpoint;
use chio_kernel_core::evidence_verify::{
    build_checkpoint_with_chain_frontier_at, build_checkpoint_with_previous_at,
    CheckpointChainFrontier, CheckpointError, CheckpointSigningContext,
};

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
/// checkpoint in sequence order; the new body then carries a `chain_root`
/// extending them, and the leaves are cross-checked against the predecessor's
/// own commitment when it has one. An empty slice is valid only with no
/// previous checkpoint.
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

/// Build a signed kernel checkpoint from the chain frontier rather than from
/// every prior leaf, so issuing a checkpoint costs O(log n) hashes.
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
