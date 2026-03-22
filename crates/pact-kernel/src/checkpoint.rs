//! Merkle-committed receipt batch checkpointing.
//!
//! Produces signed kernel checkpoint statements that commit a batch of receipts
//! to a Merkle root. Inclusion proofs allow verifying that a specific receipt
//! was part of a batch without replaying the entire log.
//!
//! Schema: "pact.checkpoint_statement.v1"

use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::canonical::canonical_json_bytes;
use pact_core::crypto::{Keypair, PublicKey, Signature};
use pact_core::hashing::Hash;
use pact_core::merkle::{MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::ReceiptStoreError;

/// Error type for checkpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("merkle error: {0}")]
    Merkle(#[from] pact_core::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),
}

/// The signed body of a kernel checkpoint statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCheckpointBody {
    /// Schema identifier -- always "pact.checkpoint_statement.v1".
    pub schema: String,
    /// Monotonic checkpoint counter.
    pub checkpoint_seq: u64,
    /// First receipt seq in this batch.
    pub batch_start_seq: u64,
    /// Last receipt seq in this batch.
    pub batch_end_seq: u64,
    /// Number of leaves in the Merkle tree.
    pub tree_size: usize,
    /// Root from MerkleTree::from_leaves.
    pub merkle_root: Hash,
    /// Unix timestamp (seconds) when the checkpoint was issued.
    pub issued_at: u64,
    /// The kernel's signing key (public).
    pub kernel_key: PublicKey,
}

/// A signed kernel checkpoint statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCheckpoint {
    /// The signed body.
    pub body: KernelCheckpointBody,
    /// Ed25519 signature over canonical JSON of `body`.
    pub signature: Signature,
}

/// A Merkle inclusion proof for a receipt within a checkpoint batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInclusionProof {
    /// Which checkpoint this proof is for.
    pub checkpoint_seq: u64,
    /// The seq of the receipt being proved.
    pub receipt_seq: u64,
    /// Index of this receipt in the Merkle leaf array.
    pub leaf_index: usize,
    /// The Merkle root this proof is against.
    pub merkle_root: Hash,
    /// The audit path proof.
    pub proof: MerkleProof,
}

impl ReceiptInclusionProof {
    /// Verify that `receipt_canonical_bytes` is included in the batch.
    #[must_use]
    pub fn verify(&self, receipt_canonical_bytes: &[u8], expected_root: &Hash) -> bool {
        self.proof.verify(receipt_canonical_bytes, expected_root)
    }
}

/// Return the current Unix timestamp in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a signed kernel checkpoint from a batch of canonical receipt bytes.
///
/// `receipt_canonical_bytes_batch` must not be empty.
pub fn build_checkpoint(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
) -> Result<KernelCheckpoint, CheckpointError> {
    let tree = MerkleTree::from_leaves(receipt_canonical_bytes_batch)?;
    let merkle_root = tree.root();
    let body = KernelCheckpointBody {
        schema: "pact.checkpoint_statement.v1".to_string(),
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        tree_size: tree.leaf_count(),
        merkle_root,
        issued_at: unix_now(),
        kernel_key: keypair.public_key(),
    };
    let body_bytes = canonical_json_bytes(&body)
        .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    let signature = keypair.sign(&body_bytes);
    Ok(KernelCheckpoint { body, signature })
}

/// Build an inclusion proof for a leaf in an already-built MerkleTree.
pub fn build_inclusion_proof(
    tree: &MerkleTree,
    leaf_index: usize,
    checkpoint_seq: u64,
    receipt_seq: u64,
) -> Result<ReceiptInclusionProof, CheckpointError> {
    let proof = tree.inclusion_proof(leaf_index)?;
    Ok(ReceiptInclusionProof {
        checkpoint_seq,
        receipt_seq,
        leaf_index,
        merkle_root: tree.root(),
        proof,
    })
}

/// Verify the signature on a KernelCheckpoint.
///
/// Returns `Ok(true)` if the signature is valid.
pub fn verify_checkpoint_signature(checkpoint: &KernelCheckpoint) -> Result<bool, CheckpointError> {
    let body_bytes = canonical_json_bytes(&checkpoint.body)
        .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    Ok(checkpoint
        .body
        .kernel_key
        .verify(&body_bytes, &checkpoint.signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt_bytes(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!("{{\"receipt_id\":\"rcpt-{i:04}\",\"seq\":{i}}}").into_bytes())
            .collect()
    }

    #[test]
    fn build_checkpoint_100_has_tree_size_100() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(100);
        let cp = build_checkpoint(1, 1, 100, &batch, &kp).expect("build_checkpoint failed");
        assert_eq!(cp.body.tree_size, 100);
    }

    #[test]
    fn build_checkpoint_signature_verifies() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(10);
        let cp = build_checkpoint(1, 1, 10, &batch, &kp).expect("build_checkpoint failed");
        assert!(
            verify_checkpoint_signature(&cp).expect("verify failed"),
            "signature should be valid"
        );
    }

    #[test]
    fn build_checkpoint_wrong_key_fails_verification() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let batch = make_receipt_bytes(5);
        let mut cp = build_checkpoint(1, 1, 5, &batch, &kp1).expect("build_checkpoint failed");
        // Replace the kernel_key with a different key -- signature no longer matches.
        cp.body.kernel_key = kp2.public_key();
        assert!(
            !verify_checkpoint_signature(&cp).expect("verify call failed"),
            "tampered key should fail"
        );
    }

    #[test]
    fn build_checkpoint_single_receipt() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(1);
        let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");
        assert_eq!(cp.body.tree_size, 1);
        assert!(
            verify_checkpoint_signature(&cp).expect("verify failed"),
            "single-receipt checkpoint should have valid signature"
        );
    }

    #[test]
    fn schema_is_v1() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(3);
        let cp = build_checkpoint(1, 1, 3, &batch, &kp).expect("build_checkpoint failed");
        assert_eq!(cp.body.schema, "pact.checkpoint_statement.v1");
    }

    #[test]
    fn inclusion_proof_verifies_for_leaf_n() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(10);
        let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
        let root = tree.root();
        let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
        assert!(
            proof.verify(&batch[5], &root),
            "inclusion proof should verify"
        );
    }

    #[test]
    fn inclusion_proof_tampered_bytes_fail() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(10);
        let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
        let root = tree.root();
        let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
        assert!(
            !proof.verify(b"tampered bytes that are not in the tree", &root),
            "tampered bytes should not verify"
        );
        let _ = kp; // suppress unused
    }

    #[test]
    fn inclusion_proof_all_100_leaves_verify() {
        let batch = make_receipt_bytes(100);
        let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
        let root = tree.root();
        for i in 0..100 {
            let proof = build_inclusion_proof(&tree, i, 1, i as u64 + 1).expect("proof failed");
            assert!(
                proof.verify(&batch[i], &root),
                "leaf {i} inclusion proof failed"
            );
        }
    }

    #[test]
    fn checkpoint_body_schema_field() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(5);
        let cp = build_checkpoint(7, 101, 105, &batch, &kp).expect("build failed");
        let json = serde_json::to_string(&cp.body).expect("serialize failed");
        assert!(
            json.contains("pact.checkpoint_statement.v1"),
            "JSON should contain schema string"
        );
    }

    #[test]
    fn kernel_checkpoint_serde_roundtrip() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(5);
        let cp = build_checkpoint(1, 1, 5, &batch, &kp).expect("build failed");
        let json = serde_json::to_string(&cp).expect("serialize failed");
        let restored: KernelCheckpoint = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(cp.body.checkpoint_seq, restored.body.checkpoint_seq);
        assert_eq!(cp.body.tree_size, restored.body.tree_size);
        assert_eq!(cp.signature.to_hex(), restored.signature.to_hex());
        // Verify signature still works after roundtrip.
        assert!(
            verify_checkpoint_signature(&restored).expect("verify failed"),
            "roundtripped checkpoint signature should verify"
        );
    }
}
