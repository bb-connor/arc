use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Deserializer, Serialize};

use crate::crypto::{PublicKey, Signature};
use crate::error::{Error, Result};
use crate::hashing::Hash;
use crate::merkle::MerkleProof;

/// Declared verifier material required to treat a checkpoint publication as
/// trust-anchored rather than local-preview only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointPublicationTrustAnchorBinding {
    /// Typed publication surface identity declared for this publication path.
    pub publication_identity: CheckpointPublicationIdentity,
    /// Typed trust-anchor identity declared for this publication path.
    pub trust_anchor_identity: CheckpointTrustAnchorIdentity,
    /// Stable identifier for the trust anchor that vouches for the publication path.
    pub trust_anchor_ref: String,
    /// Stable identifier for the signer certificate or chain entry used by the publisher.
    pub signer_cert_ref: String,
    /// Versioned publication profile that defines the verifier policy for this path.
    pub publication_profile_version: String,
}

impl CheckpointPublicationTrustAnchorBinding {
    pub fn validate(&self) -> Result<()> {
        fn require_non_empty(value: &str, field: &str) -> Result<()> {
            if value.trim().is_empty() {
                return Err(Error::CanonicalJson(format!(
                    "{field} must not be empty for trust-anchored checkpoint publication"
                )));
            }
            Ok(())
        }

        if !self.publication_identity.has_identity() {
            return Err(Error::CanonicalJson(
                "publication_identity.identity must not be empty for trust-anchored checkpoint publication"
                    .to_string(),
            ));
        }
        if !self.trust_anchor_identity.has_identity() {
            return Err(Error::CanonicalJson(
                "trust_anchor_identity.identity must not be empty for trust-anchored checkpoint publication"
                    .to_string(),
            ));
        }
        require_non_empty(&self.trust_anchor_ref, "trust_anchor_ref")?;
        require_non_empty(&self.signer_cert_ref, "signer_cert_ref")?;
        require_non_empty(
            &self.publication_profile_version,
            "publication_profile_version",
        )?;
        Ok(())
    }
}

/// Declared publication surface family for a checkpoint publication record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPublicationIdentityKind {
    LocalLog,
    TransparencyService,
    ImmutableRecord,
    ChainAnchor,
}

/// Optional typed publication identity carried alongside a checkpoint record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPublicationIdentity {
    pub kind: CheckpointPublicationIdentityKind,
    pub identity: String,
}

impl CheckpointPublicationIdentity {
    #[must_use]
    pub fn new(kind: CheckpointPublicationIdentityKind, identity: impl Into<String>) -> Self {
        Self {
            kind,
            identity: identity.into(),
        }
    }

    #[must_use]
    pub fn has_identity(&self) -> bool {
        !self.identity.trim().is_empty()
    }
}

/// Declared trust-anchor family for a checkpoint publication record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointTrustAnchorIdentityKind {
    OperatorRoot,
    Did,
    X509Root,
    TransparencyRoot,
    ChainRoot,
}

/// Optional typed trust-anchor identity carried alongside a checkpoint record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointTrustAnchorIdentity {
    pub kind: CheckpointTrustAnchorIdentityKind,
    pub identity: String,
}

impl CheckpointTrustAnchorIdentity {
    #[must_use]
    pub fn new(kind: CheckpointTrustAnchorIdentityKind, identity: impl Into<String>) -> Self {
        Self {
            kind,
            identity: identity.into(),
        }
    }

    #[must_use]
    pub fn has_identity(&self) -> bool {
        !self.identity.trim().is_empty()
    }
}

/// Signed checkpoint statement carrying the checkpoint-chain commitment.
pub const CHECKPOINT_SCHEMA: &str = "chio.checkpoint_statement.v1";
pub const CHECKPOINT_PUBLICATION_SCHEMA: &str = "chio.checkpoint_publication.v1";
pub const CHECKPOINT_WITNESS_SCHEMA: &str = "chio.checkpoint_witness.v1";
/// Cryptographic checkpoint-chain consistency proof.
pub const CHECKPOINT_CONSISTENCY_PROOF_SCHEMA: &str = "chio.checkpoint_consistency_proof.v1";
pub const CHECKPOINT_EQUIVOCATION_SCHEMA: &str = "chio.checkpoint_equivocation.v1";

#[must_use]
pub fn is_supported_checkpoint_schema(schema: &str) -> bool {
    schema == CHECKPOINT_SCHEMA
}

fn deserialize_non_null_option<'de, D, T>(
    deserializer: D,
) -> core::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Err(<D::Error as serde::de::Error>::custom(
            "explicit null is not permitted; omit the optional field",
        ));
    }
    T::deserialize(value)
        .map(Some)
        .map_err(<D::Error as serde::de::Error>::custom)
}

/// The signed body of a kernel checkpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelCheckpointBody {
    /// Schema identifier, always [`CHECKPOINT_SCHEMA`].
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
    /// Hash of the immediately preceding checkpoint body when this checkpoint extends a prior batch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub previous_checkpoint_sha256: Option<String>,
    /// RFC 6962 root over the checkpoint-chain leaves for checkpoint_seq 1
    /// through this checkpoint, one leaf per checkpoint binding its sequence,
    /// entry range, and batch root (see `checkpoint_chain_leaf_hash`). This
    /// is the commitment that consistency proofs verify against. Checkpoint 1
    /// and every checkpoint that extends a predecessor carry it; only a
    /// detached checkpoint built without chain context omits it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub chain_root: Option<Hash>,
}

/// A signed kernel checkpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        if self.leaf_index != self.proof.leaf_index {
            return false;
        }
        self.proof.verify(receipt_canonical_bytes, expected_root)
    }
}

/// A deterministic publication record derived from a signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointPublication {
    /// Local log identity derived from the checkpoint signing key until an
    /// explicit persisted transparency log ID is available.
    pub log_id: String,
    /// Schema identifier for derived publication records.
    pub schema: String,
    /// Monotonic checkpoint counter.
    pub checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the signed checkpoint body.
    pub checkpoint_sha256: String,
    /// Merkle root published by the checkpoint.
    pub merkle_root: Hash,
    /// Timestamp when the checkpoint was issued/published.
    pub published_at: u64,
    /// The kernel key that signed the checkpoint.
    pub kernel_key: PublicKey,
    /// Cumulative log size derived from the covered entry sequence range.
    pub log_tree_size: u64,
    /// First entry sequence covered by this checkpoint batch.
    pub entry_start_seq: u64,
    /// Last entry sequence covered by this checkpoint batch.
    pub entry_end_seq: u64,
    /// Digest of the predecessor checkpoint body when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
    /// Declared verifier material when this publication is tied to a typed
    /// publication path and explicit trust-anchor policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_binding: Option<CheckpointPublicationTrustAnchorBinding>,
}

/// A deterministic witness record derived from a checkpoint's predecessor digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointWitness {
    /// Local log identity derived from the checkpoint signing key.
    pub log_id: String,
    /// Schema identifier for derived witness records.
    pub schema: String,
    /// The checkpoint being witnessed.
    pub checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the witnessed checkpoint body.
    pub checkpoint_sha256: String,
    /// The later checkpoint that cites the witnessed checkpoint digest.
    pub witness_checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the witness checkpoint body.
    pub witness_checkpoint_sha256: String,
    /// Timestamp from the witness checkpoint body.
    pub witnessed_at: u64,
}

/// A Merkle consistency proof between two checkpoint-chain commitments.
///
/// Proves, with RFC 6962 node hashes, that the checkpoint chain committed by
/// `to_chain_root` is an append-only extension of the chain committed by
/// `from_chain_root`. The chain tree has one leaf per checkpoint, so the tree
/// sizes are the checkpoint sequences themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointConsistencyProof {
    /// Schema identifier for consistency proof records.
    pub schema: String,
    /// Local log identity derived from the checkpoint signing key.
    pub log_id: String,
    /// Earlier checkpoint sequence in the proven prefix chain.
    pub from_checkpoint_seq: u64,
    /// Later checkpoint sequence in the proven prefix chain.
    pub to_checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the earlier checkpoint body.
    pub from_checkpoint_sha256: String,
    /// Canonical SHA-256 digest of the later checkpoint body.
    pub to_checkpoint_sha256: String,
    /// Cumulative log size before the append.
    pub from_log_tree_size: u64,
    /// Cumulative log size after the append.
    pub to_log_tree_size: u64,
    /// First entry sequence appended by the later checkpoint.
    pub appended_entry_start_seq: u64,
    /// Last entry sequence appended by the later checkpoint.
    pub appended_entry_end_seq: u64,
    /// Signed chain commitment of the earlier checkpoint.
    pub from_chain_root: Hash,
    /// Signed chain commitment of the later checkpoint.
    pub to_chain_root: Hash,
    /// RFC 6962 consistency path from the earlier chain tree to the later
    /// chain tree.
    pub chain_proof_hashes: Vec<Hash>,
    /// Inclusion proof binding the earlier checkpoint's own chain leaf to
    /// `from_chain_root` at the last position of that tree.
    pub from_leaf_inclusion: MerkleProof,
    /// Inclusion proof binding the later checkpoint's own chain leaf to
    /// `to_chain_root` at the last position. Without both endpoints bound, a
    /// key holder could commit chain trees whose leaves are unrelated to the
    /// bodies the proof names and still produce a verifying consistency path.
    pub to_leaf_inclusion: MerkleProof,
}

/// Classifies a conflicting checkpoint observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointEquivocationKind {
    /// Two distinct checkpoints claim the same checkpoint sequence.
    ConflictingCheckpointSeq,
    /// Two distinct checkpoints claim the same log and cumulative tree size.
    ConflictingLogTreeSize,
    /// Two distinct checkpoints cite the same predecessor digest.
    ConflictingPredecessorWitness,
}

/// A deterministic conflict record derived from multiple checkpoint statements.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CheckpointEquivocation {
    /// Schema identifier for derived equivocation records.
    pub schema: String,
    /// Which transparency rule was violated.
    pub kind: CheckpointEquivocationKind,
    /// Local log identity when the conflict can be tied to one derived log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_id: Option<String>,
    /// Shared cumulative log size when the conflict is a tree-size fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_tree_size: Option<u64>,
    /// The first conflicting checkpoint sequence.
    pub first_checkpoint_seq: u64,
    /// The second conflicting checkpoint sequence.
    pub second_checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the first checkpoint body.
    pub first_checkpoint_sha256: String,
    /// Canonical SHA-256 digest of the second checkpoint body.
    pub second_checkpoint_sha256: String,
    /// Shared predecessor digest when the conflict is a witness fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
}

/// Derived transparency records for a set of checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CheckpointTransparencySummary {
    /// Publication records for each checkpoint.
    pub publications: Vec<CheckpointPublication>,
    /// Witness records derived from predecessor-digest links.
    pub witnesses: Vec<CheckpointWitness>,
    /// Prefix-growth proofs derived from contiguous checkpoint extensions.
    pub consistency_proofs: Vec<CheckpointConsistencyProof>,
    /// Conflict records derived from contradictory checkpoints.
    pub equivocations: Vec<CheckpointEquivocation>,
}
