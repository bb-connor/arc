//! Public-witness lane clients for `chio.anchor_batch.v1`.
//!
//! W2.3 closes the audit P0 on T1.3 by providing a real
//! [`AnchorWitnessClient`] trait, two production submodules
//! ([`rekor`] and [`ots`]), and the [`WitnessState`] state machine
//! consumed by `verify_anchor_batch_with_witness_policy`.
//!
//! The clients implement the actual HTTP (Rekor REST) and process
//! (`ots-cli`) protocols. Tests substitute a mock HTTP server or a
//! stubbed binary; production builds reach the live endpoint.

pub mod ots;
pub mod rekor;

use chio_core::canonical_json_bytes;
use chio_core::hashing::{sha256, Hash};
use serde::{Deserialize, Serialize};

use crate::batch::{AnchorBatch, AnchorBatchWitnessKind};

/// Receipt returned by an [`AnchorWitnessClient`] on successful
/// publication.
///
/// All fields are wire-stable and travel with the batch through
/// [`WitnessState::Witnessed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessReceipt {
    pub kind: AnchorBatchWitnessKind,
    /// External identifier returned by the witness lane (Rekor UUID,
    /// OTS calendar URI, Solana signature, etc.).
    pub external_uuid: String,
    /// Lane-side observation time (UNIX seconds, UTC).
    pub published_at: i64,
    /// Inclusion proof bytes returned by the lane (Rekor logEntry
    /// `body` hash chain, OTS DER blob, etc.). Opaque to the verifier
    /// other than via `verify_inclusion`.
    #[serde(with = "serde_bytes_b64")]
    pub inclusion_proof: Vec<u8>,
    /// Root that the witness lane committed to. MUST equal
    /// `batch.body.tree_root` for the receipt to be accepted.
    pub witness_root: Hash,
    /// SHA-256 digest of the canonical-JSON encoding of
    /// `batch.body`. Used by `verify_inclusion` to detect lane-side
    /// substitution attacks (the lane returned an entry that does not
    /// commit to our batch).
    pub body_hash: Hash,
}

mod serde_bytes_b64 {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Errors raised by [`AnchorWitnessClient`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorWitnessError {
    #[error("witness network error: {0}")]
    Network(String),
    #[error("witness HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("witness body-hash mismatch: lane committed to {lane}, batch body hashes to {batch}")]
    BodyHashMismatch { lane: String, batch: String },
    #[error("witness root mismatch: lane committed to {lane}, batch tree_root is {batch}")]
    RootMismatch { lane: String, batch: String },
    #[error("witness receipt is stale: published_at={published_at} now={now} max_age_seconds={max_age_seconds}")]
    Stale {
        published_at: i64,
        now: i64,
        max_age_seconds: i64,
    },
    #[error("witness payload could not be parsed: {0}")]
    Decode(String),
    #[error("witness configuration error: {0}")]
    Config(String),
}

/// Production witness-lane interface. Both [`rekor::RekorClient`] and
/// [`ots::OtsClient`] implement this trait.
///
/// Implementations MUST be fail-closed: a failed publish or a failed
/// inclusion-verify returns `Err(_)`, never silently downgrades the
/// batch to `WitnessState::Witnessed`.
#[async_trait::async_trait]
pub trait AnchorWitnessClient: Send + Sync {
    async fn publish(&self, batch: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError>;
    async fn verify_inclusion(&self, receipt: &WitnessReceipt) -> Result<(), AnchorWitnessError>;
}

/// Compute the canonical-JSON SHA-256 of `batch.body`. Both publish
/// and verify_inclusion bind to this value; lanes MUST commit to it.
pub fn batch_body_hash(batch: &AnchorBatch) -> Result<Hash, AnchorWitnessError> {
    let bytes = canonical_json_bytes(&batch.body)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(sha256(&bytes))
}

/// Public-witness lifecycle for a batch.
///
/// `Pending`: the batch was minted locally; no lane has confirmed
/// inclusion yet. Verifier policy `require_public_witness=true`
/// rejects pending batches.
///
/// `Witnessed`: an [`AnchorWitnessClient`] returned a [`WitnessReceipt`]
/// whose `witness_root == batch.body.tree_root` and whose
/// `body_hash == batch_body_hash(batch)`.
///
/// `Stale`: the witness lane was last verified at `last_verified` and
/// re-verification returned an error. Verifier policy
/// `require_public_witness=true` rejects new batches but tolerates
/// already-witnessed receipts up to `stale_window_seconds`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WitnessState {
    #[default]
    Pending,
    Witnessed {
        receipt: WitnessReceipt,
        observed_at: i64,
    },
    Stale {
        last_verified: i64,
        error: String,
    },
}

/// Verifier policy controlling whether the public-witness lane is
/// advisory or load-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessPolicy {
    /// When true, batches in [`WitnessState::Pending`] are rejected
    /// and `Stale` batches with `now - last_verified > stale_window`
    /// are rejected. When false, all states are accepted (advisory).
    pub require_public_witness: bool,
    /// Tolerance window for already-witnessed-but-temporarily-down
    /// lanes. Only consulted when `require_public_witness=true`.
    pub stale_window_seconds: i64,
}

impl Default for WitnessPolicy {
    fn default() -> Self {
        WitnessPolicy {
            require_public_witness: false,
            stale_window_seconds: 24 * 60 * 60,
        }
    }
}

/// Reasons a witness-lane policy check rejected a batch.
#[derive(Debug, thiserror::Error)]
pub enum WitnessPolicyError {
    #[error("require_public_witness=true but batch is in Pending state")]
    PendingNotAllowed,
    #[error("require_public_witness=true and stale window exceeded: last_verified={last_verified} now={now} stale_window_seconds={stale_window_seconds}")]
    StaleWindowExceeded {
        last_verified: i64,
        now: i64,
        stale_window_seconds: i64,
    },
    #[error("witness receipt root {receipt_root} does not match batch tree_root {batch_root}")]
    WitnessReceiptRootMismatch {
        receipt_root: String,
        batch_root: String,
    },
}

/// Apply [`WitnessPolicy`] to an in-flight batch.
pub fn evaluate_witness_policy(
    batch: &AnchorBatch,
    state: &WitnessState,
    policy: &WitnessPolicy,
    now: i64,
) -> Result<(), WitnessPolicyError> {
    match state {
        WitnessState::Witnessed { receipt, .. } => {
            if receipt.witness_root != batch.body.tree_root {
                return Err(WitnessPolicyError::WitnessReceiptRootMismatch {
                    receipt_root: receipt.witness_root.to_hex_prefixed(),
                    batch_root: batch.body.tree_root.to_hex_prefixed(),
                });
            }
            Ok(())
        }
        WitnessState::Pending => {
            if policy.require_public_witness {
                Err(WitnessPolicyError::PendingNotAllowed)
            } else {
                Ok(())
            }
        }
        WitnessState::Stale { last_verified, .. } => {
            if !policy.require_public_witness {
                return Ok(());
            }
            if now.saturating_sub(*last_verified) > policy.stale_window_seconds {
                Err(WitnessPolicyError::StaleWindowExceeded {
                    last_verified: *last_verified,
                    now,
                    stale_window_seconds: policy.stale_window_seconds,
                })
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::batch::{build_anchor_batch, AnchorBatchWitness, AnchorBatchWitnessKind};
    use chio_core::Keypair;

    fn sample_batch() -> AnchorBatch {
        let kp = Keypair::generate();
        let witness = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:placeholder".to_string(),
            root: Hash::zero(),
            observed_at: Some(1_700_000_000),
        };
        build_anchor_batch(
            vec!["ck-1".to_string(), "ck-2".to_string()],
            witness,
            1_700_000_000,
            &kp,
        )
        .unwrap()
    }

    #[test]
    fn witness_policy_rejects_pending_when_required() {
        let batch = sample_batch();
        let state = WitnessState::Pending;
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60,
        };
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap_err();
        assert!(matches!(err, WitnessPolicyError::PendingNotAllowed));
    }

    #[test]
    fn witness_policy_accepts_pending_when_advisory() {
        let batch = sample_batch();
        let state = WitnessState::Pending;
        let policy = WitnessPolicy {
            require_public_witness: false,
            stale_window_seconds: 60,
        };
        evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap();
    }

    #[test]
    fn witness_policy_rejects_stale_outside_window() {
        let batch = sample_batch();
        let state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "lane down".to_string(),
        };
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60,
        };
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_500).unwrap_err();
        assert!(matches!(
            err,
            WitnessPolicyError::StaleWindowExceeded { .. }
        ));
    }

    #[test]
    fn witness_policy_accepts_stale_already_witnessed_advisory() {
        let batch = sample_batch();
        let state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "lane down".to_string(),
        };
        let policy = WitnessPolicy {
            require_public_witness: false,
            stale_window_seconds: 60,
        };
        evaluate_witness_policy(&batch, &state, &policy, 1_700_000_500).unwrap();
    }

    #[test]
    fn witness_policy_rejects_root_mismatch_on_witnessed() {
        let batch = sample_batch();
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-1".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![1, 2, 3],
            witness_root: Hash::zero(),
            body_hash: batch_body_hash(&batch).unwrap(),
        };
        let state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        let policy = WitnessPolicy::default();
        let err = evaluate_witness_policy(&batch, &state, &policy, 1_700_000_100).unwrap_err();
        assert!(matches!(
            err,
            WitnessPolicyError::WitnessReceiptRootMismatch { .. }
        ));
    }
}
