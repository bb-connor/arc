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
//!
//! # Soundness notes (PR #594 review fixes)
//!
//! - The receipt's `body_hash` binds a stable [`BatchHashInput`] view
//!   of the batch body that EXCLUDES `witness_state`. This breaks the
//!   circular reference where signing a witnessed body would otherwise
//!   change the body the receipt was supposed to commit to.
//! - Honoring `WitnessState::Witnessed` against
//!   `require_public_witness=true` requires an active call to
//!   [`AnchorWitnessClient::verify_inclusion`]. Self-carried
//!   `Witnessed` states are not sufficient.
//! - `WitnessState::Stale` is admitted only if the receipt's
//!   `external_uuid` (or ots digest, etc.) is in the caller-supplied
//!   `previously_verified_receipts` set. Producers cannot bootstrap
//!   themselves into the verified set.

pub mod ots;
pub mod rekor;

use std::collections::HashSet;

use chio_core::canonical_json_bytes;
use chio_core::hashing::{sha256, Hash};
use chio_core::PublicKey;
use serde::{Deserialize, Serialize};

use crate::batch::{
    AnchorBatch, AnchorBatchBody, AnchorBatchInclusion, AnchorBatchWitness, AnchorBatchWitnessKind,
};

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
    /// SHA-256 digest of the canonical-JSON encoding of the
    /// [`BatchHashInput`] view of `batch.body` (every field except
    /// `witness_state`). Used by `verify_inclusion` to detect
    /// lane-side substitution attacks (the lane returned an entry that
    /// does not commit to our batch).
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
    #[error("witness lane signature verification failed: {0}")]
    SignatureInvalid(String),
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

/// Stable hash-input view of [`AnchorBatchBody`] used to compute the
/// receipt's `body_hash`.
///
/// The view EXCLUDES `witness_state`, breaking the circular reference
/// in which signing the batch with `WitnessState::Witnessed { receipt
/// .. }` would change the body that `receipt.body_hash` was supposed
/// to commit to. Verifiers re-derive this view from the final signed
/// batch and recompute the SHA-256.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchHashInput<'a> {
    pub schema: &'a str,
    pub tree_root: &'a Hash,
    pub checkpoint_ids: &'a [String],
    pub inclusions: &'a [AnchorBatchInclusion],
    pub witness: &'a AnchorBatchWitness,
    pub issued_at: u64,
    pub signer_key: &'a PublicKey,
}

impl<'a> BatchHashInput<'a> {
    /// Project an [`AnchorBatchBody`] into the stable hash-input view.
    pub fn from_body(body: &'a AnchorBatchBody) -> Self {
        BatchHashInput {
            schema: &body.schema,
            tree_root: &body.tree_root,
            checkpoint_ids: &body.checkpoint_ids,
            inclusions: &body.inclusions,
            witness: &body.witness,
            issued_at: body.issued_at,
            signer_key: &body.signer_key,
        }
    }
}

/// Compute the canonical-JSON SHA-256 of `batch.body` over the
/// witness_state-free [`BatchHashInput`] view. Both publish and
/// verify_inclusion bind to this value; lanes MUST commit to it.
pub fn batch_body_hash(batch: &AnchorBatch) -> Result<Hash, AnchorWitnessError> {
    batch_body_hash_from_body(&batch.body)
}

/// Compute the canonical-JSON SHA-256 of an [`AnchorBatchBody`] over
/// the witness_state-free [`BatchHashInput`] view. Pre-witness signing
/// paths use this to compute the receipt body_hash before the batch
/// has been re-signed with the receipt embedded.
pub fn batch_body_hash_from_body(body: &AnchorBatchBody) -> Result<Hash, AnchorWitnessError> {
    let view = BatchHashInput::from_body(body);
    let bytes = canonical_json_bytes(&view)
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
    #[error("witness receipt body_hash {receipt_hash} does not match recomputed batch body hash {batch_hash}")]
    WitnessReceiptBodyHashMismatch {
        receipt_hash: String,
        batch_hash: String,
    },
    #[error("require_public_witness=true requires an AnchorWitnessClient verifier but none was supplied")]
    VerifierRequired,
    #[error("witness lane verification failed: {0}")]
    VerifierRejected(String),
    #[error("require_public_witness=true and stale receipt is not in the previously_verified set: external_uuid={external_uuid}")]
    StaleNotPreviouslyVerified { external_uuid: String },
}

/// Apply [`WitnessPolicy`] without performing live witness-lane
/// verification.
///
/// This advisory variant is suitable for callers that want only the
/// shape checks (Pending vs Witnessed vs Stale, root binding,
/// body-hash binding, stale window). It MUST NOT be used to honor
/// `require_public_witness=true`: a producer can put any
/// `WitnessState::Witnessed` in the signed body without ever talking
/// to the lane. Use [`evaluate_witness_policy_with_verifier`] for the
/// load-bearing path.
pub fn evaluate_witness_policy(
    batch: &AnchorBatch,
    state: &WitnessState,
    policy: &WitnessPolicy,
    now: i64,
) -> Result<(), WitnessPolicyError> {
    match state {
        WitnessState::Witnessed { receipt, .. } => {
            check_witnessed_invariants(batch, receipt)?;
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

fn check_witnessed_invariants(
    batch: &AnchorBatch,
    receipt: &WitnessReceipt,
) -> Result<(), WitnessPolicyError> {
    if receipt.witness_root != batch.body.tree_root {
        return Err(WitnessPolicyError::WitnessReceiptRootMismatch {
            receipt_root: receipt.witness_root.to_hex_prefixed(),
            batch_root: batch.body.tree_root.to_hex_prefixed(),
        });
    }
    let recomputed = batch_body_hash(batch).map_err(|error| {
        WitnessPolicyError::VerifierRejected(format!("recompute body_hash: {error}"))
    })?;
    if recomputed != receipt.body_hash {
        return Err(WitnessPolicyError::WitnessReceiptBodyHashMismatch {
            receipt_hash: receipt.body_hash.to_hex_prefixed(),
            batch_hash: recomputed.to_hex_prefixed(),
        });
    }
    Ok(())
}

/// Apply [`WitnessPolicy`] WITH live witness-lane verification.
///
/// When `require_public_witness=true`:
///
/// - `Witnessed`: the receipt's invariants
///   (`witness_root == batch.body.tree_root` and
///   `body_hash == batch_body_hash(batch)`) are checked first, then
///   `client.verify_inclusion(receipt)` is invoked. The receipt is
///   not honored unless both pass.
/// - `Stale`: the receipt's `external_uuid` MUST be present in
///   `previously_verified_receipts` (i.e. some prior call to
///   `client.verify_inclusion` succeeded against this very receipt).
///   Producers cannot fake their way into the previously-verified
///   set; the caller (a verifier daemon, a CI gate) is the
///   authoritative source.
/// - `Pending`: rejected outright.
///
/// When `require_public_witness=false` this function delegates to the
/// sync [`evaluate_witness_policy`] path.
pub async fn evaluate_witness_policy_with_verifier(
    batch: &AnchorBatch,
    state: &WitnessState,
    policy: &WitnessPolicy,
    now: i64,
    client: Option<&dyn AnchorWitnessClient>,
    previously_verified_receipts: &HashSet<String>,
) -> Result<(), WitnessPolicyError> {
    if !policy.require_public_witness {
        return evaluate_witness_policy(batch, state, policy, now);
    }
    match state {
        WitnessState::Pending => Err(WitnessPolicyError::PendingNotAllowed),
        WitnessState::Witnessed { receipt, .. } => {
            check_witnessed_invariants(batch, receipt)?;
            let client = client.ok_or(WitnessPolicyError::VerifierRequired)?;
            client
                .verify_inclusion(receipt)
                .await
                .map_err(|error| WitnessPolicyError::VerifierRejected(error.to_string()))?;
            Ok(())
        }
        WitnessState::Stale { last_verified, .. } => {
            if now.saturating_sub(*last_verified) > policy.stale_window_seconds {
                return Err(WitnessPolicyError::StaleWindowExceeded {
                    last_verified: *last_verified,
                    now,
                    stale_window_seconds: policy.stale_window_seconds,
                });
            }
            // Stale admission requires that the original receipt was
            // previously verified by a real call to verify_inclusion.
            // The body must therefore carry a Witnessed receipt-ish
            // pointer somewhere; in this codebase, the body still
            // holds witness.witness_id which is the Rekor UUID or
            // OTS digest. We accept both representations: if the
            // caller has the external_uuid in the set, admission
            // proceeds.
            //
            // Production callers wire the previously-verified set
            // from the durable store of receipts that completed a
            // verify_inclusion round-trip. If the set is empty (as
            // for a brand-new verifier), Stale admission is denied:
            // fail-closed.
            let candidate = batch.body.witness.witness_id.as_str();
            if previously_verified_receipts.contains(candidate) {
                Ok(())
            } else {
                Err(WitnessPolicyError::StaleNotPreviouslyVerified {
                    external_uuid: candidate.to_string(),
                })
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

    /// HIGH-1 regression: the body_hash bound by a receipt MUST be
    /// identical between the Pending body and the same body once
    /// signed under WitnessState::Witnessed. If batch_body_hash
    /// reads witness_state, the two values diverge and the receipt
    /// no longer commits to the final signed batch.
    #[test]
    fn body_hash_is_stable_across_witness_state_transitions() {
        let kp = Keypair::generate();
        let mut pending = sample_batch();
        let pending_hash = batch_body_hash(&pending).unwrap();

        // Move to Witnessed with a populated receipt and re-sign.
        let receipt = WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-A".to_string(),
            published_at: 1_700_000_010,
            inclusion_proof: vec![9, 9, 9, 9],
            witness_root: pending.body.tree_root,
            body_hash: pending_hash,
        };
        pending.body.witness_state = WitnessState::Witnessed {
            receipt,
            observed_at: 1_700_000_010,
        };
        let resigned = AnchorBatch::sign(pending.body.clone(), &kp).unwrap();
        let witnessed_hash = batch_body_hash(&resigned).unwrap();
        assert_eq!(
            pending_hash, witnessed_hash,
            "BatchHashInput must exclude witness_state"
        );

        // Move to Stale and re-sign; same invariant must hold.
        let mut stale_body = pending.body.clone();
        stale_body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_500,
            error: "rekor 503".to_string(),
        };
        let resigned_stale = AnchorBatch::sign(stale_body, &kp).unwrap();
        let stale_hash = batch_body_hash(&resigned_stale).unwrap();
        assert_eq!(
            pending_hash, stale_hash,
            "BatchHashInput must be identical across Pending/Witnessed/Stale"
        );
    }

    /// HIGH-2 regression: a self-asserted Witnessed state must NOT
    /// satisfy require_public_witness=true on its own. The verifier
    /// path requires a real client.verify_inclusion call.
    #[tokio::test]
    async fn require_public_witness_rejects_self_asserted_witnessed() {
        struct AlwaysFailClient;
        #[async_trait::async_trait]
        impl AnchorWitnessClient for AlwaysFailClient {
            async fn publish(&self, _: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError> {
                unreachable!()
            }
            async fn verify_inclusion(&self, _: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
                Err(AnchorWitnessError::SignatureInvalid(
                    "no SET on this self-asserted receipt".to_string(),
                ))
            }
        }
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        let body_hash = batch_body_hash(&batch).unwrap();
        batch.body.witness_state = WitnessState::Witnessed {
            receipt: WitnessReceipt {
                kind: AnchorBatchWitnessKind::Rekor,
                external_uuid: "uuid-self-asserted".to_string(),
                published_at: 1_700_000_010,
                inclusion_proof: vec![],
                witness_root: batch.body.tree_root,
                body_hash,
            },
            observed_at: 1_700_000_010,
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let client = AlwaysFailClient;
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        let err = evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_100,
            Some(&client),
            &HashSet::new(),
        )
        .await
        .expect_err("self-asserted Witnessed must be rejected by the verifier client");
        assert!(matches!(err, WitnessPolicyError::VerifierRejected(_)));
    }

    /// HIGH-2 regression for Stale: a stale state with no prior
    /// verified record must be rejected when require_public_witness.
    #[tokio::test]
    async fn require_public_witness_rejects_stale_without_prior_verification() {
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        batch.body.witness.witness_id = "rekor:uuid-some".to_string();
        batch.body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "rekor 503".to_string(),
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        let err = evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_100,
            None,
            &HashSet::new(),
        )
        .await
        .expect_err("stale without prior verification must be rejected");
        assert!(matches!(
            err,
            WitnessPolicyError::StaleNotPreviouslyVerified { .. }
        ));
    }

    #[tokio::test]
    async fn require_public_witness_admits_stale_when_previously_verified() {
        let kp = Keypair::generate();
        let mut batch = sample_batch();
        batch.body.witness.witness_id = "rekor:uuid-prior".to_string();
        batch.body.witness_state = WitnessState::Stale {
            last_verified: 1_700_000_000,
            error: "rekor 503".to_string(),
        };
        let signed = AnchorBatch::sign(batch.body, &kp).unwrap();
        let policy = WitnessPolicy {
            require_public_witness: true,
            stale_window_seconds: 60 * 60,
        };
        let mut verified = HashSet::new();
        verified.insert("rekor:uuid-prior".to_string());
        evaluate_witness_policy_with_verifier(
            &signed,
            &signed.body.witness_state,
            &policy,
            1_700_000_100,
            None,
            &verified,
        )
        .await
        .expect("previously verified stale receipt is admissible");
    }
}
