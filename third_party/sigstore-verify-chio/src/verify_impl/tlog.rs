//! Transparency log verification
//!
//! This module handles verification of transparency log entries including
//! checkpoint verification and SET (Signed Entry Timestamp) verification.

use crate::error::{Error, Result};
use base64::Engine;
use serde::Serialize;
use sigstore_crypto::{verify_signature, Checkpoint, SigningScheme};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::InclusionProof;
use sigstore_types::{Bundle, SignatureBytes, TransparencyLogEntry};

/// Verify transparency log entries (checkpoints and SETs)
///
/// # Arguments
/// * `bundle` - The bundle containing transparency log entries
/// * `content_bound_entry_indices` - Entries cryptographically bound to the verified content
/// * `trusted_root` - Trusted root for cryptographic verification
/// * `not_before` - Certificate validity start time (Unix timestamp)
/// * `not_after` - Certificate validity end time (Unix timestamp)
/// * `clock_skew_seconds` - Tolerance in seconds for future time checks
pub fn verify_tlog_entries(
    bundle: &Bundle,
    content_bound_entry_indices: &[usize],
    trusted_root: &TrustedRoot,
    not_before: i64,
    not_after: i64,
    clock_skew_seconds: i64,
) -> Result<Option<i64>> {
    crate::verify::validate_clock_skew_seconds(clock_skew_seconds)?;
    let mut integrated_time_result: Option<i64> = None;

    for &entry_index in content_bound_entry_indices {
        let entry = bundle
            .verification_material
            .tlog_entries
            .get(entry_index)
            .ok_or_else(|| {
                Error::Verification(format!(
                    "content-bound transparency log entry index {entry_index} is out of range"
                ))
            })?;
        // Verify checkpoint signature if present
        if let Some(ref inclusion_proof) = entry.inclusion_proof {
            verify_inclusion_proof(entry, inclusion_proof, trusted_root)?;
        }

        // Verify inclusion promise (SET) if present
        let integrated_time_is_authenticated = if entry.inclusion_promise.is_some() {
            verify_set(entry, trusted_root)?;
            true
        } else {
            false
        };

        // Integrated time is authenticated only by the signed entry timestamp.
        // An inclusion proof authenticates tree membership, not this metadata field.
        let time = entry.integrated_time;
        if integrated_time_is_authenticated && time > 0 {
            // Check that integrated time is not in the future (with clock skew tolerance)
            let now = chrono::Utc::now().timestamp();
            let latest_accepted_time = now
                .checked_add(clock_skew_seconds)
                .ok_or_else(|| Error::Verification("clock skew deadline overflowed".to_string()))?;
            if time > latest_accepted_time {
                return Err(Error::Verification(format!(
                    "integrated time {} is in the future (current time: {}, tolerance: {}s)",
                    time, now, clock_skew_seconds
                )));
            }

            // Check that integrated time is within certificate validity period
            if time < not_before {
                return Err(Error::Verification(format!(
                    "integrated time {} is before certificate validity (not_before: {})",
                    time, not_before
                )));
            }

            if time > not_after {
                return Err(Error::Verification(format!(
                    "integrated time {} is after certificate validity (not_after: {})",
                    time, not_after
                )));
            }

            integrated_time_result =
                Some(integrated_time_result.map_or(time, |current_time| current_time.min(time)));
        }
    }

    Ok(integrated_time_result)
}

/// Verify a checkpoint signature using the trusted root
pub fn verify_checkpoint(
    checkpoint_envelope: &str,
    inclusion_proof: &InclusionProof,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    use sigstore_crypto::verify_signature_auto;

    // Parse the checkpoint (signed note)
    let checkpoint = Checkpoint::from_text(checkpoint_envelope)
        .map_err(|e| Error::Verification(format!("Failed to parse checkpoint: {}", e)))?;

    // Verify that the checkpoint's root hash matches the inclusion proof's root hash
    let checkpoint_root_hash = &checkpoint.root_hash;

    // The root hash in the inclusion proof is already a Sha256Hash
    let proof_root_hash = &inclusion_proof.root_hash;

    if checkpoint_root_hash.as_bytes() != proof_root_hash.as_bytes() {
        return Err(Error::Verification(format!(
            "Checkpoint root hash mismatch: expected {}, got {}",
            checkpoint_root_hash.to_hex(),
            proof_root_hash.to_hex()
        )));
    }
    let proof_tree_size = u64::try_from(inclusion_proof.tree_size)
        .map_err(|_| Error::Verification("inclusion proof has an invalid tree size".to_string()))?;
    if checkpoint.tree_size != proof_tree_size {
        return Err(Error::Verification(format!(
            "Checkpoint tree size mismatch: expected {}, got {}",
            checkpoint.tree_size, proof_tree_size
        )));
    }

    // Checkpoints do not carry an authenticated signing time. A key retained
    // only for historical SET verification must therefore not authorize a new
    // checkpoint after its authority window has closed.
    let verification_time = chrono::Utc::now().timestamp();
    let mut matched_inactive_key = false;
    let mut matched_active_key_failures = Vec::new();

    // For each signature in the checkpoint, try to find a matching active key.
    for sig in &checkpoint.signatures {
        for log in &trusted_root.tlogs {
            let log_id = log.log_id.key_id.decode().map_err(|error| {
                Error::Verification(format!("Failed to decode Rekor log ID: {error}"))
            })?;
            if log_id.len() < 4 || sig.key_id.as_slice() != &log_id[..4] {
                continue;
            }

            if !super::helpers::validity_period_contains(
                log.public_key.valid_for.as_ref(),
                verification_time,
                "Rekor checkpoint key",
            )? {
                matched_inactive_key = true;
                continue;
            }

            let message = checkpoint.signed_data();
            match verify_signature_auto(&log.public_key.raw_bytes, &sig.signature, message) {
                Ok(()) => return Ok(()),
                Err(error) => matched_active_key_failures.push(error.to_string()),
            }
        }
    }

    if !matched_active_key_failures.is_empty() {
        return Err(Error::Verification(format!(
            "No active matching Rekor key verified a checkpoint signature: {}",
            matched_active_key_failures.join("; ")
        )));
    }

    if matched_inactive_key {
        return Err(Error::Verification(
            "Rekor checkpoint key is outside its validity period".to_string(),
        ));
    }

    Err(Error::Verification(
        "No matching Rekor key found for checkpoint signature".to_string(),
    ))
}

pub(crate) fn verify_inclusion_proof(
    entry: &TransparencyLogEntry,
    inclusion_proof: &InclusionProof,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    verify_checkpoint(
        &inclusion_proof.checkpoint.envelope,
        inclusion_proof,
        trusted_root,
    )?;
    let proof_log_index = inclusion_proof.log_index.as_u64().ok_or_else(|| {
        Error::Verification("inclusion proof has an invalid log index".to_string())
    })?;
    let tree_size = u64::try_from(inclusion_proof.tree_size)
        .map_err(|_| Error::Verification("inclusion proof has an invalid tree size".to_string()))?;
    let leaf_hash = sigstore_merkle::hash_leaf(entry.canonicalized_body.as_bytes());
    sigstore_merkle::verify_inclusion_proof(
        &leaf_hash,
        proof_log_index,
        tree_size,
        &inclusion_proof.hashes,
        &inclusion_proof.root_hash,
    )
    .map_err(|error| Error::Verification(format!("inclusion proof verification failed: {error}")))
}

#[derive(Serialize)]
struct RekorPayload {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

/// Verify SET (Signed Entry Timestamp)
pub fn verify_set(entry: &TransparencyLogEntry, trusted_root: &TrustedRoot) -> Result<()> {
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(Error::Verification("Missing inclusion promise".into()))?;

    // Resolve the key together with its authority window. A historical key may
    // remain trusted for old entries without retaining authority indefinitely.
    let log = trusted_root
        .tlogs
        .iter()
        .find(|log| log.log_id.key_id == entry.log_id.key_id)
        .ok_or_else(|| Error::Verification(format!("Unknown log ID: {}", entry.log_id.key_id)))?;
    if !super::helpers::validity_period_contains(
        log.public_key.valid_for.as_ref(),
        entry.integrated_time,
        "Rekor key",
    )? {
        return Err(Error::Verification(format!(
            "Rekor key is outside its validity period at integrated time {}",
            entry.integrated_time
        )));
    }
    let log_key = log.public_key.raw_bytes.clone();

    // Construct the payload (base64-encoded body)
    let body = entry.canonicalized_body.to_base64();

    let integrated_time = entry.integrated_time;
    let log_index = entry
        .log_index
        .as_u64()
        .ok_or_else(|| Error::Verification("Invalid log index".into()))? as i64;

    // Log ID for payload must be hex encoded
    let log_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(entry.log_id.key_id.as_str())
        .map_err(|_| Error::Verification("Invalid base64 log ID".into()))?;
    let log_id_hex = hex::encode(log_id_bytes);

    let payload = RekorPayload {
        body,
        integrated_time,
        log_index,
        log_id: log_id_hex,
    };

    let canonical_json = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|e| Error::Verification(format!("Canonicalization failed: {}", e)))?;

    // Get signature bytes from signed timestamp
    let signature = SignatureBytes::new(promise.signed_entry_timestamp.as_bytes().to_vec());

    verify_signature(
        &log_key,
        &canonical_json,
        &signature,
        SigningScheme::EcdsaP256Sha256,
    )
    .map_err(|e| Error::Verification(format!("SET verification failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_crypto::parse_certificate_info;
    use sigstore_trust_root::ValidityPeriod;
    use sigstore_types::CanonicalizedBody;

    const COSIGN_V3_BLOB_BUNDLE: &str =
        include_str!("../../test_data/bundles/cosign-v3-blob.sigstore.json");

    #[test]
    fn unsigned_integrated_time_is_not_consumed() {
        let mut bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let certificate_info =
            parse_certificate_info(certificate.as_bytes()).expect("certificate info");
        bundle.verification_material.tlog_entries[0].inclusion_promise = None;

        let integrated_time = verify_tlog_entries(
            &bundle,
            &[0],
            &TrustedRoot::production().expect("production root"),
            certificate_info.not_before,
            certificate_info.not_after,
            crate::verify::DEFAULT_CLOCK_SKEW_SECONDS,
        )
        .expect("inclusion proof remains valid without unsigned chronology");

        assert_eq!(integrated_time, None);
    }

    #[test]
    fn inclusion_proof_is_bound_to_the_canonicalized_entry() {
        let mut bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let certificate_info =
            parse_certificate_info(certificate.as_bytes()).expect("certificate info");
        bundle.verification_material.tlog_entries[0].inclusion_promise = None;

        verify_tlog_entries(
            &bundle,
            &[0],
            &TrustedRoot::production().expect("production root"),
            certificate_info.not_before,
            certificate_info.not_after,
            crate::verify::DEFAULT_CLOCK_SKEW_SECONDS,
        )
        .expect("the original canonicalized entry must match the inclusion proof");

        bundle.verification_material.tlog_entries[0].canonicalized_body =
            CanonicalizedBody::new(b"{}".to_vec());

        let error = verify_tlog_entries(
            &bundle,
            &[0],
            &TrustedRoot::production().expect("production root"),
            certificate_info.not_before,
            certificate_info.not_after,
            crate::verify::DEFAULT_CLOCK_SKEW_SECONDS,
        )
        .expect_err("a checkpoint must not authenticate an unrelated entry");

        assert!(error.to_string().contains("inclusion proof"));
    }

    #[test]
    fn set_rejects_a_rekor_key_outside_its_authority_window() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let entry = &bundle.verification_material.tlog_entries[0];
        let mut trusted_root = TrustedRoot::production().expect("production root");
        let matching_log = trusted_root
            .tlogs
            .iter_mut()
            .find(|log| log.log_id.key_id == entry.log_id.key_id)
            .expect("matching Rekor log");
        matching_log.public_key.valid_for = Some(ValidityPeriod {
            start: Some("2999-01-01T00:00:00Z".to_string()),
            end: None,
        });

        let error = verify_set(entry, &trusted_root)
            .expect_err("a retired or not-yet-active Rekor key must not verify a SET");

        assert!(error.to_string().contains("validity period"));
    }

    #[test]
    fn checkpoint_rejects_a_rekor_key_outside_its_current_authority_window() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let proof = bundle.verification_material.tlog_entries[0]
            .inclusion_proof
            .as_ref()
            .expect("inclusion proof");
        let mut trusted_root = TrustedRoot::production().expect("production root");
        for log in &mut trusted_root.tlogs {
            log.public_key.valid_for = Some(ValidityPeriod {
                start: None,
                end: Some("2000-01-01T00:00:00Z".to_string()),
            });
        }

        let error = verify_checkpoint(&proof.checkpoint.envelope, proof, &trusted_root)
            .expect_err("a retired Rekor key must not authorize a new checkpoint");

        assert!(error.to_string().contains("validity period"));
    }

    #[test]
    fn checkpoint_tries_a_valid_signature_after_an_invalid_matching_signature() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let proof = bundle.verification_material.tlog_entries[0]
            .inclusion_proof
            .as_ref()
            .expect("inclusion proof");
        let (body, signature_block) = proof
            .checkpoint
            .envelope
            .split_once("\n\n")
            .expect("checkpoint body and signatures");
        let valid_line = signature_block.lines().next().expect("checkpoint signature");
        let (line_prefix, encoded_signature) = valid_line
            .rsplit_once(' ')
            .expect("checkpoint signature encoding");
        let mut invalid_signature = base64::engine::general_purpose::STANDARD
            .decode(encoded_signature)
            .expect("decode checkpoint signature");
        *invalid_signature.last_mut().expect("signature bytes") ^= 1;
        let invalid_line = format!(
            "{line_prefix} {}",
            base64::engine::general_purpose::STANDARD.encode(invalid_signature)
        );
        let redundant_envelope = format!("{body}\n\n{invalid_line}\n{valid_line}\n");

        verify_checkpoint(
            &redundant_envelope,
            proof,
            &TrustedRoot::production().expect("production root"),
        )
        .expect("the later valid redundant signature must verify");
    }

    #[test]
    fn checkpoint_tries_a_valid_key_after_a_colliding_invalid_key() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let proof = bundle.verification_material.tlog_entries[0]
            .inclusion_proof
            .as_ref()
            .expect("inclusion proof");
        let checkpoint = Checkpoint::from_text(&proof.checkpoint.envelope).expect("checkpoint");
        let key_hint = checkpoint.signatures[0].key_id.as_slice();
        let mut trusted_root = TrustedRoot::production().expect("production root");
        let matching_log = trusted_root
            .tlogs
            .iter()
            .find(|log| {
                log.log_id
                    .key_id
                    .decode()
                    .is_ok_and(|log_id| log_id.len() >= 4 && key_hint == &log_id[..4])
            })
            .expect("matching Rekor key")
            .clone();
        let mut colliding_invalid_log = matching_log;
        colliding_invalid_log.public_key.raw_bytes = sigstore_types::DerPublicKey::new(vec![0xff]);
        trusted_root.tlogs.insert(0, colliding_invalid_log);

        verify_checkpoint(&proof.checkpoint.envelope, proof, &trusted_root)
            .expect("the later valid colliding key must verify");
    }
}
