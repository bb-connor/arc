#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::{Ed25519Backend, Keypair};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn record() -> Result<TreatyEpochRecordV1, Box<dyn std::error::Error>> {
        Ok(TreatyEpochRecordV1 {
            schema: CHIO_TREATY_EPOCH_SCHEMA.to_owned(),
            verifier_id: AdmissionIdentifier::try_new("verifier", "kernel.buyer")?,
            treaty_id: AdmissionIdentifier::try_new("treaty", "buyer-vendor")?,
            sequence: 1,
            previous_record_sha256: None,
            status: TreatyEpochStatusV1::Active,
            participants: vec![
                TreatyEpochParticipantV1 {
                    kernel_id: AdmissionIdentifier::try_new("participant", "kernel.buyer")?,
                    public_key: Keypair::generate().public_key(),
                    ladder_manifest_sha256: AdmissionDigest::try_new("ladder", "a".repeat(64))?,
                },
                TreatyEpochParticipantV1 {
                    kernel_id: AdmissionIdentifier::try_new("participant", "kernel.vendor")?,
                    public_key: Keypair::generate().public_key(),
                    ladder_manifest_sha256: AdmissionDigest::try_new("ladder", "b".repeat(64))?,
                },
            ],
            trust_bundle_sha256: AdmissionDigest::try_new("trust", "c".repeat(64))?,
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 200,
        })
    }

    #[test]
    fn configured_signer_round_trips_and_body_digest_excludes_envelope() -> TestResult {
        let backend = Ed25519Backend::generate();
        let pin = backend.public_key()?;
        let body = record()?;
        let update = sign_treaty_epoch_record(body.clone(), &backend, &pin)?;
        let canonical = chio_core_types::crypto::canonical_json_bytes(&body)?;
        assert_eq!(
            update.body_digest().as_str(),
            chio_core_types::crypto::sha256_hex(&canonical)
        );
        let wire = serde_json::to_vec(update.envelope())?;
        let decoded = treaty_epoch_from_wire(&wire, &pin)?;
        assert_eq!(decoded.body(), &body);
        decoded.validate_active_at(100)?;
        decoded.validate_active_at(199)?;
        Ok(())
    }

    #[test]
    fn self_signed_attacker_and_changed_signed_body_are_refused() -> TestResult {
        let authority = Keypair::generate();
        let attacker = Keypair::generate();
        let body = record()?;
        let valid = SignedTreatyEpochV1::sign(body.clone(), &authority)?;
        verify_treaty_epoch_update(valid.clone(), &authority.public_key())?;
        let forged = SignedTreatyEpochV1::sign(body, &attacker)?;
        assert!(forged.verify_signature()?);
        assert!(matches!(
            verify_treaty_epoch_update(forged, &authority.public_key()),
            Err(TreatyEpochError::AuthorityMismatch)
        ));
        let mut altered = valid;
        altered.body.expires_at_unix_ms = 201;
        assert!(matches!(
            verify_treaty_epoch_update(altered, &authority.public_key()),
            Err(TreatyEpochError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn historical_authenticity_does_not_grant_current_admission() -> TestResult {
        let key = Keypair::generate();
        let active = SignedTreatyEpochV1::sign(record()?, &key)?;
        let verified = verify_treaty_epoch_update(active, &key.public_key())?;
        for now in [99, 200, 201] {
            assert!(matches!(
                verified.validate_active_at(now),
                Err(TreatyEpochError::Stale)
            ));
        }
        for status in [TreatyEpochStatusV1::Revoked, TreatyEpochStatusV1::Withdrawn] {
            let mut body = record()?;
            body.status = status;
            let signed = SignedTreatyEpochV1::sign(body, &key)?;
            let verified = verify_treaty_epoch_update(signed, &key.public_key())?;
            let expected = match status {
                TreatyEpochStatusV1::Revoked => TreatyEpochError::Revoked,
                TreatyEpochStatusV1::Withdrawn => TreatyEpochError::Withdrawn,
                TreatyEpochStatusV1::Active => return Err("unexpected active status".into()),
            };
            assert_eq!(verified.validate_active_at(150), Err(expected));
        }
        Ok(())
    }

    #[test]
    fn producer_refuses_backend_with_unconfigured_identity() -> TestResult {
        let backend = Ed25519Backend::generate();
        assert!(matches!(
            sign_treaty_epoch_record(record()?, &backend, &Keypair::generate().public_key()),
            Err(TreatyEpochError::AuthorityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn original_wire_rejects_duplicate_fields_and_oversized_input() -> TestResult {
        let key = Keypair::generate();
        let signed = SignedTreatyEpochV1::sign(record()?, &key)?;
        let wire = serde_json::to_string(&signed)?;
        treaty_epoch_from_wire(wire.as_bytes(), &key.public_key())?;
        let duplicate = wire.replacen("\"sequence\":1", "\"sequence\":1,\"sequence\":1", 1);
        assert_ne!(wire, duplicate);
        assert!(matches!(
            treaty_epoch_from_wire(duplicate.as_bytes(), &key.public_key()),
            Err(TreatyEpochError::InvalidEncoding)
        ));
        assert!(matches!(
            treaty_epoch_from_wire(&vec![b' '; MAX_TREATY_EPOCH_BYTES + 1], &key.public_key()),
            Err(TreatyEpochError::TooLarge)
        ));
        Ok(())
    }
}
