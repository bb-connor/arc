use super::*;
use chio_core_types::canonical::UntrustedJsonText;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, SigningBackend};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct VerifiedTreatyEpochUpdate {
    envelope: SignedTreatyEpochV1,
    body_digest: AdmissionDigest,
}

impl VerifiedTreatyEpochUpdate {
    pub fn envelope(&self) -> &SignedTreatyEpochV1 {
        &self.envelope
    }

    pub fn body(&self) -> &TreatyEpochRecordV1 {
        &self.envelope.body
    }

    pub fn body_digest(&self) -> &AdmissionDigest {
        &self.body_digest
    }

    pub fn authority(&self) -> &PublicKey {
        &self.envelope.signer_key
    }

    pub fn validate_active_at(&self, now_unix_ms: u64) -> Result<(), TreatyEpochError> {
        match self.body().status {
            TreatyEpochStatusV1::Revoked => return Err(TreatyEpochError::Revoked),
            TreatyEpochStatusV1::Withdrawn => return Err(TreatyEpochError::Withdrawn),
            TreatyEpochStatusV1::Active => {}
        }
        if now_unix_ms < self.body().issued_at_unix_ms
            || now_unix_ms >= self.body().expires_at_unix_ms
        {
            return Err(TreatyEpochError::Stale);
        }
        Ok(())
    }
}

pub fn verify_treaty_epoch_update(
    envelope: SignedTreatyEpochV1,
    pinned_authority: &PublicKey,
) -> Result<VerifiedTreatyEpochUpdate, TreatyEpochError> {
    validate_record(&envelope.body)?;
    if &envelope.signer_key != pinned_authority {
        return Err(TreatyEpochError::AuthorityMismatch);
    }
    let canonical =
        canonical_json_bytes(&envelope).map_err(|_| TreatyEpochError::InvalidEncoding)?;
    if canonical.len() > MAX_TREATY_EPOCH_BYTES {
        return Err(TreatyEpochError::TooLarge);
    }
    if !envelope
        .verify_signature(pinned_authority)
        .map_err(|_| TreatyEpochError::InvalidSignature)?
    {
        return Err(TreatyEpochError::InvalidSignature);
    }
    let body =
        canonical_json_bytes(&envelope.body).map_err(|_| TreatyEpochError::InvalidEncoding)?;
    let body_digest = AdmissionDigest::try_new("treaty_epoch_body", sha256_hex(&body))
        .map_err(|_| TreatyEpochError::InvalidEncoding)?;
    Ok(VerifiedTreatyEpochUpdate {
        envelope,
        body_digest,
    })
}

pub fn sign_treaty_epoch_record(
    body: TreatyEpochRecordV1,
    backend: &dyn SigningBackend,
    pinned_authority: &PublicKey,
) -> Result<VerifiedTreatyEpochUpdate, TreatyEpochError> {
    validate_record(&body)?;
    let envelope = SignedTreatyEpochV1::sign_with_backend(body, backend)
        .map_err(|_| TreatyEpochError::SigningFailed)?;
    verify_treaty_epoch_update(envelope, pinned_authority)
}

pub fn treaty_epoch_from_wire(
    bytes: &[u8],
    pinned_authority: &PublicKey,
) -> Result<VerifiedTreatyEpochUpdate, TreatyEpochError> {
    if bytes.len() > MAX_TREATY_EPOCH_BYTES {
        return Err(TreatyEpochError::TooLarge);
    }
    let envelope = UntrustedJsonText::from_wire(bytes, MAX_TREATY_EPOCH_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(|_| TreatyEpochError::InvalidEncoding)?;
    verify_treaty_epoch_update(envelope, pinned_authority)
}

fn validate_record(body: &TreatyEpochRecordV1) -> Result<(), TreatyEpochError> {
    if body.schema != CHIO_TREATY_EPOCH_SCHEMA {
        return Err(TreatyEpochError::InvalidSchema);
    }
    if body.sequence == 0
        || body.sequence > MAX_TREATY_EPOCH_INTEGER
        || (body.sequence == 1) != body.previous_record_sha256.is_none()
    {
        return Err(TreatyEpochError::InvalidSequence);
    }
    if body.issued_at_unix_ms >= body.expires_at_unix_ms
        || body.expires_at_unix_ms > MAX_TREATY_EPOCH_INTEGER
    {
        return Err(TreatyEpochError::InvalidInterval);
    }
    if !(2..=MAX_TREATY_EPOCH_PARTICIPANTS).contains(&body.participants.len()) {
        return Err(TreatyEpochError::InvalidParticipants);
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut manifests = BTreeSet::new();
    for participant in &body.participants {
        if !ids.insert(participant.kernel_id.as_str())
            || !keys.insert(participant.public_key.to_hex())
            || !manifests.insert(participant.ladder_manifest_sha256.as_str())
        {
            return Err(TreatyEpochError::InvalidParticipants);
        }
    }
    Ok(())
}

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
        assert!(forged.verify_signature(&attacker.public_key())?);
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
    fn signature_over_the_bare_canonical_body_is_refused() -> TestResult {
        let authority = Keypair::generate();
        let body = record()?;
        let mut bare = SignedTreatyEpochV1::sign(body.clone(), &authority)?;
        bare.signature = authority.sign_exempt(
            chio_core_types::crypto::ExemptFormat::JwsSigningInput,
            &chio_core_types::crypto::canonical_json_bytes(&body)?,
        );
        assert!(matches!(
            verify_treaty_epoch_update(bare, &authority.public_key()),
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
    fn signed_malformed_records_refuse_exact_structural_errors() -> TestResult {
        let key = Keypair::generate();
        let valid = record()?;
        let mut cases = Vec::new();
        let mut body = valid.clone();
        body.schema = "chio.other-domain.v1".to_owned();
        cases.push((body, TreatyEpochError::InvalidSchema));
        for sequence in [0, MAX_TREATY_EPOCH_INTEGER + 1, 2] {
            let mut body = valid.clone();
            body.sequence = sequence;
            cases.push((body, TreatyEpochError::InvalidSequence));
        }
        let mut body = valid.clone();
        body.previous_record_sha256 = Some(AdmissionDigest::try_new("previous", "d".repeat(64))?);
        cases.push((body, TreatyEpochError::InvalidSequence));
        for (issued, expires) in [(100, 100), (201, 200), (100, MAX_TREATY_EPOCH_INTEGER + 1)] {
            let mut body = valid.clone();
            body.issued_at_unix_ms = issued;
            body.expires_at_unix_ms = expires;
            cases.push((body, TreatyEpochError::InvalidInterval));
        }
        let mut body = valid.clone();
        body.participants.truncate(1);
        cases.push((body, TreatyEpochError::InvalidParticipants));
        let mut body = valid.clone();
        body.participants[1].kernel_id = body.participants[0].kernel_id.clone();
        cases.push((body, TreatyEpochError::InvalidParticipants));
        let mut body = valid.clone();
        body.participants[1].public_key = body.participants[0].public_key.clone();
        cases.push((body, TreatyEpochError::InvalidParticipants));
        let mut body = valid.clone();
        body.participants[1].ladder_manifest_sha256 =
            body.participants[0].ladder_manifest_sha256.clone();
        cases.push((body, TreatyEpochError::InvalidParticipants));
        let mut body = valid.clone();
        body.participants = (0..=MAX_TREATY_EPOCH_PARTICIPANTS)
            .map(|index| {
                Ok(TreatyEpochParticipantV1 {
                    kernel_id: AdmissionIdentifier::try_new(
                        "participant",
                        format!("kernel.{index}"),
                    )?,
                    public_key: Keypair::generate().public_key(),
                    ladder_manifest_sha256: AdmissionDigest::try_new(
                        "ladder",
                        format!("{index:064x}"),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, chio_kernel::admission_operation::AdmissionOperationError>>(
            )?;
        let mut at_limit = body.clone();
        at_limit
            .participants
            .truncate(MAX_TREATY_EPOCH_PARTICIPANTS);
        verify_treaty_epoch_update(
            SignedTreatyEpochV1::sign(at_limit, &key)?,
            &key.public_key(),
        )?;
        cases.push((body, TreatyEpochError::InvalidParticipants));
        for (body, expected) in cases {
            let signed = SignedTreatyEpochV1::sign(body, &key)?;
            assert!(signed.verify_signature(&key.public_key())?);
            assert!(matches!(
                verify_treaty_epoch_update(signed, &key.public_key()),
                Err(error) if error == expected
            ));
        }
        let mut next = valid;
        next.sequence = 2;
        next.previous_record_sha256 = Some(AdmissionDigest::try_new("previous", "d".repeat(64))?);
        verify_treaty_epoch_update(
            SignedTreatyEpochV1::sign(next.clone(), &key)?,
            &key.public_key(),
        )?;
        next.sequence = MAX_TREATY_EPOCH_INTEGER;
        next.expires_at_unix_ms = MAX_TREATY_EPOCH_INTEGER;
        verify_treaty_epoch_update(SignedTreatyEpochV1::sign(next, &key)?, &key.public_key())?;
        Ok(())
    }

    #[test]
    fn original_wire_rejects_duplicate_fields_and_oversized_input() -> TestResult {
        let key = Keypair::generate();
        let signed = SignedTreatyEpochV1::sign(record()?, &key)?;
        let wire = serde_json::to_string(&signed)?;
        treaty_epoch_from_wire(wire.as_bytes(), &key.public_key())?;
        let mut at_limit = wire.as_bytes().to_vec();
        at_limit.resize(MAX_TREATY_EPOCH_BYTES, b' ');
        treaty_epoch_from_wire(&at_limit, &key.public_key())?;
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
