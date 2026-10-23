use super::*;
use crate::authority::AuthorityTrustedKeySnapshot;

fn envelope() -> Result<(SignedAuthoritySnapshot, AuthorityReplicationAnchor), AuthorityStoreError>
{
    let signer = Keypair::from_seed(&[42; 32]);
    let key = signer.public_key().to_hex();
    let anchor = AuthorityReplicationAnchor::new(
        "clock-policy".into(),
        AuthoritySnapshot {
            public_key_hex: key.clone(),
            generation: 1,
            rotated_at: 100,
            trusted_keys: vec![AuthorityTrustedKeySnapshot {
                public_key_hex: key,
                generation: 1,
                activated_at: 100,
                lifecycle: super::super::lifecycle::AuthorityKeyLifecycle::Active,
            }],
        },
    )?;
    Ok((
        SignedAuthoritySnapshot::sign(&anchor, vec![], 101, &signer)?,
        anchor,
    ))
}

#[test]
fn final_f11_future_skew_and_exclusive_expiry_have_independent_boundaries(
) -> Result<(), AuthorityStoreError> {
    let (signed, anchor) = envelope()?;
    let commitment = anchor.commitment()?;
    for (skew, now, valid) in [
        (0, 100, false),
        (1, 100, true),
        (1, 99, false),
        (1, 101, true),
        (60, 400, true),
        (60, 401, false),
    ] {
        let verified = signed.verify_with_clock_policy(
            &anchor,
            &anchor.snapshot,
            &commitment,
            now,
            AuthorityEnvelopeClockPolicy::new(skew)?,
        );
        if valid {
            verified?;
        } else {
            assert!(
                matches!(verified, Err(AuthorityStoreError::Fence(message)) if message == "authority envelope outside freshness window"),
                "skew={skew}, now={now}"
            );
        }
    }
    assert!(
        matches!(signed.verify(&anchor, &anchor.snapshot, &commitment, 100), Err(AuthorityStoreError::Fence(message)) if message == "authority envelope outside freshness window")
    );
    assert!(matches!(signed.verify_with_clock_policy(
            &anchor,
            &anchor.snapshot,
            &commitment,
            u64::MAX,
            AuthorityEnvelopeClockPolicy::new(60)?
        ), Err(AuthorityStoreError::Fence(message)) if message == "authority envelope outside freshness window"));
    Ok(())
}

#[test]
fn final_f11_future_skew_policy_rejects_unbounded_configuration() {
    assert!(AuthorityEnvelopeClockPolicy::new(0).is_ok());
    assert!(AuthorityEnvelopeClockPolicy::new(60).is_ok());
    assert!(
        matches!(AuthorityEnvelopeClockPolicy::new(61), Err(AuthorityStoreError::Fence(message)) if message == "authority envelope future skew exceeds 60 seconds")
    );
    assert!(
        matches!(AuthorityEnvelopeClockPolicy::new(u64::MAX), Err(AuthorityStoreError::Fence(message)) if message == "authority envelope future skew exceeds 60 seconds")
    );
}

#[test]
fn final_f11_skew_never_bypasses_signature_domain_or_replay_checks(
) -> Result<(), AuthorityStoreError> {
    let (signed, anchor) = envelope()?;
    let commitment = anchor.commitment()?;
    let policy = AuthorityEnvelopeClockPolicy::new(1)?;
    for (tamper, refusal) in [
        ("signature", "authority envelope signature invalid"),
        ("domain", "authority envelope domain mismatch"),
        (
            "commitment",
            "authority snapshot differs from authenticated chain",
        ),
        (
            "epoch",
            "authority snapshot differs from authenticated chain",
        ),
        ("lifetime", "authority envelope outside freshness window"),
    ] {
        let mut forged = signed.clone();
        let proof = forged
            .proof
            .as_mut()
            .ok_or_else(|| refused("test envelope missing proof"))?;
        match tamper {
            "signature" => {
                proof.signature =
                    crate::wrapper_refusals::unrelated_signature(&Keypair::from_seed(&[43; 32]))
            }
            "domain" => proof.stream_id = "another-authority".into(),
            "commitment" => proof.chain_commitment = "00".repeat(32),
            "epoch" => forged.snapshot.generation = 2,
            "lifetime" => proof.expires_at = 402,
            _ => unreachable!(),
        }
        assert!(
            matches!(forged.verify_with_clock_policy(&anchor, &anchor.snapshot, &commitment, 100, policy), Err(AuthorityStoreError::Fence(message)) if message == refusal),
            "skew admitted a forged {tamper}"
        );
    }
    Ok(())
}

#[test]
fn lifecycle_and_snapshot_refuse_unwrapped_and_foreign_id_signatures(
) -> Result<(), AuthorityStoreError> {
    let (signed, anchor) = envelope()?;
    let commitment = anchor.commitment()?;
    let signer = Keypair::from_seed(&[42; 32]);
    let policy = AuthorityEnvelopeClockPolicy::new(1)?;
    let proof = signed
        .proof
        .as_ref()
        .ok_or_else(|| refused("test envelope missing proof"))?;
    let body = EnvelopeBody {
        schema: &proof.schema,
        stream_id: &proof.stream_id,
        anchor_digest: &proof.anchor_digest,
        chain_commitment: &proof.chain_commitment,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
        snapshot: &signed.snapshot,
    };
    for (label, signature) in crate::wrapper_refusals::refused_signatures(&signer, &body) {
        let mut forged = signed.clone();
        forged
            .proof
            .as_mut()
            .ok_or_else(|| refused("test envelope missing proof"))?
            .signature = signature;
        assert!(
            matches!(forged.verify_with_clock_policy(&anchor, &anchor.snapshot, &commitment, 100, policy), Err(AuthorityStoreError::Fence(message)) if message == "authority envelope signature invalid"),
            "{label}"
        );
    }

    let transition = SignedAuthorityTransition::sign(
        &anchor,
        &anchor.snapshot,
        &commitment,
        &Keypair::from_seed(&[44; 32]).public_key(),
        102,
        &signer,
    )?;
    verify_authority_chain(&anchor, std::slice::from_ref(&transition))?;
    for (label, signature) in crate::wrapper_refusals::refused_signatures(&signer, &transition.body)
    {
        let forged = SignedAuthorityTransition {
            signature,
            ..transition.clone()
        };
        assert!(
            matches!(verify_authority_chain(&anchor, &[forged]), Err(AuthorityStoreError::Fence(message)) if message == "authority transition signature invalid"),
            "{label}"
        );
    }
    Ok(())
}
