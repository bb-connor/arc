//! Modeled prior-verification compatibility, not a physical native capture.
use chio_core_types::{
    canonical::CanonicalBytes,
    canonical_json_bytes,
    recovery::{
        RecoveryDigestDomain, RecoveryGrantBodyV2, SignedAuthorityCoverageAttestationV1,
        SignedRecoveryGrantV2,
    },
    Keypair,
};
use chio_flow::{
    required_recovery_disclosure_obligations, verify_historical_recovery_coverage_digest,
    verify_recovery_coverage, DeclassificationError, RecoveryAuthorityAssignment,
};
use chio_security_types::{flow::PrincipalId, recovery::*, InformationLabel};
use std::collections::{BTreeMap, BTreeSet};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn retained_coverage_preserves_preparation_time_without_creating_fresh_authority() -> TestResult {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?;
    let mut requirements: AuthorizationRequirementsV1 =
        serde_json::from_value(corpus["requirements"].clone())?;
    let mut approval: ApprovalIntentV1 = serde_json::from_value(corpus["approval_intent"].clone())?;
    let mut grant: RecoveryGrantBodyV2 = serde_json::from_value(corpus["grant"]["body"].clone())?;
    let owners = (0..17)
        .map(|index| {
            let owner = PrincipalId::new(format!("owner:{index:02}"))?;
            Ok((owner.clone(), BTreeSet::from([owner])))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    requirements.source_label = InformationLabel::try_known(owners, BTreeSet::new())?;
    requirements.admitted_target = InformationLabel::bottom();
    requirements.obligations = required_recovery_disclosure_obligations(
        &requirements.source_label,
        &requirements.admitted_target,
    )?;
    approval.obligations = requirements.obligations.clone();
    approval.authorization_requirements = AuthorizationRequirementsDigest::from_bytes(
        *RecoveryDigestDomain::AuthorizationRequirements
            .digest(&CanonicalBytes::new(&requirements)?)
            .as_bytes(),
    );
    let basis = BasisDigest::from_bytes([8; 32]);
    let prepared_at = approval.issued_at_unix_ms.get() + 1;
    let mut assignments = BTreeMap::new();
    let mut proofs = Vec::new();
    let mut keys = Vec::new();
    for (index, obligation) in requirements.obligations.as_slice().iter().enumerate() {
        let AuthorityObligationV1::OwnerRelease { owner } = obligation else {
            return Err("modeled retained fixture contains only owner releases".into());
        };
        let key = Keypair::from_seed(&[u8::try_from(index)? + 111; 32]);
        let body = AuthorityCoverageAttestationV1 {
            schema: AuthorityCoverageSchema::V1,
            version: VersionV1,
            scope: approval.scope.clone(),
            approval_intent: approval.approval_intent.clone(),
            challenge: approval.challenge.clone(),
            action_intent: approval.action_intent,
            authorization_requirements: approval.authorization_requirements,
            source_basis: basis,
            issuer_id: IssuerId::new(&format!("issuer:{index:02}"))?,
            principal: owner.clone(),
            obligations: NonEmptyBoundedList::new(vec![obligation.clone()])?,
            issued_at_unix_ms: approval.issued_at_unix_ms,
            expires_at_unix_ms: approval.expires_at_unix_ms,
        };
        assignments.insert(
            body.issuer_id.clone(),
            RecoveryAuthorityAssignment {
                principal: owner.clone(),
                key: key.public_key(),
                obligations: BTreeSet::from([obligation.clone()]),
            },
        );
        let proof = SignedAuthorityCoverageAttestationV1::sign(body, &key)?;
        assert!(proof.verify_signature()?);
        proofs.push(proof);
        keys.push(key);
    }
    let expected = CoverageDigest::from_bytes(
        *RecoveryDigestDomain::AuthorityCoverage
            .digest(&CanonicalBytes::new(&proofs)?)
            .as_bytes(),
    );
    grant.recovery.authorization_requirements = approval.authorization_requirements;
    grant.recovery.coverage_digest = expected;
    grant.claims = {
        let mut claims = serde_json::to_value(&grant.claims)?;
        claims["source_label_hash"] = serde_json::to_value(chio_flow::information_label_hash(
            &requirements.source_label,
        )?)?;
        serde_json::from_value(claims)?
    };
    grant.validate()?;
    let signed = SignedRecoveryGrantV2::sign(grant, &Keypair::from_seed(&[91; 32]))?;
    assert!(signed.verify_signature()?);
    assert_eq!(
        serde_json::to_value(serde_json::from_slice::<SignedRecoveryGrantV2>(
            &canonical_json_bytes(&signed)?,
        )?)?,
        serde_json::to_value(&signed)?,
    );
    let proofs = NonEmptyBoundedList::new(proofs)?;
    assert_eq!(
        verify_recovery_coverage(
            &approval,
            &requirements,
            basis,
            &proofs,
            &assignments,
            prepared_at,
        )
        .err(),
        Some(DeclassificationError::InvalidGrant),
    );
    assert_eq!(
        verify_historical_recovery_coverage_digest(
            &approval,
            &requirements,
            basis,
            &proofs,
            &assignments,
            prepared_at,
        )?,
        expected,
    );
    assert_eq!(
        verify_historical_recovery_coverage_digest(
            &approval,
            &requirements,
            basis,
            &proofs,
            &assignments,
            approval.expires_at_unix_ms.get(),
        )
        .err(),
        Some(DeclassificationError::Expired),
    );
    let mut substituted = proofs.as_slice().to_vec();
    let mut body = substituted[0].body().clone();
    body.challenge = ChallengeId::new("foreign-review")?;
    substituted[0] = SignedAuthorityCoverageAttestationV1::sign(body, &keys[0])?;
    assert_eq!(
        verify_historical_recovery_coverage_digest(
            &approval,
            &requirements,
            basis,
            &NonEmptyBoundedList::new(substituted)?,
            &assignments,
            prepared_at,
        )
        .err(),
        Some(DeclassificationError::BindingMismatch),
    );
    Ok(())
}
