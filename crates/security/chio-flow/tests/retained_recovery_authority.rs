use chio_core_types::{
    canonical::CanonicalBytes,
    canonical_json_bytes,
    recovery::{
        RecoveryDigestDomain, RecoveryGrantBody, SignedAuthorityCoverageAttestationV1,
        SignedRecoveryGrant,
    },
    Keypair,
};
use chio_flow::{
    required_recovery_disclosure_obligations, verify_recovery_coverage,
    verify_retained_recovery_coverage_digest, DeclassificationError, RecoveryAuthorityAssignment,
};
use chio_security_types::{flow::PrincipalId, recovery::*, InformationLabel};
use std::collections::{BTreeMap, BTreeSet};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn action_digest(action: &ActionIntentV1) -> Result<IntentDigest, Box<dyn std::error::Error>> {
    Ok(IntentDigest::from_bytes(
        *RecoveryDigestDomain::ActionIntent
            .digest(&CanonicalBytes::new(action)?)
            .as_bytes(),
    ))
}
type Attestations =
    NonEmptyBoundedList<SignedAuthorityCoverageAttestationV1, MAX_RECOVERY_APPROVAL_ATTESTATIONS>;

struct Retained {
    approval: ApprovalIntentV1,
    requirements: AuthorizationRequirementsV1,
    action: ActionIntentV1,
    basis: BasisDigest,
    proofs: Vec<SignedAuthorityCoverageAttestationV1>,
    assignments: BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    keys: Vec<Keypair>,
}

/// A current-format bundle of `owners` single-owner attestations over the
/// current corpus approval and its reviewed action, retained for verification
/// at preparation time.
fn retained(owners: usize) -> Result<Retained, Box<dyn std::error::Error>> {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?;
    let mut requirements: AuthorizationRequirementsV1 =
        serde_json::from_value(corpus["requirements"].clone())?;
    let mut approval: ApprovalIntentV1 = serde_json::from_value(corpus["approval_intent"].clone())?;
    let labels = (0..owners)
        .map(|index| {
            let owner = PrincipalId::new(format!("owner:{index:02}"))?;
            Ok((owner.clone(), BTreeSet::from([owner])))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    requirements.source_label = InformationLabel::try_known(labels, BTreeSet::new())?;
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
    let mut action: ActionIntentV1 = serde_json::from_value(corpus["action"].clone())?;
    action.authorization_requirements = requirements.clone();
    action.basis = basis;
    approval.action_intent = action_digest(&action)?;
    let mut assignments = BTreeMap::new();
    let mut proofs = Vec::new();
    let mut keys = Vec::new();
    for (index, obligation) in requirements.obligations.as_slice().iter().enumerate() {
        let AuthorityObligationV1::OwnerRelease { owner } = obligation else {
            return Err("retained fixture contains only owner releases".into());
        };
        let seed = u8::try_from(index)?
            .checked_add(111)
            .ok_or("key seed overflow")?;
        let key = Keypair::from_seed(&[seed; 32]);
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
        assert!(proof.verify_integrity_embedded_key()?);
        proofs.push(proof);
        keys.push(key);
    }
    Ok(Retained {
        approval,
        requirements,
        action,
        basis,
        proofs,
        assignments,
        keys,
    })
}

impl Retained {
    fn digest_at(
        &self,
        proofs: &Attestations,
        assignments: &BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
        prepared_at: u64,
    ) -> Result<CoverageDigest, DeclassificationError> {
        verify_retained_recovery_coverage_digest(
            &self.approval,
            &self.requirements,
            &self.action,
            self.basis,
            proofs,
            assignments,
            prepared_at,
        )
    }
}

#[test]
fn retained_coverage_verifies_at_preparation_time_and_returns_only_a_digest() -> TestResult {
    let bundle = retained(MAX_RECOVERY_APPROVAL_ATTESTATIONS)?;
    let prepared_at = bundle
        .approval
        .issued_at_unix_ms
        .get()
        .checked_add(1)
        .ok_or("preparation time overflow")?;
    let after_expiry = bundle.approval.expires_at_unix_ms.get();
    let expected = CoverageDigest::from_bytes(
        *RecoveryDigestDomain::AuthorityCoverage
            .digest(&CanonicalBytes::new(&bundle.proofs)?)
            .as_bytes(),
    );
    let proofs = Attestations::new(bundle.proofs.clone())?;

    assert_eq!(
        bundle.digest_at(&proofs, &bundle.assignments, prepared_at)?,
        expected
    );
    let fresh = verify_recovery_coverage(
        &bundle.approval,
        &bundle.requirements,
        &bundle.action,
        bundle.basis,
        &proofs,
        &bundle.assignments,
        prepared_at,
    )?;
    assert_eq!(
        fresh.digest(),
        expected,
        "the same v1 shape at the same time"
    );
    assert_eq!(
        verify_recovery_coverage(
            &bundle.approval,
            &bundle.requirements,
            &bundle.action,
            bundle.basis,
            &proofs,
            &bundle.assignments,
            after_expiry,
        )
        .err(),
        Some(DeclassificationError::Expired),
        "the current time cannot reuse an expired bundle as fresh coverage"
    );
    assert_eq!(
        bundle
            .digest_at(&proofs, &bundle.assignments, after_expiry)
            .err(),
        Some(DeclassificationError::Expired),
        "retained verification is still bounded by the bundle validity"
    );

    let mut grant: RecoveryGrantBody = {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../spec/vectors/recovery/v1/authority-positive.json"
        ))?;
        serde_json::from_value(corpus["grant"]["body"].clone())?
    };
    grant.recovery.action_intent = bundle.approval.action_intent;
    grant.recovery.authorization_requirements = bundle.approval.authorization_requirements;
    grant.recovery.coverage_digest = expected;
    grant.claims = {
        let mut claims = serde_json::to_value(&grant.claims)?;
        claims["source_label_hash"] = serde_json::to_value(chio_flow::information_label_hash(
            &bundle.requirements.source_label,
        )?)?;
        serde_json::from_value(claims)?
    };
    grant.validate()?;
    let signed = SignedRecoveryGrant::sign(grant, &Keypair::from_seed(&[91; 32]))?;
    assert!(signed.verify_integrity_embedded_key()?);
    assert_eq!(
        serde_json::to_value(serde_json::from_slice::<SignedRecoveryGrant>(
            &canonical_json_bytes(&signed)?,
        )?)?,
        serde_json::to_value(&signed)?,
        "the retained digest binds into a canonical v1 grant"
    );
    Ok(())
}

#[test]
fn retained_coverage_keeps_every_action_binding_assignment_and_signature_check() -> TestResult {
    let bundle = retained(MAX_RECOVERY_APPROVAL_ATTESTATIONS)?;
    let prepared_at = bundle
        .approval
        .issued_at_unix_ms
        .get()
        .checked_add(1)
        .ok_or("preparation time overflow")?;

    let mut substituted = bundle.proofs.clone();
    let mut body = substituted[0].body().clone();
    body.challenge = ChallengeId::new("foreign-review")?;
    substituted[0] = SignedAuthorityCoverageAttestationV1::sign(body, &bundle.keys[0])?;
    assert_eq!(
        bundle
            .digest_at(
                &Attestations::new(substituted)?,
                &bundle.assignments,
                prepared_at
            )
            .err(),
        Some(DeclassificationError::BindingMismatch)
    );

    let proofs = Attestations::new(bundle.proofs.clone())?;
    let mut foreign_action = bundle.action.clone();
    foreign_action.request_id = RequestId::new("foreign-request")?;
    assert_eq!(
        verify_retained_recovery_coverage_digest(
            &bundle.approval,
            &bundle.requirements,
            &foreign_action,
            bundle.basis,
            &proofs,
            &bundle.assignments,
            prepared_at,
        )
        .err(),
        Some(DeclassificationError::BindingMismatch),
        "a retained bundle verifies only against the action its approval names"
    );
    let mut foreign_basis = bundle.action.clone();
    foreign_basis.basis = BasisDigest::from_bytes([9; 32]);
    assert_eq!(
        verify_retained_recovery_coverage_digest(
            &bundle.approval,
            &bundle.requirements,
            &foreign_basis,
            bundle.basis,
            &proofs,
            &bundle.assignments,
            prepared_at,
        )
        .err(),
        Some(DeclassificationError::BindingMismatch),
        "a retained action must carry the independently selected basis"
    );
    let unassigned: BTreeMap<_, _> = bundle
        .assignments
        .iter()
        .skip(1)
        .map(|(issuer, assignment)| {
            (
                issuer.clone(),
                RecoveryAuthorityAssignment {
                    principal: assignment.principal.clone(),
                    key: assignment.key.clone(),
                    obligations: assignment.obligations.clone(),
                },
            )
        })
        .collect();
    assert_eq!(
        bundle.digest_at(&proofs, &unassigned, prepared_at).err(),
        Some(DeclassificationError::UntrustedAuthority),
        "a retained bundle cannot skip a missing operator assignment"
    );

    let mut foreign_key = bundle.proofs.clone();
    foreign_key[0] = SignedAuthorityCoverageAttestationV1::sign(
        foreign_key[0].body().clone(),
        &Keypair::from_seed(&[250; 32]),
    )?;
    assert_eq!(
        bundle
            .digest_at(
                &Attestations::new(foreign_key)?,
                &bundle.assignments,
                prepared_at
            )
            .err(),
        Some(DeclassificationError::UntrustedAuthority)
    );

    let mut swapped = serde_json::to_value(&bundle.proofs[0])?;
    swapped["signature"] = serde_json::to_value(bundle.proofs[1].signature())?;
    let mut tampered = bundle.proofs.clone();
    tampered[0] = serde_json::from_value(swapped)?;
    assert_eq!(
        bundle
            .digest_at(
                &Attestations::new(tampered)?,
                &bundle.assignments,
                prepared_at
            )
            .err(),
        Some(DeclassificationError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn retained_bundles_share_the_sixteen_attestation_bound() -> TestResult {
    let wide = retained(MAX_RECOVERY_APPROVAL_ATTESTATIONS + 1)?;
    assert_eq!(wide.proofs.len(), 17);
    assert_eq!(
        Attestations::new(wide.proofs.clone()).err(),
        Some(ContractError::LimitExceeded),
        "a retained bundle has no wider codec than a fresh one"
    );
    let decoded = serde_json::from_value::<Attestations>(serde_json::to_value(&wide.proofs)?)
        .err()
        .map(|error| error.to_string());
    assert!(
        decoded
            .is_some_and(|message| message.starts_with(&ContractError::LimitExceeded.to_string())),
        "a retained 17-entry wire bundle refuses at the type bound"
    );
    Ok(())
}
