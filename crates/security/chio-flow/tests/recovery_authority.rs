use chio_core_types::recovery::SignedAuthorityCoverageAttestationV1 as Signed;
use chio_core_types::{canonical_json_bytes, sha256, Keypair};
use chio_flow::*;
use chio_security_types::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
use chio_security_types::ports::DestinationId;
use chio_security_types::recovery::*;
use std::collections::BTreeMap;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    approval: ApprovalIntentV1,
    requirements: AuthorizationRequirementsV1,
    basis: BasisDigest,
    proofs: Vec<Signed>,
    assignments: BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    keys: Vec<Keypair>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("authority")?,
            tenant_id: RecoveryTenantId::new("tenant")?,
            process_id: ProcessId::new("process")?,
        };
        let source: InformationLabel = serde_json::from_value(
            serde_json::json!({"kind":"known","owners":{"alice":["alice"],"bob":["bob"]},"compartments":["restricted"]}),
        )?;
        let requirements = AuthorizationRequirementsV1 {
            schema: AuthorizationRequirementsSchema::V1,
            version: VersionV1,
            scope: scope.clone(),
            source_label: source.clone(),
            admitted_target: InformationLabel::bottom(),
            source_join: SourceDigest::from_bytes([1; 32]),
            influence_basis: SourceDigest::from_bytes([2; 32]),
            recipient: DestinationId::new("issues")?,
            purpose: DeclassificationPurpose::new("approved-disclosure")?,
            obligations: required_recovery_disclosure_obligations(
                &source,
                &InformationLabel::bottom(),
            )?,
            issuer_scope: AuthorityScopeDigest::from_bytes([3; 32]),
            validity_ceiling_unix_ms: SafeInteger::new(200_000)?,
            attachment_profile: RecoveryAttachmentProfile::Ordinary,
        };
        let mut preimage = b"chio.recovery.authorization-requirements.v1\0".to_vec();
        preimage.extend_from_slice(&canonical_json_bytes(&requirements)?);
        let approval = ApprovalIntentV1 {
            schema: ApprovalIntentSchema::V1,
            version: VersionV1,
            scope,
            approval_intent: ApprovalIntentRef::new("approval")?,
            challenge: ChallengeId::new("challenge")?,
            action_intent: IntentDigest::from_bytes([4; 32]),
            authorization_requirements: AuthorizationRequirementsDigest::from_bytes(
                *sha256(&preimage).as_bytes(),
            ),
            offer: OfferDigest::from_bytes([5; 32]),
            plan: PlanDigest::from_bytes([6; 32]),
            preview: ReviewDigest::from_bytes([7; 32]),
            recipient: requirements.recipient.clone(),
            purpose: requirements.purpose.clone(),
            obligations: requirements.obligations.clone(),
            reviewer: PrincipalId::new("reviewer")?,
            issued_at_unix_ms: SafeInteger::new(100_000)?,
            expires_at_unix_ms: SafeInteger::new(200_000)?,
        };
        let basis = BasisDigest::from_bytes([8; 32]);
        let mut proofs = Vec::new();
        let mut assignments = BTreeMap::new();
        let mut keys = Vec::new();
        for (index, name) in ["alice", "bob", "ops"].into_iter().enumerate() {
            let key = Keypair::from_seed(&[index as u8 + 11; 32]);
            let obligation = requirements.obligations.as_slice()[index].clone();
            let body = AuthorityCoverageAttestationV1 {
                schema: AuthorityCoverageSchema::V1,
                version: VersionV1,
                scope: approval.scope.clone(),
                approval_intent: approval.approval_intent.clone(),
                challenge: approval.challenge.clone(),
                action_intent: approval.action_intent,
                authorization_requirements: approval.authorization_requirements,
                source_basis: basis,
                issuer_id: IssuerId::new(&format!("issuer-{name}"))?,
                principal: PrincipalId::new(name)?,
                obligations: NonEmptyBoundedList::new(vec![obligation.clone()])?,
                issued_at_unix_ms: approval.issued_at_unix_ms,
                expires_at_unix_ms: approval.expires_at_unix_ms,
            };
            assignments.insert(
                body.issuer_id.clone(),
                RecoveryAuthorityAssignment {
                    principal: body.principal.clone(),
                    key: key.public_key(),
                    obligations: [obligation].into_iter().collect(),
                },
            );
            proofs.push(Signed::sign(body, &key)?);
            keys.push(key);
        }
        Ok(Self {
            approval,
            requirements,
            basis,
            proofs,
            assignments,
            keys,
        })
    }
    fn verify(
        &self,
        proofs: Vec<Signed>,
        now: u64,
    ) -> std::result::Result<VerifiedRecoveryCoverage, DeclassificationError> {
        let proofs =
            NonEmptyBoundedList::new(proofs).map_err(|_| DeclassificationError::InvalidGrant)?;
        verify_recovery_coverage(
            &self.approval,
            &self.requirements,
            self.basis,
            &proofs,
            &self.assignments,
            now,
        )
    }
}
#[test]
fn recovery_multiple_owners_require_conjunctive_scoped_coverage() -> Result {
    let f = Fixture::new()?;
    let positive = f.verify(f.proofs.clone(), 150_000)?;
    let mut reverse = f.proofs.clone();
    reverse.reverse();
    assert_eq!(positive.digest(), f.verify(reverse, 150_000)?.digest());
    assert_eq!(positive.obligations().len(), 3);
    for omitted in 0..3 {
        let mut proofs = f.proofs.clone();
        proofs.remove(omitted);
        assert_eq!(
            f.verify(proofs, 150_000).err(),
            Some(DeclassificationError::UntrustedAuthority)
        );
    }
    let mut duplicates = f.proofs.clone();
    duplicates.push(f.proofs[0].clone());
    assert_eq!(
        f.verify(duplicates, 150_000).err(),
        Some(DeclassificationError::BindingMismatch)
    );
    assert_eq!(
        f.verify(f.proofs.clone(), 99_999).err(),
        Some(DeclassificationError::NotYetValid)
    );
    assert_eq!(
        f.verify(f.proofs.clone(), 200_000).err(),
        Some(DeclassificationError::Expired)
    );
    Ok(())
}

#[test]
fn fresh_coverage_enforces_the_protocol_attestation_ceiling() -> Result {
    use std::collections::BTreeSet;
    for count in [16, 17] {
        let mut f = Fixture::new()?;
        let owners = (0..count)
            .map(|index| {
                let owner = PrincipalId::new(format!("owner:{index:02}"))?;
                Ok((owner.clone(), BTreeSet::from([owner])))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        f.requirements.source_label = InformationLabel::try_known(owners, BTreeSet::new())?;
        f.requirements.obligations = required_recovery_disclosure_obligations(
            &f.requirements.source_label,
            &f.requirements.admitted_target,
        )?;
        f.approval.obligations = f.requirements.obligations.clone();
        let mut preimage = b"chio.recovery.authorization-requirements.v1\0".to_vec();
        preimage.extend_from_slice(&canonical_json_bytes(&f.requirements)?);
        f.approval.authorization_requirements =
            AuthorizationRequirementsDigest::from_bytes(*sha256(&preimage).as_bytes());
        f.proofs.clear();
        f.assignments.clear();
        for (index, obligation) in f.requirements.obligations.as_slice().iter().enumerate() {
            let AuthorityObligationV1::OwnerRelease { owner } = obligation else {
                return Err("fixture contains only owner releases".into());
            };
            let index = u8::try_from(index)?;
            let key = Keypair::from_seed(&[index + 101; 32]);
            let body = AuthorityCoverageAttestationV1 {
                schema: AuthorityCoverageSchema::V1,
                version: VersionV1,
                scope: f.approval.scope.clone(),
                approval_intent: f.approval.approval_intent.clone(),
                challenge: f.approval.challenge.clone(),
                action_intent: f.approval.action_intent,
                authorization_requirements: f.approval.authorization_requirements,
                source_basis: f.basis,
                issuer_id: IssuerId::new(&format!("issuer:{index:02}"))?,
                principal: owner.clone(),
                obligations: NonEmptyBoundedList::new(vec![obligation.clone()])?,
                issued_at_unix_ms: f.approval.issued_at_unix_ms,
                expires_at_unix_ms: f.approval.expires_at_unix_ms,
            };
            f.assignments.insert(
                body.issuer_id.clone(),
                RecoveryAuthorityAssignment {
                    principal: owner.clone(),
                    key: key.public_key(),
                    obligations: BTreeSet::from([obligation.clone()]),
                },
            );
            f.proofs.push(Signed::sign(body, &key)?);
        }
        let result = f.verify(f.proofs.clone(), 150_000);
        if count == 16 {
            assert_eq!(result?.obligations().len(), count);
        } else {
            assert_eq!(result.err(), Some(DeclassificationError::InvalidGrant));
        }
    }
    Ok(())
}
#[test]
fn recovery_resigned_context_substitutions_fail_the_intended_binding() -> Result {
    let f = Fixture::new()?;
    for field in [
        "scope",
        "approval_intent",
        "challenge",
        "action_intent",
        "authorization_requirements",
        "source_basis",
        "principal",
        "obligations",
    ] {
        let mut body = serde_json::to_value(f.proofs[0].body())?;
        match field {
            "scope" => body[field]["tenant_id"] = serde_json::json!("foreign-tenant"),
            "action_intent" | "authorization_requirements" | "source_basis" => {
                body[field] = serde_json::to_value(vec![9; 32])?
            }
            "obligations" => {
                body[field] = serde_json::to_value(f.proofs[2].body().obligations.clone())?
            }
            _ => body[field] = serde_json::json!("foreign"),
        }
        let signed = Signed::sign(serde_json::from_value(body)?, &f.keys[0])?;
        assert!(
            signed.verify_signature()?,
            "mutation must retain valid crypto: {field}"
        );
        let mut proofs = f.proofs.clone();
        proofs[0] = signed;
        let expected = if matches!(field, "principal" | "obligations") {
            DeclassificationError::UntrustedAuthority
        } else {
            DeclassificationError::BindingMismatch
        };
        assert_eq!(f.verify(proofs, 150_000).err(), Some(expected), "{field}");
    }
    let mut changed = Fixture::new()?;
    changed.requirements.issuer_scope = AuthorityScopeDigest::from_bytes([99; 32]);
    assert_eq!(
        changed.verify(changed.proofs.clone(), 150_000).err(),
        Some(DeclassificationError::BindingMismatch)
    );
    Ok(())
}
#[test]
fn recovery_alias_rotation_and_integrity_powers_cannot_manufacture_coverage() -> Result {
    let mut f = Fixture::new()?;
    let mut body = f.proofs[0].body().clone();
    body.issuer_id = IssuerId::new("rotated-alias")?;
    let rotated = Keypair::from_seed(&[40; 32]);
    f.assignments.insert(
        body.issuer_id.clone(),
        RecoveryAuthorityAssignment {
            principal: body.principal.clone(),
            key: rotated.public_key(),
            obligations: body.obligations.as_slice().iter().cloned().collect(),
        },
    );
    let mut proofs = f.proofs.clone();
    proofs.push(Signed::sign(body, &rotated)?);
    assert_eq!(
        f.verify(proofs, 150_000).err(),
        Some(DeclassificationError::BindingMismatch)
    );
    let mut body = f.proofs[0].body().clone();
    body.obligations =
        NonEmptyBoundedList::new(vec![AuthorityObligationV1::IntegrityEndorsement {
            principal: PrincipalId::new("alice")?,
        }])?;
    let mut proofs = f.proofs.clone();
    proofs[0] = Signed::sign(body, &f.keys[0])?;
    assert_eq!(
        f.verify(proofs, 150_000).err(),
        Some(DeclassificationError::UntrustedAuthority)
    );
    let mut proofs = f.proofs.clone();
    proofs[0] = Signed::sign(f.proofs[0].body().clone(), &rotated)?;
    assert_eq!(
        f.verify(proofs, 150_000).err(),
        Some(DeclassificationError::UntrustedAuthority)
    );
    Ok(())
}

#[test]
fn recovery_all_resigned_grant_binding_fields_refuse_foreign_contexts() -> Result {
    use chio_core_types::recovery::SignedRecoveryGrantV2;
    use chio_security_types::ports::{CanonicalBody, RecordId};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?;
    let grant: SignedRecoveryGrantV2 = serde_json::from_value(fixture["grant"].clone())?;
    let requirements: AuthorizationRequirementsV1 =
        serde_json::from_value(fixture["requirements"].clone())?;
    let approval: ApprovalIntentV1 = serde_json::from_value(fixture["approval_intent"].clone())?;
    let action: ActionIntentV1 = serde_json::from_value(fixture["action"].clone())?;
    let proof: Signed = serde_json::from_value(fixture["coverage"][0].clone())?;
    let assignments = BTreeMap::from([(
        proof.body().issuer_id.clone(),
        RecoveryAuthorityAssignment {
            principal: proof.body().principal.clone(),
            key: proof.authority_key().clone(),
            obligations: proof
                .body()
                .obligations
                .as_slice()
                .iter()
                .cloned()
                .collect(),
        },
    )]);
    let coverage = verify_recovery_coverage(
        &approval,
        &requirements,
        action.basis,
        &NonEmptyBoundedList::new(vec![proof])?,
        &assignments,
        approval.issued_at_unix_ms.get() + 1,
    )?;
    let claims = &grant.body().claims;
    let request = DeclassificationVerificationRequest {
        capability_id: claims.capability_id().clone(),
        tenant_id: claims.tenant_id().clone(),
        subject_id: claims.subject_id().clone(),
        agent_id: claims.agent_id().clone(),
        session_id: claims.session_id().clone(),
        source_label: requirements.source_label,
        destination_id: claims.destination_id().clone(),
        tool_name: claims.tool_name().clone(),
        purpose: claims.purpose().clone(),
        policy_purposes: [claims.purpose().clone()].into_iter().collect(),
        manifest_purposes: [claims.purpose().clone()].into_iter().collect(),
        canonical_request: CanonicalBody::new(canonical_json_bytes(
            &fixture["request"]["arguments"],
        )?)?,
        now_unix_ms: approval
            .issued_at_unix_ms
            .get()
            .checked_add(1)
            .ok_or("approval fixture timestamp overflow")?,
        trusted_authorities: BTreeMap::from([(
            claims.authority_key_id().clone(),
            grant.authority_key().clone(),
        )]),
    };
    let expected = grant.body().recovery.clone();
    // Whole-second grant claims do not move signed millisecond coverage earlier.
    let mut premature = request.clone();
    premature.now_unix_ms = claims
        .issued_at_unix_seconds()
        .checked_mul(1000)
        .and_then(|issued| issued.checked_add(1))
        .ok_or("grant fixture timestamp overflow")?;
    assert_eq!(
        verify_recovery_declassification(&grant, &premature, &expected, &coverage).err(),
        Some(DeclassificationError::NotYetValid)
    );
    assert_eq!(
        verify_recovery_declassification(&grant, &request, &expected, &coverage).err(),
        None,
        "positive signed coverage control"
    );
    let key = Keypair::from_seed(&[143; 32]);
    for (name, original) in fixture["grant"]["body"]["recovery"]
        .as_object()
        .ok_or("binding")?
    {
        if matches!(name.as_str(), "schema" | "version") {
            continue;
        }
        let mut body = fixture["grant"]["body"].clone();
        body["recovery"][name] = match original {
            serde_json::Value::Array(_) => serde_json::to_value(vec![99; 32])?,
            serde_json::Value::Number(_) => serde_json::json!(999),
            _ => serde_json::json!("foreign-context"),
        };
        let changed = SignedRecoveryGrantV2::sign(serde_json::from_value(body)?, &key)?;
        assert!(
            changed.verify_signature()?,
            "resigned mutation lost crypto: {name}"
        );
        assert_eq!(
            verify_recovery_declassification(&changed, &request, &expected, &coverage).err(),
            Some(DeclassificationError::BindingMismatch),
            "wrong invariant: {name}"
        );
    }
    let mut other = request.clone();
    other.destination_id = DestinationId::new("foreign-recipient")?;
    assert_eq!(
        verify_recovery_declassification(&grant, &other, &expected, &coverage).err(),
        Some(DeclassificationError::BindingMismatch)
    );
    let mut other = request.clone();
    other.trusted_authorities = BTreeMap::from([(
        RecordId::new(claims.authority_key_id().as_str())?,
        Keypair::from_seed(&[99; 32]).public_key(),
    )]);
    assert_eq!(
        verify_recovery_declassification(&grant, &other, &expected, &coverage).err(),
        Some(DeclassificationError::UntrustedAuthority)
    );
    let mut expired = request;
    expired.now_unix_ms = claims.expires_at_unix_seconds() * 1000;
    assert_eq!(
        verify_recovery_declassification(&grant, &expired, &expected, &coverage).err(),
        Some(DeclassificationError::Expired)
    );
    Ok(())
}

#[test]
fn recovery_grants_cannot_widen_or_substitute_independently_verified_coverage() -> Result {
    use chio_core_types::canonical::CanonicalBytes;
    use chio_core_types::recovery::{RecoveryDigestDomain, SignedRecoveryGrantV2};
    use chio_security_types::ports::CanonicalBody;

    let mut f = Fixture::new()?;
    let target: InformationLabel = serde_json::from_value(serde_json::json!({
        "kind":"known", "owners":{"bob":["bob"]}, "compartments":["restricted"]
    }))?;
    f.requirements.admitted_target = target.clone();
    f.requirements.obligations =
        required_recovery_disclosure_obligations(&f.requirements.source_label, &target)?;
    f.approval.obligations = f.requirements.obligations.clone();
    f.approval.authorization_requirements = AuthorizationRequirementsDigest::from_bytes(
        *RecoveryDigestDomain::AuthorizationRequirements
            .digest(&CanonicalBytes::new(&f.requirements)?)
            .as_bytes(),
    );
    let mut proof = f.proofs[0].body().clone();
    proof.authorization_requirements = f.approval.authorization_requirements;
    proof.obligations = f.requirements.obligations.clone();
    f.proofs = vec![Signed::sign(proof, &f.keys[0])?];
    let coverage = f.verify(f.proofs.clone(), 150_000)?;

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?;
    let mut body = fixture["grant"]["body"].clone();
    let source_hash = information_label_hash(&f.requirements.source_label)?;
    body["claims"]["source_label_hash"] = serde_json::to_value(source_hash)?;
    body["claims"]["target_label"] = serde_json::to_value(&target)?;
    body["claims"]["tenant_id"] = serde_json::to_value(&f.approval.scope.tenant_id)?;
    body["claims"]["destination_id"] = serde_json::to_value(&f.approval.recipient)?;
    body["claims"]["purpose"] = serde_json::to_value(&f.approval.purpose)?;
    body["claims"]["issued_at_unix_seconds"] = serde_json::json!(100);
    body["claims"]["expires_at_unix_seconds"] = serde_json::json!(160);
    body["recovery"]["authority_domain"] =
        serde_json::to_value(&f.approval.scope.authority_domain)?;
    body["recovery"]["process_id"] = serde_json::to_value(&f.approval.scope.process_id)?;
    body["recovery"]["action_intent"] = serde_json::to_value(f.approval.action_intent)?;
    body["recovery"]["authorization_requirements"] =
        serde_json::to_value(f.approval.authorization_requirements)?;
    body["recovery"]["approval_intent"] = serde_json::to_value(&f.approval.approval_intent)?;
    body["recovery"]["challenge"] = serde_json::to_value(&f.approval.challenge)?;
    body["recovery"]["selected_offer"] = serde_json::to_value(f.approval.offer)?;
    body["recovery"]["approved_plan"] = serde_json::to_value(f.approval.plan)?;
    body["recovery"]["authority_scope"] = serde_json::to_value(f.requirements.issuer_scope)?;
    body["recovery"]["coverage_digest"] = serde_json::to_value(coverage.digest())?;
    let key = Keypair::from_seed(&[143; 32]);
    let grant = SignedRecoveryGrantV2::sign(serde_json::from_value(body.clone())?, &key)?;
    let claims = &grant.body().claims;
    let request = DeclassificationVerificationRequest {
        capability_id: claims.capability_id().clone(),
        tenant_id: claims.tenant_id().clone(),
        subject_id: claims.subject_id().clone(),
        agent_id: claims.agent_id().clone(),
        session_id: claims.session_id().clone(),
        source_label: f.requirements.source_label,
        destination_id: claims.destination_id().clone(),
        tool_name: claims.tool_name().clone(),
        purpose: claims.purpose().clone(),
        policy_purposes: [claims.purpose().clone()].into_iter().collect(),
        manifest_purposes: [claims.purpose().clone()].into_iter().collect(),
        canonical_request: CanonicalBody::new(canonical_json_bytes(
            &fixture["request"]["arguments"],
        )?)?,
        now_unix_ms: 150_000,
        trusted_authorities: BTreeMap::from([(
            claims.authority_key_id().clone(),
            key.public_key(),
        )]),
    };
    assert!(
        verify_recovery_declassification(&grant, &request, &grant.body().recovery, &coverage)
            .is_ok()
    );
    for field in [
        "target_label",
        "action_intent",
        "authorization_requirements",
        "approval_intent",
        "challenge",
        "selected_offer",
        "approved_plan",
        "authority_scope",
        "authority_domain",
        "process_id",
    ] {
        let mut changed = body.clone();
        if field == "target_label" {
            changed["claims"][field] = serde_json::to_value(InformationLabel::bottom())?;
        } else {
            let value = &changed["recovery"][field];
            changed["recovery"][field] = if value.is_array() {
                serde_json::to_value([99; 32])?
            } else {
                serde_json::json!("foreign-context")
            };
        }
        let changed = SignedRecoveryGrantV2::sign(serde_json::from_value(changed)?, &key)?;
        assert!(
            changed.verify_signature()?,
            "the negative must retain trusted cryptography"
        );
        assert_eq!(
            verify_recovery_declassification(
                &changed,
                &request,
                &changed.body().recovery,
                &coverage
            )
            .err(),
            Some(DeclassificationError::BindingMismatch),
            "coverage must independently bind {field}",
        );
    }
    // A verified proof object keeps its original freshness interval even when
    // an otherwise trusted issuer signs a later grant around that old proof.
    let mut later = body;
    later["claims"]["issued_at_unix_seconds"] = serde_json::json!(180);
    later["claims"]["expires_at_unix_seconds"] = serde_json::json!(240);
    let later = SignedRecoveryGrantV2::sign(serde_json::from_value(later)?, &key)?;
    let mut after_coverage = request;
    after_coverage.now_unix_ms = 200_000;
    assert_eq!(
        verify_recovery_declassification(
            &later,
            &after_coverage,
            &later.body().recovery,
            &coverage,
        )
        .err(),
        Some(DeclassificationError::Expired),
    );
    Ok(())
}
