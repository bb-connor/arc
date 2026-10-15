use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::recovery::{
    RecoveryDigestDomain, SignedAuthorityCoverageAttestationV1 as Signed, SignedRecoveryGrant,
};
use chio_core_types::{canonical_json_bytes, Keypair};
use chio_flow::*;
use chio_security_types::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
use chio_security_types::ports::{CanonicalBody, DestinationId, RecordId};
use chio_security_types::recovery::*;
use std::collections::{BTreeMap, BTreeSet};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type Attestations = NonEmptyBoundedList<Signed, MAX_RECOVERY_APPROVAL_ATTESTATIONS>;

fn corpus() -> Result<serde_json::Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?)
}

fn requirements_digest(
    requirements: &AuthorizationRequirementsV1,
) -> Result<AuthorizationRequirementsDigest> {
    Ok(AuthorizationRequirementsDigest::from_bytes(
        *RecoveryDigestDomain::AuthorizationRequirements
            .digest(&CanonicalBytes::new(requirements)?)
            .as_bytes(),
    ))
}

fn key(seed: usize, base: u8) -> Result<Keypair> {
    let seed = u8::try_from(seed)?
        .checked_add(base)
        .ok_or("key seed overflow")?;
    Ok(Keypair::from_seed(&[seed; 32]))
}

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
        let source: InformationLabel = serde_json::from_value(serde_json::json!({
            "kind":"known", "owners":{"alice":["alice"],"bob":["bob"]}, "compartments":["restricted"]
        }))?;
        let mut fixture = Self::empty(source)?;
        for (index, name) in ["alice", "bob", "ops"].into_iter().enumerate() {
            let obligation = fixture
                .requirements
                .obligations
                .as_slice()
                .get(index)
                .ok_or("fixture obligation")?
                .clone();
            fixture.attest(
                key(index, 11)?,
                &format!("issuer-{name}"),
                name,
                vec![obligation],
            )?;
        }
        Ok(fixture)
    }

    /// Requirements over `source` downgraded to the bottom label, with no attestations.
    fn empty(source: InformationLabel) -> Result<Self> {
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("authority")?,
            tenant_id: RecoveryTenantId::new("tenant")?,
            process_id: ProcessId::new("process")?,
        };
        let obligations =
            required_recovery_disclosure_obligations(&source, &InformationLabel::bottom())?;
        let requirements = AuthorizationRequirementsV1 {
            schema: AuthorizationRequirementsSchema::V1,
            version: VersionV1,
            scope: scope.clone(),
            source_label: source,
            admitted_target: InformationLabel::bottom(),
            source_join: SourceDigest::from_bytes([1; 32]),
            influence_basis: SourceDigest::from_bytes([2; 32]),
            recipient: DestinationId::new("issues")?,
            purpose: DeclassificationPurpose::new("approved-disclosure")?,
            obligations,
            issuer_scope: AuthorityScopeDigest::from_bytes([3; 32]),
            validity_ceiling_unix_ms: SafeInteger::new(200_000)?,
            attachment_profile: RecoveryAttachmentProfile::Ordinary,
        };
        let approval = ApprovalIntentV1 {
            schema: ApprovalIntentSchema::V1,
            version: VersionV1,
            scope,
            approval_intent: ApprovalIntentRef::new("approval")?,
            challenge: ChallengeId::new("challenge")?,
            action_intent: IntentDigest::from_bytes([4; 32]),
            authorization_requirements: requirements_digest(&requirements)?,
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
        Ok(Self {
            approval,
            requirements,
            basis: BasisDigest::from_bytes([8; 32]),
            proofs: Vec::new(),
            assignments: BTreeMap::new(),
            keys: Vec::new(),
        })
    }

    /// Source label with `count` owners, each released to the bottom label.
    fn owners(count: usize) -> Result<Self> {
        let owners = (0..count)
            .map(|index| {
                let owner = PrincipalId::new(format!("owner:{index:02}"))?;
                Ok((owner.clone(), BTreeSet::from([owner])))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Self::empty(InformationLabel::try_known(owners, BTreeSet::new())?)
    }

    /// Sign one attestation and install the matching operator assignment.
    fn attest(
        &mut self,
        key: Keypair,
        issuer: &str,
        principal: &str,
        obligations: Vec<AuthorityObligationV1>,
    ) -> Result {
        let body = self.body(issuer, principal, obligations.clone())?;
        self.assignments.insert(
            body.issuer_id.clone(),
            RecoveryAuthorityAssignment {
                principal: body.principal.clone(),
                key: key.public_key(),
                obligations: obligations.into_iter().collect(),
            },
        );
        self.proofs.push(Signed::sign(body, &key)?);
        self.keys.push(key);
        Ok(())
    }

    fn body(
        &self,
        issuer: &str,
        principal: &str,
        obligations: Vec<AuthorityObligationV1>,
    ) -> Result<AuthorityCoverageAttestationV1> {
        Ok(AuthorityCoverageAttestationV1 {
            schema: AuthorityCoverageSchema::V1,
            version: VersionV1,
            scope: self.approval.scope.clone(),
            approval_intent: self.approval.approval_intent.clone(),
            challenge: self.approval.challenge.clone(),
            action_intent: self.approval.action_intent,
            authorization_requirements: self.approval.authorization_requirements,
            source_basis: self.basis,
            issuer_id: IssuerId::new(issuer)?,
            principal: PrincipalId::new(principal)?,
            obligations: NonEmptyBoundedList::new(obligations)?,
            issued_at_unix_ms: self.approval.issued_at_unix_ms,
            expires_at_unix_ms: self.approval.expires_at_unix_ms,
        })
    }

    /// Attestation `index` covers the obligations selected by `cover`.
    fn attest_all(&mut self, attestations: usize, cover: impl Fn(usize) -> Vec<usize>) -> Result {
        let obligations = self.requirements.obligations.as_slice().to_vec();
        for index in 0..attestations {
            let selected = cover(index)
                .into_iter()
                .map(|position| obligations.get(position).cloned().ok_or("obligation index"))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            self.attest(
                key(index, 101)?,
                &format!("issuer:{index:02}"),
                &format!("principal:{index:02}"),
                selected,
            )?;
        }
        Ok(())
    }

    fn verify(
        &self,
        proofs: Vec<Signed>,
        now: u64,
    ) -> std::result::Result<VerifiedRecoveryCoverage, DeclassificationError> {
        let proofs = Attestations::new(proofs).map_err(|_| DeclassificationError::InvalidGrant)?;
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

fn corpus_request(
    corpus: &serde_json::Value,
    grant: &SignedRecoveryGrant,
    source_label: InformationLabel,
    now_unix_ms: u64,
    authority: chio_core_types::PublicKey,
) -> Result<DeclassificationVerificationRequest> {
    let claims = &grant.body().claims;
    Ok(DeclassificationVerificationRequest {
        capability_id: claims.capability_id().clone(),
        tenant_id: claims.tenant_id().clone(),
        subject_id: claims.subject_id().clone(),
        agent_id: claims.agent_id().clone(),
        session_id: claims.session_id().clone(),
        source_label,
        destination_id: claims.destination_id().clone(),
        tool_name: claims.tool_name().clone(),
        purpose: claims.purpose().clone(),
        policy_purposes: [claims.purpose().clone()].into_iter().collect(),
        manifest_purposes: [claims.purpose().clone()].into_iter().collect(),
        canonical_request: CanonicalBody::new(canonical_json_bytes(
            &corpus["request"]["arguments"],
        )?)?,
        now_unix_ms,
        trusted_authorities: BTreeMap::from([(claims.authority_key_id().clone(), authority)]),
    })
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
fn approval_bundles_are_bounded_at_sixteen_attestations() -> Result {
    let mut f = Fixture::owners(16)?;
    f.attest_all(16, |index| vec![index])?;
    let coverage = f.verify(f.proofs.clone(), 150_000)?;
    assert_eq!(coverage.obligations().len(), 16);

    let mut wide = Fixture::owners(17)?;
    wide.attest_all(17, |index| vec![index])?;
    assert_eq!(wide.proofs.len(), 17);
    assert_eq!(
        Attestations::new(wide.proofs.clone()).err(),
        Some(ContractError::LimitExceeded)
    );
    let decoded = serde_json::from_value::<Attestations>(serde_json::to_value(&wide.proofs)?)
        .err()
        .map(|error| error.to_string());
    assert!(
        decoded
            .is_some_and(|message| message.starts_with(&ContractError::LimitExceeded.to_string())),
        "a 17-entry wire bundle must refuse at the type bound"
    );
    Ok(())
}

#[test]
fn verification_work_is_charged_before_key_and_signature_checks() -> Result {
    let mut spread = Fixture::owners(64)?;
    spread.attest_all(16, |index| (index * 4..index * 4 + 4).collect())?;
    let coverage = spread.verify(spread.proofs.clone(), 150_000)?;
    assert_eq!(
        coverage.obligations().len(),
        MAX_RECOVERY_OBLIGATIONS,
        "16 attestations within the work bound cover all 64 obligations"
    );

    let mut heavy = Fixture::owners(64)?;
    heavy.attest_all(16, |_| (0..64).collect())?;
    assert_eq!(
        heavy.verify(heavy.proofs.clone(), 150_000).err(),
        Some(DeclassificationError::InvalidGrant),
        "the fifteenth full attestation exceeds MAX_RECOVERY_VERIFICATION_WORK"
    );
    let foreign = Keypair::from_seed(&[250; 32]);
    let resign = |index: usize| -> Result<Vec<Signed>> {
        let mut proofs = heavy.proofs.clone();
        let slot = proofs.get_mut(index).ok_or("proof index")?;
        *slot = Signed::sign(slot.body().clone(), &foreign)?;
        Ok(proofs)
    };
    assert_eq!(
        heavy.verify(resign(0)?, 150_000).err(),
        Some(DeclassificationError::UntrustedAuthority),
        "a foreign key inside the budget refuses as untrusted"
    );
    assert_eq!(
        heavy.verify(resign(14)?, 150_000).err(),
        Some(DeclassificationError::InvalidGrant),
        "work is charged before the key and signature of the attestation that exceeds it"
    );
    Ok(())
}

#[test]
fn swapped_attestation_signature_refuses_after_every_binding_matches() -> Result {
    let f = Fixture::new()?;
    let mut tampered = serde_json::to_value(&f.proofs[0])?;
    tampered["signature"] = serde_json::to_value(f.proofs[1].signature())?;
    let mut proofs = f.proofs.clone();
    proofs[0] = serde_json::from_value(tampered)?;
    assert_eq!(
        f.verify(proofs, 150_000).err(),
        Some(DeclassificationError::InvalidSignature)
    );
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
fn requirements_cannot_declare_endorsement_or_acceptance_as_disclosure() -> Result {
    for extra in [
        AuthorityObligationV1::IntegrityEndorsement {
            principal: PrincipalId::new("alice")?,
        },
        AuthorityObligationV1::UserAcceptance {
            principal: PrincipalId::new("alice")?,
        },
    ] {
        let mut f = Fixture::new()?;
        let mut declared = f.requirements.obligations.as_slice().to_vec();
        declared.push(extra);
        f.requirements.obligations = NonEmptyBoundedList::new(declared)?;
        f.approval.obligations = f.requirements.obligations.clone();
        f.approval.authorization_requirements = requirements_digest(&f.requirements)?;
        assert_eq!(
            f.verify(f.proofs.clone(), 150_000).err(),
            Some(DeclassificationError::BindingMismatch)
        );
    }
    Ok(())
}

#[test]
fn recovery_all_resigned_grant_binding_fields_refuse_foreign_contexts() -> Result {
    let fixture = corpus()?;
    let grant: SignedRecoveryGrant = serde_json::from_value(fixture["grant"].clone())?;
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
    let now = approval
        .issued_at_unix_ms
        .get()
        .checked_add(1)
        .ok_or("approval fixture timestamp overflow")?;
    let coverage = verify_recovery_coverage(
        &approval,
        &requirements,
        action.basis,
        &NonEmptyBoundedList::new(vec![proof])?,
        &assignments,
        now,
    )?;
    let claims = &grant.body().claims;
    let request = corpus_request(
        &fixture,
        &grant,
        requirements.source_label.clone(),
        now,
        grant.authority_key().clone(),
    )?;
    let expected = grant.body().recovery.clone();
    let mut premature = request.clone();
    premature.now_unix_ms = claims
        .issued_at_unix_seconds()
        .checked_mul(1000)
        .and_then(|issued| issued.checked_add(1))
        .ok_or("grant fixture timestamp overflow")?;
    assert_eq!(
        verify_recovery_declassification(&grant, &premature, &expected, &coverage).err(),
        Some(DeclassificationError::NotYetValid),
        "whole-second grant claims do not move signed millisecond coverage earlier"
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
        let changed = SignedRecoveryGrant::sign(serde_json::from_value(body)?, &key)?;
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
    let mut expired = request.clone();
    expired.now_unix_ms = claims
        .expires_at_unix_seconds()
        .checked_mul(1000)
        .ok_or("grant fixture timestamp overflow")?;
    assert_eq!(
        verify_recovery_declassification(&grant, &expired, &expected, &coverage).err(),
        Some(DeclassificationError::Expired)
    );

    let mut unsigned = fixture["grant"].clone();
    unsigned["body"]["claims"]["grant_id"] = serde_json::json!("foreign-grant");
    let unsigned: SignedRecoveryGrant = serde_json::from_value(unsigned)?;
    assert_eq!(
        verify_recovery_declassification(&unsigned, &request, &expected, &coverage).err(),
        Some(DeclassificationError::InvalidSignature),
        "an unbound claim edit still fails the recovery grant signature"
    );
    let mut invalid = fixture["grant"].clone();
    invalid["body"]["claims"]["expires_at_unix_seconds"] =
        serde_json::json!(claims.issued_at_unix_seconds() + 61);
    let invalid: SignedRecoveryGrant = serde_json::from_value(invalid)?;
    assert_eq!(
        verify_recovery_declassification(&invalid, &request, &expected, &coverage).err(),
        Some(DeclassificationError::InvalidGrant),
        "a recovery grant validity window above 60 seconds refuses before any binding"
    );
    Ok(())
}

#[test]
fn matching_digest_or_signature_alone_cannot_substitute_for_verified_coverage() -> Result {
    let fixture = corpus()?;
    let grant: SignedRecoveryGrant = serde_json::from_value(fixture["grant"].clone())?;
    let requirements: AuthorizationRequirementsV1 =
        serde_json::from_value(fixture["requirements"].clone())?;
    let approval: ApprovalIntentV1 = serde_json::from_value(fixture["approval_intent"].clone())?;
    let now = approval
        .issued_at_unix_ms
        .get()
        .checked_add(1)
        .ok_or("approval fixture timestamp overflow")?;
    let request = corpus_request(
        &fixture,
        &grant,
        requirements.source_label,
        now,
        grant.authority_key().clone(),
    )?;
    let foreign = Fixture::new()?;
    let foreign = foreign.verify(foreign.proofs.clone(), 150_000)?;
    let expected = grant.body().recovery.clone();
    assert_eq!(
        verify_recovery_declassification(&grant, &request, &expected, &foreign).err(),
        Some(DeclassificationError::BindingMismatch),
        "a valid signed grant cannot borrow coverage for another review"
    );
    let mut claimed = expected.clone();
    claimed.coverage_digest = foreign.digest();
    assert_eq!(
        verify_recovery_declassification(&grant, &request, &claimed, &foreign).err(),
        Some(DeclassificationError::BindingMismatch),
        "an expected binding naming the foreign digest does not match the signed grant"
    );
    Ok(())
}

#[test]
fn recovery_grants_cannot_widen_or_substitute_independently_verified_coverage() -> Result {
    let mut f = Fixture::new()?;
    let target: InformationLabel = serde_json::from_value(serde_json::json!({
        "kind":"known", "owners":{"bob":["bob"]}, "compartments":["restricted"]
    }))?;
    f.requirements.admitted_target = target.clone();
    f.requirements.obligations =
        required_recovery_disclosure_obligations(&f.requirements.source_label, &target)?;
    f.approval.obligations = f.requirements.obligations.clone();
    f.approval.authorization_requirements = requirements_digest(&f.requirements)?;
    let mut proof = f.proofs[0].body().clone();
    proof.authorization_requirements = f.approval.authorization_requirements;
    proof.obligations = f.requirements.obligations.clone();
    f.proofs = vec![Signed::sign(proof, &f.keys[0])?];
    let coverage = f.verify(f.proofs.clone(), 150_000)?;

    let fixture = corpus()?;
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
    let grant = SignedRecoveryGrant::sign(serde_json::from_value(body.clone())?, &key)?;
    let request = corpus_request(
        &fixture,
        &grant,
        f.requirements.source_label.clone(),
        150_000,
        key.public_key(),
    )?;
    assert_eq!(
        verify_recovery_declassification(&grant, &request, &grant.body().recovery, &coverage).err(),
        None,
        "positive narrowed coverage control"
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
        let changed = SignedRecoveryGrant::sign(serde_json::from_value(changed)?, &key)?;
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
    let mut later = body;
    later["claims"]["issued_at_unix_seconds"] = serde_json::json!(180);
    later["claims"]["expires_at_unix_seconds"] = serde_json::json!(240);
    let later = SignedRecoveryGrant::sign(serde_json::from_value(later)?, &key)?;
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
        "verified coverage keeps its own validity window under a later trusted grant"
    );
    Ok(())
}
