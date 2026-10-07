//! Exact conjunctive coverage under operator-installed assignments.
use crate::DeclassificationError;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::recovery::{
    RecoveryDigestDomain, RecoveryGrantBodyV2, SignedAuthorityCoverageAttestationV1,
};
use chio_core_types::PublicKey;
use chio_security_types::flow::{InformationLabel, PrincipalId};
use chio_security_types::ports::Digest32;
use chio_security_types::recovery::{
    ApprovalIntentV1, AuthorityObligationV1, AuthorizationRequirementsV1, BasisDigest,
    CoverageDigest, IssuerId, NonEmptyBoundedList, MAX_RECOVERY_OBLIGATIONS,
};

/// Trusted operator assignment, selected by the host rather than incoming data.
pub struct RecoveryAuthorityAssignment {
    pub principal: PrincipalId,
    pub key: PublicKey,
    pub obligations: BTreeSet<AuthorityObligationV1>,
}
impl core::fmt::Debug for RecoveryAuthorityAssignment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryAuthorityAssignment([redacted])")
    }
}

/// Verified evidence is not an execution owner or a consumed grant.
pub struct VerifiedRecoveryCoverage {
    digest: CoverageDigest,
    obligations: BTreeSet<AuthorityObligationV1>,
    binding: VerifiedCoverageBinding,
}

/// The independent proof preserves the exact reviewed context. These values
/// cannot be supplied by the subsequently presented aggregate grant.
struct VerifiedCoverageBinding {
    approval: ApprovalIntentV1,
    source_label_hash: Digest32,
    target_label: InformationLabel,
    authority_scope: chio_security_types::recovery::AuthorityScopeDigest,
    valid_from_unix_ms: u64,
    expires_at_unix_ms: u64,
}
impl core::fmt::Debug for VerifiedRecoveryCoverage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedRecoveryCoverage([redacted])")
    }
}
impl VerifiedRecoveryCoverage {
    pub const fn digest(&self) -> CoverageDigest {
        self.digest
    }
    pub fn obligations(&self) -> &BTreeSet<AuthorityObligationV1> {
        &self.obligations
    }

    pub(crate) fn verify_grant_binding(
        &self,
        grant: &RecoveryGrantBodyV2,
        now_unix_ms: u64,
    ) -> Result<(), DeclassificationError> {
        let bound = &self.binding;
        if now_unix_ms < bound.valid_from_unix_ms {
            return Err(DeclassificationError::NotYetValid);
        }
        if now_unix_ms >= bound.expires_at_unix_ms {
            return Err(DeclassificationError::Expired);
        }
        let actual = &grant.recovery;
        let approval = &bound.approval;
        let claims = &grant.claims;
        if actual.coverage_digest != self.digest
            || actual.authority_domain != approval.scope.authority_domain
            || actual.process_id != approval.scope.process_id
            || claims.tenant_id().as_str() != approval.scope.tenant_id.as_str()
            || actual.action_intent != approval.action_intent
            || actual.authorization_requirements != approval.authorization_requirements
            || actual.approval_intent != approval.approval_intent
            || actual.challenge != approval.challenge
            || actual.selected_offer != approval.offer
            || actual.approved_plan != approval.plan
            || actual.authority_scope != bound.authority_scope
            || claims.destination_id() != &approval.recipient
            || claims.purpose() != &approval.purpose
            || claims.source_label_hash() != bound.source_label_hash
            || claims.target_label() != &bound.target_label
            || claims
                .expires_at_unix_seconds()
                .checked_mul(1_000)
                .is_none_or(|expires| expires > bound.expires_at_unix_ms)
        {
            return Err(DeclassificationError::BindingMismatch);
        }
        Ok(())
    }
}

/// Derive every confidentiality restriction changed by one exact downgrade.
/// Integrity endorsement is deliberately not a disclosure obligation.
pub fn required_recovery_disclosure_obligations(
    source: &InformationLabel,
    target: &InformationLabel,
) -> Result<
    NonEmptyBoundedList<AuthorityObligationV1, MAX_RECOVERY_OBLIGATIONS>,
    DeclassificationError,
> {
    if source == target {
        return Err(DeclassificationError::NoOpTarget);
    }
    if !target.flows_to(source) {
        return Err(DeclassificationError::InvalidTarget);
    }
    let source_owners = source.owners().ok_or(DeclassificationError::TopSource)?;
    let target_owners = target
        .owners()
        .ok_or(DeclassificationError::InvalidTarget)?;
    let source_compartments = source
        .compartments()
        .ok_or(DeclassificationError::TopSource)?;
    let target_compartments = target
        .compartments()
        .ok_or(DeclassificationError::InvalidTarget)?;
    let mut required = BTreeSet::new();
    for (owner, readers) in source_owners {
        if target_owners.get(owner) != Some(readers) {
            required.insert(AuthorityObligationV1::OwnerRelease {
                owner: owner.clone(),
            });
        }
    }
    for compartment in source_compartments.difference(target_compartments) {
        required.insert(AuthorityObligationV1::CompartmentRelease {
            compartment: compartment.clone(),
        });
    }
    NonEmptyBoundedList::new(required.into_iter().collect())
        .map_err(|_| DeclassificationError::InvalidTarget)
}

/// All attestations bind the same review and action. Keys are not authority:
/// each must match a current operator assignment for its represented principal.
pub fn verify_recovery_coverage(
    approval: &ApprovalIntentV1,
    requirements: &AuthorizationRequirementsV1,
    basis: BasisDigest,
    attestations: &NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_OBLIGATIONS,
    >,
    assignments: &BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    now_unix_ms: u64,
) -> Result<VerifiedRecoveryCoverage, DeclassificationError> {
    // Retained capture records have a wider historical codec. Every newly
    // verified approval bundle still obeys the current protocol ceiling.
    if attestations.as_slice().len()
        > chio_security_types::recovery::MAX_RECOVERY_APPROVAL_ATTESTATIONS
    {
        return Err(DeclassificationError::InvalidGrant);
    }
    verify_coverage(
        approval,
        requirements,
        basis,
        attestations,
        assignments,
        now_unix_ms,
    )
}

/// Verify a retained bundle at its independently authenticated preparation
/// time. The historical codec retains 64 entries and the original bounded
/// cryptographic checks. The result is data, never fresh verified authority.
/// Native callers must first verify physical capture and retained profile roots.
///
/// ```compile_fail
/// use chio_flow::VerifiedRecoveryCoverage;
/// use chio_security_types::recovery::CoverageDigest;
/// fn fresh_authority(historical_digest: CoverageDigest) -> VerifiedRecoveryCoverage {
///     historical_digest.into()
/// }
/// ```
pub fn verify_historical_recovery_coverage_digest(
    approval: &ApprovalIntentV1,
    requirements: &AuthorizationRequirementsV1,
    basis: BasisDigest,
    attestations: &NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_OBLIGATIONS,
    >,
    assignments: &BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    prepared_at_unix_ms: u64,
) -> Result<CoverageDigest, DeclassificationError> {
    verify_coverage(
        approval,
        requirements,
        basis,
        attestations,
        assignments,
        prepared_at_unix_ms,
    )
    .map(|coverage| coverage.digest())
}

fn verify_coverage(
    approval: &ApprovalIntentV1,
    requirements: &AuthorizationRequirementsV1,
    basis: BasisDigest,
    attestations: &NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_OBLIGATIONS,
    >,
    assignments: &BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    now_unix_ms: u64,
) -> Result<VerifiedRecoveryCoverage, DeclassificationError> {
    if approval.scope != requirements.scope
        || approval.recipient != requirements.recipient
        || approval.purpose != requirements.purpose
        || approval.obligations != requirements.obligations
    {
        return Err(DeclassificationError::BindingMismatch);
    }
    let canonical_requirements =
        CanonicalBytes::new(requirements).map_err(|_| DeclassificationError::InvalidGrant)?;
    if canonical_requirements.as_bytes().len()
        > chio_security_types::recovery::MAX_RECOVERY_WIRE_BYTES
    {
        return Err(DeclassificationError::InvalidGrant);
    }
    if approval.authorization_requirements.as_bytes()
        != RecoveryDigestDomain::AuthorizationRequirements
            .digest(&canonical_requirements)
            .as_bytes()
    {
        return Err(DeclassificationError::BindingMismatch);
    }
    if now_unix_ms < approval.issued_at_unix_ms.get() {
        return Err(DeclassificationError::NotYetValid);
    }
    if now_unix_ms >= approval.expires_at_unix_ms.get()
        || now_unix_ms >= requirements.validity_ceiling_unix_ms.get()
    {
        return Err(DeclassificationError::Expired);
    }
    let required = required_recovery_disclosure_obligations(
        &requirements.source_label,
        &requirements.admitted_target,
    )?;
    let declared: BTreeSet<_> = requirements
        .obligations
        .as_slice()
        .iter()
        .cloned()
        .collect();
    let expected: BTreeSet<_> = required.as_slice().iter().cloned().collect();
    // native recovery supports disclosure only. Undeclared or endorsement powers refuse.
    if declared != expected || declared.len() != requirements.obligations.as_slice().len() {
        return Err(DeclassificationError::BindingMismatch);
    }
    let mut principals = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut ordered = Vec::new();
    let mut valid_from_unix_ms = approval.issued_at_unix_ms.get();
    let mut expires_at_unix_ms = approval
        .expires_at_unix_ms
        .get()
        .min(requirements.validity_ceiling_unix_ms.get());
    let mut work = 0_usize;
    for attestation in attestations.as_slice() {
        let body = attestation.body();
        let assignment = assignments
            .get(&body.issuer_id)
            .ok_or(DeclassificationError::UntrustedAuthority)?;
        // Charge before signature verification or per-obligation allocation.
        work = work
            .checked_add(32 + body.obligations.as_slice().len() * 3 + assignment.obligations.len())
            .ok_or(DeclassificationError::InvalidGrant)?;
        if work > chio_security_types::recovery::MAX_RECOVERY_VERIFICATION_WORK as usize {
            return Err(DeclassificationError::InvalidGrant);
        }
        if assignment.key != *attestation.authority_key() || assignment.principal != body.principal
        {
            return Err(DeclassificationError::UntrustedAuthority);
        }
        if !principals.insert(body.principal.clone()) || !issuers.insert(body.issuer_id.clone()) {
            return Err(DeclassificationError::BindingMismatch);
        }
        if body.scope != approval.scope
            || body.approval_intent != approval.approval_intent
            || body.challenge != approval.challenge
            || body.action_intent != approval.action_intent
            || body.authorization_requirements != approval.authorization_requirements
            || body.source_basis != basis
        {
            return Err(DeclassificationError::BindingMismatch);
        }
        if now_unix_ms < body.issued_at_unix_ms.get() {
            return Err(DeclassificationError::NotYetValid);
        }
        if now_unix_ms >= body.expires_at_unix_ms.get()
            || body.expires_at_unix_ms > approval.expires_at_unix_ms
        {
            return Err(DeclassificationError::Expired);
        }
        valid_from_unix_ms = valid_from_unix_ms.max(body.issued_at_unix_ms.get());
        expires_at_unix_ms = expires_at_unix_ms.min(body.expires_at_unix_ms.get());
        if !attestation
            .verify_signature()
            .map_err(|_| DeclassificationError::InvalidSignature)?
        {
            return Err(DeclassificationError::InvalidSignature);
        }
        let mut local = BTreeSet::new();
        for obligation in body.obligations.as_slice() {
            if !expected.contains(obligation)
                || !assignment.obligations.contains(obligation)
                || !local.insert(obligation.clone())
            {
                return Err(DeclassificationError::UntrustedAuthority);
            }
            covered.insert(obligation.clone());
        }
        ordered.push(attestation);
    }
    if covered != expected {
        return Err(DeclassificationError::UntrustedAuthority);
    }
    ordered.sort_by(|a, b| {
        a.body()
            .principal
            .cmp(&b.body().principal)
            .then(a.body().issuer_id.cmp(&b.body().issuer_id))
    });
    let canonical =
        CanonicalBytes::new(&ordered).map_err(|_| DeclassificationError::InvalidGrant)?;
    Ok(VerifiedRecoveryCoverage {
        digest: CoverageDigest::from_bytes(
            *RecoveryDigestDomain::AuthorityCoverage
                .digest(&canonical)
                .as_bytes(),
        ),
        obligations: covered,
        binding: VerifiedCoverageBinding {
            approval: approval.clone(),
            source_label_hash: crate::information_label_hash(&requirements.source_label)?,
            target_label: requirements.admitted_target.clone(),
            authority_scope: requirements.issuer_scope,
            valid_from_unix_ms,
            expires_at_unix_ms,
        },
    })
}
