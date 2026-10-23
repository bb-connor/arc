//! Exact conjunctive recovery coverage under operator-installed assignments.
//!
//! Trust boundary: the approval intent, authorization requirements, reviewed
//! action, source basis, assignments and verification time are expected
//! inputs. The host selects them from its own authenticated workflow and
//! operator state. They are never taken from an incoming grant, attestation or
//! retained digest.
//!
//! Authority follows the installed assignments. Each attestation is admitted
//! only through the assignment of its issuer, which names one principal, one
//! key and the obligations that principal may release. Principals and issuers
//! are unique within a bundle. An operator may install one key in several
//! assignments, but reusing that key never creates an assignment the operator
//! did not install, so a repeated signature cannot add an approver.
//!
//! Verification work is charged per attestation before its key, principal and
//! signature checks and before obligation allocation: 32 units, plus 3 per
//! attested obligation, plus the size of the assigned obligation set. The
//! cumulative charge must not exceed `MAX_RECOVERY_VERIFICATION_WORK`.
//!
//! The coverage digest is the `AuthorityCoverage` domain digest of the
//! canonical signed attestations ordered by principal, then issuer. Principals
//! are unique, so the digest is independent of presentation order.
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::recovery::{
    RecoveryDigestDomain, RecoveryGrantBody, SignedAuthorityCoverageAttestationV1,
};
use chio_core_types::PublicKey;
use chio_security_types::flow::{InformationLabel, PrincipalId};
use chio_security_types::ports::Digest32;
use chio_security_types::recovery::{
    ActionIntentV1, ApprovalIntentV1, AuthorityObligationV1, AuthorityScopeDigest,
    AuthorizationRequirementsV1, BasisDigest, CoverageDigest, IssuerId, NonEmptyBoundedList,
    MAX_RECOVERY_APPROVAL_ATTESTATIONS, MAX_RECOVERY_OBLIGATIONS, MAX_RECOVERY_VERIFICATION_WORK,
    MAX_RECOVERY_WIRE_BYTES,
};

use crate::DeclassificationError;

const ATTESTATION_WORK: u64 = 32;
const ATTESTED_OBLIGATION_WORK: u64 = 3;

/// One operator-installed issuer assignment. The host selects it from its own
/// authority configuration, never from incoming data. A key is not authority
/// by itself: it covers only the listed obligations for the named principal.
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

/// Verified conjunctive coverage of one reviewed recovery action. It is
/// evidence that may be borrowed for grant checks within its validity window.
/// It is not an execution owner or a consumed grant: one-shot use comes from
/// the declassification use store, and single issuance per challenge belongs
/// to the native issuer.
///
/// Only [`verify_recovery_coverage`] constructs it. A retained digest cannot
/// become verified coverage:
/// ```compile_fail
/// use chio_flow::VerifiedRecoveryCoverage;
/// use chio_security_types::recovery::CoverageDigest;
/// fn fresh_authority(retained: CoverageDigest) -> VerifiedRecoveryCoverage {
///     retained.into()
/// }
/// ```
///
/// Wire data cannot decode into verified coverage:
/// ```compile_fail
/// use chio_flow::VerifiedRecoveryCoverage;
/// fn decode(bytes: &[u8]) -> Option<VerifiedRecoveryCoverage> {
///     serde_json::from_slice::<VerifiedRecoveryCoverage>(bytes).ok()
/// }
/// ```
///
/// Its fields are private to this crate, even when every field is supplied:
/// ```compile_fail,E0451
/// use chio_flow::VerifiedRecoveryCoverage;
/// use chio_security_types::recovery::CoverageDigest;
/// use std::collections::BTreeSet;
/// fn forge(digest: CoverageDigest) -> VerifiedRecoveryCoverage {
///     VerifiedRecoveryCoverage {
///         digest,
///         obligations: BTreeSet::new(),
///         binding: loop {},
///     }
/// }
/// ```
///
/// Reading the digest of verified coverage is the public interface:
/// ```
/// use chio_flow::VerifiedRecoveryCoverage;
/// use chio_security_types::recovery::CoverageDigest;
/// fn digest(coverage: &VerifiedRecoveryCoverage) -> CoverageDigest {
///     coverage.digest()
/// }
/// ```
pub struct VerifiedRecoveryCoverage {
    digest: CoverageDigest,
    obligations: BTreeSet<AuthorityObligationV1>,
    binding: VerifiedCoverageBinding,
}

/// The reviewed context bound by coverage. A presented grant must match it
/// and cannot supply any of these values.
struct VerifiedCoverageBinding {
    approval: ApprovalIntentV1,
    action: ActionIntentV1,
    source_label_hash: Digest32,
    target_label: InformationLabel,
    authority_scope: AuthorityScopeDigest,
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

    /// The grant must fall inside the coverage validity window and repeat the
    /// reviewed scope, action, requirements, approval, challenge, offer, plan,
    /// issuer scope, recipient, purpose and labels. Its workflow, step,
    /// continuation, request, policy, contract, isolation lineage, output
    /// disposition and capability must be those of the authenticated action.
    /// Its expiry cannot exceed the coverage expiry. The isolation epoch is
    /// bound only by the caller's expected binding.
    pub(crate) fn verify_grant_binding(
        &self,
        grant: &RecoveryGrantBody,
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
        let action = &bound.action;
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
            || actual.workflow_id != action.workflow_id
            || actual.step_id != action.step_id
            || actual.continuation_id != action.continuation_id
            || actual.request_namespace != action.request_namespace
            || actual.request_id != action.request_id
            || actual.policy_digest != action.policy_digest
            || actual.contract_digest != action.contract_digest
            || actual.isolation_lineage != action.isolation_lineage
            || actual.output_disposition != action.output_disposition
            || claims.capability_id() != &action.capability_id
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

/// Derive every confidentiality restriction removed by one exact downgrade.
/// Labels carry owners and compartments only, so the result contains owner
/// and compartment releases. Integrity endorsement and user acceptance are
/// distinct obligations and never disclosure authority. A downgrade that
/// would require more than `MAX_RECOVERY_OBLIGATIONS` releases refuses with
/// `InvalidTarget`.
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

/// Verify one approval bundle at the current trusted time. The approval must
/// name the `ActionIntent` digest of the exact reviewed action, and that
/// action must embed these requirements, the approval scope, this source
/// basis and the requirements issuer scope. Every attestation binds the same
/// review, action, requirements and source basis. Each issuer must match an
/// operator assignment for its principal, key and obligations, and the union
/// of attested obligations must equal the derived disclosure obligations
/// exactly.
pub fn verify_recovery_coverage(
    approval: &ApprovalIntentV1,
    requirements: &AuthorizationRequirementsV1,
    action: &ActionIntentV1,
    basis: BasisDigest,
    attestations: &NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_APPROVAL_ATTESTATIONS,
    >,
    assignments: &BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    now_unix_ms: u64,
) -> Result<VerifiedRecoveryCoverage, DeclassificationError> {
    verify_coverage(
        approval,
        requirements,
        action,
        basis,
        attestations,
        assignments,
        now_unix_ms,
    )
}

/// Verify a retained bundle of the same current format at its preparation
/// time. The caller authenticates that time, the retained action and the
/// retained assignments independently. Every action, cryptographic,
/// assignment, scope and work check still runs. The result is the coverage
/// digest only, never verified coverage or live authority.
pub fn verify_retained_recovery_coverage_digest(
    approval: &ApprovalIntentV1,
    requirements: &AuthorizationRequirementsV1,
    action: &ActionIntentV1,
    basis: BasisDigest,
    attestations: &NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_APPROVAL_ATTESTATIONS,
    >,
    assignments: &BTreeMap<IssuerId, RecoveryAuthorityAssignment>,
    prepared_at_unix_ms: u64,
) -> Result<CoverageDigest, DeclassificationError> {
    verify_coverage(
        approval,
        requirements,
        action,
        basis,
        attestations,
        assignments,
        prepared_at_unix_ms,
    )
    .map(|coverage| coverage.digest())
}

/// Charge one attestation before its signature or obligation allocation.
fn charge_attestation(
    work: u64,
    attested_obligations: usize,
    assigned_obligations: usize,
) -> Result<u64, DeclassificationError> {
    let attested =
        u64::try_from(attested_obligations).map_err(|_| DeclassificationError::InvalidGrant)?;
    let assigned =
        u64::try_from(assigned_obligations).map_err(|_| DeclassificationError::InvalidGrant)?;
    let charged = attested
        .checked_mul(ATTESTED_OBLIGATION_WORK)
        .and_then(|cost| cost.checked_add(ATTESTATION_WORK))
        .and_then(|cost| cost.checked_add(assigned))
        .and_then(|cost| work.checked_add(cost))
        .ok_or(DeclassificationError::InvalidGrant)?;
    if charged > u64::from(MAX_RECOVERY_VERIFICATION_WORK) {
        return Err(DeclassificationError::InvalidGrant);
    }
    Ok(charged)
}

fn verify_coverage(
    approval: &ApprovalIntentV1,
    requirements: &AuthorizationRequirementsV1,
    action: &ActionIntentV1,
    basis: BasisDigest,
    attestations: &NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_APPROVAL_ATTESTATIONS,
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
    if canonical_requirements.as_bytes().len() > MAX_RECOVERY_WIRE_BYTES {
        return Err(DeclassificationError::InvalidGrant);
    }
    if approval.authorization_requirements.as_bytes()
        != RecoveryDigestDomain::AuthorizationRequirements
            .digest(&canonical_requirements)
            .as_bytes()
    {
        return Err(DeclassificationError::BindingMismatch);
    }
    let canonical_action =
        CanonicalBytes::new(action).map_err(|_| DeclassificationError::InvalidGrant)?;
    if canonical_action.as_bytes().len() > MAX_RECOVERY_WIRE_BYTES {
        return Err(DeclassificationError::InvalidGrant);
    }
    if approval.action_intent.as_bytes()
        != RecoveryDigestDomain::ActionIntent
            .digest(&canonical_action)
            .as_bytes()
        || action.authorization_requirements != *requirements
        || action.scope != approval.scope
        || action.basis != basis
        || action.authority_scope != requirements.issuer_scope
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
    let mut work = 0_u64;
    for attestation in attestations.as_slice() {
        let body = attestation.body();
        let assignment = assignments
            .get(&body.issuer_id)
            .ok_or(DeclassificationError::UntrustedAuthority)?;
        work = charge_attestation(
            work,
            body.obligations.as_slice().len(),
            assignment.obligations.len(),
        )?;
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
            .verify_integrity_embedded_key()
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
            action: action.clone(),
            source_label_hash: crate::information_label_hash(&requirements.source_label)?,
            target_label: requirements.admitted_target.clone(),
            authority_scope: requirements.issuer_scope,
            valid_from_unix_ms,
            expires_at_unix_ms,
        },
    })
}
