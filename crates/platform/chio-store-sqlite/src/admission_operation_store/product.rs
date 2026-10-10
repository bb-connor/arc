//! Product evidence participates in the existing native commit and rollback chain.
use super::recovery::storage as protected;
use super::*;
use chio_core::{recovery::RecoveryDigestDomain, PublicKey};
use chio_kernel::recovery::{AuthenticatedRecoveryActor, RecoveryDeploymentV1, RecoveryPermission};
use chio_security_types::{flow::PrincipalId, knowledge::*, recovery::*, InformationLabel};

pub(in crate::admission_operation_store) mod evidence_reclamation;
mod evidence_source;
use evidence_source::require_product_evidence_owners;
pub(in crate::admission_operation_store) use evidence_source::{
    product_evidence_source, verify_product_evidence_source,
};
mod lifecycle;
pub(in crate::admission_operation_store) mod reference_intake;
pub(super) use lifecycle::complete_policy_review;
#[cfg(test)]
mod projection_tests;
mod proposals;
mod reports;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDecisionReportV1 {
    pub id: EvidenceRef,
    pub digest: CommandDigest,
    pub report: DecisionReportV1,
    pub reporter: PrincipalId,
    pub reporter_subject: PublicKey,
    pub label: InformationLabel,
    pub influence: ArtifactInfluenceV1,
    pub submitted_at_unix_ms: SafeInteger,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPolicyMaintenanceProposalV1 {
    pub proposal: PolicyMaintenanceProposalV1,
    pub digest: CanonicalPayloadDigest,
    pub maintainer: PrincipalId,
    pub maintainer_subject: PublicKey,
    pub label: InformationLabel,
    pub influence: ArtifactInfluenceV1,
    pub submitted_at_unix_ms: SafeInteger,
}
macro_rules! protected_debug {
    ($($name:ident),+ $(,)?) => { $(impl core::fmt::Debug for $name {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(concat!(stringify!($name), "([redacted])"))
        }
    })+ };
}
protected_debug!(StoredDecisionReportV1, StoredPolicyMaintenanceProposalV1);

fn refused(_error: impl core::fmt::Display) -> AdmissionOperationStoreError {
    invariant("product authority refused")
}
fn load<T: serde::de::DeserializeOwned + Serialize>(
    tx: &Connection,
    key: &str,
) -> Result<Option<T>, AdmissionOperationStoreError> {
    let Some(row) = protected::raw_checked(tx, key)? else {
        return Ok(None);
    };
    protected::source_reference(tx, key)?;
    protected::decode(&row.payload).map(Some)
}
fn save<T: Serialize>(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    key: &str,
    value: &T,
) -> Result<(), AdmissionOperationStoreError> {
    protected::save(
        tx,
        owner,
        key,
        &protected::scope_key(scope)?,
        "command",
        &protected::encode(value)?,
        None,
    )
}
fn hash<T: Serialize>(
    domain: RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], AdmissionOperationStoreError> {
    chio_kernel::recovery::recovery_digest(domain, value).map_err(refused)
}
fn current_label(
    tx: &Transaction<'_>,
    profile: &RecoveryDeploymentV1,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    super::knowledge::source(tx, &profile.native_authority, &profile.security_context)
}
// Historical assignments remain retained data. A fresh publication needs an
// actual finite current audience before acquiring any product or artifact owner.
fn require_finite_intake_audience(
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
) -> Result<(), AdmissionOperationStoreError> {
    let assignment = profile.actors.as_slice().iter().find(|assignment| {
        assignment.principal == *actor.principal()
            && assignment.subject == actor.capability().subject
    });
    if profile.scope != *actor.scope()
        || assignment
            .is_none_or(|assignment| matches!(assignment.preview_clearance, InformationLabel::Top))
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(())
}
fn require_clearance(
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    label: &InformationLabel,
) -> Result<(), AdmissionOperationStoreError> {
    let assignment = profile
        .actors
        .as_slice()
        .iter()
        .find(|value| {
            value.principal == *actor.principal() && value.subject == actor.capability().subject
        })
        .ok_or(AdmissionOperationStoreError::RecoveryAuthorityDenied)?;
    if matches!(assignment.preview_clearance, InformationLabel::Top)
        || !label.flows_to(&assignment.preview_clearance)
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(())
}
fn require_reader(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reader: Option<&AuthenticatedRecoveryActor>,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let reader = reader.ok_or(AdmissionOperationStoreError::RecoveryAuthorityDenied)?;
    if reader.permission() != RecoveryPermission::KnowledgeRead
        || reader.scope() != actor.scope()
        || reader.principal() != actor.principal()
        || reader.capability().subject != actor.capability().subject
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    super::recovery::verify_actor(tx, reader, profile, now)
}
fn join_attachment(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    label: InformationLabel,
    reference: &ArtifactVersionRefV1,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    if reference.scope.tenant_id != scope.tenant_id
        || reference.scope.authority_domain != scope.authority_domain
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let artifact = super::knowledge::selected_product_artifact(tx, reference)?;
    label
        .join_restrictions(&artifact.metadata.label)
        .map_err(refused)
}
fn join_retained_attachment(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    label: InformationLabel,
    reference: &ArtifactVersionRefV1,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    if reference.scope.tenant_id != scope.tenant_id
        || reference.scope.authority_domain != scope.authority_domain
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let artifact = super::knowledge::retained_product_artifact(tx, reference)?;
    label
        .join_restrictions(&artifact.metadata.label)
        .map_err(refused)
}
fn reserve_quota(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    kind: lifecycle::ProductWorkKind,
) -> Result<(), AdmissionOperationStoreError> {
    // Process changes cannot reset an aggregate tenant/domain counter.
    let (key, domain) = lifecycle::quota_key(scope, kind)?;
    let count = load::<SafeInteger>(tx, &key)?.map_or(0, SafeInteger::get);
    if count >= kind.ceiling() {
        return Err(refused("retained product quota"));
    }
    protected::save(
        tx,
        owner,
        &key,
        &domain,
        "command",
        &protected::encode(&SafeInteger::new(count + 1).map_err(refused)?)?,
        None,
    )
}
pub(super) fn proposal_key(
    scope: &RecoveryScopeV1,
    id: &ReviewId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "product-proposal:{}:{}",
        protected::scope_key(scope)?,
        id.as_str()
    ))
}
pub(super) fn stored_proposal(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &ReviewId,
) -> Result<StoredPolicyMaintenanceProposalV1, AdmissionOperationStoreError> {
    let value: StoredPolicyMaintenanceProposalV1 =
        load(tx, &proposal_key(scope, id)?)?.ok_or_else(|| refused("missing proposal"))?;
    if value.proposal.scope != *scope
        || value.proposal.proposal_id != *id
        || value.digest
            != CanonicalPayloadDigest::from_bytes(hash(
                RecoveryDigestDomain::PolicyMaintenanceProposal,
                &value.proposal,
            )?)
    {
        return Err(refused("proposal identity"));
    }
    Ok(value)
}
fn optional_report(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &EvidenceRef,
) -> Result<Option<StoredDecisionReportV1>, AdmissionOperationStoreError> {
    let Some(value) = load::<StoredDecisionReportV1>(tx, &reports::key(scope, id)?)? else {
        return Ok(None);
    };
    if value.report.scope != *scope
        || value.id != *id
        || value.digest
            != CommandDigest::from_bytes(hash(RecoveryDigestDomain::DecisionReport, &value.report)?)
    {
        return Err(refused("report identity"));
    }
    Ok(Some(value))
}

pub(super) fn stored_report(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &EvidenceRef,
) -> Result<StoredDecisionReportV1, AdmissionOperationStoreError> {
    optional_report(tx, scope, id)?.ok_or_else(|| refused("missing retained report"))
}

fn selected_report(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &EvidenceRef,
) -> Result<StoredDecisionReportV1, AdmissionOperationStoreError> {
    optional_report(tx, scope, id)?.ok_or(AdmissionOperationStoreError::RecoveryAuthorityDenied)
}
