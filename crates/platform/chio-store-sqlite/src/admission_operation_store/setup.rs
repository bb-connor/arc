//! Protected readiness is native custody, never an incoming readiness claim.
use super::recovery::storage as protected;
use super::*;
use chio_core::recovery::{
    RecoveryDigestDomain, SignedRecoverySetupProbeV1, SignedRecoverySetupReportV1,
};
use chio_core::PublicKey;
use chio_kernel::{recovery::*, SecurityInvocationContext, ToolCallRequest};
use chio_security_types::recovery::*;

/// Trusted local setup host selections, not a decoded readiness claim.
pub struct NativeSetupCreationHost<'a> {
    pub receipt_key: &'a PublicKey,
    pub operator: &'a PublicKey,
    pub process: &'a dyn RecoveryProcessOriginPort,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    probe: RecoverySetupProbeV1,
    creation: CanonicalPayloadDigest,
    command: RecoveryCommandV1,
    // Historical selections are decoded through their exact canonical codec.
    // The exposed Resume identity remains bound without rewriting its preimage.
    command_bound: bool,
    operator: PublicKey,
    receipt_key: PublicKey,
    previous_fence: SourceDigest,
    evidence: Option<Evidence>,
    report: Option<SignedRecoverySetupReportV1>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    probe: SignedRecoverySetupProbeV1,
    operation: OperationId,
    benign_receipt: SourceDigest,
    denied_command: CommandDigest,
}
/// Trusted host preparation; signatures are produced outside native transactions.
#[derive(Clone)]
pub struct NativeSetupPreparationV1 {
    pub probe: RecoverySetupProbeV1,
    pub command: RecoveryCommandV1,
    pub previous_serving_fence: SourceDigest,
    pub signed_probe: Option<SignedRecoverySetupProbeV1>,
    pub report: Option<SignedRecoverySetupReportV1>,
}
/// Public setup categories are separate from physical store failures. A failed
/// preparation never authorizes dispatch or changes the original operation.
#[derive(Debug, thiserror::Error)]
pub enum NativeSetupPreparationError {
    #[error("the uncommitted setup probe has expired")]
    Expired,
    #[error("the uncommitted setup probe belongs to another serving writer")]
    WriterChanged,
    #[error("the uncommitted setup probe has a stale native source")]
    StaleSource,
    #[error(transparent)]
    Store(#[from] AdmissionOperationStoreError),
}
/// Exact signed observations from the real kernel self-test, not a readiness claim.
pub struct NativeSetupProbeEvidenceV1<'a> {
    pub probe: &'a SignedRecoverySetupProbeV1,
    pub benign: &'a ChioReceipt,
    pub denied_request: &'a ToolCallRequest,
    pub denied: &'a ChioReceipt,
}
impl core::fmt::Debug for NativeSetupProbeEvidenceV1<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeSetupProbeEvidenceV1([redacted])")
    }
}
impl core::fmt::Debug for NativeSetupPreparationV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeSetupPreparationV1([redacted])")
    }
}
fn refused(_: impl core::fmt::Display) -> AdmissionOperationStoreError {
    invariant("protected recovery setup refused")
}
fn original_custody_error(error: RecoveryCommandPortError) -> AdmissionOperationStoreError {
    match error {
        RecoveryCommandPortError::Store(error) => error,
        RecoveryCommandPortError::OriginRefused | RecoveryCommandPortError::Conflict => {
            refused("setup original custody refused")
        }
        RecoveryCommandPortError::Busy => {
            AdmissionOperationStoreError::Unavailable("recovery process journal is busy".into())
        }
    }
}
fn digest<T: Serialize>(
    domain: RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], AdmissionOperationStoreError> {
    recovery_digest(domain, value).map_err(refused)
}
fn fence_digest(fence: &StoreMutationFence) -> Result<SourceDigest, AdmissionOperationStoreError> {
    digest(RecoveryDigestDomain::ServingFence, fence).map(SourceDigest::from_bytes)
}
fn key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "protected-setup:v2:{}",
        protected::scope_key(scope)?
    ))
}
fn legacy_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "protected-setup:{}",
        sha256_hex(&protected::encode(&(
            &scope.authority_domain,
            &scope.tenant_id,
        ))?)
    ))
}
fn load(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<Option<Selection>, AdmissionOperationStoreError> {
    if let Some(row) = authenticated_record(tx, &key(scope)?)? {
        let value: Selection = protected::decode(&row.payload)?;
        require_selection_envelope(&row, &value)?;
        if value.probe.scope != *scope {
            return Err(refused("scoped setup selection changed"));
        }
        return Ok(Some(value));
    }
    let Some(row) = authenticated_record(tx, &legacy_key(scope)?)? else {
        return Ok(None);
    };
    let value = selection_codec::decode(&row.payload)?;
    require_selection_envelope(&row, &value)?;
    // The tenant-wide historical marker never chooses another process's
    // self-test. It still protects that tenant through tenant_required().
    Ok((value.probe.scope == *scope).then_some(value))
}
fn authenticated_record(
    tx: &Connection,
    key: &str,
) -> Result<Option<protected::RawRecord>, AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?;
    if row.is_some() {
        protected::source_reference(tx, key)?;
    }
    Ok(row)
}
fn require_selection_envelope(
    row: &protected::RawRecord,
    value: &Selection,
) -> Result<(), AdmissionOperationStoreError> {
    if row.kind != "command"
        || row.version == 0
        || row.scope != protected::scope_key(&value.probe.scope)?
    {
        return Err(refused("setup selection envelope changed"));
    }
    Ok(())
}
fn save(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    value: &Selection,
) -> Result<(), AdmissionOperationStoreError> {
    context::mark_tenant_required(tx, owner, &value.probe.scope)?;
    protected::save(
        tx,
        owner,
        &key(&value.probe.scope)?,
        &protected::scope_key(&value.probe.scope)?,
        "command",
        &protected::encode(value)?,
        None,
    )
}
fn creation(
    record: &RecoveryWorkflowRecordV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    let digest = match &record.origin {
        Some(origin) => digest(
            RecoveryDigestDomain::SetupCreation,
            &(&record.creation_seed, origin),
        ),
        // Retained legacy selections keep their historical commitment, but
        // the changed setup source profile cannot qualify fresh capture.
        None => digest(
            RecoveryDigestDomain::SetupCreationLegacy,
            &record.creation_seed,
        ),
    };
    digest.map(CanonicalPayloadDigest::from_bytes)
}
fn profile(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    receipt_key: &PublicKey,
) -> Result<(SourceDigest, DeploymentDigest, SourceDigest, PublicKey), AdmissionOperationStoreError>
{
    let recovery = protected::deployment_tx(tx, scope)?;
    let semantic = super::semantic::installation(tx, scope)?;
    let knowledge = super::knowledge::installation(tx, scope)?;
    if semantic.native_authority != recovery.native_authority
        || knowledge.native_authority != recovery.native_authority
        || semantic.security_context != recovery.security_context
        || knowledge.producer_context != recovery.security_context
    {
        return Err(refused("mediator closure"));
    }
    Ok((
        SourceDigest::from_bytes(digest(
            RecoveryDigestDomain::SetupNativeAuthority,
            &recovery.native_authority,
        )?),
        semantic.policy_basis()?.deployment,
        SourceDigest::from_bytes(digest(
            RecoveryDigestDomain::SetupSourceProfile,
            &(&recovery, &semantic, &knowledge, receipt_key),
        )?),
        recovery
            .setup_policy
            .as_ref()
            .map_or(semantic.operator_root, |policy| {
                policy.operator_root.clone()
            }),
    ))
}
fn current(tx: &Connection, value: &Selection) -> Result<(), AdmissionOperationStoreError> {
    let (authority, deployment, source, root) =
        profile(tx, &value.probe.scope, &value.receipt_key)?;
    if authority != value.probe.native_authority
        || deployment != value.probe.deployment
        || source != value.probe.source_profile
        || root != value.operator
        || required_coverage(tx, &value.probe.scope)? != value.probe.required_coverage
    {
        return Err(refused("changed setup profile"));
    }
    Ok(())
}
fn authorized(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    value: &Selection,
) -> Result<(), AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::Inspect || actor.scope() != &value.probe.scope {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let record = protected::workflow_tx(tx, actor.scope(), &value.probe.benign_workflow)?;
    super::recovery::verify_status(actor, profile, &record)?;
    current(tx, value)
}
fn completed(
    tx: &Transaction<'_>,
    value: &Selection,
    receipt: &ChioReceipt,
) -> Result<OperationId, AdmissionOperationStoreError> {
    let record = protected::workflow_tx(tx, &value.probe.scope, &value.probe.benign_workflow)?;
    let id = record
        .native_link
        .clone()
        .ok_or_else(|| refused("benign operation absent"))?;
    let operation =
        load_by_operation_id_tx(tx, &AdmissionOperationId::from_persisted(id.as_str())?)?
            .ok_or_else(|| refused("benign operation absent"))?;
    if creation(&record)? != value.creation
        || !record.captured
        || operation.operation.state() != AdmissionOperationState::Completed
    {
        return Err(refused("benign completion custody"));
    }
    if receipt.kernel_key != value.receipt_key
        || !receipt.is_allowed()
        || !matches!(operation.operation.terminal_replay(), Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) if receipt_id.as_str() == receipt.id)
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(id)
}
fn ready(
    tx: &Connection,
    value: &Selection,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    current(tx, value)?;
    let report = value
        .report
        .as_ref()
        .ok_or(AdmissionOperationStoreError::RecoveryMediationRequired)?;
    if report.body().probe != value.probe {
        return Err(refused("setup report probe binding changed"));
    }
    if report.body().current_serving_fence != fence_digest(fence)? {
        return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
    }
    Ok(())
}
mod context;
mod denied_counterpart;
mod gate;
mod incoming_proof;
mod inventory;
#[cfg(test)]
mod legacy_selection_tests;
mod original_scope;
mod retirement;
mod selection_codec;
mod service;
mod unused_generation;
pub(super) use context::register_native_setup_context;
pub(super) use gate::{require_capture, require_command, require_ready};
use inventory::required_coverage;
pub use retirement::{NativeSetupRetirementAuthorizationV1, NativeSetupRetirementBodyV1};
pub(super) use unused_generation::{UnusedSetupReplacementReason, VerifiedUnusedSetupGeneration};

fn preparation(value: &Selection) -> NativeSetupPreparationV1 {
    NativeSetupPreparationV1 {
        probe: value.probe.clone(),
        command: value.command.clone(),
        previous_serving_fence: value.previous_fence,
        signed_probe: value
            .evidence
            .as_ref()
            .map(|evidence| evidence.probe.clone()),
        report: value.report.clone(),
    }
}
