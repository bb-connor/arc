//! Captured unknown status has independent provenance and no output authority.
use super::super::projection::native_status::AuthenticatedNativeStatusSource;
use super::*;
use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use chio_security_types::{knowledge::ArtifactInfluenceV1, ports::FlowStateKey, InformationLabel};

/// Authenticated retained status data for the host/store trusted computing
/// base. It cannot be decoded, cloned or converted into an output-received or
/// effect-settlement permit.
pub struct SemanticStatusOriginData {
    label: InformationLabel,
    influence: ArtifactInfluenceV1,
}

impl SemanticStatusOriginData {
    pub fn source_label(&self) -> &InformationLabel {
        &self.label
    }

    pub fn influence(&self) -> &ArtifactInfluenceV1 {
        &self.influence
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum NativeStatusOriginKind {
    CapturedUnknownIncident,
}

#[derive(Serialize)]
struct NativeStatusOriginV1<'a> {
    domain_version: VersionV1,
    kind: NativeStatusOriginKind,
    operation: &'a OperationId,
    native_authority: &'a NativeSecurityAuthorityBindingV1,
    source: &'a FlowStateKey,
    native_dispatch_ledger: &'a AdmissionDigest,
    terminal_version: SafeInteger,
    incident_id: &'a AdmissionIdentifier,
    projection_digest: &'a AdmissionDigest,
    global_commit_sequence: SafeInteger,
    capture_global_commit_sequence: SafeInteger,
    terminal_committed_at_unix_ms: SafeInteger,
    action: SemanticActionDigest,
    inputs: &'a NonEmptyBoundedList<SemanticInputVersionV1, 16>,
    source_label: &'a InformationLabel,
    externally_influenced: bool,
    unknown: bool,
}

pub(in crate::admission_operation_store) fn authenticated_native_status_influence(
    source: &AuthenticatedNativeStatusSource<'_, '_>,
) -> Result<Option<SemanticStatusOriginData>, AdmissionOperationStoreError> {
    let tx = source.transaction();
    source.verify(tx)?;
    let operation = source.operation();
    if operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch {
        return Err(refused("semantic status requires an unknown physical fate"));
    }
    let Some(origin) = output::authenticated_captured_origin(
        tx,
        operation,
        source.original(),
        source.native_binding(),
    )?
    else {
        return Ok(None);
    };
    let captured = origin.record();
    if source.key() != &recovery_flow_key(&captured.security_context) {
        return Err(refused("semantic status source scope changed"));
    }
    let classification = output::classify_captured_origin(&origin)?;
    let ledger = operation
        .native_dispatch_ledger_digest()
        .ok_or_else(|| refused("semantic status native dispatch ledger absent"))?;
    // Physical uncertainty is not permission to invent returned content. A
    // complete signed restriction floor can remain finite while its status
    // observation records unknown influence. Incomplete classification is Top.
    let body = NativeStatusOriginV1 {
        domain_version: VersionV1,
        kind: NativeStatusOriginKind::CapturedUnknownIncident,
        operation: &captured.operation_id,
        native_authority: source.native_binding(),
        source: source.key(),
        native_dispatch_ledger: ledger,
        terminal_version: SafeInteger::new(source.terminal_version()).map_err(refused)?,
        incident_id: source.incident_id(),
        projection_digest: source.projection_digest(),
        global_commit_sequence: SafeInteger::new(source.global_commit_sequence())
            .map_err(refused)?,
        capture_global_commit_sequence: SafeInteger::new(source.capture_global_commit_sequence())
            .map_err(refused)?,
        terminal_committed_at_unix_ms: SafeInteger::new(source.terminal_committed_at_unix_ms())
            .map_err(refused)?,
        action: semantic_action_digest(&captured.invocation.action).map_err(refused)?,
        inputs: &captured.invocation.action.inputs,
        source_label: &classification.label,
        externally_influenced: classification.externally_influenced,
        unknown: true,
    };
    let canonical = chio_core::CanonicalBytes::new(&body).map_err(refused)?;
    let influence = ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            *RecoveryDigestDomain::SemanticNativeStatusOrigin
                .digest(&canonical)
                .as_bytes(),
        ),
        externally_influenced: classification.externally_influenced,
        unknown: true,
    };
    Ok(Some(SemanticStatusOriginData {
        label: classification.label,
        influence,
    }))
}

impl SqliteAdmissionOperationStore {
    /// Read retained native Unknown and Incident provenance for the fenced
    /// host/store trusted computing base. This data API exposes no recovery
    /// HTTP, model or user channel and grants no live recipient disclosure,
    /// finishing, output-received, output-absence or effect-settlement authority.
    pub fn load_native_status_origin(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<SemanticStatusOriginData>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let origin = self
            .serving_owner
            .prepare_native_source_transaction(&tx)
            .map_err(map_owner_error)?;
        let classification = {
            let source = super::super::projection::native_status::authenticate_historical_native_status_source(
                &tx, self, &origin, operation_id, now,
            )?;
            authenticated_native_status_influence(&source)?
        };
        tx.commit().map_err(sqlite_error)?;
        Ok(classification)
    }
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Fixture adapter returns data only and cannot spend a fresh append.
    pub fn load_native_status_origin_for_test(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<(InformationLabel, ArtifactInfluenceV1)>, AdmissionOperationStoreError> {
        self.load_native_status_origin(operation_id, fence, now)
            .map(|evidence| evidence.map(|evidence| (evidence.label, evidence.influence)))
    }
}
