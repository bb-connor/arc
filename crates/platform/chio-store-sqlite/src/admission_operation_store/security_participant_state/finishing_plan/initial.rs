//! Authenticate the original before nonce issuance or the first dispatch Input.
use super::*;
use chio_kernel::{SecurityInvocationContext, ToolCallRequest};
use chio_security_types::ports::FlowStateSnapshot;

/// Borrowed command material is descriptive. The private factory independently
/// reads the physical original, current lease and actual initialized source.
/// The live request is never serialized into the plan or any bank record.
pub(in crate::admission_operation_store) struct NativeInitialFinishingCustody<'call> {
    pub(in crate::admission_operation_store) operation: &'call AdmissionOperationV1,
    pub(in crate::admission_operation_store) lease: &'call AdmissionRecoveryLease,
    pub(in crate::admission_operation_store) binding:
        &'call chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
    pub(in crate::admission_operation_store) context: &'call SecurityInvocationContext,
    pub(in crate::admission_operation_store) request: &'call ToolCallRequest,
    pub(in crate::admission_operation_store) trusted_now_unix_ms: u64,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::admission_operation_store) enum NativeInitialFinishingPhase {
    BeforeNonce,
    BeforeInput,
}

/// Actual original-source custody at the first pre-effect financing cut.
/// Unlike the later CapturePending role, this does not require an Input that
/// has not yet been produced. Its authenticated absence is a phase fact, never
/// a zero bank balance, a clean influence observation or a capture permission.
pub(in crate::admission_operation_store) struct VerifiedNativeInitialFinishingPlan<
    'source,
    'database,
> {
    tx: &'source Transaction<'database>,
    owner: &'source SqliteServingOwner,
    origin: NativeSourceTransactionOrigin<'source>,
    custody: NativeInitialFinishingCustody<'source>,
    original: RetainedToolAdmissionRequestV1,
    initialized: SecurityParticipantStateInitialization,
    key: FlowStateKey,
    phase: NativeInitialFinishingPhase,
    before: Option<FlowStateSnapshot>,
    before_generation: Option<u64>,
    source_head: (u64, String),
    journal_usage: (u64, u64),
    native_catalog: String,
    physical_profile: ToolOutcomeWriteProfileData,
    global_envelope: NativeToolOutcomeGlobalEnvelopeData,
    envelope: NativeToolOutcomeEnvelopeData,
}

pub(in crate::admission_operation_store) fn prepare_native_initial_finishing_plan<
    'source,
    'database,
>(
    tx: &'source Transaction<'database>,
    owner: &'source SqliteServingOwner,
    origin: &NativeSourceTransactionOrigin<'source>,
    custody: NativeInitialFinishingCustody<'source>,
) -> Result<VerifiedNativeInitialFinishingPlan<'source, 'database>, AdmissionOperationStoreError> {
    // Fence the actual namespace and every source-dependent callback before
    // reading originals, current clocks, initialization or absence facts.
    let catalog = schema::native_flow_write_catalog(tx)?;
    let physical_profile =
        super::super::super::raw_custody_liability::tool_outcome_write_profile(tx)?;
    origin.verify(tx).map_err(map_owner_error)?;
    let source_head =
        crate::serving_owner::native_finishing_global_head(tx).map_err(map_owner_error)?;
    if !origin.matches_owner(owner)
        || custody.binding.store_uuid().as_str() != owner.fence.store_uuid
        || source_head.0 != origin.prepared_global_sequence()
    {
        return Err(invalid(
            "initial native financing changed its actual owner cut",
        ));
    }
    let now = observed_time(tx, custody.trusted_now_unix_ms)?;
    verify_participant_recovery_tx(tx, owner, custody.operation, custody.lease, now)?;
    ensure_no_reserved_terminal_stage(tx, custody.operation.binding().operation_id())?;
    let original = retained_request::load_retained_request_tx(tx, custody.operation)?
        .ok_or_else(|| invalid("initial native financing lost its physical original"))?;
    original.validate_binding(custody.operation.binding())?;
    original.validate_request_material(custody.request)?;
    original.validate_native_security_authority(custody.binding)?;
    original.validate_native_security_context(custody.context)?;
    original.validate_bounded_native_materializer()?;
    if original.authority_profile().is_none()
        || custody.operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || custody.operation.dispatch_commit().is_some()
        || custody.operation.budget_hold_id().is_some()
    {
        return Err(invalid(
            "initial native financing is past its pre-budget source",
        ));
    }
    let requirements = custody.operation.binding().participant_requirements();
    let phase = match custody.operation.state() {
        AdmissionOperationState::Prepared
            if requirements.execution_nonce
                && custody.request.execution_nonce.is_none()
                && custody
                    .operation
                    .execution_nonce_issuance_digest()
                    .is_none()
                && custody
                    .operation
                    .execution_nonce_preflight_digest()
                    .is_none() =>
        {
            NativeInitialFinishingPhase::BeforeNonce
        }
        AdmissionOperationState::BrokerAttemptRegistered if !requirements.execution_nonce => {
            NativeInitialFinishingPhase::BeforeInput
        }
        _ => {
            return Err(invalid(
                "native financing was requested after its first pending purpose",
            ))
        }
    };
    let initialized = records::load_current_metadata(tx, custody.binding)?;
    let context = custody.context.as_v1();
    let key = FlowStateKey {
        tenant_id: context.tenant_id().clone(),
        principal_id: context.principal_id().clone(),
        lineage_id: context.lineage_root_id().clone(),
        session_id: context.session_id().clone(),
        isolation_epoch_id: context.isolation_epoch_id().clone(),
    };
    // This owner verified complete retained coverage at its initial cut. Check
    // the whole journal family union once at account birth as well; a missing
    // dispatch Input alone cannot establish that no earlier preflight exists.
    super::super::verify_coverage(tx).map_err(map_owner_error)?;
    require_unproduced_original(tx, custody.operation)?;
    let (before, before_generation) =
        crate::security_state::observe_native_flow_state(tx, initialized.authority.as_str(), &key)
            .map_err(invalid)?;
    if before_generation != context.flow_state_generation() {
        return Err(invalid(
            "initial native financing has a stale original context",
        ));
    }
    let journal_usage = history::ordered::journal_totals(tx, initialized.authority.as_str())?;
    let profile = original
        .native_output_retention()
        .ok_or_else(|| invalid("initial native financing lacks the original output profile"))?;
    if profile.envelopes().evaluation()
        > u64::try_from(crate::tool_outcome_store::evaluation_record_maximum_bytes())
            .map_err(invalid)?
    {
        return Err(invalid(
            "initial native evaluation exceeds the real producer",
        ));
    }
    let envelope = NativeToolOutcomeEnvelopeData {
        raw: profile.envelopes().raw(),
        outcome_json: u64::try_from(crate::tool_outcome_store::outcome_record_maximum_bytes())
            .map_err(invalid)?,
        evaluation: profile.envelopes().evaluation(),
        resolved: profile.envelopes().resolved(),
        receipt: profile.envelopes().receipt(),
        selected_pure_steps: original.post_return_steps().len(),
    };
    let global_envelope =
        global_envelope::describe_original_tool_outcome_global(owner, custody.operation)?;
    let source = VerifiedNativeInitialFinishingPlan {
        tx,
        owner,
        origin: origin.fork_for_source(),
        custody,
        original,
        initialized,
        key,
        phase,
        before,
        before_generation,
        source_head,
        journal_usage,
        native_catalog: catalog.fingerprint().into(),
        physical_profile,
        global_envelope,
        envelope,
    };
    source.verify_before(tx, owner, origin)?;
    Ok(source)
}

fn require_unproduced_original(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let id = operation.binding().operation_id();
    if history::load_for_operation(tx, id)?.is_some()
        || super::super::nonce_preflight::load_operation(tx, id)?.is_some()
    {
        return Err(invalid(
            "initial native financing follows a retained Input or preflight",
        ));
    }
    // The anchored global union and actual operation state are authenticated
    // above. Exact per-operation immutable rows must also be absent; no generic
    // current admission or ACK miss can stand in for these closed families.
    let occupied: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.security_participant_egress_events WHERE operation_id=?1)
         OR EXISTS(SELECT 1 FROM main.security_participant_output_events WHERE operation_id=?1)
         OR EXISTS(SELECT 1 FROM main.admission_operation_native_dispatch_ledger WHERE operation_id=?1)
         OR EXISTS(SELECT 1 FROM main.tool_outcomes WHERE operation_id=?1)
         OR EXISTS(SELECT 1 FROM main.post_return_evaluations WHERE operation_id=?1)",
        [id.as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if occupied {
        return Err(invalid(
            "initial native financing follows egress, Output or dispatch custody",
        ));
    }
    Ok(())
}

impl VerifiedNativeInitialFinishingPlan<'_, '_> {
    pub(in crate::admission_operation_store) fn phase(&self) -> NativeInitialFinishingPhase {
        self.phase
    }
    pub(in crate::admission_operation_store) fn key(&self) -> &FlowStateKey {
        &self.key
    }
    pub(in crate::admission_operation_store) fn binding(
        &self,
    ) -> &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1 {
        self.custody.binding
    }
    pub(in crate::admission_operation_store) fn lease(&self) -> &AdmissionRecoveryLease {
        self.custody.lease
    }
    pub(in crate::admission_operation_store) fn initial_source_head(&self) -> &(u64, String) {
        &self.source_head
    }
    pub(in crate::admission_operation_store) fn native_journal_usage(&self) -> (u64, u64) {
        self.journal_usage
    }
    pub(in crate::admission_operation_store) fn initialized(
        &self,
    ) -> &SecurityParticipantStateInitialization {
        &self.initialized
    }
}

impl source_plan::sealed::Sealed for VerifiedNativeInitialFinishingPlan<'_, '_> {}

impl NativeToolOutcomeSourcePlan for VerifiedNativeInitialFinishingPlan<'_, '_> {
    fn verify_before(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        origin: &NativeSourceTransactionOrigin<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        schema::native_flow_write_catalog(tx)?;
        self.origin.verify(tx).map_err(map_owner_error)?;
        origin.verify(tx).map_err(map_owner_error)?;
        if !std::ptr::eq(&**self.tx, &**tx)
            || !std::ptr::eq(self.owner, owner)
            || !origin.matches_owner(owner)
            || origin.prepared_global_sequence() != self.origin.prepared_global_sequence()
            || crate::serving_owner::native_finishing_global_head(tx).map_err(map_owner_error)?
                != self.source_head
            || schema::native_flow_write_catalog(tx)?.fingerprint() != self.native_catalog
            || super::super::super::raw_custody_liability::tool_outcome_write_profile(tx)?
                .fingerprint()
                != self.physical_profile.fingerprint()
        {
            return Err(invalid(
                "initial native financing changed its exact physical cut",
            ));
        }
        let now = observed_time(tx, self.custody.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(tx, owner, self.custody.operation, self.custody.lease, now)?;
        ensure_no_reserved_terminal_stage(tx, self.custody.operation.binding().operation_id())?;
        let original = retained_request::load_retained_request_tx(tx, self.custody.operation)?
            .ok_or_else(|| invalid("initial native financing original disappeared"))?;
        original.validate_request_material(self.custody.request)?;
        let current = crate::security_state::observe_native_flow_state(
            tx,
            self.initialized.authority.as_str(),
            &self.key,
        )
        .map_err(invalid)?;
        if original.canonical_bytes() != self.original.canonical_bytes()
            || records::load_current_metadata(tx, self.custody.binding)? != self.initialized
            || current.0 != self.before
            || current.1 != self.before_generation
            || history::ordered::journal_totals(tx, self.initialized.authority.as_str())?
                != self.journal_usage
        {
            return Err(invalid(
                "initial native financing changed its retained sources",
            ));
        }
        require_unproduced_original(tx, self.custody.operation)
    }
    fn original(&self) -> &RetainedToolAdmissionRequestV1 {
        &self.original
    }
    fn operation(&self) -> &AdmissionOperationV1 {
        self.custody.operation
    }
    fn frozen_steps(&self) -> &[FrozenEvaluationStepV1] {
        self.original.post_return_steps()
    }
    fn tool_outcome_envelope(&self) -> &NativeToolOutcomeEnvelopeData {
        &self.envelope
    }
    fn physical_write_profile(&self) -> &ToolOutcomeWriteProfileData {
        &self.physical_profile
    }
    fn global_commit_envelope(&self) -> &NativeToolOutcomeGlobalEnvelopeData {
        &self.global_envelope
    }
}
