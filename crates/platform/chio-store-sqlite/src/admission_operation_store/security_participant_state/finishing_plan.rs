//! The physical original supplies a finishing footprint, never a bank loan.
use super::super::raw_custody_liability::ToolOutcomeWriteProfileData;
use super::*;
use crate::serving_owner::NativeSourceTransactionOrigin;
use chio_kernel::admission_operation::{
    AdmissionParticipantRequirements, NativeOutputRetentionProfileV1, NativeSecurityEgressContext,
    RetainedToolAdmissionRequestV1, MAX_ADMISSION_IDENTIFIER_BYTES,
};
use chio_kernel::tool_outcome::FrozenEvaluationStepV1;
use chio_security_types::ports::FlowStateKey;

mod global_envelope;
mod initial;
mod source_plan;
pub(in crate::admission_operation_store) use global_envelope::NativeToolOutcomeGlobalEnvelopeData;
pub(in crate::admission_operation_store) use initial::{
    prepare_native_initial_finishing_plan, NativeInitialFinishingCustody,
    NativeInitialFinishingPhase, VerifiedNativeInitialFinishingPlan,
};
pub(in crate::admission_operation_store) use source_plan::NativeToolOutcomeSourcePlan;

/// Source-bound envelope DATA. A scalar or decoded copy cannot construct the
/// original-source role, fund a purpose, or permit capture or authorization.
pub(in crate::admission_operation_store) struct NativeToolOutcomeEnvelopeData {
    raw: u64,
    outcome_json: u64,
    evaluation: u64,
    resolved: u64,
    receipt: u64,
    selected_pure_steps: usize,
}

impl NativeToolOutcomeEnvelopeData {
    pub(in crate::admission_operation_store) fn raw_bytes(&self) -> u64 {
        self.raw
    }
    pub(in crate::admission_operation_store) fn outcome_json_bytes(&self) -> u64 {
        self.outcome_json
    }
    pub(in crate::admission_operation_store) fn outcome_bytes(&self) -> u64 {
        self.outcome_json
    }
    pub(in crate::admission_operation_store) fn evaluation_bytes(&self) -> u64 {
        self.evaluation
    }
    pub(in crate::admission_operation_store) fn resolved_bytes(&self) -> u64 {
        self.resolved
    }
    pub(in crate::admission_operation_store) fn receipt_bytes(&self) -> u64 {
        self.receipt
    }
    pub(in crate::admission_operation_store) fn selected_pure_steps(&self) -> usize {
        self.selected_pure_steps
    }
    pub(in crate::admission_operation_store) fn claimant_maximum_bytes(&self) -> usize {
        MAX_ADMISSION_IDENTIFIER_BYTES
    }
    pub(in crate::admission_operation_store) fn final_evaluation_rewrites(
        &self,
    ) -> Result<u64, AdmissionOperationStoreError> {
        u64::try_from(self.selected_pure_steps)
            .map_err(invalid)?
            .checked_add(1)
            .ok_or_else(|| invalid("native evaluation rewrite count overflow"))
    }
}

/// This affine role authenticates the actual retained original plan and its
/// declared footprint inputs. It is not a complete liability quotation or a
/// prepaid purpose. No writer, capture gate, or rail can spend this role.
/// The full bank must separately verify the supported bounded producer and
/// every native, participant, receipt and second-database purpose.
pub(in crate::admission_operation_store) struct VerifiedNativeFinishingPlan<'source, 'database> {
    tx: &'source Transaction<'database>,
    owner: &'source SqliteServingOwner,
    origin: NativeSourceTransactionOrigin<'source>,
    custody: &'source NativeSecurityEgressContext<'source>,
    original: RetainedToolAdmissionRequestV1,
    initialized: SecurityParticipantStateInitialization,
    key: FlowStateKey,
    input_digest: String,
    source_head: (u64, String),
    native_catalog: String,
    physical_profile: ToolOutcomeWriteProfileData,
    global_envelope: NativeToolOutcomeGlobalEnvelopeData,
    envelope: NativeToolOutcomeEnvelopeData,
}

pub(in crate::admission_operation_store) fn prepare_native_finishing_plan<'source, 'database>(
    tx: &'source Transaction<'database>,
    owner: &'source SqliteServingOwner,
    origin: &NativeSourceTransactionOrigin<'source>,
    custody: &'source NativeSecurityEgressContext<'source>,
) -> Result<VerifiedNativeFinishingPlan<'source, 'database>, AdmissionOperationStoreError> {
    // These source-owned catalogs fence attached databases and TEMP shadows
    // before any original, lease, source, clock or program is inspected.
    let native_catalog = schema::native_flow_write_catalog(tx)?;
    let physical_profile = super::super::raw_custody_liability::tool_outcome_write_profile(tx)?;
    origin.verify(tx).map_err(map_owner_error)?;
    if !origin.matches_owner(owner)
        || custody.binding.store_uuid().as_str() != owner.fence.store_uuid
    {
        return Err(invalid("native finishing plan changed its actual owner"));
    }
    let source_head =
        crate::serving_owner::native_finishing_global_head(tx).map_err(map_owner_error)?;
    if source_head.0 != origin.prepared_global_sequence() {
        return Err(invalid(
            "native finishing plan was prepared after a mutation",
        ));
    }
    let operation = custody.operation;
    operation.validate()?;
    if operation.state() != AdmissionOperationState::CapturePending
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.dispatch_commit().is_some()
        || operation.budget_hold_id().is_none()
    {
        return Err(invalid(
            "native finishing plan is not fresh capture custody",
        ));
    }
    let now = observed_time(tx, custody.trusted_now_unix_ms)?;
    verify_participant_recovery_tx(tx, owner, operation, custody.lease, now)?;
    ensure_no_reserved_terminal_stage(tx, operation.binding().operation_id())?;
    let original = retained_request::load_retained_request_tx(tx, operation)?
        .ok_or_else(|| invalid("native finishing plan lost its actual original"))?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(custody.request)?;
    original.validate_native_security_authority(custody.binding)?;
    original.validate_native_security_context(custody.security_context)?;
    if original.authority_profile().is_none() {
        return Err(invalid(
            "native finishing plan has no original authority profile",
        ));
    }
    let profile = original
        .native_output_retention()
        .ok_or_else(|| invalid("native finishing plan has no original output profile"))?;
    // This exact shared producer identity is derived from the complete
    // ORIGINAL profile. Current Kernel configuration and caller metadata are
    // absent from this selection, and old unbounded plans cannot acquire it.
    original.validate_bounded_native_materializer()?;
    let steps = original.post_return_steps();
    if steps.is_empty() || steps.len() > usize::from(profile.envelopes().post_return_steps()) {
        return Err(invalid(
            "native finishing plan has an unsupported original schedule",
        ));
    }
    let evaluation_maximum =
        u64::try_from(crate::tool_outcome_store::evaluation_record_maximum_bytes())
            .map_err(invalid)?;
    if profile.envelopes().evaluation() > evaluation_maximum {
        return Err(invalid(
            "native evaluation profile exceeds its real producer",
        ));
    }
    let envelope = NativeToolOutcomeEnvelopeData {
        raw: profile.envelopes().raw(),
        outcome_json: u64::try_from(crate::tool_outcome_store::outcome_record_maximum_bytes())
            .map_err(invalid)?,
        evaluation: profile.envelopes().evaluation(),
        resolved: profile.envelopes().resolved(),
        receipt: profile.envelopes().receipt(),
        selected_pure_steps: steps.len(),
    };
    let global_envelope = global_envelope::describe_original_tool_outcome_global(owner, operation)?;
    let initialized = records::load_current_metadata(tx, custody.binding)?;
    let input = history::load_for_operation(tx, operation.binding().operation_id())?
        .ok_or_else(|| invalid("native finishing plan lost its actual Input"))?;
    let intent = input
        .input
        .as_ref()
        .ok_or_else(|| invalid("native finishing plan cannot upgrade a raw join"))?;
    if input.authority != initialized.authority
        || intent.operation_id() != operation.binding().operation_id()
    {
        return Err(invalid(
            "native finishing plan changed its actual Input owner",
        ));
    }
    original.validate_native_security_context(&input.context)?;
    intent.validate(operation.binding().operation_id())?;
    intent.validate_resolution(
        operation.binding().operation_id(),
        &input.request,
        &input.result,
    )?;
    let key = intent.key().clone();
    let plan = VerifiedNativeFinishingPlan {
        tx,
        owner,
        origin: origin.fork_for_source(),
        custody,
        original,
        initialized,
        key,
        input_digest: input.digest()?,
        source_head,
        native_catalog: native_catalog.fingerprint().into(),
        physical_profile,
        global_envelope,
        envelope,
    };
    plan.verify_before(tx, owner, origin)?;
    Ok(plan)
}

impl VerifiedNativeFinishingPlan<'_, '_> {
    pub(in crate::admission_operation_store) fn verify_before(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        origin: &NativeSourceTransactionOrigin<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.origin.verify(tx).map_err(map_owner_error)?;
        origin.verify(tx).map_err(map_owner_error)?;
        if !std::ptr::eq(&**self.tx, &**tx)
            || !std::ptr::eq(self.owner, owner)
            || !origin.matches_owner(owner)
            || origin.prepared_global_sequence() != self.origin.prepared_global_sequence()
            || crate::serving_owner::native_finishing_global_head(tx).map_err(map_owner_error)?
                != self.source_head
            || schema::native_flow_write_catalog(tx)?.fingerprint() != self.native_catalog
            || super::super::raw_custody_liability::tool_outcome_write_profile(tx)?.fingerprint()
                != self.physical_profile.fingerprint()
        {
            return Err(invalid(
                "native finishing plan changed its exact source cut",
            ));
        }
        let now = observed_time(tx, self.custody.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(tx, owner, self.custody.operation, self.custody.lease, now)?;
        let original = retained_request::load_retained_request_tx(tx, self.custody.operation)?
            .ok_or_else(|| invalid("native finishing original disappeared"))?;
        let input =
            history::load_for_operation(tx, self.custody.operation.binding().operation_id())?
                .ok_or_else(|| invalid("native finishing Input disappeared"))?;
        if original.canonical_bytes() != self.original.canonical_bytes()
            || input.digest()? != self.input_digest
            || records::load_current_metadata(tx, self.custody.binding)? != self.initialized
        {
            return Err(invalid("native finishing plan changed its retained source"));
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn original(&self) -> &RetainedToolAdmissionRequestV1 {
        &self.original
    }
    pub(in crate::admission_operation_store) fn operation(&self) -> &AdmissionOperationV1 {
        self.custody.operation
    }
    pub(in crate::admission_operation_store) fn lease(&self) -> &AdmissionRecoveryLease {
        self.custody.lease
    }
    pub(in crate::admission_operation_store) fn key(&self) -> &FlowStateKey {
        &self.key
    }
    pub(in crate::admission_operation_store) fn frozen_steps(&self) -> &[FrozenEvaluationStepV1] {
        self.original.post_return_steps()
    }
    pub(in crate::admission_operation_store) fn participant_requirements(
        &self,
    ) -> AdmissionParticipantRequirements {
        self.custody.operation.binding().participant_requirements()
    }
    pub(in crate::admission_operation_store) fn original_profile(
        &self,
    ) -> Result<&NativeOutputRetentionProfileV1, AdmissionOperationStoreError> {
        self.original
            .native_output_retention()
            .ok_or_else(|| invalid("native finishing profile disappeared"))
    }
    pub(in crate::admission_operation_store) fn tool_outcome_envelope(
        &self,
    ) -> &NativeToolOutcomeEnvelopeData {
        &self.envelope
    }
    pub(in crate::admission_operation_store) fn store_fence(&self) -> &StoreMutationFence {
        self.custody.lease.store_fence()
    }
    pub(in crate::admission_operation_store) fn physical_write_profile(
        &self,
    ) -> &ToolOutcomeWriteProfileData {
        &self.physical_profile
    }
    pub(in crate::admission_operation_store) fn global_commit_envelope(
        &self,
    ) -> &NativeToolOutcomeGlobalEnvelopeData {
        &self.global_envelope
    }
}
