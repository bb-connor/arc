//! Kernel-scoped authority for a trusted runtime verifier. Serialized request
//! metadata and historical claim references cannot construct this handle.

use super::runtime_participant::store_call;
use super::*;
use crate::admission_operation::runtime_participant::{
    RuntimeDispatchValidity, RuntimeParticipantAuthorityBindingV1,
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimIntentInput,
    RuntimeParticipantClaimIntentV1, RuntimeParticipantClaimReferenceV1,
    RuntimeParticipantDisposition, RuntimeParticipantPhase, RuntimeParticipantResourceV1,
};
use crate::admission_operation::{AdmissionOperationStoreError, AdmissionRecoveryLease};
use std::cell::{Cell, RefCell};

#[path = "runtime_reserved.rs"]
mod reserved;

/// Call-scoped, non-serializable authority to claim a completely prepared plan.
/// The kernel owns the operation and immediately retains every confirmed store
/// update, even when the verifier subsequently denies or panics. The verifier
/// chooses only its prepared-plan digest and exact resource set.
pub struct RuntimeParticipantClaimAuthority<'a> {
    kernel: &'a ChioKernel,
    admission: RefCell<&'a mut DurableToolAdmission>,
    binding: RuntimeParticipantAuthorityBindingV1,
    source_snapshot: crate::admission_operation::RuntimeReplaySourceSnapshotV1,
    episode_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    grant_index: u32,
    phase: RuntimeParticipantPhase,
    requested_now_unix_ms: u64,
    attempted: RefCell<Option<RuntimeParticipantClaimIntentV1>>,
    confirmed: RefCell<Option<RuntimeParticipantClaimReferenceV1>>,
    failed: Cell<bool>,
}

impl fmt::Debug for RuntimeParticipantClaimAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeParticipantClaimAuthority")
            .field("phase", &self.phase)
            .field("grant_index", &self.grant_index)
            .finish_non_exhaustive()
    }
}

impl RuntimeParticipantClaimAuthority<'_> {
    pub fn binding(&self) -> &RuntimeParticipantAuthorityBindingV1 {
        &self.binding
    }
    /// Expected source evidence from the qualified activation record, not from
    /// request metadata. The runtime must verify its actual backend against it.
    pub fn source_snapshot(&self) -> &crate::admission_operation::RuntimeReplaySourceSnapshotV1 {
        &self.source_snapshot
    }
    pub fn episode_id(&self) -> &AdmissionIdentifier {
        &self.episode_id
    }
    pub fn request_binding_hash(&self) -> &AdmissionDigest {
        &self.request_binding_hash
    }
    pub fn grant_index(&self) -> u32 {
        self.grant_index
    }
    pub fn phase(&self) -> RuntimeParticipantPhase {
        self.phase
    }

    /// Reserve the complete prepared set exactly once. An error remains a
    /// failed admission even when readback recovers ownership for cleanup.
    pub fn claim(
        &self,
        plan_digest: AdmissionDigest,
        resources: Vec<RuntimeParticipantResourceV1>,
    ) -> Result<RuntimeParticipantClaimReferenceV1, KernelError> {
        let result = self.claim_once(plan_digest, resources);
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    fn claim_once(
        &self,
        plan_digest: AdmissionDigest,
        resources: Vec<RuntimeParticipantResourceV1>,
    ) -> Result<RuntimeParticipantClaimReferenceV1, KernelError> {
        let intent = RuntimeParticipantClaimIntentV1::new(RuntimeParticipantClaimIntentInput {
            episode_id: self.episode_id.clone(),
            runtime_authority_id: self.binding.runtime_authority_id().clone(),
            expectation_id: self.binding.expectation_id().clone(),
            request_binding_hash: self.request_binding_hash.clone(),
            grant_index: self.grant_index,
            phase: self.phase,
            plan_digest,
            resources,
        })
        .map_err(durable_store_error)?;
        {
            let mut attempted = self.attempted.try_borrow_mut().map_err(borrow_error)?;
            if attempted.is_some() {
                return Err(acquisition_error(
                    "runtime verifier attempted more than one claim",
                ));
            }
            *attempted = Some(intent.clone());
        }
        let runtime = self.kernel.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.requested_now_unix_ms);
        let source = store_call("activation", || {
            runtime
                .store
                .load_runtime_participant_activation(&self.binding, &runtime.fence, now)
        })?;
        if source != self.source_snapshot {
            return Err(acquisition_error(
                "runtime activation source changed during preparation",
            ));
        }
        let mut admission = self.admission.try_borrow_mut().map_err(borrow_error)?;
        let original = admission.operation.clone();
        let lease = self.kernel.claim_admission_recovery(&original, now)?;
        // Catch inside the sequencer's scope so a participant callback panic
        // cannot poison the coordinator lock before ownership readback.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime
                .store
                .claim_runtime_participants(&original, &lease, &intent, now)
        }))
        .unwrap_or_else(|_| {
            Err(AdmissionOperationStoreError::OutcomeUnknown(
                "runtime participant claim callback panicked".into(),
            ))
        });
        if let Ok((updated, _)) = &result {
            if validate_claim_successor(&original, updated, &lease, now).is_ok() {
                admission.operation = updated.clone();
            }
        }
        // Attempt readback even after an error. Never leave a durably attached
        // ledger hidden behind the caller's old in-memory operation version.
        let (current, history) = load_history(runtime, &original, now)?;
        admission.operation = current.clone();
        let (updated, reference) = result.map_err(durable_store_error)?;
        validate_claim_successor(&original, &updated, &lease, now)?;
        if updated != current {
            return Err(acquisition_error(
                "runtime claim acknowledgement changed its operation",
            ));
        }
        require_claim(&current, &history, &intent, &reference)?;
        self.confirmed
            .try_borrow_mut()
            .map_err(borrow_error)?
            .replace(reference.clone());
        Ok(reference)
    }

    fn finish(
        self,
        result: Result<RuntimeAdmissionDecision, KernelError>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let runtime = self.kernel.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.requested_now_unix_ms);
        let admission = self.admission.into_inner();
        let attempted = self.attempted.into_inner();
        let confirmed = self.confirmed.into_inner();
        let result = match result {
            Ok(decision) if decision.allowed => {
                match (self.failed.get(), attempted.as_ref(), confirmed.as_ref()) {
                    (false, Some(intent), Some(reference)) => {
                        let verified = load_history(runtime, &admission.operation, now).and_then(
                            |(current, history)| {
                                let unchanged = current == admission.operation;
                                admission.operation = current;
                                if !unchanged {
                                    return Err(acquisition_error(
                                        "runtime operation changed before verifier completion",
                                    ));
                                }
                                require_claim(&admission.operation, &history, intent, reference)
                            },
                        );
                        verified.map(|()| decision)
                    }
                    _ => Err(acquisition_error(
                        "runtime Allow lacks one confirmed prepared-plan claim",
                    )),
                }
            }
            other => other,
        };
        if result.as_ref().is_ok_and(|decision| decision.allowed) {
            return result;
        }
        // No hook metadata participates in cleanup. The exact lease and physical
        // history remain authoritative even after a panic or lost acknowledgement.
        let lease = self
            .kernel
            .claim_admission_recovery(&admission.operation, now)?;
        self.kernel
            .release_retained_runtime_participants(&admission.operation, &lease, now)?;
        result
    }
}

impl ChioKernel {
    pub(crate) fn verify_owned_runtime_for_native_capture(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        grant_index: usize,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<(RuntimeParticipantClaimHistoryV1, RuntimeDispatchValidity)>, KernelError>
    {
        let Some(binding) = self.configured_runtime_participant_binding()? else {
            if self.runtime_admission_hook.is_some()
                || admission
                    .operation()
                    .runtime_participant_ledger_digest()
                    .is_some()
            {
                return Err(acquisition_error(
                    "native capture lacks owned runtime authority",
                ));
            }
            return Ok(None);
        };
        let hook = self.runtime_admission_hook.as_ref().ok_or_else(|| {
            acquisition_error("native capture lost its original runtime verifier")
        })?;
        let now = current_unix_timestamp_ms();
        let context = RuntimeAdmissionRevalidationContext {
            request,
            admission_metadata: metadata,
            now_unix_secs: now / 1000,
            now_unix_ms: now,
            matched_grant_index: Some(grant_index),
            local_kernel_id: self.federation_local_kernel_id(),
        };
        let runtime = self.durable_runtime()?;
        let operation = admission.operation();
        let (current, history) = {
            let _guard = runtime.lock_mutations()?;
            let now = runtime.refresh_trusted_time(now);
            load_history(runtime, operation, now)?
        };
        if current != *operation {
            return Err(acquisition_error(
                "native runtime capture changed its operation",
            ));
        }
        super::runtime_participant::validate_recovery_history(operation, &history)?;
        let live = history
            .into_iter()
            .find(|claim| {
                claim.disposition == RuntimeParticipantDisposition::ReservedBeforeDispatch
            })
            .ok_or_else(|| acquisition_error("native capture requires a live runtime claim"))?;
        if usize::try_from(live.intent.grant_index()).ok() != Some(grant_index)
            || live.intent.phase() != RuntimeParticipantPhase::Dispatch
            || live.intent.runtime_authority_id() != binding.runtime_authority_id()
            || live.intent.expectation_id() != binding.expectation_id()
        {
            return Err(acquisition_error(
                "native runtime claim selected another grant or phase",
            ));
        }
        let source = self.runtime_revalidation_source(&context, binding)?;
        let validity = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.revalidate_operation_owned_for_native_capture(&context, &source, &live.intent)
        }))
        .map_err(|_| acquisition_error("native runtime revalidation panicked"))??;
        validity
            .validate_at(runtime.refresh_trusted_time(current_unix_timestamp_ms()))
            .map_err(|error| acquisition_error(&error.to_string()))?;
        Ok(Some((live, validity)))
    }

    pub(crate) fn release_operation_owned_runtime_before_dispatch(
        &self,
        operation: Option<&AdmissionOperationV1>,
    ) -> Result<(), KernelError> {
        let operation = operation
            .ok_or_else(|| acquisition_error("runtime release requires its durable operation"))?;
        if operation.runtime_participant_ledger_digest().is_none() {
            return Ok(());
        }
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let lease = self.claim_admission_recovery(operation, now)?;
            self.release_retained_runtime_participants(operation, &lease, now)
        }))
        .unwrap_or_else(|_| {
            Err(acquisition_error(
                "operation-owned runtime release panicked (fail-closed)",
            ))
        })
    }

    pub(crate) fn revalidate_operation_owned_runtime_hook(
        &self,
        hook: &dyn RuntimeAdmissionHook,
        context: &RuntimeAdmissionRevalidationContext<'_>,
        binding: &RuntimeParticipantAuthorityBindingV1,
    ) -> Result<(), KernelError> {
        let source = self.runtime_revalidation_source(context, binding)?;
        // The source backend may perform external I/O. Do not hold the kernel
        // sequencer while asking it to verify its immutable replay barriers.
        hook.revalidate_operation_owned_before_dispatch(context, &source)
    }

    fn runtime_revalidation_source(
        &self,
        context: &RuntimeAdmissionRevalidationContext<'_>,
        binding: &RuntimeParticipantAuthorityBindingV1,
    ) -> Result<crate::admission_operation::RuntimeReplaySourceSnapshotV1, KernelError> {
        let runtime = self.durable_runtime()?;
        let source = {
            let _mutation_guard = runtime.lock_mutations()?;
            let now = runtime.refresh_trusted_time(context.now_unix_ms);
            store_call("activation", || {
                runtime
                    .store
                    .load_runtime_participant_activation(binding, &runtime.fence, now)
            })?
        };
        if source.runtime_authority_id() != binding.runtime_authority_id().as_str()
            || source.destination_authority_id() != runtime.fence.store_uuid
        {
            return Err(acquisition_error(
                "runtime revalidation source differs from its configured authority",
            ));
        }
        Ok(source)
    }

    pub(crate) fn evaluate_operation_owned_runtime_hook(
        &self,
        hook: &dyn RuntimeAdmissionHook,
        context: &RuntimeAdmissionContext<'_>,
        admission: &mut DurableToolAdmission,
        binding: &RuntimeParticipantAuthorityBindingV1,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        if admission.operation.state() == AdmissionOperationState::ReadyToDispatch
            && admission
                .operation
                .provider_attempt()
                .is_some_and(is_caller_report_attempt)
        {
            return self.revalidate_reserved_caller_runtime(hook, context, admission, binding);
        }
        let phase = match admission.operation.state() {
            AdmissionOperationState::Prepared
                if admission
                    .operation
                    .binding()
                    .participant_requirements()
                    .execution_nonce
                    && admission
                        .operation
                        .execution_nonce_issuance_digest()
                        .is_none()
                    && admission
                        .operation
                        .execution_nonce_preflight_digest()
                        .is_none() =>
            {
                RuntimeParticipantPhase::NoncePreflight
            }
            AdmissionOperationState::BrokerAttemptRegistered => RuntimeParticipantPhase::Dispatch,
            _ => {
                return Err(acquisition_error(
                    "runtime claim is outside an acquisition phase",
                ))
            }
        };
        let grant_index = context
            .matched_grant_index
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| acquisition_error("runtime claim requires an exact matching grant"))?;
        if !hook.requires_dispatch_revalidation()
            || admission.operation.binding().kind() != AdmissionOperationKind::ToolDispatch
            || admission.operation.dispatch_commit().is_some()
        {
            return Err(acquisition_error(
                "runtime claim requires pre-dispatch revalidation authority",
            ));
        }
        let retained = admission.retained_request.as_ref().ok_or_else(|| {
            acquisition_error("runtime claim requires the retained original request")
        })?;
        if retained
            .authority_profile()
            .and_then(|profile| profile.runtime())
            != Some(binding)
        {
            return Err(acquisition_error(
                "runtime authority differs from the original profile",
            ));
        }
        retained
            .validate_request_material(context.request)
            .map_err(durable_store_error)?;
        if retained
            .retained_matching_grant(grant_index as usize)
            .is_none()
        {
            return Err(acquisition_error(
                "runtime claim grant differs from original matching grants",
            ));
        }
        let runtime = self.durable_runtime()?;
        let source_snapshot = {
            let _mutation_guard = runtime.lock_mutations()?;
            let now = runtime.refresh_trusted_time(context.now_unix_ms);
            let source = store_call("activation", || {
                runtime
                    .store
                    .load_runtime_participant_activation(binding, &runtime.fence, now)
            })?;
            if source.runtime_authority_id() != binding.runtime_authority_id().as_str()
                || source.destination_authority_id() != runtime.fence.store_uuid
            {
                return Err(acquisition_error(
                    "runtime activation source differs from its configured authority",
                ));
            }
            // A later grant may follow an admitted plan whose budget check denied.
            // Retire that pre-dispatch episode before preparing the next plan.
            let lease = self.claim_admission_recovery(&admission.operation, now)?;
            self.release_retained_runtime_participants(&admission.operation, &lease, now)?;
            source
        };
        let authority = RuntimeParticipantClaimAuthority {
            kernel: self,
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            admission: RefCell::new(admission),
            binding: binding.clone(),
            source_snapshot,
            episode_id: AdmissionIdentifier::try_new(
                "runtime_episode_id",
                uuid::Uuid::now_v7().to_string(),
            )?,
            grant_index,
            phase,
            requested_now_unix_ms: context.now_unix_ms,
            attempted: RefCell::new(None),
            confirmed: RefCell::new(None),
            failed: Cell::new(false),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.evaluate_operation_owned(context, &authority)
        }))
        .unwrap_or_else(|_| Err(acquisition_error("operation-owned runtime hook panicked")));
        authority.finish(result)
    }
}

fn load_history(
    runtime: &DurableAdmissionRuntime,
    original: &AdmissionOperationV1,
    now: u64,
) -> Result<(AdmissionOperationV1, Vec<RuntimeParticipantClaimHistoryV1>), KernelError> {
    let (current, history) = store_call("history", || {
        runtime.store.load_runtime_participant_history(
            original.binding().operation_id(),
            &runtime.fence,
            now,
        )
    })?
    .ok_or_else(|| acquisition_error("runtime claim ownership readback is missing"))?;
    if current.binding() != original.binding() || current.version() < original.version() {
        return Err(acquisition_error(
            "runtime claim readback changed its operation binding",
        ));
    }
    Ok((current, history))
}

fn validate_claim_successor(
    original: &AdmissionOperationV1,
    updated: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    now: u64,
) -> Result<(), KernelError> {
    let root = updated
        .runtime_participant_ledger_digest()
        .ok_or_else(|| acquisition_error("runtime claim omitted its operation ledger"))?;
    let command = AdmissionOperationCommand::new(
        original.binding().operation_id().clone(),
        original.version(),
        lease.clone(),
        vec![AdmissionAttachment::RuntimeParticipantLedgerDigest(
            root.clone(),
        )],
        Some(original.state()),
        None,
        None,
    )?;
    if original.apply_command(&command, now)?.into_operation() != *updated {
        return Err(acquisition_error(
            "runtime claim returned an invalid operation successor",
        ));
    }
    Ok(())
}

fn require_claim(
    operation: &AdmissionOperationV1,
    history: &[RuntimeParticipantClaimHistoryV1],
    intent: &RuntimeParticipantClaimIntentV1,
    reference: &RuntimeParticipantClaimReferenceV1,
) -> Result<(), KernelError> {
    super::runtime_participant::validate_recovery_history(operation, history)?;
    if operation.dispatch_commit().is_some()
        || operation.state().is_terminal()
        || !history.iter().any(|claim| {
            &claim.intent == intent
                && &claim.reference == reference
                && claim.disposition == RuntimeParticipantDisposition::ReservedBeforeDispatch
        })
    {
        return Err(acquisition_error(
            "runtime claim readback lacks exact live ownership",
        ));
    }
    Ok(())
}

fn acquisition_error(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.to_owned())
}

fn borrow_error(error: std::cell::BorrowMutError) -> KernelError {
    acquisition_error(&format!(
        "runtime claim authority is already in use: {error}"
    ))
}
