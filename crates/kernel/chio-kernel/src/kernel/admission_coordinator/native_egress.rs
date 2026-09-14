//! Kernel-owned, affine native egress custody, separate from dispatch authority.

use super::native_acquisition::store_call;
use super::*;
use crate::admission_operation::{
    AdmissionOperationId, NativeSecurityAuthorityBindingV1, NativeSecurityEgressContext,
    NativeSecurityEgressHistoryV1, NativeSecurityFlowJoinRecordV1, NativeSecurityFlowObservationV1,
    RetainedToolAdmissionRequestV1,
};
use chio_security_types::ports::{
    CommittedEgressFence, Digest32, EgressFenceCommit, EgressFenceRequest, FlowStateKey, RecordId,
    RequestId,
};

#[path = "native_egress/capture.rs"]
mod capture;
#[path = "native_egress/ledger.rs"]
mod ledger;
#[cfg(feature = "admission-test-support")]
pub(crate) use capture::NativeCaptureCheckpointInput;
#[cfg(feature = "admission-test-support")]
pub use capture::NativeSecurityCaptureCheckpointHook;
pub use capture::NativeSecurityDispatchCaptureAuthority;

/// Test-only observer at the still-closed native pre-dispatch boundary. It can
/// exercise real kernel custody without bypassing the final dispatch refusal.
#[cfg(feature = "admission-test-support")]
pub type NativeSecurityEgressCheckpointHook = Arc<
    dyn Fn(&ChioKernel, &AdmissionOperationV1, &ToolCallRequest, &SecurityInvocationContext)
        + Send
        + Sync,
>;

#[cfg(feature = "admission-test-support")]
impl ChioKernel {
    pub fn install_native_egress_checkpoint_hook(
        &mut self,
        hook: NativeSecurityEgressCheckpointHook,
    ) {
        self.native_egress_checkpoint_hook = Some(hook);
    }
}

/// Fresh post-join data bound to one original admission and borrowed live request.
/// The host can inspect the observation before deciding whether to acquire.
/// This does not certify classification, clearance, credentials or execution.
/// No native dispatch path is activated by constructing or consuming this handle.
#[must_use]
pub struct PreparedNativeSecurityEgress<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    operation: AdmissionOperationV1,
    original: RetainedToolAdmissionRequestV1,
    joined: NativeSecurityFlowJoinRecordV1,
    observation: NativeSecurityFlowObservationV1,
    context: SecurityInvocationContext,
    live_request_hash: AdmissionDigest,
    dispatch_commitment_id: RecordId,
}

/// One confirmed acquisition. Consuming it attempts exactly one commitment;
/// errors, including lost acknowledgements, never return successful custody.
/// Dropping it does not undo historical acquisition or authorize compensation.
#[must_use]
pub struct AcquiredNativeSecurityEgress<'a> {
    prepared: PreparedNativeSecurityEgress<'a>,
    history: NativeSecurityEgressHistoryV1,
}

impl fmt::Debug for PreparedNativeSecurityEgress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedNativeSecurityEgress")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AcquiredNativeSecurityEgress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcquiredNativeSecurityEgress")
            .finish_non_exhaustive()
    }
}

impl ChioKernel {
    /// Prepare custody for an already admitted in-kernel operation
    /// in `CapturePending`. The identifier selects history, not authority: the
    /// kernel checks original material, configured selections and trusted identity.
    /// A new fenced observation supplies the post-join generation. The original
    /// join's historical snapshot is never substituted for this observation.
    ///
    /// This trusted-host orchestration API neither runs policy nor dispatches.
    /// Its result is not accepted as permission to enter a connector.
    pub fn prepare_native_security_egress<'a>(
        &'a self,
        operation_id: &AdmissionOperationId,
        request: &'a ToolCallRequest,
        context: &SecurityInvocationContext,
    ) -> Result<PreparedNativeSecurityEgress<'a>, KernelError> {
        self.validate_security_invocation_context_binding(request, Some(context), None)?;
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(0);
        let (operation, original) = store_call(|| {
            runtime
                .store
                .load_retained_tool_request(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| invalid("native egress original admission is absent"))?;
        if operation.binding().operation_id() != operation_id {
            return Err(invalid("native egress read returned another operation"));
        }
        self.validate_native_egress_original(&operation, &original, request, context)?;
        let binding = original
            .native_security_authority_binding()
            .ok_or_else(|| invalid("native egress original selection is absent"))?;
        let joined = read_join(runtime, &operation, binding, now)?;
        let trusted = context.as_v1();
        let key = FlowStateKey {
            tenant_id: trusted.tenant_id().clone(),
            principal_id: trusted.principal_id().clone(),
            lineage_id: trusted.lineage_root_id().clone(),
            session_id: trusted.session_id().clone(),
            isolation_epoch_id: trusted.isolation_epoch_id().clone(),
        };
        if joined.command.key != key || joined.snapshot.key != key {
            return Err(invalid("native egress join differs from original identity"));
        }
        let observation = observe(runtime, binding, &key, now)?;
        let generation = observation
            .stored_context_generation()
            .ok_or_else(|| invalid("native egress requires a current joined context"))?;
        if generation < joined.snapshot.context_generation {
            return Err(invalid("native egress observation predates original join"));
        }
        let context =
            SecurityInvocationContext::v1(trusted.clone().with_flow_state_generation(generation));
        let canonical = canonical_live_request(request)?;
        let live_request_hash =
            AdmissionDigest::try_new("native_live_request_hash", sha256_hex(&canonical))
                .map_err(|error| invalid(&error.to_string()))?;
        let dispatch_commitment_id =
            super::super::dispatch::derive_security_dispatch_commitment_id(&canonical, &context)?;
        Ok(PreparedNativeSecurityEgress {
            kernel: self,
            request,
            operation,
            original,
            joined,
            observation,
            context,
            live_request_hash,
            dispatch_commitment_id,
        })
    }

    fn validate_native_egress_original(
        &self,
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        request: &ToolCallRequest,
        context: &SecurityInvocationContext,
    ) -> Result<(), KernelError> {
        operation
            .validate()
            .map_err(|error| invalid(&error.to_string()))?;
        if operation.binding().kind() != AdmissionOperationKind::ToolDispatch
            || operation.state() != AdmissionOperationState::CapturePending
            || operation.dispatch_commit().is_some()
            || operation.provider_attempt().is_none_or(|attempt| {
                attempt.transport_id
                    != DispatchTransport::KernelToolServer.transport_id(&request.server_id)
                    && !(attempt.is_native_caller_report()
                        && attempt.transport_id
                            == format!(
                                "{}{}",
                                ProviderAttemptBindingV1::NATIVE_CALLER_REPORT_TRANSPORT_PREFIX,
                                request.server_id
                            )
                        && original
                            .authority_profile()
                            .and_then(|profile| profile.caller_executor())
                            .is_some())
            })
            || original.authority_profile().is_none()
            || self.security_pre_dispatch_policy != SecurityPreDispatchPolicy::Enforce
        {
            return Err(invalid("native egress requires original capture custody"));
        }
        let selected = self
            .native_security_authority_binding()?
            .ok_or_else(|| invalid("native egress configured selection is absent"))?;
        original
            .validate_binding(operation.binding())
            .and_then(|()| original.validate_native_security_authority(&selected))
            .and_then(|()| original.validate_native_security_context(context))
            .and_then(|()| original.validate_request_material(request))
            .map_err(durable_store_error)?;
        self.validate_original_authority_profile(original)
    }
}

impl<'a> PreparedNativeSecurityEgress<'a> {
    /// The exact borrowed live request whose full commitment this handle owns.
    /// Reading it does not verify its transient credentials.
    pub fn request(&self) -> &'a ToolCallRequest {
        self.request
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        self.operation.binding().operation_id()
    }

    /// Original capture-pending version inspected by this borrowed handle.
    pub fn operation_version(&self) -> u64 {
        self.operation.version()
    }

    /// Commitment to the exact retained request, including original authority
    /// selections. It excludes reusable live credentials and grants no custody.
    pub fn retained_request_digest(&self) -> Result<AdmissionDigest, KernelError> {
        AdmissionDigest::try_new(
            "native_original_request_digest",
            sha256_hex(self.original.canonical_bytes()),
        )
        .map_err(|error| invalid(&error.to_string()))
    }

    /// Current kernel policy identity, immutable while preparation borrows it.
    pub fn kernel_policy_hash(&self) -> &str {
        &self.kernel.config.policy_hash
    }

    /// Recheck original custody and the inspected observation without writing.
    /// The returned time is the kernel's post-read sample, not an execution permit.
    pub fn validate_current(&self) -> Result<u64, KernelError> {
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.observation.observed_at_unix_ms());
        self.revalidate(runtime, now)?;
        Ok(runtime.refresh_trusted_time(now))
    }

    pub fn observation(&self) -> &NativeSecurityFlowObservationV1 {
        &self.observation
    }

    /// Stable admitted identity with the freshly observed stored flow generation.
    pub fn security_context(&self) -> &SecurityInvocationContext {
        &self.context
    }

    /// Acquire once, checking that the inspected observation is still current.
    /// Expiry is an absolute deadline and is never silently extended on retry.
    pub fn acquire(
        self,
        expires_at_unix_ms: u64,
    ) -> Result<AcquiredNativeSecurityEgress<'a>, KernelError> {
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.observation.observed_at_unix_ms());
        require_deadline(expires_at_unix_ms, now)?;
        self.revalidate(runtime, now)?;
        let payload = canonical_json_bytes(&self.request.arguments)
            .map_err(|error| invalid(&error.to_string()))?;
        if sha256_hex(&payload) != self.operation.binding().action_parameter_hash().as_str() {
            return Err(invalid(
                "native egress payload differs from original action",
            ));
        }
        let command = EgressFenceRequest {
            key: self.observation.key().clone(),
            request_id: RequestId::new(&self.request.request_id)
                .map_err(|error| invalid(&error.to_string()))?,
            request_hash: Digest32::new(*chio_core::sha256(&payload).as_bytes()),
            expected_context_generation: self
                .context
                .as_v1()
                .flow_state_generation()
                .ok_or_else(|| invalid("native egress current generation is absent"))?,
            expires_at_unix_ms,
        };
        let lease = self.kernel.claim_admission_recovery(&self.operation, now)?;
        let input = self.command_context(&lease, now);
        let acknowledged = store_call(|| {
            runtime
                .store
                .acquire_native_security_egress(&input, &command)
        });
        // Read even on a denied or panicked callback. Never convert a lost
        // acknowledgement into success, and never obscure the original denial.
        let history = self.read_history(runtime, now);
        let fence = acknowledged?;
        let history = history?;
        if fence.key != command.key
            || fence.request_id != command.request_id
            || fence.request_hash != command.request_hash
            || fence.context_generation != command.expected_context_generation
            || fence.expires_at_unix_ms != command.expires_at_unix_ms
            || history.acquisition.fence != fence
            || history.commitment.is_some()
        {
            return Err(invalid(
                "native egress acquisition differs from command history",
            ));
        }
        // A callback may have advanced trusted time or changed configuration.
        let after = runtime.refresh_trusted_time(now);
        require_deadline(expires_at_unix_ms, after)?;
        self.revalidate(runtime, after)?;
        if self.read_history(runtime, after)? != history {
            return Err(invalid(
                "native egress acquisition changed during confirmation",
            ));
        }
        Ok(AcquiredNativeSecurityEgress {
            prepared: self,
            history,
        })
    }

    fn revalidate(&self, runtime: &DurableAdmissionRuntime, now: u64) -> Result<(), KernelError> {
        self.kernel.validate_native_egress_original(
            &self.operation,
            &self.original,
            self.request,
            &self.context,
        )?;
        let (current, original) = store_call(|| {
            runtime.store.load_retained_tool_request(
                self.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("native egress original admission disappeared"))?;
        if current != self.operation
            || original.canonical_bytes() != self.original.canonical_bytes()
            || sha256_hex(&canonical_live_request(self.request)?) != self.live_request_hash.as_str()
            || read_join(runtime, &self.operation, self.observation.binding(), now)? != self.joined
        {
            return Err(invalid("native egress original custody changed"));
        }
        let current = observe(
            runtime,
            self.observation.binding(),
            self.observation.key(),
            now,
        )?;
        if current.snapshot() != self.observation.snapshot()
            || current.stored_context_generation() != self.observation.stored_context_generation()
        {
            return Err(invalid("native egress post-join observation changed"));
        }
        Ok(())
    }

    fn command_context<'b>(
        &'b self,
        lease: &'b crate::admission_operation::AdmissionRecoveryLease,
        now: u64,
    ) -> NativeSecurityEgressContext<'b> {
        NativeSecurityEgressContext {
            operation: &self.operation,
            lease,
            binding: self.observation.binding(),
            security_context: &self.context,
            request: self.request,
            trusted_now_unix_ms: now,
        }
    }

    fn read_history(
        &self,
        runtime: &DurableAdmissionRuntime,
        now: u64,
    ) -> Result<NativeSecurityEgressHistoryV1, KernelError> {
        let (operation, history) = store_call(|| {
            runtime.store.load_native_security_egress(
                self.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("native egress operation readback is absent"))?;
        let history = history.ok_or_else(|| invalid("native egress custody readback is absent"))?;
        if operation != self.operation
            || history.operation_id != *self.operation.binding().operation_id()
            || &history.binding != self.observation.binding()
            || history.live_request_hash != self.live_request_hash
        {
            return Err(invalid("native egress readback changed original custody"));
        }
        Ok(history)
    }
}

impl AcquiredNativeSecurityEgress<'_> {
    /// Historical acquisition evidence, not a transferable execution permit.
    pub fn history(&self) -> &NativeSecurityEgressHistoryV1 {
        &self.history
    }

    /// Commit the exact acquired fence and borrowed live request. Returned
    /// history records custody only; dispatch-ledger and credential authority
    /// remain separate required checks. No connector is invoked here.
    pub fn commit(self) -> Result<NativeSecurityEgressHistoryV1, KernelError> {
        self.commit_current()
    }

    fn commit_current(&self) -> Result<NativeSecurityEgressHistoryV1, KernelError> {
        self.commit_current_with_declassification(None)
    }

    fn commit_current_with_declassification(
        &self,
        consumption: Option<&chio_security_types::ports::DeclassificationConsumptionEvidenceCommit>,
    ) -> Result<NativeSecurityEgressHistoryV1, KernelError> {
        let prepared = &self.prepared;
        let runtime = prepared.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(prepared.observation.observed_at_unix_ms());
        require_deadline(self.history.acquisition.fence.expires_at_unix_ms, now)?;
        prepared.revalidate(runtime, now)?;
        if prepared.read_history(runtime, now)? != self.history {
            return Err(invalid(
                "native egress acquisition changed before commitment",
            ));
        }
        let command = EgressFenceCommit {
            fence: self.history.acquisition.fence.clone(),
            dispatch_commitment_id: prepared.dispatch_commitment_id.clone(),
            committed_at_unix_ms: now,
        };
        let expected = CommittedEgressFence {
            fence_id: command.fence.fence_id.clone(),
            request_id: command.fence.request_id.clone(),
            request_hash: command.fence.request_hash,
            context_generation: command.fence.context_generation,
            dispatch_commitment_id: command.dispatch_commitment_id.clone(),
            committed_at_unix_ms: now,
        };
        let lease = prepared
            .kernel
            .claim_admission_recovery(&prepared.operation, now)?;
        let input = prepared.command_context(&lease, now);
        let acknowledged = store_call(|| match consumption {
            Some(consumption) => runtime.store.commit_native_security_declassified_egress(
                &input,
                &command,
                consumption,
            ),
            None => runtime
                .store
                .commit_native_security_egress(&input, &command),
        });
        let history = prepared.read_history(runtime, now);
        let committed = acknowledged?;
        let history = history?;
        let evidence = history
            .commitment
            .as_ref()
            .ok_or_else(|| invalid("native egress commitment readback is absent"))?;
        if committed != expected
            || evidence.commitment != expected
            || history.acquisition != self.history.acquisition
            || evidence.acquisition_digest != self.history.acquisition.event_digest
            || evidence.event_digest == evidence.acquisition_digest
            || evidence.declassification.as_ref() != consumption
        {
            return Err(invalid(
                "native egress commitment differs from acquired command history",
            ));
        }
        let after = runtime.refresh_trusted_time(now);
        require_deadline(command.fence.expires_at_unix_ms, after)?;
        prepared.revalidate(runtime, after)?;
        if prepared.read_history(runtime, after)? != history {
            return Err(invalid(
                "native egress commitment changed during confirmation",
            ));
        }
        Ok(history)
    }
}

fn read_join(
    runtime: &DurableAdmissionRuntime,
    operation: &AdmissionOperationV1,
    binding: &NativeSecurityAuthorityBindingV1,
    now: u64,
) -> Result<NativeSecurityFlowJoinRecordV1, KernelError> {
    let (current, history) = store_call(|| {
        runtime.store.load_native_security_flow_join(
            operation.binding().operation_id(),
            &runtime.fence,
            now,
        )
    })?
    .ok_or_else(|| invalid("native egress joined operation is absent"))?;
    let history = history.ok_or_else(|| invalid("native egress original join is absent"))?;
    if current != *operation
        || &history.binding != binding
        || history.operation_id != *operation.binding().operation_id()
    {
        return Err(invalid(
            "native egress cannot adopt another operation's join",
        ));
    }
    Ok(history)
}

fn observe(
    runtime: &DurableAdmissionRuntime,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    now: u64,
) -> Result<NativeSecurityFlowObservationV1, KernelError> {
    let observation = store_call(|| {
        runtime
            .store
            .observe_native_security_flow(binding, key, &runtime.fence, now)
    })?;
    // The store samples its clock inside the read transaction. The callback
    // need not finish in the millisecond in which the kernel started it.
    // Do not admit either an older snapshot timestamp or an invented future.
    let completed_at = runtime.refresh_trusted_time(now);
    if observation.binding() != binding
        || observation.key() != key
        || observation.observed_at_unix_ms() < now
        || observation.observed_at_unix_ms() > completed_at
        || observation.stored_context_generation().is_none()
    {
        return Err(invalid(
            "native egress observation differs from fresh selected context",
        ));
    }
    Ok(observation)
}

fn canonical_live_request(request: &ToolCallRequest) -> Result<Vec<u8>, KernelError> {
    let bytes = canonical_json_bytes(request).map_err(|error| invalid(&error.to_string()))?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid("native live request exceeds bounds"));
    }
    Ok(bytes)
}

fn require_deadline(deadline: u64, now: u64) -> Result<(), KernelError> {
    if deadline <= now || deadline > I_JSON_MAX_SAFE_INTEGER {
        return Err(invalid("native egress deadline is expired or invalid"));
    }
    Ok(())
}

fn invalid(detail: &str) -> KernelError {
    KernelError::DurableAdmission(detail.into())
}
