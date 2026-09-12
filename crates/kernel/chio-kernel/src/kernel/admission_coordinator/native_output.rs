//! Original finalization owns output mutation. Classification supplies only a
//! label, never a replacement operation, lease, clock, identity or output blob.
use super::native_acquisition::store_call;
use super::*;
use crate::admission_operation::{
    AdmissionRecoveryLease, NativeSecurityAuthorityBindingV1, NativeSecurityOutputJoinRecordV1,
    NativeSecurityOutputJoinRequestV1,
};
use crate::tool_outcome::DurableSecurityReleaseContext;
use chio_security_types::ports::{FlowStateKey, FlowStateSnapshot};
use chio_security_types::InformationLabel;
use std::cell::{Cell, RefCell};

/// A non-serializable, call-scoped writer borrowed from the kernel's original
/// finalization. Historical output records cannot construct this authority.
/// A successful join is taint persistence only, not permission to release data.
pub struct NativeSecurityOutputJoinAuthority<'a> {
    kernel: &'a ChioKernel,
    admission: &'a DurableToolAdmission,
    lease: &'a AdmissionRecoveryLease,
    context: &'a DurableSecurityReleaseContext<'a>,
    binding: NativeSecurityAuthorityBindingV1,
    attempted: Cell<bool>,
    failed: Cell<bool>,
    confirmed: RefCell<Option<NativeSecurityOutputJoinRecordV1>>,
}

impl fmt::Debug for NativeSecurityOutputJoinAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSecurityOutputJoinAuthority")
            .finish_non_exhaustive()
    }
}

impl NativeSecurityOutputJoinAuthority<'_> {
    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        &self.binding
    }

    /// Join the classified post-guard label with every current inherited label.
    /// Even if the hook suppresses an error, it cannot acknowledge preparation.
    /// No failed callback compensates or rolls back an already committed taint.
    pub fn join_output(&self, label: InformationLabel) -> Result<FlowStateSnapshot, KernelError> {
        let result = if self.attempted.replace(true) {
            Err(invalid(
                "native output callback attempted more than one join",
            ))
        } else {
            self.join_once(label)
        };
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    fn join_once(&self, label: InformationLabel) -> Result<FlowStateSnapshot, KernelError> {
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        self.validate_original(runtime, now)?;
        let identity = self.context.security_context().as_v1();
        let key = FlowStateKey {
            tenant_id: identity.tenant_id().clone(),
            principal_id: identity.principal_id().clone(),
            lineage_id: identity.lineage_root_id().clone(),
            session_id: identity.session_id().clone(),
            isolation_epoch_id: identity.isolation_epoch_id().clone(),
        };
        let observed = store_call(|| {
            runtime
                .store
                .observe_native_security_flow(&self.binding, &key, &runtime.fence, now)
        })?;
        if observed.binding() != &self.binding
            || observed.key() != &key
            || observed.observed_at_unix_ms() < now
            || observed.observed_at_unix_ms() > runtime.refresh_trusted_time(now)
        {
            return Err(invalid(
                "native output observation changed identity or time",
            ));
        }
        let intent = NativeSecurityOutputJoinRequestV1::new(
            self.context.operation(),
            &observed,
            label,
            self.context.outcome(),
            self.context.evaluation(),
        )
        .map_err(durable_store_error)?;
        // Never renew after classification. The physical writer must check the
        // same lease selected before the unlocked callback, even if it expired.
        let record = store_call(|| {
            runtime.store.join_native_security_output(
                &self.admission.operation,
                self.lease,
                &self.binding,
                &intent,
                runtime.refresh_trusted_time(now),
            )
        })?;
        if record.output != intent
            || record.join.binding != self.binding
            || record.join.operation_id != *self.admission.operation.binding().operation_id()
        {
            return Err(invalid(
                "native output acknowledgement changed original command",
            ));
        }
        intent
            .validate_resolution(&record.join.command, &record.join.snapshot)
            .map_err(durable_store_error)?;
        if self.read_history(runtime, now)? != record {
            return Err(invalid(
                "native output acknowledgement differs from physical history",
            ));
        }
        let snapshot = record.join.snapshot.clone();
        *self
            .confirmed
            .try_borrow_mut()
            .map_err(|_| invalid("native output confirmation is borrowed"))? = Some(record);
        Ok(snapshot)
    }

    fn validate_original(
        &self,
        runtime: &DurableAdmissionRuntime,
        now: u64,
    ) -> Result<(), KernelError> {
        if now >= self.lease.untrusted_claim().expires_at_unix_ms() {
            return Err(invalid("native output original lease expired"));
        }
        let (current, retained) = store_call(|| {
            runtime.store.load_retained_tool_request(
                self.admission.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("native output lost original admission"))?;
        if current != self.admission.operation
            || &current != self.context.operation()
            || current.state() != AdmissionOperationState::Finalizing
            || current.native_dispatch_ledger_digest().is_none()
            || self
                .admission
                .retained_request
                .as_ref()
                .is_none_or(|original| original.canonical_bytes() != retained.canonical_bytes())
        {
            return Err(invalid(
                "native output differs from original captured finalization",
            ));
        }
        let request: ToolCallRequest = serde_json::from_str(self.context.request_canonical_json())
            .map_err(|_| invalid("native output request is invalid"))?;
        retained
            .validate_request_material(&request)
            .map_err(durable_store_error)?;
        retained
            .validate_native_security_authority(&self.binding)
            .and_then(|()| {
                retained.validate_native_security_context(self.context.security_context())
            })
            .map_err(durable_store_error)
    }

    fn read_history(
        &self,
        runtime: &DurableAdmissionRuntime,
        now: u64,
    ) -> Result<NativeSecurityOutputJoinRecordV1, KernelError> {
        let (operation, history) = store_call(|| {
            runtime.store.load_native_security_output_join(
                self.admission.operation.binding().operation_id(),
                &runtime.fence,
                runtime.refresh_trusted_time(now),
            )
        })?
        .ok_or_else(|| invalid("native output readback lost original operation"))?;
        if operation != self.admission.operation {
            return Err(invalid("native output readback changed original operation"));
        }
        history.ok_or_else(|| invalid("native output readback is absent"))
    }

    fn finish(&self) -> Result<(), KernelError> {
        if self.failed.get() {
            return Err(invalid("native output callback suppressed a failed join"));
        }
        let confirmed = self
            .confirmed
            .try_borrow()
            .map_err(|_| invalid("native output confirmation is borrowed"))?;
        let confirmed = confirmed
            .as_ref()
            .ok_or_else(|| invalid("native output callback returned without a confirmed join"))?;
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        self.validate_original(runtime, now)?;
        if &self.read_history(runtime, now)? != confirmed {
            return Err(invalid(
                "native output history changed before callback completion",
            ));
        }
        Ok(())
    }
}

impl ChioKernel {
    /// Exercise only native taint preparation against retained test artifacts
    /// and an existing physical lease. This cannot recreate a release owner,
    /// acknowledge release, finalize a receipt or enter a connector.
    #[cfg(feature = "admission-test-support")]
    pub fn prepare_native_output_for_test(
        &self,
        context: &DurableSecurityReleaseContext<'_>,
        lease: &AdmissionRecoveryLease,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let (operation, retained_request) = store_call(|| {
            runtime.store.load_retained_tool_request(
                context.operation().binding().operation_id(),
                &runtime.fence,
                runtime.refresh_trusted_time(current_unix_timestamp_ms()),
            )
        })?
        .ok_or_else(|| invalid("test native output original admission is absent"))?;
        let admission = DurableToolAdmission {
            _live_owner: None,
            operation,
            retained_request: Some(retained_request),
            aggregate_quota: None,
            supplemental_quota: None,
            issued_nonce: None,
            nonce_preflight: None,
        };
        self.prepare_durable_native_output(&admission, lease, context)
    }

    pub(super) fn prepare_durable_native_output(
        &self,
        admission: &DurableToolAdmission,
        lease: &AdmissionRecoveryLease,
        context: &DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        let original = admission.original_native_security_authority_binding();
        if self.native_security_authority_binding()?.as_ref() != original {
            return Err(invalid(
                "native output selection differs from original admission",
            ));
        }
        let Some(binding) = original else {
            return Ok(());
        };
        let retained = admission
            .original_retained_request()
            .ok_or_else(|| invalid("native output original request is absent"))?;
        self.validate_original_authority_profile(retained)?;
        let request: ToolCallRequest = serde_json::from_str(context.request_canonical_json())
            .map_err(|_| invalid("native output request is invalid"))?;
        // Workload binding can call a configured capability authority. Like
        // classification, it must never run while holding the mutation lock.
        super::super::security_dispatch::callback("native output identity", || {
            self.validate_security_invocation_context_binding(
                &request,
                Some(context.security_context()),
                None,
            )
        })?;
        let hook = self
            .security_pre_dispatch_hook
            .as_ref()
            .ok_or_else(|| invalid("native output hook is absent"))?;
        let authority = NativeSecurityOutputJoinAuthority {
            kernel: self,
            admission,
            lease,
            context,
            binding: binding.clone(),
            attempted: Cell::new(false),
            failed: Cell::new(false),
            confirmed: RefCell::new(None),
        };
        {
            let runtime = self.durable_runtime()?;
            let _guard = runtime.lock_mutations()?;
            authority.validate_original(
                runtime,
                runtime.refresh_trusted_time(current_unix_timestamp_ms()),
            )?;
        }
        // The original live lifecycle owner remains required by the caller.
        // Arbitrary classification and hook callbacks run outside the sequencer.
        super::super::security_dispatch::callback("native output preparation", || {
            hook.prepare_native_output(context, &authority)
        })?;
        if self.native_security_authority_binding()?.as_ref() != Some(binding) {
            return Err(invalid(
                "native output selection changed during classification",
            ));
        }
        // Input authorization and persisted output taint do not authorize
        // release after revocation or containment. Query current authority
        // outside the mutation lock, then revalidate the original lease.
        super::super::security_dispatch::callback("native output release authority", || {
            self.check_revocation(&request.capability)?;
            if self.is_emergency_stopped() {
                return Err(invalid("native output denied by emergency stop"));
            }
            Ok(())
        })?;
        authority.finish()
    }
}

fn invalid(message: &str) -> KernelError {
    KernelError::SecurityDispatchOutcomeRecoveryRequired(message.into())
}
