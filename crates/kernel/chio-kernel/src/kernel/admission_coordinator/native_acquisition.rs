//! Call-scoped ownership of native monotone preparation. Hooks supply labels,
//! never an operation, destination, flow identity, clock or recovery lease.

use super::*;
use crate::admission_operation::{
    NativeSecurityAuthorityBindingV1, NativeSecurityFlowJoinRecordV1,
};
use chio_security_types::ports::{FlowJoinRequest, FlowStateKey, FlowStateSnapshot, RecordId};
use chio_security_types::InformationLabel;
use std::cell::{Cell, RefCell};

#[path = "native_acquisition/input.rs"]
mod input;
#[path = "native_acquisition/nonce_preflight.rs"]
mod nonce_preflight;
pub use nonce_preflight::NativeSecurityNoncePreflightJoinAuthority;

/// A kernel-created, non-cloneable, non-serializable handle. Its lifetime is
/// bounded by one admission callback and it cannot authorize external effects.
pub struct NativeSecurityFlowJoinAuthority<'a> {
    kernel: &'a ChioKernel,
    admission: &'a DurableToolAdmission,
    binding: NativeSecurityAuthorityBindingV1,
    context: &'a SecurityInvocationContext,
    requested_now: u64,
    attempted: Cell<bool>,
    failed: Cell<bool>,
    confirmed: RefCell<Option<NativeSecurityFlowJoinRecordV1>>,
}

impl fmt::Debug for NativeSecurityFlowJoinAuthority<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSecurityFlowJoinAuthority")
            .finish_non_exhaustive()
    }
}

impl NativeSecurityFlowJoinAuthority<'_> {
    fn resumes_native_caller(&self) -> bool {
        self.admission.operation.state() == AdmissionOperationState::ReadyToDispatch
            && self
                .admission
                .operation
                .provider_attempt()
                .is_some_and(ProviderAttemptBindingV1::is_native_caller_report)
    }

    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        &self.binding
    }

    /// Record one join. The returned snapshot is historical evidence, not a
    /// fresh egress observation. Errors permanently fail this callback even if
    /// its implementation catches them and returns success. Monotone labels
    /// are never rolled back after denial, panic or a lost acknowledgement.
    pub fn join(
        &self,
        transition_id: RecordId,
        principal_join: InformationLabel,
        lineage_join: InformationLabel,
        session_join: InformationLabel,
    ) -> Result<FlowStateSnapshot, KernelError> {
        self.attempt(|| {
            self.join_once(FlowJoinRequest {
                key: self.key(),
                principal_join,
                lineage_join,
                session_join,
                transition_id,
            })
        })
    }

    fn key(&self) -> FlowStateKey {
        let context = self.context.as_v1();
        FlowStateKey {
            tenant_id: context.tenant_id().clone(),
            principal_id: context.principal_id().clone(),
            lineage_id: context.lineage_root_id().clone(),
            session_id: context.session_id().clone(),
            isolation_epoch_id: context.isolation_epoch_id().clone(),
        }
    }

    fn attempt(
        &self,
        call: impl FnOnce() -> Result<FlowStateSnapshot, KernelError>,
    ) -> Result<FlowStateSnapshot, KernelError> {
        let result = if self.attempted.replace(true) {
            Err(invalid("native verifier attempted more than one join"))
        } else {
            call()
        };
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    fn join_once(&self, command: FlowJoinRequest) -> Result<FlowStateSnapshot, KernelError> {
        if self.resumes_native_caller() {
            return Err(invalid(
                "native caller start requires its original classified input custody",
            ));
        }
        self.with_join_custody(|runtime, lease, now| {
            let operation = &self.admission.operation;
            // Contain panics inside the sequencer, then read durable evidence even
            // after a lost acknowledgement. Recovery must not undo this join.
            let acknowledged = store_call(|| {
                runtime.store.join_native_security_flow(
                    operation,
                    lease,
                    &self.binding,
                    self.context,
                    &command,
                    now,
                )
            });
            let history = self.read_history(runtime, now);
            let snapshot = acknowledged?;
            let history = history?;
            if history.binding != self.binding
                || history.operation_id != *operation.binding().operation_id()
                || history.command != command
                || history.snapshot != snapshot
                || snapshot.key != command.key
                || snapshot.context_generation == 0
            {
                return Err(invalid(
                    "native join acknowledgement differs from original command history",
                ));
            }
            self.confirm(history)?;
            Ok(snapshot)
        })
    }

    fn with_join_custody<T>(
        &self,
        call: impl FnOnce(
            &DurableAdmissionRuntime,
            &crate::admission_operation::AdmissionRecoveryLease,
            u64,
        ) -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.requested_now);
        let operation = &self.admission.operation;
        let (current, retained) = store_call(|| {
            runtime.store.load_retained_tool_request(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("original native request is absent"))?;
        if &current != operation
            || self
                .admission
                .retained_request
                .as_ref()
                .is_none_or(|original| original.canonical_bytes() != retained.canonical_bytes())
        {
            return Err(invalid("native admission changed before preparation"));
        }
        retained
            .validate_native_security_context(self.context)
            .and_then(|()| retained.validate_native_security_authority(&self.binding))
            .map_err(durable_store_error)?;
        // Shared qualified lease acquisition contains store callback panics
        // before they can unwind through this mutation sequencer.
        let lease = self.kernel.claim_admission_recovery(operation, now)?;
        call(runtime, &lease, now)
    }

    fn confirm(&self, history: NativeSecurityFlowJoinRecordV1) -> Result<(), KernelError> {
        self.confirmed
            .try_borrow_mut()
            .map_err(|_| invalid("native join confirmation is already borrowed"))?
            .replace(history);
        Ok(())
    }

    fn read_history(
        &self,
        runtime: &DurableAdmissionRuntime,
        now: u64,
    ) -> Result<NativeSecurityFlowJoinRecordV1, KernelError> {
        let (current, history) = store_call(|| {
            runtime.store.load_native_security_flow_join(
                self.admission.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("native operation readback is absent"))?;
        if current != self.admission.operation {
            return Err(invalid(
                "native preparation changed its admission operation",
            ));
        }
        history.ok_or_else(|| invalid("native preparation has no recorded join"))
    }

    fn finish(self, result: Result<(), KernelError>) -> Result<(), KernelError> {
        self.finish_with(result, |owner, runtime, now| {
            owner.read_history(runtime, now)
        })
    }

    fn finish_with(
        self,
        result: Result<(), KernelError>,
        read: impl FnOnce(
            &Self,
            &DurableAdmissionRuntime,
            u64,
        ) -> Result<NativeSecurityFlowJoinRecordV1, KernelError>,
    ) -> Result<(), KernelError> {
        result?;
        if self.failed.get() {
            return Err(invalid("native preparation suppressed a failed join"));
        }
        let confirmed = self
            .confirmed
            .try_borrow()
            .map_err(|_| invalid("native join confirmation is already borrowed"))?
            .clone()
            .ok_or_else(|| invalid("native preparation returned success without a join"))?;
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.requested_now);
        if read(&self, runtime, now)? != confirmed {
            return Err(invalid("native history changed before verifier completion"));
        }
        Ok(())
    }
}

impl ChioKernel {
    pub(crate) fn run_native_admission_preparation(
        &self,
        request: &ToolCallRequest,
        context: Option<&SecurityInvocationContext>,
        admission: Option<&DurableToolAdmission>,
        now: u64,
    ) -> Result<(), KernelError> {
        let selected = self.native_security_authority_binding()?;
        let original = admission.and_then(|admission| admission.retained_request.as_ref());
        if original.and_then(|request| request.native_security_authority_binding())
            != selected.as_ref()
        {
            return Err(invalid("native selection changed after original admission"));
        }
        let Some(binding) = selected else {
            return Ok(());
        };
        let admission =
            admission.ok_or_else(|| invalid("native preparation requires durable admission"))?;
        let original =
            original.ok_or_else(|| invalid("native preparation requires original request"))?;
        let context =
            context.ok_or_else(|| invalid("native preparation requires trusted context"))?;
        let caller_resume = admission.operation.state() == AdmissionOperationState::ReadyToDispatch
            && admission
                .operation
                .provider_attempt()
                .is_some_and(ProviderAttemptBindingV1::is_native_caller_report)
            && original
                .authority_profile()
                .and_then(|profile| profile.caller_executor())
                .is_some();
        if original.authority_profile().is_none()
            || (admission.operation.state() != AdmissionOperationState::BrokerAttemptRegistered
                && !caller_resume)
            || admission.operation.dispatch_commit().is_some()
            || self.security_pre_dispatch_policy != SecurityPreDispatchPolicy::Enforce
        {
            return Err(invalid(
                "native preparation requires original pre-budget authority",
            ));
        }
        original
            .validate_request_material(request)
            .and_then(|()| original.validate_native_security_context(context))
            .map_err(durable_store_error)?;
        let hook = self
            .security_pre_dispatch_hook
            .as_ref()
            .ok_or_else(|| invalid("native preparation hook is absent"))?;
        let authority = NativeSecurityFlowJoinAuthority {
            kernel: self,
            admission,
            binding,
            context,
            requested_now: now,
            attempted: Cell::new(false),
            failed: Cell::new(false),
            confirmed: RefCell::new(None),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.prepare_native_admission(
                &NativeSecurityAdmissionContext {
                    request,
                    security_context: context,
                },
                &authority,
            )
        }))
        .unwrap_or_else(|_| Err(invalid("native preparation callback panicked")));
        authority.finish(result)?;
        if self.native_security_authority_binding()?.as_ref()
            != original.native_security_authority_binding()
        {
            return Err(invalid("native selection changed during preparation"));
        }
        self.validate_live_admission_authority_profile(Some(admission))
    }
}

pub(super) fn store_call<T>(
    call: impl FnOnce() -> Result<T, crate::admission_operation::AdmissionOperationStoreError>,
) -> Result<T, KernelError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
        .unwrap_or_else(|_| {
            Err(
                crate::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(
                    "native security store callback panicked".into(),
                ),
            )
        })
        .map_err(durable_store_error)
}

fn invalid(detail: &str) -> KernelError {
    KernelError::DurableAdmission(detail.into())
}
