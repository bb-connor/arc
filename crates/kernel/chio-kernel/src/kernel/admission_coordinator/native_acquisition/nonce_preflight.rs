//! Strict nonce preflight is a separate callback with no dispatch-join handle.
use super::*;
use crate::admission_operation::NativeSecurityNoncePreflightJoinRequestV1;

/// A call-scoped handle for pre-issuance taint only. It cannot authorize dispatch,
/// consume a nonce, or expose the dispatch-phase join authority it privately uses
/// for lease and acknowledgement bookkeeping.
pub struct NativeSecurityNoncePreflightJoinAuthority<'a>(NativeSecurityFlowJoinAuthority<'a>);

impl fmt::Debug for NativeSecurityNoncePreflightJoinAuthority<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSecurityNoncePreflightJoinAuthority")
            .finish_non_exhaustive()
    }
}

impl NativeSecurityNoncePreflightJoinAuthority<'_> {
    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        self.0.binding()
    }

    fn finish(self, result: Result<(), KernelError>) -> Result<(), KernelError> {
        self.0.finish_with(result, |owner, runtime, now| {
            let (current, history) = store_call(|| {
                runtime.store.load_native_security_nonce_preflight_join(
                    owner.admission.operation.binding().operation_id(),
                    &runtime.fence,
                    now,
                )
            })?
            .ok_or_else(|| invalid("native nonce preflight readback is absent"))?;
            if current != owner.admission.operation {
                return Err(invalid(
                    "native nonce preflight changed its original operation",
                ));
            }
            let history =
                history.ok_or_else(|| invalid("native nonce preflight has no recorded join"))?;
            history.validate().map_err(durable_store_error)?;
            Ok(history.join)
        })
    }

    /// Resolve classified input with all inherited labels under the actual
    /// Prepared lease. One attempted join is allowed, including failed calls.
    pub fn join_input(
        &self,
        input_label: InformationLabel,
    ) -> Result<FlowStateSnapshot, KernelError> {
        self.0.attempt(|| {
            let input = NativeSecurityNoncePreflightJoinRequestV1::new(
                self.0.admission.operation.binding().operation_id().clone(),
                self.0.key(),
                input_label,
            )
            .map_err(durable_store_error)?;
            self.0.with_join_custody(|runtime, lease, now| {
                let operation = &self.0.admission.operation;
                let acknowledged = store_call(|| {
                    runtime.store.join_native_security_nonce_preflight(
                        operation,
                        lease,
                        &self.0.binding,
                        self.0.context,
                        &input,
                        now,
                    )
                });
                // Inspect independently even after failure or panic. A durable
                // write does not turn a lost acknowledgement into success.
                let history = store_call(|| {
                    runtime.store.load_native_security_nonce_preflight_join(
                        operation.binding().operation_id(),
                        &runtime.fence,
                        now,
                    )
                });
                let acknowledged = acknowledged?;
                let (current, history) =
                    history?.ok_or_else(|| invalid("native nonce preflight operation readback is absent"))?;
                let history = history
                    .ok_or_else(|| invalid("native nonce preflight preparation has no recorded join"))?;
                if current != *operation
                    || history != acknowledged
                    || history.input != input
                    || history.join.binding != self.0.binding
                    || history.join.operation_id != *operation.binding().operation_id()
                {
                    return Err(invalid(
                        "native nonce preflight acknowledgement differs from original intent history",
                    ));
                }
                history.validate().map_err(durable_store_error)?;
                let snapshot = history.join.snapshot.clone();
                self.0.confirm(history.join)?;
                Ok(snapshot)
            })
        })
    }
}

impl ChioKernel {
    pub(crate) fn run_native_nonce_preflight_preparation(
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
        if original.authority_profile().is_none()
            || admission.operation.state() != AdmissionOperationState::Prepared
            || !admission.requires_execution_nonce()
            || request.execution_nonce.is_some()
            || admission
                .operation
                .execution_nonce_issuance_digest()
                .is_some()
            || admission
                .operation
                .execution_nonce_preflight_digest()
                .is_some()
            || admission.operation.dispatch_commit().is_some()
            || self.security_pre_dispatch_policy != SecurityPreDispatchPolicy::Enforce
        {
            return Err(invalid(
                "native nonce preflight requires original pre-issuance authority",
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
        let authority =
            NativeSecurityNoncePreflightJoinAuthority(NativeSecurityFlowJoinAuthority {
                kernel: self,
                admission,
                binding,
                context,
                requested_now: now,
                attempted: Cell::new(false),
                failed: Cell::new(false),
                confirmed: RefCell::new(None),
            });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.prepare_native_nonce_preflight(
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
