//! Original capture hands one live owner to the common durable finalizer.
//! Historical readback can validate that owner, but can never construct it.
use super::*;
use crate::kernel::credential_reservation::DispatchCredentialReservation;
use crate::tool_outcome::DurableSecurityReleaseContext;

pub(super) struct CapturedLifecycle {
    pub context: DurableToolReturnContext,
    pub operation: AdmissionOperationV1,
    pub observation: NativeSecurityFlowObservationV1,
    pub original_digest: String,
    pub dispatch_commitment_id: RecordId,
    pub valid_until_unix_ms: u64,
}

struct NativeReleaseOwner {
    captured: AdmissionOperationV1,
    context: SecurityInvocationContext,
}

impl SecurityRequestLifecyclePermit for NativeReleaseOwner {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        Err(invalid(
            "native release requires the original durable output",
        ))
    }

    fn ensure_final_release_with_output(
        self: Box<Self>,
        context: &DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        let current = context.operation();
        if current.binding() != self.captured.binding()
            || current.dispatch_commit() != self.captured.dispatch_commit()
            || current.native_dispatch_ledger_digest()
                != self.captured.native_dispatch_ledger_digest()
            || current.state() != AdmissionOperationState::Finalizing
            || context.security_context() != &self.context
        {
            return Err(invalid(
                "native release owner differs from original capture",
            ));
        }
        // The common release path has independently joined the exact guarded
        // output under the original finalization lease before consuming us.
        // Its physical checkpoint still revalidates that lease and output.
        Ok(())
    }
}

impl CapturedLifecycle {
    pub(super) fn finish(
        self,
        kernel: &ChioKernel,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<(DurableToolReturnContext, SecurityRequestLifecycleHandle), KernelError> {
        let original = admission
            .original_retained_request()
            .ok_or_else(|| invalid("native lifecycle lost its original request"))?;
        kernel.validate_original_authority_profile(original)?;
        if kernel.native_security_authority_binding()?.as_ref() != Some(self.observation.binding())
        {
            return Err(invalid(
                "native lifecycle lost its original authority selection",
            ));
        }
        kernel.validate_security_invocation_context_binding(
            request,
            self.context.security_invocation_context.as_ref(),
            None,
        )?;
        kernel.check_revocation(&request.capability)?;
        if kernel.is_emergency_stopped() {
            return Err(invalid("native lifecycle denied by emergency stop"));
        }
        self.context.validate_binding(admission, request)?;
        let runtime = kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        if now >= self.valid_until_unix_ms || admission.operation() != &self.operation {
            return Err(invalid("native lifecycle capture expired or changed"));
        }
        let (operation, retained) = store_call(|| {
            runtime.store.load_retained_tool_request(
                self.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("native lifecycle physical capture is absent"))?;
        if operation != self.operation
            || sha256_hex(retained.canonical_bytes()) != self.original_digest
        {
            return Err(invalid("native lifecycle capture readback changed"));
        }
        let observed = observe(
            runtime,
            self.observation.binding(),
            self.observation.key(),
            now,
        )?;
        if observed.snapshot() != self.observation.snapshot()
            || observed.stored_context_generation() != self.observation.stored_context_generation()
            || runtime.refresh_trusted_time(now) >= self.valid_until_unix_ms
        {
            return Err(invalid(
                "native lifecycle lost current flow or capture time",
            ));
        }
        let security_context = self
            .context
            .security_invocation_context
            .as_ref()
            .ok_or_else(|| invalid("native lifecycle lost frozen security context"))?;
        let canonical = canonical_live_request(request)?;
        let dispatch = SecurityPreDispatchContext {
            request,
            canonical_request: &canonical,
            security_context,
            dispatch_commitment_id: &self.dispatch_commitment_id,
        };
        let owner = SecurityRequestLifecycleHandle::new(
            Box::new(NativeReleaseOwner {
                captured: self.operation,
                context: security_context.clone(),
            }),
            &dispatch,
        );
        Ok((self.context, owner))
    }
}

impl ChioKernel {
    /// Shared ordinary/nested handoff. A native path cannot use generic capture
    /// or return successfully without an original, privately created owner.
    pub(crate) fn freeze_and_commit_evaluation_dispatch<'kernel>(
        &'kernel self,
        admission: &mut DurableToolAdmission,
        budget: &mut PreExecutionBudgetMutation,
        credentials: &mut DispatchCredentialReservation<'kernel>,
        input: DurableToolReturnContextInput<'_>,
    ) -> Result<
        (
            DurableToolReturnContext,
            Option<SecurityRequestLifecycleHandle>,
        ),
        DurableDispatchCommitError,
    > {
        if admission
            .original_native_security_authority_binding()
            .is_none()
        {
            return self
                .freeze_and_commit_durable_dispatch(
                    admission,
                    &input.request.capability,
                    budget,
                    input,
                )
                .map(|context| (context, None));
        }
        let rejected = DurableDispatchCommitError::RejectedBeforeCommit;
        let hook = self
            .security_pre_dispatch_hook
            .as_ref()
            .ok_or_else(|| rejected(invalid("native lifecycle hook is absent")))?;
        let security_context = input
            .security_invocation_context
            .ok_or_else(|| rejected(invalid("native lifecycle security context is absent")))?;
        let request = input.request;
        let metadata = input.extra_receipt_metadata.clone();
        let mut authority = NativeSecurityDispatchCaptureAuthority {
            kernel: self,
            request,
            context: security_context,
            admission,
            budget,
            credentials,
            metadata: metadata.as_ref(),
            attempted: false,
            failed: false,
            return_input: Some(input),
            captured_lifecycle: None,
        };
        let result = crate::kernel::security_dispatch::callback("native dispatch capture", || {
            hook.commit_native_dispatch(&mut authority)
        });
        let attempted = authority.attempted;
        let result = result.and_then(|()| {
            if authority.failed {
                return Err(invalid(
                    "native lifecycle callback suppressed capture failure",
                ));
            }
            let captured = authority.captured_lifecycle.take().ok_or_else(|| {
                invalid("native lifecycle callback did not capture original custody")
            })?;
            crate::kernel::security_dispatch::callback("native lifecycle handoff", || {
                captured.finish(self, authority.admission, request)
            })
        });
        result
            .map(|(context, owner)| (context, Some(owner)))
            .map_err(|error| {
                if attempted {
                    DurableDispatchCommitError::CommitUnconfirmed(error)
                } else {
                    rejected(error)
                }
            })
    }
}

/// This is a deadline extracted from the exact policy bytes that the physical
/// capture independently validates, not policy evaluation or authentication.
pub(super) fn policy_deadline(bytes: &[u8]) -> Result<u64, KernelError> {
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err(invalid("native lifecycle policy exceeds its bound"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("native lifecycle policy is invalid"))?;
    if !matches!(
        value.get("schema").and_then(serde_json::Value::as_str),
        Some("chio.native-flow-dispatch-policy.v1" | "chio.native-flow-dispatch-policy.v2")
    ) {
        return Err(invalid("native lifecycle policy schema is unsupported"));
    }
    value
        .pointer("/inputs/valid_until_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .filter(|time| *time > 0 && *time < (1_u64 << 53))
        .ok_or_else(|| invalid("native lifecycle policy deadline is absent or invalid"))
}
