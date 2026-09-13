//! Capture actual invocation custody and preserve its original live handoff.
use super::*;
use crate::kernel::credential_reservation::DispatchCredentialReservation;

#[path = "capture_ack.rs"]
mod acknowledgement;
#[path = "lifecycle.rs"]
mod lifecycle;

/// Kernel-owned boundary borrowing the live evaluation's actual budget and
/// credential reservation. No public constructor accepts historical records.
pub struct NativeSecurityDispatchCaptureAuthority<'a, 'kernel> {
    kernel: &'kernel ChioKernel,
    request: &'a ToolCallRequest,
    context: &'a SecurityInvocationContext,
    admission: &'a mut DurableToolAdmission,
    budget: &'a mut PreExecutionBudgetMutation,
    credentials: &'a mut DispatchCredentialReservation<'kernel>,
    metadata: Option<&'a serde_json::Value>,
    attempted: bool,
    failed: bool,
    return_input: Option<DurableToolReturnContextInput<'a>>,
    captured_lifecycle: Option<lifecycle::CapturedLifecycle>,
}

impl<'a, 'kernel: 'a> NativeSecurityDispatchCaptureAuthority<'a, 'kernel> {
    pub fn prepare_egress(&self) -> Result<PreparedNativeSecurityEgress<'a>, KernelError> {
        self.kernel.prepare_native_security_egress(
            self.admission.operation().binding().operation_id(),
            self.request,
            self.context,
        )
    }

    pub fn grant_index(&self) -> Result<usize, KernelError> {
        self.budget
            .durable_hold_result()
            .map(|hold| hold.grant_index)
            .ok_or_else(|| invalid("native capture requires the actual invocation hold"))
    }

    /// Retain on uncertain commit, then bind the real reservation and policy to
    /// the dedicated physical transaction. A successful result records capture
    /// only. It is never a tool permit or authorization to reacquire resources.
    pub fn capture(
        &mut self,
        prepared: PreparedNativeSecurityEgress<'_>,
        ledger: &crate::admission_operation::NativeSecurityDispatchLedgerRecordV1,
        policy_json: &[u8],
    ) -> Result<crate::receipt_store::AdmissionBudgetCapture, KernelError> {
        let result = self.capture_once(prepared, ledger, policy_json);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn capture_once(
        &mut self,
        prepared: PreparedNativeSecurityEgress<'_>,
        ledger: &crate::admission_operation::NativeSecurityDispatchLedgerRecordV1,
        policy_json: &[u8],
    ) -> Result<crate::receipt_store::AdmissionBudgetCapture, KernelError> {
        let grant_index = self.grant_index()?;
        if self.attempted {
            return Err(invalid(
                "native capture authority already attempted capture",
            ));
        }
        if !std::ptr::eq(prepared.kernel, self.kernel)
            || !std::ptr::eq(prepared.request, self.request)
            || prepared.operation != *self.admission.operation()
        {
            return Err(invalid(
                "native capture preparation belongs to another live evaluation",
            ));
        }
        let mut frozen = self
            .return_input
            .take()
            .map(|input| {
                if input.matched_grant_index != grant_index {
                    return Err(invalid("native lifecycle replaced the selected grant"));
                }
                self.kernel.freeze_durable_tool_return_context(
                    self.admission,
                    DurableToolReturnContextInput {
                        security_invocation_context: Some(&prepared.context),
                        security_release_required: true,
                        trusted_now_unix_ms: current_unix_timestamp_ms()
                            .max(input.trusted_now_unix_ms),
                        ..input
                    },
                )
            })
            .transpose()?;
        if let Some(context) = frozen.as_mut() {
            context.bind_native_dispatch(&ledger.record_digest)?;
        }
        // From this point, a callback failure or lost acknowledgement cannot
        // justify refunding quota or releasing one-shot credential custody.
        self.attempted = true;
        self.credentials.retain_if_dropped()?;
        let proof = self.credentials.verify_native_dispatch(
            self.admission,
            self.request,
            grant_index,
            self.metadata,
        )?;
        let credentials_until = proof.valid_until_unix_ms();
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        // The physical transaction rechecks the original operation, authority,
        // observation, journal, credentials and deadline together. Do not
        // discard this live handle and reconstruct one through historical reads.
        let lease = self
            .kernel
            .claim_admission_recovery(self.admission.operation(), now)?;
        let valid_until = credentials_until
            .min(lease.untrusted_claim().expires_at_unix_ms())
            .min(lifecycle::policy_deadline(policy_json)?);
        let caller_frame = if self
            .admission
            .operation()
            .provider_attempt()
            .is_some_and(ProviderAttemptBindingV1::is_native_caller_report)
        {
            let context = frozen
                .as_ref()
                .ok_or_else(|| invalid("native caller requires frozen return custody"))?;
            let custody = crate::admission_operation::NativeCallerReleaseCustodyV1::prepare(
                &prepared.original,
                ledger,
                &prepared.context,
                valid_until,
            )
            .map_err(durable_store_error)?;
            self.kernel.frame_caller_return_context_with_native(
                self.admission,
                context,
                now,
                Some(custody),
            )?
        } else {
            None
        };
        let charge = self
            .budget
            .durable_hold_result_mut()
            .ok_or_else(|| invalid("native capture lost its actual invocation hold"))?;
        let request = BudgetCaptureInvocationRequest {
            capability_id: self.request.capability.id.clone(),
            grant_index,
            hold_id: charge.budget_hold_id.clone(),
            event_id: charge.capture_invocation_event_id(),
            trusted_time: None,
            authority: Some(runtime.authority()),
        };
        let expected_request = request.clone();
        let capture = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let capture = crate::receipt_store::AdmissionNativeDispatchCapture {
                custody: prepared.command_context(&lease, now),
                request,
                credentials: &proof,
                ledger,
                policy_json,
            };
            if let Some(frame) = caller_frame.as_ref() {
                runtime
                    .store
                    .capture_native_caller_invocation_and_commit_dispatch(capture, frame)
            } else {
                runtime
                    .store
                    .capture_native_invocation_and_commit_dispatch(capture)
            }
        }))
        .map_err(|_| invalid("native capture callback panicked; commitment is unconfirmed"))?
        .map_err(|error| invalid(&error.to_string()))?;
        let mut attachments = vec![AdmissionAttachment::NativeDispatchLedgerDigest(
            ledger.record_digest.clone(),
        )];
        if let Some(frame) = caller_frame.as_ref() {
            attachments.push(AdmissionAttachment::CallerDispatchContextDigest(
                frame.digest().clone(),
            ));
        }
        let command = AdmissionOperationCommand::new(
            self.admission.operation().binding().operation_id().clone(),
            self.admission.operation().version(),
            lease,
            attachments,
            Some(AdmissionOperationState::DispatchCommitted),
            None,
            None,
        )?;
        let expected = self
            .admission
            .operation()
            .apply_command(&command, now)?
            .into_operation();
        let mutation = acknowledgement::verify(
            &capture,
            &expected,
            &expected_request,
            &charge.authorize_metadata,
        )?;
        // The acknowledgement is accepted only after independent physical
        // readback. An error still remains unconfirmed, even if recovery later
        // finds a committed row. It cannot authorize a second live capture.
        let loaded = store_call(|| {
            runtime.store.load_retained_tool_request(
                expected.binding().operation_id(),
                &runtime.fence,
                runtime.refresh_trusted_time(now),
            )
        })?
        .ok_or_else(|| invalid("native capture readback is absent"))?;
        if loaded.0 != expected || loaded.1.canonical_bytes() != prepared.original.canonical_bytes()
        {
            return Err(invalid(
                "native capture acknowledgement differs from physical readback",
            ));
        }
        let physical = store_call(|| {
            runtime.store.load_native_dispatch_capture(
                expected.binding().operation_id(),
                &runtime.fence,
                runtime.refresh_trusted_time(now),
            )
        })?
        .ok_or_else(|| invalid("native capture budget readback is absent"))?;
        if physical != capture {
            return Err(invalid(
                "native capture acknowledgement differs from committed budget readback",
            ));
        }
        if let Some(context) = frozen {
            self.captured_lifecycle = Some(lifecycle::CapturedLifecycle {
                context,
                operation: expected.clone(),
                observation: prepared.observation.clone(),
                original_digest: sha256_hex(prepared.original.canonical_bytes()),
                dispatch_commitment_id: prepared.dispatch_commitment_id.clone(),
                valid_until_unix_ms: valid_until,
            });
        }
        self.admission.operation = expected;
        charge.invocation_capture = Some(Box::new(mutation.clone()));
        Ok(capture)
    }
}

/// Default-off qualification observer. It always stops before connector use,
/// including after a successful physical capture.
#[cfg(feature = "admission-test-support")]
pub type NativeSecurityCaptureCheckpointHook = Arc<
    dyn Fn(&mut NativeSecurityDispatchCaptureAuthority<'_, '_>) -> Result<(), KernelError>
        + Send
        + Sync,
>;

#[cfg(feature = "admission-test-support")]
pub(crate) struct NativeCaptureCheckpointInput<'a, 'kernel> {
    pub request: &'a ToolCallRequest,
    pub context: Option<&'a SecurityInvocationContext>,
    pub admission: Option<&'a mut DurableToolAdmission>,
    pub budget: &'a mut PreExecutionBudgetMutation,
    pub credentials: &'a mut DispatchCredentialReservation<'kernel>,
    pub metadata: Option<&'a serde_json::Value>,
}

#[cfg(feature = "admission-test-support")]
impl ChioKernel {
    pub fn install_native_capture_checkpoint_hook(
        &mut self,
        hook: NativeSecurityCaptureCheckpointHook,
    ) {
        self.native_capture_checkpoint_hook = Some(hook);
    }

    pub(crate) fn reach_native_capture_checkpoint<'a, 'kernel>(
        &'kernel self,
        input: NativeCaptureCheckpointInput<'a, 'kernel>,
    ) -> Option<DurableDispatchCommitError> {
        let NativeCaptureCheckpointInput {
            request,
            context,
            admission,
            budget,
            credentials,
            metadata,
        } = input;
        let hook = self.native_capture_checkpoint_hook.as_ref()?;
        let admission = admission?;
        admission.original_native_security_authority_binding()?;
        let Some(context) = context else {
            return Some(DurableDispatchCommitError::RejectedBeforeCommit(invalid(
                "native capture checkpoint lost its security context",
            )));
        };
        let mut authority = NativeSecurityDispatchCaptureAuthority {
            kernel: self,
            request,
            context,
            admission,
            budget,
            credentials,
            metadata,
            attempted: false,
            failed: false,
            return_input: None,
            captured_lifecycle: None,
        };
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(&mut authority)))
                .unwrap_or_else(|_| Err(invalid("native capture checkpoint panicked")));
        let error = result.err().unwrap_or_else(|| {
            invalid("native capture checkpoint complete; execution remains unsupported")
        });
        Some(if authority.attempted {
            DurableDispatchCommitError::CommitUnconfirmed(error)
        } else {
            DurableDispatchCommitError::RejectedBeforeCommit(error)
        })
    }
}
