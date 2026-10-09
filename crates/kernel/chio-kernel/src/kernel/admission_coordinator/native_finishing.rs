//! Prepare native and Process finishing debt before the first pending purpose.
use super::native_acquisition::store_call;
use super::*;
use crate::native_finishing::{
    NativeInitialFinishingAuthority, NativeInitialFinishingContext,
    NativeProcessFinishingSourceProvider, OriginalNativeFinishingPreparationData,
};

impl ChioKernel {
    /// Hold the configured native mutation sequencer for the full source,
    /// preservation, Process commit and actual readback boundary.
    pub fn run_original_process_current_write(
        &self,
        provider: &dyn crate::native_finishing::NativeProcessCurrentWriteProvider,
    ) -> Result<(), KernelError> {
        self.original_process_current_write_enforcement()?
            .run(provider)
    }

    pub fn original_process_current_write_enforcement(
        &self,
    ) -> Result<crate::native_finishing::NativeProcessCurrentWriteEnforcement, KernelError> {
        Ok(
            crate::native_finishing::NativeProcessCurrentWriteEnforcement::from_actual_runtime(
                self.durable_runtime()?,
            ),
        )
    }

    pub(crate) fn prepare_original_native_finishing_before_first_purpose(
        &self,
        request: &ToolCallRequest,
        context: Option<&SecurityInvocationContext>,
        admission: Option<&DurableToolAdmission>,
        provider: Option<&dyn NativeProcessFinishingSourceProvider>,
        requested_now: u64,
    ) -> Result<(), KernelError> {
        let Some(admission) = admission else {
            return Ok(());
        };
        let Some(original) = admission.retained_request.as_ref() else {
            // Ordinary durable admission need not retain an original request.
            // The actual selected Native authority may never take that path.
            return if self.native_security_authority_binding()?.is_some() {
                Err(invalid("native finishing lost its retained original"))
            } else {
                Ok(())
            };
        };
        // Ordinary calls and genuinely unselected original profiles retain
        // their existing admission behavior. Fresh native capture independently
        // requires its original full account and actual purpose loan.
        if original.native_output_retention().is_none() {
            return Ok(());
        }
        let binding = original
            .native_security_authority_binding()
            .ok_or_else(|| invalid("native finishing lost its original binding"))?;
        let context =
            context.ok_or_else(|| invalid("native finishing requires its actual host context"))?;
        original
            .validate_request_material(request)
            .and_then(|()| original.validate_native_security_context(context))
            .and_then(|()| original.validate_bounded_native_materializer())
            .map_err(durable_store_error)?;
        if self.native_security_authority_binding()?.as_ref() != Some(binding) {
            return Err(invalid(
                "native finishing selection changed before preparation",
            ));
        }
        let runtime = self.durable_runtime()?;
        let guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(requested_now);
        let (current, physical_original) = store_call(|| {
            runtime.store.load_retained_tool_request(
                admission.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("native finishing physical original is absent"))?;
        if current != admission.operation
            || physical_original.canonical_bytes() != original.canonical_bytes()
        {
            return Err(invalid("native finishing original changed at preparation"));
        }
        let lease = self.claim_admission_recovery(&current, now)?;
        let authority = NativeInitialFinishingAuthority::from_original_callback(
            NativeInitialFinishingContext {
                operation: &current,
                lease: &lease,
                original: &physical_original,
                binding,
                context,
                request,
                trusted_now_unix_ms: now,
            },
            crate::native_finishing::NativeProcessBankProofIssuer::in_configured_writer(
                runtime.store.as_ref(),
                &runtime.fence,
                now,
                &guard,
            )
            .map_err(durable_store_error)?,
        )
        .map_err(durable_store_error)?;
        let configured_receipt_store = self
            .receipt_store
            .as_deref()
            .ok_or_else(|| invalid("native financing requires its configured receipt owner"))?;
        let authority = match self.native_receipt_store_registration.as_ref() {
            Some(registration) => {
                if !std::ptr::addr_eq(configured_receipt_store, registration.receipt_store()) {
                    return Err(invalid(
                        "native receipt registration lost its configured sink",
                    ));
                }
                authority.with_configured_receipt_registration(registration)
            }
            // Ordinary sink installation supplies no concrete Native identity.
            // The Store retains its missing Receipt producer refusal.
            None => authority,
        };
        // This guard is not released between either database's COMMIT and the
        // authentic confirmation. The Store never calls back into Kernel locks.
        let preparation = store_call(|| {
            runtime
                .store
                .prepare_original_native_finishing(&authority, provider)
        })?;
        match preparation {
            OriginalNativeFinishingPreparationData::Prepared { process_source } => {
                match (provider, process_source) {
                    (Some(provider), Some(_)) => store_call(|| {
                        runtime
                            .store
                            .enroll_original_native_finishing_process(provider, &authority)
                    })?,
                    (None, None) => (),
                    _ => return Err(invalid("native Prepared omitted its original Process debt")),
                }
                store_call(|| {
                    runtime
                        .store
                        .confirm_original_native_finishing(&authority, provider)
                })?;
            }
            OriginalNativeFinishingPreparationData::Confirmed {
                original_process_source,
                original_process_account_digest,
            } => {
                match (
                    provider,
                    original_process_source,
                    original_process_account_digest,
                ) {
                    (Some(provider), Some(_), Some(account)) => store_call(|| {
                        runtime.store.restore_original_native_finishing_process(
                            provider, &account, &authority,
                        )
                    })?,
                    (None, None, None) => (),
                    _ => {
                        return Err(invalid(
                            "confirmed native account omitted original Process custody",
                        ))
                    }
                }
            }
        }
        if self.native_security_authority_binding()?.as_ref() != Some(binding) {
            return Err(invalid(
                "native finishing selection changed during preparation",
            ));
        }
        Ok(())
    }
}

impl DurableAdmissionRuntime {
    pub(crate) fn run_original_process_current_write_scope(
        &self,
        provider: &dyn crate::native_finishing::NativeProcessCurrentWriteProvider,
    ) -> Result<(), KernelError> {
        let _guard = self.lock_mutations()?;
        let now = self.refresh_trusted_time(current_unix_timestamp_ms());
        let issuer = crate::native_finishing::NativeProcessBankProofIssuer::in_configured_writer(
            self.store.as_ref(),
            &self.fence,
            now,
            &_guard,
        )
        .map_err(durable_store_error)?;
        store_call(|| {
            self.store
                .commit_original_process_current_write(provider, &issuer, &self.fence, now)
        })
    }
}

fn invalid(detail: &str) -> KernelError {
    KernelError::DurableAdmission(detail.into())
}
