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

impl ChioKernel {
    /// Settle the original account after its Process member committed its
    /// reconciliation. The physical owner reads the Process journal back
    /// through the concrete source; no caller DATA can settle an account.
    pub fn settle_original_native_finishing(
        &self,
        provider: &dyn NativeProcessFinishingSourceProvider,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        store_call(|| {
            runtime.store.settle_original_native_finishing_process(
                provider,
                self.native_receipt_store_registration.as_ref(),
                &runtime.fence,
                now,
            )
        })
    }

    /// Settle a native-only account once its terminal projection and receipt
    /// are retained. Accounts with a Process member wait for reconciliation.
    pub(in crate::kernel) fn settle_native_finishing_after_terminal(
        &self,
        operation_id: &crate::admission_operation::AdmissionOperationId,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        store_call(|| {
            runtime.store.settle_native_finishing_after_terminal(
                operation_id,
                self.native_receipt_store_registration.as_ref(),
                &runtime.fence,
                now,
            )
        })
    }
}

impl ChioKernel {
    /// A native original's receipt is retained under its prepaid ReceiptSink
    /// purpose by the physical owner; every other receipt keeps the ordinary
    /// durable path. The receipt writer never takes a Kernel lock, so the
    /// mutation sequencer is held across the sink append and the spend.
    pub(in crate::kernel) fn materialize_admission_receipt(
        &self,
        admission: &DurableToolAdmission,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), KernelError> {
        let native = admission
            .original_retained_request()
            .is_some_and(|original| original.native_output_retention().is_some());
        if !native {
            return self.materialize_durable_admission_receipt(receipt);
        }
        let registration = self
            .native_receipt_store_registration
            .as_ref()
            .ok_or_else(|| invalid("native receipt requires its registered sink"))?;
        let pending_visible_at_ms = self
            .settlement_observer
            .as_ref()
            .map(|_| current_unix_timestamp_ms());
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        store_call(|| {
            runtime.store.materialize_native_finishing_receipt(
                admission.operation.binding().operation_id(),
                receipt,
                pending_visible_at_ms,
                Some(registration),
                &runtime.fence,
                now,
            )
        })
    }
}

impl ChioKernel {
    /// Startup reconciliation retains each native original's missing receipt
    /// under its prepaid purpose and returns the receipts that keep the
    /// ordinary durable projection.
    pub(in crate::kernel) fn reconcile_native_finishing_receipts(
        &self,
        receipts: &[chio_core::receipt::body::ChioReceipt],
    ) -> Result<Vec<chio_core::receipt::body::ChioReceipt>, KernelError> {
        let Some(registration) = self.native_receipt_store_registration.as_ref() else {
            return Ok(receipts.to_vec());
        };
        let runtime = self.durable_runtime()?;
        let pending_visible_at_ms = self
            .settlement_observer
            .as_ref()
            .map(|_| current_unix_timestamp_ms());
        let mut ordinary = Vec::new();
        for receipt in receipts {
            let _guard = runtime.lock_mutations()?;
            let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
            let native = store_call(|| {
                runtime.store.reconcile_native_finishing_receipt(
                    receipt,
                    pending_visible_at_ms,
                    registration,
                    &runtime.fence,
                    now,
                )
            })?;
            if !native {
                ordinary.push(receipt.clone());
            }
        }
        Ok(ordinary)
    }

    /// After receipt reconciliation, settle every native-only account whose
    /// terminal and receipt are retained.
    pub(in crate::kernel) fn settle_native_finishing_at_startup(&self) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        store_call(|| {
            runtime.store.settle_native_finishing_at_startup(
                self.native_receipt_store_registration.as_ref(),
                &runtime.fence,
                now,
            )
        })
    }
}

impl DurableAdmissionRuntime {
    /// The configured store attaches its finishing bank to the registered sink.
    pub(crate) fn attach_native_receipt_sink(
        &self,
        registration: &crate::receipt_store::NativeReceiptStoreRegistration,
    ) -> Result<(), crate::admission_operation::AdmissionOperationStoreError> {
        self.store.attach_native_receipt_sink(registration)
    }

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
