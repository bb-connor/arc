//! Freeze start authority while original credentials and runtime custody are
//! still live. Replaying a committed context never refreshes this deadline.

use super::*;

impl ChioKernel {
    pub(super) fn freeze_caller_start_deadline(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        context: &DurableToolReturnContext,
        now: u64,
    ) -> Result<u64, KernelError> {
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(invalid("caller deadline must be frozen before capture"));
        }
        let original = admission
            .original_retained_request()
            .ok_or_else(|| invalid("caller deadline lost its original request"))?;
        // Retained request material deliberately omits credentials. Freeze the
        // deadline from the live presentation, then bind it to the original
        // operation without retaining the proof in the return snapshot.
        let prepared = self
            .prepare_dispatch_credentials(
                request,
                &request.capability,
                original.matching_grants_require_dpop(),
                now / 1000,
                admission.requires_execution_nonce(),
            )?
            .refresh()?;
        prepared.validate_origin(self, original)?;
        let nonce_binding = self.verified_bound_execution_nonce_time(admission, request, now)?;
        let mut deadline = prepared.valid_until_unix_ms(nonce_binding.as_ref())?;
        if let Some((_, validity)) = self.verify_owned_runtime_for_native_capture(
            admission,
            request,
            context.matched_grant_index,
            context.admitted_metadata.as_ref(),
        )? {
            deadline = deadline.min(validity.valid_until_unix_ms());
        }
        if deadline <= now || deadline > I_JSON_MAX_SAFE_INTEGER {
            return Err(invalid("caller start deadline is expired or out of range"));
        }
        Ok(deadline)
    }
}

impl CallerReturnWire {
    pub(super) fn valid_deadline_shape(&self) -> bool {
        self.schema == CALLER_RETURN_CONTEXT_SCHEMA
            && self.start_valid_until_unix_ms > self.frozen_at_unix_ms
            && self.start_valid_until_unix_ms <= I_JSON_MAX_SAFE_INTEGER
            && self.native_custody.as_ref().is_none_or(|custody| {
                self.start_valid_until_unix_ms == custody.valid_until_unix_ms()
            })
    }

    pub(super) fn start_deadline(&self) -> Result<u64, KernelError> {
        if self.valid_deadline_shape() {
            Ok(self.start_valid_until_unix_ms)
        } else {
            Err(invalid("caller context cannot acquire start authority"))
        }
    }
}
