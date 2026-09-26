//! Freeze start authority while original credentials and runtime custody are
//! still live. Replaying a committed context never refreshes this deadline.

use super::*;

impl ChioKernel {
    pub(super) fn freeze_caller_start_deadline(
        &self,
        admission: &DurableToolAdmission,
        context: &DurableToolReturnContext,
        now: u64,
    ) -> Result<u64, KernelError> {
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(invalid("caller deadline must be frozen before capture"));
        }
        let original = admission
            .original_retained_request()
            .ok_or_else(|| invalid("caller deadline lost its original request"))?;
        let mut request = original.request_for_revalidation().clone();
        request.execution_nonce = admission
            .issued_execution_nonce()
            .map(|reservation| reservation.signed_nonce().clone());
        let prepared = self
            .prepare_dispatch_credentials(
                &request,
                &request.capability,
                original.matching_grants_require_dpop(),
                now / 1000,
                admission.requires_execution_nonce(),
            )?
            .refresh()?;
        prepared.validate_origin(self, original)?;
        let mut deadline = prepared.valid_until_unix_ms()?;
        if let Some((_, validity)) = self.verify_owned_runtime_for_native_capture(
            admission,
            &request,
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
        match (self.schema.as_str(), self.start_valid_until_unix_ms) {
            (SCHEMA, Some(deadline)) => {
                deadline > self.frozen_at_unix_ms && deadline <= I_JSON_MAX_SAFE_INTEGER
            }
            (SCHEMA, None) | (_, Some(_)) => false,
            (_, None) => true,
        }
    }

    pub(super) fn start_deadline(&self) -> Result<u64, KernelError> {
        match self.schema.as_str() {
            SCHEMA if self.valid_deadline_shape() => self
                .start_valid_until_unix_ms
                .ok_or_else(|| invalid("caller start deadline is absent")),
            NATIVE_CALLER_CONTEXT_SCHEMA => self
                .native_custody
                .as_ref()
                .map(NativeCallerReleaseCustodyV1::valid_until_unix_ms)
                .ok_or_else(|| invalid("native caller start custody is absent")),
            _ => Err(invalid(
                "legacy caller context cannot acquire start authority",
            )),
        }
    }
}
