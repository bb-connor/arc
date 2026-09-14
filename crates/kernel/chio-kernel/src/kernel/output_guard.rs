use super::*;

impl ChioKernel {
    /// Re-run output-aware guard checks over the exact value that is about to
    /// cross the kernel boundary. Any error or panic denies fail-closed.
    pub(crate) fn validate_guarded_output(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        output: &ToolServerOutput,
        post_invocation_applied: bool,
    ) -> Result<(), KernelError> {
        self.check_guarded_output(
            request,
            matched_grant_index,
            output,
            post_invocation_applied,
            false,
        )
        .map(|_| ())
    }

    pub(crate) fn has_checked_output_contract(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
    ) -> Result<bool, KernelError> {
        let context = GuardContext {
            request,
            scope: &request.capability.scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots: None,
            matched_grant_index: Some(matched_grant_index),
        };
        let mut required = false;
        for guard in self.guards.iter() {
            required |= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guard.output_rejection_is_zero_charge(&context)
            }))
            .map_err(|_| {
                KernelError::GuardDenied(
                    "checked-output contract panicked (fail-closed)".to_owned(),
                )
            })?;
        }
        Ok(required)
    }

    /// Return true only for a rejection covered by a trusted zero-charge
    /// contract. Ordinary errors still fail closed without releasing a hold.
    pub(crate) fn check_guarded_output(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        output: &ToolServerOutput,
        post_invocation_applied: bool,
        allow_contractual_denial: bool,
    ) -> Result<bool, KernelError> {
        let context = GuardContext {
            request,
            scope: &request.capability.scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots: None,
            matched_grant_index: Some(matched_grant_index),
        };
        let mut rejected = false;
        for guard in self.guards.iter() {
            if !post_invocation_applied
                && !self.post_invocation_pipeline.is_empty()
                && guard.requires_exact_released_output(&context)
            {
                // The raw durable return is not the release boundary when a
                // frozen transform plan exists. Persist it, then validate this
                // guard against the replayed post-transform value before any
                // terminal receipt or response is produced.
                continue;
            }
            let validation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guard.validate_output_before_release(&context, output)
            }));
            if !matches!(validation, Ok(Ok(()))) && allow_contractual_denial {
                let zero_charge = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    guard.output_rejection_is_zero_charge(&context)
                }))
                .unwrap_or(false);
                if zero_charge {
                    rejected = true;
                    continue;
                }
            }
            match validation {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard output validation failed: {error}"
                    )));
                }
                Err(_) => {
                    return Err(KernelError::GuardDenied(
                        "guard output validation panicked (fail-closed)".to_owned(),
                    ));
                }
            }
        }
        Ok(rejected)
    }
}
