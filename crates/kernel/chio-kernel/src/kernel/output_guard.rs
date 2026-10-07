use super::*;

#[derive(Clone, Copy)]
enum OutputGuardPhase {
    Release,
    BeforeDurableRecord,
}

struct SelectedOutputGuard<'kernel> {
    guard: &'kernel dyn Guard,
    check_raw: bool,
}

/// Role probes finish before any contractual validator. The borrowed selection
/// carries the original context, not independent settlement authority.
pub(super) struct DurableOutputGuards<'kernel, 'request> {
    context: GuardContext<'request>,
    ordinary: Vec<SelectedOutputGuard<'kernel>>,
    contractual: Vec<SelectedOutputGuard<'kernel>>,
}

impl DurableOutputGuards<'_, '_> {
    pub(super) fn validate_ordinary_output(
        &self,
        output: &ToolServerOutput,
        post_invocation_applied: bool,
    ) -> Result<(), KernelError> {
        for selected in &self.ordinary {
            if post_invocation_applied || selected.check_raw {
                validate_output_guard(selected.guard, &self.context, output)?;
            }
        }
        Ok(())
    }

    /// No role probe or ordinary validator can discard an earlier rejection.
    /// Evaluate every selected checker and combine its refusal or panic.
    pub(super) fn contractual_rejection(
        &self,
        output: &ToolServerOutput,
        post_invocation_applied: bool,
    ) -> bool {
        let mut rejected = false;
        for selected in &self.contractual {
            if post_invocation_applied || selected.check_raw {
                rejected |= validate_output_guard(selected.guard, &self.context, output).is_err();
            }
        }
        rejected
    }
}

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
            OutputGuardPhase::Release,
        )
    }

    /// Ordinary guards must accept before raw-return persistence. Contractual
    /// checkers run only after fallible durable output preparation finishes.
    pub(super) fn validate_output_before_durable_record(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        self.check_guarded_output(
            request,
            matched_grant_index,
            output,
            false,
            OutputGuardPhase::BeforeDurableRecord,
        )
    }

    pub(crate) fn has_checked_output_contract(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
    ) -> Result<bool, KernelError> {
        let context = output_guard_context(request, matched_grant_index);
        let mut required = false;
        for guard in self.guards.iter() {
            required |= checked_output_contract(guard.as_ref(), &context)?;
        }
        Ok(required)
    }

    pub(super) fn prepare_durable_output_guards<'kernel, 'request>(
        &'kernel self,
        request: &'request ToolCallRequest,
        matched_grant_index: usize,
    ) -> Result<DurableOutputGuards<'kernel, 'request>, KernelError> {
        let context = output_guard_context(request, matched_grant_index);
        let mut ordinary = Vec::new();
        let mut contractual = Vec::new();
        for guard in self.guards.iter() {
            let zero_charge = checked_output_contract(guard.as_ref(), &context)?;
            let check_raw = self.post_invocation_pipeline.is_empty()
                || !std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    guard.requires_exact_released_output(&context)
                }))
                .map_err(|_| {
                    KernelError::GuardDenied(
                        "guard output applicability panicked (fail-closed)".to_owned(),
                    )
                })?;
            let selected = SelectedOutputGuard {
                guard: guard.as_ref(),
                check_raw,
            };
            if zero_charge {
                contractual.push(selected);
            } else {
                ordinary.push(selected);
            }
        }
        Ok(DurableOutputGuards {
            context,
            ordinary,
            contractual,
        })
    }

    fn check_guarded_output(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        output: &ToolServerOutput,
        post_invocation_applied: bool,
        phase: OutputGuardPhase,
    ) -> Result<(), KernelError> {
        let context = output_guard_context(request, matched_grant_index);
        for guard in self.guards.iter() {
            if !post_invocation_applied
                && !self.post_invocation_pipeline.is_empty()
                && guard.requires_exact_released_output(&context)
            {
                // The raw return is not the release boundary with a frozen
                // transform plan. Validate its exact released value later.
                continue;
            }
            if matches!(phase, OutputGuardPhase::BeforeDurableRecord)
                && checked_output_contract(guard.as_ref(), &context)?
            {
                continue;
            }
            validate_output_guard(guard.as_ref(), &context, output)?;
        }
        Ok(())
    }
}

fn output_guard_context(request: &ToolCallRequest, matched_grant_index: usize) -> GuardContext<'_> {
    GuardContext {
        request,
        scope: &request.capability.scope,
        agent_id: &request.agent_id,
        server_id: &request.server_id,
        session_filesystem_roots: None,
        matched_grant_index: Some(matched_grant_index),
        security_context: None,
    }
}

fn checked_output_contract(
    guard: &dyn Guard,
    context: &GuardContext<'_>,
) -> Result<bool, KernelError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        guard.output_rejection_is_zero_charge(context)
    }))
    .map_err(|_| {
        KernelError::GuardDenied("checked-output contract panicked (fail-closed)".to_owned())
    })
}

fn validate_output_guard(
    guard: &dyn Guard,
    context: &GuardContext<'_>,
    output: &ToolServerOutput,
) -> Result<(), KernelError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        guard.validate_output_before_release(context, output)
    })) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(KernelError::GuardDenied(format!(
            "guard output validation failed: {error}"
        ))),
        Err(_) => Err(KernelError::GuardDenied(
            "guard output validation panicked (fail-closed)".to_owned(),
        )),
    }
}
