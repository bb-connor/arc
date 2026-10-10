//! Session request ownership across cancellation, never dispatch authority.
use super::*;
use chio_log_redact::redacted;

pub(super) struct ToolRequestClaim<'kernel> {
    kernel: &'kernel ChioKernel,
    context: OperationContext,
    retained: Option<PendingThresholdApproval>,
    armed: bool,
    #[cfg(test)]
    before_restore_lock: Option<Box<dyn Fn() + Send + Sync + 'kernel>>,
}

impl<'kernel> ToolRequestClaim<'kernel> {
    pub(super) fn new(
        kernel: &'kernel ChioKernel,
        context: &OperationContext,
        retained: Option<PendingThresholdApproval>,
    ) -> Self {
        Self {
            kernel,
            context: context.clone(),
            retained,
            armed: true,
            #[cfg(test)]
            before_restore_lock: None,
        }
    }

    pub(super) fn existing_nonce_retry(
        kernel: &'kernel ChioKernel,
        context: &OperationContext,
    ) -> Self {
        // This branch only validates an existing nonce wait. It acquires no
        // exclusive session ownership that a dropped retry may cancel.
        Self {
            kernel,
            context: context.clone(),
            retained: None,
            armed: false,
            #[cfg(test)]
            before_restore_lock: None,
        }
    }

    pub(super) fn retained(&self) -> Option<PendingThresholdApproval> {
        self.retained.clone()
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }

    fn restore_or_cancel(&self) -> Result<(), KernelError> {
        let retained_or_finished = self.kernel.with_sessions_read(|sessions| {
            let session = session_from_map(sessions, &self.context.session_id)?;
            let Some(_request) = session.inflight().get(&self.context.request_id) else {
                return Ok(true);
            };
            #[cfg(test)]
            if let Some(checkpoint) = self.before_restore_lock.as_ref() {
                checkpoint();
            }
            // The cancellation decision and original opaque restoration share
            // the real request-map write lock. Every retry still revalidates
            // current durable authority, including post-dispatch replay state.
            session
                .restore_dropped_tool_request_claim(&self.context, self.retained.as_ref())
                .map_err(KernelError::from)
        })?;
        if retained_or_finished {
            return Ok(());
        }
        self.kernel.complete_session_request_with_terminal_state(
            &self.context.session_id,
            &self.context.request_id,
            OperationTerminalState::Cancelled {
                reason: "session tool evaluation dropped before completion".into(),
            },
        )
    }
}

impl Drop for ToolRequestClaim<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.restore_or_cancel() {
                warn!(request_id = %self.context.request_id,
                    reason = %redacted!(&error.to_string()),
                    "failed to release session request ownership after cancellation");
            }
        }
    }
}

#[cfg(test)]
impl ChioKernel {
    pub(crate) fn drop_threshold_claim_with_restore_checkpoint<'kernel>(
        &'kernel self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        checkpoint: impl Fn() + Send + Sync + 'kernel,
    ) -> Result<(), KernelError> {
        let mut claim = self.begin_or_resume_tool_request(context, operation, None)?;
        claim.before_restore_lock = Some(Box::new(checkpoint));
        drop(claim);
        Ok(())
    }
}
