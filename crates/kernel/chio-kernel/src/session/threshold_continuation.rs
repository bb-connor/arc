//! In-memory ownership of a pending threshold request, not authorization.

#[cfg(not(loom))]
use super::*;

/// Opaque binding for retrying an original session request after collecting votes.
/// Only the kernel can install it, from its own pending response. The kernel must
/// still revalidate all current authorization and durable admission on every retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingThresholdApproval {
    proposal_digest: String,
    operation_digest: String,
}

#[cfg(not(loom))]
impl PendingThresholdApproval {
    pub(crate) fn new(proposal_digest: String, operation_digest: String) -> Self {
        Self {
            proposal_digest,
            operation_digest,
        }
    }
}

#[cfg(not(loom))]
impl Session {
    pub(crate) fn mark_threshold_approval_pending(
        &self,
        context: &OperationContext,
        binding: PendingThresholdApproval,
    ) -> Result<(), SessionError> {
        self.validate_context(context)?;
        let mut requests = self.inflight.write_requests();
        let request = requests.get_mut(&context.request_id).ok_or_else(|| {
            SessionError::ThresholdApprovalRetryMismatch {
                request_id: context.request_id.clone(),
            }
        })?;
        if request.operation_kind != OperationKind::ToolCall
            || request
                .pending_threshold_approval
                .as_ref()
                .is_some_and(|prior| prior != &binding)
        {
            return Err(SessionError::ThresholdApprovalRetryMismatch {
                request_id: context.request_id.clone(),
            });
        }
        request.pending_execution_nonce_id = None;
        request.pending_threshold_approval = Some(binding);
        Ok(())
    }

    pub(crate) fn claim_threshold_approval_retry(
        &self,
        context: &OperationContext,
        binding: &PendingThresholdApproval,
    ) -> Result<(), SessionError> {
        self.validate_context(context)?;
        // Match initial admission's lock order: lifecycle, authentication, then
        // request ownership. Reauthentication and draining cannot race between
        // validation and the claim, and no lock escapes into kernel evaluation.
        let state = self.read_inner();
        if !operation_allowed_for_state(state.state, OperationKind::ToolCall) {
            return Err(SessionError::OperationNotAllowed {
                session_id: self.id.clone(),
                operation: OperationKind::ToolCall.as_str(),
                state: state.state.as_str(),
            });
        }
        let result = self.auth_state.with_current(|authority| {
            let mut requests = self.inflight.write_requests();
            let request = requests.get_mut(&context.request_id).ok_or_else(|| {
                SessionError::ThresholdApprovalRetryMismatch {
                    request_id: context.request_id.clone(),
                }
            })?;
            if request.operation_kind != OperationKind::ToolCall
                || request.session_anchor_id != authority.session_anchor.id()
                || request.parent_request_id != context.parent_request_id
                || request.progress_token != context.progress_token
                || request.cancellation_requested
                || request.pending_execution_nonce_id.is_some()
                || request.pending_threshold_approval.as_ref() != Some(binding)
            {
                return Err(SessionError::ThresholdApprovalRetryMismatch {
                    request_id: context.request_id.clone(),
                });
            }
            // A competing retry sees an active request, not another wait. A new
            // pending response may reinstall the binding after evaluation.
            request.pending_threshold_approval = None;
            Ok(())
        });
        drop(state);
        result
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn threshold_retry_claim_holds_lifecycle_and_authentication_until_commit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = SessionId::new("threshold-claim-locks");
        let session = Session::new(session_id.clone(), "agent".into(), Vec::new());
        session.activate()?;
        let context = OperationContext::new(session_id, RequestId::new("request"), "agent".into());
        session.track_request(&context, OperationKind::ToolCall, true)?;
        let binding = PendingThresholdApproval::new("a".repeat(64), "b".repeat(64));
        session.mark_threshold_approval_pending(&context, binding.clone())?;
        std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            // Pause the claim immediately before its atomic mutation. This
            // probes real production locks, not a replica of the state machine.
            let requests = session.inflight.write_requests();
            let claim = scope.spawn(|| session.claim_threshold_approval_retry(&context, &binding));
            let deadline = Instant::now() + std::time::Duration::from_secs(5);
            let mut authority_stable = false;
            while Instant::now() < deadline {
                let lifecycle_held = matches!(
                    session.inner.try_write(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                let authentication_held = matches!(
                    session.auth_state.current.try_write(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                if lifecycle_held && authentication_held {
                    authority_stable = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            drop(requests);
            claim
                .join()
                .map_err(|_| "threshold claim thread panicked")??;
            assert!(
                authority_stable,
                "retry claim released session authority before committing ownership"
            );
            assert!(session
                .inflight()
                .get(&context.request_id)
                .ok_or("request missing")?
                .pending_threshold_approval
                .is_none());
            Ok(())
        })
    }
}
