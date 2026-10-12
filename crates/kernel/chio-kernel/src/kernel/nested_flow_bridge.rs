//! Session-bound nested interactions and their retained receipt evidence.

use super::*;

pub(super) struct SessionNestedFlowBridge<'a, C> {
    pub(super) clock: Arc<dyn chio_security_types::clock::Clock>,
    pub(super) sessions: &'a DashMap<SessionId, Arc<Session>>,
    pub(super) child_receipts: &'a mut Vec<super::effect_obligation::recovery::PendingChildReceipt>,
    pub(super) evidence_slot: &'a mut Option<super::effect_obligation::evidence::EvidenceSlot>,
    pub(super) kernel: &'a ChioKernel,
    pub(super) started_children: usize,
    pub(super) max_child_receipts: usize,
    pub(super) nested_interaction_observed: &'a std::sync::atomic::AtomicBool,
    pub(super) parent_context: &'a OperationContext,
    pub(super) allow_sampling: bool,
    pub(super) allow_sampling_tool_use: bool,
    pub(super) allow_elicitation: bool,
    pub(super) policy_hash: &'a str,
    pub(super) kernel_keypair: &'a Keypair,
    pub(super) client: &'a mut C,
}

impl<C> SessionNestedFlowBridge<'_, C> {
    fn reserve_child_receipt(
        &mut self,
        request_id: &RequestId,
        operation_kind: OperationKind,
    ) -> Result<(), KernelError> {
        if self.started_children >= self.max_child_receipts {
            return Err(KernelError::PostEffectEvidenceCapacity);
        }
        // Reserve the worst retained representation before beginning a child.
        // Six JSON bytes per control character bound diagnostic escaping.
        let diagnostic = "\0".repeat(512);
        let body = ChildRequestReceiptBody {
            id: "child-rcpt-00000000-0000-0000-0000-000000000000".into(),
            timestamp: 9_007_199_254_740_991,
            session_id: self.parent_context.session_id.clone(),
            parent_request_id: self.parent_context.request_id.clone(),
            request_id: request_id.clone(),
            operation_kind,
            terminal_state: OperationTerminalState::Incomplete {
                reason: diagnostic.clone(),
            },
            outcome_hash: "f".repeat(64),
            policy_hash: self.policy_hash.to_owned(),
            metadata: Some(
                serde_json::json!({ "outcome": "error", "message": diagnostic,
                "message_sha256": "f".repeat(64), "message_truncated": true }),
            ),
            kernel_key: self.kernel_keypair.public_key(),
        };
        let bytes = chio_core::canonical::canonical_json_bytes(&body)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
            .len()
            .checked_add(512)
            .ok_or(KernelError::PostEffectEvidenceCapacity)?;
        if self.evidence_slot.is_none() {
            let bytes = std::num::NonZeroUsize::new(bytes)
                .ok_or(KernelError::PostEffectEvidenceCapacity)?;
            *self.evidence_slot = Some(self.kernel.acquire_post_effect_evidence_slot(bytes)?);
        } else if let Some(slot) = self.evidence_slot.as_mut() {
            slot.reserve_bytes(bytes)?;
        }
        self.started_children += 1;
        Ok(())
    }
    fn mark_nested_interaction_observed(&self) {
        self.nested_interaction_observed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn ensure_parent_not_cancelled(&self) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        let request_id = &self.parent_context.request_id;
        let Some(parent) = session.inflight().get(request_id) else {
            return Err(KernelError::RequestCancelled {
                request_id: request_id.clone(),
                reason: "parent session request completed during nested dispatch".to_string(),
            });
        };
        if parent.cancellation_requested {
            return Err(KernelError::RequestCancelled {
                request_id: request_id.clone(),
                reason: parent.cancellation_reason.unwrap_or_else(|| {
                    "parent session request cancelled during nested dispatch".to_string()
                }),
            });
        }
        Ok(())
    }

    pub(super) fn latch_matching_cancellation<T>(
        &mut self,
        result: &Result<T, KernelError>,
        child_request_id: Option<&RequestId>,
    ) -> Result<(), KernelError> {
        let Err(KernelError::RequestCancelled { request_id, reason }) = result else {
            return Ok(());
        };
        if request_id != &self.parent_context.request_id
            && child_request_id.is_none_or(|child_request_id| request_id != child_request_id)
        {
            return Ok(());
        }
        session_from_map(self.sessions, &self.parent_context.session_id)?
            .request_cancellation_with_reason(request_id, reason)?;
        Ok(())
    }

    fn complete_child_request_with_receipt<T: serde::Serialize>(
        &mut self,
        child_context: &OperationContext,
        operation_kind: OperationKind,
        result: &Result<T, KernelError>,
    ) -> Result<(), KernelError> {
        let terminal_state = child_terminal_state(&child_context.request_id, result);
        let mut encoding_failed = false;
        let encoding_notice = || {
            serde_json::json!({
                "outcome": "result_encoding_unavailable",
                "encoding_error_code": "CHIO-KERNEL-RECEIPT-SIGNING-FAILED",
                "original_payload_omitted": true
            })
        };
        let payload = match child_outcome_payload(result) {
            Ok(payload) => payload,
            Err(_) => {
                encoding_failed = true;
                encoding_notice()
            }
        };
        let body = match prepare_child_request_receipt(
            self.policy_hash,
            self.kernel_keypair.public_key(),
            child_context,
            operation_kind,
            terminal_state.clone(),
            payload,
        ) {
            Ok(body) => body,
            Err(_) => {
                encoding_failed = true;
                prepare_child_request_receipt(
                    self.policy_hash,
                    self.kernel_keypair.public_key(),
                    child_context,
                    operation_kind,
                    terminal_state.clone(),
                    encoding_notice(),
                )?
            }
        };
        let index = self.child_receipts.len();
        self.child_receipts
            .push(super::effect_obligation::recovery::PendingChildReceipt::Unsigned(body));
        complete_session_request_with_terminal_state_in_sessions(
            self.sessions,
            &child_context.session_id,
            &child_context.request_id,
            terminal_state.clone(),
        )?;

        let now = self.clock.unix_millis()?;
        let Some(super::effect_obligation::recovery::PendingChildReceipt::Unsigned(body)) =
            self.child_receipts.get(index)
        else {
            return Err(KernelError::Internal(
                "nested child lost its unsigned evidence owner".into(),
            ));
        };
        let body = ChildRequestReceiptBody {
            timestamp: now.as_secs(),
            ..body.clone()
        };
        let signed = ChildRequestReceipt::sign(body, self.kernel_keypair)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        let child = self.child_receipts.get_mut(index).ok_or_else(|| {
            KernelError::Internal("nested child lost its reserved evidence position".into())
        })?;
        *child = super::effect_obligation::recovery::PendingChildReceipt::Signed(signed);
        if encoding_failed {
            tracing::warn!(request_id = %child_context.request_id, audit_fault = "child_outcome_encoding_unavailable",
                "child completed but its outcome could not be encoded");
            return Err(KernelError::ReceiptSigningFailed(
                "completed child outcome encoding is unavailable".into(),
            ));
        }
        Ok(())
    }
}

impl<C> Drop for SessionNestedFlowBridge<'_, C> {
    fn drop(&mut self) {
        if let Some(session) = self.sessions.get(&self.parent_context.session_id) {
            session.mark_request_dispatch_finished(&self.parent_context.request_id);
        }
    }
}

impl<C: NestedFlowClient> NestedFlowBridge for SessionNestedFlowBridge<'_, C> {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent_context.request_id
    }

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let result = self.client.poll_parent_cancellation(self.parent_context);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        self.ensure_parent_not_cancelled()?;
        let request_id = nested_child_request_id(&self.parent_context.request_id, "roots");
        self.reserve_child_receipt(&request_id, OperationKind::ListRoots)?;
        self.mark_nested_interaction_observed();
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            request_id,
            OperationKind::ListRoots,
            None,
            false,
        )?;

        let result = (|| {
            let session = session_from_map(self.sessions, &child_context.session_id)?;
            session.validate_context(&child_context)?;
            session.ensure_operation_allowed(OperationKind::ListRoots)?;
            if !session.peer_capabilities().supports_roots {
                return Err(KernelError::RootsNotNegotiated);
            }

            let roots = self
                .client
                .list_roots(self.parent_context, &child_context)?;
            session_from_map(self.sessions, &child_context.session_id)?
                .replace_roots(roots.clone());
            Ok(roots)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::ListRoots,
            &result,
        )?;

        result
    }

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        self.ensure_parent_not_cancelled()?;
        let request_id = nested_child_request_id(&self.parent_context.request_id, "sample");
        self.reserve_child_receipt(&request_id, OperationKind::CreateMessage)?;
        self.mark_nested_interaction_observed();
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            request_id,
            OperationKind::CreateMessage,
            None,
            true,
        )?;

        let result = (|| {
            validate_sampling_request_in_sessions(
                self.sessions,
                self.allow_sampling,
                self.allow_sampling_tool_use,
                &child_context,
                &operation,
            )?;
            self.client
                .create_message(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateMessage,
            &result,
        )?;

        result
    }

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        self.ensure_parent_not_cancelled()?;
        let request_id = nested_child_request_id(&self.parent_context.request_id, "elicit");
        self.reserve_child_receipt(&request_id, OperationKind::CreateElicitation)?;
        self.mark_nested_interaction_observed();
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            request_id,
            OperationKind::CreateElicitation,
            None,
            true,
        )?;

        let result = (|| {
            validate_elicitation_request_in_sessions(
                self.sessions,
                self.allow_elicitation,
                &child_context,
                &operation,
            )?;
            self.client
                .create_elicitation(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateElicitation,
            &result,
        )?;

        result
    }

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_elicitation_completed(self.parent_context, elicitation_id);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        if !session.is_resource_subscribed(uri) {
            return Ok(());
        }

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_resource_updated(self.parent_context, uri);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_resources_list_changed(self.parent_context);
        self.latch_matching_cancellation(&result, None)?;
        result
    }
}
