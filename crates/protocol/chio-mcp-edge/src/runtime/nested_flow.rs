use super::*;

#[cfg(test)]
#[path = "nested_flow_tests.rs"]
mod tests;

// One synchronous poll must return control to the upstream operation even when
// a host producer replenishes the accounted inbox during receipt persistence.
const MAX_CANCELLATION_POLL_MESSAGES: usize = 16;

pub(super) struct QueuedEdgeNestedFlowClient<'a, W> {
    pub(super) refusal_kernel: &'a ChioKernel,
    pub(super) refusal_context: &'a OperationContext,
    pub(super) held_reply_reservations: Vec<crate::ingress::FrameReservation>,
    pub(super) request_counter: &'a mut u64,
    pub(super) parent_progress_step: &'a mut u64,
    pub(super) parent_client_request_id: &'a Value,
    pub(super) parent_kernel_request_id: &'a RequestId,
    pub(super) pending_notifications: &'a mut Vec<Value>,
    pub(super) deferred_client_messages: &'a mut VecDeque<AccountedMessage>,
    pub(super) accepted_url_elicitations: &'a mut Vec<AcceptedUrlElicitation>,
    pub(super) logging_enabled: bool,
    pub(super) minimum_log_level: LogLevel,
    pub(super) related_task_id: Option<&'a str>,
    pub(super) admission: InboxAdmission,
    pub(super) clock: Arc<dyn chio_security_types::clock::Clock>,
    pub(super) expires_at: chio_security_types::clock::UnixMillis,
    pub(super) capability_deadline: Result<
        chio_security_types::clock::AuthorityDeadline,
        chio_security_types::clock::ClockError,
    >,
    pub(super) task_deadline: Option<chio_security_types::clock::AuthorityDeadline>,
    pub(super) client_rx: &'a mut mpsc::Receiver<ClientInbound>,
    pub(super) cancel_rx: &'a mut mpsc::Receiver<Value>,
    pub(super) writer: &'a mut W,
}

#[derive(Debug, Clone)]
pub(super) struct AcceptedUrlElicitation {
    pub(super) elicitation_id: String,
    pub(super) related_task_id: Option<String>,
}

impl<W: Write + Send> QueuedEdgeNestedFlowClient<'_, W> {
    fn check_poll_authority(&mut self) -> Result<(), chio_kernel::KernelError> {
        let reading = self.clock.read()?;
        self.capability_deadline
            .as_mut()
            .map_err(|error| *error)?
            .remaining(reading)?;
        if let Some(task) = self.task_deadline.as_mut() {
            task.remaining(reading)?;
        }
        Ok(())
    }

    fn emit_log(&mut self, level: LogLevel, logger: &str, data: Value) {
        if !self.logging_enabled || level < self.minimum_log_level {
            return;
        }

        self.pending_notifications
            .push(attach_related_task_meta_to_message(
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": level.as_str(),
                        "logger": logger,
                        "data": data,
                    }
                }),
                self.related_task_id,
            ));
    }

    fn send_client_request(
        &mut self,
        method: &str,
        params: Value,
        _child_request_id: &RequestId,
    ) -> Result<Value, chio_kernel::KernelError> {
        *self.request_counter = self
            .request_counter
            .checked_add(1)
            .ok_or(chio_security_types::clock::ClockError::Overflow)?;
        let request_id = format!("edge-client-{}", *self.request_counter);
        let request = attach_related_task_meta_to_message(
            json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }),
            self.related_task_id,
        );
        let _control = self
            .admission
            .begin_wait(json!(request_id))
            .map_err(|error| chio_kernel::KernelError::Internal(error.to_string()))?;
        let mut deadline = ClientReplyDeadline::new(
            self.clock.clone(),
            Some(self.expires_at),
            self.task_deadline,
        )
        .map_err(client_wait_error)?;
        write_jsonrpc_line(self.writer, &request)
            .map_err(|error| chio_kernel::KernelError::Internal(error.to_string()))?;

        loop {
            let message = deadline
                .receive(self.client_rx, &self.admission, |command| {
                    persist_host_refusal(self.refusal_kernel, self.refusal_context, command)
                })
                .map_err(client_wait_error)?;

            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    let message = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown JSON-RPC error");
                    return Err(chio_kernel::KernelError::Internal(message.to_string()));
                }

                let result = message.into_accounted_result().map_err(client_wait_error)?;
                let (value, reservation) = result.into_parts();
                self.held_reply_reservations.push(reservation);
                return Ok(value);
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(chio_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }

            if cancellation_matches_client_request(&message, self.parent_client_request_id) {
                return Err(chio_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }

            if message.get("method").is_some() {
                let explicit_task_cancel =
                    task_cancel_matches_related_task(&message, self.related_task_id);
                self.deferred_client_messages.push_back(message);
                if explicit_task_cancel {
                    return Err(chio_kernel::KernelError::RequestCancelled {
                        request_id: self.parent_kernel_request_id.clone(),
                        reason: explicit_task_cancel_reason().to_string(),
                    });
                }
                continue;
            }

            return Err(chio_kernel::KernelError::Internal(
                "outer MCP client sent an unexpected response while a nested flow was in flight"
                    .to_string(),
            ));
        }
    }

    fn flush_notifications(&mut self) -> Result<(), chio_kernel::KernelError> {
        for notification in std::mem::take(self.pending_notifications) {
            write_jsonrpc_line(self.writer, &notification)
                .map_err(|error| chio_kernel::KernelError::Internal(error.to_string()))?;
        }
        Ok(())
    }
}

impl<W: Write + Send> NestedFlowClient for QueuedEdgeNestedFlowClient<'_, W> {
    fn poll_parent_cancellation(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), chio_kernel::KernelError> {
        for _ in 0..MAX_CANCELLATION_POLL_MESSAGES {
            self.check_poll_authority()?;
            // Recheck cancellation between synchronous host commands, not only
            // before a drain that a concurrent producer can keep nonempty.
            if let Ok(message) = self.cancel_rx.try_recv() {
                if cancellation_matches_client_request(&message, self.parent_client_request_id) {
                    return Err(chio_kernel::KernelError::RequestCancelled {
                        request_id: self.parent_kernel_request_id.clone(),
                        reason: cancellation_reason(&message),
                    });
                }
                if task_cancel_matches_related_task(&message, self.related_task_id) {
                    return Err(chio_kernel::KernelError::RequestCancelled {
                        request_id: self.parent_kernel_request_id.clone(),
                        reason: explicit_task_cancel_reason().to_string(),
                    });
                }
                self.check_poll_authority()?;
                continue;
            }
            let Ok(inbound) = self.client_rx.try_recv() else {
                break;
            };
            let message = match inbound {
                ClientInbound::HostProtocolRefusal(command) => {
                    persist_host_refusal(self.refusal_kernel, self.refusal_context, command);
                    self.check_poll_authority()?;
                    continue;
                }
                ClientInbound::Accounted(message) => message,
                #[cfg(test)]
                ClientInbound::Message(value) => self
                    .admission
                    .admit_value(value)
                    .map_err(client_wait_error)?,
                ClientInbound::ParseError(error) => return Err(client_wait_error(error)),
                #[cfg(test)]
                ClientInbound::ReadError(error) => {
                    return Err(chio_kernel::KernelError::Internal(error))
                }
                #[cfg(test)]
                ClientInbound::Closed => break,
            };
            if cancellation_matches_client_request(&message, self.parent_client_request_id) {
                return Err(chio_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }
            if task_cancel_matches_related_task(&message, self.related_task_id) {
                self.deferred_client_messages.push_back(message);
                return Err(chio_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: explicit_task_cancel_reason().into(),
                });
            }
            self.deferred_client_messages.push_back(message);
            self.check_poll_authority()?;
        }
        self.check_poll_authority()?;
        Ok(())
    }

    fn list_roots(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, chio_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting client roots",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.roots",
            json!({
                "event": "roots_request_started",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
            }),
        );
        self.flush_notifications()?;

        let result =
            self.send_client_request("roots/list", json!({}), &child_context.request_id)?;
        let roots_value = result.get("roots").cloned().ok_or_else(|| {
            chio_kernel::KernelError::Internal("roots/list response missing 'roots'".to_string())
        })?;
        let roots: Vec<RootDefinition> = serde_json::from_value(roots_value).map_err(|error| {
            chio_kernel::KernelError::UntrustedInput(
                chio_core::canonical::UntrustedJsonError::Decode(error),
            )
        })?;

        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Received client roots",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.roots",
            json!({
                "event": "roots_request_completed",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "rootCount": roots.len(),
            }),
        );
        self.flush_notifications()?;

        Ok(roots)
    }

    fn create_message(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, chio_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting sampled message from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.sampling",
            json!({
                "event": "sampling_request_started",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "toolCount": operation.tools.len(),
            }),
        );
        self.flush_notifications()?;

        let params = serde_json::to_value(operation).map_err(|error| {
            chio_kernel::KernelError::Internal(format!(
                "failed to serialize sampling/createMessage params: {error}"
            ))
        })?;
        let result =
            self.send_client_request("sampling/createMessage", params, &child_context.request_id)?;
        let message: CreateMessageResult = serde_json::from_value(result).map_err(|error| {
            chio_kernel::KernelError::UntrustedInput(
                chio_core::canonical::UntrustedJsonError::Decode(error),
            )
        })?;

        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Received sampled message from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.sampling",
            json!({
                "event": "sampling_request_completed",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "model": message.model.clone(),
                "stopReason": message.stop_reason.clone(),
            }),
        );
        self.flush_notifications()?;

        Ok(message)
    }

    fn create_elicitation(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, chio_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting elicitation response from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.elicitation",
            json!({
                "event": "elicitation_request_started",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "mode": match operation {
                    CreateElicitationOperation::Form { .. } => "form",
                    CreateElicitationOperation::Url { .. } => "url",
                },
            }),
        );
        self.flush_notifications()?;

        let params = serde_json::to_value(operation).map_err(|error| {
            chio_kernel::KernelError::Internal(format!(
                "failed to serialize elicitation/create params: {error}"
            ))
        })?;
        let result =
            self.send_client_request("elicitation/create", params, &child_context.request_id)?;
        let elicitation: CreateElicitationResult =
            serde_json::from_value(result).map_err(|error| {
                chio_kernel::KernelError::UntrustedInput(
                    chio_core::canonical::UntrustedJsonError::Decode(error),
                )
            })?;
        capture_accepted_url_elicitation(
            self.accepted_url_elicitations,
            operation,
            &elicitation,
            self.related_task_id,
        );

        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Received elicitation response from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.elicitation",
            json!({
                "event": "elicitation_request_completed",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "action": &elicitation.action,
            }),
        );
        self.flush_notifications()?;

        Ok(elicitation)
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        elicitation_id: &str,
    ) -> Result<(), chio_kernel::KernelError> {
        self.pending_notifications
            .push(make_elicitation_completion_notification(
                elicitation_id,
                self.related_task_id,
            ));
        self.flush_notifications()
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        uri: &str,
    ) -> Result<(), chio_kernel::KernelError> {
        self.pending_notifications
            .push(attach_related_task_meta_to_message(
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {
                        "uri": uri,
                    }
                }),
                self.related_task_id,
            ));
        self.flush_notifications()
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), chio_kernel::KernelError> {
        self.pending_notifications
            .push(attach_related_task_meta_to_message(
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/list_changed",
                }),
                self.related_task_id,
            ));
        self.flush_notifications()
    }
}

fn client_wait_error(error: AdapterError) -> chio_kernel::KernelError {
    match error {
        AdapterError::Clock(error) => error.into(),
        other => chio_kernel::KernelError::Internal(other.to_string()),
    }
}
