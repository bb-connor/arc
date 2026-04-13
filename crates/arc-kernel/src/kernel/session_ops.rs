use super::*;

impl ArcKernel {
    pub fn open_session(
        &mut self,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> SessionId {
        self.session_counter += 1;
        let session_id = SessionId::new(format!("sess-{}", self.session_counter));

        info!(session_id = %session_id, agent_id = %agent_id, "opening session");
        self.sessions.insert(
            session_id.clone(),
            Session::new(session_id.clone(), agent_id, issued_capabilities),
        );

        session_id
    }

    /// Transition a session into the `ready` state once setup is complete.
    pub fn activate_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        self.session_mut(session_id)?.activate()?;
        Ok(())
    }

    /// Persist transport/session authentication context for a session.
    pub fn set_session_auth_context(
        &mut self,
        session_id: &SessionId,
        auth_context: SessionAuthContext,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.set_auth_context(auth_context);
        Ok(())
    }

    /// Persist peer capabilities negotiated at the edge for a session.
    pub fn set_session_peer_capabilities(
        &mut self,
        session_id: &SessionId,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .set_peer_capabilities(peer_capabilities);
        Ok(())
    }

    /// Replace the session's current root snapshot.
    pub fn replace_session_roots(
        &mut self,
        session_id: &SessionId,
        roots: Vec<RootDefinition>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.replace_roots(roots);
        Ok(())
    }

    /// Return the runtime's normalized root view for a session.
    pub fn normalized_session_roots(
        &self,
        session_id: &SessionId,
    ) -> Result<&[NormalizedRoot], KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .normalized_roots())
    }

    /// Return only the enforceable filesystem root paths for a session.
    pub fn enforceable_filesystem_root_paths(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<&str>, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .enforceable_filesystem_roots()
            .filter_map(NormalizedRoot::normalized_filesystem_path)
            .collect())
    }

    pub(crate) fn session_enforceable_filesystem_root_paths_owned(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<String>, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .enforceable_filesystem_roots()
            .filter_map(NormalizedRoot::normalized_filesystem_path)
            .map(str::to_string)
            .collect())
    }

    pub(crate) fn resource_path_within_root(candidate: &str, root: &str) -> bool {
        if candidate == root {
            return true;
        }

        if root == "/" {
            return candidate.starts_with('/');
        }

        candidate
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
    }

    pub(crate) fn resource_path_matches_session_roots(
        path: &str,
        session_roots: &[String],
    ) -> bool {
        if session_roots.is_empty() {
            return false;
        }

        session_roots
            .iter()
            .any(|root| Self::resource_path_within_root(path, root))
    }

    pub(crate) fn enforce_resource_roots(
        &self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<(), KernelError> {
        match operation.classify_uri_for_runtime() {
            ResourceUriClassification::NonFileSystem { .. } => Ok(()),
            ResourceUriClassification::EnforceableFileSystem {
                normalized_path, ..
            } => {
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                if Self::resource_path_matches_session_roots(&normalized_path, &session_roots) {
                    Ok(())
                } else {
                    let reason = if session_roots.is_empty() {
                        "no enforceable filesystem roots are available for this session".to_string()
                    } else {
                        format!(
                            "filesystem-backed resource path {normalized_path} is outside the negotiated roots"
                        )
                    };

                    Err(KernelError::ResourceRootDenied {
                        uri: operation.uri.clone(),
                        reason,
                    })
                }
            }
            ResourceUriClassification::UnenforceableFileSystem { reason, .. } => {
                Err(KernelError::ResourceRootDenied {
                    uri: operation.uri.clone(),
                    reason: format!(
                        "filesystem-backed resource URI could not be enforced: {reason}"
                    ),
                })
            }
        }
    }

    pub(crate) fn build_resource_read_deny_receipt(
        &mut self,
        operation: &ReadResourceOperation,
        reason: &str,
    ) -> Result<ArcReceipt, KernelError> {
        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "uri": &operation.uri,
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash resource read parameters: {error}"
            ))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &operation.capability.id,
            tool_name: "resources/read",
            server_id: "session",
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "session_roots".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                Some(serde_json::json!({
                    "resource": {
                        "uri": &operation.uri,
                    }
                })),
                receipt_attribution_metadata(&operation.capability, None),
            ),
            timestamp: current_unix_timestamp(),
        })?;

        self.record_arc_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Subscribe the session to update notifications for a concrete resource URI.
    pub fn subscribe_session_resource(
        &mut self,
        session_id: &SessionId,
        capability: &CapabilityToken,
        agent_id: &str,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.validate_non_tool_capability(capability, agent_id)?;

        if !capability_matches_resource_subscription(capability, uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: uri.to_string(),
            });
        }

        if !self.resource_exists(uri)? {
            return Err(KernelError::ResourceNotRegistered(uri.to_string()));
        }

        self.session_mut(session_id)?
            .subscribe_resource(uri.to_string());
        Ok(())
    }

    /// Remove a session-scoped resource subscription. Missing subscriptions are ignored.
    pub fn unsubscribe_session_resource(
        &mut self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.unsubscribe_resource(uri);
        Ok(())
    }

    /// Check whether a session currently holds a resource subscription.
    pub fn session_has_resource_subscription(
        &self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<bool, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .is_resource_subscribed(uri))
    }

    /// Mark a session as draining. New tool calls are rejected after this point.
    pub fn begin_draining_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.begin_draining()?;
        Ok(())
    }

    /// Close a session and clear transient session-scoped state.
    pub fn close_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.close()?;
        Ok(())
    }

    /// Inspect an existing session.
    pub fn session(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn resource_provider_count(&self) -> usize {
        self.resource_providers.len()
    }

    pub fn prompt_provider_count(&self) -> usize {
        self.prompt_providers.len()
    }

    /// Validate a session-scoped operation and register it as in flight.
    pub fn begin_session_request(
        &mut self,
        context: &OperationContext,
        operation_kind: OperationKind,
        cancellable: bool,
    ) -> Result<(), KernelError> {
        begin_session_request_in_sessions(&mut self.sessions, context, operation_kind, cancellable)
    }

    /// Construct and register a child request under an existing parent request.
    pub fn begin_child_request(
        &mut self,
        parent_context: &OperationContext,
        request_id: RequestId,
        operation_kind: OperationKind,
        progress_token: Option<ProgressToken>,
        cancellable: bool,
    ) -> Result<OperationContext, KernelError> {
        begin_child_request_in_sessions(
            &mut self.sessions,
            parent_context,
            request_id,
            operation_kind,
            progress_token,
            cancellable,
        )
    }

    /// Complete an in-flight session request.
    pub fn complete_session_request(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.complete_session_request_with_terminal_state(
            session_id,
            request_id,
            OperationTerminalState::Completed,
        )
    }

    /// Complete an in-flight session request with an explicit terminal state.
    pub fn complete_session_request_with_terminal_state(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) -> Result<(), KernelError> {
        complete_session_request_with_terminal_state_in_sessions(
            &mut self.sessions,
            session_id,
            request_id,
            terminal_state,
        )
    }

    /// Mark an in-flight session request as cancelled.
    pub fn request_session_cancellation(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .request_cancellation(request_id)
            .map_err(KernelError::from)
    }

    /// Validate whether a sampling child request is allowed for this session.
    pub fn validate_sampling_request(
        &self,
        context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<(), KernelError> {
        validate_sampling_request_in_sessions(
            &self.sessions,
            self.config.allow_sampling,
            self.config.allow_sampling_tool_use,
            context,
            operation,
        )
    }

    /// Validate whether an elicitation child request is allowed for this session.
    pub fn validate_elicitation_request(
        &self,
        context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<(), KernelError> {
        validate_elicitation_request_in_sessions(
            &self.sessions,
            self.config.allow_elicitation,
            context,
            operation,
        )
    }

    /// Evaluate a session-scoped tool call while allowing the target tool server to proxy
    /// negotiated nested flows back through a client transport owned by the edge.
    pub fn evaluate_tool_call_operation_with_nested_flow_client<C: NestedFlowClient>(
        &mut self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        self.begin_session_request(context, OperationKind::ToolCall, true)?;

        let request = ToolCallRequest {
            request_id: context.request_id.to_string(),
            capability: operation.capability.clone(),
            tool_name: operation.tool_name.clone(),
            server_id: operation.server_id.clone(),
            agent_id: context.agent_id.clone(),
            arguments: operation.arguments.clone(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let result = self.evaluate_tool_call_with_nested_flow_client(context, &request, client);
        let terminal_state = match &result {
            Ok(response) => response.terminal_state.clone(),
            Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == &context.request_id =>
            {
                self.session_mut(&context.session_id)?
                    .request_cancellation(&context.request_id)?;
                OperationTerminalState::Cancelled {
                    reason: reason.clone(),
                }
            }
            _ => OperationTerminalState::Completed,
        };
        self.complete_session_request_with_terminal_state(
            &context.session_id,
            &context.request_id,
            terminal_state,
        )?;
        result
    }

    /// Evaluate a normalized operation against a specific session.
    ///
    /// This is the higher-level entry point that future JSON-RPC or MCP edges
    /// should target. The current stdio loop normalizes raw frames into these
    /// operations before invoking the kernel.
    pub fn evaluate_session_operation(
        &mut self,
        context: &OperationContext,
        operation: &SessionOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        let operation_kind = operation.kind();
        let should_track_inflight = matches!(
            operation,
            SessionOperation::ToolCall(_)
                | SessionOperation::ReadResource(_)
                | SessionOperation::GetPrompt(_)
                | SessionOperation::Complete(_)
        );

        if should_track_inflight {
            self.begin_session_request(context, operation_kind, true)?;
        } else {
            let session = self.session_mut(&context.session_id)?;
            session.validate_context(context)?;
            session.ensure_operation_allowed(operation_kind)?;
        }

        let evaluation = match operation {
            SessionOperation::ToolCall(tool_call) => {
                let request = ToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability.clone(),
                    tool_name: tool_call.tool_name.clone(),
                    server_id: tool_call.server_id.clone(),
                    agent_id: context.agent_id.clone(),
                    arguments: tool_call.arguments.clone(),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                };
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                self.evaluate_tool_call_with_session_roots(&request, Some(session_roots.as_slice()))
                    .map(SessionOperationResponse::ToolCall)
            }
            SessionOperation::CreateMessage(_) => Err(KernelError::Internal(
                "sampling/createMessage must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::CreateElicitation(_) => Err(KernelError::Internal(
                "elicitation/create must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::ListRoots => {
                let roots = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .roots()
                    .to_vec();
                Ok(SessionOperationResponse::RootList { roots })
            }
            SessionOperation::ListResources => {
                let resources = self
                    .list_resources_for_session(&context.session_id)?
                    .into_iter()
                    .collect();
                Ok(SessionOperationResponse::ResourceList { resources })
            }
            SessionOperation::ReadResource(resource_read) => {
                self.evaluate_resource_read(context, resource_read)
            }
            SessionOperation::ListResourceTemplates => {
                let templates = self.list_resource_templates_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::ResourceTemplateList { templates })
            }
            SessionOperation::ListPrompts => {
                let prompts = self.list_prompts_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::PromptList { prompts })
            }
            SessionOperation::GetPrompt(prompt_get) => self
                .evaluate_prompt_get(context, prompt_get)
                .map(|prompt| SessionOperationResponse::PromptGet { prompt }),
            SessionOperation::Complete(complete) => self
                .evaluate_completion(context, complete)
                .map(|completion| SessionOperationResponse::Completion { completion }),
            SessionOperation::ListCapabilities => {
                let capabilities = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .capabilities()
                    .to_vec();

                Ok(SessionOperationResponse::CapabilityList { capabilities })
            }
            SessionOperation::Heartbeat => Ok(SessionOperationResponse::Heartbeat),
        };

        if should_track_inflight {
            let terminal_state = match &evaluation {
                Ok(SessionOperationResponse::ToolCall(response)) => response.terminal_state.clone(),
                _ => OperationTerminalState::Completed,
            };
            self.complete_session_request_with_terminal_state(
                &context.session_id,
                &context.request_id,
                terminal_state,
            )?;
        }

        evaluation
    }

    pub(crate) fn list_resources_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut resources = Vec::new();
        for provider in &self.resource_providers {
            resources.extend(provider.list_resources().into_iter().filter(|resource| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_resource_request(capability, &resource.uri).unwrap_or(false)
                })
            }));
        }

        Ok(resources)
    }

    pub(crate) fn resource_exists(&self, uri: &str) -> Result<bool, KernelError> {
        for provider in &self.resource_providers {
            if provider
                .list_resources()
                .iter()
                .any(|resource| resource.uri == uri)
            {
                return Ok(true);
            }

            if provider.read_resource(uri)?.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub(crate) fn list_resource_templates_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceTemplateDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut templates = Vec::new();
        for provider in &self.resource_providers {
            templates.extend(
                provider
                    .list_resource_templates()
                    .into_iter()
                    .filter(|template| {
                        session.capabilities().iter().any(|capability| {
                            capability_matches_resource_pattern(capability, &template.uri_template)
                                .unwrap_or(false)
                        })
                    }),
            );
        }

        Ok(templates)
    }

    pub(crate) fn evaluate_resource_read(
        &mut self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_resource_request(&operation.capability, &operation.uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: operation.uri.clone(),
            });
        }

        match self.enforce_resource_roots(context, operation) {
            Ok(()) => {}
            Err(KernelError::ResourceRootDenied { reason, .. }) => {
                let receipt = self.build_resource_read_deny_receipt(operation, &reason)?;
                return Ok(SessionOperationResponse::ResourceReadDenied { receipt });
            }
            Err(error) => return Err(error),
        }

        for provider in &self.resource_providers {
            if let Some(contents) = provider.read_resource(&operation.uri)? {
                return Ok(SessionOperationResponse::ResourceRead { contents });
            }
        }

        Err(KernelError::ResourceNotRegistered(operation.uri.clone()))
    }

    pub(crate) fn list_prompts_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<PromptDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut prompts = Vec::new();
        for provider in &self.prompt_providers {
            prompts.extend(provider.list_prompts().into_iter().filter(|prompt| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_prompt_request(capability, &prompt.name).unwrap_or(false)
                })
            }));
        }

        Ok(prompts)
    }

    pub(crate) fn evaluate_prompt_get(
        &self,
        context: &OperationContext,
        operation: &GetPromptOperation,
    ) -> Result<PromptResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_prompt_request(&operation.capability, &operation.prompt_name)? {
            return Err(KernelError::OutOfScopePrompt {
                prompt: operation.prompt_name.clone(),
            });
        }

        for provider in &self.prompt_providers {
            if let Some(prompt) =
                provider.get_prompt(&operation.prompt_name, operation.arguments.clone())?
            {
                return Ok(prompt);
            }
        }

        Err(KernelError::PromptNotRegistered(
            operation.prompt_name.clone(),
        ))
    }

    pub(crate) fn evaluate_completion(
        &self,
        context: &OperationContext,
        operation: &CompleteOperation,
    ) -> Result<CompletionResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        match &operation.reference {
            CompletionReference::Prompt { name } => {
                if !capability_matches_prompt_request(&operation.capability, name)? {
                    return Err(KernelError::OutOfScopePrompt {
                        prompt: name.clone(),
                    });
                }

                for provider in &self.prompt_providers {
                    if let Some(completion) = provider.complete_prompt_argument(
                        name,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::PromptNotRegistered(name.clone()))
            }
            CompletionReference::Resource { uri } => {
                if !capability_matches_resource_pattern(&operation.capability, uri)? {
                    return Err(KernelError::OutOfScopeResource { uri: uri.clone() });
                }

                for provider in &self.resource_providers {
                    if let Some(completion) = provider.complete_resource_argument(
                        uri,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::ResourceNotRegistered(uri.clone()))
            }
        }
    }
}
