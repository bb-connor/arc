// The A2A edge server, its deferred-task state, and the explicit
// compatibility-only passthrough wrapper.

#[derive(Clone)]
struct DeferredSecurityContextAuthority {
    session_id: SessionId,
    authority: Arc<dyn SecurityInvocationContextAuthority>,
}

#[derive(Clone)]
struct DeferredA2aTask {
    owner_agent_id: String,
    owner_session_id: SessionId,
    request: CrossProtocolExecutionRequest,
    security_context_authority: Option<DeferredSecurityContextAuthority>,
    trusted_peer_negotiation: TrustedPeerNegotiation,
    response: TaskResponse,
    expires_at_ms: u64,
}

/// The A2A edge server.
///
/// Wraps a set of Chio tool manifests and exposes them as A2A skills.
pub struct ChioA2aEdge {
    config: A2aEdgeConfig,
    manifest_registry: chio_manifest::VerifiedManifestRegistry,
    skills: Vec<A2aSkillEntry>,
    skill_fidelity: BTreeMap<String, BridgeFidelity>,
    /// Maps skill ID to authoritative target binding metadata.
    skill_bindings: BTreeMap<String, SkillBinding>,
    /// Maps ambiguous unqualified tool names to the qualified published IDs.
    ambiguous_skill_ids: BTreeMap<String, Vec<String>>,
    tasks: BTreeMap<String, DeferredA2aTask>,
    deferred_security_context_authorities: BTreeMap<String, DeferredSecurityContextAuthority>,
    trusted_peer_negotiation: TrustedPeerNegotiation,
}

/// Explicit compatibility-only surface for direct A2A passthrough behavior.
///
/// This wrapper exists so non-authoritative flows are opt-in and visually
/// distinct from the default receipt-bearing kernel path.
#[cfg(any(test, feature = "compatibility-surface"))]
pub struct ChioA2aEdgeCompatibility<'a> {
    edge: &'a mut ChioA2aEdge,
}

fn validate_execution_context(execution: &A2aKernelExecutionContext) -> Result<(), A2aEdgeError> {
    validate_execution_agent_id(&execution.agent_id)?;
    if let Some(security_context) = execution.security_context.as_ref() {
        validate_security_context_session(security_context, &execution.session_id)?;
    }
    if execution.approval_token.is_some() && !execution.approval_tokens.is_empty() {
        return Err(A2aEdgeError::InvalidRequest(
            "approval_token and approval_tokens must not both be supplied".to_string(),
        ));
    }
    if execution.approval_tokens.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "approval token set exceeds the protocol ceiling of {MAX_THRESHOLD_APPROVAL_TOKENS}"
        )));
    }
    if let Some(authorization) = &execution.supplemental_authorization {
        authorization
            .validate()
            .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    }
    Ok(())
}

fn refresh_deferred_a2a_security_context(
    request: &mut CrossProtocolExecutionRequest,
    execution: &A2aKernelExecutionContext,
    owner_session_id: &SessionId,
) -> Result<(), A2aEdgeError> {
    if &execution.session_id != owner_session_id {
        return Err(A2aEdgeError::InvalidRequest(
            "deferred task is not owned by the authenticated session".to_string(),
        ));
    }
    if request.authenticated_session_id.as_ref() != Some(owner_session_id) {
        return Err(A2aEdgeError::InvalidRequest(
            "deferred task authenticated session binding changed before dispatch".to_string(),
        ));
    }
    if request.agent_id != execution.agent_id {
        return Err(A2aEdgeError::InvalidRequest(
            "deferred task agent binding changed before dispatch".to_string(),
        ));
    }
    let retained_capability = chio_core::canonical_json_bytes(&request.capability)
        .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    let presented_capability = chio_core::canonical_json_bytes(&execution.capability)
        .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    if retained_capability != presented_capability {
        return Err(A2aEdgeError::InvalidRequest(
            "deferred task capability binding changed before dispatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_security_context_session(
    security_context: &SecurityInvocationContext,
    authenticated_session_id: &SessionId,
) -> Result<(), A2aEdgeError> {
    if security_context.as_v1().session_id().as_str() != authenticated_session_id.as_str() {
        return Err(A2aEdgeError::InvalidRequest(
            "authoritative security context does not match the authenticated session".to_string(),
        ));
    }
    Ok(())
}

fn validate_execution_agent_id(agent_id: &str) -> Result<(), A2aEdgeError> {
    if agent_id.trim().is_empty() {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution agent_id must not be empty".to_string(),
        ));
    }
    if agent_id.trim() != agent_id {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution agent_id must not include leading or trailing whitespace".to_string(),
        ));
    }
    if agent_id.chars().any(|character| character.is_control()) {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution agent_id must not include control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_deferred_a2a_task_owner(
    owner_agent_id: &str,
    owner_session_id: &SessionId,
    execution: &A2aKernelExecutionContext,
) -> Result<(), A2aEdgeError> {
    if owner_agent_id != execution.agent_id {
        return Err(A2aEdgeError::InvalidRequest(
            "task is not owned by the current agent".to_string(),
        ));
    }
    if owner_session_id != &execution.session_id {
        return Err(A2aEdgeError::InvalidRequest(
            "task is not owned by the authenticated session".to_string(),
        ));
    }
    Ok(())
}

impl ChioA2aEdge {
    /// Create a new A2A edge from registered-key, policy, and topology admitted manifests.
    pub fn new(
        config: A2aEdgeConfig,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, A2aEdgeError> {
        let manifests = registry
            .verified_manifests()
            .map(|signed| signed.manifest.clone())
            .collect();
        Self::new_internal(config, manifests, Some(registry))
    }

    #[cfg(test)]
    pub(crate) fn new_from_unverified_internal(
        config: A2aEdgeConfig,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, A2aEdgeError> {
        Self::new_internal(config, manifests, None)
    }

    fn new_internal(
        config: A2aEdgeConfig,
        manifests: Vec<ToolManifest>,
        registry: Option<&chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<Self, A2aEdgeError> {
        config.validate_for_agent_card()?;

        let mut skills = Vec::new();
        let mut skill_fidelity = BTreeMap::new();
        let mut skill_bindings = BTreeMap::new();
        let mut ambiguous_skill_ids = BTreeMap::new();
        let mut tool_name_counts = BTreeMap::new();
        let mut published_id_counts = BTreeMap::new();

        for manifest in &manifests {
            chio_manifest::validate_manifest(manifest)?;
        }

        for manifest in &manifests {
            for tool in &manifest.tools {
                *tool_name_counts.entry(tool.name.clone()).or_insert(0usize) += 1;
            }
        }

        for manifest in &manifests {
            for tool in &manifest.tools {
                let security = match registry {
                    Some(registry) => registry
                        .bridge_security(&manifest.server_id, &tool.name)
                        .ok_or_else(|| {
                            A2aEdgeError::InvalidRequest(format!(
                                "verified manifest registry has no admitted security for {}/{}",
                                manifest.server_id, tool.name
                            ))
                        })?,
                    None => BridgeSecurityMetadata::from_tool(tool),
                };
                let mut skill_candidate = build_skill_candidate(
                    manifest,
                    tool,
                    tool_name_counts.get(&tool.name).copied().unwrap_or(0) > 1,
                    security,
                )?;

                let published_id_count = published_id_counts
                    .entry(skill_candidate.published_id.clone())
                    .or_insert(0usize);
                *published_id_count += 1;
                if *published_id_count > 1 {
                    skill_candidate.published_id =
                        format!("{}#{}", skill_candidate.published_id, published_id_count);
                    skill_candidate.display_name =
                        format!("{} #{}", skill_candidate.display_name, published_id_count);
                    skill_candidate
                        .tags
                        .push("chio:ordinal-qualified".to_string());
                    skill_candidate.description = format!(
                        "{} This published id is ordinal-qualified because multiple manifests expose the same server-qualified tool id.",
                        skill_candidate.description
                    );
                }

                if let Some(alias) = &skill_candidate.lookup_alias {
                    ambiguous_skill_ids
                        .entry(alias.clone())
                        .or_insert_with(Vec::new)
                        .push(skill_candidate.published_id.clone());
                }

                skill_fidelity.insert(
                    skill_candidate.published_id.clone(),
                    skill_candidate.fidelity.clone(),
                );
                if skill_candidate.fidelity.published_by_default() {
                    skills.push(A2aSkillEntry {
                        id: skill_candidate.published_id.clone(),
                        name: skill_candidate.display_name.clone(),
                        description: skill_candidate.description.clone(),
                        tags: skill_candidate.tags.clone(),
                        examples: None,
                        input_modes: vec!["text".to_string()],
                        output_modes: vec!["text".to_string()],
                        bridge_fidelity: skill_candidate.fidelity.clone(),
                    });
                }

                if let Some(binding) = skill_candidate.binding {
                    skill_bindings.insert(skill_candidate.published_id, binding);
                }
            }
        }

        for qualified_ids in ambiguous_skill_ids.values_mut() {
            qualified_ids.sort();
            qualified_ids.dedup();
        }

        for (tool_name, qualified_ids) in &ambiguous_skill_ids {
            skill_fidelity.insert(
                tool_name.clone(),
                BridgeFidelity::Unsupported {
                    reason: format!(
                        "skill id collides across manifests; use one of the qualified ids: {}",
                        qualified_ids.join(", ")
                    ),
                },
            );
        }

        skills.sort_by(|left, right| left.id.cmp(&right.id));

        Ok(Self {
            config,
            manifest_registry: registry.cloned().unwrap_or_default(),
            skills,
            skill_fidelity,
            skill_bindings,
            ambiguous_skill_ids,
            tasks: BTreeMap::new(),
            deferred_security_context_authorities: BTreeMap::new(),
            trusted_peer_negotiation: TrustedPeerNegotiation::default(),
        })
    }

    /// Install the authenticated local/peer feature intersection used for
    /// extension-bearing A2A admission. The A2A message body cannot modify it.
    pub fn set_peer_protocol_negotiation(
        &mut self,
        local_advertised: &CapabilityNegotiation,
        peer_advertised: &CapabilityNegotiation,
    ) -> Result<(), A2aEdgeError> {
        self.trusted_peer_negotiation =
            TrustedPeerNegotiation::from_advertised_intersection(local_advertised, peer_advertised)
                .map_err(A2aEdgeError::InvalidRequest)?;
        Ok(())
    }

    fn resolve_skill_binding(&self, skill_id: &str) -> Result<SkillBinding, A2aEdgeError> {
        if let Some(binding) = self.skill_bindings.get(skill_id) {
            return Ok(binding.clone());
        }

        if let Some(qualified_ids) = self.ambiguous_skill_ids.get(skill_id) {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "skill id '{skill_id}' is ambiguous across manifests; use one of: {}",
                qualified_ids.join(", ")
            )));
        }

        Err(A2aEdgeError::ToolNotFound(skill_id.to_string()))
    }

    #[cfg(any(test, feature = "compatibility-surface"))]
    fn jsonrpc_stream_not_supported(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": "message/stream is not supported on the compatibility A2A surface"
            }
        })
    }

    fn jsonrpc_error_response(id: Value, error: A2aEdgeError) -> Value {
        let (code, message) = match error {
            A2aEdgeError::ToolNotFound(message) | A2aEdgeError::InvalidRequest(message) => {
                (-32602, message)
            }
            other => (-32603, other.to_string()),
        };

        Self::jsonrpc_error_payload(id, code, &message)
    }

    fn jsonrpc_error_payload(id: Value, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
            }
        })
    }

    /// Generate the A2A Agent Card for `/.well-known/agent-card.json`.
    pub fn agent_card(&self) -> AgentCard {
        AgentCard {
            name: self.config.agent_name.clone(),
            description: self.config.agent_description.clone(),
            version: self.config.agent_version.clone(),
            supported_interfaces: vec![AgentInterface {
                url: self.config.endpoint_url.clone(),
                protocol_binding: self.config.protocol_binding.clone(),
                protocol_version: "1.0".to_string(),
            }],
            capabilities: AgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: self.skills.clone(),
        }
    }

    /// Serialize the Agent Card as JSON.
    pub fn agent_card_json(&self) -> Result<String, A2aEdgeError> {
        serde_json::to_string_pretty(&self.agent_card())
            .map_err(|e| A2aEdgeError::InvalidRequest(e.to_string()))
    }

    /// List all skill IDs.
    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.iter().map(|s| s.id.clone()).collect()
    }

    /// Get a skill entry by ID.
    pub fn skill(&self, id: &str) -> Option<&A2aSkillEntry> {
        self.skills.iter().find(|s| s.id == id)
    }

    /// Get the truthful bridge fidelity classification for a skill ID,
    /// including unpublished skills that were gated from discovery.
    pub fn bridge_fidelity(&self, id: &str) -> Option<&BridgeFidelity> {
        self.skill_fidelity.get(id)
    }

    /// Access the explicit compatibility-only passthrough surface.
    #[cfg(any(test, feature = "compatibility-surface"))]
    pub fn compatibility(&mut self) -> ChioA2aEdgeCompatibility<'_> {
        ChioA2aEdgeCompatibility { edge: self }
    }

    /// Install the trusted authority used to resolve fresh security state for
    /// each deferred task dispatch.
    pub fn set_deferred_security_context_authority(
        &mut self,
        session_id: SessionId,
        authority: Arc<dyn SecurityInvocationContextAuthority>,
    ) -> Result<(), A2aEdgeError> {
        let session_key = session_id.as_str().to_string();
        if self
            .deferred_security_context_authorities
            .contains_key(&session_key)
        {
            return Err(A2aEdgeError::InvalidRequest(
                "deferred security context authority may only be configured once per session"
                    .to_string(),
            ));
        }
        self.deferred_security_context_authorities.insert(
            session_key,
            DeferredSecurityContextAuthority {
                session_id,
                authority,
            },
        );
        Ok(())
    }

    /// Allocate a new task ID.
    fn next_task_id(&self) -> String {
        format!(
            "a2a-task-{}",
            chio_core::crypto::Keypair::generate().public_key().to_hex()
        )
    }

    fn prune_deferred_tasks(&mut self) {
        let now = unix_now_millis();
        self.tasks.retain(|_, task| task.expires_at_ms > now);
    }

    fn ensure_deferred_task_capacity(&mut self) -> Result<(), A2aEdgeError> {
        self.prune_deferred_tasks();
        let active_count = self
            .tasks
            .values()
            .filter(|task| !task.response.status.is_terminal())
            .count();
        if active_count >= MAX_DEFERRED_A2A_TASKS {
            return Err(A2aEdgeError::InvalidRequest(
                "too many deferred tasks are retained".to_string(),
            ));
        }
        Ok(())
    }

    fn build_execution_request(
        &self,
        skill_id: &str,
        request: &SendMessageRequest,
        execution: &A2aKernelExecutionContext,
        origin_request_id: String,
        kernel_request_id: String,
    ) -> Result<CrossProtocolExecutionRequest, A2aEdgeError> {
        validate_execution_context(execution)?;
        let binding = self.resolve_skill_binding(skill_id)?;
        Ok(CrossProtocolExecutionRequest {
            origin_request_id,
            kernel_request_id,
            target_protocol: binding.target_protocol,
            target_server_id: binding.server_id,
            target_tool_name: binding.tool_name,
            agent_id: execution.agent_id.clone(),
            arguments: extract_arguments_from_message(&request.message)?,
            capability: execution.capability.clone(),
            source_envelope: build_a2a_source_envelope(skill_id, request)?,
            dpop_proof: execution.dpop_proof.clone(),
            execution_nonce: execution.execution_nonce.clone(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            approval_tokens: execution.approval_tokens.clone(),
            threshold_approval_proposal: execution.threshold_approval_proposal.clone(),
            model_metadata: execution.model_metadata.clone(),
            supplemental_authorization: execution.supplemental_authorization.clone(),
            authenticated_session_id: Some(execution.session_id.clone()),
            security_context: execution.security_context.clone(),
            bridge_security: binding.security,
        })
    }

    /// Handle a SendMessage request by routing it through the Chio kernel.
    ///
    /// The caller is responsible for registering the bound tool server with the
    /// provided kernel. Successful and denied decisions both carry a signed Chio
    /// receipt in the returned metadata.
    pub fn handle_send_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let task_id = self.next_task_id();
        let request = self.build_execution_request(
            skill_id,
            request,
            execution,
            task_id.clone(),
            format!("a2a-{task_id}"),
        )?;
        let orchestrated = execute_orchestrated_a2a_request(
            kernel,
            &self.manifest_registry,
            request,
            &self.trusted_peer_negotiation,
        )?;
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Drive the kernel-backed A2A projection with a pending verdict for unit tests.
    ///
    /// The helper first executes the normal orchestrator path, then feeds a pending
    /// kernel response through the same receipt-sink mapper used by `handle_send_message`.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn project_pending_approval_for_test(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        reason: impl Into<String>,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let task_id = self.next_task_id();
        let request = self.build_execution_request(
            skill_id,
            request,
            execution,
            task_id.clone(),
            format!("a2a-{task_id}"),
        )?;
        let mut orchestrated = execute_orchestrated_a2a_request(
            kernel,
            &self.manifest_registry,
            request,
            &self.trusted_peer_negotiation,
        )?;
        let reason = reason.into();
        orchestrated.response.verdict = KernelVerdict::PendingApproval;
        orchestrated.response.output = None;
        orchestrated.response.reason = Some(reason.clone());
        orchestrated.response.terminal_state = OperationTerminalState::Incomplete { reason };
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Start an authoritative deferred task for A2A streaming/task lifecycle.
    pub fn handle_stream_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution)?;
        let security_context_authority = self
            .deferred_security_context_authorities
            .get(execution.session_id.as_str())
            .cloned();
        if execution.security_context.is_some() && security_context_authority.is_none() {
            return Err(A2aEdgeError::InvalidRequest(
                "deferred security state requires a context authority for the authenticated session"
                    .to_string(),
            ));
        }
        self.ensure_deferred_task_capacity()?;
        let task_id = self.next_task_id();
        let expires_at_ms = unix_now_millis().saturating_add(DEFERRED_A2A_TASK_TTL_MILLIS);
        let mut orchestrated_request = self.build_execution_request(
            skill_id,
            request,
            execution,
            task_id.clone(),
            format!("a2a-stream-{task_id}"),
        )?;
        // A context generation is a point-in-time authority snapshot. Retain
        // only the authenticated request binding and authority handle, then
        // resolve fresh state immediately before deferred dispatch.
        orchestrated_request.security_context = None;

        let response = TaskResponse {
            id: task_id.clone(),
            status: TaskStatus::Working,
            status_message: Some("Task accepted for authoritative deferred execution.".to_string()),
            message: None,
            metadata: Some(pending_task_metadata(
                "cross_protocol_orchestrator",
                "deferred_task_poll",
            )),
        };
        self.tasks.insert(
            task_id,
            DeferredA2aTask {
                owner_agent_id: execution.agent_id.clone(),
                owner_session_id: execution.session_id.clone(),
                request: orchestrated_request,
                security_context_authority,
                trusted_peer_negotiation: self.trusted_peer_negotiation.clone(),
                response: response.clone(),
                expires_at_ms,
            },
        );
        Ok(response)
    }

    /// Handle a SendMessage request through the explicit direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not mistake it for the
    /// signed-receipt authority path.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_send_message_passthrough(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        server: &dyn ToolServerConnection,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let tool_name = {
            let binding = self.resolve_skill_binding(skill_id)?;
            binding.tool_name
        };

        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id();

        let invoke_result =
            match crate::block_on_tool_server_invoke(server.invoke(&tool_name, arguments, None)) {
                Ok(inner) => inner,
                Err(bridge_err) => {
                    // Fail-closed mirror of the kernel sync-bridge gate:
                    // current-thread runtime detected, refuse to deadlock.
                    let msg = bridge_err.to_string();
                    return Ok(TaskResponse {
                        id: task_id,
                        status: TaskStatus::Failed,
                        status_message: Some(msg.clone()),
                        message: None,
                        metadata: Some(passthrough_metadata(Some(&msg))),
                    });
                }
            };
        match invoke_result {
            Ok(result) => {
                let response_parts = result_to_parts(&result);
                Ok(TaskResponse {
                    id: task_id,
                    status: TaskStatus::Completed,
                    status_message: None,
                    message: Some(A2aMessage {
                        role: "agent".to_string(),
                        parts: response_parts,
                        metadata: None,
                    }),
                    metadata: Some(passthrough_metadata(None)),
                })
            }
            Err(error) => Ok(TaskResponse {
                id: task_id,
                status: TaskStatus::Failed,
                status_message: Some(error.to_string()),
                message: None,
                metadata: Some(passthrough_metadata(Some(&error.to_string()))),
            }),
        }
    }

    /// Handle a JSON-RPC A2A request through the Chio kernel.
    ///
    /// This is the receipt-bearing path for production deployments that have
    /// already authenticated the caller and resolved a capability token.
    pub fn handle_jsonrpc(
        &mut self,
        message: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> A2aJsonRpcResponse {
        let A2aJsonRpcEnvelope { id, method, params } = match Self::parse_jsonrpc_envelope(&message)
        {
            Ok(envelope) => envelope,
            Err(response) => return A2aJsonRpcResponse::from_optional(response),
        };
        let should_respond = id.is_some();
        let id = id.unwrap_or(Value::Null);
        if let Err(response) = Self::ensure_jsonrpc_params_object_for_supported_method(
            &id,
            &method,
            &params,
            &["message/send", "message/stream", "task/get", "task/cancel"],
        ) {
            return A2aJsonRpcResponse::from_optional(should_respond.then_some(response));
        }

        let response = match method.as_str() {
            "message/send" => self.handle_jsonrpc_send_message(id, params, kernel, execution),
            "message/stream" => self.handle_jsonrpc_stream_message(id, params, execution),
            "task/get" => self.handle_jsonrpc_task_get(id, params, kernel, execution),
            "task/cancel" => self.handle_jsonrpc_task_cancel(id, params, execution),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        };
        A2aJsonRpcResponse::from_optional(should_respond.then_some(response))
    }

    /// Handle a JSON-RPC A2A request through the direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. Its result
    /// payload carries explicit passthrough metadata so it is not confused with
    /// the signed-receipt authority path.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_passthrough(
        &mut self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> A2aJsonRpcResponse {
        let A2aJsonRpcEnvelope { id, method, params } = match Self::parse_jsonrpc_envelope(&message)
        {
            Ok(envelope) => envelope,
            Err(response) => return A2aJsonRpcResponse::from_optional(response),
        };
        let should_respond = id.is_some();
        let id = id.unwrap_or(Value::Null);
        if let Err(response) = Self::ensure_jsonrpc_params_object_for_supported_method(
            &id,
            &method,
            &params,
            &["message/send", "message/stream"],
        ) {
            return A2aJsonRpcResponse::from_optional(should_respond.then_some(response));
        }

        let response = match method.as_str() {
            "message/send" => self.handle_jsonrpc_send_message_passthrough(id, params, server),
            "message/stream" => self.jsonrpc_stream_not_supported(id),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        };
        A2aJsonRpcResponse::from_optional(should_respond.then_some(response))
    }

    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_send_message_passthrough(
        &mut self,
        id: Value,
        params: Value,
        server: &dyn ToolServerConnection,
    ) -> Value {
        let (skill_id, request) =
            match self.parse_jsonrpc_send_message_params(params, "SendMessage") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };

        match self.handle_send_message_passthrough(&skill_id, &request, server) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_jsonrpc_send_message(
        &mut self,
        id: Value,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        let (skill_id, request) =
            match self.parse_jsonrpc_send_message_params(params, "SendMessage") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };

        match self.handle_send_message(&skill_id, &request, kernel, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_jsonrpc_stream_message(
        &mut self,
        id: Value,
        params: Value,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        let (skill_id, request) =
            match self.parse_jsonrpc_send_message_params(params, "SendStreamingMessage") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };

        match self.handle_stream_message(&skill_id, &request, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_jsonrpc_task_get(
        &mut self,
        id: Value,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        self.prune_deferred_tasks();
        let task_id = match Self::parse_jsonrpc_task_id_params(&params, "task/get") {
            Ok(task_id) => task_id,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }

        match self.resolve_task(&task_id, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(A2aEdgeError::InvalidRequest(_)) if self.tasks.contains_key(&task_id) => {
                self.complete_task(&task_id, kernel, execution, id)
            }
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn complete_task(
        &mut self,
        task_id: &str,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        id: Value,
    ) -> Value {
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }
        let Some(task) = self.tasks.get(task_id).cloned() else {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::ToolNotFound(task_id.to_string()),
            );
        };
        if let Err(error) = validate_deferred_a2a_task_owner(
            &task.owner_agent_id,
            &task.owner_session_id,
            execution,
        ) {
            return Self::jsonrpc_error_response(id, error);
        }
        if task.response.status != TaskStatus::Working {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&task.response).unwrap_or(Value::Null)
            });
        }

        let security_context_authority = task.security_context_authority.clone();
        let mut request = task.request;
        if let Err(error) =
            refresh_deferred_a2a_security_context(&mut request, execution, &task.owner_session_id)
        {
            return Self::jsonrpc_error_response(id, error);
        }
        if security_context_authority.is_none() && execution.security_context.is_some() {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::InvalidRequest(
                    "deferred security state requires a per-dispatch context authority".to_string(),
                ),
            );
        }
        if let Some(security_context_authority) = security_context_authority {
            if security_context_authority.session_id != task.owner_session_id {
                return Self::jsonrpc_error_response(
                    id,
                    A2aEdgeError::InvalidRequest(
                        "deferred authority is not bound to the task session".to_string(),
                    ),
                );
            }
            let context = OperationContext::new(
                task.owner_session_id.clone(),
                RequestId::new(request.kernel_request_id.clone()),
                request.agent_id.clone(),
            );
            let operation = match request.to_tool_call_operation() {
                Ok(operation) => operation,
                Err(error) => {
                    return Self::jsonrpc_error_response(
                        id,
                        A2aEdgeError::InvalidRequest(format!(
                            "deferred authority request projection failed: {error}"
                        )),
                    );
                }
            };
            let security_context = match security_context_authority
                .authority
                .resolve_security_invocation_context(&context, &operation)
            {
                Ok(security_context) => security_context,
                Err(error) => {
                    return Self::jsonrpc_error_response(
                        id,
                        A2aEdgeError::InvalidRequest(format!(
                            "deferred security context resolution failed: {error}"
                        )),
                    );
                }
            };
            if let Err(error) =
                validate_security_context_session(&security_context, &task.owner_session_id)
            {
                return Self::jsonrpc_error_response(id, error);
            }
            request.security_context = Some(security_context);
        }
        let orchestrated = match execute_orchestrated_a2a_request(
            kernel,
            &self.manifest_registry,
            request,
            &task.trusted_peer_negotiation,
        ) {
            Ok(orchestrated) => orchestrated,
            Err(error) => {
                let reason = error.to_string();
                if let Some(retained_task) = self.tasks.get_mut(task_id) {
                    if retained_task.response.status == TaskStatus::Working {
                        retained_task.response = TaskResponse {
                            id: task_id.to_string(),
                            status: TaskStatus::Failed,
                            status_message: Some(format!(
                                "Deferred dispatch outcome is unknown: {reason}"
                            )),
                            message: None,
                            metadata: Some(outcome_unknown_task_metadata(
                                "cross_protocol_orchestrator",
                                "deferred_task_poll",
                                &reason,
                            )),
                        };
                    }
                }
                return Self::jsonrpc_error_response(id, error);
            }
        };
        let response = task_response_from_orchestrated(task_id.to_string(), orchestrated);
        let response = match self.tasks.get_mut(task_id) {
            Some(task) if task.response.status == TaskStatus::Working => {
                task.response = response;
                task.response.clone()
            }
            Some(task) => task.response.clone(),
            None => {
                return Self::jsonrpc_error_response(
                    id,
                    A2aEdgeError::ToolNotFound(task_id.to_string()),
                );
            }
        };
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": serde_json::to_value(&response).unwrap_or(Value::Null)
        })
    }

    fn handle_jsonrpc_task_cancel(
        &mut self,
        id: Value,
        params: Value,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        self.prune_deferred_tasks();
        let task_id = match Self::parse_jsonrpc_task_id_params(&params, "task/cancel") {
            Ok(task_id) => task_id,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }

        let Some(task) = self.tasks.get_mut(&task_id) else {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::ToolNotFound(task_id.to_string()),
            );
        };
        if let Err(error) = validate_deferred_a2a_task_owner(
            &task.owner_agent_id,
            &task.owner_session_id,
            execution,
        ) {
            return Self::jsonrpc_error_response(id, error);
        }
        match task.response.status {
            TaskStatus::Working => {
                task.response.status = TaskStatus::Cancelled;
                task.response.status_message = Some("Task cancelled by caller.".to_string());
                task.response.metadata = Some(cancelled_task_metadata(
                    "cross_protocol_orchestrator",
                    "deferred_task_poll",
                ));
                let response = task.response.clone();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": serde_json::to_value(&response).unwrap_or(Value::Null)
                })
            }
            TaskStatus::Cancelled => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&task.response).unwrap_or(Value::Null)
            }),
            status => Self::jsonrpc_error_response(
                id,
                A2aEdgeError::InvalidRequest(format!(
                    "cannot cancel task in terminal status `{status:?}`"
                )),
            ),
        }
    }

    fn resolve_task(
        &self,
        task_id: &str,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let task = self
            .tasks
            .get(task_id)
            .ok_or_else(|| A2aEdgeError::ToolNotFound(task_id.to_string()))?;
        validate_deferred_a2a_task_owner(&task.owner_agent_id, &task.owner_session_id, execution)?;
        match task.response.status {
            TaskStatus::Working => Err(A2aEdgeError::InvalidRequest(
                "task is pending deferred execution".to_string(),
            )),
            _ => Ok(task.response.clone()),
        }
    }
}

#[cfg(any(test, feature = "compatibility-surface"))]
impl ChioA2aEdgeCompatibility<'_> {
    /// Handle a SendMessage request through the explicit direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not mistake it for the
    /// signed-receipt authority path.
    pub fn handle_send_message_compatibility(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        server: &dyn ToolServerConnection,
    ) -> Result<TaskResponse, A2aEdgeError> {
        self.edge
            .handle_send_message_passthrough(skill_id, request, server)
    }

    /// Handle a JSON-RPC A2A request through the direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. Its result
    /// payload carries explicit passthrough metadata so it is not confused with
    /// the signed-receipt authority path.
    pub fn handle_jsonrpc_compatibility(
        &mut self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> A2aJsonRpcResponse {
        self.edge.handle_jsonrpc_passthrough(message, server)
    }
}
