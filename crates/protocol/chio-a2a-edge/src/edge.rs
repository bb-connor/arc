// The A2A edge server, its deferred-task state, and the explicit
// kernel-mediated dispatch.

const A2A_INTERNAL_ERROR_MESSAGE: &str = "internal error";

#[derive(Debug, Clone)]
struct DeferredA2aTask {
    owner_agent_id: String,
    request: CrossProtocolExecutionRequest,
    response: TaskResponse,
    deadline: AuthorityDeadline,
    output_mode: V1OutputMode,
}

impl DeferredA2aTask {
    fn is_owned_by(&self, execution: &A2aKernelExecutionContext) -> bool {
        self.owner_agent_id == execution.agent_id
            && self.request.capability.subject == execution.capability.subject
    }
}

/// The A2A edge server.
///
/// Wraps a set of Chio tool manifests and exposes them as A2A skills.
pub struct ChioA2aEdge {
    config: A2aEdgeConfig,
    manifest_registry: Option<VerifiedManifestRegistry>,
    skills: Vec<A2aSkillEntry>,
    skill_fidelity: BTreeMap<String, BridgeFidelity>,
    /// Maps skill ID to authoritative target binding metadata.
    skill_bindings: BTreeMap<String, SkillBinding>,
    /// Maps ambiguous unqualified tool names to the qualified published IDs.
    ambiguous_skill_ids: BTreeMap<String, Vec<String>>,
    task_counter: u64,
    task_namespace: String,
    tasks: BTreeMap<String, DeferredA2aTask>,
}

fn validate_execution_context(
    execution: &A2aKernelExecutionContext,
    peer: &chio_core::capability::features::CapabilityNegotiation,
) -> Result<(), A2aEdgeError> {
    validate_execution_agent_id(&execution.agent_id)?;
    if execution.approval_token.is_some() && !execution.approval_tokens.is_empty() {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution must not mix singular and threshold approval tokens".to_string(),
        ));
    }
    if execution.approval_tokens.len()
        > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
    {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "A2A threshold approval set exceeds {} tokens",
            chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
        )));
    }
    if execution.approval_tokens.is_empty() != execution.threshold_approval_proposal.is_none() {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A threshold approval tokens and proposal must be supplied together".to_string(),
        ));
    }
    peer.validate_invocation_features(
        &execution.capability,
        &execution.approval_tokens,
        execution.threshold_approval_proposal.as_ref(),
        execution.governed_intent.as_ref(),
        execution.supplemental_authorization.as_ref(),
    )
    .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
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

fn reject_request_bound_artifacts_without_stable_request_id(
    execution: &A2aKernelExecutionContext,
) -> Result<(), A2aEdgeError> {
    if execution.approval_token.is_none()
        && execution.approval_tokens.is_empty()
        && execution.supplemental_authorization.is_none()
        && execution.execution_nonce.is_none()
    {
        return Ok(());
    }
    Err(A2aEdgeError::InvalidRequest(
        "A2A request-bound authorization artifacts and execution nonces require \
         handle_send_message_with_request_id"
            .to_string(),
    ))
}

#[cfg(test)]
fn test_registry_from_unverified_manifests(
    manifests: &[ToolManifest],
) -> Result<VerifiedManifestRegistry, A2aEdgeError> {
    let mut registry = VerifiedManifestRegistry::default();
    for manifest in manifests {
        let signer = (0..=u8::MAX)
            .map(|seed| chio_core::crypto::Keypair::from_seed(&[seed; 32]))
            .find(|candidate| candidate.public_key().to_hex() == manifest.public_key)
            .ok_or_else(|| {
                A2aEdgeError::InvalidRequest(format!(
                    "unit-test manifest signer is unavailable for {}",
                    manifest.server_id
                ))
            })?;
        let signed = chio_manifest::sign_manifest(manifest, &signer)?;
        registry
            .register_public_only(
                signed,
                &signer.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    }
    Ok(registry)
}

impl ChioA2aEdge {
    /// Create a new A2A edge from authenticated, policy-admitted manifests.
    #[cfg(not(test))]
    pub fn new(
        config: A2aEdgeConfig,
        registry: &VerifiedManifestRegistry,
    ) -> Result<Self, A2aEdgeError> {
        Self::new_with_registry(config, registry)
    }

    /// Create a new A2A edge from authenticated, policy-admitted manifests.
    pub fn new_with_registry(
        config: A2aEdgeConfig,
        registry: &VerifiedManifestRegistry,
    ) -> Result<Self, A2aEdgeError> {
        let manifests = registry
            .verified_manifests()
            .map(|signed| signed.manifest.clone())
            .collect();
        Self::new_internal(config, manifests, Some(registry.clone()))
    }

    /// Build unit-test fixtures without exposing unverified
    /// manifests to production authoritative execution.
    #[cfg(test)]
    pub(crate) fn new(
        config: A2aEdgeConfig,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, A2aEdgeError> {
        let test_registry = test_registry_from_unverified_manifests(&manifests).ok();
        Self::new_internal(config, manifests, test_registry)
    }

    fn new_internal(
        config: A2aEdgeConfig,
        manifests: Vec<ToolManifest>,
        manifest_registry: Option<VerifiedManifestRegistry>,
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
                let security = manifest_registry
                    .as_ref()
                    .and_then(|registry| registry.bridge_security(&manifest.server_id, &tool.name))
                    .unwrap_or_else(|| BridgeSecurityMetadata::from_tool(tool));
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
                        input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                        output_modes: vec![
                            "text/plain".to_string(),
                            "application/json".to_string(),
                        ],
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
            manifest_registry,
            skills,
            skill_fidelity,
            skill_bindings,
            ambiguous_skill_ids,
            task_counter: 0,
            // A random identifier prevents stale client task records from
            // aliasing unrelated work after this process loses its task table.
            // This public value is not a trust root.
            task_namespace: chio_core::crypto::Keypair::generate().public_key().to_hex(),
            tasks: BTreeMap::new(),
        })
    }

    fn manifest_registry(&self) -> Result<&VerifiedManifestRegistry, A2aEdgeError> {
        self.manifest_registry.as_ref().ok_or_else(|| {
            A2aEdgeError::InvalidRequest(
                "authoritative A2A execution requires a verified manifest registry".to_string(),
            )
        })
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

    fn jsonrpc_error_response(id: Value, error: A2aEdgeError) -> A2aJsonRpcResponse {
        let (code, message) = Self::jsonrpc_error_fields(&error);
        A2aJsonRpcResponse::with_error(Self::jsonrpc_error_payload(id, code, &message), error)
    }

    fn jsonrpc_error_fields(error: &A2aEdgeError) -> (i64, String) {
        match error {
            A2aEdgeError::UntrustedInput(error)
            | A2aEdgeError::Bridge(BridgeError::UntrustedInput(error)) => {
                (-32602, error.code().to_string())
            }
            A2aEdgeError::Clock(clock_error) => (-32603, clock_error.code().to_string()),
            A2aEdgeError::TaskCapacity => (
                -32602,
                "urn:chio:error:transport:task-capacity-exceeded".to_string(),
            ),
            A2aEdgeError::ToolNotFound(message)
            | A2aEdgeError::InvalidRequest(message)
            | A2aEdgeError::Bridge(BridgeError::InvalidRequest(message)) => {
                (-32602, message.clone())
            }
            A2aEdgeError::UnsupportedOperation(message) => (-32004, (*message).to_string()),
            A2aEdgeError::TaskNotFound(_) => (-32001, "task not found".to_string()),
            A2aEdgeError::TaskNotCancelable(_) => (-32002, "task is not cancelable".to_string()),
            A2aEdgeError::Bridge(BridgeError::CapabilityRefMismatch { .. }) => {
                (-32602, "capability reference mismatch".to_string())
            }
            A2aEdgeError::Bridge(BridgeError::UnsupportedTargetProtocol(_)) => {
                (-32004, "unsupported target protocol".to_string())
            }
            A2aEdgeError::Bridge(BridgeError::Kernel(kernel_error)) => {
                Self::internal_jsonrpc_error_fields(error, kernel_error.report().code)
            }
            A2aEdgeError::Bridge(BridgeError::InvalidAttenuation(_) | BridgeError::Canonical(_))
            | A2aEdgeError::Kernel(_)
            | A2aEdgeError::Manifest(_) => {
                Self::internal_jsonrpc_error_fields(error, A2A_INTERNAL_ERROR_MESSAGE.to_string())
            }
        }
    }

    fn internal_jsonrpc_error_fields(error: &A2aEdgeError, message: String) -> (i64, String) {
        tracing::error!(error = %error, "A2A request failed internally");
        (-32603, message)
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
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
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

    /// Allocate a new task ID.
    fn next_task_id(&mut self) -> Result<String, A2aEdgeError> {
        self.task_counter = self
            .task_counter
            .checked_add(1)
            .ok_or(A2aEdgeError::TaskCapacity)?;
        Ok(format!(
            "a2a-task-{}-{}",
            self.task_namespace, self.task_counter
        ))
    }

    fn prune_deferred_tasks(&mut self, now: ClockReading) -> Result<(), ClockError> {
        let mut expired = Vec::new();
        for (id, task) in &mut self.tasks {
            match task.deadline.remaining(now) {
                Ok(_) => {}
                Err(ClockError::Expired) => expired.push(id.clone()),
                Err(error) => return Err(error),
            }
        }
        for id in expired {
            self.tasks.remove(&id);
        }
        Ok(())
    }

    fn ensure_deferred_task_capacity(
        &mut self,
        now: ClockReading,
        execution: &A2aKernelExecutionContext,
    ) -> Result<(), A2aEdgeError> {
        self.prune_deferred_tasks(now)?;
        let subject_tasks = self.tasks.values().filter(|task| {
            task.request.capability.subject == execution.capability.subject
        }).count();
        if self.tasks.len() >= MAX_DEFERRED_A2A_TASKS
            || subject_tasks >= MAX_DEFERRED_A2A_TASKS_PER_SUBJECT
        {
            return Err(A2aEdgeError::TaskCapacity);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_execution_request(
        binding: SkillBinding,
        skill_id: &str,
        source_request: &SendMessageRequest,
        arguments: Value,
        execution: &A2aKernelExecutionContext,
        origin_request_id: String,
        kernel_request_id: String,
    ) -> Result<CrossProtocolExecutionRequest, A2aEdgeError> {
        Ok(CrossProtocolExecutionRequest {
            origin_request_id,
            kernel_request_id,
            target_protocol: binding.target_protocol,
            target_server_id: binding.server_id,
            target_tool_name: binding.tool_name,
            agent_id: execution.agent_id.clone(),
            arguments,
            capability: execution.capability.clone(),
            source_envelope: build_a2a_source_envelope(skill_id, source_request)?,
            dpop_proof: execution.dpop_proof.clone(),
            execution_nonce: execution.execution_nonce.clone(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            approval_tokens: execution.approval_tokens.clone(),
            threshold_approval_proposal: execution.threshold_approval_proposal.clone(),
            supplemental_authorization: execution.supplemental_authorization.clone(),
            model_metadata: execution.model_metadata.clone(),
            authenticated_session_id: None,
            security_context: None,
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
        validate_execution_context(execution, &self.config.peer_capabilities)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.resolve_skill_binding(skill_id)?;

        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id()?;
        let request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            arguments,
            execution,
            task_id.clone(),
            format!("a2a-{task_id}"),
        )?;
        let orchestrated = execute_orchestrated_a2a_request(
            &self.config.peer_capabilities,
            kernel,
            self.manifest_registry()?,
            request,
        )?;
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Handle a SendMessage request under the caller's stable request ID.
    ///
    /// `SendMessageRequest` carries no identifier of its own, so request-bound
    /// authorization artifacts (threshold approval sets and supplemental
    /// authorization) can only be pre-minted when the caller supplies the ID the
    /// kernel will check them against.
    pub fn handle_send_message_with_request_id(
        &mut self,
        request_id: &str,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution, &self.config.peer_capabilities)?;
        let binding = self.resolve_skill_binding(skill_id)?;

        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id()?;
        let execution_request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            arguments,
            execution,
            format!("a2a-request-{request_id}"),
            request_id.to_string(),
        )?;
        let orchestrated = execute_orchestrated_a2a_request(
            &self.config.peer_capabilities,
            kernel,
            self.manifest_registry()?,
            execution_request,
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
        validate_execution_context(execution, &self.config.peer_capabilities)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.resolve_skill_binding(skill_id)?;
        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id()?;
        let request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            arguments,
            execution,
            task_id.clone(),
            format!("a2a-{task_id}"),
        )?;
        let mut orchestrated = execute_orchestrated_a2a_request(
            &self.config.peer_capabilities,
            kernel,
            self.manifest_registry()?,
            request,
        )?;
        let reason = reason.into();
        orchestrated.response.verdict = KernelVerdict::PendingApproval;
        orchestrated.response.output = None;
        orchestrated.response.reason = Some(reason.clone());
        orchestrated.response.terminal_state = OperationTerminalState::Incomplete { reason };
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Retain a working task under the caller's stable request ID.
    fn retain_task(
        &mut self,
        request_id: &str,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        output_mode: V1OutputMode,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution, &self.config.peer_capabilities)?;
        let binding = self.resolve_skill_binding(skill_id)?;
        let now = kernel.authority_clock_reading()?;
        let deadline = AuthorityDeadline::for_timeout_ms(now, DEFERRED_A2A_TASK_TTL_MILLIS)?;
        self.ensure_deferred_task_capacity(now, execution)?;
        let task_id = self.next_task_id()?;
        let orchestrated_request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            extract_arguments_from_message(&request.message)?,
            execution,
            format!("a2a-request-{request_id}"),
            request_id.to_string(),
        )?;

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
                request: orchestrated_request,
                response: response.clone(),
                deadline,
                output_mode,
            },
        );
        Ok(response)
    }

    /// Handle a JSON-RPC A2A request through the Chio kernel.
    ///
    /// This is the receipt-bearing path for production deployments that have
    /// already authenticated the caller and resolved a capability token.
    fn handle_jsonrpc_value(
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
        let response = match method.as_str() {
            "SendMessage" | "GetTask" | "CancelTask" => {
                self.handle_v1_jsonrpc(id, &method, params, kernel, execution)
            }
            _ => A2aJsonRpcResponse::response(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            })),
        };
        if should_respond {
            response
        } else {
            response.suppress_wire_response()
        }
    }

    fn cancel_task(&mut self, task_id: &str) -> Result<TaskResponse, A2aEdgeError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| A2aEdgeError::TaskNotFound(task_id.to_string()))?;
        match task.response.status {
            TaskStatus::Working => {
                task.response.status = TaskStatus::Cancelled;
                task.response.status_message = Some("Task cancelled by caller.".to_string());
                task.response.metadata = Some(cancelled_task_metadata(
                    "cross_protocol_orchestrator",
                    "deferred_task_poll",
                ));
                Ok(task.response.clone())
            }
            TaskStatus::Cancelled => Ok(task.response.clone()),
            TaskStatus::Completed | TaskStatus::Failed => {
                Err(A2aEdgeError::TaskNotCancelable(task_id.to_string()))
            }
        }
    }
}
