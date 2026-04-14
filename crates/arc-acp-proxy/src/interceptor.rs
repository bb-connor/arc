/// Direction of a message flowing through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the editor/IDE client toward the ACP agent.
    ClientToAgent,
    /// From the ACP agent toward the editor/IDE client.
    AgentToClient,
}

/// The outcome of intercepting a single message.
#[derive(Debug, Clone)]
pub enum InterceptResult {
    /// Forward the (possibly modified) message to its destination.
    Forward(Value),
    /// Block the message and return an error response to the sender.
    Block(Value),
    /// Forward the message AND record an audit entry for it.
    ForwardWithReceipt(Value, AcpToolCallAuditEntry),
}

/// Core message interception logic for the ACP proxy.
///
/// The interceptor examines every JSON-RPC message, delegates to
/// specialized guards, and decides whether to forward, block, or
/// augment the message with an audit entry.
pub struct MessageInterceptor {
    config: AcpProxyConfig,
    permission_mapper: PermissionMapper,
    fs_guard: FsGuard,
    terminal_guard: TerminalGuard,
    receipt_logger: ReceiptLogger,
}

impl MessageInterceptor {
    /// Build an interceptor from the given proxy configuration.
    pub fn new(config: AcpProxyConfig) -> Self {
        let fs_guard = FsGuard::new(config.allowed_path_prefixes().to_vec());
        let terminal_guard = TerminalGuard::new(config.allowed_commands().to_vec());
        let receipt_logger = ReceiptLogger::new(config.server_id());
        let permission_mapper = PermissionMapper::new(3600);

        Self {
            config,
            permission_mapper,
            fs_guard,
            terminal_guard,
            receipt_logger,
        }
    }

    /// Intercept a JSON-RPC message flowing in the given `direction`.
    ///
    /// Returns an `InterceptResult` describing whether to forward,
    /// block, or forward-with-receipt.
    pub fn intercept(
        &self,
        direction: Direction,
        message: &Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        let method = extract_method(message);

        match (direction, method) {
            // -- Agent-to-client: file system reads --
            (Direction::AgentToClient, Some(AcpMethod::FsReadTextFile)) => {
                self.intercept_fs_read(message)
            }
            // -- Agent-to-client: file system writes --
            (Direction::AgentToClient, Some(AcpMethod::FsWriteTextFile)) => {
                self.intercept_fs_write(message)
            }
            // -- Agent-to-client: terminal create --
            (Direction::AgentToClient, Some(AcpMethod::TerminalCreate)) => {
                self.intercept_terminal_create(message)
            }
            // -- Agent-to-client: permission requests --
            (Direction::AgentToClient, Some(AcpMethod::SessionRequestPermission)) => {
                self.intercept_permission_request(message)
            }
            // -- Agent-to-client: session updates (receipt generation) --
            (Direction::AgentToClient, Some(AcpMethod::SessionUpdate)) => {
                self.intercept_session_update(message)
            }
            // -- New ACP methods: forward unchanged (no guard needed) --
            (_, Some(AcpMethod::Authenticate))
            | (_, Some(AcpMethod::SessionLoad))
            | (_, Some(AcpMethod::SessionList))
            | (_, Some(AcpMethod::SessionSetConfigOption))
            | (_, Some(AcpMethod::SessionSetMode))
            | (_, Some(AcpMethod::TerminalOutput))
            | (_, Some(AcpMethod::TerminalWaitForExit)) => {
                Ok(InterceptResult::Forward(message.clone()))
            }
            // -- Everything else: forward unchanged --
            _ => Ok(InterceptResult::Forward(message.clone())),
        }
    }

    /// Return a reference to the underlying proxy configuration.
    pub fn config(&self) -> &AcpProxyConfig {
        &self.config
    }

    /// Expose the permission mapper for tests.
    #[cfg(test)]
    pub fn permission_mapper(&self) -> &PermissionMapper {
        &self.permission_mapper
    }

    // -- private handlers --

    fn intercept_fs_read(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message
            .get("params")
            .ok_or_else(|| AcpProxyError::Protocol("missing params in fs/read_text_file".into()))?;

        let read_params: ReadTextFileParams =
            serde_json::from_value(params.clone()).map_err(|e| {
                AcpProxyError::Protocol(format!("invalid fs/read_text_file params: {e}"))
            })?;

        match self.fs_guard.check_read(&read_params.path) {
            Ok(()) => Ok(InterceptResult::Forward(message.clone())),
            Err(err) => {
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(path = %read_params.path, "fs read blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    fn intercept_fs_write(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message.get("params").ok_or_else(|| {
            AcpProxyError::Protocol("missing params in fs/write_text_file".into())
        })?;

        let write_params: WriteTextFileParams =
            serde_json::from_value(params.clone()).map_err(|e| {
                AcpProxyError::Protocol(format!("invalid fs/write_text_file params: {e}"))
            })?;

        match self.fs_guard.check_write(&write_params.path) {
            Ok(()) => Ok(InterceptResult::Forward(message.clone())),
            Err(err) => {
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(path = %write_params.path, "fs write blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    fn intercept_terminal_create(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message
            .get("params")
            .ok_or_else(|| AcpProxyError::Protocol("missing params in terminal/create".into()))?;

        let term_params: CreateTerminalParams =
            serde_json::from_value(params.clone()).map_err(|e| {
                AcpProxyError::Protocol(format!("invalid terminal/create params: {e}"))
            })?;

        match self
            .terminal_guard
            .check_command(&term_params.command, &term_params.args)
        {
            Ok(()) => Ok(InterceptResult::Forward(message.clone())),
            Err(err) => {
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(command = %term_params.command, "terminal create blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    /// Intercept a `session/request_permission` message.
    ///
    /// The ARC capability mapping performed here is for **audit logging
    /// only**. The actual enforcement decision is made by the user
    /// through the editor/IDE UI -- the proxy does not approve or
    /// reject permissions on behalf of the user. It maps ACP
    /// permission kinds to ARC capability decisions so that the audit
    /// trail records what the ARC-equivalent grant would be.
    fn intercept_permission_request(
        &self,
        message: &Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        // Parse permission params for logging/mapping.
        if let Some(params) = message.get("params") {
            if let Ok(perm_params) =
                serde_json::from_value::<RequestPermissionParams>(params.clone())
            {
                for option in &perm_params.options {
                    let mapped = self.permission_mapper.map_option(option);
                    tracing::info!(
                        option_id = %mapped.original_option_id,
                        decision = ?mapped.arc_decision,
                        "permission mapped"
                    );
                }
            }
        }
        // Forward the permission request to the client for user decision.
        Ok(InterceptResult::Forward(message.clone()))
    }

    fn intercept_session_update(
        &self,
        message: &Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        let params = message.get("params");
        let notification = params.and_then(|p| {
            serde_json::from_value::<SessionUpdateNotification>(p.clone()).ok()
        });

        if let Some(ref notif) = notification {
            let update = parse_session_update(&notif.update);
            match update {
                SessionUpdate::ToolCall(ref event) => {
                    let receipt = self
                        .receipt_logger
                        .log_tool_call(&notif.session_id, event);
                    tracing::info!(
                        tool_call_id = %receipt.tool_call_id,
                        status = %receipt.status,
                        "tool call receipt"
                    );
                    return Ok(InterceptResult::ForwardWithReceipt(
                        message.clone(),
                        receipt,
                    ));
                }
                SessionUpdate::ToolCallUpdate(ref event) => {
                    if let Some(receipt) = self
                        .receipt_logger
                        .log_tool_call_update(&notif.session_id, event)
                    {
                        tracing::info!(
                            tool_call_id = %receipt.tool_call_id,
                            status = %receipt.status,
                            "tool call update receipt"
                        );
                        return Ok(InterceptResult::ForwardWithReceipt(
                            message.clone(),
                            receipt,
                        ));
                    }
                }
                SessionUpdate::AgentMessageChunk(_)
                | SessionUpdate::AgentThoughtChunk(_)
                | SessionUpdate::Plan(_)
                | SessionUpdate::AvailableCommandsUpdate(_)
                | SessionUpdate::CurrentModeUpdate(_)
                | SessionUpdate::ConfigOptionUpdate(_)
                | SessionUpdate::SessionInfoUpdate(_)
                | SessionUpdate::Other(_) => {}
            }
        }

        Ok(InterceptResult::Forward(message.clone()))
    }
}
