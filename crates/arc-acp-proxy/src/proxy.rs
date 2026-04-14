/// Top-level ACP proxy orchestrator.
///
/// Wraps the transport, interceptor, and configuration into a single
/// handle that manages the full lifecycle of an ACP agent subprocess.
pub struct AcpProxy {
    config: AcpProxyConfig,
    transport: AcpTransport,
    interceptor: MessageInterceptor,
}

impl AcpProxy {
    /// Create and start the proxy, spawning the agent subprocess.
    pub fn start(config: AcpProxyConfig) -> Result<Self, AcpProxyError> {
        let transport = AcpTransport::spawn(
            config.agent_command(),
            config.agent_args(),
            config.agent_env(),
        )?;
        let interceptor = MessageInterceptor::new(config.clone());
        Ok(Self {
            config,
            transport,
            interceptor,
        })
    }

    /// Process a single message from the client (stdin) side.
    ///
    /// Returns the intercept result describing whether to forward,
    /// block, or augment the message.
    pub fn process_client_message(
        &self,
        message: &serde_json::Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        self.interceptor
            .intercept(Direction::ClientToAgent, message)
    }

    /// Process a single message from the agent (subprocess) side.
    ///
    /// Returns the intercept result describing whether to forward,
    /// block, or augment the message.
    pub fn process_agent_message(
        &self,
        message: &serde_json::Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        self.interceptor
            .intercept(Direction::AgentToClient, message)
    }

    /// Read the next message from the agent subprocess.
    pub fn recv_from_agent(&mut self) -> Result<Option<serde_json::Value>, AcpProxyError> {
        self.transport.recv()
    }

    /// Send a message to the agent subprocess.
    pub fn send_to_agent(&mut self, message: &serde_json::Value) -> Result<(), AcpProxyError> {
        self.transport.send(message)
    }

    /// Shut down the proxy, killing the agent subprocess.
    pub fn shutdown(&mut self) -> Result<(), AcpProxyError> {
        self.transport.kill()
    }

    /// Return a reference to the proxy configuration.
    pub fn config(&self) -> &AcpProxyConfig {
        &self.config
    }

    /// Return a reference to the message interceptor.
    pub fn interceptor(&self) -> &MessageInterceptor {
        &self.interceptor
    }
}
