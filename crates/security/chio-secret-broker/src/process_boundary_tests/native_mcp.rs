//! Tool-side broker IPC uses a child with no privileged registration signer.
use super::*;
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolDispatchContext, ToolInvocationContext, ToolInvocationCost,
    ToolServerConnection,
};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
pub(super) enum CompletionFault {
    LoseReply,
    ChangeBody,
    ChangeHeaders,
    ExtraContent,
}

pub(super) struct McpTool {
    pub directory: PathBuf,
    pub peer: BrokerPeerIdentity,
    pub signer: PublicKey,
    pub probe: CanaryProbe,
    pub calls: AtomicUsize,
    pub prepared: Mutex<Option<ToolDispatchContext>>,
    pub prepared_stream: Mutex<Option<(Instant, UnixStream)>>,
    pub completion: Mutex<Option<BrokerExecuteResponse>>,
    pub fault: Option<CompletionFault>,
}

#[async_trait::async_trait]
impl crate::kernel_admission::BrokerMcpToolConnection for McpTool {
    async fn prepare_broker_delivery(
        &self,
        context: &ToolDispatchContext,
        stream: UnixStream,
    ) -> std::result::Result<(), KernelError> {
        // The host authenticates and prepares the descriptor. The confined
        // transport receives no privileged signing backend or socket path.
        if chio_secure_ipc::peer_identity(&stream).map_err(|_| transport_error())? != self.peer {
            return Err(transport_error());
        }
        *self.prepared_stream.lock().map_err(|_| transport_error())? =
            Some((Instant::now(), stream));
        *self.prepared.lock().map_err(|_| transport_error())? = Some(context.clone());
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for McpTool {
    fn server_id(&self) -> &str {
        "native-broker"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["send".into()]
    }

    async fn prepare_delivery(
        &self,
        _: &ToolDispatchContext,
    ) -> std::result::Result<(), KernelError> {
        Err(transport_error())
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        Err(transport_error())
    }

    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let dispatch = context.dispatch().ok_or_else(transport_error)?;
        let prepared = self.prepared.lock().map_err(|_| transport_error())?;
        let prepared = prepared.as_ref().ok_or_else(transport_error)?;
        assert_eq!(prepared.operation_id(), dispatch.operation_id());
        assert_eq!(prepared.attempt(), dispatch.attempt());
        assert_eq!(
            dispatch.caller_capability_sha256(),
            Some(context.capability_hash())
        );
        assert_eq!(context.server_id(), self.server_id());
        assert_eq!(context.tool_name(), "send");
        let execute: BrokerExecuteRequest =
            serde_json::from_value(arguments).map_err(|_| transport_error())?;
        assert_eq!(context.request_id(), execute.invocation_id);
        assert_eq!(
            context.capability_id(),
            execute.capability.body.parent_capability_id
        );
        assert_eq!(
            context.subject_key(),
            execute.capability.body.subject.to_hex()
        );
        assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0);

        let (connected, stream) = self
            .prepared_stream
            .lock()
            .map_err(|_| transport_error())?
            .take()
            .ok_or_else(transport_error)?;
        let ready_to_send = connected.elapsed();
        let mut command = helper_command(TOOL_HELPER, "tool", &self.directory);
        command
            .env(
                REQUEST_ENV,
                hex::encode(canonical_json_bytes(&execute).map_err(|_| transport_error())?),
            )
            .env(
                RECEIPT_SIGNER_ENV,
                hex::encode(canonical_json_bytes(&self.signer).map_err(|_| transport_error())?),
            )
            .env(CANARY_LENGTH_ENV, self.probe.length.to_string())
            .env(CANARY_DIGEST_ENV, hex::encode(self.probe.sha256))
            .env(BROKER_PID_ENV, self.peer.process_id.to_string());
        let output = spawn_with_stdin(command, OwnedFd::from(stream), "native MCP broker tool")
            .wait_output();
        self.probe.assert_absent(&output.stdout, "MCP tool stdout");
        self.probe.assert_absent(&output.stderr, "MCP tool stderr");
        // The existing helper emits its signed completion before a deliberate
        // fixed panic used to inspect crash diagnostics for credential leaks.
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(TOOL_PANIC_MARKER));
        if !String::from_utf8_lossy(&output.stdout).contains(TOOL_REPORT_PREFIX) {
            eprintln!(
                "MCP preconnected stream age at dispatch: {ready_to_send:?}; child diagnostic: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(transport_error());
        }
        let report: ToolBoundaryReport = report_from_output(&output.stdout, TOOL_REPORT_PREFIX);
        assert_eq!(report.schema, "chio.process-boundary-tool-report.v1");
        assert_eq!(
            report.scanned_surfaces,
            TOOL_SCANNED_SURFACES
                .iter()
                .map(|surface| (*surface).to_string())
                .collect::<Vec<_>>()
        );
        let mut response: BrokerExecuteResponse = serde_json::from_slice(
            &hex::decode(&report.execute_response_hex).map_err(|_| transport_error())?,
        )
        .map_err(|_| transport_error())?;
        *self.completion.lock().map_err(|_| transport_error())? = Some(response.clone());
        let mut content = Vec::new();
        match self.fault {
            Some(CompletionFault::LoseReply) => return Err(transport_error()),
            Some(CompletionFault::ChangeBody) => response.body.push(b'!'),
            Some(CompletionFault::ChangeHeaders) => {
                response.headers =
                    vec![
                        crate::protocol::HeaderField::normalized("content-type", b"text/html")
                            .map_err(|_| transport_error())?,
                    ];
            }
            Some(CompletionFault::ExtraContent) => {
                content.push(serde_json::json!({"type": "text", "text": "unbound output"}));
            }
            None => {}
        }
        Ok((
            serde_json::json!({
                "content": content,
                "structuredContent": response,
                "isError": false,
            }),
            None,
        ))
    }
}

fn transport_error() -> KernelError {
    KernelError::ToolServerError("broker MCP transport refused delivery".into())
}
