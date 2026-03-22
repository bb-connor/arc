use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::{AdapterError, McpTransport};
use chrono::{SecondsFormat, Utc};
use pact_core::capability::{CapabilityToken, Operation};
use pact_core::receipt::Decision;
use pact_core::session::{
    CompleteOperation, CompletionArgument, CompletionReference, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, ElicitationAction,
    GetPromptOperation, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, ReadResourceOperation, RequestId, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, RootDefinition, SessionAuthContext, SessionId, SessionOperation,
    SessionTransport, TaskOwnershipSnapshot, ToolCallOperation,
};
use pact_kernel::{
    LateSessionEvent, NestedFlowClient, PactKernel, PeerCapabilities, SessionOperationResponse,
    ToolCallOutput, ToolCallStream, ToolServerEvent, Verdict,
};
use pact_manifest::{LatencyHint, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_INTERNAL_ERROR: i64 = -32603;
const JSONRPC_SERVER_NOT_INITIALIZED: i64 = -32002;
const JSONRPC_URL_ELICITATION_REQUIRED: i64 = -32042;
const CLIENT_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PACT_TOOL_STREAMING_NOTIFICATION_METHOD: &str = "notifications/pact/tool_call_chunk";
const TASK_POLL_INTERVAL_MILLIS: u64 = 500;
const MAX_BACKGROUND_TASKS_PER_TICK: usize = 8;
const RELATED_TASK_META_KEY: &str = "io.modelcontextprotocol/related-task";

#[derive(Debug, Clone)]
pub struct McpEdgeConfig {
    pub server_name: String,
    pub server_version: String,
    pub page_size: usize,
    pub tools_list_changed: bool,
    pub completion_enabled: Option<bool>,
    pub resources_subscribe: bool,
    pub resources_list_changed: bool,
    pub prompts_list_changed: bool,
    pub logging_enabled: bool,
}

impl Default for McpEdgeConfig {
    fn default() -> Self {
        Self {
            server_name: "PACT MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size: 50,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl LogLevel {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "critical" => Some(Self::Critical),
            "alert" => Some(Self::Alert),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpExposedTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "outputSchema"
    )]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Value>,
}

#[derive(Debug, Clone)]
struct ExposedToolBinding {
    tool: McpExposedTool,
    server_id: String,
    tool_name: String,
}

#[derive(Debug, Clone)]
enum EdgeState {
    Uninitialized,
    WaitingForInitialized { session_id: SessionId },
    Ready { session_id: SessionId },
}

#[derive(Debug, Clone)]
enum EdgeAction {
    RefreshRoots {
        session_id: SessionId,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EdgeTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeTask {
    task_id: String,
    status: EdgeTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    created_at: String,
    last_updated_at: String,
    ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval: Option<u64>,
    ownership: TaskOwnershipSnapshot,
    owner_session_id: String,
    owner_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_request_id: Option<String>,
    #[serde(skip)]
    session_id: SessionId,
    #[serde(skip)]
    context: OperationContext,
    #[serde(skip)]
    operation: ToolCallOperation,
    #[serde(skip)]
    final_outcome: Option<EdgeTaskFinalOutcome>,
    #[serde(skip)]
    background_ready_at_ms: u64,
}

#[derive(Debug, Clone)]
enum EdgeTaskFinalOutcome {
    Result(Value),
    JsonRpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

enum ToolCallEdgeOutcome {
    Result(Value),
    Cancelled {
        reason: String,
    },
    JsonRpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

impl EdgeTask {
    fn new(
        task_id: String,
        session_id: SessionId,
        context: OperationContext,
        operation: ToolCallOperation,
        ttl: Option<u64>,
        background_start_delay_millis: u64,
    ) -> Self {
        let now = iso8601_now();
        Self {
            task_id,
            status: EdgeTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_session_id: session_id.to_string(),
            owner_request_id: context.request_id.to_string(),
            parent_request_id: context.parent_request_id.clone().map(|id| id.to_string()),
            session_id,
            context,
            operation,
            final_outcome: None,
            background_ready_at_ms: unix_now_millis() + background_start_delay_millis,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            EdgeTaskStatus::Completed | EdgeTaskStatus::Failed | EdgeTaskStatus::Cancelled
        )
    }

    fn touch(&mut self) {
        self.last_updated_at = iso8601_now();
    }

    fn mark_completed(&mut self, result: Value) {
        self.status = if tool_result_is_error(&result) {
            EdgeTaskStatus::Failed
        } else {
            EdgeTaskStatus::Completed
        };
        self.status_message = task_status_message(&self.status, &result);
        self.final_outcome = Some(EdgeTaskFinalOutcome::Result(result));
        self.touch();
    }

    fn mark_cancelled(&mut self, reason: &str) {
        self.status = EdgeTaskStatus::Cancelled;
        self.status_message = Some(reason.to_string());
        self.final_outcome = Some(EdgeTaskFinalOutcome::Result(tool_error_result(reason)));
        self.touch();
    }

    fn mark_jsonrpc_error(&mut self, code: i64, message: String, data: Option<Value>) {
        self.status = EdgeTaskStatus::Failed;
        self.status_message = Some(message.clone());
        self.final_outcome = Some(EdgeTaskFinalOutcome::JsonRpcError {
            code,
            message,
            data,
        });
        self.touch();
    }

    fn record_outcome(&mut self, outcome: ToolCallEdgeOutcome) {
        match outcome {
            ToolCallEdgeOutcome::Result(result) => self.mark_completed(result),
            ToolCallEdgeOutcome::Cancelled { reason } => self.mark_cancelled(&reason),
            ToolCallEdgeOutcome::JsonRpcError {
                code,
                message,
                data,
            } => self.mark_jsonrpc_error(code, message, data),
        }
    }

    fn background_ready(&self) -> bool {
        unix_now_millis() >= self.background_ready_at_ms
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestedTask {
    #[serde(default)]
    ttl: Option<u64>,
}

enum ClientInbound {
    Message(Value),
    ParseError(String),
    ReadError(String),
    Closed,
}

#[allow(dead_code)]
struct EdgeNestedFlowClient<'a, R, W> {
    request_counter: &'a mut u64,
    parent_progress_step: &'a mut u64,
    parent_client_request_id: &'a Value,
    parent_kernel_request_id: &'a RequestId,
    pending_notifications: &'a mut Vec<Value>,
    deferred_client_messages: &'a mut Vec<Value>,
    accepted_url_elicitations: &'a mut Vec<AcceptedUrlElicitation>,
    logging_enabled: bool,
    minimum_log_level: LogLevel,
    related_task_id: Option<&'a str>,
    reader: &'a mut R,
    writer: &'a mut W,
}

struct QueuedEdgeNestedFlowClient<'a, W> {
    request_counter: &'a mut u64,
    parent_progress_step: &'a mut u64,
    parent_client_request_id: &'a Value,
    parent_kernel_request_id: &'a RequestId,
    pending_notifications: &'a mut Vec<Value>,
    deferred_client_messages: &'a mut Vec<Value>,
    accepted_url_elicitations: &'a mut Vec<AcceptedUrlElicitation>,
    logging_enabled: bool,
    minimum_log_level: LogLevel,
    related_task_id: Option<&'a str>,
    client_rx: &'a mpsc::Receiver<ClientInbound>,
    cancel_rx: &'a mpsc::Receiver<Value>,
    writer: &'a mut W,
}

#[derive(Debug, Clone)]
struct AcceptedUrlElicitation {
    elicitation_id: String,
    related_task_id: Option<String>,
}

#[allow(dead_code)]
impl<R: BufRead, W: Write> EdgeNestedFlowClient<'_, R, W> {
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
    ) -> Result<Value, pact_kernel::KernelError> {
        *self.request_counter += 1;
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
        write_jsonrpc_line(self.writer, &request)
            .map_err(|error| pact_kernel::KernelError::Internal(error.to_string()))?;

        loop {
            let message = read_jsonrpc_line(self.reader)
                .map_err(|error| pact_kernel::KernelError::Internal(error.to_string()))?;

            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    let message = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown JSON-RPC error");
                    return Err(pact_kernel::KernelError::Internal(message.to_string()));
                }

                return message.get("result").cloned().ok_or_else(|| {
                    pact_kernel::KernelError::Internal(
                        "response missing 'result' field".to_string(),
                    )
                });
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(pact_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }

            if cancellation_matches_client_request(&message, self.parent_client_request_id) {
                return Err(pact_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }

            if message.get("id").is_none() {
                continue;
            }

            if message.get("method").is_some() {
                let explicit_task_cancel =
                    task_cancel_matches_related_task(&message, self.related_task_id);
                self.deferred_client_messages.push(message);
                if explicit_task_cancel {
                    return Err(pact_kernel::KernelError::RequestCancelled {
                        request_id: self.parent_kernel_request_id.clone(),
                        reason: explicit_task_cancel_reason().to_string(),
                    });
                }
                continue;
            }

            return Err(pact_kernel::KernelError::Internal(
                "outer MCP client sent an unexpected request while a nested flow was in flight"
                    .to_string(),
            ));
        }
    }

    fn flush_notifications(&mut self) -> Result<(), pact_kernel::KernelError> {
        for notification in std::mem::take(self.pending_notifications) {
            write_jsonrpc_line(self.writer, &notification)
                .map_err(|error| pact_kernel::KernelError::Internal(error.to_string()))?;
        }
        Ok(())
    }
}

impl<W: Write> QueuedEdgeNestedFlowClient<'_, W> {
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
    ) -> Result<Value, pact_kernel::KernelError> {
        *self.request_counter += 1;
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
        write_jsonrpc_line(self.writer, &request)
            .map_err(|error| pact_kernel::KernelError::Internal(error.to_string()))?;

        loop {
            let message = next_client_message(self.client_rx)
                .map_err(|error| pact_kernel::KernelError::Internal(error.to_string()))?;

            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    let message = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown JSON-RPC error");
                    return Err(pact_kernel::KernelError::Internal(message.to_string()));
                }

                return message.get("result").cloned().ok_or_else(|| {
                    pact_kernel::KernelError::Internal(
                        "response missing 'result' field".to_string(),
                    )
                });
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(pact_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }

            if cancellation_matches_client_request(&message, self.parent_client_request_id) {
                return Err(pact_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }

            if message.get("method").is_some() {
                let explicit_task_cancel =
                    task_cancel_matches_related_task(&message, self.related_task_id);
                self.deferred_client_messages.push(message);
                if explicit_task_cancel {
                    return Err(pact_kernel::KernelError::RequestCancelled {
                        request_id: self.parent_kernel_request_id.clone(),
                        reason: explicit_task_cancel_reason().to_string(),
                    });
                }
                continue;
            }

            return Err(pact_kernel::KernelError::Internal(
                "outer MCP client sent an unexpected response while a nested flow was in flight"
                    .to_string(),
            ));
        }
    }

    fn flush_notifications(&mut self) -> Result<(), pact_kernel::KernelError> {
        for notification in std::mem::take(self.pending_notifications) {
            write_jsonrpc_line(self.writer, &notification)
                .map_err(|error| pact_kernel::KernelError::Internal(error.to_string()))?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl<R: BufRead, W: Write> NestedFlowClient for EdgeNestedFlowClient<'_, R, W> {
    fn list_roots(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, pact_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting client roots",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.roots",
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
            pact_kernel::KernelError::Internal("roots/list response missing 'roots'".to_string())
        })?;
        let roots: Vec<RootDefinition> = serde_json::from_value(roots_value).map_err(|error| {
            pact_kernel::KernelError::Internal(format!("failed to parse roots: {error}"))
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
            "pact.mcp.roots",
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
    ) -> Result<CreateMessageResult, pact_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting sampled message from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.sampling",
            json!({
                "event": "sampling_request_started",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "toolCount": operation.tools.len(),
            }),
        );
        self.flush_notifications()?;

        let params = serde_json::to_value(operation).map_err(|error| {
            pact_kernel::KernelError::Internal(format!(
                "failed to serialize sampling/createMessage params: {error}"
            ))
        })?;
        let result =
            self.send_client_request("sampling/createMessage", params, &child_context.request_id)?;
        let message: CreateMessageResult = serde_json::from_value(result).map_err(|error| {
            pact_kernel::KernelError::Internal(format!(
                "failed to parse sampling/createMessage result: {error}"
            ))
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
            "pact.mcp.sampling",
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
    ) -> Result<CreateElicitationResult, pact_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting elicitation response from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.elicitation",
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
            pact_kernel::KernelError::Internal(format!(
                "failed to serialize elicitation/create params: {error}"
            ))
        })?;
        let result =
            self.send_client_request("elicitation/create", params, &child_context.request_id)?;
        let elicitation: CreateElicitationResult =
            serde_json::from_value(result).map_err(|error| {
                pact_kernel::KernelError::Internal(format!(
                    "failed to parse elicitation/create result: {error}"
                ))
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
            "pact.mcp.elicitation",
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
    ) -> Result<(), pact_kernel::KernelError> {
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
    ) -> Result<(), pact_kernel::KernelError> {
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
    ) -> Result<(), pact_kernel::KernelError> {
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

impl<W: Write> NestedFlowClient for QueuedEdgeNestedFlowClient<'_, W> {
    fn poll_parent_cancellation(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), pact_kernel::KernelError> {
        while let Ok(message) = self.cancel_rx.try_recv() {
            if cancellation_matches_client_request(&message, self.parent_client_request_id) {
                return Err(pact_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: cancellation_reason(&message),
                });
            }
            if task_cancel_matches_related_task(&message, self.related_task_id) {
                return Err(pact_kernel::KernelError::RequestCancelled {
                    request_id: self.parent_kernel_request_id.clone(),
                    reason: explicit_task_cancel_reason().to_string(),
                });
            }
        }

        Ok(())
    }

    fn list_roots(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, pact_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting client roots",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.roots",
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
            pact_kernel::KernelError::Internal("roots/list response missing 'roots'".to_string())
        })?;
        let roots: Vec<RootDefinition> = serde_json::from_value(roots_value).map_err(|error| {
            pact_kernel::KernelError::Internal(format!("failed to parse roots: {error}"))
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
            "pact.mcp.roots",
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
    ) -> Result<CreateMessageResult, pact_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting sampled message from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.sampling",
            json!({
                "event": "sampling_request_started",
                "requestId": child_context.request_id.as_str(),
                "parentRequestId": parent_context.request_id.as_str(),
                "toolCount": operation.tools.len(),
            }),
        );
        self.flush_notifications()?;

        let params = serde_json::to_value(operation).map_err(|error| {
            pact_kernel::KernelError::Internal(format!(
                "failed to serialize sampling/createMessage params: {error}"
            ))
        })?;
        let result =
            self.send_client_request("sampling/createMessage", params, &child_context.request_id)?;
        let message: CreateMessageResult = serde_json::from_value(result).map_err(|error| {
            pact_kernel::KernelError::Internal(format!(
                "failed to parse sampling/createMessage result: {error}"
            ))
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
            "pact.mcp.sampling",
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
    ) -> Result<CreateElicitationResult, pact_kernel::KernelError> {
        queue_progress_notification(
            self.pending_notifications,
            parent_context.progress_token.as_ref(),
            self.parent_progress_step,
            "Requesting elicitation response from client",
            self.related_task_id,
        );
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.elicitation",
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
            pact_kernel::KernelError::Internal(format!(
                "failed to serialize elicitation/create params: {error}"
            ))
        })?;
        let result =
            self.send_client_request("elicitation/create", params, &child_context.request_id)?;
        let elicitation: CreateElicitationResult =
            serde_json::from_value(result).map_err(|error| {
                pact_kernel::KernelError::Internal(format!(
                    "failed to parse elicitation/create result: {error}"
                ))
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
            "pact.mcp.elicitation",
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
    ) -> Result<(), pact_kernel::KernelError> {
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
    ) -> Result<(), pact_kernel::KernelError> {
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
    ) -> Result<(), pact_kernel::KernelError> {
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

pub struct PactMcpEdge {
    config: McpEdgeConfig,
    kernel: PactKernel,
    agent_id: String,
    session_auth_context: SessionAuthContext,
    capabilities: Vec<CapabilityToken>,
    tools: Vec<ExposedToolBinding>,
    tool_index: BTreeMap<String, usize>,
    request_counter: u64,
    client_request_counter: u64,
    state: EdgeState,
    minimum_log_level: LogLevel,
    pending_actions: Vec<EdgeAction>,
    pending_notifications: Vec<Value>,
    deferred_client_messages: Vec<Value>,
    task_counter: u64,
    tasks: BTreeMap<String, EdgeTask>,
    pending_background_tasks: Vec<String>,
    upstream_transport: Option<Arc<dyn McpTransport>>,
}

impl PactMcpEdge {
    pub fn new(
        config: McpEdgeConfig,
        kernel: PactKernel,
        agent_id: String,
        capabilities: Vec<CapabilityToken>,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, AdapterError> {
        let mut tool_index = BTreeMap::new();
        let mut tools = Vec::new();

        for manifest in manifests {
            for tool in manifest.tools {
                if tool_index.contains_key(&tool.name) {
                    return Err(AdapterError::ManifestError(
                        pact_manifest::ManifestError::DuplicateToolName(tool.name),
                    ));
                }

                let exposed_name = tool.name.clone();
                let binding = ExposedToolBinding {
                    tool: manifest_tool_to_mcp_tool(tool),
                    server_id: manifest.server_id.clone(),
                    tool_name: exposed_name.clone(),
                };
                tool_index.insert(exposed_name, tools.len());
                tools.push(binding);
            }
        }

        Ok(Self {
            config,
            kernel,
            agent_id,
            session_auth_context: SessionAuthContext::stdio_anonymous(),
            capabilities,
            tools,
            tool_index,
            request_counter: 0,
            client_request_counter: 0,
            state: EdgeState::Uninitialized,
            minimum_log_level: LogLevel::Info,
            pending_actions: Vec::new(),
            pending_notifications: Vec::new(),
            deferred_client_messages: Vec::new(),
            task_counter: 0,
            tasks: BTreeMap::new(),
            pending_background_tasks: Vec::new(),
            upstream_transport: None,
        })
    }

    pub fn attach_upstream_transport(&mut self, transport: Arc<dyn McpTransport>) {
        self.upstream_transport = Some(transport);
    }

    pub fn set_session_auth_context(&mut self, auth_context: SessionAuthContext) {
        self.session_auth_context = auth_context;
    }

    pub fn handle_jsonrpc(&mut self, message: Value) -> Option<Value> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc envelope",
            ));
        }

        let method = match message.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(jsonrpc_error(
                    message.get("id").cloned().unwrap_or(Value::Null),
                    JSONRPC_INVALID_REQUEST,
                    "request missing method",
                ))
            }
        };

        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match message.get("id").cloned() {
            Some(id) => Some(self.handle_request(id, method, params)),
            None => self.handle_notification(method, params),
        }
    }

    /// Advance in-process background work and return any queued notifications.
    ///
    /// This is the session-owned late-event surface for embedders that drive the
    /// edge directly via `handle_jsonrpc` instead of a transport loop.
    pub fn drain_runtime_notifications(&mut self) -> Result<Vec<Value>, AdapterError> {
        let _ = self.process_background_tasks()?;
        self.forward_runtime_events();
        Ok(self.take_pending_notifications())
    }

    #[allow(dead_code)]
    fn handle_jsonrpc_with_transport<R: BufRead, W: Write>(
        &mut self,
        message: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Option<Value> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc envelope",
            ));
        }

        let method = match message.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(jsonrpc_error(
                    message.get("id").cloned().unwrap_or(Value::Null),
                    JSONRPC_INVALID_REQUEST,
                    "request missing method",
                ))
            }
        };

        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match message.get("id").cloned() {
            Some(id) => {
                Some(self.handle_request_with_transport(id, method, params, reader, writer))
            }
            None => self.handle_notification(method, params),
        }
    }

    fn handle_jsonrpc_with_transport_channel<W: Write>(
        &mut self,
        message: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Option<Value> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc envelope",
            ));
        }

        let method = match message.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(jsonrpc_error(
                    message.get("id").cloned().unwrap_or(Value::Null),
                    JSONRPC_INVALID_REQUEST,
                    "request missing method",
                ))
            }
        };

        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match message.get("id").cloned() {
            Some(id) => Some(self.handle_request_with_transport_channel(
                id, method, params, client_rx, cancel_rx, writer,
            )),
            None => self.handle_notification(method, params),
        }
    }

    pub fn serve_stdio<R: BufRead + Send + 'static, W: Write>(
        &mut self,
        reader: R,
        mut writer: W,
    ) -> Result<(), AdapterError> {
        let (client_tx, client_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = mpsc::channel();
        std::thread::spawn(move || pump_client_messages(reader, client_tx, cancel_tx));

        self.serve_inbound_loop(&client_rx, &cancel_rx, &mut writer)
    }

    pub fn serve_message_channels<W: Write>(
        &mut self,
        client_rx: mpsc::Receiver<Value>,
        mut writer: W,
    ) -> Result<(), AdapterError> {
        let (inbound_tx, inbound_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = mpsc::channel();
        std::thread::spawn(move || pump_channel_messages(client_rx, inbound_tx, cancel_tx));

        self.serve_inbound_loop(&inbound_rx, &cancel_rx, &mut writer)
    }

    fn serve_inbound_loop<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        loop {
            self.forward_runtime_events();
            self.flush_pending_notifications(writer)?;

            if let Some(message) = self.take_deferred_client_message() {
                let response = self
                    .handle_jsonrpc_with_transport_channel(message, client_rx, cancel_rx, writer);
                self.process_pending_actions_with_channel(client_rx, writer)?;
                self.forward_runtime_events();
                self.flush_pending_notifications(writer)?;
                if let Some(response) = response {
                    write_jsonrpc_line(writer, &response)?;
                }
                self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                continue;
            }

            match client_rx.recv_timeout(CLIENT_IDLE_POLL_INTERVAL) {
                Ok(ClientInbound::Message(message)) => {
                    let response = self.handle_jsonrpc_with_transport_channel(
                        message, client_rx, cancel_rx, writer,
                    );
                    self.process_pending_actions_with_channel(client_rx, writer)?;
                    self.forward_runtime_events();
                    self.flush_pending_notifications(writer)?;
                    if let Some(response) = response {
                        write_jsonrpc_line(writer, &response)?;
                    }
                    self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                }
                Ok(ClientInbound::ParseError(error)) => {
                    write_jsonrpc_line(
                        writer,
                        &jsonrpc_error(Value::Null, -32700, &format!("invalid JSON: {error}")),
                    )?;
                    self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                }
                Ok(ClientInbound::ReadError(error)) => {
                    return Err(AdapterError::ConnectionFailed(format!(
                        "failed to read MCP edge request: {error}"
                    )));
                }
                Ok(ClientInbound::Closed) => {
                    self.forward_runtime_events();
                    self.flush_pending_notifications(writer)?;
                    return Ok(());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }

    fn handle_request(&mut self, id: Value, method: &str, params: Value) -> Value {
        match method {
            "initialize" => self.handle_initialize(id, params),
            "ping" => jsonrpc_result(id, json!({})),
            "tools/list" => self.handle_tools_list(id, params),
            "tools/call" => self.handle_tools_call(id, params),
            "tasks/list" => self.handle_tasks_list(id, params),
            "tasks/get" => self.handle_tasks_get(id, params),
            "tasks/result" => self.handle_tasks_result(id, params),
            "tasks/cancel" => self.handle_tasks_cancel(id, params),
            "resources/list" => self.handle_resources_list(id, params),
            "resources/read" => self.handle_resources_read(id, params),
            "resources/subscribe" => self.handle_resources_subscribe(id, params),
            "resources/unsubscribe" => self.handle_resources_unsubscribe(id, params),
            "resources/templates/list" => self.handle_resource_templates_list(id, params),
            "prompts/list" => self.handle_prompts_list(id, params),
            "prompts/get" => self.handle_prompts_get(id, params),
            "completion/complete" => self.handle_completion(id, params),
            "logging/setLevel" => self.handle_logging_set_level(id, params),
            _ => jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found"),
        }
    }

    #[allow(dead_code)]
    fn handle_request_with_transport<R: BufRead, W: Write>(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        match method {
            "tools/call" => self.handle_tools_call_with_transport(id, params, reader, writer),
            "tasks/result" => self.handle_tasks_result_with_transport(id, params, reader, writer),
            _ => self.handle_request(id, method, params),
        }
    }

    fn handle_request_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        match method {
            "tools/call" => self
                .handle_tools_call_with_transport_channel(id, params, client_rx, cancel_rx, writer),
            "tasks/result" => self.handle_tasks_result_with_transport_channel(
                id, params, client_rx, cancel_rx, writer,
            ),
            _ => self.handle_request(id, method, params),
        }
    }

    fn handle_notification(&mut self, method: &str, _params: Value) -> Option<Value> {
        match method {
            "notifications/initialized" => {
                let session_id = match &self.state {
                    EdgeState::WaitingForInitialized { session_id } => session_id.clone(),
                    _ => return None,
                };
                if let Err(error) = self.kernel.activate_session(&session_id) {
                    return Some(jsonrpc_error(
                        Value::Null,
                        JSONRPC_INTERNAL_ERROR,
                        &format!("failed to activate session: {error}"),
                    ));
                }
                self.state = EdgeState::Ready {
                    session_id: session_id.clone(),
                };
                if self
                    .kernel
                    .session(&session_id)
                    .is_some_and(|session| session.peer_capabilities().supports_roots)
                {
                    self.queue_roots_refresh(session_id, "initialized");
                }
                None
            }
            "notifications/roots/list_changed" => {
                if let EdgeState::Ready { session_id } = &self.state {
                    if self.kernel.session(session_id).is_some_and(|session| {
                        session.peer_capabilities().supports_roots
                            && session.peer_capabilities().roots_list_changed
                    }) {
                        self.queue_roots_refresh(session_id.clone(), "list_changed");
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn handle_initialize(&mut self, id: Value, params: Value) -> Value {
        if !matches!(self.state, EdgeState::Uninitialized) {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_REQUEST,
                "initialize may only be called once",
            );
        }

        let session_id = self
            .kernel
            .open_session(self.agent_id.clone(), self.capabilities.clone());
        if let Err(error) = self
            .kernel
            .set_session_auth_context(&session_id, self.session_auth_context.clone())
        {
            return jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to persist session auth context: {error}"),
            );
        }
        let peer_capabilities = parse_peer_capabilities(&params);
        if let Err(error) = self
            .kernel
            .set_session_peer_capabilities(&session_id, peer_capabilities)
        {
            return jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to persist peer capabilities: {error}"),
            );
        }
        self.state = EdgeState::WaitingForInitialized { session_id };

        let mut capabilities = serde_json::Map::new();
        capabilities.insert(
            "tools".to_string(),
            json!({
                "listChanged": self.config.tools_list_changed
            }),
        );
        if self.kernel.resource_provider_count() > 0 {
            capabilities.insert(
                "resources".to_string(),
                json!({
                    "subscribe": self.config.resources_subscribe,
                    "listChanged": self.config.resources_list_changed,
                }),
            );
        }
        if self.kernel.prompt_provider_count() > 0 {
            capabilities.insert(
                "prompts".to_string(),
                json!({
                    "listChanged": self.config.prompts_list_changed,
                }),
            );
        }
        if self.has_completion_support() {
            capabilities.insert("completions".to_string(), json!({}));
        }
        if self.config.logging_enabled {
            capabilities.insert("logging".to_string(), json!({}));
        }
        capabilities.insert(
            "experimental".to_string(),
            json!({
                "pactToolStreaming": {
                    "toolCallChunkNotifications": true,
                }
            }),
        );
        capabilities.insert(
            "tasks".to_string(),
            json!({
                "list": {},
                "cancel": {},
                "requests": {
                    "tools": {
                        "call": {},
                    }
                }
            }),
        );

        jsonrpc_result(
            id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": Value::Object(capabilities),
                "serverInfo": {
                    "name": self.config.server_name,
                    "version": self.config.server_version,
                }
            }),
        )
    }

    fn handle_tools_list(&mut self, id: Value, params: Value) -> Value {
        if !matches!(self.state, EdgeState::Ready { .. }) {
            return jsonrpc_error(
                id,
                JSONRPC_SERVER_NOT_INITIALIZED,
                "tools/list requires initialize followed by notifications/initialized",
            );
        }

        let cursor = match params.get("cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(cursor)) => Some(cursor.clone()),
            Some(_) => {
                return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor must be a string");
            }
        };

        let start = match cursor.as_deref() {
            None => 0,
            Some(cursor) => match cursor.parse::<usize>() {
                Ok(parsed) => parsed,
                Err(_) => {
                    return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor must be numeric")
                }
            },
        };

        let visible_tools = self.visible_tools();
        if start > visible_tools.len() {
            return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
        }

        let page_size = self.config.page_size.max(1);
        let end = (start + page_size).min(visible_tools.len());
        let next_cursor = (end < visible_tools.len()).then(|| end.to_string());
        let tools = visible_tools[start..end]
            .iter()
            .map(|binding| serde_json::to_value(&binding.tool).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        jsonrpc_result(
            id,
            json!({
                "tools": tools,
                "nextCursor": next_cursor,
            }),
        )
    }

    fn prepare_tool_call_request(
        &mut self,
        id: &Value,
        params: &Value,
    ) -> Result<(SessionId, OperationContext, ToolCallOperation), Value> {
        let session_id = match &self.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_SERVER_NOT_INITIALIZED,
                    "tools/call requires initialize followed by notifications/initialized",
                ))
            }
        };

        let tool_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    "tools/call requires a tool name",
                ))
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let Some(&tool_index) = self.tool_index.get(tool_name) else {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "unknown tool",
            ));
        };
        let binding = self.tools[tool_index].clone();

        let capability = match select_capability_for_request(
            &self.capabilities,
            &binding.tool_name,
            &binding.server_id,
            &arguments,
        ) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.tools",
                    json!({
                        "event": "tool_denied",
                        "tool": binding.tool_name,
                        "server": binding.server_id,
                    }),
                );
                return Err(jsonrpc_result(
                    id.clone(),
                    tool_error_result("tool is not authorized by the active capability set"),
                ));
            }
        };

        let request_id = self.next_request_id();
        let context =
            build_operation_context(id, session_id.clone(), request_id, &self.agent_id, params)?;

        Ok((
            session_id,
            context,
            ToolCallOperation {
                capability,
                server_id: binding.server_id,
                tool_name: binding.tool_name,
                arguments,
            },
        ))
    }

    fn evaluate_tool_call_operation(
        &mut self,
        id: &Value,
        session_id: &SessionId,
        context: &OperationContext,
        operation: &ToolCallOperation,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let operation = SessionOperation::ToolCall(operation.clone());
        match self.kernel.evaluate_session_operation(context, &operation) {
            Ok(SessionOperationResponse::ToolCall(response)) => self
                .tool_result_for_kernel_response(
                    id,
                    session_id,
                    response.output,
                    response.reason,
                    response.verdict,
                    &response.terminal_state,
                    related_task_id,
                ),
            Ok(
                SessionOperationResponse::RootList { .. }
                | SessionOperationResponse::ResourceList { .. }
                | SessionOperationResponse::ResourceRead { .. }
                | SessionOperationResponse::ResourceReadDenied { .. }
                | SessionOperationResponse::ResourceTemplateList { .. }
                | SessionOperationResponse::PromptList { .. }
                | SessionOperationResponse::PromptGet { .. }
                | SessionOperationResponse::Completion { .. }
                | SessionOperationResponse::CapabilityList { .. }
                | SessionOperationResponse::Heartbeat,
            ) => ToolCallEdgeOutcome::JsonRpcError {
                code: JSONRPC_INTERNAL_ERROR,
                message: "unexpected kernel response type".to_string(),
                data: None,
            },
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "pact.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_tool_call_operation_with_transport<R: BufRead, W: Write>(
        &mut self,
        id: &Value,
        session_id: &SessionId,
        context: &OperationContext,
        operation: &ToolCallOperation,
        reader: &mut R,
        writer: &mut W,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = EdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            reader,
            writer,
        };

        let outcome = match self
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                operation,
                &mut nested_flow_client,
            ) {
            Ok(response) => self.tool_result_for_kernel_response(
                id,
                session_id,
                response.output,
                response.reason,
                response.verdict,
                &response.terminal_state,
                related_task_id,
            ),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "pact.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_tool_call_operation_with_transport_channel<W: Write>(
        &mut self,
        id: &Value,
        session_id: &SessionId,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = QueuedEdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            client_rx,
            cancel_rx,
            writer,
        };

        let outcome = match self
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                operation,
                &mut nested_flow_client,
            ) {
            Ok(response) => self.tool_result_for_kernel_response(
                id,
                session_id,
                response.output,
                response.reason,
                response.verdict,
                &response.terminal_state,
                related_task_id,
            ),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "pact.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }

    fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("mcp-edge-task-{}", self.task_counter)
    }

    fn create_tool_call_task(
        &mut self,
        id: Value,
        session_id: SessionId,
        context: OperationContext,
        operation: ToolCallOperation,
        requested_task: RequestedTask,
        queue_background: bool,
    ) -> Value {
        let task_id = self.next_task_id();
        let task = EdgeTask::new(
            task_id.clone(),
            session_id,
            context,
            operation,
            requested_task.ttl,
            self.background_task_start_delay_millis(),
        );
        let task_view = task.clone();
        self.tasks.insert(task_id, task);
        if queue_background {
            self.pending_background_tasks
                .push(task_view.task_id.clone());
        }
        jsonrpc_result(id, json!({ "task": task_view }))
    }

    fn background_task_start_delay_millis(&self) -> u64 {
        match self.session_auth_context.transport {
            SessionTransport::StreamableHttp => TASK_POLL_INTERVAL_MILLIS,
            SessionTransport::InProcess | SessionTransport::Stdio => 0,
        }
    }

    fn handle_tools_call(&mut self, id: Value, params: Value) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation(&id, &session_id, &context, &operation, None),
        )
    }

    #[allow(dead_code)]
    fn handle_tools_call_with_transport<R: BufRead, W: Write>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                false,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport(
                &id,
                &session_id,
                &context,
                &operation,
                reader,
                writer,
                None,
            ),
        )
    }

    fn handle_tools_call_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport_channel(
                &id,
                &session_id,
                &context,
                &operation,
                client_rx,
                cancel_rx,
                writer,
                None,
            ),
        )
    }

    fn handle_tasks_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let tasks = self
            .tasks
            .values()
            .filter(|task| task.session_id == session_id)
            .cloned()
            .collect::<Vec<_>>();
        if start > tasks.len() {
            return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
        }

        let page_size = self.config.page_size.max(1);
        let end = (start + page_size).min(tasks.len());
        let next_cursor = (end < tasks.len()).then(|| end.to_string());
        let page = tasks[start..end]
            .iter()
            .map(|task| serde_json::to_value(task).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        jsonrpc_result(
            id,
            json!({
                "tasks": page,
                "nextCursor": next_cursor,
                "total": tasks.len(),
            }),
        )
    }

    fn handle_tasks_get(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let Some(task) = self.tasks.get(&task_id) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        jsonrpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    fn handle_tasks_cancel(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let Some(mut task) = self.tasks.remove(&task_id) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        };
        if task.session_id != session_id {
            self.tasks.insert(task_id, task);
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }
        if task.is_terminal() {
            let status = task.status;
            let task_view = task.clone();
            self.tasks.insert(task_id, task);
            return match status {
                EdgeTaskStatus::Cancelled => jsonrpc_result(
                    id,
                    serde_json::to_value(task_view).unwrap_or_else(|_| json!({})),
                ),
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    &format!(
                        "cannot cancel task: already in terminal status '{}'",
                        edge_task_status_label(status)
                    ),
                ),
            };
        }

        task.mark_cancelled("task cancelled by client");
        self.dequeue_background_task(&task_id);
        let task_view = task.clone();
        self.queue_task_status_notification(&task_view);
        self.tasks.insert(task_id, task);
        jsonrpc_result(
            id,
            serde_json::to_value(task_view).unwrap_or_else(|_| json!({})),
        )
    }

    fn handle_tasks_result(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation(
                &id,
                &session_id,
                &task.context,
                &task.operation,
                Some(task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    fn handle_tasks_result_with_transport<R: BufRead, W: Write>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation_with_transport(
                &id,
                &session_id,
                &task.context,
                &task.operation,
                reader,
                writer,
                Some(task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    fn handle_tasks_result_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation_with_transport_channel(
                &id,
                &session_id,
                &task.context,
                &task.operation,
                client_rx,
                cancel_rx,
                writer,
                Some(task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    fn handle_resources_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let response = match self
            .kernel
            .evaluate_session_operation(&context, &SessionOperation::ListResources)
        {
            Ok(SessionOperationResponse::ResourceList { resources }) => resources,
            Ok(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "unexpected kernel response type",
                )
            }
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to list resources: {error}"),
                )
            }
        };

        paginate_response(
            id,
            start,
            self.config.page_size,
            serialize_resources(response),
        )
    }

    fn handle_resource_templates_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let response = match self
            .kernel
            .evaluate_session_operation(&context, &SessionOperation::ListResourceTemplates)
        {
            Ok(SessionOperationResponse::ResourceTemplateList { templates }) => templates,
            Ok(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "unexpected kernel response type",
                )
            }
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to list resource templates: {error}"),
                )
            }
        };

        paginate_named_response(
            id,
            start,
            self.config.page_size,
            "resourceTemplates",
            serialize_resource_templates(response),
        )
    }

    fn handle_resources_read(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri.to_string(),
            None => {
                return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "resources/read requires a uri")
            }
        };

        let capability = match select_capability_for_resource(&self.capabilities, &uri) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.resources",
                    json!({
                        "event": "resource_denied",
                        "uri": uri,
                    }),
                );
                return jsonrpc_error(id, -32002, "Resource not found");
            }
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let operation = SessionOperation::ReadResource(ReadResourceOperation { capability, uri });

        match self.kernel.evaluate_session_operation(&context, &operation) {
            Ok(SessionOperationResponse::ResourceRead { contents }) => jsonrpc_result(
                id,
                json!({
                    "contents": serialize_resource_contents(contents),
                }),
            ),
            Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => {
                let reason = match &receipt.decision {
                    Decision::Deny { reason, .. } => reason.clone(),
                    _ => "filesystem-backed resource read denied".to_string(),
                };
                let uri = receipt
                    .action
                    .parameters
                    .get("uri")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.resources",
                    json!({
                        "event": "resource_root_denied",
                        "uri": uri,
                        "reason": reason,
                    }),
                );
                jsonrpc_error_with_data(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    &format!("resource read denied: {reason}"),
                    Some(json!({
                        "receipt": receipt,
                    })),
                )
            }
            Ok(_) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                "unexpected kernel response type",
            ),
            Err(error) => match error {
                pact_kernel::KernelError::OutOfScopeResource { .. }
                | pact_kernel::KernelError::ResourceNotRegistered(_) => {
                    jsonrpc_error(id, -32002, "Resource not found")
                }
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to read resource: {error}"),
                ),
            },
        }
    }

    fn handle_resources_subscribe(&mut self, id: Value, params: Value) -> Value {
        if !self.config.resources_subscribe {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri.to_string(),
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "resources/subscribe requires a uri",
                )
            }
        };

        let capability = match select_capability_for_resource_subscription(&self.capabilities, &uri)
        {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.resources",
                    json!({
                        "event": "resource_subscription_denied",
                        "uri": uri,
                    }),
                );
                return jsonrpc_error(id, -32002, "Resource not found");
            }
        };

        match self
            .kernel
            .subscribe_session_resource(&session_id, &capability, &self.agent_id, &uri)
        {
            Ok(()) => jsonrpc_result(id, json!({})),
            Err(error) => match error {
                pact_kernel::KernelError::OutOfScopeResource { .. }
                | pact_kernel::KernelError::ResourceNotRegistered(_) => {
                    jsonrpc_error(id, -32002, "Resource not found")
                }
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to subscribe to resource: {error}"),
                ),
            },
        }
    }

    fn handle_resources_unsubscribe(&mut self, id: Value, params: Value) -> Value {
        if !self.config.resources_subscribe {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri.to_string(),
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "resources/unsubscribe requires a uri",
                )
            }
        };

        match self.kernel.unsubscribe_session_resource(&session_id, &uri) {
            Ok(()) => jsonrpc_result(id, json!({})),
            Err(error) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to unsubscribe from resource: {error}"),
            ),
        }
    }

    fn handle_prompts_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let response = match self
            .kernel
            .evaluate_session_operation(&context, &SessionOperation::ListPrompts)
        {
            Ok(SessionOperationResponse::PromptList { prompts }) => prompts,
            Ok(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "unexpected kernel response type",
                )
            }
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to list prompts: {error}"),
                )
            }
        };

        paginate_named_response(
            id,
            start,
            self.config.page_size,
            "prompts",
            serialize_prompts(response),
        )
    }

    fn handle_prompts_get(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let prompt_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name.to_string(),
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "prompts/get requires a prompt name",
                )
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let capability = match select_capability_for_prompt(&self.capabilities, &prompt_name) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.prompts",
                    json!({
                        "event": "prompt_denied",
                        "prompt": prompt_name,
                    }),
                );
                return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "unknown prompt");
            }
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let operation = SessionOperation::GetPrompt(GetPromptOperation {
            capability,
            prompt_name,
            arguments,
        });

        match self.kernel.evaluate_session_operation(&context, &operation) {
            Ok(SessionOperationResponse::PromptGet { prompt }) => jsonrpc_result(
                id,
                serde_json::to_value(prompt).unwrap_or_else(|_| json!({})),
            ),
            Ok(_) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                "unexpected kernel response type",
            ),
            Err(error) => match error {
                pact_kernel::KernelError::OutOfScopePrompt { .. }
                | pact_kernel::KernelError::PromptNotRegistered(_) => {
                    jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "unknown prompt")
                }
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to get prompt: {error}"),
                ),
            },
        }
    }

    fn handle_completion(&mut self, id: Value, params: Value) -> Value {
        if !self.has_completion_support() {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };

        let reference = match parse_completion_reference(&params) {
            Ok(reference) => reference,
            Err(response) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, &response),
        };
        let argument = match parse_completion_argument(&params) {
            Ok(argument) => argument,
            Err(response) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, &response),
        };
        let context_arguments = params
            .get("context")
            .and_then(|context| context.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        let capability = match &reference {
            CompletionReference::Prompt { name } => {
                select_capability_for_prompt(&self.capabilities, name)
            }
            CompletionReference::Resource { uri } => {
                select_capability_for_resource_pattern(&self.capabilities, uri)
            }
        };
        let Some(capability) = capability else {
            self.emit_log(
                LogLevel::Warning,
                "pact.mcp.completion",
                json!({
                    "event": "completion_denied",
                    "reference": &reference,
                    "argument": &argument.name,
                }),
            );
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "completion target is not authorized",
            );
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let operation = SessionOperation::Complete(CompleteOperation {
            capability,
            reference,
            argument,
            context_arguments,
        });

        match self.kernel.evaluate_session_operation(&context, &operation) {
            Ok(SessionOperationResponse::Completion { completion }) => jsonrpc_result(
                id,
                json!({
                    "completion": serde_json::to_value(completion).unwrap_or_else(|_| json!({})),
                }),
            ),
            Ok(_) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                "unexpected kernel response type",
            ),
            Err(error) => {
                self.emit_log(
                    LogLevel::Error,
                    "pact.mcp.completion",
                    json!({
                        "event": "completion_failed",
                        "error": error.to_string(),
                    }),
                );
                match error {
                    pact_kernel::KernelError::OutOfScopePrompt { .. }
                    | pact_kernel::KernelError::OutOfScopeResource { .. }
                    | pact_kernel::KernelError::PromptNotRegistered(_)
                    | pact_kernel::KernelError::ResourceNotRegistered(_) => {
                        jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "completion target not found")
                    }
                    _ => jsonrpc_error(
                        id,
                        JSONRPC_INTERNAL_ERROR,
                        &format!("failed to complete argument: {error}"),
                    ),
                }
            }
        }
    }

    fn handle_logging_set_level(&mut self, id: Value, params: Value) -> Value {
        if !self.config.logging_enabled {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let level = match params.get("level").and_then(Value::as_str) {
            Some(level) => match LogLevel::parse(level) {
                Some(level) => level,
                None => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "invalid log level"),
            },
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "logging/setLevel requires a level",
                )
            }
        };

        self.minimum_log_level = level;
        self.emit_log(
            LogLevel::Info,
            "pact.mcp.logging",
            json!({
                "event": "log_level_updated",
                "level": level.as_str(),
            }),
        );
        jsonrpc_result(id, json!({}))
    }

    pub fn create_message<R: BufRead, W: Write>(
        &mut self,
        parent_context: &OperationContext,
        operation: CreateMessageOperation,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<CreateMessageResult, AdapterError> {
        match &self.state {
            EdgeState::Ready { session_id } if session_id == &parent_context.session_id => {}
            _ => {
                return Err(AdapterError::NestedFlowDenied(
                    "sampling requires a ready MCP session".to_string(),
                ))
            }
        }

        let child_request_id = RequestId::new(self.next_request_id());
        let child_context = self
            .kernel
            .begin_child_request(
                parent_context,
                child_request_id,
                OperationKind::CreateMessage,
                None,
                true,
            )
            .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))?;

        let result = (|| {
            self.kernel
                .validate_sampling_request(&child_context, &operation)
                .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))?;

            self.emit_log(
                LogLevel::Info,
                "pact.mcp.sampling",
                json!({
                    "event": "sampling_request_started",
                    "requestId": child_context.request_id.as_str(),
                    "parentRequestId": parent_context.request_id.as_str(),
                    "toolCount": operation.tools.len(),
                }),
            );

            let params = serde_json::to_value(&operation).map_err(|error| {
                AdapterError::ParseError(format!(
                    "failed to serialize sampling/createMessage params: {error}"
                ))
            })?;
            let result =
                self.send_client_request(reader, writer, "sampling/createMessage", params)?;
            let message: CreateMessageResult = serde_json::from_value(result).map_err(|error| {
                AdapterError::ParseError(format!(
                    "failed to parse sampling/createMessage result: {error}"
                ))
            })?;

            self.emit_log(
                LogLevel::Info,
                "pact.mcp.sampling",
                json!({
                    "event": "sampling_request_completed",
                    "requestId": child_context.request_id.as_str(),
                    "parentRequestId": parent_context.request_id.as_str(),
                    "model": message.model.clone(),
                    "stopReason": message.stop_reason.clone(),
                }),
            );

            Ok(message)
        })();

        self.kernel
            .complete_session_request(&child_context.session_id, &child_context.request_id)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "failed to complete sampling child request {}: {error}",
                    child_context.request_id
                ))
            })?;

        result
    }

    #[allow(dead_code)]
    fn process_pending_actions<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        while let Some(action) = self.pending_actions.pop() {
            match action {
                EdgeAction::RefreshRoots { session_id, reason } => {
                    if let Err(error) = self.refresh_roots_from_client(&session_id, reader, writer)
                    {
                        self.emit_log(
                            LogLevel::Warning,
                            "pact.mcp.roots",
                            json!({
                                "event": "roots_refresh_failed",
                                "reason": reason,
                                "error": error.to_string(),
                            }),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn process_pending_actions_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        while let Some(action) = self.pending_actions.pop() {
            match action {
                EdgeAction::RefreshRoots { session_id, reason } => {
                    if let Err(error) =
                        self.refresh_roots_from_client_with_channel(&session_id, client_rx, writer)
                    {
                        self.emit_log(
                            LogLevel::Warning,
                            "pact.mcp.roots",
                            json!({
                                "event": "roots_refresh_failed",
                                "reason": reason,
                                "error": error.to_string(),
                            }),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn queue_roots_refresh(&mut self, session_id: SessionId, reason: &'static str) {
        if self.pending_actions.iter().any(|action| {
            matches!(
                action,
                EdgeAction::RefreshRoots {
                    session_id: pending_session_id,
                    ..
                } if pending_session_id == &session_id
            )
        }) {
            return;
        }

        self.pending_actions
            .push(EdgeAction::RefreshRoots { session_id, reason });
    }

    #[allow(dead_code)]
    fn refresh_roots_from_client<R: BufRead, W: Write>(
        &mut self,
        session_id: &SessionId,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let result = self.send_client_request(reader, writer, "roots/list", json!({}))?;
        let roots_value = result.get("roots").cloned().ok_or_else(|| {
            AdapterError::ParseError("roots/list response missing 'roots'".into())
        })?;
        let roots: Vec<RootDefinition> = serde_json::from_value(roots_value)
            .map_err(|error| AdapterError::ParseError(format!("failed to parse roots: {error}")))?;

        self.kernel
            .replace_session_roots(session_id, roots.clone())
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!("failed to update session roots: {error}"))
            })?;

        self.emit_log(
            LogLevel::Info,
            "pact.mcp.roots",
            json!({
                "event": "roots_refreshed",
                "rootCount": roots.len(),
            }),
        );
        Ok(())
    }

    fn refresh_roots_from_client_with_channel<W: Write>(
        &mut self,
        session_id: &SessionId,
        client_rx: &mpsc::Receiver<ClientInbound>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let result =
            self.send_client_request_with_channel(client_rx, writer, "roots/list", json!({}))?;
        let roots_value = result.get("roots").cloned().ok_or_else(|| {
            AdapterError::ParseError("roots/list response missing 'roots'".into())
        })?;
        let roots: Vec<RootDefinition> = serde_json::from_value(roots_value)
            .map_err(|error| AdapterError::ParseError(format!("failed to parse roots: {error}")))?;

        self.kernel
            .replace_session_roots(session_id, roots.clone())
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!("failed to update session roots: {error}"))
            })?;

        self.emit_log(
            LogLevel::Info,
            "pact.mcp.roots",
            json!({
                "event": "roots_refreshed",
                "rootCount": roots.len(),
            }),
        );
        Ok(())
    }

    fn send_client_request<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        method: &str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        self.client_request_counter += 1;
        let request_id = format!("edge-client-{}", self.client_request_counter);
        write_jsonrpc_line(
            writer,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }),
        )?;

        loop {
            let message = read_jsonrpc_line(reader)?;
            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    return Err(adapter_jsonrpc_error(error));
                }

                return message.get("result").cloned().ok_or_else(|| {
                    AdapterError::ParseError("response missing 'result' field".into())
                });
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(AdapterError::McpError {
                    code: -32800,
                    message: cancellation_reason(&message),
                    data: None,
                });
            }

            if message.get("method").is_some() {
                let response = self.handle_jsonrpc_with_transport(message, reader, writer);
                for notification in self.take_pending_notifications() {
                    write_jsonrpc_line(writer, &notification)?;
                }
                if let Some(response) = response {
                    write_jsonrpc_line(writer, &response)?;
                }
                continue;
            }

            return Err(AdapterError::ParseError(
                "outer MCP client sent an unexpected response while a child request was in flight"
                    .into(),
            ));
        }
    }

    fn send_client_request_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        writer: &mut W,
        method: &str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        self.client_request_counter += 1;
        let request_id = format!("edge-client-{}", self.client_request_counter);
        write_jsonrpc_line(
            writer,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }),
        )?;

        loop {
            let message = next_client_message(client_rx)?;
            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    return Err(adapter_jsonrpc_error(error));
                }

                return message.get("result").cloned().ok_or_else(|| {
                    AdapterError::ParseError("response missing 'result' field".into())
                });
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(AdapterError::McpError {
                    code: -32800,
                    message: cancellation_reason(&message),
                    data: None,
                });
            }

            if message.get("method").is_some() {
                self.deferred_client_messages.push(message);
                continue;
            }

            return Err(AdapterError::ParseError(
                "outer MCP client sent an unexpected response while a child request was in flight"
                    .into(),
            ));
        }
    }

    fn next_request_id(&mut self) -> String {
        self.request_counter += 1;
        format!("mcp-edge-req-{}", self.request_counter)
    }

    fn visible_tools(&self) -> Vec<&ExposedToolBinding> {
        self.tools
            .iter()
            .filter(|binding| tool_is_authorized(&self.capabilities, binding))
            .collect()
    }

    fn ready_session_id(&self, id: &Value) -> Result<SessionId, Value> {
        match &self.state {
            EdgeState::Ready { session_id } => Ok(session_id.clone()),
            _ => Err(jsonrpc_error(
                id.clone(),
                JSONRPC_SERVER_NOT_INITIALIZED,
                "operation requires initialize followed by notifications/initialized",
            )),
        }
    }

    fn has_completion_support(&self) -> bool {
        self.config.completion_enabled.unwrap_or_else(|| {
            self.kernel.resource_provider_count() > 0 || self.kernel.prompt_provider_count() > 0
        })
    }

    fn peer_supports_pact_tool_streaming(&self, session_id: &SessionId) -> bool {
        self.kernel
            .session(session_id)
            .map(|session| session.peer_capabilities().supports_pact_tool_streaming)
            .unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn tool_result_for_kernel_response(
        &mut self,
        client_request_id: &Value,
        session_id: &SessionId,
        output: Option<ToolCallOutput>,
        reason: Option<String>,
        verdict: Verdict,
        terminal_state: &OperationTerminalState,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let peer_supports_pact_tool_streaming = self.peer_supports_pact_tool_streaming(session_id);
        let result = kernel_response_to_tool_result(
            &mut self.pending_notifications,
            client_request_id,
            output,
            reason,
            verdict,
            terminal_state,
            peer_supports_pact_tool_streaming,
            related_task_id,
        );

        if let Some(reason) = cancellation_reason_from_tool_result(&result) {
            return ToolCallEdgeOutcome::Cancelled { reason };
        }

        match terminal_state {
            OperationTerminalState::Cancelled { reason } => ToolCallEdgeOutcome::Cancelled {
                reason: reason.clone(),
            },
            _ => ToolCallEdgeOutcome::Result(result),
        }
    }

    fn tool_call_error_outcome(
        &mut self,
        session_id: &SessionId,
        error: pact_kernel::KernelError,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        match error {
            pact_kernel::KernelError::RequestCancelled { reason, .. } => {
                ToolCallEdgeOutcome::Cancelled { reason }
            }
            pact_kernel::KernelError::UrlElicitationsRequired {
                message,
                elicitations,
            } => {
                if let Err(register_error) = self.kernel.register_session_required_url_elicitations(
                    session_id,
                    &elicitations,
                    related_task_id,
                ) {
                    self.emit_log_with_related_task(
                        LogLevel::Warning,
                        "pact.mcp.elicitation",
                        json!({
                            "event": "session_elicitation_registration_failed",
                            "error": register_error.to_string(),
                        }),
                        related_task_id,
                    );
                }
                ToolCallEdgeOutcome::JsonRpcError {
                    code: JSONRPC_URL_ELICITATION_REQUIRED,
                    message,
                    data: Some(json!({ "elicitations": elicitations })),
                }
            }
            other => ToolCallEdgeOutcome::Result(tool_error_result(&other.to_string())),
        }
    }

    fn persist_accepted_url_elicitations(
        &mut self,
        session_id: &SessionId,
        accepted_url_elicitations: Vec<AcceptedUrlElicitation>,
    ) {
        for accepted in accepted_url_elicitations {
            if let Err(error) = self.kernel.register_session_pending_url_elicitation(
                session_id,
                accepted.elicitation_id,
                accepted.related_task_id,
            ) {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.elicitation",
                    json!({
                        "event": "session_elicitation_registration_failed",
                        "error": error.to_string(),
                    }),
                );
            }
        }
    }

    fn emit_log(&mut self, level: LogLevel, logger: &str, data: Value) {
        self.emit_log_with_related_task(level, logger, data, None);
    }

    fn emit_log_with_related_task(
        &mut self,
        level: LogLevel,
        logger: &str,
        data: Value,
        related_task_id: Option<&str>,
    ) {
        if !self.config.logging_enabled || level < self.minimum_log_level {
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
                related_task_id,
            ));
    }

    fn current_ready_session_id(&self) -> Option<SessionId> {
        match &self.state {
            EdgeState::Ready { session_id } => Some(session_id.clone()),
            _ => None,
        }
    }

    fn queue_session_tool_server_event(&mut self, event: ToolServerEvent) {
        let Some(session_id) = self.current_ready_session_id() else {
            return;
        };
        if let Err(error) = self
            .kernel
            .queue_session_tool_server_event(&session_id, event)
        {
            self.emit_log(
                LogLevel::Warning,
                "pact.mcp.runtime",
                json!({
                    "event": "session_late_event_queue_failed",
                    "error": error.to_string(),
                }),
            );
            return;
        }
        self.flush_session_late_events(&session_id);
    }

    fn flush_session_late_events(&mut self, session_id: &SessionId) {
        let late_events = match self.kernel.drain_session_late_events(session_id) {
            Ok(late_events) => late_events,
            Err(error) => {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.runtime",
                    json!({
                        "event": "session_late_event_drain_failed",
                        "error": error.to_string(),
                    }),
                );
                return;
            }
        };

        for event in late_events {
            match event {
                LateSessionEvent::ElicitationCompleted {
                    elicitation_id,
                    related_task_id,
                } => self
                    .pending_notifications
                    .push(make_elicitation_completion_notification(
                        &elicitation_id,
                        related_task_id.as_deref(),
                    )),
                LateSessionEvent::ResourceUpdated { uri } => {
                    if self.config.resources_subscribe {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/updated",
                            "params": {
                                "uri": uri,
                            }
                        }));
                    }
                }
                LateSessionEvent::ResourcesListChanged => {
                    if self.config.resources_list_changed {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/list_changed",
                        }));
                    }
                }
                LateSessionEvent::ToolsListChanged => {
                    if self.config.tools_list_changed {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/tools/list_changed",
                        }));
                    }
                }
                LateSessionEvent::PromptsListChanged => {
                    if self.config.prompts_list_changed {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/prompts/list_changed",
                        }));
                    }
                }
            }
        }
    }

    pub fn notify_resource_updated(&mut self, uri: &str) {
        self.queue_session_tool_server_event(ToolServerEvent::ResourceUpdated {
            uri: uri.to_string(),
        });
    }

    pub fn notify_resources_list_changed(&mut self) {
        self.queue_session_tool_server_event(ToolServerEvent::ResourcesListChanged);
    }

    pub fn notify_tools_list_changed(&mut self) {
        self.queue_session_tool_server_event(ToolServerEvent::ToolsListChanged);
    }

    pub fn notify_prompts_list_changed(&mut self) {
        self.queue_session_tool_server_event(ToolServerEvent::PromptsListChanged);
    }

    pub fn notify_elicitation_completed(&mut self, elicitation_id: &str) {
        self.queue_session_tool_server_event(ToolServerEvent::ElicitationCompleted {
            elicitation_id: elicitation_id.to_string(),
        });
    }

    fn queue_task_status_notification(&mut self, task: &EdgeTask) {
        self.pending_notifications.push(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tasks/status",
            "params": serde_json::to_value(task).unwrap_or_else(|_| json!({})),
        }));
    }

    fn take_deferred_client_message(&mut self) -> Option<Value> {
        if self.deferred_client_messages.is_empty() {
            None
        } else {
            Some(self.deferred_client_messages.remove(0))
        }
    }

    fn dequeue_background_task(&mut self, task_id: &str) {
        self.pending_background_tasks
            .retain(|pending| pending != task_id);
    }

    fn process_background_tasks_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<bool, AdapterError> {
        let mut processed_any = false;

        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            let Some(task) = self.tasks.get(&task_id).cloned() else {
                continue;
            };

            if task.is_terminal() {
                continue;
            }

            if !task.background_ready() {
                self.pending_background_tasks.push(task_id);
                continue;
            }

            let result = self.evaluate_tool_call_operation_with_transport_channel(
                &Value::String(task.task_id.clone()),
                &task.session_id,
                &task.context,
                &task.operation,
                client_rx,
                cancel_rx,
                writer,
                Some(task.task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
            processed_any = true;
        }

        Ok(processed_any)
    }

    fn process_background_tasks(&mut self) -> Result<bool, AdapterError> {
        let mut processed_any = false;

        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            let Some(task) = self.tasks.get(&task_id).cloned() else {
                continue;
            };

            if task.is_terminal() {
                continue;
            }

            if !task.background_ready() {
                self.pending_background_tasks.push(task_id);
                continue;
            }

            let result = self.evaluate_tool_call_operation(
                &Value::String(task.task_id.clone()),
                &task.session_id,
                &task.context,
                &task.operation,
                Some(task.task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
            processed_any = true;
        }

        Ok(processed_any)
    }

    fn service_background_runtime_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let _ = self.process_background_tasks_with_channel(client_rx, cancel_rx, writer)?;
        self.process_pending_actions_with_channel(client_rx, writer)?;
        self.forward_runtime_events();
        self.flush_pending_notifications(writer)?;
        Ok(())
    }

    fn take_pending_notifications(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending_notifications)
    }

    fn flush_pending_notifications<W: Write>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        for notification in self.take_pending_notifications() {
            write_jsonrpc_line(writer, &notification)?;
        }
        Ok(())
    }

    fn forward_tool_server_events(&mut self) {
        let Some(session_id) = self.current_ready_session_id() else {
            return;
        };
        if let Err(error) = self.kernel.queue_session_tool_server_events(&session_id) {
            self.emit_log(
                LogLevel::Warning,
                "pact.mcp.runtime",
                json!({
                    "event": "tool_server_event_queue_failed",
                    "error": error.to_string(),
                }),
            );
            return;
        }
        self.flush_session_late_events(&session_id);
    }

    fn forward_runtime_events(&mut self) {
        self.forward_tool_server_events();
        self.forward_upstream_notifications();
    }

    fn forward_upstream_notifications(&mut self) {
        let Some(transport) = self.upstream_transport.as_ref() else {
            return;
        };

        for notification in transport.drain_notifications() {
            self.handle_upstream_transport_notification(notification);
        }
    }

    fn handle_upstream_transport_notification(&mut self, notification: Value) {
        match notification.get("method").and_then(Value::as_str) {
            Some("notifications/resources/updated") => {
                if let Some(uri) = notification
                    .get("params")
                    .and_then(|params| params.get("uri"))
                    .and_then(Value::as_str)
                {
                    self.queue_session_tool_server_event(ToolServerEvent::ResourceUpdated {
                        uri: uri.to_string(),
                    });
                } else {
                    self.emit_log(
                        LogLevel::Warning,
                        "pact.mcp.resources",
                        json!({
                            "event": "wrapped_resource_notification_invalid",
                            "notification": notification,
                        }),
                    );
                }
            }
            Some("notifications/resources/list_changed") => {
                self.queue_session_tool_server_event(ToolServerEvent::ResourcesListChanged)
            }
            Some("notifications/tools/list_changed") => {
                self.queue_session_tool_server_event(ToolServerEvent::ToolsListChanged)
            }
            Some("notifications/prompts/list_changed") => {
                self.queue_session_tool_server_event(ToolServerEvent::PromptsListChanged)
            }
            Some("notifications/elicitation/complete") => {
                if let Some(elicitation_id) = notification
                    .get("params")
                    .and_then(|params| params.get("elicitationId"))
                    .and_then(Value::as_str)
                {
                    self.queue_session_tool_server_event(ToolServerEvent::ElicitationCompleted {
                        elicitation_id: elicitation_id.to_string(),
                    });
                } else {
                    self.emit_log(
                        LogLevel::Warning,
                        "pact.mcp.elicitation",
                        json!({
                            "event": "wrapped_elicitation_completion_invalid",
                            "notification": notification,
                        }),
                    );
                }
            }
            Some(method) => {
                self.emit_log(
                    LogLevel::Debug,
                    "pact.mcp.upstream",
                    json!({
                        "event": "wrapped_notification_ignored",
                        "method": method,
                    }),
                );
            }
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "pact.mcp.upstream",
                    json!({
                        "event": "wrapped_notification_invalid",
                    }),
                );
            }
        }
    }
}

fn manifest_tool_to_mcp_tool(tool: ToolDefinition) -> McpExposedTool {
    let annotations = Some(json!({
        "readOnlyHint": !tool.has_side_effects,
        "destructiveHint": tool.has_side_effects,
    }));

    let mut execution = serde_json::Map::new();
    execution.insert("taskSupport".to_string(), json!("optional"));
    if let Some(latency_hint) = tool.latency_hint {
        execution.insert(
            "suggestedLatency".to_string(),
            json!(latency_hint_to_label(latency_hint)),
        );
    }

    McpExposedTool {
        name: tool.name,
        title: None,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        annotations,
        execution: Some(Value::Object(execution)),
    }
}

fn latency_hint_to_label(latency_hint: LatencyHint) -> &'static str {
    match latency_hint {
        LatencyHint::Instant => "instant",
        LatencyHint::Fast => "fast",
        LatencyHint::Moderate => "moderate",
        LatencyHint::Slow => "slow",
    }
}

#[allow(clippy::too_many_arguments)]
fn kernel_response_to_tool_result(
    pending_notifications: &mut Vec<Value>,
    request_id: &Value,
    output: Option<ToolCallOutput>,
    reason: Option<String>,
    verdict: Verdict,
    terminal_state: &OperationTerminalState,
    peer_supports_pact_tool_streaming: bool,
    related_task_id: Option<&str>,
) -> Value {
    let is_error = matches!(verdict, Verdict::Deny) || !terminal_state.is_completed();
    let terminal_reason = reason
        .as_deref()
        .or_else(|| terminal_state_reason(terminal_state));

    match output {
        Some(ToolCallOutput::Value(value)) if !is_error => value_to_tool_result(value),
        Some(ToolCallOutput::Stream(stream)) => {
            if peer_supports_pact_tool_streaming {
                queue_tool_stream_chunk_notifications(
                    pending_notifications,
                    request_id,
                    &stream,
                    related_task_id,
                );
                streamed_notification_tool_result(
                    request_id,
                    stream.chunk_count(),
                    terminal_state,
                    terminal_reason,
                    is_error,
                )
            } else {
                collapsed_stream_tool_result(stream, terminal_state, terminal_reason, is_error)
            }
        }
        Some(ToolCallOutput::Value(_)) | None if is_error => tool_error_result(
            &reason.unwrap_or_else(|| default_tool_failure_reason(terminal_state)),
        ),
        Some(ToolCallOutput::Value(value)) => value_to_tool_result(value),
        None => value_to_tool_result(Value::Null),
    }
}

fn queue_tool_stream_chunk_notifications(
    pending_notifications: &mut Vec<Value>,
    request_id: &Value,
    stream: &ToolCallStream,
    related_task_id: Option<&str>,
) {
    let total_chunks = stream.chunk_count();
    for (index, chunk) in stream.chunks.iter().enumerate() {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": PACT_TOOL_STREAMING_NOTIFICATION_METHOD,
            "params": {
                "requestId": request_id,
                "chunkIndex": index as u64,
                "totalChunks": total_chunks,
                "chunk": chunk.data.clone(),
            }
        });
        pending_notifications.push(attach_related_task_meta_to_message(
            notification,
            related_task_id,
        ));
    }
}

fn streamed_notification_tool_result(
    request_id: &Value,
    total_chunks: u64,
    terminal_state: &OperationTerminalState,
    reason: Option<&str>,
    is_error: bool,
) -> Value {
    let mut stream = serde_json::Map::new();
    stream.insert("mode".to_string(), json!("notification_stream"));
    stream.insert(
        "notificationMethod".to_string(),
        json!(PACT_TOOL_STREAMING_NOTIFICATION_METHOD),
    );
    stream.insert("requestId".to_string(), request_id.clone());
    stream.insert("totalChunks".to_string(), json!(total_chunks));
    stream.insert(
        "terminalState".to_string(),
        json!(terminal_state_label(terminal_state)),
    );
    if let Some(reason) = reason {
        stream.insert("reason".to_string(), json!(reason));
    }

    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "PACT streamed tool output delivered via {}",
                PACT_TOOL_STREAMING_NOTIFICATION_METHOD
            ),
        }],
        "structuredContent": {
            "pactToolStream": Value::Object(stream),
        },
        "isError": is_error,
    })
}

fn collapsed_stream_tool_result(
    stream: ToolCallStream,
    terminal_state: &OperationTerminalState,
    reason: Option<&str>,
    is_error: bool,
) -> Value {
    let total_chunks = stream.chunk_count();
    let chunks = stream
        .chunks
        .into_iter()
        .map(|chunk| chunk.data)
        .collect::<Vec<_>>();

    let mut stream_summary = serde_json::Map::new();
    stream_summary.insert("mode".to_string(), json!("collapsed_result"));
    stream_summary.insert("totalChunks".to_string(), json!(total_chunks));
    stream_summary.insert(
        "terminalState".to_string(),
        json!(terminal_state_label(terminal_state)),
    );
    stream_summary.insert("chunks".to_string(), Value::Array(chunks));
    if let Some(reason) = reason {
        stream_summary.insert("reason".to_string(), json!(reason));
    }

    json!({
        "content": [{
            "type": "text",
            "text": format!("PACT streamed tool output collapsed into {} final chunk(s)", total_chunks),
        }],
        "structuredContent": {
            "pactToolStream": Value::Object(stream_summary),
        },
        "isError": is_error,
    })
}

fn terminal_state_label(terminal_state: &OperationTerminalState) -> &'static str {
    match terminal_state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

fn terminal_state_reason(terminal_state: &OperationTerminalState) -> Option<&str> {
    match terminal_state {
        OperationTerminalState::Completed => None,
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => Some(reason),
    }
}

fn default_tool_failure_reason(terminal_state: &OperationTerminalState) -> String {
    match terminal_state {
        OperationTerminalState::Completed => "tool call denied".to_string(),
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => reason.clone(),
    }
}

fn iso8601_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn unix_now_millis() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

fn parse_requested_task(id: &Value, params: &Value) -> Result<Option<RequestedTask>, Value> {
    let Some(task) = params.get("task").cloned() else {
        return Ok(None);
    };
    serde_json::from_value(task).map(Some).map_err(|_| {
        jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "task must be an object with an optional numeric ttl",
        )
    })
}

fn parse_task_id(id: &Value, params: &Value) -> Result<String, Value> {
    params
        .get("taskId")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "taskId must be a string",
            )
        })
}

fn edge_task_status_label(status: EdgeTaskStatus) -> &'static str {
    match status {
        EdgeTaskStatus::Working => "working",
        EdgeTaskStatus::Completed => "completed",
        EdgeTaskStatus::Failed => "failed",
        EdgeTaskStatus::Cancelled => "cancelled",
    }
}

fn tool_result_is_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn cancellation_reason_from_tool_result(result: &Value) -> Option<String> {
    if !tool_result_is_error(result) {
        return None;
    }

    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)?;

    if let Some((_, reason)) = text.split_once(" was cancelled: ") {
        return Some(reason.to_string());
    }

    if text.starts_with("cancelled by client") || text.starts_with("task cancelled by client") {
        return Some(text.to_string());
    }

    None
}

fn task_status_message(status: &EdgeTaskStatus, result: &Value) -> Option<String> {
    match status {
        EdgeTaskStatus::Completed => Some("The operation completed successfully.".to_string()),
        EdgeTaskStatus::Failed => result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|content| content.first())
            .and_then(|block| block.get("text"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| Some("The operation failed.".to_string())),
        EdgeTaskStatus::Working => Some("The operation is now in progress.".to_string()),
        EdgeTaskStatus::Cancelled => Some("The operation was cancelled.".to_string()),
    }
}

fn build_related_task_meta(
    task_id: &str,
    owner_session_id: Option<&str>,
    owner_request_id: Option<&str>,
    parent_request_id: Option<&str>,
) -> Value {
    json!({
        "taskId": task_id,
        "ownerSessionId": owner_session_id,
        "ownerRequestId": owner_request_id,
        "parentRequestId": parent_request_id,
    })
}

fn attach_related_task_meta_to_result(mut result: Value, related_task_meta: Value) -> Value {
    if let Some(object) = result.as_object_mut() {
        let meta = object
            .entry("_meta".to_string())
            .or_insert_with(|| json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(RELATED_TASK_META_KEY.to_string(), related_task_meta);
        }
    }
    result
}

fn attach_related_task_meta_to_message(message: Value, related_task_id: Option<&str>) -> Value {
    let Some(task_id) = related_task_id else {
        return message;
    };

    let mut message = message;
    if let Some(object) = message.as_object_mut() {
        let params = object
            .entry("params".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(params) = params.as_object_mut() {
            let meta = params
                .entry("_meta".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(
                    RELATED_TASK_META_KEY.to_string(),
                    json!({ "taskId": task_id }),
                );
            }
        }
    }
    message
}

fn capture_accepted_url_elicitation(
    accepted_url_elicitations: &mut Vec<AcceptedUrlElicitation>,
    operation: &CreateElicitationOperation,
    result: &CreateElicitationResult,
    related_task_id: Option<&str>,
) {
    let CreateElicitationOperation::Url { elicitation_id, .. } = operation else {
        return;
    };
    if !matches!(result.action, ElicitationAction::Accept) {
        return;
    }

    accepted_url_elicitations.push(AcceptedUrlElicitation {
        elicitation_id: elicitation_id.clone(),
        related_task_id: related_task_id.map(ToString::to_string),
    });
}

fn make_elicitation_completion_notification(
    elicitation_id: &str,
    related_task_id: Option<&str>,
) -> Value {
    attach_related_task_meta_to_message(
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/elicitation/complete",
            "params": {
                "elicitationId": elicitation_id,
            }
        }),
        related_task_id,
    )
}

fn value_to_tool_result(value: Value) -> Value {
    if let Some(object) = value.as_object() {
        let has_mcp_shape = object.contains_key("content")
            || object.contains_key("structuredContent")
            || object.contains_key("isError");
        if has_mcp_shape {
            let mut object = object.clone();
            object
                .entry("isError".to_string())
                .or_insert_with(|| Value::Bool(false));
            if !object.contains_key("content") {
                if let Some(structured) = object.get("structuredContent") {
                    object.insert(
                        "content".to_string(),
                        json!([{"type": "text", "text": serde_json::to_string(structured).unwrap_or_default()}]),
                    );
                }
            }
            return Value::Object(object);
        }

        return json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&value).unwrap_or_default(),
                }
            ],
            "structuredContent": value,
            "isError": false,
        });
    }

    match value {
        Value::String(text) => json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false,
        }),
        other => json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&other).unwrap_or_default(),
                }
            ],
            "isError": false,
        }),
    }
}

fn tool_error_result(reason: &str) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": reason,
            }
        ],
        "isError": true,
    })
}

impl From<Value> for ToolCallEdgeOutcome {
    fn from(result: Value) -> Self {
        Self::Result(result)
    }
}

fn tool_call_outcome_to_jsonrpc(id: Value, outcome: ToolCallEdgeOutcome) -> Value {
    match outcome {
        ToolCallEdgeOutcome::Result(result) => jsonrpc_result(id, result),
        ToolCallEdgeOutcome::Cancelled { reason } => jsonrpc_result(id, tool_error_result(&reason)),
        ToolCallEdgeOutcome::JsonRpcError {
            code,
            message,
            data,
        } => jsonrpc_error_with_data(id, code, &message, data),
    }
}

fn task_outcome_to_jsonrpc(task: Option<EdgeTask>, id: &Value, task_id: &str) -> Value {
    match task {
        Some(task) => {
            let related_task_meta = build_related_task_meta(
                &task.task_id,
                Some(&task.owner_session_id),
                Some(&task.owner_request_id),
                task.parent_request_id.as_deref(),
            );
            match task.final_outcome {
                Some(EdgeTaskFinalOutcome::Result(result)) => jsonrpc_result(
                    id.clone(),
                    attach_related_task_meta_to_result(result, related_task_meta),
                ),
                Some(EdgeTaskFinalOutcome::JsonRpcError {
                    code,
                    message,
                    data,
                }) => jsonrpc_error_with_data(id.clone(), code, &message, data),
                None => jsonrpc_result(
                    id.clone(),
                    attach_related_task_meta_to_result(
                        tool_error_result("task result unavailable"),
                        related_task_meta,
                    ),
                ),
            }
        }
        None => jsonrpc_result(
            id.clone(),
            attach_related_task_meta_to_result(
                tool_error_result("task result unavailable"),
                build_related_task_meta(task_id, None, None, None),
            ),
        ),
    }
}

fn serialize_resources(resources: Vec<ResourceDefinition>) -> Vec<Value> {
    resources
        .into_iter()
        .map(|resource| serde_json::to_value(resource).unwrap_or_else(|_| json!({})))
        .collect()
}

fn serialize_resource_templates(templates: Vec<ResourceTemplateDefinition>) -> Vec<Value> {
    templates
        .into_iter()
        .map(|template| serde_json::to_value(template).unwrap_or_else(|_| json!({})))
        .collect()
}

fn serialize_resource_contents(contents: Vec<ResourceContent>) -> Vec<Value> {
    contents
        .into_iter()
        .map(|content| serde_json::to_value(content).unwrap_or_else(|_| json!({})))
        .collect()
}

fn serialize_prompts(prompts: Vec<PromptDefinition>) -> Vec<Value> {
    prompts
        .into_iter()
        .map(|prompt| serde_json::to_value(prompt).unwrap_or_else(|_| json!({})))
        .collect()
}

fn parse_completion_reference(params: &Value) -> Result<CompletionReference, String> {
    let reference = params
        .get("ref")
        .and_then(Value::as_object)
        .ok_or_else(|| "completion/complete requires a ref".to_string())?;

    match reference.get("type").and_then(Value::as_str) {
        Some("ref/prompt") => {
            let name = reference
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| "prompt ref requires a name".to_string())?;
            Ok(CompletionReference::Prompt {
                name: name.to_string(),
            })
        }
        Some("ref/resource") => {
            let uri = reference
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| "resource ref requires a uri".to_string())?;
            Ok(CompletionReference::Resource {
                uri: uri.to_string(),
            })
        }
        Some(_) => Err("unsupported completion ref type".to_string()),
        None => Err("completion ref requires a type".to_string()),
    }
}

fn parse_completion_argument(params: &Value) -> Result<CompletionArgument, String> {
    let argument = params
        .get("argument")
        .and_then(Value::as_object)
        .ok_or_else(|| "completion/complete requires an argument".to_string())?;

    let name = argument
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "completion argument requires a name".to_string())?;
    let value = argument
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| "completion argument requires a value".to_string())?;

    Ok(CompletionArgument {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn paginate_response(id: Value, start: usize, page_size: usize, values: Vec<Value>) -> Value {
    paginate_named_response(id, start, page_size, "resources", values)
}

fn paginate_named_response(
    id: Value,
    start: usize,
    page_size: usize,
    field_name: &str,
    values: Vec<Value>,
) -> Value {
    if start > values.len() {
        return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
    }

    let page_size = page_size.max(1);
    let end = (start + page_size).min(values.len());
    let next_cursor = (end < values.len()).then(|| end.to_string());

    let mut result = serde_json::Map::new();
    result.insert(
        field_name.to_string(),
        Value::Array(values[start..end].to_vec()),
    );
    result.insert(
        "nextCursor".to_string(),
        next_cursor.map(Value::String).unwrap_or(Value::Null),
    );

    jsonrpc_result(id, Value::Object(result))
}

fn parse_cursor(id: &Value, params: &Value) -> Result<usize, Value> {
    let cursor = match params.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "cursor must be a string",
            ))
        }
    };

    match cursor.as_deref() {
        None => Ok(0),
        Some(cursor) => cursor.parse::<usize>().map_err(|_| {
            jsonrpc_error(id.clone(), JSONRPC_INVALID_PARAMS, "cursor must be numeric")
        }),
    }
}

fn build_operation_context(
    id: &Value,
    session_id: SessionId,
    request_id: String,
    agent_id: &str,
    params: &Value,
) -> Result<OperationContext, Value> {
    let mut context =
        OperationContext::new(session_id, RequestId::new(request_id), agent_id.to_string());
    context.progress_token = parse_progress_token(id, params)?;
    Ok(context)
}

fn parse_progress_token(id: &Value, params: &Value) -> Result<Option<ProgressToken>, Value> {
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    let Some(meta) = meta.as_object() else {
        return Err(jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "_meta must be an object",
        ));
    };
    let Some(progress_token) = meta.get("progressToken") else {
        return Ok(None);
    };

    serde_json::from_value(progress_token.clone())
        .map(Some)
        .map_err(|_| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "progressToken must be a string or integer",
            )
        })
}

fn parse_peer_capabilities(params: &Value) -> PeerCapabilities {
    let experimental = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("experimental"));
    let resources = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("resources"));
    let roots = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("roots"));
    let sampling = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("sampling"));
    let elicitation = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("elicitation"));
    let elicitation_form = elicitation.is_some_and(|value| {
        value.as_object().is_some_and(|object| object.is_empty()) || value.get("form").is_some()
    });
    let elicitation_url = elicitation
        .is_some_and(|value| value.get("url").is_some() || value.get("openUrl").is_some());

    PeerCapabilities {
        supports_progress: true,
        supports_cancellation: true,
        supports_subscriptions: resources
            .and_then(|value| value.get("subscribe"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_pact_tool_streaming: experimental
            .and_then(|value| value.get("pactToolStreaming"))
            .and_then(|value| value.get("toolCallChunkNotifications"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_roots: roots.is_some(),
        roots_list_changed: roots
            .and_then(|value| value.get("listChanged"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_sampling: sampling.is_some(),
        sampling_context: sampling
            .and_then(|value| value.get("includeContext"))
            .is_some(),
        sampling_tools: sampling.and_then(|value| value.get("tools")).is_some(),
        supports_elicitation: elicitation.is_some(),
        elicitation_form,
        elicitation_url,
    }
}

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn queue_progress_notification(
    pending_notifications: &mut Vec<Value>,
    progress_token: Option<&ProgressToken>,
    progress_step: &mut u64,
    message: &str,
    related_task_id: Option<&str>,
) {
    let Some(progress_token) = progress_token else {
        return;
    };

    *progress_step += 1;
    pending_notifications.push(attach_related_task_meta_to_message(
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": progress_token_to_value(progress_token),
                "progress": *progress_step,
                "message": message,
            }
        }),
        related_task_id,
    ));
}

fn progress_token_to_value(progress_token: &ProgressToken) -> Value {
    match progress_token {
        ProgressToken::String(value) => Value::String(value.clone()),
        ProgressToken::Integer(value) => json!(*value),
    }
}

fn cancellation_matches_request(message: &Value, request_id: &str) -> bool {
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            == Some(&Value::String(request_id.to_string()))
}

fn cancellation_matches_client_request(message: &Value, request_id: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            == Some(request_id)
}

fn task_cancel_matches_related_task(message: &Value, related_task_id: Option<&str>) -> bool {
    let Some(related_task_id) = related_task_id else {
        return false;
    };

    message.get("method").and_then(Value::as_str) == Some("tasks/cancel")
        && message
            .get("params")
            .and_then(|params| params.get("taskId"))
            .and_then(Value::as_str)
            == Some(related_task_id)
}

fn explicit_task_cancel_reason() -> &'static str {
    "task cancelled by client"
}

fn cancellation_reason(message: &Value) -> String {
    let reason = message
        .get("params")
        .and_then(|params| params.get("reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty());

    match reason {
        Some(reason) => format!("cancelled by client: {reason}"),
        None => "cancelled by client".to_string(),
    }
}

fn next_client_message(client_rx: &mpsc::Receiver<ClientInbound>) -> Result<Value, AdapterError> {
    match client_rx.recv() {
        Ok(ClientInbound::Message(message)) => Ok(message),
        Ok(ClientInbound::ParseError(error)) => Err(AdapterError::ParseError(format!(
            "failed to parse MCP edge message: {error}"
        ))),
        Ok(ClientInbound::ReadError(error)) => Err(AdapterError::ConnectionFailed(format!(
            "failed to read MCP edge request: {error}"
        ))),
        Ok(ClientInbound::Closed) | Err(mpsc::RecvError) => Err(AdapterError::ConnectionFailed(
            "MCP client closed connection while request was in flight".into(),
        )),
    }
}

fn pump_client_messages<R: BufRead>(
    mut reader: R,
    sender: mpsc::Sender<ClientInbound>,
    cancel_sender: mpsc::Sender<Value>,
) {
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = sender.send(ClientInbound::Closed);
                return;
            }
            Ok(_) => {}
            Err(error) => {
                let _ = sender.send(ClientInbound::ReadError(error.to_string()));
                return;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<Value>(trimmed) {
            Ok(message) => {
                if matches!(
                    message.get("method").and_then(Value::as_str),
                    Some("notifications/cancelled" | "tasks/cancel")
                ) {
                    let _ = cancel_sender.send(message.clone());
                }
                if sender.send(ClientInbound::Message(message)).is_err() {
                    return;
                }
            }
            Err(error) => {
                if sender
                    .send(ClientInbound::ParseError(error.to_string()))
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

fn pump_channel_messages(
    receiver: mpsc::Receiver<Value>,
    sender: mpsc::Sender<ClientInbound>,
    cancel_sender: mpsc::Sender<Value>,
) {
    while let Ok(message) = receiver.recv() {
        if matches!(
            message.get("method").and_then(Value::as_str),
            Some("notifications/cancelled" | "tasks/cancel")
        ) {
            let _ = cancel_sender.send(message.clone());
        }
        if sender.send(ClientInbound::Message(message)).is_err() {
            return;
        }
    }

    let _ = sender.send(ClientInbound::Closed);
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn jsonrpc_error_with_data(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), json!(code));
    error.insert("message".to_string(), json!(message));
    if let Some(data) = data {
        error.insert("data".to_string(), data);
    }

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": Value::Object(error),
    })
}

fn adapter_jsonrpc_error(error: &Value) -> AdapterError {
    AdapterError::McpError {
        code: error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or(JSONRPC_INTERNAL_ERROR),
        message: error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown JSON-RPC error")
            .to_string(),
        data: error.get("data").cloned(),
    }
}

fn write_jsonrpc_line(writer: &mut impl Write, value: &Value) -> Result<(), AdapterError> {
    let line = serde_json::to_string(value).map_err(|error| {
        AdapterError::ParseError(format!("failed to serialize JSON-RPC response: {error}"))
    })?;
    writer.write_all(line.as_bytes()).map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to write MCP edge response: {error}"))
    })?;
    writer.write_all(b"\n").map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to terminate MCP edge response: {error}"))
    })?;
    writer.flush().map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to flush MCP edge response: {error}"))
    })?;
    Ok(())
}

fn read_jsonrpc_line(reader: &mut impl BufRead) -> Result<Value, AdapterError> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to read MCP edge request: {error}"))
    })?;

    if bytes_read == 0 {
        return Err(AdapterError::ConnectionFailed(
            "MCP client closed connection while request was in flight".into(),
        ));
    }

    serde_json::from_str(line.trim()).map_err(|error| {
        AdapterError::ParseError(format!("failed to parse MCP edge message: {error}"))
    })
}

fn select_capability_for_request(
    capabilities: &[CapabilityToken],
    tool_name: &str,
    server_id: &str,
    arguments: &Value,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_request(capability, tool_name, server_id, arguments)
                .unwrap_or(false)
        })
        .cloned()
}

fn select_capability_for_resource(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_resource_request(capability, uri).unwrap_or(false)
        })
        .cloned()
}

fn select_capability_for_resource_subscription(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_resource_subscription(capability, uri).unwrap_or(false)
        })
        .cloned()
}

fn select_capability_for_prompt(
    capabilities: &[CapabilityToken],
    prompt_name: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_prompt_request(capability, prompt_name).unwrap_or(false)
        })
        .cloned()
}

fn select_capability_for_resource_pattern(
    capabilities: &[CapabilityToken],
    pattern: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_resource_pattern(capability, pattern).unwrap_or(false)
        })
        .cloned()
}

fn tool_is_authorized(capabilities: &[CapabilityToken], binding: &ExposedToolBinding) -> bool {
    capabilities.iter().any(|capability| {
        capability.scope.grants.iter().any(|grant| {
            matches_server(&grant.server_id, &binding.server_id)
                && matches_name(&grant.tool_name, &binding.tool_name)
                && grant.operations.contains(&Operation::Invoke)
        })
    })
}

fn matches_server(pattern: &str, server_id: &str) -> bool {
    pattern == "*" || pattern == server_id
}

fn matches_name(pattern: &str, tool_name: &str) -> bool {
    pattern == "*" || pattern == tool_name
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use pact_core::capability::{Operation, PactScope, PromptGrant, ResourceGrant, ToolGrant};
    use pact_core::crypto::Keypair;
    use pact_core::{
        CompletionResult, PromptArgument, PromptDefinition, PromptMessage, PromptResult,
        ResourceContent, ResourceDefinition, ResourceTemplateDefinition, SamplingMessage,
        SamplingTool, SamplingToolChoice,
    };
    use pact_kernel::{
        KernelConfig, KernelError, PromptProvider, ResourceProvider, ToolCallChunk, ToolCallStream,
        ToolServerConnection, ToolServerEvent, ToolServerStreamResult,
    };
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    struct EchoServer;
    struct StreamingEchoServer;
    struct UrlRequiredServer;
    #[derive(Default)]
    struct AsyncEventServer {
        events: Mutex<Vec<ToolServerEvent>>,
    }
    struct AsyncEventServerConnection(Arc<AsyncEventServer>);
    struct DocsResourceProvider;
    struct ExamplePromptProvider;

    impl ToolServerConnection for EchoServer {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "echo_json".to_string(),
            ]
        }

        fn invoke(
            &self,
            tool_name: &str,
            arguments: Value,
            _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            match tool_name {
                "echo_json" => Ok(json!({
                    "temperature": 22.5,
                    "conditions": "Partly cloudy",
                })),
                _ => Ok(json!({
                    "tool": tool_name,
                    "arguments": arguments,
                })),
            }
        }
    }

    impl ToolServerConnection for StreamingEchoServer {
        fn server_id(&self) -> &str {
            "stream-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "stream_file".to_string(),
                "stream_file_incomplete".to_string(),
            ]
        }

        fn invoke(
            &self,
            tool_name: &str,
            arguments: Value,
            _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(json!({
                "tool": tool_name,
                "arguments": arguments,
                "fallback": true,
            }))
        }

        fn invoke_stream(
            &self,
            tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            let stream = ToolCallStream {
                chunks: vec![
                    ToolCallChunk {
                        data: json!({"type": "text", "text": "chunk one"}),
                    },
                    ToolCallChunk {
                        data: json!({"type": "text", "text": "chunk two"}),
                    },
                ],
            };

            let result = match tool_name {
                "stream_file" => ToolServerStreamResult::Complete(stream),
                "stream_file_incomplete" => ToolServerStreamResult::Incomplete {
                    stream,
                    reason: "upstream stream interrupted".to_string(),
                },
                _ => return Ok(None),
            };

            Ok(Some(result))
        }
    }

    impl ToolServerConnection for UrlRequiredServer {
        fn server_id(&self) -> &str {
            "url-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["authorize".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Err(KernelError::UrlElicitationsRequired {
                message: "URL elicitation is required for this operation".to_string(),
                elicitations: vec![CreateElicitationOperation::Url {
                    meta: None,
                    message: "Complete authorization in your browser".to_string(),
                    url: "https://example.com/authorize".to_string(),
                    elicitation_id: "elicit-auth".to_string(),
                }],
            })
        }
    }

    impl AsyncEventServer {
        fn push_event(&self, event: ToolServerEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl ToolServerConnection for AsyncEventServerConnection {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "echo_json".to_string(),
            ]
        }

        fn invoke(
            &self,
            tool_name: &str,
            arguments: Value,
            _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(json!({
                "tool": tool_name,
                "arguments": arguments,
            }))
        }

        fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
            let mut events = self.0.events.lock().unwrap();
            Ok(std::mem::take(&mut *events))
        }
    }

    impl ResourceProvider for DocsResourceProvider {
        fn list_resources(&self) -> Vec<ResourceDefinition> {
            vec![
                ResourceDefinition {
                    uri: "repo://docs/roadmap".to_string(),
                    name: "Roadmap".to_string(),
                    title: Some("Roadmap".to_string()),
                    description: Some("Project roadmap".to_string()),
                    mime_type: Some("text/markdown".to_string()),
                    size: Some(128),
                    annotations: Some(json!({"audience": "engineering"})),
                    icons: None,
                },
                ResourceDefinition {
                    uri: "repo://secret/ops".to_string(),
                    name: "Ops Secret".to_string(),
                    title: None,
                    description: Some("Should be filtered".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: None,
                    annotations: None,
                    icons: None,
                },
            ]
        }

        fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
            vec![ResourceTemplateDefinition {
                uri_template: "repo://docs/{slug}".to_string(),
                name: "Doc Template".to_string(),
                title: None,
                description: Some("Parameterized docs resource".to_string()),
                mime_type: Some("text/markdown".to_string()),
                annotations: None,
                icons: None,
            }]
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
            match uri {
                "repo://docs/roadmap" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/markdown".to_string()),
                    text: Some("# Roadmap".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                _ => Ok(None),
            }
        }

        fn complete_resource_argument(
            &self,
            uri: &str,
            argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, KernelError> {
            if uri == "repo://docs/{slug}" && argument_name == "slug" {
                let values = ["roadmap", "architecture", "api"]
                    .into_iter()
                    .filter(|candidate| candidate.starts_with(value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                return Ok(Some(CompletionResult {
                    total: Some(values.len() as u32),
                    has_more: false,
                    values,
                }));
            }

            Ok(None)
        }
    }

    struct FilesystemResourceProvider;

    impl ResourceProvider for FilesystemResourceProvider {
        fn list_resources(&self) -> Vec<ResourceDefinition> {
            vec![
                ResourceDefinition {
                    uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                    name: "Filesystem Roadmap".to_string(),
                    title: Some("Filesystem Roadmap".to_string()),
                    description: Some("In-root file-backed resource".to_string()),
                    mime_type: Some("text/markdown".to_string()),
                    size: Some(64),
                    annotations: None,
                    icons: None,
                },
                ResourceDefinition {
                    uri: "file:///workspace/private/ops.md".to_string(),
                    name: "Filesystem Ops".to_string(),
                    title: None,
                    description: Some("Out-of-root file-backed resource".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: Some(32),
                    annotations: None,
                    icons: None,
                },
            ]
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
            match uri {
                "file:///workspace/project/docs/roadmap.md" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/markdown".to_string()),
                    text: Some("# Filesystem Roadmap".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                "file:///workspace/private/ops.md" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/plain".to_string()),
                    text: Some("ops".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                _ => Ok(None),
            }
        }
    }

    impl PromptProvider for ExamplePromptProvider {
        fn list_prompts(&self) -> Vec<PromptDefinition> {
            vec![
                PromptDefinition {
                    name: "summarize_docs".to_string(),
                    title: Some("Summarize Docs".to_string()),
                    description: Some("Summarize a documentation resource".to_string()),
                    arguments: vec![PromptArgument {
                        name: "topic".to_string(),
                        title: None,
                        description: Some("Topic to summarize".to_string()),
                        required: Some(true),
                    }],
                    icons: None,
                },
                PromptDefinition {
                    name: "ops_secret".to_string(),
                    title: None,
                    description: Some("Should be filtered".to_string()),
                    arguments: vec![],
                    icons: None,
                },
            ]
        }

        fn get_prompt(
            &self,
            name: &str,
            arguments: Value,
        ) -> Result<Option<PromptResult>, KernelError> {
            match name {
                "summarize_docs" => Ok(Some(PromptResult {
                    description: Some("Summarize docs".to_string()),
                    messages: vec![PromptMessage {
                        role: "user".to_string(),
                        content: json!({
                            "type": "text",
                            "text": format!(
                                "Summarize {}",
                                arguments["topic"].as_str().unwrap_or("the docs")
                            ),
                        }),
                    }],
                })),
                _ => Ok(None),
            }
        }

        fn complete_prompt_argument(
            &self,
            name: &str,
            argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, KernelError> {
            if name == "summarize_docs" && argument_name == "topic" {
                let values = ["roadmap", "architecture", "release-plan"]
                    .into_iter()
                    .filter(|candidate| candidate.starts_with(value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                return Ok(Some(CompletionResult {
                    total: Some(values.len() as u32),
                    has_more: false,
                    values,
                }));
            }

            Ok(None)
        }
    }

    fn make_kernel() -> (PactKernel, Keypair) {
        let keypair = Keypair::generate();
        let config = KernelConfig {
            keypair: keypair.clone(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "edge-policy".to_string(),
            allow_sampling: true,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: pact_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: pact_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        };
        let mut kernel = PactKernel::new(config);
        kernel.register_tool_server(Box::new(EchoServer));
        kernel.register_resource_provider(Box::new(DocsResourceProvider));
        kernel.register_resource_provider(Box::new(FilesystemResourceProvider));
        kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
        (kernel, keypair)
    }

    fn make_streaming_kernel() -> (PactKernel, Keypair) {
        let (mut kernel, keypair) = make_kernel();
        kernel.register_tool_server(Box::new(StreamingEchoServer));
        (kernel, keypair)
    }

    fn issue_capabilities(kernel: &PactKernel, agent: &Keypair) -> Vec<CapabilityToken> {
        issue_capabilities_with_resource_operations(kernel, agent, vec![Operation::Read])
    }

    fn issue_streaming_capabilities(kernel: &PactKernel, agent: &Keypair) -> Vec<CapabilityToken> {
        let mut capabilities = issue_capabilities(kernel, agent);
        capabilities.push(
            kernel
                .issue_capability(
                    &agent.public_key(),
                    PactScope {
                        grants: vec![
                            ToolGrant {
                                server_id: "stream-srv".to_string(),
                                tool_name: "stream_file".to_string(),
                                operations: vec![Operation::Invoke],
                                constraints: vec![],
                                max_invocations: None,
                                max_cost_per_invocation: None,
                                max_total_cost: None,
                            },
                            ToolGrant {
                                server_id: "stream-srv".to_string(),
                                tool_name: "stream_file_incomplete".to_string(),
                                operations: vec![Operation::Invoke],
                                constraints: vec![],
                                max_invocations: None,
                                max_cost_per_invocation: None,
                                max_total_cost: None,
                            },
                        ],
                        resource_grants: vec![],
                        prompt_grants: vec![],
                    },
                    300,
                )
                .unwrap(),
        );
        capabilities
    }

    fn issue_capabilities_with_resource_operations(
        kernel: &PactKernel,
        agent: &Keypair,
        resource_operations: Vec<Operation>,
    ) -> Vec<CapabilityToken> {
        issue_capabilities_with_resource_grants(
            kernel,
            agent,
            vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: resource_operations,
            }],
        )
    }

    fn issue_capabilities_with_resource_grants(
        kernel: &PactKernel,
        agent: &Keypair,
        resource_grants: Vec<ResourceGrant>,
    ) -> Vec<CapabilityToken> {
        vec![kernel
            .issue_capability(
                &agent.public_key(),
                PactScope {
                    grants: vec![
                        ToolGrant {
                            server_id: "srv".to_string(),
                            tool_name: "read_file".to_string(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                        },
                        ToolGrant {
                            server_id: "srv".to_string(),
                            tool_name: "echo_json".to_string(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                        },
                    ],
                    resource_grants,
                    prompt_grants: vec![PromptGrant {
                        prompt_name: "summarize_*".to_string(),
                        operations: vec![Operation::Get],
                    }],
                },
                300,
            )
            .unwrap()]
    }

    fn sample_manifest() -> ToolManifest {
        ToolManifest {
            schema: "pact.manifest.v1".into(),
            server_id: "srv".into(),
            name: "Test Server".into(),
            description: Some("test".into()),
            version: "0.1.0".into(),
            tools: vec![
                ToolDefinition {
                    name: "read_file".into(),
                    description: "Read a file".into(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    has_side_effects: false,
                    latency_hint: Some(LatencyHint::Fast),
                },
                ToolDefinition {
                    name: "echo_json".into(),
                    description: "Return a JSON object".into(),
                    input_schema: json!({"type": "object"}),
                    output_schema: Some(json!({
                        "type": "object",
                        "properties": {
                            "temperature": { "type": "number" },
                            "conditions": { "type": "string" }
                        }
                    })),
                    has_side_effects: false,
                    latency_hint: Some(LatencyHint::Moderate),
                },
                ToolDefinition {
                    name: "write_file".into(),
                    description: "Write a file".into(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    has_side_effects: true,
                    latency_hint: Some(LatencyHint::Slow),
                },
            ],
            required_permissions: None,
            public_key: "abcd".into(),
        }
    }

    fn streaming_manifest() -> ToolManifest {
        ToolManifest {
            schema: "pact.manifest.v1".into(),
            server_id: "stream-srv".into(),
            name: "Streaming Test Server".into(),
            description: Some("streaming test".into()),
            version: "0.1.0".into(),
            tools: vec![
                ToolDefinition {
                    name: "stream_file".into(),
                    description: "Return streamed chunks".into(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    has_side_effects: false,
                    latency_hint: Some(LatencyHint::Moderate),
                },
                ToolDefinition {
                    name: "stream_file_incomplete".into(),
                    description: "Return streamed chunks then terminate incomplete".into(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    has_side_effects: false,
                    latency_hint: Some(LatencyHint::Slow),
                },
            ],
            required_permissions: None,
            public_key: "stream-abcd".into(),
        }
    }

    fn make_edge(page_size: usize) -> PactMcpEdge {
        make_edge_with_config(page_size, false)
    }

    fn make_edge_with_config(page_size: usize, logging_enabled: bool) -> PactMcpEdge {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities(&kernel, &agent);
        PactMcpEdge::new(
            McpEdgeConfig {
                server_name: "PACT MCP Edge".to_string(),
                server_version: "0.1.0".to_string(),
                page_size,
                tools_list_changed: false,
                completion_enabled: None,
                resources_subscribe: false,
                resources_list_changed: false,
                prompts_list_changed: false,
                logging_enabled,
            },
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap()
    }

    fn make_streaming_edge(page_size: usize) -> PactMcpEdge {
        let (kernel, _) = make_streaming_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_streaming_capabilities(&kernel, &agent);
        PactMcpEdge::new(
            McpEdgeConfig {
                server_name: "PACT MCP Edge".to_string(),
                server_version: "0.1.0".to_string(),
                page_size,
                tools_list_changed: false,
                completion_enabled: None,
                resources_subscribe: false,
                resources_list_changed: false,
                prompts_list_changed: false,
                logging_enabled: false,
            },
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest(), streaming_manifest()],
        )
        .unwrap()
    }

    fn make_url_required_edge() -> PactMcpEdge {
        let keypair = Keypair::generate();
        let config = KernelConfig {
            keypair: keypair.clone(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "edge-policy".to_string(),
            allow_sampling: true,
            allow_sampling_tool_use: false,
            allow_elicitation: true,
            max_stream_duration_secs: pact_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: pact_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        };
        let mut kernel = PactKernel::new(config);
        kernel.register_tool_server(Box::new(UrlRequiredServer));
        let agent = Keypair::generate();
        let capabilities = vec![kernel
            .issue_capability(
                &agent.public_key(),
                PactScope {
                    grants: vec![ToolGrant {
                        server_id: "url-srv".to_string(),
                        tool_name: "authorize".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap()];

        PactMcpEdge::new(
            McpEdgeConfig::default(),
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![ToolManifest {
                schema: "pact.manifest.v1".into(),
                server_id: "url-srv".into(),
                name: "URL Required Server".into(),
                description: Some("url required test".into()),
                version: "0.1.0".into(),
                tools: vec![ToolDefinition {
                    name: "authorize".into(),
                    description: "Requires URL elicitation".into(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    has_side_effects: false,
                    latency_hint: Some(LatencyHint::Moderate),
                }],
                required_permissions: None,
                public_key: "url-abcd".into(),
            }],
        )
        .unwrap()
    }

    fn make_event_edge(server: Arc<AsyncEventServer>) -> PactMcpEdge {
        let keypair = Keypair::generate();
        let config = KernelConfig {
            keypair: keypair.clone(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "edge-policy".to_string(),
            allow_sampling: true,
            allow_sampling_tool_use: false,
            allow_elicitation: true,
            max_stream_duration_secs: pact_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: pact_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        };
        let mut kernel = PactKernel::new(config);
        kernel.register_tool_server(Box::new(AsyncEventServerConnection(server)));
        kernel.register_resource_provider(Box::new(DocsResourceProvider));
        kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_operations(
            &kernel,
            &agent,
            vec![Operation::Read, Operation::Subscribe],
        );

        PactMcpEdge::new(
            McpEdgeConfig {
                tools_list_changed: true,
                resources_subscribe: true,
                resources_list_changed: true,
                prompts_list_changed: true,
                ..McpEdgeConfig::default()
            },
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap()
    }

    fn ready_session_id(edge: &PactMcpEdge) -> SessionId {
        match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            other => panic!("expected ready session, got {other:?}"),
        }
    }

    fn register_pending_url_elicitation(
        edge: &mut PactMcpEdge,
        elicitation_id: &str,
        related_task_id: Option<&str>,
    ) {
        let session_id = ready_session_id(edge);
        edge.kernel
            .register_session_pending_url_elicitation(
                &session_id,
                elicitation_id.to_string(),
                related_task_id.map(ToString::to_string),
            )
            .unwrap();
    }

    #[test]
    fn initialize_then_initialized_enters_ready_state() {
        let mut edge = make_edge(10);

        let initialize = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .unwrap();

        assert_eq!(
            initialize["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(
            initialize["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
        assert_eq!(
            initialize["result"]["capabilities"]["resources"]["subscribe"],
            false
        );
        assert_eq!(
            initialize["result"]["capabilities"]["prompts"]["listChanged"],
            false
        );
        assert_eq!(
            initialize["result"]["capabilities"]["completions"],
            json!({})
        );
        assert_eq!(
            initialize["result"]["capabilities"]["experimental"]["pactToolStreaming"]
                ["toolCallChunkNotifications"],
            true
        );
        assert_eq!(
            initialize["result"]["capabilities"]["tasks"]["list"],
            json!({})
        );
        assert_eq!(
            initialize["result"]["capabilities"]["tasks"]["cancel"],
            json!({})
        );
        assert_eq!(
            initialize["result"]["capabilities"]["tasks"]["requests"]["tools"]["call"],
            json!({})
        );
        assert!(initialize["result"]["capabilities"]
            .get("logging")
            .is_none());

        let initialized = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        assert!(initialized.is_none());
        assert!(matches!(edge.state, EdgeState::Ready { .. }));
    }

    #[test]
    fn tools_list_is_paginated() {
        let mut edge = make_edge(2);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let first_page = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }))
            .unwrap();
        assert_eq!(first_page["result"]["tools"].as_array().unwrap().len(), 2);
        assert!(first_page["result"]["nextCursor"].is_null());
        assert!(
            first_page["result"]["tools"][0]["annotations"]["readOnlyHint"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            first_page["result"]["tools"][0]["execution"]["taskSupport"],
            "optional"
        );
        assert_eq!(
            first_page["result"]["tools"][1]["outputSchema"]["type"],
            "object"
        );

        let second_page = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": { "cursor": "2" }
            }))
            .unwrap();
        assert_eq!(second_page["result"]["tools"].as_array().unwrap().len(), 0);
        assert!(second_page["result"]["nextCursor"].is_null());
    }

    #[test]
    fn tools_call_requires_initialized_session() {
        let mut edge = make_edge(10);
        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "read_file", "arguments": { "path": "/tmp/x" } }
            }))
            .unwrap();

        assert_eq!(response["error"]["code"], JSONRPC_SERVER_NOT_INITIALIZED);
    }

    #[test]
    fn parse_peer_capabilities_treats_empty_elicitation_as_form_support() {
        let capabilities = parse_peer_capabilities(&json!({
            "capabilities": {
                "elicitation": {},
            }
        }));

        assert!(capabilities.supports_elicitation);
        assert!(capabilities.elicitation_form);
        assert!(!capabilities.elicitation_url);

        let capabilities = parse_peer_capabilities(&json!({
            "capabilities": {
                "elicitation": {
                    "form": {},
                    "url": {}
                }
            }
        }));

        assert!(capabilities.supports_elicitation);
        assert!(capabilities.elicitation_form);
        assert!(capabilities.elicitation_url);
    }

    #[test]
    fn parse_peer_capabilities_tracks_resource_subscription_support_when_present() {
        let capabilities = parse_peer_capabilities(&json!({
            "capabilities": {
                "resources": {
                    "subscribe": true
                }
            }
        }));

        assert!(capabilities.supports_subscriptions);

        let capabilities = parse_peer_capabilities(&json!({
            "capabilities": {
                "resources": {
                    "subscribe": false
                }
            }
        }));

        assert!(!capabilities.supports_subscriptions);
    }

    #[test]
    fn wrapped_elicitation_completion_notifications_only_emit_for_known_ids() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "elicitation": {
                        "form": {},
                        "url": {}
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        register_pending_url_elicitation(&mut edge, "elicit-123", Some("task-7"));

        edge.handle_upstream_transport_notification(json!({
            "jsonrpc": "2.0",
            "method": "notifications/elicitation/complete",
            "params": {
                "elicitationId": "elicit-123"
            }
        }));
        edge.handle_upstream_transport_notification(json!({
            "jsonrpc": "2.0",
            "method": "notifications/elicitation/complete",
            "params": {
                "elicitationId": "unknown-id"
            }
        }));

        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]["method"],
            "notifications/elicitation/complete"
        );
        assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-123");
        assert_eq!(
            notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            "task-7"
        );
    }

    #[test]
    fn direct_tool_server_url_required_errors_are_brokered_as_jsonrpc_errors() {
        let mut edge = make_url_required_edge();
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "elicitation": {
                        "url": {}
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "authorize",
                    "arguments": {}
                }
            }))
            .unwrap();

        assert_eq!(response["error"]["code"], JSONRPC_URL_ELICITATION_REQUIRED);
        assert_eq!(response["error"]["data"]["elicitations"][0]["mode"], "url");
        assert_eq!(
            response["error"]["data"]["elicitations"][0]["elicitationId"],
            "elicit-auth"
        );

        edge.notify_elicitation_completed("elicit-auth");
        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]["method"],
            "notifications/elicitation/complete"
        );
        assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-auth");
    }

    #[test]
    fn direct_tool_server_events_are_forwarded_through_the_edge() {
        let server = Arc::new(AsyncEventServer::default());
        let mut edge = make_event_edge(Arc::clone(&server));
        edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "elicitation": {
                        "url": {}
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        let subscribe = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/subscribe",
                "params": {
                    "uri": "repo://docs/roadmap"
                }
            }))
            .unwrap();
        assert!(subscribe.get("result").is_some());

        register_pending_url_elicitation(&mut edge, "elicit-async", None);
        server.push_event(ToolServerEvent::ElicitationCompleted {
            elicitation_id: "elicit-async".to_string(),
        });
        server.push_event(ToolServerEvent::ResourceUpdated {
            uri: "repo://docs/roadmap".to_string(),
        });
        server.push_event(ToolServerEvent::ResourcesListChanged);
        server.push_event(ToolServerEvent::ToolsListChanged);
        server.push_event(ToolServerEvent::PromptsListChanged);

        let notifications = edge.drain_runtime_notifications().unwrap();
        let methods = notifications
            .iter()
            .map(|notification| notification["method"].as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        assert!(methods.contains(&"notifications/elicitation/complete"));
        assert!(methods.contains(&"notifications/resources/updated"));
        assert!(methods.contains(&"notifications/resources/list_changed"));
        assert!(methods.contains(&"notifications/tools/list_changed"));
        assert!(methods.contains(&"notifications/prompts/list_changed"));
    }

    #[test]
    fn in_process_runtime_drain_flushes_late_async_events_without_request_bridge() {
        let server = Arc::new(AsyncEventServer::default());
        let mut edge = make_event_edge(Arc::clone(&server));
        edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "elicitation": {
                        "url": {}
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        register_pending_url_elicitation(&mut edge, "elicit-late", Some("task-7"));

        server.push_event(ToolServerEvent::ElicitationCompleted {
            elicitation_id: "elicit-late".to_string(),
        });

        let notifications = edge.drain_runtime_notifications().unwrap();

        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]["method"],
            "notifications/elicitation/complete"
        );
        assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-late");
        assert_eq!(
            notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            "task-7"
        );
        assert!(edge.drain_runtime_notifications().unwrap().is_empty());
    }

    #[test]
    fn in_process_runtime_drain_completes_task_after_tools_call_returns_task() {
        let mut edge = make_edge(10);
        edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let create = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "echo_json",
                    "arguments": {},
                    "task": {}
                }
            }))
            .unwrap();
        let task_id = create["result"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(create["result"]["task"]["status"], "working");

        let notifications = edge.drain_runtime_notifications().unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0]["method"], "notifications/tasks/status");
        assert_eq!(notifications[0]["params"]["taskId"], task_id);
        assert_eq!(notifications[0]["params"]["status"], "completed");

        let get_completed = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/get",
                "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(get_completed["result"]["status"], "completed");

        let result = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tasks/result",
                "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            task_id
        );
        assert_eq!(result["result"]["structuredContent"]["temperature"], 22.5);
        assert!(edge.drain_runtime_notifications().unwrap().is_empty());
    }

    #[test]
    fn tools_call_returns_structured_content_for_object_results() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "echo_json", "arguments": {} }
            }))
            .unwrap();

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["temperature"], 22.5);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("temperature"));
    }

    #[test]
    fn tools_call_denied_by_capabilities_returns_tool_error() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "write_file", "arguments": { "path": "/tmp/x", "content": "hi" } }
            }))
            .unwrap();

        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not authorized"));
    }

    #[test]
    fn tools_call_streams_chunks_via_experimental_notifications_when_negotiated() {
        let mut edge = make_streaming_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "experimental": {
                        "pactToolStreaming": {
                            "toolCallChunkNotifications": true
                        }
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "stream_file", "arguments": {} }
            }))
            .unwrap();

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["mode"],
            "notification_stream"
        );
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["notificationMethod"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["totalChunks"],
            2
        );

        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 2);
        assert_eq!(
            notifications[0]["method"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
        assert_eq!(notifications[0]["params"]["requestId"], json!(2));
        assert_eq!(notifications[0]["params"]["chunkIndex"], 0);
        assert_eq!(notifications[0]["params"]["totalChunks"], 2);
        assert_eq!(notifications[0]["params"]["chunk"]["text"], "chunk one");
        assert_eq!(notifications[1]["params"]["chunkIndex"], 1);
        assert_eq!(notifications[1]["params"]["chunk"]["text"], "chunk two");
    }

    #[test]
    fn tools_call_streams_collapse_when_peer_does_not_negotiate_extension() {
        let mut edge = make_streaming_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "stream_file", "arguments": {} }
            }))
            .unwrap();

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["mode"],
            "collapsed_result"
        );
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["chunks"][0]["text"],
            "chunk one"
        );
        assert!(edge.take_pending_notifications().is_empty());
    }

    #[test]
    fn incomplete_streamed_tools_call_preserves_chunks_and_terminal_state() {
        let mut edge = make_streaming_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "experimental": {
                        "pactToolStreaming": {
                            "toolCallChunkNotifications": true
                        }
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "stream_file_incomplete", "arguments": {} }
            }))
            .unwrap();

        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["terminalState"],
            "incomplete"
        );
        assert_eq!(
            response["result"]["structuredContent"]["pactToolStream"]["reason"],
            "upstream stream interrupted"
        );

        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 2);
        assert_eq!(
            notifications[0]["method"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
    }

    #[test]
    fn task_augmented_tool_call_completes_via_tasks_result_and_tracks_status() {
        let mut edge = make_streaming_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "experimental": {
                        "pactToolStreaming": {
                            "toolCallChunkNotifications": true
                        }
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let create = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "stream_file",
                    "arguments": {},
                    "task": { "ttl": 60000 }
                }
            }))
            .unwrap();
        let task_id = create["result"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(create["result"]["task"]["status"], "working");
        assert_eq!(create["result"]["task"]["ttl"], 60000);
        assert_eq!(
            create["result"]["task"]["pollInterval"],
            TASK_POLL_INTERVAL_MILLIS
        );
        assert_eq!(create["result"]["task"]["ownership"]["workOwner"], "task");
        assert_eq!(
            create["result"]["task"]["ownership"]["resultStreamOwner"],
            "request_stream"
        );
        assert_eq!(
            create["result"]["task"]["ownership"]["statusNotificationOwner"],
            "session_notification_stream"
        );
        assert_eq!(
            create["result"]["task"]["ownership"]["terminalStateOwner"],
            "task"
        );
        assert!(create["result"]["task"]["ownerSessionId"]
            .as_str()
            .unwrap()
            .starts_with("sess-"));
        assert!(create["result"]["task"]["ownerRequestId"]
            .as_str()
            .unwrap()
            .starts_with("mcp-edge-req-"));
        assert!(create["result"]["task"]["parentRequestId"].is_null());

        let get_working = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/get",
                "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(get_working["result"]["status"], "working");
        assert_eq!(get_working["result"]["ownership"]["workOwner"], "task");

        let result = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tasks/result",
                "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            task_id
        );
        assert!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerSessionId"]
                .as_str()
                .unwrap()
                .starts_with("sess-")
        );
        assert!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"]
                .as_str()
                .unwrap()
                .starts_with("mcp-edge-req-")
        );
        assert!(result["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"].is_null());
        assert_eq!(
            result["result"]["structuredContent"]["pactToolStream"]["mode"],
            "notification_stream"
        );

        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 3);
        assert_eq!(
            notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            task_id
        );
        assert!(notifications.iter().any(|notification| {
            notification["method"] == "notifications/tasks/status"
                && notification["params"]["taskId"] == task_id
                && notification["params"]["status"] == "completed"
        }));

        let get_completed = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tasks/get",
                "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(get_completed["result"]["status"], "completed");
        assert_eq!(
            get_completed["result"]["ownership"]["terminalStateOwner"],
            "task"
        );
    }

    #[test]
    fn tasks_cancel_marks_working_task_cancelled_and_result_returns_error_payload() {
        let mut edge = make_streaming_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let create = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "stream_file",
                    "arguments": {},
                    "task": {}
                }
            }))
            .unwrap();
        let task_id = create["result"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        let cancelled = edge
            .handle_jsonrpc(json!({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tasks/cancel",
                    "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(cancelled["result"]["status"], "cancelled");
        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0]["method"], "notifications/tasks/status");
        assert_eq!(notifications[0]["params"]["taskId"], task_id);
        assert!(notifications[0]["params"].get("_meta").is_none());

        let result = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tasks/result",
                "params": { "taskId": task_id.clone() }
            }))
            .unwrap();
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            task_id
        );
    }

    #[test]
    fn request_cancelled_errors_record_cancelled_task_terminal_state() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let (session_id, context, operation) = edge
            .prepare_tool_call_request(
                &json!(2),
                &json!({
                    "name": "read_file",
                    "arguments": { "path": "/tmp/race" },
                    "task": {}
                }),
            )
            .unwrap();
        let task_id = "mcp-edge-task-cancelled".to_string();
        let mut task = EdgeTask::new(task_id.clone(), session_id, context, operation, None, 0);

        let outcome = edge.tool_call_error_outcome(
            &task.session_id,
            KernelError::RequestCancelled {
                request_id: pact_core::session::RequestId::new("cancelled-request"),
                reason: "cancelled by client: user aborted sample".to_string(),
            },
            Some(task_id.as_str()),
        );
        task.record_outcome(outcome);

        assert_eq!(task.status, EdgeTaskStatus::Cancelled);
        assert_eq!(
            task.status_message.as_deref(),
            Some("cancelled by client: user aborted sample")
        );

        let result = task_outcome_to_jsonrpc(Some(task.clone()), &json!(3), &task_id);
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            task_id
        );
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerSessionId"],
            task.owner_session_id
        );
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"],
            task.owner_request_id
        );
        assert_eq!(
            result["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"].as_str(),
            task.parent_request_id.as_deref()
        );
        assert!(result["result"]["content"][0]["text"]
            .as_str()
            .expect("cancelled task result text")
            .contains("cancelled by client: user aborted sample"));
    }

    #[test]
    fn serve_stdio_handles_initialize_and_tools_list_roundtrip() {
        let mut edge = make_edge(10);
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
        );

        let mut output = Vec::new();
        edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();

        let lines = String::from_utf8(output).unwrap();
        let responses = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(responses.len(), 2);
        assert_eq!(
            responses[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        let tools = responses[1]["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools.iter().all(|tool| tool["name"] != "write_file"));
    }

    #[test]
    fn serve_stdio_emits_stream_chunk_notifications_before_final_tool_response() {
        let mut edge = make_streaming_edge(10);
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"experimental\":{\"pactToolStreaming\":{\"toolCallChunkNotifications\":true}}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"stream_file\",\"arguments\":{}}}\n"
        );

        let mut output = Vec::new();
        edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();

        let lines = String::from_utf8(output).unwrap();
        let responses = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(responses.len(), 4);
        assert_eq!(
            responses[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(
            responses[1]["method"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
        assert_eq!(responses[1]["params"]["chunkIndex"], 0);
        assert_eq!(
            responses[2]["method"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
        assert_eq!(responses[2]["params"]["chunkIndex"], 1);
        assert_eq!(responses[3]["id"], 2);
        assert_eq!(
            responses[3]["result"]["structuredContent"]["pactToolStream"]["mode"],
            "notification_stream"
        );
    }

    #[test]
    fn serve_stdio_tasks_result_emits_stream_chunk_notifications_before_result() {
        let mut edge = make_streaming_edge(10);
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"experimental\":{\"pactToolStreaming\":{\"toolCallChunkNotifications\":true}}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"stream_file\",\"arguments\":{},\"task\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tasks/result\",\"params\":{\"taskId\":\"mcp-edge-task-1\"}}\n"
        );

        let mut output = Vec::new();
        edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();

        let lines = String::from_utf8(output).unwrap();
        let responses = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(responses.len(), 6);
        assert_eq!(
            responses[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(responses[1]["result"]["task"]["status"], "working");
        assert_eq!(
            responses[2]["method"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
        assert_eq!(
            responses[3]["method"],
            PACT_TOOL_STREAMING_NOTIFICATION_METHOD
        );
        assert_eq!(responses[4]["method"], "notifications/tasks/status");
        assert_eq!(responses[4]["params"]["status"], "completed");
        assert_eq!(responses[5]["id"], 3);
        assert_eq!(
            responses[5]["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            "mcp-edge-task-1"
        );
    }

    #[test]
    fn resources_list_is_filtered_by_capabilities() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/list",
                "params": {}
            }))
            .unwrap();

        let resources = response["result"]["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "repo://docs/roadmap");
    }

    #[test]
    fn resources_read_returns_contents() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": "repo://docs/roadmap" }
            }))
            .unwrap();

        assert_eq!(response["result"]["contents"][0]["text"], "# Roadmap");
    }

    #[test]
    fn resources_read_allows_in_root_filesystem_resources() {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_grants(
            &kernel,
            &agent,
            vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
        );
        let mut edge = PactMcpEdge::new(
            McpEdgeConfig::default(),
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap();

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        edge.kernel
            .replace_session_roots(
                &session_id,
                vec![RootDefinition {
                    uri: "file:///workspace/project".to_string(),
                    name: Some("Project".to_string()),
                }],
            )
            .unwrap();

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": "file:///workspace/project/docs/roadmap.md" }
            }))
            .unwrap();

        assert_eq!(
            response["result"]["contents"][0]["text"],
            "# Filesystem Roadmap"
        );
    }

    #[test]
    fn resources_read_denies_out_of_root_filesystem_resources() {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_grants(
            &kernel,
            &agent,
            vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
        );
        let mut edge = PactMcpEdge::new(
            McpEdgeConfig::default(),
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap();

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        edge.kernel
            .replace_session_roots(
                &session_id,
                vec![RootDefinition {
                    uri: "file:///workspace/project".to_string(),
                    name: Some("Project".to_string()),
                }],
            )
            .unwrap();

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": "file:///workspace/private/ops.md" }
            }))
            .unwrap();

        assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
        assert_eq!(
            response["error"]["message"],
            "resource read denied: filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
        );
        let receipt = &response["error"]["data"]["receipt"];
        assert_eq!(receipt["tool_name"], "resources/read");
        assert_eq!(receipt["tool_server"], "session");
        assert_eq!(receipt["decision"]["verdict"], "deny");
        assert_eq!(receipt["decision"]["guard"], "session_roots");
        assert_eq!(
            receipt["decision"]["reason"],
            "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
        );
        assert!(receipt["signature"].is_string());
    }

    #[test]
    fn resources_read_denies_filesystem_resources_when_roots_are_missing() {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_grants(
            &kernel,
            &agent,
            vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
        );
        let mut edge = PactMcpEdge::new(
            McpEdgeConfig::default(),
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap();

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": "file:///workspace/project/docs/roadmap.md" }
            }))
            .unwrap();

        assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
        assert_eq!(
            response["error"]["message"],
            "resource read denied: no enforceable filesystem roots are available for this session"
        );
        let receipt = &response["error"]["data"]["receipt"];
        assert_eq!(receipt["tool_name"], "resources/read");
        assert_eq!(receipt["tool_server"], "session");
        assert_eq!(receipt["decision"]["verdict"], "deny");
        assert_eq!(receipt["decision"]["guard"], "session_roots");
        assert_eq!(
            receipt["decision"]["reason"],
            "no enforceable filesystem roots are available for this session"
        );
        assert!(receipt["signature"].is_string());
    }

    #[test]
    fn resources_subscribe_tracks_session_state() {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_operations(
            &kernel,
            &agent,
            vec![Operation::Read, Operation::Subscribe],
        );
        let mut edge = PactMcpEdge::new(
            McpEdgeConfig {
                resources_subscribe: true,
                ..McpEdgeConfig::default()
            },
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap();

        let initialize = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .unwrap();
        assert_eq!(
            initialize["result"]["capabilities"]["resources"]["subscribe"],
            true
        );
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/subscribe",
                "params": { "uri": "repo://docs/roadmap" }
            }))
            .unwrap();

        assert_eq!(response["result"], json!({}));
        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        assert!(edge
            .kernel
            .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
            .unwrap());
    }

    #[test]
    fn resources_unsubscribe_clears_session_state() {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_operations(
            &kernel,
            &agent,
            vec![Operation::Read, Operation::Subscribe],
        );
        let mut edge = PactMcpEdge::new(
            McpEdgeConfig {
                resources_subscribe: true,
                ..McpEdgeConfig::default()
            },
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap();

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "repo://docs/roadmap" }
        }));
        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/unsubscribe",
                "params": { "uri": "repo://docs/roadmap" }
            }))
            .unwrap();

        assert_eq!(response["result"], json!({}));
        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        assert!(!edge
            .kernel
            .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
            .unwrap());
    }

    #[test]
    fn resource_update_notifications_only_emit_for_subscribed_uris() {
        let (kernel, _) = make_kernel();
        let agent = Keypair::generate();
        let capabilities = issue_capabilities_with_resource_operations(
            &kernel,
            &agent,
            vec![Operation::Read, Operation::Subscribe],
        );
        let mut edge = PactMcpEdge::new(
            McpEdgeConfig {
                resources_subscribe: true,
                ..McpEdgeConfig::default()
            },
            kernel,
            agent.public_key().to_hex(),
            capabilities,
            vec![sample_manifest()],
        )
        .unwrap();

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "repo://docs/roadmap" }
        }));

        edge.notify_resource_updated("repo://secret/ops");
        assert!(edge.take_pending_notifications().is_empty());

        edge.notify_resource_updated("repo://docs/roadmap");
        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]["method"],
            "notifications/resources/updated"
        );
        assert_eq!(notifications[0]["params"]["uri"], "repo://docs/roadmap");
    }

    #[test]
    fn resources_list_changed_notification_emits_when_enabled() {
        let mut edge = make_edge(10);
        edge.config.resources_list_changed = true;

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        edge.notify_resources_list_changed();
        let notifications = edge.take_pending_notifications();

        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]["method"],
            "notifications/resources/list_changed"
        );
        assert!(notifications[0].get("params").is_none());
    }

    #[test]
    fn prompts_list_and_get_are_filtered_by_capabilities() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let list_response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "prompts/list",
                "params": {}
            }))
            .unwrap();

        let prompts = list_response["result"]["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "summarize_docs");

        let get_response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "prompts/get",
                "params": { "name": "summarize_docs", "arguments": { "topic": "roadmap" } }
            }))
            .unwrap();

        assert_eq!(
            get_response["result"]["messages"][0]["content"]["text"],
            "Summarize roadmap"
        );
    }

    #[test]
    fn completion_complete_returns_candidates_for_prompt_and_resource_refs() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let prompt_response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "completion/complete",
                "params": {
                    "ref": { "type": "ref/prompt", "name": "summarize_docs" },
                    "argument": { "name": "topic", "value": "r" },
                    "context": { "arguments": {} }
                }
            }))
            .unwrap();
        assert_eq!(prompt_response["result"]["completion"]["total"], 2);
        assert_eq!(
            prompt_response["result"]["completion"]["values"],
            json!(["roadmap", "release-plan"])
        );

        let resource_response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "completion/complete",
                "params": {
                    "ref": { "type": "ref/resource", "uri": "repo://docs/{slug}" },
                    "argument": { "name": "slug", "value": "a" },
                    "context": { "arguments": {} }
                }
            }))
            .unwrap();
        assert_eq!(
            resource_response["result"]["completion"]["values"],
            json!(["architecture", "api"])
        );
    }

    #[test]
    fn logging_set_level_enables_warning_notifications_for_denied_calls() {
        let mut edge = make_edge_with_config(10, true);
        let initialize = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .unwrap();
        assert_eq!(initialize["result"]["capabilities"]["logging"], json!({}));

        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let set_level = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "logging/setLevel",
                "params": { "level": "warning" }
            }))
            .unwrap();
        assert_eq!(set_level["result"], json!({}));
        assert!(edge.take_pending_notifications().is_empty());

        let denied = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {}
                }
            }))
            .unwrap();
        assert_eq!(denied["result"]["isError"], true);

        let notifications = edge.take_pending_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0]["method"], "notifications/message");
        assert_eq!(notifications[0]["params"]["level"], "warning");
        assert_eq!(notifications[0]["params"]["logger"], "pact.mcp.tools");
        assert_eq!(notifications[0]["params"]["data"]["event"], "tool_denied");
    }

    #[test]
    fn initialize_persists_configured_session_auth_context() {
        let mut edge = make_edge(10);
        let auth_context = SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("http://localhost:3000".to_string()),
        );
        edge.set_session_auth_context(auth_context.clone());

        let initialize = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .unwrap();
        assert_eq!(
            initialize["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );

        let session_id = match &edge.state {
            EdgeState::WaitingForInitialized { session_id } => session_id.clone(),
            other => panic!("expected waiting-for-initialized state, got {other:?}"),
        };

        let session = edge.kernel.session(&session_id).expect("session exists");
        assert_eq!(session.auth_context(), &auth_context);
    }

    #[test]
    fn create_message_roundtrips_through_client_with_child_lineage() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "sampling": {
                        "includeContext": true
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        let parent_context = OperationContext::new(
            session_id.clone(),
            RequestId::new("tool-parent"),
            edge.agent_id.clone(),
        );
        edge.kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let operation = CreateMessageOperation {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: json!({
                    "type": "text",
                    "text": "Summarize the latest diff"
                }),
                meta: None,
            }],
            model_preferences: None,
            system_prompt: Some("Be concise.".to_string()),
            include_context: Some("thisServer".to_string()),
            temperature: Some(0.1),
            max_tokens: 256,
            stop_sequences: vec![],
            metadata: None,
            tools: vec![],
            tool_choice: None,
        };

        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":",
            "{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"Summary ready.\"},\"model\":\"gpt-5.4\",\"stopReason\":\"endTurn\"}}\n"
        );
        let mut output = Vec::new();
        let result = edge
            .create_message(
                &parent_context,
                operation,
                &mut Cursor::new(input.as_bytes()),
                &mut output,
            )
            .unwrap();

        assert_eq!(result.model, "gpt-5.4");
        assert_eq!(result.content["text"], "Summary ready.");

        let lines = String::from_utf8(output).unwrap();
        let messages = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["method"], "sampling/createMessage");
        assert_eq!(messages[0]["params"]["includeContext"], "thisServer");
        assert_eq!(
            messages[0]["params"]["messages"][0]["content"]["text"],
            "Summarize the latest diff"
        );

        let session = edge.kernel.session(&session_id).unwrap();
        assert!(session
            .inflight()
            .get(&RequestId::new("tool-parent"))
            .is_some());
        assert!(session
            .inflight()
            .get(&RequestId::new("mcp-edge-req-1"))
            .is_none());
    }

    #[test]
    fn create_message_denies_tool_use_when_not_negotiated() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "sampling": {
                        "includeContext": true
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        let parent_context = OperationContext::new(
            session_id.clone(),
            RequestId::new("tool-parent"),
            edge.agent_id.clone(),
        );
        edge.kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let operation = CreateMessageOperation {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: json!({
                    "type": "text",
                    "text": "Search the docs first"
                }),
                meta: None,
            }],
            model_preferences: None,
            system_prompt: None,
            include_context: None,
            temperature: None,
            max_tokens: 128,
            stop_sequences: vec![],
            metadata: None,
            tools: vec![SamplingTool {
                name: "search_docs".to_string(),
                description: Some("Search docs".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
            }],
            tool_choice: Some(SamplingToolChoice {
                mode: "auto".to_string(),
            }),
        };

        let mut output = Vec::new();
        let error = edge
            .create_message(
                &parent_context,
                operation,
                &mut Cursor::new(b""),
                &mut output,
            )
            .unwrap_err();
        match error {
            AdapterError::NestedFlowDenied(message) => {
                assert!(message.contains("tool use"));
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(output.is_empty());
        assert!(edge
            .kernel
            .session(&session_id)
            .unwrap()
            .inflight()
            .get(&RequestId::new("mcp-edge-req-1"))
            .is_none());
    }

    #[test]
    fn serve_stdio_requests_roots_after_initialized_and_updates_session() {
        let mut edge = make_edge(10);
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"roots\":{\"listChanged\":true}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project\",\"name\":\"Project\"}]}}\n"
        );

        let mut output = Vec::new();
        edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();

        let lines = String::from_utf8(output).unwrap();
        let messages = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(messages[1]["method"], "roots/list");

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        let session = edge.kernel.session(&session_id).unwrap();
        assert!(session.peer_capabilities().supports_roots);
        assert!(session.peer_capabilities().roots_list_changed);
        assert_eq!(session.roots().len(), 1);
        assert_eq!(session.roots()[0].uri, "file:///workspace/project");
    }

    #[test]
    fn serve_stdio_refreshes_roots_after_list_changed_notification() {
        let mut edge = make_edge(10);
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"roots\":{\"listChanged\":true}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project-a\",\"name\":\"Project A\"}]}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/roots/list_changed\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-2\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project-b\",\"name\":\"Project B\"}]}}\n"
        );

        let mut output = Vec::new();
        edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();

        let lines = String::from_utf8(output).unwrap();
        let messages = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 3);
        assert_eq!(messages[1]["method"], "roots/list");
        assert_eq!(messages[2]["method"], "roots/list");

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };
        let session = edge.kernel.session(&session_id).unwrap();
        assert_eq!(session.roots().len(), 1);
        assert_eq!(session.roots()[0].uri, "file:///workspace/project-b");
        assert_eq!(session.roots()[0].name.as_deref(), Some("Project B"));
    }

    #[test]
    fn refresh_roots_with_channel_defers_unrelated_requests() {
        let mut edge = make_edge(10);
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "roots": {
                        "listChanged": true
                    }
                }
            }
        }));
        let _ = edge.handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));

        let session_id = match &edge.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => panic!("expected ready state"),
        };

        let (client_tx, client_rx) = mpsc::channel();
        client_tx
            .send(ClientInbound::Message(json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {
                        "path": "/tmp/example.txt"
                    }
                }
            })))
            .unwrap();
        client_tx
            .send(ClientInbound::Message(json!({
                "jsonrpc": "2.0",
                "id": "edge-client-1",
                "result": {
                    "roots": [{
                        "uri": "file:///workspace/project",
                        "name": "Project"
                    }]
                }
            })))
            .unwrap();
        drop(client_tx);

        let mut output = Vec::new();
        edge.refresh_roots_from_client_with_channel(&session_id, &client_rx, &mut output)
            .unwrap();

        let lines = String::from_utf8(output).unwrap();
        let messages = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["method"], "roots/list");

        assert_eq!(edge.deferred_client_messages.len(), 1);
        assert_eq!(edge.deferred_client_messages[0]["method"], "tools/call");

        let session = edge.kernel.session(&session_id).unwrap();
        assert_eq!(session.roots().len(), 1);
        assert_eq!(session.roots()[0].uri, "file:///workspace/project");
        assert_eq!(session.roots()[0].name.as_deref(), Some("Project"));
    }
}
