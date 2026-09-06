use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, SigningBackend,
};
use chio_kernel::{NestedFlowBridge, ReceiptStore, ToolDispatchContext};
use serde_json::json;
use tracing::{debug, warn};

use crate::edge::{AdapterError, McpServerCapabilities, McpToolInfo, McpToolResult, McpTransport};
use crate::framing::MAX_STDIO_MCP_FRAME_BYTES;

use super::handlers::{
    forward_upstream_notification, respond_to_upstream_nested_flow,
    respond_to_upstream_roots_without_bridge, service_active_request_runtime,
};
use super::nested_flow::NestedFlowTaskRuntime;
use super::utils::{
    adapter_jsonrpc_error, is_nested_flow_notification, proxy_client_capabilities, read_line,
    remove_chio_auth_env, send_line, MAX_STDIO_MCP_BUFFERED_MESSAGES, MCP_PROTOCOL_VERSION,
    UPSTREAM_REQUEST_POLL_INTERVAL,
};

const UPSTREAM_INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const LEGACY_CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(2);

include!("stdio_parts/transport.inc");
include!("stdio_parts/lifecycle_and_tests.inc");
