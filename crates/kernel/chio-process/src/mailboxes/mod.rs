//! Durable capability-addressed channels served through normal kernel tools.
//! The host registers this native server; callers hold send, receive,
//! acknowledge, claim and complete grants.

mod store;
mod types;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolInvocationContext, ToolInvocationCost,
    ToolServerConnection,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};

use crate::{ProcessError, ProcessRegistry};
pub use types::{MailboxConfig, MailboxLimits};

pub const SERVER_ID: &str = "chio-ipc";

/// Native tool server. Its public invocation method is a trusted host API,
/// just like other ToolServerConnection implementations. Guests use the kernel.
pub struct MailboxServer {
    config: BTreeMap<String, MailboxConfig>,
    store: Mutex<store::MailboxStore>,
    public_key: String,
    registry: Option<ProcessRegistry>,
}

impl MailboxServer {
    pub fn open(
        path: impl AsRef<Path>,
        kernel: &ChioKernel,
        mut config: Vec<MailboxConfig>,
    ) -> Result<Self, ProcessError> {
        if kernel.durable_admission_mode()
            != chio_kernel::admission_operation::DurableAdmissionMode::All
        {
            return Err(ProcessError::Configuration(
                "mailboxes require durable admission for all calls",
            ));
        }
        let authority =
            kernel
                .durable_admission_store_uuid()
                .ok_or(ProcessError::Configuration(
                    "mailboxes require qualified durable authority",
                ))?;
        if config.is_empty() || config.len() > 32 {
            return Err(ProcessError::Invalid("expected 1-32 mailboxes"));
        }
        config.sort_by(|a, b| a.id.cmp(&b.id));
        for (index, channel) in config.iter().enumerate() {
            channel.validate()?;
            if index > 0 && config[index - 1].id == channel.id {
                return Err(ProcessError::Invalid("duplicate mailbox id"));
            }
        }
        let public_key = kernel.public_key().to_hex();
        let store = store::MailboxStore::open(path.as_ref(), authority, &public_key, &config)?;
        Ok(Self {
            config: config.into_iter().map(|c| (c.id.clone(), c)).collect(),
            store: Mutex::new(store),
            public_key,
            registry: None,
        })
    }

    /// Record the kernel-selected sending process on every message. Sends
    /// whose capability is not bound to one live process are rejected, and a
    /// message key belongs to the process that committed it.
    pub fn attest_senders(mut self, registry: ProcessRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn manifest(&self) -> ToolManifest {
        let mut tools = Vec::new();
        for channel in self.config.keys() {
            for (operation, description, properties) in [
                ("send", "Append a message, deduplicated by its stable key. Full queues report full without enqueueing.",
                    json!({"message_key": {"type": "string"}, "payload": {}})),
                ("receive", "Read messages after a sequence without consuming them. A new logical poll observes later sends.",
                    json!({"after_sequence": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 16}})),
                ("ack", "Discard pending payloads through a sequence. This authority can acknowledge unread messages.",
                    json!({"through_sequence": {"type": "string"}})),
                ("claim", "Lease the oldest pending messages no live lease holds to this process. Expired leases are claimed again under a new generation.",
                    json!({"limit": {"type": "integer", "minimum": 1, "maximum": 16}, "lease_ms": {"type": "integer", "minimum": 1000, "maximum": 300000}})),
                ("complete", "Consume one message under the claim that holds it. A claim superseded after its lease expired is refused.",
                    json!({"sequence": {"type": "string"}, "claim": {"type": "string"}})),
            ] {
                let required: Vec<_> = properties.as_object().into_iter().flat_map(|map| map.keys()).cloned().collect();
                tools.push(ToolDefinition {
                    name: format!("{operation}_{channel}"), description: description.to_owned(),
                    input_schema: json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false}),
                    output_schema: None, pricing: None, has_side_effects: operation != "receive", latency_hint: None,
                });
            }
        }
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        ToolManifest {
            schema: "chio.manifest.v1".to_owned(), server_id: SERVER_ID.to_owned(), name: "Chio process mailboxes".to_owned(),
            description: Some("Durable local channels; grants authorize endpoint operations, not a claimed sender identity".to_owned()),
            version: "1".to_owned(), tools, server_tools: Vec::new(), required_permissions: None, public_key: self.public_key.clone(),
        }
    }

    fn dispatch(
        &self,
        tool: &str,
        arguments: Value,
        context: Option<&ToolInvocationContext>,
    ) -> Result<Value, ProcessError> {
        let (operation, id) = tool
            .split_once('_')
            .ok_or(ProcessError::Invalid("unknown mailbox tool"))?;
        let channel = self
            .config
            .get(id)
            .ok_or(ProcessError::Invalid("unknown mailbox"))?;
        // Sends are attributed when a registry attests them; claims and
        // completions are owned by a process and require attestation.
        let caller = match (&self.registry, operation) {
            (Some(registry), "send" | "claim" | "complete") => {
                let context = context.ok_or(ProcessError::Unauthenticated)?;
                Some(registry.caller(context)?.id)
            }
            (None, "claim" | "complete") => return Err(ProcessError::Unauthenticated),
            _ => None,
        };
        let mut store = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        match (operation, caller) {
            ("send", sender) => store.send(
                channel,
                serde_json::from_value(arguments)?,
                sender.as_deref(),
            ),
            ("receive", _) => store.receive(channel, serde_json::from_value(arguments)?),
            ("ack", _) => store.acknowledge(channel, serde_json::from_value(arguments)?),
            ("claim", Some(claimant)) => store.claim(
                channel,
                serde_json::from_value(arguments)?,
                &claimant,
                now_ms()?,
            ),
            ("complete", Some(claimant)) => {
                store.complete(channel, serde_json::from_value(arguments)?, &claimant)
            }
            _ => Err(ProcessError::Invalid("unknown mailbox operation")),
        }
    }

    fn tool_error(error: ProcessError) -> KernelError {
        let reason = match error {
            ProcessError::Conflict => {
                "mailbox message key or claim conflicts with the recorded payload, sender or claimant"
            }
            ProcessError::Unauthenticated | ProcessError::Cancelled(_) => {
                "mailbox caller is not one live attested process"
            }
            ProcessError::Invalid(_) | ProcessError::Json(_) => "invalid mailbox operation",
            _ => "mailbox storage failed",
        };
        KernelError::ToolServerError(reason.to_owned())
    }
}

/// Lease deadlines are measured on the host clock.
fn now_ms() -> Result<u64, ProcessError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProcessError::Invalid("host clock precedes the Unix epoch"))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| ProcessError::Invalid("host clock exceeds the lease range"))
}

#[async_trait::async_trait]
impl ToolServerConnection for MailboxServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }
    fn tool_names(&self) -> Vec<String> {
        self.manifest().tools.into_iter().map(|t| t.name).collect()
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool.strip_prefix("receive_")
            .is_some_and(|id| self.config.contains_key(id))
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.dispatch(tool, arguments, None)
            .map_err(Self::tool_error)
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.dispatch(context.tool_name(), arguments, Some(context))
            .map_err(Self::tool_error)
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke_with_context(context, arguments, bridge).await?,
            None,
        ))
    }
}
