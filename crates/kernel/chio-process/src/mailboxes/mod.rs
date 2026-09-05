//! Durable capability-addressed channels served through normal kernel tools.
//! The host registers this native server; callers hold send/receive/ack grants.

mod store;
mod types;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use chio_kernel::{ChioKernel, KernelError, NestedFlowBridge, ToolServerConnection};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};

use crate::ProcessError;
pub use types::{MailboxConfig, MailboxLimits};

pub const SERVER_ID: &str = "chio-ipc";

/// Native tool server. Its public invocation method is a trusted host API,
/// just like other ToolServerConnection implementations. Guests use the kernel.
pub struct MailboxServer {
    config: BTreeMap<String, MailboxConfig>,
    store: Mutex<store::MailboxStore>,
    public_key: String,
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
        })
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

    fn dispatch(&self, tool: &str, arguments: Value) -> Result<Value, ProcessError> {
        let (operation, id) = tool
            .split_once('_')
            .ok_or(ProcessError::Invalid("unknown mailbox tool"))?;
        let channel = self
            .config
            .get(id)
            .ok_or(ProcessError::Invalid("unknown mailbox"))?;
        let mut store = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        match operation {
            "send" => store.send(channel, serde_json::from_value(arguments)?),
            "receive" => store.receive(channel, serde_json::from_value(arguments)?),
            "ack" => store.acknowledge(channel, serde_json::from_value(arguments)?),
            _ => Err(ProcessError::Invalid("unknown mailbox operation")),
        }
    }
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
        self.dispatch(tool, arguments).map_err(|error| {
            let reason = match error {
                ProcessError::Conflict => "mailbox message key conflicts with existing payload",
                ProcessError::Invalid(_) | ProcessError::Json(_) => "invalid mailbox operation",
                _ => "mailbox storage failed",
            };
            KernelError::ToolServerError(reason.to_owned())
        })
    }
}
