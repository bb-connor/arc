#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }
    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }
    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for EventDrainServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolNotRegistered(tool_name.to_string()))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Ok(self.events.clone())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingEventDrainServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolNotRegistered(tool_name.to_string()))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Err(KernelError::Internal("drain failed".to_string()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedFlowServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "sample_via_client".to_string(),
            "elicit_via_client".to_string(),
            "roots_via_client".to_string(),
            "notify_resources_via_client".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let nested_flow_bridge = nested_flow_bridge
            .ok_or_else(|| KernelError::Internal("nested-flow bridge is required".to_string()))?;

        match tool_name {
            "sample_via_client" => {
                let message = nested_flow_bridge.create_message(CreateMessageOperation {
                    messages: vec![SamplingMessage {
                        role: "user".to_string(),
                        content: serde_json::json!({
                            "type": "text",
                            "text": "Summarize the architecture",
                        }),
                        meta: None,
                    }],
                    model_preferences: None,
                    system_prompt: None,
                    include_context: None,
                    temperature: Some(0.2),
                    max_tokens: 128,
                    stop_sequences: vec![],
                    metadata: None,
                    tools: vec![],
                    tool_choice: None,
                })?;

                Ok(serde_json::json!({
                    "model": message.model,
                    "content": message.content,
                }))
            }
            "elicit_via_client" => {
                let elicitation =
                    nested_flow_bridge.create_elicitation(CreateElicitationOperation::Form {
                        meta: None,
                        message: "Which environment should this run against?".to_string(),
                        requested_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "environment": {
                                    "type": "string",
                                    "enum": ["staging", "production"]
                                }
                            },
                            "required": ["environment"]
                        }),
                    })?;

                Ok(serde_json::json!({
                    "action": elicitation.action,
                    "content": elicitation.content,
                }))
            }
            "roots_via_client" => {
                let roots = nested_flow_bridge.list_roots()?;
                Ok(serde_json::json!({
                    "roots": roots,
                }))
            }
            "notify_resources_via_client" => {
                nested_flow_bridge.notify_resource_updated("repo://docs/architecture")?;
                nested_flow_bridge.notify_resource_updated("repo://secret/ops")?;
                nested_flow_bridge.notify_resources_list_changed()?;
                Ok(serde_json::json!({
                    "notified": true,
                }))
            }
            _ => Err(KernelError::ToolNotRegistered(tool_name.to_string())),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["drop_stream".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::RequestIncomplete(
            "upstream stream closed before tool response completed".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for StreamingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: self
                .chunks
                .iter()
                .cloned()
                .map(|data| ToolCallChunk { data })
                .collect(),
        })))
    }
}

impl NestedFlowClient for MockNestedFlowClient {
    fn list_roots(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(self.roots.clone())
    }

    fn create_message(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        _operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        if self.cancel_parent_on_create_message {
            return Err(KernelError::RequestCancelled {
                request_id: parent_context.request_id.clone(),
                reason: "client cancelled parent request".to_string(),
            });
        }

        if self.cancel_child_on_create_message {
            return Err(KernelError::RequestCancelled {
                request_id: child_context.request_id.clone(),
                reason: "client cancelled nested request".to_string(),
            });
        }

        Ok(self.sampled_message.clone())
    }

    fn create_elicitation(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Ok(self.elicited_content.clone())
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.completed_elicitation_ids
            .push(elicitation_id.to_string());
        Ok(())
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.resource_updates.push(uri.to_string());
        Ok(())
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        self.resources_list_changed_count += 1;
        Ok(())
    }
}

impl ResourceProvider for DocsResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "repo://docs/architecture".to_string(),
                name: "Architecture".to_string(),
                title: Some("Architecture".to_string()),
                description: Some("System architecture".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(128),
                annotations: None,
                icons: None,
            },
            ResourceDefinition {
                uri: "repo://secret/ops".to_string(),
                name: "Ops".to_string(),
                title: None,
                description: Some("Hidden".to_string()),
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
            description: Some("Template".to_string()),
            mime_type: Some("text/markdown".to_string()),
            annotations: None,
            icons: None,
        }]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "repo://docs/architecture" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Architecture".to_string()),
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
            let values = ["architecture", "protocol", "api"]
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

#[derive(Default)]
struct AppendOnlyReceiptStore;

impl ReceiptStore for AppendOnlyReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

/// A store that reports retention support but, like the real prefix-watermark
/// store, cannot honor a tenant-scoped policy (it inherits the default
/// `supports_tenant_scoped_retention` = false). Used to prove the attach path
/// rejects a tenant-scoped retention config before spawning the worker.
#[derive(Default)]
struct RetentionCapableReceiptStore;

impl ReceiptStore for RetentionCapableReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_retention(&self) -> bool {
        true
    }
}

/// A receipt store whose supervised commit writer has died. Appends would still
/// nominally succeed, but the writer flag reports serving-closed, so the kernel
/// pre-dispatch gate must fail closed before any tool executes.
struct DeadWriterReceiptStore;

impl ReceiptStore for DeadWriterReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }
}

/// A receipt store whose supervised commit writer is serving-closed AND whose
/// appends now fail, modelling a real poisoned-head or dead-writer store rather
/// than one that still silently accepts writes. The pre-dispatch gate must deny
/// before any tool executes, and the fail-closed deny it builds must not be
/// masked into an error by attempting to persist itself through the same closed
/// writer.
struct RejectingDeadWriterReceiptStore;

impl ReceiptStore for RejectingDeadWriterReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "receipt append rejected by a serving-closed commit writer".to_string(),
        ))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "child receipt append rejected by a serving-closed commit writer".to_string(),
        ))
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }
}

/// A commit writer that is always serving closed and, once armed, fails every
/// capability-lineage write like a poisoned writer. It records whether the
/// lineage write was attempted so a test can prove the pre-dispatch gate denies
/// BEFORE any writer-backed metadata write runs. Arming is deferred so capability
/// issuance during test setup (which also records lineage) still succeeds.
struct SnapshotTrackingDeadWriterStore {
    snapshot_attempted: std::sync::Arc<AtomicBool>,
    fail_snapshots: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for SnapshotTrackingDeadWriterStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }

    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        if self.fail_snapshots.load(Ordering::SeqCst) {
            self.snapshot_attempted.store(true, Ordering::SeqCst);
            return Err(ReceiptStoreError::Pool(
                "capability lineage write rejected by a dead receipt writer".to_string(),
            ));
        }
        Ok(())
    }
}

/// A store-authoritative point-lookup store: appended chio receipts are retained
/// in-memory and `load_chio_receipt` resolves them by id. Models a durable store
/// that implements point loads, so an evicted parent receipt still resolves from
/// the store after the bounded mirror drops it.
#[derive(Default)]
struct PointLookupReceiptStore {
    chio: std::sync::Mutex<std::collections::HashMap<String, ChioReceipt>>,
}

impl ReceiptStore for PointLookupReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if let Ok(mut map) = self.chio.lock() {
            map.insert(receipt.id.clone(), receipt.clone());
        }
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .chio
            .lock()
            .ok()
            .and_then(|map| map.get(receipt_id).cloned()))
    }
}

/// A store that appends fine (so the local mirror is populated) but fails every
/// point load with a read-boundary error, exercising the fail-closed
/// error-propagation path.
#[derive(Default)]
struct ErroringReceiptStore;

impl ReceiptStore for ErroringReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::ReadBoundary(
            "simulated receipt store read failure".to_string(),
        ))
    }

    fn load_child_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::ReadBoundary(
            "simulated child receipt store read failure".to_string(),
        ))
    }
}

#[derive(Default)]
struct FailingCheckpointHydrationReceiptStore;

impl ReceiptStore for FailingCheckpointHydrationReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "checkpoint chain corrupted".to_string(),
        ))
    }
}

#[derive(Default)]
struct FailingSessionAnchorReceiptStore;

impl ReceiptStore for FailingSessionAnchorReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        _anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        _supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "session anchor write failed".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedSessionAnchor {
    anchor_id: String,
    supersedes_anchor_id: Option<String>,
}

#[derive(Default)]
struct RecordingSessionAnchorReceiptStore {
    anchors: std::sync::Arc<Mutex<Vec<RecordedSessionAnchor>>>,
}

impl ReceiptStore for RecordingSessionAnchorReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.anchors
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("anchor recorder lock poisoned".to_string()))?
            .push(RecordedSessionAnchor {
                anchor_id: anchor_id.to_string(),
                supersedes_anchor_id: supersedes_anchor_id.map(str::to_string),
            });
        Ok(())
    }
}

#[derive(Default)]
struct FailingRequestLineageReceiptStore;

impl ReceiptStore for FailingRequestLineageReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record_request_lineage(
        &self,
        _session_id: &str,
        _request_id: &str,
        _parent_request_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _recorded_at: u64,
        _request_fingerprint: Option<&str>,
        _lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "request lineage write failed".to_string(),
        ))
    }
}

impl ResourceProvider for FilesystemResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "file:///workspace/project/docs/architecture.md".to_string(),
                name: "Filesystem Architecture".to_string(),
                title: Some("Filesystem Architecture".to_string()),
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
            "file:///workspace/project/docs/architecture.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Filesystem Architecture".to_string()),
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
                description: Some("Summarize documentation".to_string()),
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
                description: Some("Hidden".to_string()),
                arguments: vec![],
                icons: None,
            },
        ]
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        match name {
            "summarize_docs" => Ok(Some(PromptResult {
                description: Some("Summarize docs".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: serde_json::json!({
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
            let values = ["architecture", "protocol", "release-notes"]
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
