// A2A 1.0 JSON-RPC projection onto the existing kernel task lifecycle.
// Request metadata remains input, never an execution authority.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V1SendRequest {
    message: V1Message,
    #[serde(default)]
    configuration: Option<V1SendConfiguration>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V1SendConfiguration {
    #[serde(default)]
    accepted_output_modes: Vec<String>,
    #[serde(default)]
    history_length: u32,
    #[serde(default)]
    return_immediately: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V1Message {
    message_id: String,
    role: String,
    parts: Vec<V1Part>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V1Part {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V1TaskRequest {
    id: String,
    #[serde(default)]
    history_length: u32,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Clone, Copy)]
enum V1OutputMode {
    Json,
    Text,
}

fn v1_invalid(message: impl Into<String>) -> A2aEdgeError {
    A2aEdgeError::InvalidRequest(message.into())
}

fn v1_object_metadata(metadata: &Option<Value>) -> Result<(), A2aEdgeError> {
    if metadata.as_ref().is_some_and(|value| !value.is_object()) {
        return Err(v1_invalid("metadata must be an object"));
    }
    Ok(())
}

impl V1SendRequest {
    fn into_internal(
        self,
    ) -> Result<(String, SendMessageRequest, bool, V1OutputMode), A2aEdgeError> {
        let config = self.configuration.unwrap_or_default();
        if config.history_length != 0 {
            return Err(v1_invalid("task history is not supported"));
        }
        if !config.accepted_output_modes.is_empty()
            && !config
                .accepted_output_modes
                .iter()
                .any(|mode| mode == "text/plain" || mode == "application/json")
        {
            return Err(v1_invalid("no supported output mode was requested"));
        }
        let output_mode = if config.accepted_output_modes.is_empty()
            || config
                .accepted_output_modes
                .iter()
                .any(|mode| mode == "application/json")
        {
            V1OutputMode::Json
        } else {
            V1OutputMode::Text
        };
        let message = self.message;
        if message.role != "ROLE_USER" {
            return Err(v1_invalid("message.role must be ROLE_USER"));
        }
        validate_execution_agent_id(&message.message_id)
            .map_err(|_| v1_invalid("message.messageId must be a nonblank, unpadded identifier"))?;
        if message.message_id.len() > 256 {
            return Err(v1_invalid("message.messageId exceeds 256 bytes"));
        }
        v1_object_metadata(&self.metadata)?;
        v1_object_metadata(&message.metadata)?;
        let parts = message
            .parts
            .into_iter()
            .map(|part| {
                v1_object_metadata(&part.metadata)?;
                match (part.text, part.data, part.media_type.as_deref()) {
                    (Some(text), None, None | Some("text/plain")) => Ok(A2aPart::Text { text }),
                    (None, Some(data), None | Some("application/json")) => {
                        Ok(A2aPart::Data { data })
                    }
                    _ => Err(v1_invalid(
                        "each part must contain exactly one supported text or data value",
                    )),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let request = SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts,
                metadata: message.metadata,
            },
            metadata: self.metadata,
        };
        // Validate before retaining a task, including duplicate data parts.
        extract_arguments_from_message(&request.message)?;
        Ok((
            message.message_id,
            request,
            config.return_immediately,
            output_mode,
        ))
    }
}

fn v1_parts(parts: &[A2aPart], mode: V1OutputMode) -> Vec<Value> {
    parts
        .iter()
        .map(|part| match (part, mode) {
            (A2aPart::Text { text }, V1OutputMode::Text) => json!({"text": text}),
            (A2aPart::Text { text }, V1OutputMode::Json) => json!({"data": {"text": text}}),
            (A2aPart::Data { data }, V1OutputMode::Text) => json!({"text": data.to_string()}),
            (A2aPart::Data { data }, V1OutputMode::Json) if data.is_object() => {
                json!({"data": data})
            }
            (A2aPart::Data { data }, V1OutputMode::Json) => json!({"data": {"value": data}}),
        })
        .collect()
}

fn v1_task(task: &TaskResponse, mode: V1OutputMode) -> Value {
    let state = match task.status {
        TaskStatus::Working => "TASK_STATE_WORKING",
        TaskStatus::Completed => "TASK_STATE_COMPLETED",
        TaskStatus::Failed => "TASK_STATE_FAILED",
        TaskStatus::Cancelled => "TASK_STATE_CANCELED",
    };
    let mut result = json!({
        "id": task.id,
        "contextId": format!("context-{}", task.id),
        "status": {"state": state},
    });
    if let Some(metadata) = &task.metadata {
        result["metadata"] = metadata.clone();
    }
    if let Some(message) = &task.message {
        result["artifacts"] = json!([{
            "artifactId": format!("result-{}", task.id),
            "parts": v1_parts(&message.parts, mode),
        }]);
    }
    if let Some(reason) = &task.status_message {
        result["status"]["message"] = json!({
            "messageId": format!("status-{}", task.id),
            "role": "ROLE_AGENT",
            "parts": [{"text": reason}],
        });
    }
    result
}

impl ChioA2aEdge {
    fn handle_v1_send(
        &mut self,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<Value, A2aEdgeError> {
        let skill = self.resolve_jsonrpc_target_skill_id(&params)?;
        let parsed: V1SendRequest = serde_json::from_value(params)
            .map_err(|error| v1_invalid(format!("invalid SendMessage request: {error}")))?;
        let (message_id, request, deferred, output_mode) = parsed.into_internal()?;
        self.prune_deferred_tasks();
        // Include terminal records in this limit because v1 retains blocking results too.
        if self.tasks.len() >= MAX_DEFERRED_A2A_TASKS {
            return Err(v1_invalid("too many retained A2A tasks"));
        }
        let task =
            self.handle_stream_message_with_request_id(&message_id, &skill, &request, execution)?;
        if let Some(retained) = self.tasks.get_mut(&task.id) {
            retained.v1_output_mode = Some(output_mode);
        }
        if deferred {
            return Ok(json!({"task": v1_task(&task, output_mode)}));
        }
        let response = self.complete_task(&task.id, kernel, execution, Value::Null);
        self.v1_project_response(response, true)
    }

    fn v1_project_response(&self, response: Value, wrap: bool) -> Result<Value, A2aEdgeError> {
        if let Some(error) = response.get("error") {
            return Err(A2aEdgeError::Kernel(error.to_string()));
        }
        let task: TaskResponse = serde_json::from_value(response["result"].clone())
            .map_err(|error| A2aEdgeError::Kernel(format!("task projection failed: {error}")))?;
        let mode = self
            .tasks
            .get(&task.id)
            .and_then(|task| task.v1_output_mode)
            .unwrap_or(V1OutputMode::Json);
        let value = v1_task(&task, mode);
        Ok(if wrap { json!({"task": value}) } else { value })
    }

    fn handle_v1_jsonrpc(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        let result = if method == "SendMessage" {
            self.handle_v1_send(params, kernel, execution)
        } else {
            self.handle_v1_task(method, params, kernel, execution)
        };
        match result {
            Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_v1_task(
        &mut self,
        method: &str,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<Value, A2aEdgeError> {
        let parsed: V1TaskRequest = serde_json::from_value(params)
            .map_err(|error| v1_invalid(format!("invalid {method} request: {error}")))?;
        if parsed.history_length != 0 {
            return Err(v1_invalid("task history is not supported"));
        }
        v1_object_metadata(&parsed.metadata)?;
        let params = json!({"taskId": parsed.id});
        let response = if method == "GetTask" {
            self.handle_jsonrpc_task_get(Value::Null, params, kernel, execution)
        } else {
            self.handle_jsonrpc_task_cancel(Value::Null, params, execution)
        };
        self.v1_project_response(response, false)
    }
}
