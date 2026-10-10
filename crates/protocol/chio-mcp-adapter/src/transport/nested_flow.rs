use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, ClockReading, SystemClock};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

const MAX_NESTED_TASKS: usize = 128;
const MAX_TASK_TTL_MS: u64 = 86_400_000;
const DEFAULT_TASK_TTL_MS: u64 = 600_000;

use chio_core::session::{
    CreateElicitationOperation, CreateMessageOperation, TaskOwnershipSnapshot,
};
use chio_kernel::{KernelError, NestedFlowBridge};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::edge::AdapterError;

use super::utils::{
    attach_related_task_meta_to_result, build_related_task_meta, json_rpc_error, json_rpc_result,
    map_nested_flow_error_code, send_line, MAX_BACKGROUND_TASKS_PER_TICK,
    TASK_POLL_INTERVAL_MILLIS,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RequestedTask {
    #[serde(default)]
    pub(super) ttl: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NestedFlowTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
enum NestedFlowTaskOperation {
    CreateMessage(CreateMessageOperation),
    CreateElicitation(CreateElicitationOperation),
}

#[derive(Debug, Clone)]
enum NestedFlowTaskFinalOutcome {
    Result(serde_json::Value),
    Error { code: i64, message: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NestedFlowTask {
    task_id: String,
    status: NestedFlowTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    created_at: String,
    last_updated_at: String,
    pub(super) ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval: Option<u64>,
    ownership: TaskOwnershipSnapshot,
    owner_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_request_id: Option<String>,
    #[serde(skip)]
    operation: NestedFlowTaskOperation,
    #[serde(skip)]
    final_outcome: Option<NestedFlowTaskFinalOutcome>,
    #[serde(skip)]
    deadline: AuthorityDeadline,
}

impl NestedFlowTask {
    fn new_create_message(
        task_id: String,
        owner_request_id: String,
        parent_request_id: Option<String>,
        operation: CreateMessageOperation,
        ttl: Option<u64>,
        observed: ClockReading,
    ) -> Result<Self, AdapterError> {
        let now = task_timestamp(observed)?;
        let ttl_ms = ttl.unwrap_or(DEFAULT_TASK_TTL_MS);
        if ttl_ms > MAX_TASK_TTL_MS {
            return Err(ClockError::InvalidWindow.into());
        }
        let deadline = AuthorityDeadline::for_timeout_ms(observed, ttl_ms)?;
        Ok(Self {
            task_id,
            status: NestedFlowTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_request_id,
            parent_request_id,
            operation: NestedFlowTaskOperation::CreateMessage(operation),
            final_outcome: None,
            deadline,
        })
    }

    fn new_create_elicitation(
        task_id: String,
        owner_request_id: String,
        parent_request_id: Option<String>,
        operation: CreateElicitationOperation,
        ttl: Option<u64>,
        observed: ClockReading,
    ) -> Result<Self, AdapterError> {
        let now = task_timestamp(observed)?;
        let ttl_ms = ttl.unwrap_or(DEFAULT_TASK_TTL_MS);
        if ttl_ms > MAX_TASK_TTL_MS {
            return Err(ClockError::InvalidWindow.into());
        }
        let deadline = AuthorityDeadline::for_timeout_ms(observed, ttl_ms)?;
        Ok(Self {
            task_id,
            status: NestedFlowTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_request_id,
            parent_request_id,
            operation: NestedFlowTaskOperation::CreateElicitation(operation),
            final_outcome: None,
            deadline,
        })
    }

    pub(super) fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            NestedFlowTaskStatus::Completed
                | NestedFlowTaskStatus::Failed
                | NestedFlowTaskStatus::Cancelled
        )
    }

    fn touch(&mut self, observed: ClockReading) {
        if let Ok(timestamp) = task_timestamp(observed) {
            self.last_updated_at = timestamp;
        }
    }

    fn mark_completed(&mut self, result: serde_json::Value, observed: ClockReading) {
        self.status = NestedFlowTaskStatus::Completed;
        self.status_message = Some("The operation completed successfully.".to_string());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Result(result));
        self.touch(observed);
    }

    fn mark_failed(&mut self, code: i64, message: String, observed: ClockReading) {
        self.status = NestedFlowTaskStatus::Failed;
        self.status_message = Some(message.clone());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Error { code, message });
        self.touch(observed);
    }

    fn mark_cancelled(&mut self, reason: &str, observed: ClockReading) {
        self.status = NestedFlowTaskStatus::Cancelled;
        self.status_message = Some(reason.to_string());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Error {
            code: -32800,
            message: reason.to_string(),
        });
        self.touch(observed);
    }
}

pub(super) struct NestedFlowTaskRuntime {
    task_counter: u64,
    clock: Arc<dyn Clock>,
    pub(super) tasks: BTreeMap<String, NestedFlowTask>,
    pending_background_tasks: Vec<String>,
}

impl Default for NestedFlowTaskRuntime {
    fn default() -> Self {
        Self {
            task_counter: 0,
            clock: Arc::new(SystemClock),
            tasks: BTreeMap::new(),
            pending_background_tasks: Vec::new(),
        }
    }
}

impl NestedFlowTaskRuntime {
    fn prune_expired(&mut self) -> Result<ClockReading, AdapterError> {
        let now = self.clock.read()?;
        let mut expired = Vec::new();
        for (id, task) in &mut self.tasks {
            match task.deadline.remaining(now) {
                Ok(_) => {}
                Err(ClockError::Expired) => expired.push(id.clone()),
                Err(error) => return Err(error.into()),
            }
        }
        for id in expired {
            self.tasks.remove(&id);
        }
        self.pending_background_tasks
            .retain(|id| self.tasks.contains_key(id));
        Ok(now)
    }

    fn prepare_task(&mut self) -> Result<ClockReading, AdapterError> {
        let now = self.prune_expired()?;
        // Terminal results remain owned by the caller until their original TTL
        // expires. A new request cannot reclaim another task's result custody.
        if self.tasks.len() >= MAX_NESTED_TASKS {
            return Err(AdapterError::TaskCapacity);
        }
        Ok(now)
    }

    fn next_task_id(&mut self) -> Result<String, AdapterError> {
        self.task_counter = self
            .task_counter
            .checked_add(1)
            .ok_or(ClockError::Overflow)?;
        Ok(format!("nested-client-task-{}", self.task_counter))
    }

    pub(super) fn create_message_task(
        &mut self,
        owner_request_id: String,
        parent_request_id: String,
        operation: CreateMessageOperation,
        requested_task: RequestedTask,
    ) -> Result<serde_json::Value, AdapterError> {
        let observed = self.prepare_task()?;
        let task_id = self.next_task_id()?;
        let task = NestedFlowTask::new_create_message(
            task_id.clone(),
            owner_request_id,
            Some(parent_request_id),
            operation,
            requested_task.ttl,
            observed,
        )?;
        let task_view = task.clone();
        self.tasks.insert(task_id.clone(), task);
        self.pending_background_tasks.push(task_id);
        Ok(json!({ "task": task_view }))
    }

    pub(super) fn create_elicitation_task(
        &mut self,
        owner_request_id: String,
        parent_request_id: String,
        operation: CreateElicitationOperation,
        requested_task: RequestedTask,
    ) -> Result<serde_json::Value, AdapterError> {
        let observed = self.prepare_task()?;
        let task_id = self.next_task_id()?;
        let task = NestedFlowTask::new_create_elicitation(
            task_id.clone(),
            owner_request_id,
            Some(parent_request_id),
            operation,
            requested_task.ttl,
            observed,
        )?;
        let task_view = task.clone();
        self.tasks.insert(task_id.clone(), task);
        self.pending_background_tasks.push(task_id);
        Ok(json!({ "task": task_view }))
    }

    pub(super) fn handle_tasks_list(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let _observed = match self.prune_expired() {
            Ok(now) => now,
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        };
        let start = match parse_cursor(params) {
            Ok(start) => start,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let tasks = self.tasks.values().cloned().collect::<Vec<_>>();
        if start > tasks.len() {
            return json_rpc_error(id, -32602, "cursor is out of range");
        }

        let end = start + 50.min(tasks.len() - start);
        let next_cursor = (end < tasks.len()).then(|| end.to_string());
        let page = tasks[start..end]
            .iter()
            .map(|task| serde_json::to_value(task).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        json_rpc_result(
            id,
            json!({
                "tasks": page,
                "nextCursor": next_cursor,
            }),
        )
    }

    pub(super) fn handle_tasks_get(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let _observed = match self.prune_expired() {
            Ok(now) => now,
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        };
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let Some(task) = self.tasks.get(&task_id) else {
            return json_rpc_error(id, -32602, "Failed to retrieve task: Task not found");
        };

        json_rpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    pub(super) fn handle_tasks_cancel(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let observed = match self.prune_expired() {
            Ok(now) => now,
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        };
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let Some(task) = self.tasks.get_mut(&task_id) else {
            return json_rpc_error(id, -32602, "Failed to retrieve task: Task not found");
        };
        if task.is_terminal() {
            return json_rpc_error(
                id,
                -32602,
                &format!(
                    "Cannot cancel task: already in terminal status '{}'",
                    nested_flow_task_status_label(task.status)
                ),
            );
        }

        task.mark_cancelled("The task was cancelled by request.", observed);
        self.pending_background_tasks
            .retain(|pending| pending != &task_id);
        json_rpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    pub(super) fn handle_tasks_result(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        writer: &mut impl Write,
    ) -> Result<serde_json::Value, AdapterError> {
        self.prune_expired()?;
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return Ok(json_rpc_error(id, -32602, &message)),
        };

        if !self.tasks.contains_key(&task_id) {
            return Ok(json_rpc_error(
                id,
                -32602,
                "Failed to retrieve task: Task not found",
            ));
        }

        if !self
            .tasks
            .get(&task_id)
            .is_some_and(NestedFlowTask::is_terminal)
        {
            self.execute_task(&task_id, nested_flow_bridge, writer)?;
        }

        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(json_rpc_error(
                id,
                -32602,
                "Failed to retrieve task: Task not found",
            ));
        };

        let response = match task.final_outcome.clone() {
            Some(NestedFlowTaskFinalOutcome::Result(result)) => json_rpc_result(
                id,
                attach_related_task_meta_to_result(
                    result,
                    build_related_task_meta(
                        &task.task_id,
                        Some(&task.owner_request_id),
                        task.parent_request_id.as_deref(),
                    ),
                ),
            ),
            Some(NestedFlowTaskFinalOutcome::Error { code, message }) => {
                json_rpc_error(id, code, &message)
            }
            None => json_rpc_error(id, -32603, "task result unavailable"),
        };

        Ok(response)
    }

    pub(super) fn process_background_tasks(
        &mut self,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        writer: &mut impl Write,
    ) -> Result<(), AdapterError> {
        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            self.prune_expired()?;
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };

            if !self.tasks.contains_key(&task_id) {
                self.pending_background_tasks
                    .retain(|pending| pending != &task_id);
                continue;
            }

            if self
                .tasks
                .get(&task_id)
                .is_some_and(NestedFlowTask::is_terminal)
            {
                self.pending_background_tasks
                    .retain(|pending| pending != &task_id);
                continue;
            }

            self.execute_task(&task_id, nested_flow_bridge, writer)?;
            if let Some(task) = self.tasks.get(&task_id) {
                send_line(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/tasks/status",
                        "params": serde_json::to_value(task).unwrap_or_else(|_| json!({})),
                    }),
                )?;
            }
        }
        Ok(())
    }

    fn execute_task(
        &mut self,
        task_id: &str,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        _writer: &mut impl Write,
    ) -> Result<(), AdapterError> {
        let observed = self.prune_expired()?;
        let Some(mut task) = self.tasks.remove(task_id) else {
            return Ok(());
        };

        if !task.is_terminal() {
            let result = match task.operation.clone() {
                NestedFlowTaskOperation::CreateMessage(operation) => nested_flow_bridge
                    .create_message(operation)
                    .and_then(|value| {
                        serde_json::to_value(value).map_err(|error| {
                            KernelError::UntrustedInput(
                                chio_core::canonical::UntrustedJsonError::Decode(error),
                            )
                        })
                    }),
                NestedFlowTaskOperation::CreateElicitation(operation) => nested_flow_bridge
                    .create_elicitation(operation)
                    .and_then(|value| {
                        serde_json::to_value(value).map_err(|error| {
                            KernelError::UntrustedInput(
                                chio_core::canonical::UntrustedJsonError::Decode(error),
                            )
                        })
                    }),
            };
            match result {
                Ok(result) => task.mark_completed(result, observed),
                Err(error) => task.mark_failed(
                    map_nested_flow_error_code(&error),
                    error.to_string(),
                    observed,
                ),
            }
        }
        self.pending_background_tasks
            .retain(|pending| pending != task_id);

        self.tasks.insert(task_id.to_string(), task);
        Ok(())
    }
}

pub(super) fn parse_requested_task(
    params: &serde_json::Value,
) -> Result<Option<RequestedTask>, AdapterError> {
    let Some(task) = params.get("task").cloned() else {
        return Ok(None);
    };
    let task: RequestedTask =
        serde_json::from_value(task).map_err(chio_core::canonical::UntrustedJsonError::Decode)?;
    if task
        .ttl
        .is_some_and(|ttl| ttl == 0 || ttl > MAX_TASK_TTL_MS)
    {
        return Err(ClockError::InvalidWindow.into());
    }
    Ok(Some(task))
}

fn parse_cursor(params: &serde_json::Value) -> Result<usize, String> {
    let cursor = match params.get("cursor") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return Err("cursor must be a string".to_string()),
    };

    match cursor.as_deref() {
        None => Ok(0),
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| "cursor must be numeric".to_string()),
    }
}

fn parse_task_id(params: &serde_json::Value) -> Result<String, String> {
    params
        .get("taskId")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "taskId must be a string".to_string())
}

fn nested_flow_task_status_label(status: NestedFlowTaskStatus) -> &'static str {
    match status {
        NestedFlowTaskStatus::Working => "working",
        NestedFlowTaskStatus::Completed => "completed",
        NestedFlowTaskStatus::Failed => "failed",
        NestedFlowTaskStatus::Cancelled => "cancelled",
    }
}

fn task_timestamp(observed: ClockReading) -> Result<String, ClockError> {
    let millis = i64::try_from(observed.unix_millis().get()).map_err(|_| ClockError::Overflow)?;
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .ok_or(ClockError::Overflow)
}

#[cfg(test)]
#[path = "nested_flow_tests.rs"]
mod boundary_tests;
