//! Task completion records whether kernel evaluation was entered.

use super::*;

pub(super) enum TaskCompletionAttempt {
    NotEvaluated(A2aJsonRpcResponse),
    Evaluated(A2aJsonRpcResponse),
}

impl TaskCompletionAttempt {
    fn into_response(self) -> A2aJsonRpcResponse {
        match self {
            Self::NotEvaluated(response) | Self::Evaluated(response) => response,
        }
    }
}

impl ChioA2aEdge {
    pub(super) fn complete_task(
        &mut self,
        task_id: &str,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        id: Value,
    ) -> A2aJsonRpcResponse {
        self.attempt_task_completion(task_id, kernel, execution, id)
            .into_response()
    }

    pub(super) fn attempt_task_completion(
        &mut self,
        task_id: &str,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        id: Value,
    ) -> TaskCompletionAttempt {
        use TaskCompletionAttempt::{Evaluated, NotEvaluated};

        if let Err(error) = validate_execution_context(execution, &self.config.peer_capabilities) {
            return NotEvaluated(Self::jsonrpc_error_response(id, error));
        }
        let Some(task) = self.tasks.get_mut(task_id) else {
            return NotEvaluated(Self::jsonrpc_error_response(
                id,
                A2aEdgeError::ToolNotFound(task_id.to_string()),
            ));
        };
        if !task.is_owned_by(execution) {
            return NotEvaluated(Self::jsonrpc_error_response(
                id,
                A2aEdgeError::InvalidRequest("task is not owned by the current agent".to_string()),
            ));
        }
        if task.response.status != TaskStatus::Working {
            return NotEvaluated(A2aJsonRpcResponse::response(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&task.response).unwrap_or(Value::Null)
            })));
        }
        if let Err(error) = kernel
            .authority_clock_reading()
            .and_then(|now| task.deadline.remaining(now))
        {
            if error == ClockError::Expired {
                self.tasks.remove(task_id);
            }
            return NotEvaluated(Self::jsonrpc_error_response(id, error.into()));
        }
        let request = task.request.clone();
        let registry = match self.manifest_registry() {
            Ok(registry) => registry,
            Err(error) => return NotEvaluated(Self::jsonrpc_error_response(id, error)),
        };
        // After entering orchestration, an error may follow a committed effect.
        // This marker permits no inference that a tool did or did not execute.
        let orchestrated = match execute_orchestrated_a2a_request(
            &self.config.peer_capabilities,
            kernel,
            registry,
            request,
        ) {
            Ok(orchestrated) => orchestrated,
            Err(error) => return Evaluated(Self::jsonrpc_error_response(id, error)),
        };
        let response = task_response_from_orchestrated(task_id.to_string(), orchestrated);
        let response = match self.tasks.get_mut(task_id) {
            Some(task) if task.response.status == TaskStatus::Working => {
                task.response = response;
                task.response.clone()
            }
            Some(task) => task.response.clone(),
            None => {
                return Evaluated(Self::jsonrpc_error_response(
                    id,
                    A2aEdgeError::ToolNotFound(task_id.to_string()),
                ));
            }
        };
        Evaluated(A2aJsonRpcResponse::response(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": serde_json::to_value(&response).unwrap_or(Value::Null)
        })))
    }
}
