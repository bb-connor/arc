//! Owner-authorized continuation of a frozen v1 work request.

use super::*;

fn immutable_request_bytes(
    request: &CrossProtocolExecutionRequest,
) -> Result<Vec<u8>, A2aEdgeError> {
    let mut kernel_request = chio_cross_protocol::execution::kernel_tool_call_request(request);
    kernel_request.approval_token = None;
    kernel_request.approval_tokens.clear();
    kernel_request.threshold_approval_proposal = None;
    // The shared projection includes every kernel field. Only the signed
    // approval artifacts may change when an interrupted owner resumes work.
    Ok(chio_core::canonical_json_bytes(&(
        &request.origin_request_id,
        &request.target_protocol,
        &request.source_envelope,
        &request.bridge_security,
        &request.authenticated_session_id,
        &request.security_context,
        kernel_request,
    ))
    .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?)
}

impl ChioA2aEdge {
    pub(super) fn handle_v1_continuation(
        &mut self,
        id: Value,
        skill: &str,
        invocation: V1Invocation,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<A2aJsonRpcResponse, A2aEdgeError> {
        let task_id = invocation
            .task_id
            .as_deref()
            .ok_or_else(|| v1_invalid("continuation requires an existing task id"))?;
        self.prune_deferred_tasks(kernel.authority_clock_reading()?)?;
        validate_execution_context(execution, &self.config.peer_capabilities)?;
        let retained = self
            .tasks
            .get(task_id)
            .filter(|task| task.is_owned_by(execution) && task.v1_output_mode.is_some())
            .ok_or_else(|| A2aEdgeError::TaskNotFound(task_id.to_string()))?;
        if retained.response.status.is_terminal() {
            return Err(v1_invalid("terminal tasks cannot accept a continuation"));
        }
        if invocation
            .context_id
            .as_ref()
            .is_some_and(|context| *context != format!("context-{task_id}"))
        {
            return Err(v1_invalid("continuation context does not match its task"));
        }
        if retained.v1_output_mode != Some(invocation.output_mode) {
            return Err(v1_invalid("continuation must preserve its output mode"));
        }
        if invocation.message_id != retained.request.kernel_request_id {
            return Err(v1_invalid(
                "continuation must preserve its original message id",
            ));
        }
        let candidate = Self::build_execution_request(
            self.resolve_skill_binding(skill)?,
            skill,
            &invocation.request,
            extract_arguments_from_message(&invocation.request.message)?,
            execution,
            retained.request.origin_request_id.clone(),
            retained.request.kernel_request_id.clone(),
        )?;
        if immutable_request_bytes(&candidate)? != immutable_request_bytes(&retained.request)? {
            return Err(v1_invalid(
                "continuation must preserve its original request authority",
            ));
        }
        let original_request = retained.request.clone();
        let original_response = retained.response.clone();
        let retained = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| A2aEdgeError::TaskNotFound(task_id.to_string()))?;
        retained.request = candidate;

        // Explicit SendMessage resumes the accepted work. Polling never enters
        // this path. The kernel validates the new signatures against the same
        // invocation and retains all outcome, replay and settlement authority.
        let response = self.complete_task(task_id, kernel, execution, id);
        let projected = self.v1_project_response(response, true);
        let successful = projected
            .as_ref()
            .is_ok_and(|response| response.get("error").is_none());
        if successful {
            if self
                .tasks
                .get(task_id)
                .is_some_and(|task| task.response.status.is_terminal())
            {
                self.tasks.remove(task_id);
            }
        } else if let Some(retained) = self.tasks.get_mut(task_id) {
            // Keep earlier recoverable custody after transport/projection errors.
            // Do not restore a removed expired task or reset its clock deadline.
            retained.request = original_request;
            retained.response = original_response;
        }
        projected
    }
}
