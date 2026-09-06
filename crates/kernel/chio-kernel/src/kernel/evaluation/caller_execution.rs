//! Caller-executed tool calls under durable admission. A reserve keeps the
//! executable hold and the nonce for a tool that runs outside this kernel; the
//! reconcile resumes the same operation with the caller's report standing in
//! for the tool server, so the return is recorded, evaluated and receipted
//! exactly as an in-kernel dispatch.

use std::sync::{Arc, Mutex};

use super::evaluation_helpers::ExecutionNonceReservingResponse;
use super::*;
use crate::execution_nonce::SignedExecutionNonce;
use crate::kernel::credential_reservation::DispatchCredentialReservation;
use crate::kernel::responses::PreflightNonceSource;
use crate::{NestedFlowBridge, ToolInvocationCost, ToolServerConnection};

/// What a caller reports after executing a reserved tool call elsewhere.
#[derive(Debug, Clone)]
pub struct CallerExecutionReport {
    /// The output the caller observed, recorded as the tool's return.
    pub output: serde_json::Value,
    /// The realized cost the caller reports, settled against the reservation.
    pub realized_cost: Option<ToolInvocationCost>,
}

/// Stands in for the tool server while a caller-reserved operation finalizes.
struct CallerReportServer {
    server_id: String,
    tool_name: String,
    report: Mutex<Option<CallerExecutionReport>>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CallerReportServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invoke_with_cost(tool_name, arguments, nested_flow_bridge)
            .await
            .map(|(value, _)| value)
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        if tool_name != self.tool_name {
            return Err(KernelError::ToolServerError(format!(
                "caller report covers tool {} but the dispatch names {tool_name}",
                self.tool_name
            )));
        }
        let report = self
            .report
            .lock()
            .map_err(|_| KernelError::Internal("caller report lock poisoned".to_owned()))?
            .take()
            .ok_or_else(|| {
                KernelError::ToolServerError("caller report was already consumed".to_owned())
            })?;
        Ok((report.output, report.realized_cost))
    }
}

/// The admitted state a caller reservation stops at, before any capture.
pub(super) struct CallerReservation<'a, 'c> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) durable_admission: Option<&'a mut DurableToolAdmission>,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) credential_reservation: &'a mut DispatchCredentialReservation<'c>,
    pub(super) extra_metadata: Option<serde_json::Value>,
    pub(super) now: u64,
    pub(super) now_unix_ms: u64,
    pub(super) matched_grant_index: usize,
    pub(super) pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
    pub(super) budget_lease_acquired: bool,
}

impl ChioKernel {
    /// Reserve the nonce of an admitted caller execution and answer with the
    /// reserving authorization. The operation rests in `ReadyToDispatch`; a
    /// reservation that cannot be confirmed denies with the retained metadata
    /// and leaves the operation to recovery.
    pub(super) fn finish_caller_reservation(
        &self,
        reservation: CallerReservation<'_, '_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let CallerReservation {
            request,
            durable_admission,
            budget_mutation,
            credential_reservation,
            extra_metadata,
            now,
            now_unix_ms,
            matched_grant_index,
            pre_invocation_guard_evidence,
            budget_lease_acquired,
        } = reservation;
        let reserved = durable_admission
            .filter(|admission| admission.requires_execution_nonce())
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "caller execution reservation requires the durable nonce participant"
                        .to_owned(),
                )
            })
            .and_then(|admission| {
                self.reserve_durable_execution_nonce(admission, now_unix_ms)?;
                admission.issued_nonce().cloned().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "caller execution reservation lost its issued nonce".to_owned(),
                    )
                })
            });
        let nonce = match reserved {
            Ok(nonce) => nonce,
            Err(error) => {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "caller execution reservation could not be confirmed");
                return self.build_deny_response_with_metadata(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    self.retained_admission_receipt_metadata(budget_mutation, extra_metadata),
                );
            }
        };
        credential_reservation.commit()?;
        self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
            self.build_execution_nonce_authorization_reserving_response(
                ExecutionNonceReservingResponse {
                    request,
                    timestamp: now,
                    matched_grant_index,
                    budget_mutation,
                    runtime_admission_metadata: extra_metadata.clone(),
                    reserved_payment_reference: None,
                    budget_lease_acquired,
                    nonce: PreflightNonceSource::Durable(Box::new(nonce.clone())),
                },
            )
        })
    }

    /// Reserve a caller execution. Without a nonce the strict preflight runs
    /// first and issues the operation-bound nonce; the execution's first half
    /// then acquires the executable hold, decides cumulative approval and
    /// reserves the nonce, and the operation rests in `ReadyToDispatch` until
    /// the caller reconciles or the nonce expires. A request presenting the
    /// issued nonce is an approved retry of that second half. The receipt is
    /// the reserving authorization, not a completed execution, and no tool
    /// target has to be registered because none is dispatched.
    pub fn reserve_caller_execution_blocking(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        let mut execution = request.clone();
        if execution.execution_nonce.is_none() {
            let preflight = self.reserve_caller_execution_step(&execution)?;
            let Some(nonce) = preflight.execution_nonce.as_deref() else {
                return Ok(preflight);
            };
            execution.execution_nonce = Some(nonce.clone());
        }
        self.reserve_caller_execution_step(&execution)
    }

    fn reserve_caller_execution_step(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            None,
            None,
            None,
            EvaluationDisposition::caller_reservation(),
        ))
    }

    /// Reconcile a caller execution. The presented nonce names the reserved
    /// operation, the arguments must hash to the retained action, and the
    /// report is recorded as the tool's return before the operation completes.
    /// A second reconcile replays the completed receipt.
    pub fn reconcile_caller_execution_blocking(
        &self,
        nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        report: CallerExecutionReport,
    ) -> Result<ToolCallResponse, KernelError> {
        let mut request = self.caller_reserved_request(
            &nonce.nonce.bound_to.request_id,
            current_unix_timestamp_ms(),
        )?;
        let presented = ToolCallAction::from_parameters(arguments.clone()).map_err(|error| {
            KernelError::DurableAdmission(format!(
                "caller report arguments cannot be hashed: {error}"
            ))
        })?;
        let retained =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "retained request arguments cannot be hashed: {error}"
                ))
            })?;
        if presented.parameter_hash != retained.parameter_hash {
            return Err(KernelError::DurableAdmission(
                "caller report arguments do not match the reserved call".to_owned(),
            ));
        }
        request.execution_nonce = Some(nonce.clone());
        let server: Arc<dyn ToolServerConnection> = Arc::new(CallerReportServer {
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            report: Mutex::new(Some(report)),
        });
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            &request,
            None,
            None,
            None,
            None,
            EvaluationDisposition::caller_report(server),
        ))
    }
}
