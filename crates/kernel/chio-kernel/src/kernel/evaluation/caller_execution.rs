//! Caller execution separates preparation, committed start and authenticated
//! return. Reservation never authorizes an effect. Legacy unsigned reports are
//! refused when an executor is pinned; historical signed reports enter the
//! original finalization path without repeating admission.

use std::sync::{Arc, Mutex};

use super::evaluation_helpers::ExecutionNonceReservingResponse;
use super::*;
use crate::execution_nonce::SignedExecutionNonce;
use crate::kernel::credential_reservation::DispatchCredentialReservation;
use crate::kernel::responses::PreflightNonceSource;
use crate::{NestedFlowBridge, ToolInvocationCost, ToolServerConnection};

/// A reservation or receipt is never execution permission. Only `Authorized`
/// carries the committed statement a configured durable executor can claim.
pub enum CallerStartResponse {
    Authorized(Box<crate::caller_delivery::SignedCallerDispatchAuthorizationV1>),
    Denied(Box<ToolCallResponse>),
}

/// Live credential presentation for a reserved caller start. These artifacts
/// are revalidated against the original operation-owned claims, never copied
/// into the private return snapshot or recovered from a delivery report.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerStartCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_proof: Option<crate::dpop::DpopProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<chio_core::capability::governance::GovernedApprovalToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<chio_core::capability::governance::GovernedApprovalToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_approval_proposal:
        Option<chio_core::capability::governance::ThresholdApprovalProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declassification_grant: Option<chio_core_types::SignedDeclassificationGrant>,
}

/// The trusted executor callback's output after a committed caller start.
/// This unsigned value is not delivery evidence until its durable executor
/// ledger has bound and signed it as a `SignedCallerDeliveryReportV1`.
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
    /// Complete the start-side evaluation only after the original dispatch is
    /// committed. The outer start producer signs the authorization separately;
    /// this internal receipt and nonce are not permission to execute.
    pub(super) fn build_committed_caller_start_response(
        &self,
        request: &ToolCallRequest,
        admission: Option<&DurableToolAdmission>,
        grant_index: usize,
        metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let nonce = admission
            .filter(|admission| admission.operation().dispatch_commit().is_some())
            .and_then(DurableToolAdmission::issued_nonce)
            .ok_or_else(|| {
                KernelError::DurableAdmission("caller start lost its committed nonce".into())
            })?;
        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            current_unix_timestamp(),
            Some(grant_index),
            metadata,
            "caller dispatch committed; authenticated executor claim required",
            None,
            PreflightNonceSource::Durable(Box::new(nonce.clone())),
        )
    }

    /// Configure the trusted host executor before admitting calls. A supplied
    /// report cannot choose this key. Reconfiguration refuses old operations
    /// through their immutable authority profile.
    pub fn set_caller_executor(
        &mut self,
        executor: crate::caller_delivery::CallerExecutorIdentityV1,
    ) -> Result<(), KernelError> {
        executor
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        self.caller_executor = Some(executor);
        Ok(())
    }

    /// Trusted host selection, never a value adopted from caller input.
    pub fn caller_executor_identity(
        &self,
    ) -> Option<&crate::caller_delivery::CallerExecutorIdentityV1> {
        self.caller_executor.as_ref()
    }

    /// Capture the original reservation before publishing execution authority.
    /// Explicit retries recover the identical original statement and interval;
    /// they never renew permission or dispatch a registered tool server.
    pub fn start_caller_execution_blocking(
        &self,
        nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
    ) -> Result<CallerStartResponse, KernelError> {
        self.start_caller_execution_with_credentials_blocking(
            nonce,
            arguments,
            CallerStartCredentials::default(),
        )
    }

    /// Start with a fresh presentation of the originally admitted credentials.
    /// Historical authorization recovery does not consume those credentials or
    /// extend their validity; new starts run the shared live admission checks.
    pub fn start_caller_execution_with_credentials_blocking(
        &self,
        nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        credentials: CallerStartCredentials,
    ) -> Result<CallerStartResponse, KernelError> {
        self.start_caller_execution_inner(nonce, arguments, credentials, None)
    }

    /// A trusted embedding supplies native identity and isolation context for
    /// a fresh start. Caller-provided JSON cannot select this host context.
    pub fn start_caller_execution_blocking_with_security_context(
        &self,
        nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        credentials: CallerStartCredentials,
        security_context: &SecurityInvocationContext,
    ) -> Result<CallerStartResponse, KernelError> {
        self.start_caller_execution_inner(nonce, arguments, credentials, Some(security_context))
    }

    fn start_caller_execution_inner(
        &self,
        nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        credentials: CallerStartCredentials,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<CallerStartResponse, KernelError> {
        if let Some(authorization) = self.committed_caller_authorization(nonce, arguments)? {
            return Ok(CallerStartResponse::Authorized(Box::new(authorization)));
        }
        let mut request = self.caller_reserved_request(
            &nonce.nonce.bound_to.request_id,
            current_unix_timestamp_ms(),
        )?;
        request.execution_nonce = Some(nonce.clone());
        request.dpop_proof = credentials.dpop_proof;
        request.approval_token = credentials.approval_token;
        request.approval_tokens = credentials.approval_tokens;
        request.threshold_approval_proposal = credentials.threshold_approval_proposal;
        request.declassification_grant = credentials.declassification_grant;
        let response =
            block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
                &request,
                None,
                None,
                None,
                security_context,
                EvaluationDisposition::caller_start(),
            ))?;
        if response.verdict != Verdict::Allow {
            return Ok(CallerStartResponse::Denied(Box::new(response)));
        }
        let authorization = self
            .committed_caller_authorization(nonce, arguments)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("caller start did not retain a commitment".into())
            })?;
        Ok(CallerStartResponse::Authorized(Box::new(authorization)))
    }

    /// Credentials require authenticated start and physical operation-owned
    /// custody. Live-only security owners and opaque extensions cannot be
    /// reconstructed from historical request DTOs and remain fail-closed.
    pub(super) fn caller_reservation_profile_denial(
        &self,
        request: &ToolCallRequest,
        dpop_required: bool,
    ) -> Option<&'static str> {
        let authenticated = self.caller_executor.is_some();
        let native = authenticated
            && self.security_pre_dispatch_policy == SecurityPreDispatchPolicy::Enforce
            && self
                .native_security_authority_binding()
                .ok()
                .flatten()
                .is_some();
        if ((dpop_required || request.dpop_proof.is_some())
            && (!authenticated || self.dpop_authority.is_none()))
            || (request.approval_token.is_some()
                && (!authenticated || self.governed_approval_authority.is_none()))
            || ((!request.approval_tokens.is_empty()
                || request.threshold_approval_proposal.is_some())
                && !authenticated)
            || request.supplemental_authorization.is_some()
            || (request.declassification_grant.is_some() && !native)
        {
            return Some("caller execution requires authenticated start and operation-owned credential custody");
        }
        if (self.security_pre_dispatch_hook.is_some()
            || self.security_pre_dispatch_policy == SecurityPreDispatchPolicy::Enforce)
            && !native
        {
            return Some("caller execution requires qualified native capture and recoverable release custody");
        }
        None
    }

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
            mut durable_admission,
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
            .as_deref_mut()
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
                    durable_admission: durable_admission.as_deref(),
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
    /// an authenticated start commits it or unused permission expires. A request
    /// presenting the issued nonce retries the same preparation. The receipt is
    /// a reservation acknowledgement, never execution authority. No registered
    /// tool is dispatched. Credential-bearing profiles require operation-owned
    /// custody; live-only security owners remain unsupported for external calls.
    pub fn reserve_caller_execution_blocking(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.reserve_caller_execution_inner(request, None)
    }

    /// Reserve against identity supplied by the trusted native host. The
    /// reservation is still non-executable and acquires no release owner.
    /// Without a nonce, returns only the preflight response. The host must
    /// refresh the native flow generation after that join and present the nonce
    /// with the refreshed context to reserve. No historical context is promoted
    /// into current host authority by this convenience API.
    pub fn reserve_caller_execution_blocking_with_security_context(
        &self,
        request: &ToolCallRequest,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        self.reserve_caller_execution_inner(request, Some(security_context))
    }

    fn reserve_caller_execution_inner(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<ToolCallResponse, KernelError> {
        let mut execution = request.clone();
        if execution.execution_nonce.is_none() {
            let preflight = self.reserve_caller_execution_step(&execution, security_context)?;
            if security_context.is_some() {
                return Ok(preflight);
            }
            let Some(nonce) = preflight.execution_nonce.as_deref() else {
                return Ok(preflight);
            };
            execution.execution_nonce = Some(nonce.clone());
        }
        self.reserve_caller_execution_step(&execution, security_context)
    }

    fn reserve_caller_execution_step(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            None,
            None,
            security_context,
            EvaluationDisposition::caller_reservation(),
        ))
    }

    /// Legacy unsigned reconciliation, refused when a caller executor is pinned.
    /// This compatibility path does not authorize an external effect. New
    /// integrations must use committed start and authenticated delivery reports.
    pub fn reconcile_caller_execution_blocking(
        &self,
        nonce: &SignedExecutionNonce,
        arguments: &serde_json::Value,
        report: CallerExecutionReport,
    ) -> Result<ToolCallResponse, KernelError> {
        if self.caller_executor.is_some() {
            return Err(KernelError::DurableAdmission(
                "configured caller executor requires authenticated start and delivery; unsigned reports are not accepted".into(),
            ));
        }
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
