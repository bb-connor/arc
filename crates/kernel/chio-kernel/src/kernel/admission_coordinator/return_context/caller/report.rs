//! Authenticate historical delivery without running any admission or dispatch
//! callback. Only the original finalization pipeline may release the output.
use super::*;
use crate::caller_delivery::{SignedCallerDeliveryReportV1, SignedCallerDispatchAuthorizationV1};
use crate::kernel::kernel_scopes::RECEIPT_EVALUATION_SCOPE_KEY;

impl ChioKernel {
    /// Accept the configured executor's original report, including after nonce
    /// or capability expiry. Authentication here confers no execution authority.
    /// Conflicting reports cannot replace a previously recorded observation.
    pub fn reconcile_authenticated_caller_execution_blocking(
        &self,
        authorization: &SignedCallerDispatchAuthorizationV1,
        report: &SignedCallerDeliveryReportV1,
    ) -> Result<ToolCallResponse, KernelError> {
        authorization
            .canonical_bytes()
            .map_err(|error| invalid(error.to_string()))?;
        let report_bytes = report
            .canonical_bytes()
            .map_err(|error| invalid(error.to_string()))?;
        let digest = chio_core::crypto::sha256_hex(&report_bytes);
        let runtime = self.durable_runtime()?;
        let guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let (operation, original) = custody::custody_call(|| {
            runtime.store.load_unambiguous_retained_tool_request(
                &authorization.authorization.invocation.request_id,
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("caller report original request is absent"))?;
        let live_owner = runtime
            .mutation_sequencer
            .try_own_operation(operation.binding().operation_id())?
            .ok_or_else(|| invalid("caller operation is already being evaluated"))?;
        let nonce = custody::custody_call(|| {
            runtime.store.load_execution_nonce_reservation(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("caller report original nonce is absent"))?;
        let frame = custody::custody_call(|| {
            runtime.store.load_caller_dispatch_context(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("caller report original context is absent"))?;
        let request = original.request_for_revalidation().clone();
        let mut admission = DurableToolAdmission {
            operation,
            retained_request: Some(original),
            issued_nonce: Some(nonce.clone()),
            aggregate_quota: None,
            supplemental_quota: None,
            nonce_preflight: None,
            _live_owner: Some(live_owner),
        };
        drop(guard);
        let expected = self
            .committed_caller_authorization(nonce.signed_nonce(), &request.arguments)?
            .ok_or_else(|| invalid("caller report preceded dispatch commitment"))?;
        if authorization != &expected {
            return Err(invalid(
                "caller report authorization differs from original commitment",
            ));
        }
        report
            .verify(
                &expected,
                &self.config.keypair.public_key(),
                &expected.authorization.executor,
                &expected.authorization.invocation,
            )
            .map_err(|error| invalid(error.to_string()))?;
        if report.report.completed_at_unix_ms > now {
            return Err(invalid(
                "caller report completion is later than trusted observation time",
            ));
        }
        // No evaluation scope, live operation owner, nonce, hold or dispatch
        // authority is reconstructed from the report's untrusted fields.
        RECEIPT_EVALUATION_SCOPE_KEY.sync_scope(uuid::Uuid::now_v7().to_string(), || {
            if matches!(
                admission.state(),
                AdmissionOperationState::Finalizing
                    | AdmissionOperationState::Completed
                    | AdmissionOperationState::DeniedAfterDelivery
            ) {
                let retained = self.load_durable_tool_return(&admission)?;
                if retained.caller_report_digest() != Some(digest.as_str()) {
                    return Err(invalid(
                        "caller report conflicts with retained authenticated delivery",
                    ));
                }
                return self
                    .recover_durable_tool_admission(&mut admission, &request)?
                    .ok_or_else(|| invalid("caller report lost original finalization"));
            }
            let mut context = self.restore_caller_return_context(&admission, &frame, now)?;
            context.caller_delivery_evidence =
                Some(Box::new(crate::caller_delivery::CallerDeliveryEvidenceV1 {
                    authorization: authorization.clone(),
                    report: report.clone(),
                }));
            context.admitted_metadata = merge_metadata_objects(
                context.admitted_metadata,
                Some(serde_json::json!({"caller_delivery": {
                    "schema": "chio.authenticated-caller-observation.v1",
                    "report_digest": digest,
                    "authorization_digest": report.report.authorization_digest,
                    "executor": report.report.executor,
                    "claim_id": report.report.claim_id,
                    "execution_started_at_unix_ms": report.report.execution_started_at_unix_ms,
                    "completed_at_unix_ms": report.report.completed_at_unix_ms
                }})),
            );
            let output = ToolServerOutput::Value(report.report.output.clone());
            let returned = self.record_durable_tool_return(
                &mut admission,
                DurableToolReturnInput {
                    request: &request,
                    output: &output,
                    context: &context,
                    reported_cost: report.report.realized_cost.as_ref().map(|cost| {
                        ToolInvocationCost {
                            units: cost.units,
                            currency: cost.currency.clone(),
                            breakdown: None,
                        }
                    }),
                    elapsed: Duration::from_millis(
                        report.report.completed_at_unix_ms
                            - report.report.execution_started_at_unix_ms,
                    ),
                    trusted_now_unix_ms: now,
                },
            )?;
            self.reach_durable_finalization_cutpoint(
                DurableFinalizationCutpoint::ToolReturnRecorded,
            );
            self.finalize_durable_tool_return(&mut admission, &request, &returned)
        })
    }
}
