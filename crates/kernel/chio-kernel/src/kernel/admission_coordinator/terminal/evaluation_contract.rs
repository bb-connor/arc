//! Reconstruct the recorded evaluation contract without granting redispatch authority.

use super::*;

impl ChioKernel {
    /// The frozen evaluation facts every durable terminal pass re-derives
    /// from the recorded request: the selected grant, the frozen
    /// post-return plan, the normalized replay context, the committed
    /// output digest, and the purchase binding for a marked reveal.
    pub(super) fn durable_evaluation_contract(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<DurableEvaluationContract, KernelError> {
        let matched_grant_index = raw.matched_grant_index().map_err(tool_outcome_error)?;
        let matching_grants = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let plan = self.durable_post_return_plan()?;
        // Raw outcome context is committed historical data for finalization,
        // never a source of authority for a new invocation or redispatch.
        let security_binding =
            self.admission_security_binding(raw.security_invocation_context())?;
        let recovered_request_hash = immutable_tool_admission_request_hash(
            request,
            &matching_grants,
            &plan,
            security_binding.as_ref(),
            admission
                .retained_request
                .as_ref()
                .and_then(|original| original.authority_profile()),
        )?;
        if &recovered_request_hash != admission.operation.binding().immutable_request_hash() {
            return Err(KernelError::DurableAdmission(
                "recovered post-return plan does not match durable admission".to_owned(),
            ));
        }
        if let Some(reason) =
            crate::kernel::evaluation::evaluation_helpers::delivery_marked_selection_denial(
                &matching_grants,
                matched_grant_index,
            )
        {
            return Err(KernelError::DurableAdmission(format!(
                "recorded delivery contract is invalid: {reason}"
            )));
        }
        let Some(selected_grant) = matching_grants.iter().find(|matching| {
            matching.index == matched_grant_index && admission.permits_matching_grant(matching)
        }) else {
            return Err(KernelError::DurableAdmission(
                "recorded tool return does not match the captured grant".to_owned(),
            ));
        };
        // The expected output digest is frozen: the whole matching-grant
        // set is covered by the durable binding's immutable_request_hash
        // (revalidated above) and the selected index by the raw blob, so
        // this reads the same digest the grant fixed at admission. The
        // selection-cardinality rule guarantees at most one.
        let mut expected_output_digest = None;
        for constraint in &selected_grant.grant.constraints {
            if let Constraint::OutputDigestSha256(digest) = constraint {
                if expected_output_digest.replace(digest.clone()).is_some() {
                    return Err(KernelError::DurableAdmission(
                        "selected grant carries more than one output digest constraint".to_owned(),
                    ));
                }
            }
        }
        let stream_limits = raw.stream_limits();
        let normalized_context = PostReturnNormalizedRequestContextV1::from_verified_normalization(
            serde_json::to_value(KernelPostReturnContext {
                schema: "chio.kernel-post-return-context.v1",
                request_binding_hash: admission
                    .operation
                    .binding()
                    .request_binding_hash()
                    .as_str(),
                matched_grant_index,
                elapsed_millis: raw.elapsed_millis(),
                max_stream_total_bytes: stream_limits.max_total_bytes,
                max_stream_chunks: stream_limits.max_chunks,
                max_stream_duration_secs: stream_limits.max_duration_secs,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        )
        .map_err(tool_outcome_error)?;
        // The purchase binding was verified when the authenticated raw tool
        // return was recorded. Reuse that frozen result so a later
        // status-operator rotation cannot strand an already-dispatched
        // operation. The raw outcome and immutable request hash bind the
        // snapshot to this exact request.
        let purchase = self.restore_purchase_replay_snapshot(
            selected_grant.grant,
            request,
            raw.receipt_metadata_snapshot(),
        )?;
        let recovery_snapshot = self.restore_recovery_replay_snapshot(
            selected_grant.grant,
            request,
            raw.receipt_metadata_snapshot(),
        )?;
        let (recovery, recovery_status) = recovery_snapshot.map_or((None, None), |admission| {
            (Some(admission.recovery), Some(admission.status))
        });
        Ok(DurableEvaluationContract {
            matched_grant_index,
            plan,
            normalized_context,
            expected_output_digest,
            purchase,
            recovery,
            recovery_status,
        })
    }
}
