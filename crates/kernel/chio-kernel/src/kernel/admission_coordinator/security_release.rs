//! Release checkpoints are neither output evaluation nor fresh dispatch authority.
//! Live callbacks run outside the mutation sequencer; fenced persistence resumes
//! only after the callback has completed and its owner has been consumed.

use super::*;
use crate::admission_operation::AdmissionRecoveryLease;
use crate::tool_outcome::{
    AcknowledgedSecurityReleaseV1, SecurityReleaseArtifacts, SecurityReleaseRecordV1,
};

#[path = "security_release/native_caller.rs"]
mod native_caller;

pub(super) struct DurableSecurityReleaseInput<'a> {
    pub admission: &'a DurableToolAdmission,
    pub raw: &'a RawInvocationOutcomeV1,
    pub outcome: &'a ToolOutcomeRecordV1,
    pub evaluation: &'a PostReturnEvaluationRecordV1,
    pub output: &'a ToolCallOutput,
    pub resolved_output: &'a [u8],
    pub lease: &'a AdmissionRecoveryLease,
    pub trusted_now_unix_ms: u64,
}

fn recovery_required(error: impl std::fmt::Display) -> KernelError {
    KernelError::SecurityDispatchOutcomeRecoveryRequired(format!(
        "durable security release requires authoritative recovery: {error}"
    ))
}

impl ChioKernel {
    pub(super) fn verify_durable_security_release(
        &self,
        admission: &DurableToolAdmission,
        raw: &RawInvocationOutcomeV1,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<Option<SecurityReleaseRecordV1>, KernelError> {
        if !raw.requires_security_release().map_err(recovery_required)? {
            return Ok(None);
        }
        let record = self
            .durable_runtime()?
            .outcome_store
            .lookup_security_release(admission.operation.binding().operation_id())
            .map_err(recovery_required)?;
        if let Some(record) = &record {
            record
                .validate_against(&admission.operation, raw, outcome, evaluation)
                .map_err(recovery_required)?;
        }
        Ok(record)
    }

    pub(super) fn require_durable_security_release(
        &self,
        admission: &DurableToolAdmission,
        raw: &RawInvocationOutcomeV1,
        outcome: &ToolOutcomeRecordV1,
    ) -> Result<(), KernelError> {
        if !raw.requires_security_release().map_err(recovery_required)? {
            return Ok(());
        }
        let evaluation = self
            .durable_runtime()?
            .outcome_store
            .lookup_post_return_evaluation(admission.operation.binding().operation_id())
            .map_err(recovery_required)?
            .ok_or_else(|| recovery_required("release evaluation is absent"))?;
        self.verify_durable_security_release(admission, raw, outcome, &evaluation)?
            .ok_or_else(|| recovery_required("release checkpoint is absent"))?;
        Ok(())
    }

    pub(super) fn complete_durable_security_release(
        &self,
        input: DurableSecurityReleaseInput<'_>,
        permit: Option<SecurityRequestLifecycleHandle>,
    ) -> Result<(), KernelError> {
        let required = input
            .raw
            .requires_security_release()
            .map_err(recovery_required)?;
        if !required {
            return if permit.is_none() {
                Ok(())
            } else {
                Err(recovery_required(
                    "live owner was omitted from the frozen requirement",
                ))
            };
        }
        if self
            .verify_durable_security_release(
                input.admission,
                input.raw,
                input.outcome,
                input.evaluation,
            )?
            .is_some()
        {
            return if permit.is_none() {
                Ok(())
            } else {
                Err(recovery_required(
                    "a checkpoint cannot retire another live owner",
                ))
            };
        }
        let permit = match permit {
            Some(permit) => Some(permit),
            None => self.recover_native_caller_release_owner(input.admission, input.raw)?,
        }
        .ok_or_else(|| {
            recovery_required(
                "the original release owner is unavailable; fresh admission cannot replace it",
            )
        })?;
        let runtime = self.durable_runtime()?;
        let acknowledged = AcknowledgedSecurityReleaseV1::acknowledge(
            permit,
            SecurityReleaseArtifacts {
                operation: &input.admission.operation,
                raw: input.raw,
                outcome: input.outcome,
                evaluation: input.evaluation,
                output: input.output,
                resolved_output: input.resolved_output,
            },
            runtime.fence.clone(),
            input.trusted_now_unix_ms,
            |context| self.prepare_durable_native_output(input.admission, input.lease, context),
        )?;
        self.reach_durable_finalization_cutpoint(
            DurableFinalizationCutpoint::SecurityReleaseAcknowledged,
        );
        let _guard = runtime.lock_mutations()?;
        // Do not renew or replace the original operation lease after an
        // unlocked callback. The physical checkpoint write must reject an
        // expired lease, a changed owner, or substituted finalization records.
        let recorded = runtime
            .outcome_store
            .record_security_release(&acknowledged, input.lease)
            .map_err(recovery_required)?;
        if &recorded != acknowledged.record() {
            return Err(recovery_required(
                "checkpoint acknowledgement changed its binding",
            ));
        }
        let readback = self
            .verify_durable_security_release(
                input.admission,
                input.raw,
                input.outcome,
                input.evaluation,
            )?
            .ok_or_else(|| recovery_required("acknowledged checkpoint is absent"))?;
        if readback != recorded {
            return Err(recovery_required("checkpoint readback changed its binding"));
        }
        self.reach_durable_finalization_cutpoint(
            DurableFinalizationCutpoint::SecurityReleaseCheckpointed,
        );
        Ok(())
    }
}
