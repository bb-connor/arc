//! Output taint intent, separate from the pre-dispatch input journal.
use super::*;
use crate::tool_outcome::{
    PostReturnEvaluationRecordV1, PostReturnEvaluationStateV1, ToolOutcomeRecordV1,
};
use chio_security_types::ports::{FlowJoinRequest, FlowStateKey, FlowStateSnapshot, RecordId};
use chio_security_types::InformationLabel;

/// Data only. Classification must inspect the actual post-guard payload, not
/// the signing preimage (which contains hashes for streams). The writer checks
/// original native capture, physical outcome/evaluation, current flow state and
/// the actual operation lease before enabling its monotone mutation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSecurityOutputJoinRequestV1 {
    operation_id: AdmissionOperationId,
    key: FlowStateKey,
    observed_generation: u64,
    output_label: InformationLabel,
    outcome_digest: AdmissionDigest,
    evaluation_digest: AdmissionDigest,
    transition_id: RecordId,
}

/// Historical acknowledgement. It cannot recreate a live release owner.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityOutputJoinRecordV1 {
    pub output: NativeSecurityOutputJoinRequestV1,
    pub join: NativeSecurityFlowJoinRecordV1,
}

impl std::fmt::Debug for NativeSecurityOutputJoinRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityOutputJoinRecordV1")
            .finish_non_exhaustive()
    }
}

impl NativeSecurityOutputJoinRequestV1 {
    pub fn new(
        operation: &AdmissionOperationV1,
        observation: &NativeSecurityFlowObservationV1,
        output_label: InformationLabel,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let observed_generation = observation
            .stored_context_generation()
            .ok_or_else(|| invalid("native output requires an existing flow context"))?;
        let mut intent = Self {
            operation_id: operation.binding().operation_id().clone(),
            key: observation.key().clone(),
            observed_generation,
            output_label,
            outcome_digest: digest(&outcome.to_persisted())?,
            evaluation_digest: digest(&evaluation.to_persisted())?,
            transition_id: RecordId::new("uninitialized-output-intent").map_err(invalid)?,
        };
        intent.transition_id = intent.expected_transition()?;
        intent.validate_artifacts(operation, outcome, evaluation)?;
        Ok(intent)
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }
    pub fn key(&self) -> &FlowStateKey {
        &self.key
    }
    pub fn observed_generation(&self) -> u64 {
        self.observed_generation
    }
    pub fn output_label(&self) -> &InformationLabel {
        &self.output_label
    }
    pub fn transition_id(&self) -> &RecordId {
        &self.transition_id
    }

    pub fn validate_artifacts(
        &self,
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        operation.validate()?;
        outcome.validate_against(operation).map_err(invalid)?;
        evaluation
            .validate_against(operation, outcome)
            .map_err(invalid)?;
        if operation.state() != AdmissionOperationState::Finalizing
            || operation.native_dispatch_ledger_digest().is_none()
            || operation.binding().operation_id() != &self.operation_id
            || self.observed_generation == 0
            || self.observed_generation > I_JSON_MAX_SAFE_INTEGER
            || !matches!(
                evaluation.state(),
                PostReturnEvaluationStateV1::Resolved { .. }
            )
            || outcome.resolved_output_ref().is_none()
            || self.outcome_digest != digest(&outcome.to_persisted())?
            || self.evaluation_digest != digest(&evaluation.to_persisted())?
            || self.transition_id != self.expected_transition()?
        {
            return Err(invalid(
                "native output intent differs from captured finalization",
            ));
        }
        Ok(())
    }

    pub fn validate_resolution(
        &self,
        command: &FlowJoinRequest,
        snapshot: &FlowStateSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        let source = &command.principal_join;
        if command.key != self.key
            || command.transition_id != self.transition_id
            || &command.lineage_join != source
            || &command.session_join != source
            || snapshot.key != self.key
            || &snapshot.principal_label != source
            || &snapshot.lineage_label != source
            || &snapshot.session_label != source
            || snapshot.context_generation <= self.observed_generation
            || snapshot.context_generation > I_JSON_MAX_SAFE_INTEGER
            || self
                .output_label
                .join_restrictions(source)
                .map_err(invalid)?
                != *source
        {
            return Err(invalid(
                "native output did not propagate its complete source",
            ));
        }
        Ok(())
    }

    fn expected_transition(&self) -> Result<RecordId, AdmissionOperationStoreError> {
        let mut bytes = b"chio.native-security-output-join-request.v1\0".to_vec();
        bytes.extend(
            canonical_json_bytes(&(
                &self.operation_id,
                &self.key,
                self.observed_generation,
                &self.output_label,
                &self.outcome_digest,
                &self.evaluation_digest,
            ))
            .map_err(invalid)?,
        );
        RecordId::new(format!("native-output:{}", sha256_hex(&bytes))).map_err(invalid)
    }
}

impl std::fmt::Debug for NativeSecurityOutputJoinRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityOutputJoinRequestV1")
            .finish_non_exhaustive()
    }
}

fn digest(value: &impl Serialize) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    AdmissionDigest::try_new(
        "native_output_artifact",
        sha256_hex(&canonical_json_bytes(value).map_err(invalid)?),
    )
    .map_err(Into::into)
}

fn invalid(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}
