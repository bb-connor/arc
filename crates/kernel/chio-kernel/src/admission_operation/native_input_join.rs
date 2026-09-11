//! Classified-input intent and historical full-source join evidence.

use super::{
    canonical_json_bytes, sha256_hex, AdmissionOperationId, AdmissionOperationStoreError,
    NativeSecurityFlowJoinRecordV1,
};
use chio_security_types::ports::{FlowJoinRequest, FlowStateKey, FlowStateSnapshot, RecordId};
use chio_security_types::InformationLabel;
use serde::{Deserialize, Serialize};

/// Data only. The operation, selected authority and actual lease must still be
/// checked by the writer. The input label includes classification and the
/// operator floor, not a caller's estimate of inherited native state.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSecurityInputJoinRequestV1 {
    operation_id: AdmissionOperationId,
    key: FlowStateKey,
    input_label: InformationLabel,
    transition_id: RecordId,
}

/// The original input intent and its resolved monotone join. Neither this
/// historical result nor a deserialized input request grants mutation authority.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityInputJoinRecordV1 {
    pub input: NativeSecurityInputJoinRequestV1,
    pub join: NativeSecurityFlowJoinRecordV1,
}

impl NativeSecurityInputJoinRequestV1 {
    pub fn new(
        operation_id: AdmissionOperationId,
        key: FlowStateKey,
        input_label: InformationLabel,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let transition_id = transition_id(&operation_id, &key, &input_label)?;
        Ok(Self {
            operation_id,
            key,
            input_label,
            transition_id,
        })
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }
    pub fn key(&self) -> &FlowStateKey {
        &self.key
    }
    pub fn input_label(&self) -> &InformationLabel {
        &self.input_label
    }
    pub fn transition_id(&self) -> &RecordId {
        &self.transition_id
    }

    pub fn validate(
        &self,
        operation: &AdmissionOperationId,
    ) -> Result<(), AdmissionOperationStoreError> {
        if &self.operation_id != operation
            || self.transition_id != transition_id(operation, &self.key, &self.input_label)?
        {
            return Err(invalid("native input join intent binding differs"));
        }
        Ok(())
    }

    /// Verify data relationships, not freshness, authenticity or store custody.
    /// The physical writer must derive the exact complete source under its own
    /// transaction. Independent readback binds the acknowledgement to that event.
    pub fn validate_resolution(
        &self,
        operation: &AdmissionOperationId,
        command: &FlowJoinRequest,
        snapshot: &FlowStateSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate(operation)?;
        let source = &command.principal_join;
        if command.key != self.key
            || command.transition_id != self.transition_id
            || &command.lineage_join != source
            || &command.session_join != source
            || snapshot.key != self.key
            || &snapshot.principal_label != source
            || &snapshot.lineage_label != source
            || &snapshot.session_label != source
            || snapshot.context_generation == 0
            || snapshot.context_generation > super::I_JSON_MAX_SAFE_INTEGER
            || self
                .input_label
                .join_restrictions(source)
                .map_err(invalid)?
                != *source
        {
            return Err(invalid(
                "native input join did not propagate its complete source",
            ));
        }
        Ok(())
    }
}

impl NativeSecurityInputJoinRecordV1 {
    pub fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        self.input.validate_resolution(
            &self.join.operation_id,
            &self.join.command,
            &self.join.snapshot,
        )
    }
}

impl std::fmt::Debug for NativeSecurityInputJoinRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityInputJoinRequestV1")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeSecurityInputJoinRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityInputJoinRecordV1")
            .finish_non_exhaustive()
    }
}

fn transition_id(
    operation: &AdmissionOperationId,
    key: &FlowStateKey,
    input: &InformationLabel,
) -> Result<RecordId, AdmissionOperationStoreError> {
    let mut bytes = b"chio.native-security-input-join-request.v1\0".to_vec();
    bytes.extend(canonical_json_bytes(&(operation, key, input)).map_err(invalid)?);
    RecordId::new(format!("native-input:{}", sha256_hex(&bytes))).map_err(invalid)
}

fn invalid(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}

#[cfg(test)]
mod tests;
