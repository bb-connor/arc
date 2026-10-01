//! Nonce preflight has distinct intent, journal and live authority from dispatch.
use super::native_input_join::InputJoinPhase;
use super::{
    AdmissionOperationId, AdmissionOperationStoreError, NativeSecurityFlowJoinRecordV1,
    NativeSecurityInputJoinRequestV1,
};
use chio_security_types::ports::{FlowJoinRequest, FlowStateKey, FlowStateSnapshot, RecordId};
use chio_security_types::InformationLabel;
use serde::{Deserialize, Serialize};

/// Data only. The physical writer must require the original strict nonce
/// operation in Prepared, its selected native authority and current lease.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeSecurityNoncePreflightJoinRequestV1(NativeSecurityInputJoinRequestV1);

#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityNoncePreflightJoinRecordV1 {
    pub input: NativeSecurityNoncePreflightJoinRequestV1,
    pub join: NativeSecurityFlowJoinRecordV1,
}

impl NativeSecurityNoncePreflightJoinRequestV1 {
    pub fn new(
        operation_id: AdmissionOperationId,
        key: FlowStateKey,
        input_label: InformationLabel,
    ) -> Result<Self, AdmissionOperationStoreError> {
        NativeSecurityInputJoinRequestV1::for_phase(
            operation_id,
            key,
            input_label,
            InputJoinPhase::NoncePreflight,
        )
        .map(Self)
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        self.0.operation_id()
    }
    pub fn key(&self) -> &FlowStateKey {
        self.0.key()
    }
    pub fn input_label(&self) -> &InformationLabel {
        self.0.input_label()
    }
    pub fn transition_id(&self) -> &RecordId {
        self.0.transition_id()
    }
    pub fn validate(
        &self,
        operation: &AdmissionOperationId,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.0
            .validate_phase(operation, InputJoinPhase::NoncePreflight)
    }
    pub fn validate_resolution(
        &self,
        operation: &AdmissionOperationId,
        command: &FlowJoinRequest,
        snapshot: &FlowStateSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.0.validate_phase_resolution(
            operation,
            command,
            snapshot,
            InputJoinPhase::NoncePreflight,
        )
    }
}

impl NativeSecurityNoncePreflightJoinRecordV1 {
    pub fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        self.input.validate_resolution(
            &self.join.operation_id,
            &self.join.command,
            &self.join.snapshot,
        )
    }
}

impl std::fmt::Debug for NativeSecurityNoncePreflightJoinRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityNoncePreflightJoinRequestV1")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeSecurityNoncePreflightJoinRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityNoncePreflightJoinRecordV1")
            .finish_non_exhaustive()
    }
}
