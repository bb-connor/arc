//! Distinct intents share the same fenced writer, not each other's replay.
use super::*;
use chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1;
use chio_security_types::ports::{FlowStateKey, RecordId};

pub(super) enum Command<'a> {
    Raw(&'a FlowJoinRequest),
    Input(&'a NativeSecurityInputJoinRequestV1),
}

impl Command<'_> {
    pub(super) fn key(&self) -> &FlowStateKey {
        match self {
            Self::Raw(request) => &request.key,
            Self::Input(input) => input.key(),
        }
    }

    pub(super) fn transition_id(&self) -> &RecordId {
        match self {
            Self::Raw(request) => &request.transition_id,
            Self::Input(input) => input.transition_id(),
        }
    }

    pub(super) fn input(&self) -> Option<&NativeSecurityInputJoinRequestV1> {
        match self {
            Self::Raw(_) => None,
            Self::Input(input) => Some(input),
        }
    }

    pub(super) fn validate(
        &self,
        operation: &AdmissionOperationId,
    ) -> Result<(), AdmissionOperationStoreError> {
        match self {
            Self::Raw(_) => Ok(()),
            Self::Input(input) => input.validate(operation),
        }
    }

    pub(super) fn matches(&self, record: &history::Record) -> bool {
        match self {
            Self::Raw(request) => record.input.is_none() && record.request == **request,
            Self::Input(input) => record.input.as_ref() == Some(*input),
        }
    }

    pub(super) fn resolve(
        &self,
        tx: &rusqlite::Transaction<'_>,
        authority: &str,
    ) -> Result<FlowJoinRequest, AdmissionOperationStoreError> {
        match self {
            Self::Raw(request) => Ok((*request).clone()),
            Self::Input(input) => {
                crate::security_state::resolve_native_input_join(tx, authority, input)
                    .map_err(invalid)
            }
        }
    }
}
