//! Native egress has its own closed journal and operation-owned row policy.
//! It is not activation, declassification authority, or permission to dispatch.
use super::*;
use crate::security_state::{NativeEgressCommand, NativeEgressResult};
use chio_kernel::{SecurityInvocationContext, ToolCallRequest};
use chio_security_types::ports::{
    BoundedVec, CommittedEgressFence, EgressFence, EgressFenceCommit, EgressFenceRequest,
};

mod contract;
pub(super) use contract::live_request_hash;
mod integrity;
mod readback;
mod record;
pub(super) use readback::load_history;
pub use readback::SecurityParticipantEgressHistory;
mod schema;
mod write;
pub(super) use integrity::verify_coverage;
pub(super) use record::{head, load, load_operation, Record};
pub(in crate::admission_operation_store) use schema::{exists, sql, verify_catalog};

pub(super) const PROJECTION: &str = "security_participant_egress";

pub(crate) struct NativeEgressAuthority {
    authority: AdmissionIdentifier,
    command: NativeEgressCommand,
}

impl NativeEgressAuthority {
    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }
    pub(crate) fn command(&self) -> &NativeEgressCommand {
        &self.command
    }
}

pub(crate) fn projection_reference(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    load(connection, authority, sequence)
        .map_err(map_integrity)?
        .ok_or_else(|| map_integrity("native egress reference is absent"))?
        .digest()
        .map_err(map_integrity)
}

fn map_integrity(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("native egress integrity: {detail}"))
}
