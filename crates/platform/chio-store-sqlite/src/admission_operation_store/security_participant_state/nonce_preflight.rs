//! Prepared-operation-owned nonce preflight taint, never dispatch authority.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityNoncePreflightJoinRecordV1, NativeSecurityNoncePreflightJoinRequestV1,
};
use chio_security_types::ports::{BoundedVec, FlowJoinRequest, FlowStateSnapshot};

mod contract;
mod integrity;
mod issuance;
mod record;
mod schema;
mod write;
pub(super) use integrity::verify_coverage;
pub(in crate::admission_operation_store) use issuance::require_preflight_for_issuance;
pub(super) use record::{head, load, load_operation, Record};
pub(in crate::admission_operation_store) use schema::{exists, sql, verify_catalog};

const PROJECTION: &str = "security_participant_nonce_preflight";
const MUTATION: &str = "join_security_participant_nonce_preflight";

/// Minted only after validating strict nonce preflight custody inside the writer's
/// transaction. It enables the same closed monotone row policy as an input
/// join, but never the input journal or its pre-dispatch admission contract.
pub(crate) struct NativeNoncePreflightJoinAuthority {
    authority: AdmissionIdentifier,
    request: FlowJoinRequest,
}

impl NativeNoncePreflightJoinAuthority {
    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }
    pub(crate) fn request(&self) -> &FlowJoinRequest {
        &self.request
    }
}

pub(crate) fn projection_reference(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    load(connection, authority, sequence)
        .map_err(map_integrity)?
        .ok_or_else(|| map_integrity("native nonce preflight reference is absent"))?
        .digest()
        .map_err(map_integrity)
}

fn map_integrity(error: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("native nonce preflight integrity: {error}"))
}

fn checkpoint(connection: &Connection, stage: u8) -> Result<(), AdmissionOperationStoreError> {
    super::cutpoint(stage)?;
    let _ = connection;
    Ok(())
}
