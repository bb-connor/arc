//! Finalizing-operation-owned output taint, not input replay or release authority.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityOutputJoinRecordV1, NativeSecurityOutputJoinRequestV1,
};
use chio_security_types::ports::{BoundedVec, FlowJoinRequest, FlowStateSnapshot};

mod contract;
mod declassification;
#[cfg(feature = "admission-test-support")]
mod faults;
#[cfg(feature = "admission-test-support")]
pub use faults::NativeOutputJoinTestFault;
mod integrity;
#[cfg(feature = "admission-test-support")]
mod legacy_test;
mod record;
mod schema;
mod write;
pub(super) use integrity::verify_coverage;
pub(super) use record::{head, load, load_operation, Record};
pub(in crate::admission_operation_store) use schema::{exists, sql, verify_catalog};

const PROJECTION: &str = "security_participant_output";
const MUTATION: &str = "join_security_participant_output";

/// Read authenticated captured output taint inside an existing fenced
/// transaction. No current classification or new output join is selected.
pub(in crate::admission_operation_store) fn captured_output(
    tx: &Connection,
    operation: &AdmissionOperationId,
) -> Result<NativeSecurityOutputJoinRecordV1, AdmissionOperationStoreError> {
    let record = load_operation(tx, operation)?
        .ok_or_else(|| invalid("recovery captured output taint is absent"))?;
    record.validate(tx)?;
    let initialized = super::records::load_metadata(tx, record.authority.as_str())?
        .ok_or_else(|| invalid("recovery captured output initialization is absent"))?;
    record.evidence(&initialized)
}

/// Minted only after validating finalization custody inside the writer's
/// transaction. It enables the closed monotone row policy and, when selected,
/// the original use outcome. It cannot mutate the input journal or admit work.
pub(crate) struct NativeOutputJoinAuthority {
    authority: AdmissionIdentifier,
    request: FlowJoinRequest,
    declassification: Option<Box<crate::security_state::NativeDeclassificationOutcome>>,
}

impl NativeOutputJoinAuthority {
    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }
    pub(crate) fn request(&self) -> &FlowJoinRequest {
        &self.request
    }
    pub(crate) fn declassification(
        &self,
    ) -> Option<&crate::security_state::NativeDeclassificationOutcome> {
        self.declassification.as_deref()
    }
}

pub(crate) fn projection_reference(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    load(connection, authority, sequence)
        .map_err(map_integrity)?
        .ok_or_else(|| map_integrity("native output reference is absent"))?
        .digest()
        .map_err(map_integrity)
}

fn map_integrity(error: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("native output integrity: {error}"))
}

fn checkpoint(connection: &Connection, stage: u8) -> Result<(), AdmissionOperationStoreError> {
    super::cutpoint(stage)?;
    #[cfg(feature = "admission-test-support")]
    faults::check(connection, stage)?;
    #[cfg(not(feature = "admission-test-support"))]
    let _ = connection;
    Ok(())
}
