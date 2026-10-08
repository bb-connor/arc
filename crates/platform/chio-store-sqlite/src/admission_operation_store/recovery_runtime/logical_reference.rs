//! Closed logical reference ownership. Physical finishing credits are separate.
use super::*;
use crate::admission_operation_store::knowledge::reference_census::VerifiedKnowledgeReferenceAccountBaseline;
use crate::admission_operation_store::knowledge::reference_ready::VerifiedKnowledgeReferenceReady;
use crate::admission_operation_store::knowledge::reference_source::ReferenceCutoff;
use crate::admission_operation_store::knowledge::references::{
    aggregate_key, ready_reference_account, reference_identity, PreparedColdReferenceBaseline,
    PreparedReferenceUpdates, ProductEvidenceOwner, ReadyReferenceAccount, ReferenceAccount,
    ReferenceOwner, ReferenceReadyRecord, StagedReferenceUpdate,
};
use crate::admission_operation_store::product::reference_intake::VerifiedProductReferenceIntake;
use chio_security_types::knowledge::ArtifactVersionRefV1;
use std::ops::Deref;

#[path = "logical_reference/reference_capacity.rs"]
mod reference_capacity;
#[path = "logical_reference/reference_cold.rs"]
mod reference_cold;
#[path = "logical_reference/reference_knowledge.rs"]
mod reference_knowledge;
#[path = "logical_reference/reference_product.rs"]
mod reference_product;

use reference_capacity::{
    load_capacity, load_capacity_account, require_ready_capacity, save_capacity, ReferenceCapacity,
};
pub(in crate::admission_operation_store) use reference_cold::{
    initialize_knowledge_reference_account, persist_knowledge_new_artifact_reference_baseline,
    persist_knowledge_reference_cold_baseline, persist_knowledge_reference_ready,
    VerifiedKnowledgeReferenceColdProgress,
};
pub(in crate::admission_operation_store) use reference_knowledge::{
    persist_knowledge_reference_retain, persist_knowledge_reference_retirement,
    persist_product_reference_retirement,
};
pub(in crate::admission_operation_store) use reference_product::{
    bind_product_reference_source, persist_knowledge_reference_progress,
    reserve_product_reference_intake, ReservedProductReferenceIntake, VerifiedParticipantAllowance,
};

const ACCOUNT_RECORD_BYTES: usize = 4096;
const ORDINARY_REFERENCE_BYTES: usize = 16384;
const MAX_ACTIVE_REFERENCE_OWNERS: u64 = 4096;

fn require_reference_format(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let revision: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION < 40
        || revision != Some(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    {
        return Err(invariant(
            "logical references require the current serving format",
        ));
    }
    Ok(())
}

fn same_writer(
    expected: &Transaction<'_>,
    actual: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    if !std::ptr::eq::<Connection>(Deref::deref(expected), Deref::deref(actual)) {
        return Err(invariant("reference allowance changed its physical writer"));
    }
    Ok(())
}

fn same_source(left: &ProtectedSourceReference, right: &ProtectedSourceReference) -> bool {
    left.record_key() == right.record_key()
        && left.scope_key() == right.scope_key()
        && left.kind() == right.kind()
        && left.version() == right.version()
        && left.digest() == right.digest()
        && left.event_sequence() == right.event_sequence()
        && left.global_commit_sequence() == right.global_commit_sequence()
}

fn ordinary_header(tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
    let ordinary: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !ordinary {
        return Err(invariant("reference metadata acquired a native request"));
    }
    Ok(())
}

fn persist_update(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    write: &StagedReferenceUpdate,
    maximum_payload: usize,
) -> Result<ProtectedSourceReference, AdmissionOperationStoreError> {
    if write.key().is_empty()
        || write.payload().is_empty()
        || write.payload().len() > maximum_payload
        || write.version()
            != write
                .expected_version()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| invariant("reference version exhausted"))?
    {
        return Err(invariant(
            "reference staged write exceeds its closed envelope",
        ));
    }
    let _: serde_json::Value = decode(write.payload())?;
    match raw_checked(tx, write.key())? {
        Some(row) => {
            let source = source_reference(tx, write.key())?;
            ordinary_header(tx, write.key())?;
            if Some(row.version) != write.expected_version()
                || row.scope != write.scope()
                || row.kind != "command"
                || source.version() != row.version
            {
                return Err(invariant("reference staged write lost its current head"));
            }
        }
        None if write.expected_version().is_some() => {
            return Err(invariant("reference staged head disappeared"));
        }
        None => {}
    }
    persist_record(
        tx,
        owner,
        write.key(),
        write.scope(),
        "command",
        write.payload(),
        None,
    )?;
    let source = source_reference(tx, write.key())?;
    if source.version() != write.version() || source.scope_key() != write.scope() {
        return Err(invariant("reference staged writer changed its exact frame"));
    }
    Ok(source)
}

#[derive(Clone, Eq, PartialEq)]
struct GlobalHead {
    sequence: u64,
    digest: [u8; 32],
}

fn global_head(tx: &Connection) -> Result<GlobalHead, AdmissionOperationStoreError> {
    let (sequence, digest): (i64, String) = tx
        .query_row(
            "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    let sequence = stored_u64(sequence, "reference global head")?;
    let digest: [u8; 32] = hex::decode(digest)
        .map_err(|_| invariant("reference global digest is corrupt"))?
        .try_into()
        .map_err(|_| invariant("reference global digest is corrupt"))?;
    let retained: Option<String> = tx
        .query_row(
            "SELECT chain_digest FROM authority_global_commits WHERE commit_sequence=?1",
            [
                i64::try_from(sequence)
                    .map_err(|_| invariant("reference global head exhausted"))?,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if sequence == 0 || retained.as_deref() != Some(hex::encode(digest).as_str()) {
        return Err(invariant("reference global head lost retained custody"));
    }
    Ok(GlobalHead { sequence, digest })
}

fn same_account(scope: &RecoveryScopeV1, other: &RecoveryScopeV1) -> bool {
    scope.authority_domain == other.authority_domain && scope.tenant_id == other.tenant_id
}
