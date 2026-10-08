//! Permanent original provenance and the independently fenced current owner.
use super::*;
use crate::serving_owner::NativeSourceTransactionOrigin;
use chio_core::recovery::RecoveryDigestDomain;
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "original_owner/predecessor_absence_tests.rs"]
mod predecessor_absence_tests;

#[path = "original_owner/creation.rs"]
mod creation;
#[path = "original_owner/history.rs"]
mod history;
#[path = "original_owner/no_future_admission.rs"]
mod no_future_admission;
#[path = "original_owner/unused_setup_generation.rs"]
mod unused_setup_generation;

pub(in crate::admission_operation_store) use creation::{
    prepare_original_owner_creation, publish_original_owner_creation,
    seal_original_owner_predecessor,
};
pub(in crate::admission_operation_store) use history::{
    original_owner_is_current, persist_original_owner_cohort, prepare_original_owner_cohort,
    require_current_original_owner, verify_original_owner_inventory,
    verify_original_owner_membership, VerifiedOriginalOwnerCohort, VerifiedOriginalOwnerInventory,
};
pub(in crate::admission_operation_store) use no_future_admission::AuthenticatedNoFutureNativeAdmission;
pub(in crate::admission_operation_store) use unused_setup_generation::{
    retire_unused_setup_generation_with_origin, verify_unused_setup_generation_inventory,
    UNUSED_SETUP_GENERATION_SQL,
};

const MAX_OWNER_BYTES: usize = 4096;
pub(in crate::admission_operation_store) const ORIGINAL_OWNER_SQL: &str =
    "CREATE INDEX admission_operation_recovery_original_owner ON admission_operation_recovery_records(record_key) WHERE kind='command' AND record_key GLOB 'recovery-original-owner:*';
     CREATE UNIQUE INDEX admission_operation_recovery_original_transfer ON admission_operation_recovery_records(scope_key,json_extract(CAST(payload AS TEXT),'$.successor.workflow_id')) WHERE kind='command' AND record_key GLOB 'recovery-original-transfer:*';
     CREATE INDEX admission_operation_recovery_original_tombstone ON admission_operation_recovery_records(record_key) WHERE kind='command' AND record_key GLOB 'recovery-original-tombstone:*';";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceVersion {
    version: SafeInteger,
    digest: ProjectionDigest,
    event_sequence: SafeInteger,
    global_commit_sequence: SafeInteger,
}

impl SourceVersion {
    fn capture(source: &ProtectedSourceReference) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            version: safe(source.version())?,
            digest: *source.digest(),
            event_sequence: safe(source.event_sequence())?,
            global_commit_sequence: safe(source.global_commit_sequence())?,
        })
    }

    fn historical(&self, tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
        let (digest, commit) = historical_record_reference(tx, key, self.version.get())?;
        let sequence: i64 = tx.query_row(
            "SELECT sequence FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
            params![key, i64::try_from(self.version.get()).map_err(|_| invariant("original owner version exhausted"))?],
            |row| row.get(0),
        ).map_err(sqlite_error)?;
        if digest != hex(self.digest.as_bytes())
            || commit != self.global_commit_sequence.get()
            || stored_u64(sequence, "original owner source event")? != self.event_sequence.get()
        {
            return Err(invariant("original owner historical source changed"));
        }
        Ok(())
    }

    fn current(&self, tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
        let source = source_reference(tx, key)?;
        if Self::capture(&source)? != *self {
            return Err(invariant("original owner lost its exact current source"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDescriptor {
    workflow_id: WorkflowId,
    step_id: StepId,
    continuation_id: ContinuationId,
    created_by: chio_security_types::PrincipalId,
    initial: SourceVersion,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum HeadSchema {
    #[serde(rename = "chio.recovery.original-owner-head.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerHead {
    schema: HeadSchema,
    scope: RecoveryScopeV1,
    original_claim: SourceVersion,
    initial_owner: OwnerDescriptor,
    owner_ordinal: SafeInteger,
    current_owner: OwnerDescriptor,
    last_transfer: Option<SourceVersion>,
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
enum ClosureSchema {
    #[serde(rename = "chio.recovery.original-owner-tombstone.v1")]
    V1,
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerClosure {
    schema: ClosureSchema,
    scope: RecoveryScopeV1,
    workflow_id: WorkflowId,
    original: RecoveryOriginV1,
    original_claim: SourceVersion,
    original_head: SourceVersion,
    owner_ordinal: SafeInteger,
    workflow: SourceVersion,
    quota: SourceVersion,
    allocation: SourceVersion,
    sealed_at_unix_ms: SafeInteger,
    continuation_closure: no_future_admission::ContinuationClosure,
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
enum TransferSchema {
    #[serde(rename = "chio.recovery.original-owner-transfer.v1")]
    V1,
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerTransfer {
    schema: TransferSchema,
    scope: RecoveryScopeV1,
    original_claim: SourceVersion,
    previous_head: SourceVersion,
    previous_owner_ordinal: SafeInteger,
    previous_owner: OwnerDescriptor,
    closure: SourceVersion,
    successor_owner_ordinal: SafeInteger,
    successor: OwnerDescriptor,
}

fn safe(value: u64) -> Result<SafeInteger, AdmissionOperationStoreError> {
    SafeInteger::new(value).map_err(|_| invariant("original owner ordinal exhausted"))
}

fn suffix(origin: &RecoveryOriginV1) -> Result<String, AdmissionOperationStoreError> {
    origins::claim_key(origin)?
        .strip_prefix("recovery-origin:")
        .map(str::to_owned)
        .ok_or_else(|| invariant("original owner claim namespace changed"))
}

fn head_key(origin: &RecoveryOriginV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!("recovery-original-owner:{}", suffix(origin)?))
}

fn transfer_key(
    origin: &RecoveryOriginV1,
    ordinal: u64,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "recovery-original-transfer:{}:{ordinal:016}",
        suffix(origin)?
    ))
}

fn closure_key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "recovery-original-tombstone:{}",
        sha256_hex(&encode(&(
            RecoveryDigestDomain::ParticipantOwner.name(),
            "original_owner_tombstone",
            scope,
            workflow,
        ))?)
    ))
}

fn quota_key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "workflow-quota:{}:{}",
        scope_key(scope)?,
        workflow.as_str()
    ))
}

fn allocation_key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "recovery-workflow-allocation:{}:{}",
        scope_key(scope)?,
        workflow.as_str()
    ))
}

fn descriptor(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<OwnerDescriptor, AdmissionOperationStoreError> {
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let current =
        raw_checked(tx, &key)?.ok_or_else(|| invariant("original owner workflow disappeared"))?;
    source_reference(tx, &key)?;
    if current.kind != "workflow"
        || current.scope != scope_key(&record.scope)?
        || current.version != record.revision.get()
        || current.payload != encode(record)?
    {
        return Err(invariant("original owner requires its physical workflow"));
    }
    let (digest, commit) = historical_record_reference(tx, &key, 1)?;
    let mut initial = record.clone();
    initial.seed =
        chio_core_types::recovery::decode_contract(record.creation_seed.as_str().as_bytes())
            .map_err(|_| invariant("original owner lost its pristine creation seed"))?;
    initial.revision = safe(1)?;
    initial.control = WorkflowControlV1::Active;
    initial.action = None;
    initial.process_reservation = None;
    initial.selected = false;
    initial.review = None;
    initial.approval = None;
    initial.issuance = None;
    initial.signed_grant = None;
    initial.envelope = None;
    initial.admission = None;
    initial.admission_closed = false;
    initial.native_link = None;
    initial.captured = false;
    initial.captured_deployment = None;
    initial.historical_hold = None;
    initial.effect = EffectObservationV1::NeverAdmitted;
    initial.release = ReleaseDispositionV1::NotAvailable;
    initial.original_flow = None;
    initial.reported_decision = None;
    initial.provider_finality = None;
    initial.provider_lookups = SafeInteger::ZERO;
    if record_digest(
        &key,
        &scope_key(&record.scope)?,
        "workflow",
        1,
        &encode(&initial)?,
        None,
        None,
    )? != digest
    {
        return Err(invariant(
            "original owner changed its complete immutable creation preimage",
        ));
    }
    let sequence: i64 = tx.query_row(
        "SELECT sequence FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=1",
        [&key], |row| row.get(0),
    ).map_err(sqlite_error)?;
    Ok(OwnerDescriptor {
        workflow_id: record.workflow_id.clone(),
        step_id: record.step_id.clone(),
        continuation_id: record.continuation_id.clone(),
        created_by: record.created_by.clone(),
        initial: SourceVersion {
            version: safe(1)?,
            digest: ProjectionDigest::from_bytes(native::decode_hex(&digest)?),
            event_sequence: safe(stored_u64(sequence, "original owner creation event")?)?,
            global_commit_sequence: safe(commit)?,
        },
    })
}

fn checked_body<T: serde::de::DeserializeOwned + Serialize>(
    tx: &Connection,
    key: &str,
    scope: &RecoveryScopeV1,
    immutable: bool,
) -> Result<(T, SourceVersion), AdmissionOperationStoreError> {
    let row =
        raw_checked(tx, key)?.ok_or_else(|| invariant("original owner metadata disappeared"))?;
    let source = source_reference(tx, key)?;
    let ordinary: bool = tx.query_row(
        "SELECT native_namespace IS NULL AND native_request IS NULL FROM admission_operation_recovery_records WHERE record_key=?1",
        [key], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !ordinary
        || row.kind != "command"
        || row.scope != scope_key(scope)?
        || row.payload.len() > MAX_OWNER_BYTES
        || (immutable && row.version != 1)
    {
        return Err(invariant(
            "original owner metadata changed its closed frame",
        ));
    }
    Ok((decode(&row.payload)?, SourceVersion::capture(&source)?))
}

fn persist<T: Serialize>(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    cut: &NativeSourceTransactionOrigin<'_>,
    key: &str,
    scope: &RecoveryScopeV1,
    body: &T,
) -> Result<(SourceVersion, ProtectedMutationDelta), AdmissionOperationStoreError> {
    cut.verify(tx).map_err(map_owner_error)?;
    if !cut.matches_owner(owner) || scope.authority_domain.as_str() != owner.fence.store_uuid {
        return Err(invariant("original owner writer changed its authority"));
    }
    schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    let payload = encode(body)?;
    if payload.len() > MAX_OWNER_BYTES {
        return Err(invariant("original owner envelope exhausted"));
    }
    let before: i64 = tx
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    persist_record(
        tx,
        owner,
        key,
        &scope_key(scope)?,
        "command",
        &payload,
        None,
    )?;
    let source = source_reference(tx, key)?;
    let after: i64 = tx
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if before.checked_add(1) != Some(after)
        || source.global_commit_sequence() != stored_u64(after, "original owner global append")?
    {
        return Err(invariant(
            "original owner append has an unaccounted mutation",
        ));
    }
    Ok((
        SourceVersion::capture(&source)?,
        ProtectedMutationDelta {
            mutations: 1,
            encoded_bytes: u64::try_from(payload.len())
                .map_err(|_| invariant("original owner bytes exhausted"))?,
        },
    ))
}

fn require_format(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let stamp: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION != 41 || stamp != Some(41) {
        return Err(invariant(
            "original owner requires the complete successor format",
        ));
    }
    Ok(())
}

/// Source40 keeps only its authenticated permanent first owner. Successor
/// authority is unavailable until the complete Source41 format is published.
pub(in crate::admission_operation_store) fn using_original_owner_successor_format(
    tx: &Connection,
) -> Result<bool, AdmissionOperationStoreError> {
    let version: i32 = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    match version {
        40 => {
            require_predecessor_original_owner_absence(tx)?;
            Ok(false)
        }
        41 => {
            require_format(tx)?;
            Ok(true)
        }
        _ => Err(invariant(
            "live recovery original ownership requires its exact supported format",
        )),
    }
}

fn actual_delta_since(
    tx: &Connection,
    before: u64,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    let after: i64 = tx
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let total = stored_u64(after, "protected original append count")?
        .checked_sub(before)
        .ok_or_else(|| invariant("protected original append count reversed"))?;
    let (count, bytes): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(r.payload)),0) FROM authority_global_commits AS c
         JOIN admission_operation_recovery_records AS r ON c.projection_kind='recovery' AND c.projection_key=r.record_key AND c.projection_sequence=r.version
         WHERE c.commit_sequence>?1",
        [i64::try_from(before).map_err(|_| invariant("protected original append count exhausted"))?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if stored_u64(count, "protected original mutation count")? != total {
        return Err(invariant(
            "protected original writer has an unreported mutation",
        ));
    }
    Ok(ProtectedMutationDelta {
        mutations: total,
        encoded_bytes: stored_u64(bytes, "protected original payload bytes")?,
    })
}

fn global_sequence(tx: &Connection) -> Result<u64, AdmissionOperationStoreError> {
    stored_u64(
        tx.query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?,
        "original owner global cut",
    )
}

pub(in crate::admission_operation_store) fn require_predecessor_original_owner_absence(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let present: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN ('admission_operation_recovery_original_owner','admission_operation_recovery_original_transfer','admission_operation_recovery_original_tombstone','admission_operation_recovery_unused_setup_generation'))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if present {
        return Err(invariant(
            "predecessor contains successor original ownership catalog",
        ));
    }
    for (table, query) in [
        ("admission_operation_recovery_records", "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-original-*' OR record_key GLOB 'unused-setup-generation:*')"),
        ("admission_operation_recovery_events", "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-original-*' OR record_key GLOB 'unused-setup-generation:*')"),
        ("authority_global_commits", "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND (projection_key GLOB 'recovery-original-*' OR projection_key GLOB 'unused-setup-generation:*'))"),
    ] {
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)", [table], |row| row.get(0)).map_err(sqlite_error)?;
        if exists && tx.query_row(query, [], |row| row.get::<_,bool>(0)).map_err(sqlite_error)? {
            return Err(invariant("predecessor contains successor original ownership data"));
        }
    }
    Ok(())
}
