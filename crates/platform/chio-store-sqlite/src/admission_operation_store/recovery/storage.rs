use super::*;
use crate::admission_operation_store::knowledge::account::NewKnowledgeAccount;
use crate::admission_operation_store::knowledge::publication_capacity;
use crate::admission_operation_store::knowledge::publication_source::VerifiedKnowledgePublicationIntake;
use crate::admission_operation_store::knowledge::{
    AuthenticatedKnowledgeIntakeSource, DerivedWrite, PreparedKnowledgeClosure,
    VerifiedHandleCensus, VerifiedImportManifestBaseline,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[path = "active_workflows.rs"]
mod active_workflows;
#[path = "checkpoint_head.rs"]
mod checkpoint_head;
#[path = "command_selection.rs"]
mod command_selection;
#[path = "finalized_record_shape.rs"]
mod finalized_record_shape;
#[cfg(feature = "admission-test-support")]
#[path = "foreign_fixture_admission.rs"]
mod foreign_fixture_admission;
#[path = "knowledge_encoding.rs"]
mod knowledge_encoding;
#[path = "logical_reference.rs"]
mod logical_reference;
#[path = "native_finishing_account.rs"]
mod native_finishing_account;
#[path = "native_finishing_bank.rs"]
pub(in crate::admission_operation_store) mod native_finishing_bank;
#[path = "native_influence.rs"]
mod native_influence;
#[path = "native_journal_seal.rs"]
mod native_journal_seal;
#[path = "original_owner.rs"]
mod original_owner;
#[path = "planning_budgets.rs"]
mod planning_budgets;
#[path = "protected_mutation_delta.rs"]
mod protected_mutation_delta;
#[path = "settled_command_aliases.rs"]
mod settled_command_aliases;
#[path = "workflow_reservations.rs"]
mod workflow_reservations;
pub(in crate::admission_operation_store) use checkpoint_head::persist_checkpoint_head;
pub(in crate::admission_operation_store) use command_selection::load_selected_workflow;
pub(in crate::admission_operation_store) use knowledge_encoding::persist_knowledge_encoding;
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) use knowledge_encoding::retain_restore_extra_ordinal_fixture;
pub(in crate::admission_operation_store) use logical_reference::{
    bind_product_reference_source, initialize_knowledge_reference_account,
    persist_knowledge_new_artifact_reference_baseline, persist_knowledge_reference_progress,
    persist_knowledge_reference_retain, persist_knowledge_reference_retirement,
    persist_product_reference_retirement, reserve_product_reference_intake,
    verify_knowledge_reference_account, ReservedProductReferenceIntake,
};
pub(crate) use native_finishing_account::{
    authority_current_write_price, authority_current_write_profile, native_authority_debt,
    native_authority_file_page_debt, native_authority_table_row_debt, native_receipt_is_owed,
    native_registered_file_debt, AuthorityCurrentWritePrice, NativeAuthorityDebtData,
    NativeRegisteredFileDebtData,
};
pub(in crate::admission_operation_store) use native_finishing_account::{
    load_native_finishing_account, load_native_finishing_account_for_source,
    native_finishing_account_bound, native_finishing_account_key, native_finishing_bank_key,
    native_finishing_bank_readback, native_finishing_bank_scope, native_finishing_debt_for_file,
    native_finishing_flow_scope, native_finishing_publication, native_finishing_version_commit,
    persist_native_finishing_transition, persist_prepared_native_finishing_account,
    process_file_enrollments, process_return_bank_readback, unsettled_native_only_accounts,
    NativeFinishingAccountV1, NativeFinishingDispositionV1, NativeFinishingFileRoleV1,
    NativeFinishingFileV1, NativeFinishingIdentityV1, NativeFinishingLiabilityV1,
    NativeFinishingPageRecipeV1, NativeFinishingProcessEnrollmentV1, NativeFinishingProcessV1,
    NativeFinishingPurposeV1, NativeFinishingStateV1, NativeFinishingTransitionAllowanceV1,
    RetainedNativeFinishingAccount, NATIVE_FINISHING_BANK_MAX_BYTES,
};
pub(in crate::admission_operation_store) use native_finishing_bank::NativeFinishingWidthRecipeV1;
pub(crate) use native_finishing_bank::{
    generation_width_class_floor, native_finishing_generation, native_finishing_width_debt,
    width_class_ceiling,
};
pub(in crate::admission_operation_store) use native_influence::{
    persist_imported_influence_root, persist_native_influence_heads,
};
pub(in crate::admission_operation_store) use native_journal_seal::persist_native_journal_seal;
pub(in crate::admission_operation_store) use original_owner::{
    original_owner_is_current, require_current_original_owner,
    require_predecessor_original_owner_absence,
    retire_unused_materialized_setup_generation_with_origin,
    retire_unused_setup_generation_with_origin, verify_original_owner_inventory,
};
pub(in crate::admission_operation_store) use protected_mutation_delta::ProtectedMutationDelta;
pub(in crate::admission_operation_store) use settled_command_aliases::{
    retained_command_alias, save_settled_command_alias,
};

#[cfg(feature = "admission-test-support")]
pub(super) use finalized_record_shape::fixture_finalized_shape;
pub(in crate::admission_operation_store) use finalized_record_shape::{
    require_finalized_workflow_headroom, require_provider_finality_headroom,
};
#[cfg(feature = "admission-test-support")]
pub(super) use foreign_fixture_admission::fill_intake_events as fill_fixture_intake_events;
use workflow_reservations::verify_native_archive_allocations;
pub(in crate::admission_operation_store) use workflow_reservations::{
    auxiliary_captured_release, auxiliary_captured_terminal, auxiliary_historical_hold,
    require_command_slot, save_auxiliary_captured_release, save_auxiliary_captured_terminal,
    save_auxiliary_historical_hold, save_captured_deployment_history, save_command, save_workflow,
    viewed_workflow_quota, workflow_report_requested, workflow_resume_requested,
    ViewedWorkflowQuota, WorkflowWriteClass,
};

#[cfg(all(test, unix))]
#[path = "participant_namespace_isolation_tests.rs"]
mod participant_namespace_isolation_tests;

#[cfg(test)]
#[path = "projection_presence_tests.rs"]
mod projection_presence_tests;

#[path = "protected_source_reference.rs"]
mod protected_source_reference;
#[path = "successor_binding.rs"]
pub(in crate::admission_operation_store) mod successor_binding;
pub(in crate::admission_operation_store) use protected_source_reference::{
    matches_historical_source_payload_at_cut, source_reference, verify_source_reference,
    HistoricalProtectedSourceData, ProtectedSourceReference,
};

/// Missing current data is pristine only without any exact retained ownership.
pub(in crate::admission_operation_store) fn raw_checked(
    tx: &Connection,
    key: &str,
) -> Result<Option<RawRecord>, AdmissionOperationStoreError> {
    let row = raw(tx, key)?;
    if row.is_none() && retained_history(tx, key)? {
        return Err(invariant(
            "recovery projection disappeared with retained history",
        ));
    }
    Ok(row)
}

pub(in crate::admission_operation_store) struct RawRecord {
    pub version: u64,
    pub payload: Vec<u8>,
    pub scope: String,
    pub kind: String,
}
pub(in crate::admission_operation_store) fn encode<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(value).map_err(|_| invariant("recovery encoding refused"))?;
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(invariant("recovery resource exhausted"));
    }
    Ok(bytes)
}
pub(in crate::admission_operation_store) fn decode<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, AdmissionOperationStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(invariant("recovery resource exhausted"));
    }
    let value: T =
        serde_json::from_slice(bytes).map_err(|_| invariant("recovery record is corrupt"))?;
    if encode(&value)? != bytes {
        return Err(invariant("recovery record is not exact canonical data"));
    }
    Ok(value)
}
pub(in crate::admission_operation_store) fn scope_key(
    scope: &RecoveryScopeV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(scope)?))
}
pub(in crate::admission_operation_store) fn workflow_key(
    scope: &RecoveryScopeV1,
    id: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!("workflow:{}:{}", scope_key(scope)?, id.as_str()))
}
pub(in crate::admission_operation_store) fn raw(
    tx: &Connection,
    key: &str,
) -> Result<Option<RawRecord>, AdmissionOperationStoreError> {
    let row = tx.query_row(
        "SELECT version,length(payload),CASE WHEN length(payload) BETWEEN 1 AND 262144 THEN payload END,scope_key,kind,native_namespace,native_request FROM main.admission_operation_recovery_records WHERE record_key=?1", [key],
        |row| Ok((row.get::<_,i64>(0)?, row.get::<_,i64>(1)?, row.get::<_,Option<Vec<u8>>>(2)?,
            row.get::<_,String>(3)?, row.get::<_,String>(4)?, row.get::<_,Option<String>>(5)?, row.get::<_,Option<String>>(6)?)))
        .optional().map_err(sqlite_error)?;
    row.map(|(version,length,payload,scope,kind,namespace,request)| {
        let payload = payload.filter(|bytes| i64::try_from(bytes.len()).ok() == Some(length))
            .ok_or_else(|| invariant("recovery record exceeds its bound"))?;
        let version = stored_u64(version,"recovery version")?;
        let digest = record_digest(key, &scope, &kind, version, &payload, namespace.as_deref(), request.as_deref())?;
        let event: Option<String> = tx.query_row(
            "SELECT record_digest FROM main.admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
            params![key,i64::try_from(version).map_err(|_| invariant("recovery version exhausted"))?], |row| row.get(0))
            .optional().map_err(sqlite_error)?;
        if event.as_deref() != Some(&digest) {
            return Err(invariant("recovery projection lost its event"));
        }
        Ok(RawRecord {version,payload,scope,kind})
    }).transpose()
}
fn retained_history(tx: &Connection, key: &str) -> Result<bool, AdmissionOperationStoreError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.admission_operation_recovery_events WHERE record_key=?1)
            OR EXISTS(SELECT 1 FROM main.authority_global_commits WHERE projection_kind='recovery' AND projection_key=?1)",
        [key], |row| row.get(0),
    ).map_err(sqlite_error)
}

fn record_digest(
    key: &str,
    scope: &str,
    kind: &str,
    version: u64,
    payload: &[u8],
    namespace: Option<&str>,
    request: Option<&str>,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::ProtectedRecord.name(),
        key,
        scope,
        kind,
        version,
        sha256_hex(payload),
        namespace,
        request,
    ))?))
}

pub(in crate::admission_operation_store) fn deployment_tx(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError> {
    let row = raw(tx, &format!("deployment:{}", scope_key(scope)?))?
        .ok_or_else(|| invariant("recovery profile is unsupported"))?;
    let deployment: RecoveryDeploymentV1 = decode(&row.payload)?;
    if deployment.scope != *scope {
        return Err(invariant("recovery scope changed"));
    }
    Ok(deployment)
}
/// Compare an as-of installation with its exact authenticated historical event.
/// The serving owner already authenticates the global chain; this lookup also
/// requires the exact retained reference rather than accepting current state.
pub(in crate::admission_operation_store) fn matches_historical_deployment(
    tx: &Connection,
    key: &str,
    scope: &str,
    version: u64,
    profile: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    if key != format!("deployment:{scope}") || version == 0 {
        return Err(invariant("historical deployment identity refused"));
    }
    let (digest, _) = historical_record_reference(tx, key, version)?;
    if scope_key(&profile.scope)? != scope {
        return Ok(false);
    }
    Ok(digest
        == record_digest(
            key,
            scope,
            "deployment",
            version,
            &encode(profile)?,
            None,
            None,
        )?)
}

/// Match one historical command-kind payload against its exact custody event.
/// This data comparison grants no progress, retirement or current-head authority.
pub(in crate::admission_operation_store) fn matches_historical_command_payload(
    tx: &Connection,
    key: &str,
    scope: &str,
    version: u64,
    canonical_payload: &[u8],
) -> Result<bool, AdmissionOperationStoreError> {
    if key.is_empty()
        || key.len() > 512
        || scope.len() != 64
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || version == 0
    {
        return Err(invariant("historical command identity refused"));
    }
    let _: serde_json::Value = decode(canonical_payload)?;
    let (digest, _) = historical_record_reference(tx, key, version)?;
    Ok(digest
        == record_digest(
            key,
            scope,
            "command",
            version,
            canonical_payload,
            None,
            None,
        )?)
}

/// An authenticated current source can retain a larger legacy key. This exact
/// historical comparison grants no intake, progress or retirement authority.
/// Ordinary callers keep the separate 512-byte key contract above.
pub(in crate::admission_operation_store) fn matches_historical_source_command_payload(
    tx: &Connection,
    source: &ProtectedSourceReference,
    version: u64,
    canonical_payload: &[u8],
) -> Result<bool, AdmissionOperationStoreError> {
    verify_source_reference(tx, source)?;
    if source.kind() != "command" || version == 0 || version > source.version() {
        return Err(invariant("historical source command identity refused"));
    }
    let _: serde_json::Value = decode(canonical_payload)?;
    let (digest, _) = historical_record_reference(tx, source.record_key(), version)?;
    Ok(digest
        == record_digest(
            source.record_key(),
            source.scope_key(),
            "command",
            version,
            canonical_payload,
            None,
            None,
        )?)
}
/// Exact historical custody ordering for an already scoped owning resolver.
pub(in crate::admission_operation_store) fn historical_record_commit(
    tx: &Connection,
    key: &str,
    version: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    historical_record_reference(tx, key, version).map(|(_, commit)| commit)
}

fn historical_record_reference(
    tx: &Connection,
    key: &str,
    version: u64,
) -> Result<(String, u64), AdmissionOperationStoreError> {
    if key.is_empty() || version == 0 {
        return Err(invariant("historical record identity refused"));
    }
    let version_sql =
        i64::try_from(version).map_err(|_| invariant("historical deployment version exhausted"))?;
    let event: Option<(i64, String, String, String, i64)> = tx
        .query_row(
            "SELECT sequence,record_digest,previous_digest,event_digest,observed_at
             FROM main.admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
            params![key, version_sql],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let (sequence, digest, previous, event, observed) =
        event.ok_or_else(|| invariant("historical deployment event disappeared"))?;
    let sequence = stored_u64(sequence, "historical deployment sequence")?;
    let observed = stored_u64(observed, "historical deployment observed time")?;
    if event != event_digest(sequence, key, version, &digest, &previous, observed)? {
        return Err(invariant("historical deployment event is corrupt"));
    }
    let mut statement = tx
        .prepare(
            "SELECT commit_sequence,projection_reference_digest FROM main.authority_global_commits
         WHERE projection_kind='recovery' AND projection_key=?1 AND projection_sequence=?2 LIMIT 2",
        )
        .map_err(sqlite_error)?;
    let mut references = statement
        .query(params![key, version_sql])
        .map_err(sqlite_error)?;
    let Some(reference) = references.next().map_err(sqlite_error)? else {
        return Err(invariant("historical deployment lost its global reference"));
    };
    let commit = stored_u64(
        reference.get::<_, i64>(0).map_err(sqlite_error)?,
        "historical global commit",
    )?;
    let reference: String = reference.get(1).map_err(sqlite_error)?;
    if commit == 0 || reference != event || references.next().map_err(sqlite_error)?.is_some() {
        return Err(invariant("historical deployment lost its global reference"));
    }
    Ok((digest, commit))
}
pub(in crate::admission_operation_store) fn workflow_tx(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    id: &WorkflowId,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    let row = raw_checked(tx, &workflow_key(scope, id)?)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
    if record.scope != *scope || record.workflow_id != *id || record.revision.get() != row.version {
        return Err(invariant("recovery scope or version changed"));
    }
    Ok(record)
}
pub(in crate::admission_operation_store) fn save(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    kind: &str,
    payload: &[u8],
    native: Option<(&str, &str)>,
) -> Result<(), AdmissionOperationStoreError> {
    if native.is_some() || payload.is_empty() || payload.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(invariant("recovery record quota exhausted"));
    }
    let pool = generic_pool(key, scope, kind)?;
    super::resources::check_intake_committing(tx)?;
    let members = match pool {
        GenericPool::RecoveryPlanning => {
            return planning_budgets::save(tx, owner, key, scope, kind, payload);
        }
        GenericPool::Family(pattern) => format!("r.record_key GLOB '{pattern}'"),
        GenericPool::Knowledge => generic_knowledge_predicate("r.record_key"),
    };
    let existing = raw_checked(tx, key)?;
    let (retained, events): (i64, i64) = tx
        .query_row(
            &format!(
                "SELECT coalesce(sum(length(payload)),0),
            (SELECT count(*) FROM main.admission_operation_recovery_events e
             JOIN main.admission_operation_recovery_records r ON r.record_key=e.record_key
             WHERE {members})
         FROM main.admission_operation_recovery_records r
         WHERE {members}"
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    let next = retained
        .checked_sub(existing.as_ref().map_or(0, |row| row.payload.len() as i64))
        .and_then(|bytes| bytes.checked_add(payload.len() as i64))
        .ok_or_else(|| invariant("recovery retained bytes exhausted"))?;
    if next > 48 * 1024 * 1024 || events >= 57344 {
        return Err(invariant("recovery retained resource exhausted"));
    }
    persist_record(tx, owner, key, scope, kind, payload, None)
}

/// Persist one prepared authenticated Knowledge closure in the settlement
/// band. The closure is bound to its own writer, current authority and exact
/// source heads; each of its one or two derived records is owed 1:1 by an
/// already admitted owning record, so the intake quotas are not consulted.
/// Every CAS precedes the first write. It frees no history and finances no
/// native work.
pub(in crate::admission_operation_store) fn persist_knowledge_closure<'tx, 'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    closure: PreparedKnowledgeClosure<'tx, 'conn>,
) -> Result<(Vec<ProtectedSourceReference>, ProtectedMutationDelta), AdmissionOperationStoreError> {
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if !std::ptr::eq::<Connection>(
        std::ops::Deref::deref(closure.transaction()),
        std::ops::Deref::deref(tx),
    ) {
        return Err(invariant("knowledge closure changed its physical writer"));
    }
    if closure.scope().authority_domain.as_str() != owner.fence.store_uuid {
        return Err(invariant("knowledge closure changed its authority"));
    }
    closure.verify(tx)?;
    persist_derived(
        tx,
        owner,
        closure.writes(),
        super::resources::check_committing,
        "knowledge closure",
    )
}

/// Persist one authenticated Knowledge intake in the physical intake band.
/// The source is bound to its own writer, current authority and exact source
/// heads, and its closed write set is rederived here before any write.
pub(in crate::admission_operation_store) fn persist_knowledge_intake<'tx, 'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    intake: AuthenticatedKnowledgeIntakeSource<'tx, 'conn>,
) -> Result<(Vec<ProtectedSourceReference>, ProtectedMutationDelta), AdmissionOperationStoreError> {
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if !std::ptr::eq::<Connection>(
        std::ops::Deref::deref(intake.transaction()),
        std::ops::Deref::deref(tx),
    ) {
        return Err(invariant("knowledge intake changed its physical writer"));
    }
    if intake.scope().authority_domain.as_str() != owner.fence.store_uuid {
        return Err(invariant("knowledge intake changed its authority"));
    }
    intake.verify(tx)?;
    persist_derived(
        tx,
        owner,
        intake.writes(),
        super::resources::check_intake_committing,
        "knowledge intake",
    )
}

/// Every CAS precedes the band check and the first write; the written heads
/// must follow the prior event and global heads exactly.
fn persist_derived(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    writes: &[DerivedWrite],
    band: fn(&Connection) -> Result<(), AdmissionOperationStoreError>,
    label: &str,
) -> Result<(Vec<ProtectedSourceReference>, ProtectedMutationDelta), AdmissionOperationStoreError> {
    let mut versions = Vec::with_capacity(writes.len());
    let mut encoded_bytes = 0_u64;
    for write in writes {
        let (key, scope, payload) = (write.key(), write.scope_key(), write.payload());
        if payload.is_empty() || payload.len() > MAX_RECOVERY_RECORD_BYTES {
            return Err(invariant(format!("{label} exceeds its record bound")));
        }
        encoded_bytes = encoded_bytes
            .checked_add(
                u64::try_from(payload.len())
                    .map_err(|_| invariant(format!("{label} byte count overflow")))?,
            )
            .ok_or_else(|| invariant(format!("{label} byte count overflow")))?;
        versions.push(match (write.expected(), raw_checked(tx, key)?) {
            (Some(expected), Some(row)) => {
                verify_source_reference(tx, expected)?;
                let ordinary: bool = tx
                    .query_row(
                        "SELECT native_namespace IS NULL AND native_request IS NULL
                         FROM main.admission_operation_recovery_records WHERE record_key=?1",
                        [key],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_error)?;
                if !ordinary
                    || expected.record_key() != key
                    || expected.scope_key() != scope
                    || expected.kind() != "command"
                    || row.kind != "command"
                    || row.scope != scope
                    || row.version != expected.version()
                {
                    return Err(invariant(format!("{label} lost its current CAS")));
                }
                row.version
                    .checked_add(1)
                    .ok_or_else(|| invariant(format!("{label} version exhausted")))?
            }
            (None, None) => 1,
            _ => return Err(invariant(format!("{label} lost its current CAS"))),
        });
    }
    band(tx)?;
    let (events, commits) = closure_heads(tx)?;
    let mut written = Vec::with_capacity(writes.len());
    for (write, version) in writes.iter().zip(versions) {
        persist_record(
            tx,
            owner,
            write.key(),
            write.scope_key(),
            "command",
            write.payload(),
            None,
        )?;
        let terminal = source_reference(tx, write.key())?;
        let ordinal = u64::try_from(written.len() + 1)
            .map_err(|_| invariant(format!("{label} write count overflow")))?;
        if terminal.version() != version
            || terminal.scope_key() != write.scope_key()
            || terminal.kind() != "command"
            || events.checked_add(ordinal) != Some(terminal.event_sequence())
            || commits.checked_add(ordinal) != Some(terminal.global_commit_sequence())
        {
            return Err(invariant(format!("{label} changed its exact footprint")));
        }
        written.push(terminal);
    }
    let mutations = u64::try_from(written.len())
        .map_err(|_| invariant(format!("{label} write count overflow")))?;
    if events
        .checked_add(mutations)
        .zip(commits.checked_add(mutations))
        != Some(closure_heads(tx)?)
    {
        return Err(invariant(format!("{label} changed its exact footprint")));
    }
    Ok((
        written,
        ProtectedMutationDelta {
            mutations,
            encoded_bytes,
        },
    ))
}

fn closure_heads(tx: &Connection) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let (events, commits): (i64, i64) = tx
        .query_row(
            "SELECT (SELECT coalesce(max(sequence),0) FROM main.admission_operation_recovery_events),
                    (SELECT head_sequence FROM main.authority_global_commit_meta WHERE singleton=1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    Ok((
        stored_u64(events, "knowledge closure event head")?,
        stored_u64(commits, "knowledge closure global head")?,
    ))
}

/// Knowledge families written only through their typed proofs. Generic save
/// refuses them.
const TYPED_KNOWLEDGE_PATTERNS: [&str; 17] = [
    "knowledge-handle:*",
    "knowledge-handle-index:*",
    "knowledge-handle-baseline:*",
    "knowledge-import:*",
    "knowledge-import-map:*",
    "knowledge-pin:operator:v2:*",
    "knowledge-pin:native-operation:v2:*",
    "knowledge-pin:pending-approval:v2:*",
    "knowledge-checkpoint:v2:*",
    "knowledge-release:v2:*",
    "knowledge-publication:*",
    "knowledge-version:*",
    "knowledge-certificate:*",
    "knowledge-publication-lease:*",
    "knowledge-publication-object:*",
    "knowledge-publication-capacity:*",
    "knowledge-publication-ready:*",
];

/// The installation rows that use generic save, each a prefix followed by
/// exactly one 64-hex identity: the physical owner, the profile and the
/// runtime enforcement marker.
const GENERIC_KNOWLEDGE_INSTALLATION: [&str; 3] = [
    "knowledge-owner:",
    "knowledge-profile:",
    "knowledge-runtime:",
];

/// Untyped pins (confined pins and the maintained quota fixtures). The three
/// typed pin owners are excluded.
const GENERIC_KNOWLEDGE_PIN: &str = "knowledge-pin:";

/// The pool's Knowledge families, and the only `knowledge-*` keys generic
/// save accepts. Native, encoded, closure, reference and every typed family
/// keep their own authority and physical accounting and are not counted.
fn generic_knowledge_family(key: &str) -> bool {
    let installation = GENERIC_KNOWLEDGE_INSTALLATION.iter().any(|prefix| {
        key.strip_prefix(prefix).is_some_and(|identity| {
            identity.len() == 64
                && identity
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
    });
    installation || (key.starts_with(GENERIC_KNOWLEDGE_PIN) && !typed_knowledge_family(key))
}

fn typed_knowledge_family(key: &str) -> bool {
    TYPED_KNOWLEDGE_PATTERNS
        .iter()
        .any(|pattern| key.starts_with(pattern.trim_end_matches('*')))
}

/// The SQL predicate over `column` that selects exactly the keys
/// `generic_knowledge_family` accepts. Every fragment is a closed constant.
pub(in crate::admission_operation_store) fn generic_knowledge_predicate(column: &str) -> String {
    let installation = GENERIC_KNOWLEDGE_INSTALLATION.iter().map(|prefix| {
        format!(
            "({column} GLOB '{prefix}*' AND length({column})={} \
             AND substr({column},{}) NOT GLOB '*[^0-9a-f]*')",
            prefix.len() + 64,
            prefix.len() + 1
        )
    });
    let typed_pins = TYPED_KNOWLEDGE_PATTERNS
        .iter()
        .filter(|pattern| pattern.starts_with(GENERIC_KNOWLEDGE_PIN))
        .map(|pattern| format!(" AND {column} NOT GLOB '{pattern}'"))
        .collect::<String>();
    let pins = format!("({column} GLOB '{GENERIC_KNOWLEDGE_PIN}*'{typed_pins})");
    format!(
        "({})",
        installation.chain([pins]).collect::<Vec<_>>().join(" OR ")
    )
}

/// The one quota a generic protected record is charged to.
enum GenericPool {
    RecoveryPlanning,
    Family(&'static str),
    Knowledge,
}

/// Persist one verified reservation, then its live slot derived from the
/// written record, in the intake band. The intake proof is verified while
/// the publication is still absent; any refusal rolls back both.
pub(in crate::admission_operation_store) fn persist_knowledge_publication_reservation<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    intake: &VerifiedKnowledgePublicationIntake<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    intake.verify(tx)?;
    let reservation = publication_capacity::reservation_write(intake)?;
    persist_derived(
        tx,
        owner,
        std::slice::from_ref(&reservation),
        super::resources::check_intake_committing,
        "knowledge publication reservation",
    )?;
    let allocation =
        publication_capacity::derive_allocation(tx, intake.scope(), intake.source_key())?;
    persist_derived(
        tx,
        owner,
        &allocation,
        super::resources::check_intake_committing,
        "knowledge publication allocation",
    )?;
    Ok(())
}

/// Persist the empty publication counter of a new account, then its ready
/// record anchored to the written counter, under the installation writer's
/// new-account proof.
pub(in crate::admission_operation_store) fn persist_knowledge_account_bootstrap<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: &NewKnowledgeAccount<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    proof.verify(tx)?;
    let counter = publication_capacity::bootstrap_write(tx, proof, None)?;
    let (written, _) = persist_derived(
        tx,
        owner,
        std::slice::from_ref(&counter),
        super::resources::check_intake_committing,
        "knowledge account bootstrap",
    )?;
    let counter = written
        .first()
        .ok_or_else(|| invariant("knowledge account bootstrap lost its counter"))?;
    let ready = publication_capacity::bootstrap_write(tx, proof, Some(counter))?;
    persist_derived(
        tx,
        owner,
        std::slice::from_ref(&ready),
        super::resources::check_intake_committing,
        "knowledge account bootstrap",
    )?;
    Ok(())
}

/// Persist the one import manifest baseline of this authority at startup, in
/// the settlement band. The proof is bound to this writer and owner.
pub(in crate::admission_operation_store) fn persist_knowledge_import_baseline<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    baseline: VerifiedImportManifestBaseline<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    baseline.verify(tx, owner)?;
    let (key, payload) = (baseline.key(), baseline.payload());
    if !key.starts_with("knowledge-import-baseline:")
        || payload.is_empty()
        || payload.len() > MAX_RECOVERY_RECORD_BYTES
        || raw_checked(tx, key)?.is_some()
        || retained_history(tx, key)?
    {
        return Err(invariant("import baseline record refused"));
    }
    super::resources::check_committing(tx)?;
    persist_record(
        tx,
        owner,
        key,
        baseline.scope_key(),
        "command",
        payload,
        None,
    )
}

/// One `knowledge-checkpoint:v2:` row exactly as the prior-44 generic writer
/// retained it.
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) fn retain_prior_format_checkpoint_fixture(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    if !key.starts_with("knowledge-checkpoint:v2:") || raw_checked(tx, key)?.is_some() {
        return Err(invariant("prior checkpoint fixture refused"));
    }
    persist_record(tx, owner, key, scope, "command", payload, None)
}

/// One import manifest or map row exactly as the prior-44 generic writer
/// retained it.
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) fn retain_prior_format_import_fixture(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    if !(key.starts_with("knowledge-import:") || key.starts_with("knowledge-import-map:"))
        || raw_checked(tx, key)?.is_some()
    {
        return Err(invariant("prior import fixture refused"));
    }
    persist_record(tx, owner, key, scope, "command", payload, None)
}

/// One raw protected record for store unit tests that seed exact rows.
#[cfg(test)]
pub(in crate::admission_operation_store) fn persist_test_record(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    persist_record(tx, owner, key, scope, "command", payload, None)
}

/// Persist one record of the one-time handle migration: a census index or the
/// authority baseline, each new with no retained history, in the settlement
/// band. Each is owed by the prior-44 rows the migration authenticated.
pub(in crate::admission_operation_store) fn persist_knowledge_handle_census(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    census: VerifiedHandleCensus,
) -> Result<(), AdmissionOperationStoreError> {
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    let (key, payload) = (census.key(), census.payload());
    if !(key.starts_with("knowledge-handle-index:")
        || key.starts_with("knowledge-handle-baseline:"))
        || payload.is_empty()
        || payload.len() > MAX_RECOVERY_RECORD_BYTES
        || raw_checked(tx, key)?.is_some()
        || retained_history(tx, key)?
    {
        return Err(invariant("handle migration record refused"));
    }
    super::resources::check_committing(tx)?;
    persist_record(tx, owner, key, census.scope_key(), "command", payload, None)
}

/// One handle row exactly as the prior-44 generic writer retained it.
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) fn retain_prior_format_handle_fixture(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    if !key.starts_with("knowledge-handle:") || raw_checked(tx, key)?.is_some() {
        return Err(invariant("prior handle fixture refused"));
    }
    persist_record(tx, owner, key, scope, "command", payload, None)
}

fn generic_pool(
    key: &str,
    scope: &str,
    kind: &str,
) -> Result<GenericPool, AdmissionOperationStoreError> {
    if key == format!("deployment:{scope}")
        || key.starts_with(&format!("deployment-history:{scope}:"))
    {
        if kind == "deployment" {
            return Ok(GenericPool::RecoveryPlanning);
        }
    } else if key.starts_with("recovery-origin:")
        || key.starts_with("recovery-successor:")
        || key.starts_with("recovery-owner:")
    {
        if kind == "command" {
            return Ok(GenericPool::RecoveryPlanning);
        }
    } else if key.starts_with("semantic-") {
        if matches!(kind, "command" | "deployment") {
            return Ok(GenericPool::Family("semantic-*"));
        }
    } else if kind == "command" {
        if typed_knowledge_family(key) {
            return Err(invariant("protected record family has a typed writer"));
        }
        if key.starts_with("knowledge-") {
            if generic_knowledge_family(key) {
                return Ok(GenericPool::Knowledge);
            }
            return Err(invariant("protected record namespace or kind refused"));
        }
        for (prefix, pattern) in [
            ("confined-", "confined-*"),
            ("product-", "product-*"),
            ("protected-setup:", "protected-setup*"),
            ("protected-setup-context:", "protected-setup*"),
            ("protected-setup-tenant:", "protected-setup*"),
            ("protected-setup-retired:", "protected-setup*"),
        ] {
            if key.starts_with(prefix) {
                return Ok(GenericPool::Family(pattern));
            }
        }
    }
    Err(invariant("protected record namespace or kind refused"))
}

fn persist_record(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    kind: &str,
    payload: &[u8],
    native: Option<(&str, &str)>,
) -> Result<(), AdmissionOperationStoreError> {
    if payload.is_empty() || payload.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(invariant("recovery record quota exhausted"));
    }
    let version = raw_checked(tx, key)?.map_or(Ok(1), |row| {
        if row.scope != scope || row.kind != kind {
            return Err(invariant("protected record ownership changed"));
        }
        row.version
            .checked_add(1)
            .ok_or_else(|| invariant("recovery version exhausted"))
    })?;
    let (namespace, request) = native.map_or((None, None), |(namespace, request)| {
        (Some(namespace), Some(request))
    });
    tx.execute("INSERT INTO main.admission_operation_recovery_records(record_key,scope_key,kind,version,payload,native_namespace,native_request) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(record_key) DO UPDATE SET version=excluded.version,payload=excluded.payload,native_namespace=excluded.native_namespace,native_request=excluded.native_request",params![key,scope,kind,i64::try_from(version).map_err(|_|invariant("recovery version exhausted"))?,payload,namespace,request]).map_err(sqlite_error)?;
    let head:Option<(i64,String)>=tx.query_row("SELECT sequence,event_digest FROM main.admission_operation_recovery_events ORDER BY sequence DESC LIMIT 1",[],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(sqlite_error)?;
    let (sequence, previous) = head.map_or((1, "0".repeat(64)), |(sequence, digest)| {
        (sequence + 1, digest)
    });
    let sequence =
        u64::try_from(sequence).map_err(|_| invariant("recovery sequence is corrupt"))?;
    if sequence > 9007199254740991 {
        return Err(invariant("recovery history exhausted"));
    }
    let digest = record_digest(key, scope, kind, version, payload, namespace, request)?;
    let observed = super::super::schema::observe_authority_time(tx)?;
    let event = event_digest(sequence, key, version, &digest, &previous, observed)?;
    tx.execute("INSERT INTO main.admission_operation_recovery_events(sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![i64::try_from(sequence).map_err(|_|invariant("recovery sequence exhausted"))?,key,i64::try_from(version).map_err(|_|invariant("recovery version exhausted"))?,digest,previous,event,i64::try_from(observed).map_err(|_|invariant("recovery time exhausted"))?]).map_err(sqlite_error)?;
    owner
        .append_global_commit(tx, "recovery_transition", "recovery", key, version)
        .map_err(map_owner_error)
}
fn event_digest(
    sequence: u64,
    key: &str,
    version: u64,
    digest: &str,
    previous: &str,
    observed: u64,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::StoreEvent.name(),
        sequence,
        key,
        version,
        digest,
        previous,
        observed,
    ))?))
}
pub(crate) fn projection_reference(
    tx: &Connection,
    key: &str,
    version: u64,
) -> Result<String, crate::SqliteServingOwnerError> {
    tx.query_row("SELECT event_digest FROM main.admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",params![key,i64::try_from(version).map_err(|_|crate::SqliteServingOwnerError::Invalid("recovery version exhausted".into()))?],|row|row.get(0)).optional()?.ok_or_else(||crate::SqliteServingOwnerError::Invalid("recovery event is absent".into()))
}
pub(crate) fn verify_all(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name='admission_operation_recovery_events')",[],|row|row.get(0)).map_err(sqlite_error)?;
    if !exists {
        return Ok(());
    }
    let mut previous = "0".repeat(64);
    let mut high_water = 0;
    let mut statement=tx.prepare("SELECT sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at FROM main.admission_operation_recovery_events ORDER BY sequence").map_err(sqlite_error)?;
    let mut rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(sqlite_error)?;
    rows.try_fold(1_u64, |expected, row| {
        let (sequence, key, version, digest, parent, event, observed) =
            row.map_err(sqlite_error)?;
        let observed = stored_u64(observed, "recovery observed time")?;
        let sequence = stored_u64(sequence, "recovery sequence")?;
        let version = stored_u64(version, "recovery version")?;
        if observed < high_water
            || sequence != expected
            || parent != previous
            || event != event_digest(sequence, &key, version, &digest, &parent, observed)?
        {
            return Err(invariant("recovery history is corrupt"));
        }
        high_water = observed;
        previous = event;
        Ok::<_, AdmissionOperationStoreError>(expected + 1)
    })?;
    drop(rows);
    let invalid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM main.admission_operation_recovery_records r WHERE (SELECT count(*) FROM main.admission_operation_recovery_events e WHERE e.record_key=r.record_key)<>r.version OR (SELECT max(record_version) FROM main.admission_operation_recovery_events e WHERE e.record_key=r.record_key)<>r.version) OR EXISTS(SELECT 1 FROM main.admission_operation_recovery_events e WHERE NOT EXISTS(SELECT 1 FROM main.admission_operation_recovery_records r WHERE r.record_key=e.record_key))",[],|row|row.get(0)).map_err(sqlite_error)?;
    if invalid {
        return Err(invariant("recovery history coverage is incomplete"));
    }
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    for key in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        raw(tx, &key)?.ok_or_else(|| invariant("recovery row disappeared"))?;
    }
    workflow_reservations::verify_all(tx)?;
    planning_budgets::verify_all(tx)?;
    active_workflows::verify_all(tx)?;
    settled_command_aliases::verify_all(tx)?;
    verify_original_owner_inventory(tx)?;
    successor_binding::verify_owner_inventory(tx)?;
    native_finishing_account::verify_native_finishing_inventory(tx)?;
    super::origins::verify_history(tx)?;
    Ok(())
}
