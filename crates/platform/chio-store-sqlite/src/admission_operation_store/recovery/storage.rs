use super::*;
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
    persist_knowledge_new_artifact_reference_baseline, persist_knowledge_reference_cold_baseline,
    persist_knowledge_reference_progress, persist_knowledge_reference_ready,
    reserve_product_reference_intake, ReservedProductReferenceIntake,
    VerifiedKnowledgeReferenceColdProgress, VerifiedParticipantAllowance,
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
#[cfg(feature = "admission-test-support")]
pub(super) use workflow_reservations::save_legacy_inspection;
use workflow_reservations::verify_native_archive_allocations;
pub(in crate::admission_operation_store) use workflow_reservations::{
    auxiliary_captured_release, auxiliary_captured_terminal, auxiliary_historical_hold,
    require_command_slot, save_auxiliary_captured_release, save_auxiliary_captured_terminal,
    save_auxiliary_historical_hold, save_captured_deployment_history, save_command, save_workflow,
    workflow_report_requested, workflow_resume_requested, WorkflowWriteClass,
};

#[cfg(test)]
#[path = "projection_presence_tests.rs"]
mod projection_presence_tests;

#[path = "protected_source_reference.rs"]
mod protected_source_reference;
pub(in crate::admission_operation_store) use protected_source_reference::{
    source_reference, verify_source_reference, ProtectedSourceReference,
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
        "SELECT version,length(payload),CASE WHEN length(payload) BETWEEN 1 AND 262144 THEN payload END,scope_key,kind,native_namespace,native_request FROM admission_operation_recovery_records WHERE record_key=?1", [key],
        |row| Ok((row.get::<_,i64>(0)?, row.get::<_,i64>(1)?, row.get::<_,Option<Vec<u8>>>(2)?,
            row.get::<_,String>(3)?, row.get::<_,String>(4)?, row.get::<_,Option<String>>(5)?, row.get::<_,Option<String>>(6)?)))
        .optional().map_err(sqlite_error)?;
    row.map(|(version,length,payload,scope,kind,namespace,request)| {
        let payload = payload.filter(|bytes| i64::try_from(bytes.len()).ok() == Some(length))
            .ok_or_else(|| invariant("recovery record exceeds its bound"))?;
        let version = stored_u64(version,"recovery version")?;
        let digest = record_digest(key, &scope, &kind, version, &payload, namespace.as_deref(), request.as_deref())?;
        let event: Option<String> = tx.query_row(
            "SELECT record_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
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
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key=?1)
            OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key=?1)",
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
             FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
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
            "SELECT commit_sequence,projection_reference_digest FROM authority_global_commits
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
    let (patterns, recovery_planning) = generic_pool(key, scope, kind)?;
    super::resources::check_intake_committing(tx)?;
    if recovery_planning {
        return planning_budgets::save(tx, owner, key, scope, kind, payload);
    }
    let existing = raw(tx, key)?;
    let (retained, events): (i64, i64) = tx
        .query_row(
            "SELECT coalesce(sum(length(payload)),0),
            (SELECT count(*) FROM admission_operation_recovery_events e
             JOIN admission_operation_recovery_records r ON r.record_key=e.record_key
             WHERE r.record_key GLOB ?1 OR r.record_key GLOB ?2 OR r.record_key GLOB ?3)
         FROM admission_operation_recovery_records r
         WHERE r.record_key GLOB ?1 OR r.record_key GLOB ?2 OR r.record_key GLOB ?3",
            params![patterns[0], patterns[1], patterns[2]],
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

fn generic_pool(
    key: &str,
    scope: &str,
    kind: &str,
) -> Result<([&'static str; 3], bool), AdmissionOperationStoreError> {
    let recovery_planning = ["deployment:*", "deployment-history:*", "recovery-origin:*"];
    if key == format!("deployment:{scope}")
        || key.starts_with(&format!("deployment-history:{scope}:"))
    {
        if kind == "deployment" {
            return Ok((recovery_planning, true));
        }
    } else if key.starts_with("recovery-origin:") {
        if kind == "command" {
            return Ok((recovery_planning, true));
        }
    } else if key.starts_with("semantic-") {
        if matches!(kind, "command" | "deployment") {
            return Ok((["semantic-*", "semantic-*", "semantic-*"], false));
        }
    } else if kind == "command" {
        for (prefix, pattern) in [
            ("knowledge-", "knowledge-*"),
            ("confined-", "confined-*"),
            ("product-", "product-*"),
            ("protected-setup:", "protected-setup*"),
            ("protected-setup-context:", "protected-setup*"),
            ("protected-setup-tenant:", "protected-setup*"),
            ("protected-setup-retired:", "protected-setup*"),
        ] {
            if key.starts_with(prefix) {
                return Ok(([pattern, pattern, pattern], false));
            }
        }
    }
    Err(invariant("protected record namespace or kind refused"))
}

#[cfg(feature = "admission-test-support")]
pub(super) fn save_legacy_planning_fixture_profile(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &RecoveryDeploymentV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !super::legacy_planning_test_support::constructing_legacy_planning(tx, owner, true)? {
        return Err(invariant("legacy planning construction is not active"));
    }
    validate_deployment(profile, &owner.fence)?;
    let scope = scope_key(&profile.scope)?;
    let current = deployment_tx(tx, &profile.scope)?;
    if current.native_authority != profile.native_authority
        || current.security_context != profile.security_context
    {
        return Err(invariant("legacy planning fixture native owner changed"));
    }
    persist_record(
        tx,
        owner,
        &format!("deployment:{scope}"),
        &scope,
        "deployment",
        &encode(profile)?,
        None,
    )
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
    let version = raw(tx, key)?.map_or(Ok(1), |row| {
        row.version
            .checked_add(1)
            .ok_or_else(|| invariant("recovery version exhausted"))
    })?;
    let (namespace, request) = native.map_or((None, None), |(namespace, request)| {
        (Some(namespace), Some(request))
    });
    tx.execute("INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload,native_namespace,native_request) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(record_key) DO UPDATE SET version=excluded.version,payload=excluded.payload,native_namespace=excluded.native_namespace,native_request=excluded.native_request",params![key,scope,kind,i64::try_from(version).map_err(|_|invariant("recovery version exhausted"))?,payload,namespace,request]).map_err(sqlite_error)?;
    let head:Option<(i64,String)>=tx.query_row("SELECT sequence,event_digest FROM admission_operation_recovery_events ORDER BY sequence DESC LIMIT 1",[],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(sqlite_error)?;
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
    tx.execute("INSERT INTO admission_operation_recovery_events(sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![i64::try_from(sequence).map_err(|_|invariant("recovery sequence exhausted"))?,key,i64::try_from(version).map_err(|_|invariant("recovery version exhausted"))?,digest,previous,event,i64::try_from(observed).map_err(|_|invariant("recovery time exhausted"))?]).map_err(sqlite_error)?;
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
    tx.query_row("SELECT event_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",params![key,i64::try_from(version).map_err(|_|crate::SqliteServingOwnerError::Invalid("recovery version exhausted".into()))?],|row|row.get(0)).optional()?.ok_or_else(||crate::SqliteServingOwnerError::Invalid("recovery event is absent".into()))
}
pub(crate) fn verify_all(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_events')",[],|row|row.get(0)).map_err(sqlite_error)?;
    if !exists {
        return Ok(());
    }
    let mut previous = "0".repeat(64);
    let mut expected = 1;
    let mut high_water = 0;
    let mut statement=tx.prepare("SELECT sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at FROM admission_operation_recovery_events ORDER BY sequence").map_err(sqlite_error)?;
    let rows = statement
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
    for row in rows {
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
        expected += 1;
    }
    let invalid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records r WHERE (SELECT count(*) FROM admission_operation_recovery_events e WHERE e.record_key=r.record_key)<>r.version OR (SELECT max(record_version) FROM admission_operation_recovery_events e WHERE e.record_key=r.record_key)<>r.version) OR EXISTS(SELECT 1 FROM admission_operation_recovery_events e WHERE NOT EXISTS(SELECT 1 FROM admission_operation_recovery_records r WHERE r.record_key=e.record_key))",[],|row|row.get(0)).map_err(sqlite_error)?;
    if invalid {
        return Err(invariant("recovery history coverage is incomplete"));
    }
    let mut statement = tx
        .prepare("SELECT record_key FROM admission_operation_recovery_records ORDER BY record_key")
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
    super::origins::verify_history(tx)?;
    Ok(())
}
