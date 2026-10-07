//! Real captured originals retain physical workflow bytes under an auxiliary hold.
use super::*;
use rusqlite::{params, Connection, OpenFlags};

#[derive(Debug, Eq, PartialEq)]
struct ProtectedWorkflowRow {
    key: String,
    scope_hash: String,
    version: u64,
    payload: Vec<u8>,
    digest: String,
}

struct ProtectedQuotaRow {
    key: String,
    version: u64,
    payload: Vec<u8>,
    value: Value,
}

fn read_workflow_row(
    path: &Path,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<ProtectedWorkflowRow> {
    let db =
        Connection::open_with_flags(path.join("admission.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (key, scope_hash, version, payload, digest): (String, String, i64, Vec<u8>, String) = db.query_row(
        "SELECT r.record_key,r.scope_key,r.version,r.payload,e.record_digest
         FROM admission_operation_recovery_records r
         JOIN admission_operation_recovery_events e ON e.record_key=r.record_key AND e.record_version=r.version
         WHERE r.kind='workflow' AND json_extract(r.payload,'$.workflow_id')=?1
           AND json_extract(r.payload,'$.scope.authority_domain')=?2
           AND json_extract(r.payload,'$.scope.tenant_id')=?3
           AND json_extract(r.payload,'$.scope.process_id')=?4",
        params![record.workflow_id.as_str(),record.scope.authority_domain.as_str(),record.scope.tenant_id.as_str(),record.scope.process_id.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    )?;
    let decoded: RecoveryWorkflowRecordV1 = serde_json::from_slice(&payload)?;
    assert_eq!(decoded.scope, record.scope);
    assert_eq!(decoded.workflow_id, record.workflow_id);
    assert_eq!(chio_core::canonical_json_bytes(&decoded)?, payload);
    assert_eq!(
        key,
        format!("workflow:{scope_hash}:{}", record.workflow_id.as_str())
    );
    Ok(ProtectedWorkflowRow {
        key,
        scope_hash,
        version: u64::try_from(version)?,
        payload,
        digest,
    })
}

fn read_quota_row(
    path: &Path,
    row: &ProtectedWorkflowRow,
    id: &WorkflowId,
) -> TestResult<ProtectedQuotaRow> {
    let db =
        Connection::open_with_flags(path.join("admission.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let key = format!("workflow-quota:{}:{}", row.scope_hash, id.as_str());
    let (version,payload): (i64,Vec<u8>) = db.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1 AND kind='command'",
        [&key], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    assert!(payload.len() <= 4096);
    let value: Value = serde_json::from_slice(&payload)?;
    assert_eq!(chio_core::canonical_json_bytes(&value)?, payload);
    Ok(ProtectedQuotaRow {
        key,
        version: u64::try_from(version)?,
        payload,
        value,
    })
}

fn digest_array_hex(value: &Value) -> TestResult<String> {
    let bytes = value.as_array().ok_or("hold digest array")?;
    assert_eq!(bytes.len(), 32);
    bytes
        .iter()
        .map(|byte| {
            let byte = u8::try_from(byte.as_u64().ok_or("hold digest byte")?)?;
            Ok(format!("{byte:02x}"))
        })
        .collect::<TestResult<Vec<String>>>()
        .map(|parts| parts.concat())
}

fn assert_auxiliary_hold(
    record: &RecoveryWorkflowRecordV1,
    row: &ProtectedWorkflowRow,
    before: &ProtectedQuotaRow,
    after: &ProtectedQuotaRow,
) -> TestResult {
    let allocation = after
        .value
        .get("native_hold")
        .filter(|value| value.is_object())
        .ok_or("authenticated auxiliary hold missing")?;
    assert_eq!(
        allocation["workflow_record_version"].as_u64(),
        Some(row.version)
    );
    assert_eq!(
        digest_array_hex(&allocation["workflow_record_digest"])?,
        row.digest
    );
    let hold: RecoveryHistoricalHoldV1 = serde_json::from_value(allocation["hold"].clone())?;
    assert_eq!(record.historical_hold.as_ref(), Some(&hold));
    assert_eq!(record.control, WorkflowControlV1::Quarantined);
    assert_eq!(
        hold.reason,
        RecoveryHistoricalHoldReasonV1::FrozenOutputVerifierUnavailable
    );
    let intent = record.admission.as_ref().ok_or("held native intent")?;
    assert_eq!(hold.operation.operation_id(), &intent.native_operation_id);
    assert_eq!(after.version, before.version + 1);
    for field in [
        "baseline_revision",
        "baseline_commands",
        "planning",
        "control",
        "native",
        "commands",
        "native_archive",
    ] {
        assert_eq!(
            after.value[field], before.value[field],
            "hold reassigned quota field {field}"
        );
    }
    assert_eq!(after.value["scope"], serde_json::to_value(&record.scope)?);
    assert_eq!(
        after.value["workflow_id"],
        serde_json::to_value(&record.workflow_id)?
    );
    let physical: RecoveryWorkflowRecordV1 = serde_json::from_slice(&row.payload)?;
    assert!(physical.historical_hold.is_none());
    assert_eq!(physical.control, WorkflowControlV1::Active);
    assert_eq!(record.revision.get(), row.version);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_owed_hold_preserves_exhausted_native_128_and_original_custody() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let original = retained_workflow(directory.path())?;
    let native_before = native_original_bytes(directory.path(), &original)?;
    let return_before = captured_return_bytes(directory.path(), &original)?;
    // A genuine current capture is advanced only by the existing protected
    // Native writer. This models exhausted legacy-compatible allowance bytes;
    // it is not a claim that a predecessor public route generated 128 writes.
    let authority = SqliteAuthorityStore::open_serving(
        directory.path().join("admission.db"),
        directory.path().join("locks"),
    )?;
    authority
        .admission_operation_store()
        .exhaust_captured_recovery_native_allowance_for_test(
            &original.scope,
            &original.workflow_id,
        )?;
    drop(authority);
    let before = retained_workflow(directory.path())?;
    let row_before = read_workflow_row(directory.path(), &before)?;
    let quota_before = read_quota_row(directory.path(), &row_before, &before.workflow_id)?;
    assert_eq!(quota_before.value["native"].as_u64(), Some(128));
    assert!(quota_before.value.get("native_hold").is_none());
    assert_eq!(
        native_original_bytes(directory.path(), &before)?,
        native_before
    );
    assert_eq!(
        captured_return_bytes(directory.path(), &before)?,
        return_before
    );
    std::fs::write(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
        b"1",
    )?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let held = fixture.record(&before.workflow_id)?;
    let row_after = read_workflow_row(directory.path(), &before)?;
    assert_eq!(row_after, row_before);
    let quota_after = read_quota_row(directory.path(), &row_after, &before.workflow_id)?;
    assert_auxiliary_hold(&held, &row_before, &quota_before, &quota_after)?;
    assert_eq!(quota_after.value["native"].as_u64(), Some(128));
    for _ in 0..3 {
        assert_eq!(
            fixture
                .runtime
                .settle(&fixture.control, &before.workflow_id)?
                .control,
            WorkflowControlV1::Quarantined,
        );
    }
    assert_eq!(read_workflow_row(directory.path(), &before)?, row_before);
    assert_eq!(
        read_quota_row(directory.path(), &row_before, &before.workflow_id)?.payload,
        quota_after.payload
    );
    assert_eq!(
        native_original_bytes(directory.path(), &before)?,
        native_before
    );
    assert_eq!(
        captured_return_bytes(directory.path(), &before)?,
        return_before
    );
    assert_eq!(external_count(directory.path())?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_auxiliary_hold_authenticates_exact_event_and_native_ownership() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let before = retained_workflow(directory.path())?;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
        b"1",
    )?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let held = fixture.record(&before.workflow_id)?;
    let physical = read_workflow_row(directory.path(), &before)?;
    let quota = read_quota_row(directory.path(), &physical, &before.workflow_id)?;
    let native = native_original_bytes(directory.path(), &before)?;
    let returned = captured_return_bytes(directory.path(), &before)?;
    let events = recovery_event_count(directory.path())?;
    assert_eq!(
        fixture
            .authority
            .admission_operation_store()
            .verify_auxiliary_recovery_hold_faults_for_test(&held.scope, &held.workflow_id)?,
        7
    );
    assert_eq!(read_workflow_row(directory.path(), &before)?, physical);
    assert_eq!(
        read_quota_row(directory.path(), &physical, &before.workflow_id)?.payload,
        quota.payload
    );
    assert_eq!(recovery_event_count(directory.path())?, events);
    assert_eq!(native_original_bytes(directory.path(), &before)?, native);
    assert_eq!(captured_return_bytes(directory.path(), &before)?, returned);
    assert_eq!(external_count(directory.path())?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_first_historical_hold_preserves_exact_physical_workflow() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let before = retained_workflow(directory.path())?;
    let workflow_before = read_workflow_row(directory.path(), &before)?;
    let quota_before = read_quota_row(directory.path(), &workflow_before, &before.workflow_id)?;
    let native_before = native_original_bytes(directory.path(), &before)?;
    let return_before = captured_return_bytes(directory.path(), &before)?;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
        b"1",
    )?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let held = fixture.record(&before.workflow_id)?;
    let workflow_after = read_workflow_row(directory.path(), &before)?;
    assert_eq!(
        workflow_after, workflow_before,
        "first historical hold rewrote the size-capped captured workflow"
    );
    let quota_after = read_quota_row(directory.path(), &workflow_after, &before.workflow_id)?;
    assert_auxiliary_hold(&held, &workflow_before, &quota_before, &quota_after)?;
    assert_eq!(
        native_original_bytes(directory.path(), &before)?,
        native_before
    );
    assert_eq!(
        captured_return_bytes(directory.path(), &before)?,
        return_before
    );
    assert_eq!(external_count(directory.path())?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    for _ in 0..3 {
        let status = fixture
            .runtime
            .settle(&fixture.control, &before.workflow_id)?;
        assert_eq!(status.control, WorkflowControlV1::Quarantined);
        assert!(!status.effect.is_settled());
    }
    assert_eq!(
        read_workflow_row(directory.path(), &before)?,
        workflow_before
    );
    assert_eq!(
        read_quota_row(directory.path(), &workflow_before, &before.workflow_id)?.payload,
        quota_after.payload
    );
    let events = recovery_event_count(directory.path())?;
    drop(fixture);
    // Restoring the original hook does not clear already retained custody.
    std::fs::remove_file(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
    )?;
    let reopened = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let held = reopened.record(&before.workflow_id)?;
    assert_eq!(held.control, WorkflowControlV1::Quarantined);
    assert_eq!(
        read_workflow_row(directory.path(), &before)?,
        workflow_before
    );
    let held_again = read_quota_row(directory.path(), &workflow_before, &before.workflow_id)?;
    assert_eq!(held_again.payload, quota_after.payload);
    assert_eq!(recovery_event_count(directory.path())?, events);
    assert_eq!(
        native_original_bytes(directory.path(), &before)?,
        native_before
    );
    assert_eq!(
        captured_return_bytes(directory.path(), &before)?,
        return_before
    );
    let actor = reopened.kernel.authenticate_recovery_actor(
        reopened.runtime.scope(),
        &reopened.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(reopened
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)
        .is_err());
    let resume = reopened.command(
        "restored-original-hold-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: before.workflow_id.clone(),
            expected_revision: held.revision,
        },
    )?;
    assert!(
        Box::pin(reopened.runtime.execute_command(&reopened.control, &resume))
            .await
            .is_err()
    );
    assert_eq!(external_count(directory.path())?, 1);
    assert_eq!(reopened.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_auxiliary_hold_controls_cancel_without_projection_persistence() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let before = retained_workflow(directory.path())?;
    let workflow_before = read_workflow_row(directory.path(), &before)?;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
        b"1",
    )?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let held = fixture.record(&before.workflow_id)?;
    assert_eq!(
        read_workflow_row(directory.path(), &before)?,
        workflow_before,
        "hold projected into physical workflow"
    );
    let quota_before = read_quota_row(directory.path(), &workflow_before, &before.workflow_id)?;
    let allocation = quota_before
        .value
        .get("native_hold")
        .filter(|value| value.is_object())
        .ok_or("auxiliary hold")?
        .clone();
    let cancel = fixture.command(
        "cancel-auxiliary-held-original",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: before.workflow_id.clone(),
            expected_revision: held.revision,
        },
    )?;
    let result = Box::pin(fixture.runtime.execute_command(&fixture.control, &cancel)).await?;
    assert_eq!(result.status.control, WorkflowControlV1::Quarantined);
    assert!(result.original_response.is_none());
    assert_eq!(
        read_workflow_row(directory.path(), &before)?,
        workflow_before,
        "Cancel persisted the derived hold or cleared its control"
    );
    let quota_after = read_quota_row(directory.path(), &workflow_before, &before.workflow_id)?;
    assert_eq!(quota_after.value["native_hold"], allocation);
    assert_eq!(quota_after.value["native"], quota_before.value["native"]);
    assert_eq!(quota_after.value["control"], quota_before.value["control"]);
    assert_eq!(quota_after.version, quota_before.version + 1);
    let replay = Box::pin(fixture.runtime.execute_command(&fixture.control, &cancel)).await?;
    assert_eq!(
        chio_core::canonical_json_bytes(&replay.status)?,
        chio_core::canonical_json_bytes(&result.status)?
    );
    assert_eq!(
        read_quota_row(directory.path(), &workflow_before, &before.workflow_id)?.payload,
        quota_after.payload
    );
    assert_eq!(external_count(directory.path())?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_auxiliary_hold_rejects_removal_and_substituted_custody() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let before = retained_workflow(directory.path())?;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
        b"1",
    )?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let physical = read_workflow_row(directory.path(), &before)?;
    let quota = read_quota_row(directory.path(), &physical, &before.workflow_id)?;
    assert!(
        quota.value.get("native_hold").is_some_and(Value::is_object),
        "hold has no authenticated auxiliary custody"
    );
    drop(fixture);
    let db = Connection::open(directory.path().join("admission.db"))?;
    for fault in ["removed", "reason-substituted", "operation-substituted"] {
        let mut changed = quota.value.clone();
        match fault {
            "removed" => {
                changed
                    .as_object_mut()
                    .ok_or("quota object")?
                    .remove("native_hold");
            }
            "reason-substituted" => {
                changed["native_hold"]["hold"]["reason"] =
                    Value::String("legacy_deployment_unavailable".into());
            }
            "operation-substituted" => {
                changed["native_hold"]["hold"]["operation"]["operation_id"] = serde_json::to_value(
                    before
                        .origin
                        .as_ref()
                        .ok_or("original origin")?
                        .operation
                        .operation_id(),
                )?;
            }
            _ => return Err("unknown hold fault".into()),
        }
        let error=db.execute("UPDATE admission_operation_recovery_records SET version=version+1,payload=?1 WHERE record_key=?2",params![chio_core::canonical_json_bytes(&changed)?,&quota.key]);
        assert!(error.is_err(), "{fault}: immutable historical hold changed");
    }
    assert!(db
        .execute(
            "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
            [&quota.key]
        )
        .is_err());
    drop(db);
    let reopened = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    assert_eq!(
        reopened.record(&before.workflow_id)?.control,
        WorkflowControlV1::Quarantined
    );
    assert_eq!(
        read_quota_row(directory.path(), &physical, &before.workflow_id)?.payload,
        quota.payload
    );
    assert_eq!(external_count(directory.path())?, 1);
    Ok(())
}
