//! Genuine captured holds stay visible through the current quota projection.
use super::super::command_quotas::protected_usage;
use super::*;
use rusqlite::{Connection, OpenFlags};

fn retained_quota(
    fixture: &RecoveryFixture,
    scope: &RecoveryScopeV1,
    id: &WorkflowId,
) -> TestResult<(u64, Vec<u8>)> {
    let scope_hash = chio_core::sha256_hex(&chio_core::canonical_json_bytes(scope)?);
    let key = format!("workflow-quota:{scope_hash}:{}", id.as_str());
    let connection = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (version, payload): (i64, Vec<u8>) = connection.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((u64::try_from(version)?, payload))
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_authentic_pre_hold_quota_cannot_hide_captured_isolation() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let physical_before = retained_workflow(directory.path())?;
    let physical_bytes = chio_core::canonical_json_bytes(&physical_before)?;
    let native_before = native_original_bytes(directory.path(), &physical_before)?;
    let return_before = captured_return_bytes(directory.path(), &physical_before)?;
    assert!(physical_before.captured);
    assert!(physical_before.historical_hold.is_none());
    assert_eq!(external_count(directory.path())?, 1);
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
    let held = fixture.record(&physical_before.workflow_id)?;
    assert_eq!(held.control, WorkflowControlV1::Quarantined);
    assert!(held.historical_hold.is_some());
    let quota_before = retained_quota(&fixture, &held.scope, &held.workflow_id)?;
    let usage_before = protected_usage(&fixture)?;
    assert_eq!(
        fixture
            .authority
            .admission_operation_store()
            .verify_recovery_quota_retained_head_for_test(&held.scope, &held.workflow_id)?,
        1,
        "the authentic previous quota hid an already captured owning hold",
    );
    assert_eq!(
        retained_quota(&fixture, &held.scope, &held.workflow_id)?,
        quota_before
    );
    assert_eq!(protected_usage(&fixture)?, usage_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(directory.path())?)?,
        physical_bytes
    );
    assert_eq!(
        native_original_bytes(directory.path(), &physical_before)?,
        native_before
    );
    assert_eq!(
        captured_return_bytes(directory.path(), &physical_before)?,
        return_before
    );
    let after = fixture.record(&held.workflow_id)?;
    assert_eq!(after.historical_hold, held.historical_hold);
    assert_eq!(after.control, WorkflowControlV1::Quarantined);
    assert_eq!(external_count(directory.path())?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}
