//! Actual native custody across a process abort, restart, settlement and replay.
use super::*;

fn custody_phases(path: &std::path::Path, account: &str) -> TestResult<Vec<String>> {
    let journal = rusqlite::Connection::open_with_flags(
        path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = journal.prepare(
        "SELECT phase FROM process_native_return_events WHERE account_digest=?1 ORDER BY sequence",
    )?;
    let phases = statement
        .query_map([account], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(phases)
}

pub(super) fn native_account(
    path: &std::path::Path,
    operation: &str,
) -> TestResult<serde_json::Value> {
    let database = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let bytes: Vec<u8> = database.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [format!("native-finishing-account:{operation}")],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(unix)]
#[tokio::test]
async fn complete_native_lifecycle_aborts_after_capture_settles_releases_and_replays_once(
) -> TestResult {
    // The child invokes the real public continuation and aborts after its
    // external effect and raw-return commit, before native finalization.
    let directory = super::authority_history::crash_after_capture("return-recorded").await?;
    let path = directory.path();
    let interrupted = super::authority_history::retained_workflow(path)?;
    assert!(interrupted.captured);
    let intent = interrupted
        .admission
        .as_ref()
        .ok_or("captured native intent absent")?;
    let operation = intent.native_operation_id.as_str();
    let before = native_account(path, operation)?;
    assert_eq!(
        before["state"], "confirmed",
        "the cut must leave genuine outstanding funding"
    );
    assert!(before["liabilities"]
        .as_array()
        .ok_or("liabilities absent")?
        .iter()
        .any(|purpose| purpose["disposition"] == "outstanding"));
    let journal = rusqlite::Connection::open_with_flags(
        path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let account: String = journal.query_row(
        "SELECT account_digest FROM process_native_return_accounts WHERE native_operation_id=?1",
        [operation],
        |row| row.get(0),
    )?;
    let charged: u32 = journal.query_row(
        "SELECT tree_calls FROM processes WHERE id='root'",
        [],
        |row| row.get(0),
    )?;
    drop(journal);
    let phases = custody_phases(path, &account)?;
    assert_eq!(phases.first().map(String::as_str), Some("enrolled"));
    assert!(
        !phases.iter().any(|phase| phase == "reconciled"),
        "the cut must precede Process settlement"
    );
    assert_eq!(external_count(path)?, 1);
    assert_eq!(charged, 2, "original denial and one continuation charge");

    // Normal startup owns native reconciliation, followed by Process custody.
    // It must use the retained source without submitting the effect again.
    let fixture = RecoveryFixture::open(path.to_path_buf(), None, false)?;
    let settled = fixture
        .runtime
        .settle(&fixture.control, &interrupted.workflow_id)?;
    assert!(
        matches!(settled.effect, EffectObservationV1::Complete { .. }),
        "the captured operation must settle its actual completed effect: {:?}",
        settled.effect
    );
    assert_eq!(external_count(path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, charged);
    let after = native_account(path, operation)?;
    assert_eq!(
        after["identity"], before["identity"],
        "restart must preserve original funding identity"
    );
    assert_eq!(after["state"], "settled");
    assert!(after["liabilities"]
        .as_array()
        .ok_or("liabilities absent")?
        .iter()
        .all(|purpose| purpose["disposition"] != "outstanding"));
    let phases = custody_phases(path, &account)?;
    assert!(phases.iter().any(|phase| phase == "native_custody"));
    assert!(phases.iter().any(|phase| phase == "reconciled"));

    let resume: RecoveryCommandV1 =
        serde_json::from_slice(&std::fs::read(path.join("resume.json"))?)?;
    let first = fixture
        .runtime
        .execute_command(&fixture.control, &resume)
        .await?;
    let receipt = first
        .original_response
        .ok_or("retained original response absent")?
        .receipt;
    assert!(receipt.verify_signature()?);
    let replay = fixture
        .runtime
        .execute_command(&fixture.control, &resume)
        .await?;
    assert_eq!(
        chio_core::canonical_json_bytes(&receipt)?,
        chio_core::canonical_json_bytes(
            &replay
                .original_response
                .ok_or("replay lost the original response")?
                .receipt
        )?
    );
    assert_eq!(external_count(path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, charged);
    assert_eq!(
        native_account(path, operation)?,
        after,
        "replay cannot spend or release funding twice"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn interrupted_process_enrollment_confirms_and_settles_its_no_future_return() -> TestResult {
    let directory = super::authority_history::crash_after_capture("finishing-enrolled").await?;
    let path = directory.path();
    let workflow = super::authority_history::retained_workflow(path)?;
    let operation = workflow
        .admission
        .as_ref()
        .ok_or("original admission absent")?
        .native_operation_id
        .as_str();
    let before = native_account(path, operation)?;
    assert_eq!(before["state"], "prepared");
    assert!(before["process_enrollment"].is_null());
    let journal = rusqlite::Connection::open_with_flags(
        path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (account, original_bytes): (String, Vec<u8>) = journal.query_row(
        "SELECT account_digest,account_json FROM process_native_return_accounts WHERE native_operation_id=?1",
        [operation], |row| Ok((row.get(0)?, row.get(1)?)))?;
    drop(journal);
    assert_eq!(custody_phases(path, &account)?, ["enrolled"]);
    assert_eq!(external_count(path)?, 0);

    // Startup authenticates the actual Process enrollment before confirming
    // its native counterpart. Native compensation of the undispatched call
    // cannot discard the Process debt ahead of that reconciliation.
    let fixture = RecoveryFixture::open(path.to_path_buf(), None, false)?;
    let after = native_account(path, operation)?;
    assert_eq!(after["identity"], before["identity"]);
    assert_eq!(after["state"], "settled");
    assert_eq!(after["process_enrollment"]["account_digest"], account);
    assert!(after["liabilities"]
        .as_array()
        .ok_or("liabilities absent")?
        .iter()
        .all(|purpose| purpose["disposition"] != "outstanding"));
    assert_eq!(
        custody_phases(path, &account)?,
        ["enrolled", "native_custody", "reconciled"]
    );
    let journal = rusqlite::Connection::open_with_flags(
        path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let retained_bytes: Vec<u8> = journal.query_row(
        "SELECT account_json FROM process_native_return_accounts WHERE account_digest=?1",
        [&account],
        |row| row.get(0),
    )?;
    assert_eq!(retained_bytes, original_bytes);
    drop(journal);
    let process = fixture.process.process("root")?;
    fixture.process.checkpoint(
        "root",
        process.checkpoint.revision,
        serde_json::json!({"restored_enrollment":true}),
    )?;
    assert_eq!(
        fixture.process.process("root")?.tree_calls,
        process.tree_calls
    );
    assert_eq!(external_count(path)?, 0);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn interrupted_native_preparation_releases_only_its_unenrolled_compensated_account(
) -> TestResult {
    let directory = super::authority_history::crash_after_capture("finishing-prepared").await?;
    let path = directory.path();
    let workflow = super::authority_history::retained_workflow(path)?;
    let operation = workflow
        .admission
        .as_ref()
        .ok_or("original admission absent")?
        .native_operation_id
        .as_str();
    let before = native_account(path, operation)?;
    assert_eq!(before["state"], "prepared");
    assert!(before["process_enrollment"].is_null());
    assert!(before["liabilities"]
        .as_array()
        .ok_or("liabilities absent")?
        .iter()
        .all(|purpose| purpose["disposition"] == "outstanding"));
    let enrollment_count = || -> TestResult<i64> {
        let journal = rusqlite::Connection::open_with_flags(
            path.join("process.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(journal.query_row(
            "SELECT count(*) FROM process_native_return_accounts WHERE native_operation_id=?1",
            [operation],
            |row| row.get(0),
        )?)
    };
    assert_eq!(enrollment_count()?, 0);
    assert_eq!(external_count(path)?, 0);
    let fixture = RecoveryFixture::open(path.to_path_buf(), None, false)?;
    let after = native_account(path, operation)?;
    assert_eq!(after["identity"], before["identity"]);
    assert_eq!(after["state"], "settled");
    assert!(after["process_enrollment"].is_null());
    assert!(after["liabilities"]
        .as_array()
        .ok_or("liabilities absent")?
        .iter()
        .all(|purpose| purpose["disposition"] == "released"));
    assert_eq!(
        enrollment_count()?,
        0,
        "startup cannot invent Process enrollment"
    );
    let process = fixture.process.process("root")?;
    fixture.process.checkpoint(
        "root",
        process.checkpoint.revision,
        serde_json::json!({"unenrolled_original_released":true}),
    )?;
    assert_eq!(native_account(path, operation)?, after);
    assert_eq!(
        fixture.process.process("root")?.tree_calls,
        process.tree_calls
    );
    assert_eq!(external_count(path)?, 0);
    Ok(())
}
