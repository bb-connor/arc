//! Malformed retained bytes on actual qualified stores, never a serving waiver.
use super::*;

const RECORD_BYTES: usize = 1024 * 1024;

fn committed_fixture(
    label: &str,
) -> Result<(Fixture, AdmissionOperationV1, AdmissionTerminalProjection), Box<dyn std::error::Error>>
{
    let fixture = fixture();
    let at = now_ms();
    let operation = finalizing_tool_operation(&fixture, label, "rc2-capability", at);
    let projection = unknown_projection(&fixture, &operation, "rc2-incident", 'b', at + 20);
    fixture.store.commit_terminal_projection(&projection)?;
    Ok((fixture, operation, projection))
}

fn insert_oversized_receipt(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
) -> AnchoredTestResult {
    let connection = fixture.store.connection()?;
    // Simulate already-corrupt retained storage. Re-enable constraints before
    // invoking the unmodified public serving reader; no authority is minted.
    connection.pragma_update(None, "ignore_check_constraints", true)?;
    connection.execute(
        "INSERT INTO admission_operation_terminal_records
         (operation_id, record_kind, record_id, record_digest, record_json)
         VALUES (?1, 'receipt', 'rc2-large-receipt', ?2, zeroblob(?3))",
        params![
            operation.binding().operation_id().as_str(),
            "a".repeat(64),
            i64::try_from(RECORD_BYTES + 1)?
        ],
    )?;
    connection.pragma_update(None, "ignore_check_constraints", false)?;
    Ok(())
}

fn assert_bounds(error: impl std::fmt::Display) {
    let detail = error.to_string();
    assert!(
        detail.contains("terminal record") && detail.contains("bounds"),
        "reader must refuse the native byte ceiling before later authority/JSON checks: {detail}"
    );
}

#[test]
fn rc2_terminal_receipt_point_refuses_native_byte_bound_before_authority_decode(
) -> AnchoredTestResult {
    let (fixture, operation, _) = committed_fixture("rc2-point")?;
    assert!(fixture
        .store
        .load_chio_receipt("rc2-large-receipt")?
        .is_none());
    insert_oversized_receipt(&fixture, &operation)?;
    let error = fixture
        .store
        .load_chio_receipt("rc2-large-receipt")
        .err()
        .ok_or("oversized point record was accepted")?;
    assert_bounds(error);
    Ok(())
}

#[test]
fn rc2_terminal_receipt_page_refuses_native_byte_bound_without_partial_output() -> AnchoredTestResult
{
    let (fixture, operation, _) = committed_fixture("rc2-page")?;
    assert!(fixture
        .store
        .list_terminal_receipts_after(None, 1)?
        .is_empty());
    insert_oversized_receipt(&fixture, &operation)?;
    let error = fixture
        .store
        .list_terminal_receipts_after(None, 1)
        .err()
        .ok_or("oversized page record was accepted")?;
    assert_bounds(error);
    Ok(())
}

#[test]
fn rc2_terminal_sealed_reopen_refuses_native_byte_bound_before_json_decode() -> AnchoredTestResult {
    let (fixture, operation, _) = committed_fixture("rc2-reopen")?;
    let connection = Connection::open(&fixture.database)?;
    let immutable_trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger'
         AND name = 'admission_operation_terminal_records_immutable'",
        [],
        |row| row.get(0),
    )?;
    // Fault injection only in this private fixture. Restore the exact trigger
    // and constraints before reopening the sealed authority through its API.
    connection.execute_batch("DROP TRIGGER admission_operation_terminal_records_immutable;")?;
    connection.pragma_update(None, "ignore_check_constraints", true)?;
    connection.execute(
        "UPDATE admission_operation_terminal_records SET record_json = zeroblob(?1)
         WHERE operation_id = ?2",
        params![
            i64::try_from(RECORD_BYTES + 1)?,
            operation.binding().operation_id().as_str()
        ],
    )?;
    connection.pragma_update(None, "ignore_check_constraints", false)?;
    connection.execute_batch(&immutable_trigger)?;
    drop(connection);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let error = crate::test_authority::open_serving(&database, &lock_root)
        .err()
        .ok_or("corrupt terminal record was accepted on sealed reopen")?;
    assert_bounds(error);
    drop(_temp);
    Ok(())
}

#[test]
fn rc2_terminal_healthy_sealed_replay_and_empty_paging_remain_supported() -> AnchoredTestResult {
    let (fixture, operation, projection) = committed_fixture("rc2-healthy")?;
    let first = fixture.store.commit_terminal_projection(&projection)?;
    assert_eq!(
        fixture
            .store
            .load_terminal_replay(&operation.replay_key())?,
        Some(first.replay.clone())
    );
    assert!(fixture
        .store
        .list_terminal_receipts_after(None, 1)?
        .is_empty());
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let reopened = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    assert_eq!(
        store.load_terminal_replay(&operation.replay_key())?,
        Some(first.replay)
    );
    assert!(store.list_terminal_receipts_after(None, 1)?.is_empty());
    drop(store);
    drop(reopened);
    drop(_temp);
    Ok(())
}
