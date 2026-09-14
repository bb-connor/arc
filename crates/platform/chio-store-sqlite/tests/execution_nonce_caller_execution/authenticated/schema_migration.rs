//! An actual authenticated wait must survive the native v34 to v35 upgrade.
use super::*;
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;
use rusqlite::{types::Value, Connection};

fn rows(connection: &Connection, table: &str) -> TestResult<Vec<Vec<Value>>> {
    let mut query = connection.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let count = query.column_count();
    let rows = query
        .query_map([], |row| (0..count).map(|i| row.get(i)).collect())?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

#[test]
fn v34_waiting_report_migrates_without_replacing_custody_or_renewing_authority() -> TestResult {
    let (fixture, executor_key) = fixture()?;
    let executor = fixture.caller_executor.clone().ok_or("executor")?;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("executor.db"),
        executor,
        4,
    )?;
    let (request, authorization, report) = {
        let runtime = fixture.open()?;
        let request = reserve(&fixture, &runtime, "migrate-original-caller")?;
        let authorization = start(&runtime, &request)?;
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || Ok(super::super::report()),
        )?;
        (request, authorization, report)
    };
    let expires = request.capability.expires_at.max(u64::try_from(
        request
            .execution_nonce
            .as_ref()
            .ok_or("nonce")?
            .expires_at(),
    )?);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, []);
    // Recovery records an authenticated wait before constructing the exact old
    // catalog. No fabricated operation, caller frame or report is inserted.
    drop(fixture.open()?);
    assert_state(&fixture, &request, "awaiting_caller_report")?;
    let connection = Connection::open(fixture.database())?;
    connection.execute_batch(
        "DROP TABLE unknown_payment_release_records;
         UPDATE chio_store_schema_versions SET version=34 WHERE store_key='admission_operation';",
    )?;
    let tables = [
        "admission_operations",
        "admission_operation_commits",
        "authority_global_commits",
    ];
    let before = tables
        .iter()
        .map(|table| rows(&connection, table))
        .collect::<TestResult<Vec<_>>>()?;
    drop(connection);
    chio_store_sqlite::SqliteAuthorityStore::provision(
        fixture.database(),
        fixture.directory.path().join("locks"),
    )?;
    let connection = Connection::open(fixture.database())?;
    let after = tables
        .iter()
        .map(|table| rows(&connection, table))
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(after, before);
    drop(connection);
    let runtime = fixture.open()?;
    assert_eq!(start(&runtime, &request)?, authorization);
    let settled = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
