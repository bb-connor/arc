//! Payment custody, catalog integrity and compare-and-set contracts.
use super::*;
use chio_kernel::payment::{
    PaymentAuthorizationAttempt, PaymentJournalRecord, PaymentJournalState,
    PaymentJournalTransition, PaymentRailMode,
};
use rusqlite::types::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fields(connection: &Connection, sql: &str) -> rusqlite::Result<Vec<Vec<Value>>> {
    let mut statement = connection.prepare(sql)?;
    let count = statement.column_count();
    let rows = statement
        .query_map([], |row| (0..count).map(|index| row.get(index)).collect())?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[derive(Debug, PartialEq)]
struct DatabaseSnapshot {
    application_id: i32,
    user_version: i32,
    journal_mode: String,
    catalog: Vec<Vec<Value>>,
    tables: Vec<(String, Vec<Vec<Value>>)>,
}

fn snapshot(connection: &Connection) -> TestResult<DatabaseSnapshot> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        let quoted = name.replace('"', "\"\"");
        tables.push((
            name,
            fields(
                connection,
                &format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"),
            )?,
        ));
    }
    Ok(DatabaseSnapshot {
        application_id: connection.query_row("PRAGMA application_id", [], |row| row.get(0))?,
        user_version: connection.query_row("PRAGMA user_version", [], |row| row.get(0))?,
        journal_mode: connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?,
        catalog: fields(
            connection,
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name",
        )?,
        tables,
    })
}

fn initial() -> PaymentJournalRecord {
    PaymentJournalRecord {
        operation_id: "physical-payment-op".into(),
        journal_version: 1,
        request_namespace_digest: "a".repeat(64),
        request_id: "physical-payment-request".into(),
        capability_id: "physical-payment-cap".into(),
        grant_index: 0,
        hold_id: Some("physical-payment-hold".into()),
        rail: "test-reversible-rail".into(),
        rail_mode: PaymentRailMode::ReversibleHold,
        authorization_id: None,
        transaction_id: None,
        amount_units: 10,
        authorized_amount_units: Some(5),
        authorization_attempt: Some(PaymentAuthorizationAttempt::NotStarted),
        settle_action: None,
        settle_amount_units: None,
        release_authority: None,
        currency: "USD".into(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1,
    }
}

fn populate(database: &Path, prepaid: bool) -> TestResult<PaymentJournalRecord> {
    let store = SqliteBudgetStore::open(database)?;
    let mut original = initial();
    if prepaid {
        original.rail_mode = PaymentRailMode::PrepaidFinal;
        original.rail = "test-prepaid-rail".into();
    }
    let authorized = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: original.capability_id.clone(),
        grant_index: 0,
        max_invocations: Some(2),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: original.amount_units,
        max_cost_per_invocation: Some(original.amount_units),
        max_total_cost_units: Some(100),
        hold_id: original.hold_id.clone(),
        event_id: Some("physical-payment-authorize".into()),
        authority: None,
    })?;
    assert!(matches!(
        authorized,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let mut connection = store.connection()?;
    let transaction = connection.transaction()?;
    crate::budget_store::payment_journal::insert_payment_journal(&transaction, &original)?;
    if prepaid {
        let (attempted, changed) = crate::budget_store::payment_journal::advance_payment_journal(
            &transaction,
            &original,
            &PaymentJournalTransition::BeginAuthorizationAttempt,
            None,
            2,
        )?;
        assert!(changed);
        let (settled, changed) = crate::budget_store::payment_journal::advance_payment_journal(
            &transaction,
            &attempted,
            &PaymentJournalTransition::PrepaymentSettled {
                authorization_id: "recorded-prepayment".into(),
            },
            None,
            3,
        )?;
        assert!(changed);
        original = settled;
    }
    transaction.commit()?;
    drop(connection);
    drop(store);
    drop(SqliteBudgetStore::open(database)?);
    Ok(original)
}

fn assert_invariant<T>(result: Result<T, BudgetStoreError>, expected: &str) {
    match result {
        Err(BudgetStoreError::Invariant(reason)) => assert_eq!(reason, expected),
        Err(error) => panic!("unexpected budget error: {error:?}"),
        Ok(_) => panic!("invalid budget state was accepted"),
    }
}

fn assert_stale<T>(result: Result<T, BudgetStoreError>, found: i32) {
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("noncurrent budget schema was accepted"),
    };
    assert_eq!(
        error.to_string(),
        format!(
            "database schema version {found} is not the current schema version 1; refusing to open"
        )
    );
    match error {
        BudgetStoreError::StaleSchema {
            found: actual,
            current,
        } => {
            assert_eq!((actual, current), (found, 1));
        }
        error => panic!("unexpected budget error: {error:?}"),
    }
}

fn assert_trigger(result: rusqlite::Result<usize>, expected: &str) {
    assert!(matches!(result,
        Err(rusqlite::Error::SqliteFailure(code, Some(message)))
            if code.code == rusqlite::ErrorCode::ConstraintViolation
                && code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER
                && message == expected
    ));
}

#[test]
fn noncurrent_stamps_preserve_populated_payment_and_evidence() -> TestResult {
    for found in [0, 2, 11, 12, 99] {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("payment-stamp-refusal.db");
        let original = populate(&database, true)?;
        assert_eq!(original.state, PaymentJournalState::Settled);
        assert_eq!(original.authorized_amount_units, Some(5));
        assert_eq!(
            original.authorization_id.as_deref(),
            Some("recorded-prepayment")
        );
        let connection = Connection::open(&database)?;
        connection.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE retained_payment_evidence(operation_id TEXT PRIMARY KEY REFERENCES payment_journal(operation_id), bytes BLOB NOT NULL);")?;
        connection.execute(
            "INSERT INTO retained_payment_evidence VALUES(?1,?2)",
            params![
                &original.operation_id,
                b"retained-payment-evidence".as_slice()
            ],
        )?;
        crate::test_schema::write_version(&connection, "budget", found)?;
        let before = snapshot(&connection)?;
        for _ in 0..2 {
            assert_stale(SqliteBudgetStore::open(&database), found);
            assert_eq!(snapshot(&connection)?, before);
        }
        assert_stale(SqliteBudgetStore::open(&database), found);
        assert_eq!(snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn payment_attempt_cas_is_idempotent_and_survives_reopen_without_rail_authorization() -> TestResult
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("physical-attempt-cas.db");
    let original = populate(&database, false)?;
    let mut connection = Connection::open(&database)?;
    connection.execute_batch("PRAGMA foreign_keys=ON")?;
    {
        let transaction = connection.transaction()?;
        crate::budget_store::payment_journal::advance_payment_journal(
            &transaction,
            &original,
            &PaymentJournalTransition::BeginAuthorizationAttempt,
            None,
            2,
        )?;
        transaction.rollback()?;
    }
    assert_eq!(
        crate::budget_store::payment_journal::load_payment_journal(
            &connection,
            &original.operation_id
        )?,
        Some(original.clone())
    );
    let transaction = connection.transaction()?;
    let (attempted, changed) = crate::budget_store::payment_journal::advance_payment_journal(
        &transaction,
        &original,
        &PaymentJournalTransition::BeginAuthorizationAttempt,
        None,
        2,
    )?;
    assert!(changed);
    let (replayed, changed) = crate::budget_store::payment_journal::advance_payment_journal(
        &transaction,
        &original,
        &PaymentJournalTransition::BeginAuthorizationAttempt,
        None,
        2,
    )?;
    assert!(!changed);
    assert_eq!(replayed, attempted);
    transaction.commit()?;
    drop(connection);
    drop(SqliteBudgetStore::open(&database)?);
    let mut reopened = Connection::open(&database)?;
    reopened.execute_batch("PRAGMA foreign_keys=ON")?;
    let retained = crate::budget_store::payment_journal::load_payment_journal(
        &reopened,
        &original.operation_id,
    )?
    .ok_or("retained attempt")?;
    assert_eq!(retained, attempted);
    assert_eq!(
        retained.authorization_attempt,
        Some(PaymentAuthorizationAttempt::Started)
    );
    assert_eq!(retained.authorization_id, None);
    assert!(!retained.is_compensated_before_dispatch());
    let before = snapshot(&reopened)?;
    assert_trigger(
        reopened.execute(
            "UPDATE payment_journal SET authorization_attempt='not_started' WHERE operation_id=?1",
            [&original.operation_id],
        ),
        "payment authorization attempt is monotone",
    );
    assert_trigger(
        reopened.execute(
            "UPDATE payment_journal SET authorized_amount_units=6 WHERE operation_id=?1",
            [&original.operation_id],
        ),
        "payment journal identity is immutable",
    );
    assert_trigger(
        reopened.execute(
            "DELETE FROM payment_journal WHERE operation_id=?1",
            [&original.operation_id],
        ),
        "payment journal is append-preserving",
    );
    let transaction = reopened.transaction()?;
    let mut wrong = original.clone();
    wrong.authorized_amount_units = Some(6);
    assert_invariant(
        crate::budget_store::payment_journal::advance_payment_journal(
            &transaction,
            &wrong,
            &PaymentJournalTransition::BeginAuthorizationAttempt,
            None,
            3,
        ),
        "payment journal compare-and-set conflicted",
    );
    transaction.rollback()?;
    assert_eq!(snapshot(&reopened)?, before);
    Ok(())
}

#[test]
fn current_payment_catalog_corruption_is_refused_without_repair() -> TestResult {
    for corrupt in [
        "DROP TABLE payment_journal",
        "DROP TRIGGER payment_journal_identity_immutable",
        "DROP TRIGGER payment_journal_authorization_attempt_monotone",
        "CREATE TABLE payment_journal_future_alias(value INTEGER)",
    ] {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("payment-catalog-refusal.db");
        drop(SqliteBudgetStore::open(&database)?);
        let connection = Connection::open(&database)?;
        connection.execute_batch(corrupt)?;
        let before = snapshot(&connection)?;
        assert_invariant(
            SqliteBudgetStore::open(&database),
            "budget schema does not match the current v1 shape",
        );
        assert_eq!(snapshot(&connection)?, before);
    }
    Ok(())
}

fn create_catalog(database: &Path, sql: &str) -> TestResult {
    let connection = Connection::open(database)?;
    connection.execute_batch(sql)?;
    connection.pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)?;
    crate::test_schema::write_version(&connection, "budget", 1)?;
    Ok(())
}

#[test]
fn standalone_creation_requires_the_canonical_catalog_text() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("payment-catalog-whitespace.db");
    let formatted = SCHEMA
        .replace("CHECK (", "CHECK\n\t (")
        .replace(" AND ", " \n AND \t ");
    assert_ne!(formatted, SCHEMA);
    create_catalog(&database, &formatted)?;
    verify_budget_catalog(&Connection::open(&database)?)?;
    let connection = Connection::open(&database)?;
    let before = snapshot(&connection)?;
    for _ in 0..2 {
        assert_invariant(
            SqliteBudgetStore::open(&database),
            "schema catalog differs from its canonical definition",
        );
        assert_eq!(snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn current_catalog_rejects_changed_payment_constraints_and_quoted_literals() -> TestResult {
    for changed in [
        SCHEMA.replace("length(hold_id) <= 512", "length(hold_id) <= 513"),
        SCHEMA.replace(
            "'payment journal identity is immutable'",
            "'payment  journal identity is immutable'",
        ),
    ] {
        assert_ne!(changed, SCHEMA);
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("payment-catalog-contract.db");
        create_catalog(&database, &changed)?;
        let connection = Connection::open(&database)?;
        let before = snapshot(&connection)?;
        assert_invariant(
            verify_budget_catalog(&connection),
            "budget schema does not match the current v1 shape",
        );
        assert_invariant(
            SqliteBudgetStore::open(&database),
            "budget schema does not match the current v1 shape",
        );
        assert_eq!(snapshot(&connection)?, before);
    }
    Ok(())
}
