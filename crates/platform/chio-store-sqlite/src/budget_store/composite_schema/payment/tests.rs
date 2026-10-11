//! Physical migration and compare-and-set controls; no rail effects occur here.
use super::*;
use chio_kernel::payment::{
    PaymentAuthorizationAttempt, PaymentJournalRecord, PaymentJournalState,
    PaymentJournalTransition, PaymentRailMode,
};
use rusqlite::types::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn parent(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE budget_authorization_holds(hold_id TEXT PRIMARY KEY);")
}
fn fields(connection: &Connection) -> rusqlite::Result<Vec<Vec<Value>>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {COLUMNS} FROM payment_journal ORDER BY operation_id"
    ))?;
    let count = statement.column_count();
    let rows = statement
        .query_map([], |row| (0..count).map(|index| row.get(index)).collect())?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
fn initial() -> PaymentJournalRecord {
    PaymentJournalRecord {
        operation_id: "physical-budget12-op".into(),
        journal_version: 1,
        request_namespace_digest: "a".repeat(64),
        request_id: "physical-budget12-request".into(),
        capability_id: "physical-budget12-cap".into(),
        grant_index: 0,
        hold_id: Some("physical-budget12-hold".into()),
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

#[test]
fn budget12_populated_migration_preserves_original_fields_and_evidence_across_reopen() -> TestResult
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("physical-budget12.db");
    let mut connection = Connection::open(&database)?;
    parent(&connection)?;
    connection.execute_batch(LEGACY)?;
    connection.execute(
        "INSERT INTO budget_authorization_holds VALUES('legacy-hold')",
        [],
    )?;
    connection.execute(
        "INSERT INTO payment_journal(operation_id,journal_version,request_namespace_digest,request_id,capability_id,grant_index,
         hold_id,rail,rail_mode,authorization_id,amount_units,currency,state,created_at_unix_ms,updated_at_unix_ms)
         VALUES('legacy-op',2,?1,'legacy-request','legacy-cap',0,'legacy-hold','legacy-rail','prepaid_final','actual-legacy-prepayment',10,'USD','settled',1,2)", ["b".repeat(64)])?;
    connection.execute_batch("CREATE TABLE retained_payment_evidence(operation_id TEXT PRIMARY KEY REFERENCES payment_journal(operation_id), bytes BLOB NOT NULL);")?;
    let evidence = b"original-retained-evidence-bytes";
    connection.execute(
        "INSERT INTO retained_payment_evidence VALUES('legacy-op',?1)",
        [evidence.as_slice()],
    )?;
    let before = fields(&connection)?;
    let transaction = connection.transaction()?;
    ensure(&transaction, 11)?;
    transaction.commit()?;
    assert_eq!(fields(&connection)?, before);
    let legacy =
        crate::budget_store::payment_journal::load_payment_journal(&connection, "legacy-op")?
            .ok_or("legacy journal")?;
    assert_eq!(
        legacy.authorization_attempt, None,
        "absence remains unknown"
    );
    assert_eq!(
        legacy.authorized_amount_units, None,
        "exposure cannot invent a debit"
    );
    assert_eq!(
        legacy.authorization_id.as_deref(),
        Some("actual-legacy-prepayment")
    );
    assert!(!legacy.is_compensated_before_dispatch());
    drop(connection);
    let mut reopened = Connection::open(&database)?;
    reopened.execute_batch("PRAGMA foreign_keys=ON")?;
    let transaction = reopened.transaction()?;
    ensure(&transaction, 12)?;
    transaction.commit()?;
    assert_eq!(fields(&reopened)?, before);
    let retained: Vec<u8> = reopened.query_row(
        "SELECT bytes FROM retained_payment_evidence WHERE operation_id='legacy-op'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retained, evidence);
    assert!(reopened
        .execute(
            "UPDATE payment_journal SET authorized_amount_units=10 WHERE operation_id='legacy-op'",
            []
        )
        .is_err());
    assert!(reopened.execute("UPDATE payment_journal SET authorization_attempt='not_started' WHERE operation_id='legacy-op'", []).is_err());
    Ok(())
}

#[test]
fn budget12_attempt_marker_cas_is_idempotent_and_survives_commit_before_rail() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("physical-attempt-cas.db");
    let mut connection = Connection::open(&database)?;
    parent(&connection)?;
    let transaction = connection.transaction()?;
    ensure(&transaction, 0)?;
    transaction.execute(
        "INSERT INTO budget_authorization_holds VALUES('physical-budget12-hold')",
        [],
    )?;
    let original = initial();
    crate::budget_store::payment_journal::insert_payment_journal(&transaction, &original)?;
    transaction.commit()?;
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
    drop(connection); // Crash after marker, before the test invokes any rail.
    let mut reopened = Connection::open(&database)?;
    reopened.execute_batch("PRAGMA foreign_keys=ON")?;
    let retained = crate::budget_store::payment_journal::load_payment_journal(
        &reopened,
        &original.operation_id,
    )?
    .ok_or("retained attempt")?;
    assert_eq!(
        retained.authorization_attempt,
        Some(PaymentAuthorizationAttempt::Started)
    );
    assert_eq!(retained.authorization_id, None);
    assert!(!retained.is_compensated_before_dispatch());
    assert!(reopened
        .execute(
            "UPDATE payment_journal SET authorization_attempt='not_started' WHERE operation_id=?1",
            [&original.operation_id]
        )
        .is_err());
    assert!(reopened
        .execute(
            "UPDATE payment_journal SET authorized_amount_units=6 WHERE operation_id=?1",
            [&original.operation_id]
        )
        .is_err());
    let transaction = reopened.transaction()?;
    let mut wrong = original.clone();
    wrong.authorized_amount_units = Some(6);
    assert!(
        crate::budget_store::payment_journal::advance_payment_journal(
            &transaction,
            &wrong,
            &PaymentJournalTransition::BeginAuthorizationAttempt,
            None,
            3
        )
        .is_err()
    );
    transaction.rollback()?;
    Ok(())
}

#[test]
fn budget12_declared_or_partial_catalog_never_gets_silently_repaired() -> TestResult {
    let mut missing = Connection::open_in_memory()?;
    parent(&missing)?;
    let transaction = missing.transaction()?;
    assert!(ensure(&transaction, 12).is_err());
    transaction.rollback()?;
    for corrupt in [
        "DROP TRIGGER payment_journal_identity_immutable",
        "DROP TRIGGER payment_journal_authorization_attempt_monotone",
        "CREATE TABLE payment_journal_future_alias(value INTEGER)",
    ] {
        let mut connection = Connection::open_in_memory()?;
        parent(&connection)?;
        connection.execute_batch(SCHEMA)?;
        connection.execute_batch(corrupt)?;
        let transaction = connection.transaction()?;
        assert!(ensure(&transaction, 12).is_err());
        transaction.rollback()?;
    }
    let mut future = Connection::open_in_memory()?;
    parent(&future)?;
    future.execute_batch(LEGACY)?;
    future
        .execute_batch("ALTER TABLE payment_journal ADD COLUMN unauthorized_future_field TEXT")?;
    let transaction = future.transaction()?;
    assert!(ensure(&transaction, 11).is_err());
    transaction.rollback()?;
    Ok(())
}

#[test]
fn budget12_migrates_supported_predecessor_with_equivalent_whitespace() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    parent(&connection)?;
    let formatted = LEGACY
        .replace("CHECK (", "CHECK\n\t (")
        .replace(" AND ", " \n AND \t ");
    connection.execute_batch(&formatted)?;
    let transaction = connection.transaction()?;
    ensure(&transaction, 11)?;
    transaction.commit()?;
    let transaction = connection.transaction()?;
    ensure(&transaction, 12)?;
    transaction.commit()?;
    Ok(())
}

#[test]
fn budget12_rejects_changed_predecessor_constraints_and_quoted_literals() -> TestResult {
    for changed in [
        LEGACY.replace("length(hold_id) <= 512", "length(hold_id) <= 513"),
        LEGACY.replace(
            "'payment journal identity is immutable'",
            "'payment  journal identity is immutable'",
        ),
    ] {
        let mut connection = Connection::open_in_memory()?;
        parent(&connection)?;
        connection.execute_batch(&changed)?;
        let transaction = connection.transaction()?;
        assert!(ensure(&transaction, 11).is_err());
        transaction.rollback()?;
    }
    Ok(())
}

#[test]
fn budget12_downgraded_current_catalog_is_not_a_supported_predecessor() -> TestResult {
    for declared_version in [0, 1, 3, 6, 9, 10, 11] {
        let mut connection = Connection::open_in_memory()?;
        parent(&connection)?;
        connection.execute_batch(SCHEMA)?;
        let transaction = connection.transaction()?;
        assert!(matches!(
            ensure(&transaction, declared_version),
            Err(BudgetStoreError::Invariant(reason))
                if reason == "pre-schema12 payment journal catalog is not a supported predecessor"
        ));
        transaction.rollback()?;
    }
    Ok(())
}

#[test]
fn budget12_pre_cancel_catalog_is_rejected_from_version11_onward() -> TestResult {
    for (declared_version, expected_reason) in [
        (
            11,
            "pre-schema12 payment journal catalog is not a supported predecessor",
        ),
        (12, "schema12 payment journal catalog differs"),
    ] {
        let mut connection = Connection::open_in_memory()?;
        parent(&connection)?;
        connection.execute_batch(&LEGACY.replace(CANCELLED_BRANCH, ""))?;
        let transaction = connection.transaction()?;
        assert!(matches!(
            ensure(&transaction, declared_version),
            Err(BudgetStoreError::Invariant(reason)) if reason == expected_reason
        ));
        transaction.rollback()?;
    }
    Ok(())
}
