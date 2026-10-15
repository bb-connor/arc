//! Funded caller shares are indexed by delegation parent. The indexed snapshot
//! must return exactly what verifying every live operation returns.

use super::*;
use crate::admission_operation_store::caller_budget::{read_by_full_scan, CANDIDATES_SQL};
use chio_kernel::admission_operation::AdmissionCallerBudgetShare;

type IndexRow = (String, String, Option<String>);

fn funded(transport: &str) -> TestResult<NonceFixture> {
    let mut fixture = advance_nonce_fixture_with_transport(
        prepared_nonce_fixture(None)?,
        true,
        None,
        true,
        Some(transport),
    )?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    Ok(fixture)
}

fn index_rows(database: &std::path::Path) -> TestResult<Vec<IndexRow>> {
    let connection = Connection::open(database)?;
    let mut statement = connection.prepare(
        "SELECT operation_id, parent_kind, parent_capability_id
         FROM admission_operation_caller_shares ORDER BY operation_id",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn root_row(operation: &AdmissionOperationV1) -> IndexRow {
    (
        operation.binding().operation_id().as_str().to_owned(),
        "root".to_owned(),
        None,
    )
}

fn full_scan(
    store: &SqliteAdmissionOperationStore,
    parent: &AdmissionIdentifier,
    now: u64,
) -> Result<Vec<AdmissionCallerBudgetShare>, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let transaction = store.begin_read(&mut connection)?;
    let shares = read_by_full_scan(&transaction, parent, now)?;
    transaction.rollback().map_err(sqlite_error)?;
    Ok(shares)
}

fn assert_indexed_matches_full_scan(
    fixture: &Fixture,
    parent: &AdmissionIdentifier,
) -> TestResult<Vec<AdmissionCallerBudgetShare>> {
    let now = now_ms();
    let indexed = fixture
        .store
        .load_caller_budget_shares(parent, 16, &fixture.fence, now)?;
    assert_eq!(indexed, full_scan(&fixture.store, parent, now)?);
    Ok(indexed)
}

fn transition(
    fixture: &Fixture,
    key: &Keypair,
    operation: &AdmissionOperationV1,
    attachment: AdmissionAttachment,
    state: AdmissionOperationState,
) -> TestResult<AdmissionOperationV1> {
    let command = nonce_command(
        &fixture.store,
        &fixture.fence,
        operation,
        key,
        vec![attachment],
        state,
    )?;
    Ok(fixture
        .store
        .compare_and_swap(&command, now_ms())?
        .into_operation())
}

#[test]
fn a_funded_caller_operation_is_indexed_once_from_its_retained_request() -> TestResult {
    let fixture = funded("caller-report:test-server")?;
    assert!(AdmissionCallerBudgetShare::is_owned_by(&fixture.operation));
    assert_eq!(
        index_rows(&fixture.fixture.database)?,
        vec![root_row(&fixture.operation)]
    );
    let parent = identifier("parent_id", "caller-share-parent");
    assert!(assert_indexed_matches_full_scan(&fixture.fixture, &parent)?.is_empty());

    let kernel_owned = funded("kernel-tool-server:test-server")?;
    assert!(!AdmissionCallerBudgetShare::is_owned_by(
        &kernel_owned.operation
    ));
    assert!(index_rows(&kernel_owned.fixture.database)?.is_empty());
    Ok(())
}

#[test]
fn an_unattributable_funded_caller_operation_denies_every_parent_snapshot() -> TestResult {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "unretained-caller-request",
        "unretained-caller-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    // One claimant drives both transitions, as a single kernel would.
    let key = Keypair::generate();
    let mut attempt = provider_attempt(&operation, "unretained-caller-attempt");
    attempt.transport_id = "caller-report:test-server".into();
    let operation = transition(
        &fixture,
        &key,
        &operation,
        AdmissionAttachment::BrokerAttempt(attempt),
        AdmissionOperationState::BrokerAttemptRegistered,
    )?;
    let operation = transition(
        &fixture,
        &key,
        &operation,
        AdmissionAttachment::BudgetHoldId(identifier("hold", "unretained-caller-hold")),
        AdmissionOperationState::BudgetAuthorized,
    )?;
    assert!(AdmissionCallerBudgetShare::is_owned_by(&operation));
    assert_eq!(
        index_rows(&fixture.database)?,
        vec![(
            operation.binding().operation_id().as_str().to_owned(),
            "unresolved".to_owned(),
            None,
        )]
    );
    for parent in ["caller-share-parent-a", "caller-share-parent-b"] {
        let parent = identifier("parent_id", parent);
        let now = now_ms();
        for result in [
            fixture
                .store
                .load_caller_budget_shares(&parent, 16, &fixture.fence, now),
            full_scan(&fixture.store, &parent, now),
        ] {
            assert!(
                matches!(
                    &result,
                    Err(AdmissionOperationStoreError::Invariant(detail))
                        if detail == "funded caller share lost its retained request"
                ),
                "{result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn caller_share_candidates_are_read_through_indexes() -> TestResult {
    let fixture = funded("caller-report:test-server")?;
    let connection = fixture.fixture.store.connection()?;
    let plan = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {CANDIDATES_SQL}"))?
        .query_map(["caller-share-parent"], |row| row.get::<_, String>(3))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        plan.iter()
            .any(|detail| detail.contains("admission_operation_caller_shares_parent")),
        "{plan:?}"
    );
    assert!(
        !plan.iter().any(|detail| detail.starts_with("SCAN")),
        "{plan:?}"
    );
    Ok(())
}

#[test]
fn restart_rejects_a_missing_or_forged_caller_share_index() -> TestResult {
    for (edit, expected) in [
        (
            "DELETE FROM admission_operation_caller_shares",
            "funded caller share has no parent index",
        ),
        (
            "UPDATE admission_operation_caller_shares
             SET parent_kind = 'delegated', parent_capability_id = 'forged-parent'",
            "caller share parent index disagrees with its retained request",
        ),
    ] {
        let fixture = funded("caller-report:test-server")?;
        let database = fixture.fixture.database.clone();
        let lock_root = fixture.fixture.lock_root.clone();
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch(
                "DROP TRIGGER admission_operation_caller_shares_immutable;
                 DROP TRIGGER admission_operation_caller_shares_no_delete;",
            )?;
            connection.execute_batch(edit)?;
            // Restore the canonical triggers so restart fails on the index
            // contents, not on an intentionally altered schema.
            connection.execute_batch(crate::admission_operation_store::caller_budget::SCHEMA)?;
        }
        drop(fixture.fixture.store);
        drop(fixture.fixture.authority);
        let error = match crate::test_authority::open_serving(&database, &lock_root) {
            Ok(_) => return Err(format!("restart accepted: {edit}").into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
    Ok(())
}
