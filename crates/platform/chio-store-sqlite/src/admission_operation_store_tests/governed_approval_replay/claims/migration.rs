use super::*;

#[test]
fn v23_upgrade_preserves_active_approval_authority_and_owned_claims() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let binding = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(&fixture, "v23-owned-approval")?;
    let intent = candidate(&operation, &binding, "migration-claim", credential)?;
    let (operation, _) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    let retained = fixture.store.load_governed_approval_claim_history(
        operation.binding().operation_id(),
        &fixture.fence,
        now_ms(),
    )?;
    let active =
        fixture
            .store
            .load_governed_approval_activation(&binding, &fixture.fence, now_ms())?;
    let before = global_count(&fixture);
    drop(source);
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
    let connection = Connection::open(&database)?;
    super::super::super::dpop_replay::remove_empty_v24_tables(&connection)?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 23 WHERE store_key = 'admission_operation'")?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    assert_eq!(
        store.load_governed_approval_activation(&binding, &fence, now_ms())?,
        active
    );
    assert_eq!(
        store.load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &fence,
            now_ms()
        )?,
        retained
    );
    assert_eq!(
        store.connection()?.query_row(
            "SELECT COUNT(*) FROM authority_global_commits",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        before
    );
    Ok(())
}
