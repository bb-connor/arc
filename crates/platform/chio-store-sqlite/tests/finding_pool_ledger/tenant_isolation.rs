use super::*;

#[test]
fn cognition_market_debit_resolves_tenant_from_authenticated_session_context() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let database = directory.path().join("finding-pool.sqlite3");
    let ledger = open_qualified(&database, ledger_domain()).test_expect("open qualified ledger");
    let fixture = fixture(100, &ledger);
    let purchase_id = "purchase:authenticated-tenant";

    debit_at_with_policy_and_authority_and_tenant(
        &ledger,
        &fixture,
        purchase_id,
        10,
        2_000,
        None,
        None,
        Arc::new(AtomicU64::new(0)),
        false,
        Keypair::from_seed(&[99_u8; 32]),
        fixture.authority.public_key(),
        false,
        Some("tenant-A"),
        SessionState::Ready,
    )
    .test_expect("reserve against authenticated tenant context");

    let connection = rusqlite::Connection::open(&database).test_expect("open tenant ledger");
    let tenant_id: Option<String> = connection
        .query_row(
            "SELECT tenant_id FROM finding_pool_debits WHERE purchase_id = ?1",
            [purchase_id],
            |row| row.get(0),
        )
        .test_expect("load reserved tenant");
    assert_eq!(tenant_id.as_deref(), Some("tenant-A"));
    drop(connection);
    drop(ledger);
    let ledger = open_qualified(&database, ledger_domain()).test_expect("reopen tenant ledger");
    for tenant in ["tenant-B", "tenant-A"] {
        let replay = debit_at_with_policy_and_authority_and_tenant(
            &ledger,
            &fixture,
            purchase_id,
            10,
            2_000,
            None,
            None,
            Arc::new(AtomicU64::new(0)),
            false,
            Keypair::from_seed(&[99_u8; 32]),
            fixture.authority.public_key(),
            false,
            Some(tenant),
            SessionState::Ready,
        );
        if tenant == "tenant-B" {
            assert!(matches!(
                replay,
                Err(FindingPoolDebitError::Ledger(
                    FindingPoolLedgerError::ReplayConflict
                ))
            ));
        } else {
            assert_eq!(
                replay.test_expect("owned exact replay").purchase_id,
                purchase_id
            );
        }
    }
    assert_eq!(
        ledger
            .reserved_units(&fixture.envelope_sha256)
            .test_expect("unchanged reservation"),
        Some(10)
    );
}
