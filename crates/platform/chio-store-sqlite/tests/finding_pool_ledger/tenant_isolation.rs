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
        DebitPolicy {
            status_verifier: None,
            status_proof_b64: None,
            purchase_admissions: Arc::new(AtomicU64::new(0)),
            reject_purchase_admission: false,
            kernel_key: Keypair::from_seed(&[99_u8; 32]),
            allocation_authority: fixture.authority.public_key(),
            reject_purchase_verification: false,
            tenant_id: Some("tenant-A"),
            session_state: SessionState::Ready,
        },
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
            DebitPolicy {
                status_verifier: None,
                status_proof_b64: None,
                purchase_admissions: Arc::new(AtomicU64::new(0)),
                reject_purchase_admission: false,
                kernel_key: Keypair::from_seed(&[99_u8; 32]),
                allocation_authority: fixture.authority.public_key(),
                reject_purchase_verification: false,
                tenant_id: Some(tenant),
                session_state: SessionState::Ready,
            },
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
