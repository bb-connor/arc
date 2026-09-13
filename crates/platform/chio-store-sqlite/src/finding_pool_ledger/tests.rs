use super::*;
use chio_core::crypto::{Ed25519Backend, Keypair};
use chio_test_support::prelude::*;

fn rollback_anchor_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = Path::new("/dev/shm").join(format!(
            "chio-finding-pool-unit-anchors-{}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        if let Err(error) = builder.create(&root) {
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                panic!("create test rollback anchor root: {error}");
            }
        }
        root
    })
}

#[cfg(unix)]
#[test]
fn qualified_open_rejects_anchor_on_the_database_snapshot_device() {
    use std::os::unix::fs::PermissionsExt as _;

    let identity = Ed25519Backend::new(Keypair::from_seed(&[71_u8; 32]));
    for (suffix, use_database_root) in [("same-directory", true), ("same-device", false)] {
        let database_root = tempfile::tempdir().test_expect("create database root");
        let anchor_root = tempfile::tempdir().test_expect("create sibling anchor root");
        for root in [database_root.path(), anchor_root.path()] {
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                .test_expect("secure qualification test root");
        }
        let selected_anchor = if use_database_root {
            database_root.path()
        } else {
            anchor_root.path()
        };
        let error = SqliteFindingPoolLedger::open_qualified(
            database_root.path().join("pool.sqlite3"),
            format!("ledger:test-snapshot-domain:{suffix}"),
            &identity,
            selected_anchor,
        )
        .err()
        .test_expect("co-located rollback anchor must fail qualification");
        assert!(matches!(
            error,
            FindingPoolLedgerError::Storage(message)
                if message.contains("shares the protected database snapshot domain")
        ));
    }
}

fn open_qualified(
    path: impl AsRef<Path>,
    ledger_domain: impl Into<String>,
) -> Result<SqliteFindingPoolLedger, FindingPoolLedgerError> {
    let path = path.as_ref();
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .test_expect("secure pool ledger parent");
    }
    let identity = Ed25519Backend::new(Keypair::from_seed(&[70_u8; 32]));
    SqliteFindingPoolLedger::open_qualified(path, ledger_domain, &identity, rollback_anchor_root())
}

#[test]
fn qualified_schema_indexes_pending_outbox_and_expiration_reclamation() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let ledger = open_qualified(directory.path().join("pool.sqlite3"), "ledger:test-indexes")
        .test_expect("open qualified pool ledger");
    let connection = ledger.pool.get().test_expect("open pool ledger connection");
    for index in [
        "finding_pool_receipt_outbox_pending",
        "finding_pool_receipt_outbox_delivery_sequence",
        "finding_pool_debits_expiration_reclamation",
        "finding_pool_debits_expiration_reclamation_v2",
    ] {
        let present = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = ?1)",
                [index],
                |row| row.get::<_, bool>(0),
            )
            .test_expect("query qualified index");
        assert!(present, "qualified schema is missing {index}");
    }
    let mut plan = connection
        .prepare(
            "EXPLAIN QUERY PLAN \
             SELECT receipt_id, signed_receipt_json \
             FROM finding_pool_receipt_outbox \
             WHERE acknowledged_at_unix_ms IS NULL \
               AND (delivery_claim_epoch IS NULL \
                    OR delivery_claim_epoch < ?1 \
                    OR (delivery_claim_epoch = ?1 \
                        AND (delivery_claim_expires_at_unix_ms IS NULL \
                             OR delivery_claim_expires_at_unix_ms <= ?2))) \
             ORDER BY delivery_sequence LIMIT ?3",
        )
        .test_expect("prepare pending outbox query plan");
    let details = plan
        .query_map(params![1_i64, 1_i64, 1_i64], |row| row.get::<_, String>(3))
        .test_expect("query pending outbox plan")
        .collect::<Result<Vec<_>, _>>()
        .test_expect("collect pending outbox plan");
    assert!(details
        .iter()
        .all(|detail| !detail.contains("USE TEMP B-TREE")));
    assert!(details
        .iter()
        .any(|detail| detail.contains("finding_pool_receipt_outbox_pending")));
}

#[cfg(unix)]
#[test]
fn qualified_ledger_binds_validation_to_the_borrowed_database_file() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let database = directory.path().join("pool.sqlite3");
    let replacement = directory.path().join("replacement.sqlite3");
    let ledger = open_qualified(&database, "ledger:test-borrowed-file")
        .test_expect("open qualified pool ledger");
    {
        let connection = ledger.pool.get().test_expect("borrow qualified database");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .test_expect("checkpoint qualified database");
    }
    std::fs::copy(&database, &replacement).test_expect("copy qualified database");
    let borrowed_replacement =
        rusqlite::Connection::open(&replacement).test_expect("open replacement database");

    let error = ledger
        .database_identity
        .validate_connection(&borrowed_replacement)
        .test_expect_err("different borrowed database file must reject");
    assert!(error.to_string().contains("borrowed file identity changed"));
}

#[test]
fn outbox_lease_clock_does_not_regress_with_wall_time() {
    let clock = OutboxLeaseClock::new(1);
    assert_eq!(
        clock
            .nondecreasing_now(10_000)
            .test_expect("initialize lease clock"),
        10_000
    );
    std::thread::sleep(Duration::from_millis(3));
    assert!(
        clock
            .nondecreasing_now(1)
            .test_expect("advance lease clock across rollback")
            > 10_000
    );
}

#[test]
fn leased_outbox_rows_remain_observable_as_pending() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let ledger = open_qualified(
        directory.path().join("pool.sqlite3"),
        "ledger:test-active-outbox-lease",
    )
    .test_expect("open qualified pool ledger");
    let connection = ledger.pool.get().test_expect("open pool ledger connection");
    connection
        .execute(
            "INSERT INTO finding_pool_receipt_outbox (\
                receipt_id, purchase_id, allocation_envelope_sha256, mutation_kind, \
                signed_receipt_json, occurred_at_unix_ms, acknowledged_at_unix_ms, \
                delivery_claim_owner, delivery_claim_expires_at_unix_ms, \
                delivery_claim_epoch, delivery_sequence\
             ) VALUES ('receipt:leased', 'purchase:leased', ?1, 'reserve', '{}', '1', \
                       NULL, 'worker:crashed', 100000, ?2, 1)",
            params![
                "a".repeat(64),
                i64::try_from(ledger.outbox_lease_clock.epoch)
                    .test_expect("lease epoch fits SQLite")
            ],
        )
        .test_expect("seed leased outbox row");
    drop(connection);

    assert!(ledger
        .claim_pending_mutation_receipts("worker:replacement", 1, 60_000, 1)
        .test_expect("active lease produces no duplicate claim")
        .is_empty());
    assert!(ledger
        .has_pending_mutation_receipts()
        .test_expect("pending outbox state remains visible"));
}

#[test]
fn qualified_ledger_rejects_unusable_domains() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    for (suffix, domain) in [("unicode", "ledger:é"), ("spaces", "   ")] {
        assert!(
            open_qualified(directory.path().join(format!("{suffix}.sqlite3")), domain,).is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn qualified_ledger_rejects_a_writable_parent_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777))
        .test_expect("make pool ledger parent unsafe");
    let identity = Ed25519Backend::new(Keypair::from_seed(&[70_u8; 32]));
    let error = SqliteFindingPoolLedger::open_qualified(
        directory.path().join("pool.sqlite3"),
        "ledger:test-unsafe-parent",
        &identity,
        rollback_anchor_root(),
    )
    .test_expect_err("writable parent must not qualify");
    assert!(error.to_string().contains("parent has unsafe ownership"));
}

#[test]
fn qualified_ledger_persists_one_receipt_sink() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let path = directory.path().join("pool.sqlite3");
    let ledger =
        open_qualified(&path, "ledger:test-sink").test_expect("open qualified pool ledger");
    ledger
        .bind_receipt_sink("receipt-sink:first")
        .test_expect("bind first receipt sink");
    ledger
        .bind_receipt_sink("receipt-sink:first")
        .test_expect("replay first receipt sink binding");
    assert_eq!(
        ledger.bind_receipt_sink("receipt-sink:second"),
        Err(FindingPoolLedgerError::ReceiptSinkMismatch)
    );

    let reopened =
        open_qualified(&path, "ledger:test-sink").test_expect("reopen qualified pool ledger");
    reopened
        .bind_receipt_sink("receipt-sink:first")
        .test_expect("reopen with bound receipt sink");
}

#[test]
fn claimed_admission_operation_scan_is_bounded_and_cursor_ordered() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let ledger = open_qualified(
        directory.path().join("pool.sqlite3"),
        "ledger:test-internal-scan",
    )
    .test_expect("open qualified pool ledger");
    let allocation_digest = "d".repeat(64);
    let first_operation = "a".repeat(64);
    let second_operation = "c".repeat(64);
    let terminal_operation = "e".repeat(64);
    {
        let connection = ledger.pool.get().test_expect("open pool ledger connection");
        connection
            .execute(
                "INSERT INTO finding_pool_allocations (\
                    allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                    purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                    reserved_units, spent_units, expires_at_unix_ms\
                 ) VALUES (?1, 'allocation:scan', 'pool:scan', ?2, 'buyer:scan', '{}', \
                           'USD', '100', '20', '0', '100000')",
                params![allocation_digest, "f".repeat(64)],
            )
            .test_expect("seed scan allocation");
        for (purchase_id, state, claimed_at, operation_id) in [
            (
                "purchase:first",
                "reserved",
                Some("1000"),
                Some(first_operation.as_str()),
            ),
            (
                "purchase:second",
                "reserved",
                Some("1001"),
                Some(second_operation.as_str()),
            ),
            ("purchase:unclaimed", "reserved", None, None),
            (
                "purchase:terminal",
                "released",
                Some("1002"),
                Some(terminal_operation.as_str()),
            ),
        ] {
            connection
                .execute(
                    "INSERT INTO finding_pool_debits (\
                        purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                        reservation_id, authoritative_payment_operation_id, \
                        accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                        amount_units, currency, state, claim_deadline_unix_ms, \
                        claimed_at_unix_ms, durable_admission_operation_id, \
                        reserved_after_units, spent_after_units\
                     ) VALUES (?1, ?2, ?3, 'listing:scan', ?4, ?5, ?6, ?7, \
                               '5', 'USD', ?8, '30000', ?9, ?10, '20', '0')",
                    params![
                        purchase_id,
                        allocation_digest,
                        "1".repeat(64),
                        format!("reservation:{purchase_id}"),
                        format!("payment:{purchase_id}"),
                        "2".repeat(64),
                        "3".repeat(64),
                        state,
                        claimed_at,
                        operation_id,
                    ],
                )
                .test_expect("seed claimed-operation scan row");
        }
    }

    assert_eq!(
        ledger
            .list_claimed_admission_operations(None, 1)
            .test_expect("read first claimed-operation page"),
        vec![first_operation.clone()]
    );
    assert_eq!(
        ledger
            .list_claimed_admission_operations(Some(&first_operation), 1)
            .test_expect("read second claimed-operation page"),
        vec![second_operation.clone()]
    );
    assert!(ledger
        .list_claimed_admission_operations(Some(&second_operation), 1)
        .test_expect("read terminal claimed-operation page")
        .is_empty());
}

#[test]
fn settlement_requires_claim_bound_to_same_admission_operation() {
    assert_eq!(
        require_terminal_claim_binding(None, None, "operation:completed"),
        Err(FindingPoolLedgerError::TerminalConflict)
    );
    assert_eq!(
        require_terminal_claim_binding(
            Some("1000"),
            Some("operation:other"),
            "operation:completed",
        ),
        Err(FindingPoolLedgerError::TerminalConflict)
    );
    assert_eq!(
        require_terminal_claim_binding(
            Some("1000"),
            Some("operation:completed"),
            "operation:completed",
        ),
        Ok(())
    );
}

#[test]
fn recovered_mutation_loads_the_reservations_persisted_tenant() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let ledger = open_qualified(
        directory.path().join("pool.sqlite3"),
        "ledger:test-tenant-recovery",
    )
    .test_expect("open qualified pool ledger");
    let allocation_digest = "a".repeat(64);
    let mut connection = ledger.pool.get().test_expect("open pool ledger connection");
    connection
        .execute(
            "INSERT INTO finding_pool_allocations (\
                allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                reserved_units, spent_units, expires_at_unix_ms\
             ) VALUES (?1, 'allocation:tenant', 'pool:tenant', ?2, 'buyer:tenant', '{}', \
                       'USD', '100', '25', '0', '100000')",
            params![allocation_digest, "b".repeat(64)],
        )
        .test_expect("seed tenant allocation");
    connection
        .execute(
            "INSERT INTO finding_pool_debits (\
                purchase_id, tenant_id, allocation_envelope_sha256, finding_id, listing_id, \
                reservation_id, authoritative_payment_operation_id, \
                accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                amount_units, currency, state, claim_deadline_unix_ms, \
                claimed_at_unix_ms, durable_admission_operation_id, \
                reserved_after_units, spent_after_units\
             ) VALUES ('purchase:tenant', 'tenant-recovery', ?1, ?2, 'listing:tenant', \
                       'reservation:tenant', 'payment:tenant', ?3, ?4, '25', 'USD', \
                       'reserved', '30000', '2000', 'operation:tenant', '25', '0')",
            params![
                allocation_digest,
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
            ],
        )
        .test_expect("seed tenant reservation");
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .test_expect("start tenant recovery transaction");
    let mutation = mutation_for_purchase(
        &transaction,
        "purchase:tenant",
        FindingPoolMutationKind::Release,
        3_000,
    )
    .test_expect("build recovered tenant mutation");

    assert_eq!(mutation.tenant_id.as_deref(), Some("tenant-recovery"));
}

#[test]
fn unknown_dispatch_exact_replay_ignores_later_allocation_totals() {
    let directory = tempfile::tempdir().test_expect("create pool ledger directory");
    let ledger = open_qualified(
        directory.path().join("pool.sqlite3"),
        "ledger:test-internal-unknown-dispatch",
    )
    .test_expect("open qualified pool ledger");
    let allocation_digest = "a".repeat(64);
    let operation_id = "operation:unknown-dispatch";
    {
        let connection = ledger.pool.get().test_expect("open pool ledger connection");
        connection
            .execute(
                "INSERT INTO finding_pool_allocations (\
                    allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                    purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                    reserved_units, spent_units, expires_at_unix_ms\
                 ) VALUES (?1, 'allocation:test', 'pool:test', ?2, 'buyer:test', '{}', \
                           'USD', '100', '20', '10', '100000')",
                params![allocation_digest, "b".repeat(64)],
            )
            .test_expect("seed allocation with later counters");
        connection
            .execute(
                "INSERT INTO finding_pool_debits (\
                    purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                    reservation_id, authoritative_payment_operation_id, \
                    accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                    amount_units, currency, state, claim_deadline_unix_ms, \
                    claimed_at_unix_ms, durable_admission_operation_id, \
                    reserved_after_units, spent_after_units\
                 ) VALUES ('purchase:finalized', ?1, ?2, 'listing:test', \
                           'reservation:finalized', 'payment:finalized', ?3, ?4, \
                           '10', 'USD', 'finalized', '30000', '2000', ?5, '0', '10')",
                params![
                    allocation_digest,
                    "c".repeat(64),
                    "d".repeat(64),
                    "e".repeat(64),
                    operation_id,
                ],
            )
            .test_expect("seed finalized unknown-dispatch debit");
        connection
            .execute(
                "INSERT INTO finding_pool_debits (\
                    purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                    reservation_id, authoritative_payment_operation_id, \
                    accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                    amount_units, currency, state, claim_deadline_unix_ms, \
                    claimed_at_unix_ms, durable_admission_operation_id, \
                    reserved_after_units, spent_after_units\
                 ) VALUES ('purchase:later', ?1, ?2, 'listing:test', \
                           'reservation:later', 'payment:later', ?3, ?4, \
                           '20', 'USD', 'reserved', '40000', NULL, NULL, '20', '10')",
                params![
                    allocation_digest,
                    "f".repeat(64),
                    "1".repeat(64),
                    "2".repeat(64),
                ],
            )
            .test_expect("seed later reservation that advanced allocation totals");
    }

    let attestor = |_mutation: &FindingPoolMutation| {
        Err(FindingPoolLedgerError::Receipt(
            "exact replay must not attest another mutation".to_owned(),
        ))
    };
    finalize_claimed_after_unknown_dispatch_by_operation(&ledger, operation_id, 3_000, &attestor)
        .test_expect("exact finalized replay ignores mutable allocation counters");

    assert_eq!(
        ledger
            .reserved_units(&allocation_digest)
            .test_expect("read retained reservations"),
        Some(20)
    );
    assert_eq!(
        ledger
            .spent_units(&allocation_digest)
            .test_expect("read retained spend"),
        Some(10)
    );
}
