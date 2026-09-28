//! Multi-tenant receipt isolation tests for
//! `chio_store_sqlite::SqliteReceiptStore`.
//!
//! Tenant reads return only the requested tenant, including local operator
//! tenant reads. Only explicit administrative reads include unattributed rows.
//! Tenant IDs come from signed receipt bodies.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_kernel::receipt_query::ReceiptQuery;
use chio_store_sqlite::SqliteReceiptStore;

use chio_test_support::prelude::*;

#[test]
fn point_reads_bind_ids_to_authenticated_tenants() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::{receipt_query::ReceiptReadError, ReceiptReadContext, ReceiptStoreError};
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("point-reads.sqlite");
    let store = SqliteReceiptStore::open(&path)?;
    let receipts = [
        signed_receipt("a", "cap-a", Some("tenant-A")),
        signed_receipt("b", "cap-b", Some("tenant-B")),
        signed_receipt("unattributed", "cap-c", None),
    ];
    for receipt in &receipts {
        store.append_chio_receipt_returning_seq(receipt)?;
    }
    for context in [
        ReceiptReadContext::authenticated_tenant("tenant-A"),
        ReceiptReadContext::local_operator_tenant("tenant-A"),
    ] {
        assert_eq!(
            store
                .load_chio_receipt_with_context(&receipts[0].id, &context)?
                .map(|r| r.id),
            Some(receipts[0].id.clone())
        );
        for id in [&receipts[1].id, &receipts[2].id, "absent"] {
            assert!(store
                .load_chio_receipt_with_context(id, &context)?
                .is_none());
        }
    }
    for receipt in &receipts {
        assert!(store
            .load_chio_receipt_with_context(&receipt.id, &ReceiptReadContext::admin_service())?
            .is_some());
    }
    for tenant in ["", " tenant-A", "tenant-A "] {
        assert!(matches!(
            store.load_chio_receipt_with_context(
                &receipts[0].id,
                &ReceiptReadContext::authenticated_tenant(tenant)
            ),
            Err(ReceiptStoreError::ReadAuthorization(
                ReceiptReadError::InvalidTenant
            ))
        ));
    }
    // Inject storage corruption past the immutability trigger. Restore the
    // trigger before readback to test the signed tenant check independently.
    let mut connection = rusqlite::Connection::open(path)?;
    let transaction = connection.transaction()?;
    let trigger: String = transaction.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
         AND name = 'chio_tool_receipts_reject_update'",
        [],
        |row| row.get(0),
    )?;
    transaction.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update")?;
    transaction.execute(
        "UPDATE chio_tool_receipts SET tenant_id = 'tenant-A' WHERE receipt_id = ?1",
        [&receipts[1].id],
    )?;
    transaction.execute_batch(&trigger)?;
    transaction.commit()?;
    assert!(matches!(
        store.load_chio_receipt_with_context(
            &receipts[1].id,
            &ReceiptReadContext::authenticated_tenant("tenant-A")
        ),
        Err(ReceiptStoreError::ReadAuthorization(
            ReceiptReadError::TenantProjectionMismatch
        ))
    ));
    assert!(matches!(
        store.query_receipts(&basic_query(Some("tenant-A".to_string()))),
        Err(ReceiptStoreError::ReadAuthorization(
            ReceiptReadError::TenantProjectionMismatch
        ))
    ));
    Ok(())
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-{prefix}-{nonce}.sqlite3"))
}

fn cleanup(path: &std::path::Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

fn signed_receipt(id: &str, capability_id: &str, tenant: Option<&str>) -> ChioReceipt {
    let kp = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_710_000_000,
            capability_id: capability_id.to_string(),
            tool_server: "srv".to_string(),
            tool_name: "ping".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .test_expect("tool action hash"),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: tenant.map(str::to_string),
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        },
        &kp,
    )
    .test_expect("signed receipt")
}

fn basic_query(tenant: Option<String>) -> ReceiptQuery {
    let read_context = match tenant.clone() {
        Some(tenant) => chio_kernel::ReceiptReadContext::authenticated_tenant(tenant),
        None => chio_kernel::ReceiptReadContext::local_operator_admin_all(),
    };
    ReceiptQuery {
        limit: chio_kernel::MAX_QUERY_LIMIT,
        tenant_filter: tenant,
        read_context: Some(read_context),
        ..ReceiptQuery::default()
    }
}

fn operator_tenant_query(tenant: String) -> ReceiptQuery {
    ReceiptQuery {
        limit: chio_kernel::MAX_QUERY_LIMIT,
        tenant_filter: Some(tenant.clone()),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_tenant(
            tenant,
        )),
        ..ReceiptQuery::default()
    }
}

#[test]
fn tenant_filter_without_read_context_fails_closed() {
    let path = unique_db_path("tenant-isolation-missing-context");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    let err = store
        .query_receipts(&ReceiptQuery {
            limit: chio_kernel::MAX_QUERY_LIMIT,
            tenant_filter: Some("tenant-A".to_string()),
            read_context: None,
            ..ReceiptQuery::default()
        })
        .test_expect_err("tenant_filter without read context must fail closed");

    assert!(matches!(
        err,
        chio_kernel::ReceiptStoreError::ReadAuthorization(
            chio_kernel::receipt_query::ReceiptReadError::MissingContext
        )
    ));

    cleanup(&path);
}

#[test]
fn tenant_scoped_queries_exclude_other_tenants_and_unattributed_rows() {
    let path = unique_db_path("tenant-isolation");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    // 5 receipts for tenant A.
    for i in 0..5 {
        let r = signed_receipt(
            &format!("rcpt-a-{i}"),
            &format!("cap-a-{i}"),
            Some("tenant-A"),
        );
        store
            .append_chio_receipt_returning_seq(&r)
            .test_expect("append tenant-A receipt");
    }
    // 3 receipts for tenant B.
    for i in 0..3 {
        let r = signed_receipt(
            &format!("rcpt-b-{i}"),
            &format!("cap-b-{i}"),
            Some("tenant-B"),
        );
        store
            .append_chio_receipt_returning_seq(&r)
            .test_expect("append tenant-B receipt");
    }
    // Two unattributed receipts have tenant_id IS NULL.
    for i in 0..2 {
        let r = signed_receipt(
            &format!("rcpt-untagged-{i}"),
            &format!("cap-untagged-{i}"),
            None,
        );
        store
            .append_chio_receipt_returning_seq(&r)
            .test_expect("append untagged receipt");
    }

    // Tenant A only sees its own rows.
    let a_page = store
        .query_receipts(&basic_query(Some("tenant-A".to_string())))
        .test_expect("query tenant-A");
    assert_eq!(
        a_page.total_count, 5,
        "tenant A visibility must exclude NULL-tenant rows"
    );
    assert_eq!(a_page.receipts.len(), 5);
    for stored in &a_page.receipts {
        assert_eq!(stored.receipt.tenant_id.as_deref(), Some("tenant-A"));
    }

    // Tenant B sees only its own rows.
    let b_page = store
        .query_receipts(&basic_query(Some("tenant-B".to_string())))
        .test_expect("query tenant-B");
    assert_eq!(b_page.total_count, 3);
    assert_eq!(b_page.receipts.len(), 3);
    for stored in &b_page.receipts {
        assert_eq!(stored.receipt.tenant_id.as_deref(), Some("tenant-B"));
    }

    for (tenant, expected) in [("tenant-A", 5), ("tenant-B", 3)] {
        let page = store
            .query_receipts(&operator_tenant_query(tenant.to_string()))
            .test_expect("operator tenant query");
        assert_eq!(page.total_count, expected);
        assert!(page
            .receipts
            .iter()
            .all(|stored| stored.receipt.tenant_id.as_deref() == Some(tenant)));
    }

    // Explicit local-operator admin mode returns everything.
    let admin = store
        .query_receipts(&basic_query(None))
        .test_expect("admin query");
    assert_eq!(admin.total_count, 10);
    assert_eq!(admin.receipts.len(), 10);

    cleanup(&path);
}

#[test]
fn explicit_admin_context_returns_all_rows_regardless_of_tags() {
    let path = unique_db_path("tenant-isolation-all");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    // Three distinct tenants + untagged nulls.
    for (tenant, count) in [
        (Some("ten-1"), 4usize),
        (Some("ten-2"), 1),
        (Some("ten-3"), 2),
        (None, 3),
    ] {
        for i in 0..count {
            let id = format!("rcpt-{}-{i}", tenant.unwrap_or("untagged"));
            let capability_id = format!("cap-{id}");
            let r = signed_receipt(&id, &capability_id, tenant);
            store
                .append_chio_receipt_returning_seq(&r)
                .test_expect("append receipt");
        }
    }

    let page = store
        .query_receipts(&basic_query(None))
        .test_expect("explicit admin query");
    assert_eq!(page.total_count, 10);
    assert_eq!(page.receipts.len(), 10);

    cleanup(&path);
}

#[test]
fn tenant_a_queries_never_return_tenant_b_rows() {
    // Receipts from tenant A are invisible to tenant B queries.
    // Verify isolation in both directions.
    let path = unique_db_path("tenant-isolation-cross");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    let a = signed_receipt("rcpt-secret-a", "cap-a", Some("tenant-A"));
    let b = signed_receipt("rcpt-secret-b", "cap-b", Some("tenant-B"));
    store.append_chio_receipt_returning_seq(&a).test_unwrap();
    store.append_chio_receipt_returning_seq(&b).test_unwrap();

    let a_view = store
        .query_receipts(&basic_query(Some("tenant-A".to_string())))
        .test_expect("query tenant-A");
    assert_eq!(a_view.total_count, 1);
    assert_eq!(a_view.receipts.len(), 1);
    assert_eq!(a_view.receipts[0].receipt.capability_id, "cap-a");
    assert!(
        !a_view
            .receipts
            .iter()
            .any(|r| r.receipt.capability_id == "cap-b"),
        "tenant A MUST NOT see tenant B's receipt under any mode"
    );

    let b_view = store
        .query_receipts(&basic_query(Some("tenant-B".to_string())))
        .test_expect("query tenant-B");
    assert_eq!(b_view.total_count, 1);
    assert_eq!(b_view.receipts[0].receipt.capability_id, "cap-b");
    assert!(
        !b_view
            .receipts
            .iter()
            .any(|r| r.receipt.capability_id == "cap-a"),
        "tenant B MUST NOT see tenant A's receipt under any mode"
    );

    cleanup(&path);
}
