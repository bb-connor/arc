use super::{
    require_error, BoundaryClass, ChioReceipt, ChioReceiptBody, Decision, Keypair, PortErrorKind,
    ReceiptKind, RedactionMode, SqliteReceiptStore, SqliteSecurityStateStore, ToolCallAction,
    ToolOrigin, TrustLevel,
};

#[test]
fn security_state_rejects_ephemeral_sqlite_paths() {
    for path in [
        "",
        ":memory:",
        "file:security-state?mode=memory&cache=shared",
        "FILE:security-state?mode=memory",
        "security-state?mode=memory",
        "security-state#fragment",
    ] {
        assert_eq!(
            require_error(SqliteSecurityStateStore::open(path)).kind(),
            PortErrorKind::InvalidData,
            "path must be rejected: {path:?}"
        );
    }
}

#[test]
fn migration_is_idempotent_and_preserves_existing_tables() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let receipt_store = SqliteReceiptStore::open(&path)
        .unwrap_or_else(|error| panic!("open receipt store: {error}"));
    let keypair = Keypair::generate();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "security-migration-receipt".to_owned(),
            timestamp: 1,
            capability_id: "security-migration-capability".to_owned(),
            tool_server: "migration-server".to_owned(),
            tool_name: "migration-tool".to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .unwrap_or_else(|error| panic!("tool action: {error}")),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content".to_owned(),
            policy_hash: "policy".to_owned(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_owned()),
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap_or_else(|error| panic!("sign receipt: {error}"));
    receipt_store
        .append_chio_receipt_returning_seq(&receipt)
        .unwrap_or_else(|error| panic!("append receipt: {error}"));
    drop(receipt_store);

    drop(
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("first open: {error}")),
    );
    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("second open: {error}")),
    );

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("reopen database: {error}"));
    let receipt_id: String = connection
        .query_row(
            "SELECT receipt_id FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt.id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load existing receipt: {error}"));
    assert_eq!(receipt_id, receipt.id);
}
