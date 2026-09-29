use super::*;

pub(super) fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

pub(super) fn usage_record(
    capability_id: &str,
    grant_index: u32,
    invocation_count: u32,
    updated_at: i64,
    seq: u64,
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> BudgetUsageRecord {
    BudgetUsageRecord {
        capability_id: capability_id.to_string(),
        grant_index,
        invocation_count,
        updated_at,
        seq,
        total_cost_exposed,
        total_cost_realized_spend,
    }
}

pub(super) fn install_usage_anchor(store: &SqliteBudgetStore, record: &BudgetUsageRecord) {
    install_usage_anchors(store, std::slice::from_ref(record));
}

pub(super) fn install_usage_anchors(store: &SqliteBudgetStore, records: &[BudgetUsageRecord]) {
    let mut connection = store.connection().unwrap();
    let transaction = store.begin_write(&mut connection).unwrap();
    transaction
        .execute(
            "INSERT OR IGNORE INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
            [],
        )
        .unwrap();
    for record in records {
        SqliteBudgetStore::upsert_usage_in_transaction(&transaction, record).unwrap();
        transaction
            .execute(
                r#"
                INSERT INTO budget_usage_history_anchors (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend, anchored_schema_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 6)
                "#,
                params![
                    &record.capability_id,
                    i64::from(record.grant_index),
                    i64::from(record.invocation_count),
                    record.updated_at,
                    budget_u64_to_sqlite(record.seq, "seq").unwrap(),
                    budget_u64_to_sqlite(record.total_cost_exposed, "total_cost_exposed").unwrap(),
                    budget_u64_to_sqlite(
                        record.total_cost_realized_spend,
                        "total_cost_realized_spend",
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
    }
    transaction
        .execute("DELETE FROM budget_usage_anchor_migration_gate", [])
        .unwrap();
    transaction.commit().unwrap();
}

pub(super) fn assert_usage_totals(record: &BudgetUsageRecord, exposed: u64, realized: u64) {
    assert_eq!(record.total_cost_exposed, exposed);
    assert_eq!(record.total_cost_realized_spend, realized);
    assert_eq!(record.committed_cost_units().unwrap(), exposed + realized);
}

pub(super) fn authority(
    authority_id: &str,
    lease_id: &str,
    lease_epoch: u64,
) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority_id.to_string(),
        lease_id: lease_id.to_string(),
        lease_epoch,
    }
}
