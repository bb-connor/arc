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

/// Older budget fixtures must not retain the schema12 payment catalog created
/// by today's factory. Reinstall the exact supported predecessor only when no
/// payment journal or release-evidence facts can be lost.
pub(super) fn install_empty_legacy_payment_journal(
    connection: &Connection,
) -> rusqlite::Result<()> {
    let transaction = connection.unchecked_transaction()?;
    let counts: (i64, i64) = transaction.query_row(
        "SELECT (SELECT COUNT(*) FROM payment_journal),
                (SELECT COUNT(*) FROM payment_release_evidence)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        counts,
        (0, 0),
        "older fixtures must retain all payment facts"
    );
    transaction.execute_batch("DROP TABLE payment_journal;")?;
    transaction.execute_batch(include_str!("../composite_schema/payment/legacy_v11.sql"))?;
    transaction.commit()
}

/// `(max_invocations, cost_units, max_cost_per_invocation, max_total_cost_units)`.
pub(super) type ChargeLimits = (Option<u32>, u64, Option<u64>, Option<u64>);

pub(super) fn charge(
    store: &dyn BudgetStore,
    capability_id: &str,
    grant_index: usize,
    limits: ChargeLimits,
    hold_id: &str,
    event_id: &str,
    authority: Option<&BudgetEventAuthority>,
) -> Result<bool, BudgetStoreError> {
    let (max_invocations, cost_units, max_cost_per_invocation, max_total_cost_units) = limits;
    let decision = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: capability_id.to_string(),
        grant_index,
        max_invocations,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: cost_units,
        max_cost_per_invocation,
        max_total_cost_units,
        hold_id: hold_id.to_string(),
        event_id: event_id.to_string(),
        authority: authority.cloned(),
    })?;
    Ok(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ))
}

pub(super) fn capture(
    store: &dyn BudgetStore,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.to_string(),
            event_id: format!("{hold_id}:capture-invocation"),
            trusted_time: None,
            authority: authority.cloned(),
        })
        .map(|_| ())
}

pub(super) fn reverse(
    store: &dyn BudgetStore,
    capability_id: &str,
    grant_index: usize,
    cost_units: u64,
    hold_id: &str,
    event_id: &str,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: capability_id.to_string(),
            grant_index,
            reversed_exposure_units: cost_units,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            expected_cumulative_approval_state: None,
            authority: authority.cloned(),
        })
        .map(|_| ())
}

pub(super) fn release(
    store: &dyn BudgetStore,
    capability_id: &str,
    grant_index: usize,
    cost_units: u64,
    hold_id: &str,
    event_id: &str,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: capability_id.to_string(),
            grant_index,
            released_exposure_units: cost_units,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            authority: authority.cloned(),
        })
        .map(|_| ())
}

pub(super) fn reconcile(
    store: &dyn BudgetStore,
    capability_id: &str,
    grant_index: usize,
    (exposed_cost_units, realized_spend_units): (u64, u64),
    hold_id: &str,
    event_id: &str,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: capability_id.to_string(),
            grant_index,
            exposed_cost_units,
            realized_spend_units,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            authority: authority.cloned(),
        })
        .map(|_| ())
}
