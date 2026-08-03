use super::*;

pub(crate) async fn handle_internal_cluster_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_cluster_peer_empty_request(
        &headers,
        &state.config,
        "GET",
        INTERNAL_CLUSTER_SNAPSHOT_PATH,
    ) {
        return response;
    }
    if state.cluster.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "cluster replication is not configured",
        );
    }
    if state.config.authority_seed_path.is_some() || state.config.authority_db_path.is_some() {
        return plain_http_error(
            StatusCode::CONFLICT,
            "cluster state snapshots cannot include capability-authority custody",
        );
    }
    match build_cluster_state_snapshot(&state) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_internal_authority_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_cluster_peer_empty_request(
        &headers,
        &state.config,
        "GET",
        INTERNAL_AUTHORITY_SNAPSHOT_PATH,
    ) {
        return response;
    }
    if let Some(path) = state.config.authority_db_path.as_deref() {
        return authority_snapshot_response(path);
    }

    plain_http_error(
        StatusCode::CONFLICT,
        "clustered authority replication requires --authority-db",
    )
}

fn authority_snapshot_response(path: &Path) -> Response {
    let authority = match SqliteCapabilityAuthority::open_existing(path) {
        Ok(authority) => authority,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority custody is unavailable",
            );
        }
    };
    match authority.snapshot() {
        Ok(snapshot) => Json(authority_snapshot_view(snapshot)).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) fn cluster_replication_heads(
    state: &TrustServiceState,
) -> Result<ClusterReplicationHeadsView, CliError> {
    let (tool_seq, child_seq, lineage_seq) =
        if let Some(path) = state.config.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)?;
            (
                store.max_tool_receipt_seq()?,
                store.max_child_receipt_seq()?,
                store.max_lineage_seq()?,
            )
        } else {
            (0, 0, 0)
        };
    let budget_seq = match state.config.budget_db_path.as_deref() {
        Some(path) => SqliteBudgetStore::open(path)?.max_mutation_event_seq()?,
        None => 0,
    };
    let revocation_cursor = match state.config.revocation_db_path.as_deref() {
        Some(path) => SqliteRevocationStore::open(path)?.latest_revocation_cursor()?,
        None => None,
    };
    Ok(ClusterReplicationHeadsView {
        tool_seq,
        child_seq,
        lineage_seq,
        budget_seq,
        revocation_cursor: revocation_cursor.map(|(revoked_at, capability_id)| {
            RevocationCursorView {
                revoked_at,
                capability_id,
            }
        }),
    })
}

pub(crate) fn build_cluster_state_snapshot(
    state: &TrustServiceState,
) -> Result<ClusterStateSnapshotResponse, CliError> {
    let consensus = cluster_consensus_view(state);
    let authority_lease = cluster_authority_lease_view(state);
    if state.config.authority_seed_path.is_some() || state.config.authority_db_path.is_some() {
        return Err(CliError::cli_other_error(
            "cluster state snapshots cannot include capability-authority custody".to_string(),
        ));
    }
    let authority = None;

    let revocations = if let Some(path) = state.config.revocation_db_path.as_deref() {
        let store = SqliteRevocationStore::open(path)?;
        collect_revocation_views(&store)?
    } else {
        Vec::new()
    };

    let (tool_receipts, child_receipts, lineage) =
        if let Some(path) = state.config.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)?;
            let read_context = ReceiptReadContext::admin_service();
            (
                collect_tool_receipt_views(&store, &read_context)?,
                collect_child_receipt_views(&store, &read_context)?,
                collect_lineage_views(&store)?,
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

    let budgets = if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        collect_budget_views(&store)?
    } else {
        Vec::new()
    };
    let budget_invocation_quotas = if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        collect_budget_invocation_quota_views(&store)?
    } else {
        Vec::new()
    };
    let budget_mutation_events = if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        collect_budget_mutation_event_views(&store)?
    } else {
        Vec::new()
    };
    // Range-encode the abandoned seqs (inclusive (start, end) runs) so a rollback
    // storm's long contiguous abandoned window stays a few small pairs rather than an
    // unbounded integer list that would push the snapshot body past
    // MAX_PEER_RESPONSE_BYTES and permanently break force-snapshot recovery. Computed
    // in SQL, so the full seq set is never materialized here either.
    let budget_abandoned_seq_ranges = if let Some(path) = state.config.budget_db_path.as_deref() {
        SqliteBudgetStore::open(path)?
            .list_abandoned_event_seq_ranges()?
            .into_iter()
            .map(|(start, end)| AbandonedSeqRange { start, end })
            .collect()
    } else {
        Vec::new()
    };

    let replication = ClusterReplicationHeadsView {
        tool_seq: tool_receipts.last().map(|record| record.seq).unwrap_or(0),
        child_seq: child_receipts.last().map(|record| record.seq).unwrap_or(0),
        lineage_seq: lineage.last().map(|record| record.seq).unwrap_or(0),
        budget_seq: budget_mutation_events
            .last()
            .map(|event| event.event_seq)
            .unwrap_or(0),
        revocation_cursor: revocations.last().map(|record| RevocationCursorView {
            revoked_at: record.revoked_at,
            capability_id: record.capability_id.clone(),
        }),
    };

    Ok(ClusterStateSnapshotResponse {
        generated_at: unix_timestamp_now(),
        election_term: consensus
            .as_ref()
            .map(|view| view.election_term)
            .unwrap_or(0),
        replication,
        authority_lease,
        authority,
        revocations,
        tool_receipts,
        child_receipts,
        lineage,
        budgets,
        budget_invocation_quotas,
        budget_mutation_events,
        budget_abandoned_seq_ranges,
    })
}

pub(crate) fn apply_cluster_snapshot(
    state: &TrustServiceState,
    peer_url: &str,
    snapshot: ClusterStateSnapshotResponse,
) -> Result<(), CliError> {
    let ClusterStateSnapshotResponse {
        generated_at,
        election_term,
        replication,
        authority_lease,
        authority,
        revocations,
        tool_receipts,
        child_receipts,
        lineage,
        budgets,
        budget_invocation_quotas,
        budget_mutation_events,
        budget_abandoned_seq_ranges,
    } = snapshot;

    if authority.is_some() {
        return Err(CliError::cli_other_error(
            "cluster state snapshot attempted to carry observational capability-authority metadata into the HA admission state machine"
                .to_string(),
        ));
    }

    if let Some(path) = state.config.revocation_db_path.as_deref() {
        let store = SqliteRevocationStore::open(path)?;
        if !store.is_admission_authority_managed() {
            for record in &revocations {
                store.upsert_revocation(&RevocationRecord {
                    capability_id: record.capability_id.clone(),
                    revoked_at: record.revoked_at,
                })?;
            }
        }
    }

    if let Some(path) = state.config.receipt_db_path.as_deref() {
        let mut store = SqliteReceiptStore::open(path)?;
        for record in &tool_receipts {
            let receipt: ChioReceipt = serde_json::from_value(record.receipt.clone())?;
            store.append_chio_receipt(&receipt)?;
        }
        for record in &child_receipts {
            let receipt: ChildRequestReceipt = serde_json::from_value(record.receipt.clone())?;
            store.append_child_receipt(&receipt)?;
        }
        for record in &lineage {
            store
                .upsert_capability_snapshot(&record.snapshot)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        }
    }

    let mut budget_cursor = None;
    if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        if !store.is_admission_authority_managed()? {
            let usage_records = budgets
                .iter()
                .map(budget_usage_record_from_view)
                .collect::<Vec<_>>();
            let mutation_records = budget_mutation_events
                .iter()
                .map(budget_mutation_record_from_view)
                .collect::<Result<Vec<_>, _>>()?;
            let invocation_quota_records = budget_invocation_quotas
                .iter()
                .map(budget_invocation_quota_usage_record_from_view)
                .collect::<Result<Vec<_>, _>>()?;
            store
                .import_snapshot_records_with_invocation_quotas(
                    &usage_records,
                    &invocation_quota_records,
                    &mutation_records,
                )
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            store
                .record_budget_import_floors(&mutation_records)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            // Learn the leader's abandoned/tombstoned seqs so a fresh follower's
            // contiguous ack head treats those holes as filled instead of stalling at
            // them. Carried range-encoded and stored as compact intervals, so a
            // rollback-storm run is never materialized as a huge row or memory list.
            let abandoned_ranges = budget_abandoned_seq_ranges
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>();
            store
                .record_abandoned_event_seq_ranges(&abandoned_ranges)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            for event in &budget_mutation_events {
                budget_cursor = Some(merge_budget_cursor(
                    budget_cursor,
                    budget_cursor_from_event(event),
                ));
            }
        }
    }

    seed_cluster_authority_from_snapshot(state, election_term, authority_lease.as_ref())?;

    update_peer_state(state, peer_url, |peer| {
        peer.tool_seq = replication.tool_seq;
        peer.child_seq = replication.child_seq;
        peer.lineage_seq = replication.lineage_seq;
        peer.revocation_cursor = replication
            .revocation_cursor
            .clone()
            .map(revocation_cursor_from_view);
        peer.budget_cursor = budget_cursor.clone();
        peer.snapshot_applied_count = peer.snapshot_applied_count.saturating_add(1);
        peer.last_snapshot_at = Some(generated_at);
        peer.delta_records_since_snapshot = 0;
        // Clear the peer's cached witness acks ATOMICALLY with clearing
        // `force_snapshot`. `force_snapshot` was the ONLY thing excluding this peer's stale
        // ack head from the witness set (`budget_write_quorum_commit_view`), and this
        // is the single site that clears it WITHOUT going through
        // `finalize_peer_sync_round` (which re-records a validated ack via
        // `update_peer_budget_acks`). If we cleared `force_snapshot` here but left the
        // old (stale-high) ack map in place, ANY early return after this point (an
        // authority-sync error, a puller error, a transient failure) would skip
        // finalize and leave a Healthy, not-force_snapshot peer WITNESSING at an ack
        // head that this round never validated - an OVER-COUNT / budget double-spend.
        // Snapshot recovery is precisely our admission that our incremental view of
        // this peer was broken, so the peer must start witnessing NOTHING until a
        // completed pull round's finalize re-records a validated ack. Fail-closed and
        // strictly under-count-safe: this can only SHRINK the witness set.
        peer.budget_import_acks.clear();
        peer.force_snapshot = false;
    });

    Ok(())
}

fn seed_cluster_authority_from_snapshot(
    state: &TrustServiceState,
    snapshot_election_term: u64,
    authority_lease: Option<&ClusterAuthorityLeaseView>,
) -> Result<(), CliError> {
    let Some(cluster) = state.cluster.as_ref() else {
        return Ok(());
    };

    let snapshot_term = authority_lease
        .map(|lease| lease.term)
        .unwrap_or(snapshot_election_term);
    if snapshot_term == 0 {
        return Ok(());
    }

    let snapshot_leader = authority_lease.map(|lease| lease.leader_url.clone());
    if let Some(path) = state.config.authority_db_path.as_deref() {
        let authority = SqliteCapabilityAuthority::open_existing(path)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        authority
            .seed_cluster_fence(snapshot_leader.as_deref(), snapshot_term)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    }
    let seed_guard = |guard: &mut ClusterRuntimeState| {
        let conflicting_same_term_self_leader = snapshot_term == guard.election_term
            && guard
                .last_leader_url
                .as_deref()
                .is_some_and(|leader| leader == guard.self_url)
            && snapshot_leader
                .as_deref()
                .is_some_and(|leader| leader != guard.self_url);
        if conflicting_same_term_self_leader {
            let now = unix_timestamp_now();
            guard.election_term = guard.election_term.saturating_add(1);
            guard.last_leader_url = Some(guard.self_url.clone());
            guard.term_started_at = Some(now);
            guard.lease_expires_at = Some(now.saturating_add(guard.lease_ttl_ms / 1000));
            return;
        }

        if snapshot_term > guard.election_term
            || (snapshot_term == guard.election_term
                && guard.last_leader_url.is_none()
                && snapshot_leader.is_some())
        {
            guard.election_term = snapshot_term;
            guard.last_leader_url = snapshot_leader.clone();
            guard.term_started_at = authority_lease.and_then(|lease| lease.term_started_at);
            guard.lease_expires_at = authority_lease.map(|lease| lease.lease_expires_at);
        }
    };

    match cluster.lock() {
        Ok(mut guard) => {
            seed_guard(&mut guard);
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            seed_guard(&mut guard);
        }
    }
    Ok(())
}

fn collect_revocation_views(
    store: &SqliteRevocationStore,
) -> Result<Vec<RevocationRecordView>, CliError> {
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let batch = store.list_revocations_after(
            MAX_LIST_LIMIT,
            cursor
                .as_ref()
                .map(|value: &RevocationCursor| value.revoked_at),
            cursor
                .as_ref()
                .map(|value: &RevocationCursor| value.capability_id.as_str()),
        )?;
        if batch.is_empty() {
            break;
        }
        for record in batch {
            cursor = Some(RevocationCursor {
                revoked_at: record.revoked_at,
                capability_id: record.capability_id.clone(),
            });
            records.push(RevocationRecordView {
                capability_id: record.capability_id,
                revoked_at: record.revoked_at,
            });
        }
    }
    Ok(records)
}

fn collect_tool_receipt_views(
    store: &SqliteReceiptStore,
    read_context: &ReceiptReadContext,
) -> Result<Vec<StoredReceiptView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_tool_receipts_after_seq_with_context(
            read_context,
            after_seq,
            MAX_LIST_LIMIT,
        )?;
        if batch.is_empty() {
            break;
        }
        let mut views = stored_tool_receipt_views(batch)?;
        after_seq = views.last().map(|record| record.seq).unwrap_or(after_seq);
        records.append(&mut views);
    }
    Ok(records)
}

fn collect_child_receipt_views(
    store: &SqliteReceiptStore,
    read_context: &ReceiptReadContext,
) -> Result<Vec<StoredReceiptView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_child_receipts_after_seq_with_context(
            read_context,
            after_seq,
            MAX_LIST_LIMIT,
        )?;
        if batch.is_empty() {
            break;
        }
        let mut views = stored_child_receipt_views(batch)?;
        after_seq = views.last().map(|record| record.seq).unwrap_or(after_seq);
        records.append(&mut views);
    }
    Ok(records)
}

fn collect_lineage_views(store: &SqliteReceiptStore) -> Result<Vec<StoredLineageView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store
            .list_capability_snapshots_after_seq(after_seq, MAX_LIST_LIMIT)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if batch.is_empty() {
            break;
        }
        after_seq = batch.last().map(|record| record.seq).unwrap_or(after_seq);
        records.extend(stored_lineage_views(batch));
    }
    Ok(records)
}

fn collect_budget_views(store: &SqliteBudgetStore) -> Result<Vec<BudgetUsageView>, CliError> {
    let mut after_seq = None;
    let mut records = Vec::new();
    loop {
        let batch = store.list_usages_after(MAX_LIST_LIMIT, after_seq)?;
        if batch.is_empty() {
            break;
        }
        after_seq = batch.last().map(|record| record.seq);
        records.extend(batch.into_iter().map(|usage| BudgetUsageView {
            capability_id: usage.capability_id,
            grant_index: usage.grant_index,
            invocation_count: usage.invocation_count,
            total_cost_exposed: usage.total_cost_exposed,
            total_cost_realized_spend: usage.total_cost_realized_spend,
            updated_at: usage.updated_at,
            seq: Some(usage.seq),
        }));
    }
    Ok(records)
}

fn collect_budget_invocation_quota_views(
    store: &SqliteBudgetStore,
) -> Result<Vec<BudgetInvocationQuotaUsageRecordView>, CliError> {
    let mut after: Option<BudgetInvocationQuotaUsageRecord> = None;
    let mut records = Vec::new();
    loop {
        let batch = store
            .list_compatibility_invocation_quota_usages_after(MAX_LIST_LIMIT, after.as_ref())?;
        if batch.is_empty() {
            break;
        }
        after = batch.last().cloned();
        records.extend(
            batch
                .into_iter()
                .map(budget_invocation_quota_usage_record_view),
        );
    }
    Ok(records)
}

fn collect_budget_mutation_event_views(
    store: &SqliteBudgetStore,
) -> Result<Vec<BudgetMutationEventView>, CliError> {
    // Page the FULL mutation-event history in MAX_LIST_LIMIT chunks (like the
    // receipt/lineage/usage collectors above) rather than one unbounded
    // i64::MAX-limit query, so a very large budget history does not load in a
    // single giant query. Semantics are unchanged: the
    // dense event_seq column is strictly increasing and unique, and both
    // `list_mutation_events` and `list_mutation_events_after_seq` order by
    // event_seq ASC, so this yields the identical full, ascending event set.
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_mutation_events_after_seq(MAX_LIST_LIMIT, after_seq)?;
        if batch.is_empty() {
            break;
        }
        after_seq = batch
            .last()
            .map(|record| record.event_seq)
            .unwrap_or(after_seq);
        records.extend(batch.into_iter().map(budget_mutation_event_view));
    }
    Ok(records)
}

#[cfg(test)]
mod authority_snapshot_tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn missing_authority_custody_returns_service_unavailable_without_bootstrapping() {
        let temp = tempfile::tempdir().test_unwrap();
        let path = temp.path().join("missing-authority.sqlite3");

        let response = authority_snapshot_response(&path);

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn authority_snapshot_is_explicitly_observational_and_does_not_mutate_custody() {
        let temp = tempfile::tempdir().test_unwrap();
        let path = temp.path().join("authority.sqlite3");
        let authority = SqliteCapabilityAuthority::open(&path).test_unwrap();
        let before = authority.status().test_unwrap();

        let response = authority_snapshot_response(&path);
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert!(snapshot["observationalOnly"].as_bool().test_unwrap());
        assert_eq!(snapshot["generation"], before.generation);
        assert_eq!(snapshot["publicKeyHex"], before.public_key.to_hex());

        let after = authority.status().test_unwrap();
        assert_eq!(after.generation, before.generation);
        assert_eq!(after.public_key, before.public_key);
        assert_eq!(after.rotated_at, before.rotated_at);
    }
}
