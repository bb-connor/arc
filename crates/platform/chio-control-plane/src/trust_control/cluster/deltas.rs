use super::*;

fn internal_cluster_http_error(context: &'static str, error: &dyn std::fmt::Display) -> Response {
    warn!(error = %error, "{context}");
    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, context)
}

pub(crate) async fn handle_internal_revocations_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<RevocationDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_REVOCATIONS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store.list_revocations_after(
        list_limit(query.limit),
        query.after_revoked_at,
        query.after_capability_id.as_deref(),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(RevocationDeltaResponse {
        records: records
            .into_iter()
            .map(|record| RevocationRecordView {
                capability_id: record.capability_id,
                revoked_at: record.revoked_at,
            })
            .collect(),
    })
    .into_response()
}

pub(crate) async fn handle_internal_tool_receipts_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_TOOL_RECEIPTS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let read_context = ReceiptReadContext::admin_service();
    let records = match store.list_tool_receipts_after_seq_with_context(
        &read_context,
        query.after_seq.unwrap_or(0),
        list_limit(query.limit),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let records = match stored_tool_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

pub(crate) async fn handle_internal_child_receipts_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_CHILD_RECEIPTS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let read_context = ReceiptReadContext::admin_service();
    let records = match store.list_child_receipts_after_seq_with_context(
        &read_context,
        query.after_seq.unwrap_or(0),
        list_limit(query.limit),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let records = match stored_child_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

pub(crate) async fn handle_internal_budgets_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_BUDGETS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let mutation_events = match collect_budget_mutation_event_views_after_seq(
        &store,
        query.after_seq.unwrap_or(0),
        list_limit(query.limit),
    ) {
        Ok(events) => events,
        Err(error) => {
            return internal_cluster_http_error("failed to collect budget mutation deltas", &error);
        }
    };
    let records = if mutation_events.is_empty() {
        Vec::new()
    } else {
        match collect_budget_projection_views_for_events(&store, &mutation_events) {
            Ok(records) => records,
            Err(error) => {
                return internal_cluster_http_error(
                    "failed to collect budget projection deltas",
                    &error,
                );
            }
        }
    };
    Json(BudgetDeltaResponse {
        records,
        mutation_events,
    })
    .into_response()
}

pub(crate) async fn handle_internal_lineage_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_LINEAGE_DELTA_PATH)
    {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store
        .list_capability_snapshots_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(LineageDeltaResponse {
        records: stored_lineage_views(records),
    })
    .into_response()
}

pub(crate) async fn run_cluster_sync_loop(state: TrustServiceState) {
    loop {
        let sync_state = state.clone();
        match tokio::task::spawn_blocking(move || sync_cluster_once(&sync_state)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(error = %error, "trust-control cluster sync failed");
            }
            Err(error) => {
                warn!(error = %error, "trust-control cluster sync task panicked");
            }
        }
        if let Some(progress) = state.cluster_progress.as_ref() {
            progress.notify_round_complete();
        }
        // The loop is the sole sync driver: race the inter-round sleep against a
        // writer kick so a waiting budget write is served promptly without
        // spawning its own sync storm (RFC-0011 D3, F14).
        match state.cluster_progress.as_ref() {
            Some(progress) => {
                tokio::select! {
                    _ = tokio::time::sleep(state.config.cluster_sync_interval) => {}
                    _ = progress.awaited_kick() => {}
                }
            }
            None => tokio::time::sleep(state.config.cluster_sync_interval).await,
        }
    }
}

pub(crate) fn sync_cluster_once(state: &TrustServiceState) -> Result<(), CliError> {
    let Some(cluster) = state.cluster.as_ref() else {
        return Ok(());
    };
    let peers = match cluster.lock() {
        Ok(guard) => guard.peers.keys().cloned().collect::<Vec<_>>(),
        Err(poisoned) => poisoned
            .into_inner()
            .peers
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
    };
    for peer_url in peers {
        let _ = sync_peer(state, &peer_url);
    }
    Ok(())
}

fn sync_peer(state: &TrustServiceState, peer_url: &str) -> Result<(), CliError> {
    if peer_is_partitioned(state, peer_url) {
        return Ok(());
    }
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(());
    };
    let client = service_runtime::client::build_cluster_peer_client(
        peer_url,
        &state.config.service_token,
        &self_url,
    )?;
    let peer_status = match client.cluster_status() {
        Ok(status) => status,
        Err(error) => {
            update_peer_failure(state, peer_url, error.to_string());
            return Err(error);
        }
    };
    update_peer_reachable(state, peer_url);
    update_peer_budget_acks(state, peer_url, &peer_status.budget_ack_heads);
    if peer_should_force_snapshot(state, peer_url) {
        let snapshot = client.cluster_snapshot()?;
        apply_cluster_snapshot(state, peer_url, snapshot)?;
    }
    if let Err(error) = sync_peer_authority(state, &client) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    let mut round = PullRoundBudget::new();
    let mut delta_records = 0u64;
    route_pull(
        state,
        peer_url,
        sync_peer_revocations(state, &client, peer_url, &mut round),
        &mut delta_records,
    )?;
    route_pull(
        state,
        peer_url,
        sync_peer_tool_receipts(state, &client, peer_url, &mut round),
        &mut delta_records,
    )?;
    route_pull(
        state,
        peer_url,
        sync_peer_child_receipts(state, &client, peer_url, &mut round),
        &mut delta_records,
    )?;
    route_pull(
        state,
        peer_url,
        sync_peer_lineage(state, &client, peer_url, &mut round),
        &mut delta_records,
    )?;
    route_pull(
        state,
        peer_url,
        sync_peer_budgets(state, &client, peer_url, &mut round),
        &mut delta_records,
    )?;
    update_peer_delta_records(state, peer_url, delta_records);
    update_peer_success(state, peer_url);
    Ok(())
}

/// Fold one puller's result into the round: on success accumulate the applied
/// count; on `PullError::Protocol` demote the peer to Unhealthy (fail-closed,
/// leaves consensus and witness sets); on `PullError::Transient` keep the peer
/// Healthy but record the error. Both error arms short-circuit the round.
fn route_pull(
    state: &TrustServiceState,
    peer_url: &str,
    outcome: Result<u64, PullError>,
    delta_records: &mut u64,
) -> Result<(), CliError> {
    match outcome {
        Ok(count) => {
            *delta_records = delta_records.saturating_add(count);
            Ok(())
        }
        Err(PullError::Protocol(error)) => {
            let message = error.to_string();
            update_peer_failure(state, peer_url, message.clone());
            Err(CliError::cli_other_error(message))
        }
        Err(PullError::Transient(error)) => {
            update_peer_sync_error(state, peer_url, error.to_string());
            Err(error)
        }
    }
}

fn sync_peer_authority(
    state: &TrustServiceState,
    client: &TrustControlClient,
) -> Result<(), CliError> {
    let Some(path) = state.config.authority_db_path.as_deref() else {
        return Ok(());
    };
    let authority = SqliteCapabilityAuthority::open(path)?;
    let snapshot = authority_snapshot_from_view(client.authority_snapshot()?);
    authority.apply_snapshot(&snapshot)?;
    Ok(())
}

fn sync_peer_revocations(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.revocation_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteRevocationStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        let cursor = peer_revocation_cursor(state, peer_url);
        let response = client.revocation_deltas(&RevocationDeltaQuery {
            after_revoked_at: cursor.as_ref().map(|value| value.revoked_at),
            after_capability_id: cursor.as_ref().map(|value| value.capability_id.clone()),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        round.charge_page(response.records.len() as u64)?;
        let page_max = response
            .records
            .iter()
            .map(|record| RevocationCursor {
                revoked_at: record.revoked_at,
                capability_id: record.capability_id.clone(),
            })
            .max_by(|a, b| {
                (a.revoked_at, a.capability_id.as_str())
                    .cmp(&(b.revoked_at, b.capability_id.as_str()))
            })
            .ok_or(PeerProtocolError::NonAdvancingPage {
                after_seq: 0,
                page_max_seq: 0,
            })?;
        ensure_revocation_advanced(cursor.as_ref(), &page_max)?;
        let mut last_cursor = None;
        for record in response.records {
            store
                .upsert_revocation(&RevocationRecord {
                    capability_id: record.capability_id.clone(),
                    revoked_at: record.revoked_at,
                })
                .map_err(CliError::from)?;
            applied = applied.saturating_add(1);
            last_cursor = Some(RevocationCursor {
                revoked_at: record.revoked_at,
                capability_id: record.capability_id,
            });
        }
        if let Some(cursor) = last_cursor {
            update_peer_revocation_cursor(state, peer_url, cursor);
        }
    }
    Ok(applied)
}

fn sync_peer_tool_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_tool_seq(state, peer_url);
        let response = client.tool_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        round.charge_page(response.records.len() as u64)?;
        // Tool receipts are a NON-DENSE append-only seq stream: `seq` is an
        // INTEGER PRIMARY KEY AUTOINCREMENT written with ON CONFLICT DO NOTHING
        // and pruned by retention, so legitimate gaps (rows 1 and 3, no 2)
        // occur. A gap-free contiguity guard would demote an honest peer, so
        // only forward progress + within-page monotonicity is required; a
        // legitimate gap is accepted (RFC-0011 D1, codex #965 Finding 2).
        let seqs = response
            .records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>();
        require_forward_progress(after_seq, &seqs)?;
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChioReceipt =
                serde_json::from_value(record.receipt).map_err(CliError::from)?;
            store
                .append_chio_receipt(&receipt)
                .map_err(CliError::from)?;
            last_seq = last_seq.max(record.seq);
            applied = applied.saturating_add(1);
        }
        update_peer_tool_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

fn sync_peer_child_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_child_seq(state, peer_url);
        let response = client.child_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        round.charge_page(response.records.len() as u64)?;
        // Child receipts are a NON-DENSE append-only seq stream (AUTOINCREMENT +
        // ON CONFLICT DO NOTHING, retention-pruned), so gaps are legitimate.
        // Require only forward progress + within-page monotonicity; a gap-free
        // guard would demote an honest peer (RFC-0011 D1, codex #965 Finding 2).
        let seqs = response
            .records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>();
        require_forward_progress(after_seq, &seqs)?;
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChildRequestReceipt =
                serde_json::from_value(record.receipt).map_err(CliError::from)?;
            store
                .append_child_receipt(&receipt)
                .map_err(CliError::from)?;
            last_seq = last_seq.max(record.seq);
            applied = applied.saturating_add(1);
        }
        update_peer_child_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

fn sync_peer_budgets(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.budget_db_path.as_deref() else {
        return Ok(0);
    };
    let mut store = SqliteBudgetStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        let cursor = peer_budget_cursor(state, peer_url);
        let response = client.budget_deltas(&BudgetDeltaQuery {
            after_seq: cursor.as_ref().map(|value| value.seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        let outcome = import_budget_delta_response(&mut store, &response, cursor, round)?;
        applied = applied.saturating_add(outcome.applied_count);
        if let Some(cursor) = outcome.next_cursor {
            update_peer_budget_cursor(state, peer_url, cursor);
        }
        if !outcome.should_continue {
            break;
        }
    }
    Ok(applied)
}

#[derive(Debug)]
pub(crate) struct BudgetDeltaImportOutcome {
    pub(crate) applied_count: u64,
    pub(crate) next_cursor: Option<BudgetCursor>,
    pub(crate) should_continue: bool,
}

pub(crate) fn import_budget_delta_response(
    store: &mut SqliteBudgetStore,
    response: &BudgetDeltaResponse,
    current_cursor: Option<BudgetCursor>,
    round: &mut PullRoundBudget,
) -> Result<BudgetDeltaImportOutcome, PullError> {
    if response.records.is_empty() && response.mutation_events.is_empty() {
        return Ok(BudgetDeltaImportOutcome {
            applied_count: 0,
            next_cursor: current_cursor,
            should_continue: false,
        });
    }
    let record_count = response
        .records
        .len()
        .saturating_add(response.mutation_events.len());
    if record_count > BUDGET_DELTA_MAX_RECORDS {
        return Err(PullError::Transient(CliError::cli_other_error(format!(
            "budget delta response contains {record_count} records, maximum is {BUDGET_DELTA_MAX_RECORDS}"
        ))));
    }
    round.charge_page(record_count as u64)?;

    let previous_cursor_seq = current_cursor
        .as_ref()
        .map(|cursor| cursor.seq)
        .unwrap_or(0);

    // Budget mutation events are a single STORE-WIDE, dense append-only
    // event_seq stream: every allocation yields exactly one event, so each
    // authority's events are a sparse subsequence of one global sequence and the
    // budget pull cursor is a single GLOBAL event_seq. Enforce STRICT global
    // contiguity from the cursor: the pulled page, in global-seq order, must run
    // gap-free from previous_cursor_seq + 1 with no skipped global seq.
    //
    // A per-origin compaction floor MUST NOT authorize a jump here (codex #965
    // Finding 3): the cursor spans all origins, so anchoring at the floor of the
    // authority on the page head could advance the global cursor past global
    // seqs owned by a DIFFERENT origin that this node has not yet replicated,
    // permanently omitting them. A genuine global floor (a seq below which ALL
    // origins are provably covered) does not exist as a primitive, so the
    // fail-closed behavior is strict contiguity: a jump is a protocol violation
    // that demotes the peer and pins the cursor. A follower legitimately behind
    // a leader that compacted below its cursor heals via the force-snapshot path
    // (demotion -> Unhealthy -> full snapshot resets the cursor to the
    // snapshot's global head), not via a floor-authorized delta jump.
    if !response.mutation_events.is_empty() {
        let event_seqs = response
            .mutation_events
            .iter()
            .map(|event| event.event_seq)
            .collect::<Vec<_>>();
        require_contiguous_page(previous_cursor_seq.saturating_add(1), &event_seqs)?;
    }

    let usage_records = response
        .records
        .iter()
        .map(budget_usage_record_from_view)
        .collect::<Vec<_>>();
    let mutation_records = response
        .mutation_events
        .iter()
        .map(budget_mutation_record_from_view)
        .collect::<Result<Vec<_>, CliError>>()?;
    store
        .import_snapshot_records(&usage_records, &mutation_records)
        .map_err(CliError::from)?;

    let mut next_cursor = current_cursor;
    for event in &response.mutation_events {
        next_cursor = Some(merge_budget_cursor(
            next_cursor,
            budget_cursor_from_event(event),
        ));
    }
    if response.mutation_events.is_empty() {
        for usage in &response.records {
            if let Some(cursor) = budget_cursor_from_usage(usage) {
                next_cursor = Some(merge_budget_cursor(next_cursor, cursor));
            }
        }
    }

    let cursor_advanced = next_cursor
        .as_ref()
        .is_some_and(|cursor| cursor.seq > previous_cursor_seq);
    // Fail-closed: a non-empty page (records or mutation events) that does not
    // advance the merged cursor past the caller's position is a replaying or
    // buggy peer, not a continuation. Drop the old
    // `!mutation_events.is_empty()` escape hatch (RFC-0011 D1, F15).
    if !cursor_advanced {
        let page_max_seq = next_cursor.as_ref().map(|cursor| cursor.seq).unwrap_or(0);
        return Err(PullError::Protocol(PeerProtocolError::NonAdvancingPage {
            after_seq: previous_cursor_seq,
            page_max_seq,
        }));
    }
    let applied_count = if mutation_records.is_empty() {
        usage_records.len()
    } else {
        mutation_records.len()
    } as u64;

    Ok(BudgetDeltaImportOutcome {
        applied_count,
        next_cursor,
        should_continue: cursor_advanced,
    })
}

fn sync_peer_lineage(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let mut store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_lineage_seq(state, peer_url);
        let response = client.lineage_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        round.charge_page(response.records.len() as u64)?;
        // Lineage snapshots paginate on the capability_lineage rowid, which is
        // NON-DENSE: an upsert on an existing capability_id keeps its rowid and
        // deletes leave holes, so gaps are legitimate. Require only forward
        // progress + within-page monotonicity; a gap-free guard would demote an
        // honest peer (RFC-0011 D1, codex #965 Finding 2).
        let seqs = response
            .records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>();
        require_forward_progress(after_seq, &seqs)?;
        let mut last_seq = after_seq;
        for record in response.records {
            store
                .upsert_capability_snapshot(&record.snapshot)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            last_seq = last_seq.max(record.seq);
            applied = applied.saturating_add(1);
        }
        update_peer_lineage_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

fn budget_authorize_compensation_event_id(
    payload: &TryChargeCostRequest,
    budget_seq: u64,
) -> String {
    if let Some(event_id) = payload.event_id.as_deref() {
        return format!("{event_id}:rollback:{budget_seq}");
    }
    if let Some(hold_id) = payload.hold_id.as_deref() {
        return format!("{hold_id}:rollback:{budget_seq}");
    }
    format!(
        "rollback:{}:{}:{}",
        payload.capability_id, payload.grant_index, budget_seq
    )
}

pub(crate) fn rollback_budget_authorize_exposure(
    state: &TrustServiceState,
    payload: &TryChargeCostRequest,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    let store = open_budget_store(&state.config).map_err(|response| {
        BudgetStoreError::Invariant(format!(
            "failed to reopen budget store for compensation: {}",
            response.status()
        ))
    })?;
    let usage = store.get_usage(&payload.capability_id, payload.grant_index)?;
    let Some(usage) = usage else {
        return Ok(());
    };
    if usage.total_cost_exposed == 0 {
        return Ok(());
    }
    let rollback_event_id = budget_authorize_compensation_event_id(payload, usage.seq);
    store.reverse_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
        payload.hold_id.as_deref(),
        Some(&rollback_event_id),
        authority,
    )?;
    Ok(())
}

pub(crate) async fn respond_after_budget_write_quorum_commit<T>(
    state: &TrustServiceState,
    failure_message: &'static str,
    payload: Option<(T, BudgetWriteToken)>,
) -> Response
where
    T: Serialize,
{
    let Some((payload, write)) = payload else {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, failure_message);
    };
    let budget_commit = match wait_for_budget_write_quorum_commit(state, write).await {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    json_response_with_leader_visibility_and_budget_commit(state, payload, budget_commit)
}

pub(crate) fn respond_after_leader_visible_write<T, F>(
    state: &TrustServiceState,
    failure_message: &'static str,
    verify: F,
) -> Response
where
    T: Serialize,
    F: FnOnce() -> Result<Option<T>, Response>,
{
    let Some(payload) = (match verify() {
        Ok(payload) => payload,
        Err(response) => return response,
    }) else {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, failure_message);
    };
    json_response_with_leader_visibility(state, payload)
}

/// Identifies a specific budget write for the quorum witness: the origin
/// authority that wrote the mutation event, the event's own event_seq (NOT
/// usage.seq), and the budget term (lease epoch) it was written under.
#[derive(Debug, Clone)]
pub(crate) struct BudgetWriteToken {
    pub(crate) origin_id: String,
    pub(crate) event_seq: u64,
    pub(crate) budget_term: u64,
}

pub(crate) fn budget_write_quorum_commit_view(
    state: &TrustServiceState,
    write: &BudgetWriteToken,
) -> Option<BudgetWriteCommitView> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(mut guard) => budget_write_quorum_commit_view_locked(&mut guard, write),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            budget_write_quorum_commit_view_locked(&mut guard, write)
        }
    })
}

fn budget_write_quorum_commit_view_locked(
    cluster: &mut ClusterRuntimeState,
    write: &BudgetWriteToken,
) -> BudgetWriteCommitView {
    let consensus = compute_cluster_consensus_locked(cluster);
    let mut witness_urls = BTreeSet::from([cluster.self_url.clone()]);
    for (peer_url, peer_state) in &cluster.peers {
        // A peer counts only when its contiguous ack head for THIS write's
        // origin is at least the write's event_seq. An event from a different
        // origin is grouped under a different key and cannot witness; a legacy
        // NULL-authority event is excluded from budget_ack_heads and so never
        // witnesses (RFC-0011 D2, F16).
        let acked = peer_state
            .budget_import_acks
            .get(&write.origin_id)
            .is_some_and(|imported_seq| *imported_seq >= write.event_seq);
        if peer_state.health.is_reachable() && !peer_state.partitioned && acked {
            witness_urls.insert(peer_url.clone());
        }
    }
    let committed_nodes = witness_urls.len();
    let authority_id = consensus
        .leader_url
        .clone()
        .unwrap_or_else(|| cluster.self_url.clone());
    let lease_epoch = write.budget_term;
    let lease_id = format!("{authority_id}#term-{lease_epoch}");
    BudgetWriteCommitView {
        budget_seq: write.event_seq,
        commit_index: write.event_seq,
        quorum_committed: committed_nodes >= consensus.quorum_size,
        quorum_size: consensus.quorum_size,
        committed_nodes,
        witness_urls: witness_urls.into_iter().collect(),
        authority_id,
        budget_term: write.budget_term,
        lease_id,
        lease_epoch,
    }
}

fn budget_write_quorum_commit_timeout(sync_interval: Duration) -> Duration {
    let scaled = sync_interval
        .checked_mul(20)
        .unwrap_or_else(|| Duration::from_secs(30));
    scaled
        .max(Duration::from_secs(5))
        .min(Duration::from_secs(30))
}

/// Outcome when the `ClusterProgress` watch closes while a budget write is
/// parked on it (the sync/progress task died mid-wait).
///
/// Fail-closed (codex #962): a node that is STILL clustered must return a 503
/// so the caller (`handle_try_charge_cost`) rolls back the local exposure. The
/// caller only rolls back on `Err`; returning `Ok(None)` here would render as a
/// successful leader-visible write with NO `budgetCommit`, indistinguishable
/// from a genuinely unclustered node, so an HA budget write could be acked
/// without ever reaching quorum. Only a node that has since dropped its cluster
/// (`state.cluster` is `None`) returns the legitimately-unclustered `Ok(None)`.
pub(crate) fn budget_write_progress_closed_outcome(
    state: &TrustServiceState,
    write: &BudgetWriteToken,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    if state.cluster.is_some() {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!(
                "budget write became leader-visible at commit index {} for authority term {} but the cluster progress channel closed before quorum",
                write.event_seq, write.budget_term
            ),
        ));
    }
    Ok(None)
}

pub(crate) async fn wait_for_budget_write_quorum_commit(
    state: &TrustServiceState,
    write: BudgetWriteToken,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    let Some(progress) = state.cluster_progress.as_ref() else {
        return Ok(None); // not clustered
    };
    let timeout = budget_write_quorum_commit_timeout(state.config.cluster_sync_interval);
    let mut rx = progress.subscribe();
    progress.request_sync();

    // Park on the progress watch under a single wall-clock bound and drive no
    // sync directly: the background loop is the sole sync driver, so one slow
    // peer can no longer multiply N concurrent writes into N sync storms; the
    // write waits out the bound and fails closed (RFC-0011 D3, F14).
    let waited = tokio::time::timeout(timeout, async {
        loop {
            let Some(view) = budget_write_quorum_commit_view(state, &write) else {
                return Ok::<_, Response>(None);
            };
            if view.quorum_committed {
                return Ok(Some(view));
            }
            if !cluster_consensus_view(state).is_some_and(|consensus| consensus.has_quorum) {
                return Err(plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!(
                        "budget write became leader-visible at commit index {} for authority term {} but cluster quorum disappeared before commit",
                        write.event_seq, write.budget_term
                    ),
                ));
            }
            if rx.changed().await.is_err() {
                // The ClusterProgress sender was dropped: the sync/progress task
                // died mid-write. Fail closed while still clustered (codex #962);
                // see budget_write_progress_closed_outcome.
                return budget_write_progress_closed_outcome(state, &write);
            }
        }
    })
    .await;

    match waited {
        Ok(inner) => inner,
        Err(_elapsed) => {
            let observed = budget_write_quorum_commit_view(state, &write);
            Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "budget write became leader-visible at commit index {} for authority term {} but quorum acks did not arrive before timeout ({}/{})",
                    write.event_seq,
                    write.budget_term,
                    observed.as_ref().map(|v| v.committed_nodes).unwrap_or(0),
                    observed.as_ref().map(|v| v.quorum_size).unwrap_or(0),
                ),
            ))
        }
    }
}

pub(crate) fn collect_budget_mutation_event_views_after_seq(
    store: &SqliteBudgetStore,
    after_seq: u64,
    limit: usize,
) -> Result<Vec<BudgetMutationEventView>, CliError> {
    Ok(store
        .list_mutation_events_after_seq(limit, after_seq)?
        .into_iter()
        .map(budget_mutation_event_view)
        .collect())
}

fn collect_budget_projection_views_for_events(
    store: &SqliteBudgetStore,
    events: &[BudgetMutationEventView],
) -> Result<Vec<BudgetUsageView>, CliError> {
    let mut latest = BTreeMap::<(String, u32), BudgetUsageView>::new();
    for event in events {
        let Some(usage) = store.get_usage(&event.capability_id, event.grant_index as usize)? else {
            continue;
        };
        latest.insert(
            (usage.capability_id.clone(), usage.grant_index),
            BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
                updated_at: usage.updated_at,
                seq: Some(usage.seq),
            },
        );
    }
    Ok(latest.into_values().collect())
}

pub(crate) fn budget_mutation_event_view(record: BudgetMutationRecord) -> BudgetMutationEventView {
    BudgetMutationEventView {
        event_id: record.event_id,
        hold_id: record.hold_id,
        capability_id: record.capability_id,
        grant_index: record.grant_index,
        kind: record.kind.as_str().to_string(),
        allowed: record.allowed,
        recorded_at: record.recorded_at,
        event_seq: record.event_seq,
        usage_seq: record.usage_seq,
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        max_invocations: record.max_invocations,
        max_cost_per_invocation: record.max_cost_per_invocation,
        max_total_cost_units: record.max_total_cost_units,
        invocation_count_after: record.invocation_count_after,
        total_cost_exposed_after: record.total_cost_exposed_after,
        total_cost_realized_spend_after: record.total_cost_realized_spend_after,
        authority: record
            .authority
            .map(|authority| BudgetMutationAuthorityView {
                authority_id: authority.authority_id,
                lease_id: authority.lease_id,
                lease_epoch: authority.lease_epoch,
            }),
    }
}

pub(crate) fn budget_usage_record_from_view(
    usage: &BudgetUsageView,
) -> chio_kernel::BudgetUsageRecord {
    chio_kernel::BudgetUsageRecord {
        capability_id: usage.capability_id.clone(),
        grant_index: usage.grant_index,
        invocation_count: usage.invocation_count,
        updated_at: usage.updated_at,
        seq: usage.seq.unwrap_or(0),
        total_cost_exposed: usage.total_cost_exposed,
        total_cost_realized_spend: usage.total_cost_realized_spend,
    }
}

pub(crate) fn budget_cursor_from_event(event: &BudgetMutationEventView) -> BudgetCursor {
    BudgetCursor {
        seq: event.event_seq,
        updated_at: event.recorded_at,
        capability_id: event.capability_id.clone(),
        grant_index: event.grant_index,
    }
}

fn budget_cursor_from_usage(usage: &BudgetUsageView) -> Option<BudgetCursor> {
    Some(BudgetCursor {
        seq: usage.seq?,
        updated_at: usage.updated_at,
        capability_id: usage.capability_id.clone(),
        grant_index: usage.grant_index,
    })
}

pub(crate) fn merge_budget_cursor(
    current: Option<BudgetCursor>,
    candidate: BudgetCursor,
) -> BudgetCursor {
    match current {
        Some(existing)
            if existing.seq > candidate.seq
                || (existing.seq == candidate.seq
                    && existing.updated_at >= candidate.updated_at) =>
        {
            existing
        }
        _ => candidate,
    }
}

fn budget_event_authority_from_view(
    authority: &BudgetMutationAuthorityView,
) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority.authority_id.clone(),
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    }
}

pub(crate) fn budget_mutation_record_from_view(
    event: &BudgetMutationEventView,
) -> Result<BudgetMutationRecord, CliError> {
    let kind = BudgetMutationKind::parse(&event.kind).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "unknown budget mutation kind `{}` in cluster snapshot",
            event.kind
        ))
    })?;

    Ok(BudgetMutationRecord {
        event_id: event.event_id.clone(),
        hold_id: event.hold_id.clone(),
        capability_id: event.capability_id.clone(),
        grant_index: event.grant_index,
        kind,
        allowed: event.allowed,
        recorded_at: event.recorded_at,
        event_seq: event.event_seq,
        usage_seq: event.usage_seq,
        exposure_units: event.exposure_units,
        realized_spend_units: event.realized_spend_units,
        max_invocations: event.max_invocations,
        max_cost_per_invocation: event.max_cost_per_invocation,
        max_total_cost_units: event.max_total_cost_units,
        invocation_count_after: event.invocation_count_after,
        total_cost_exposed_after: event.total_cost_exposed_after,
        total_cost_realized_spend_after: event.total_cost_realized_spend_after,
        authority: event
            .authority
            .as_ref()
            .map(budget_event_authority_from_view),
    })
}
