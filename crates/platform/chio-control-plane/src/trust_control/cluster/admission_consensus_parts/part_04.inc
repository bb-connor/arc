fn apply_combined_capture(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let command: ConsensusCombinedCaptureCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = command
        .request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "combined capture omitted its persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let revocation_set = super::super::service_runtime::budget::canonical_revocation_set_from_view(
        &command.request.revocation_set,
    )
    .map_err(|error| error.to_string())?;
    let capture_request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
        operation_id: command.request.operation_id.clone(),
        budget: BudgetCaptureInvocationRequest {
            admission_operation: Some(
                BudgetAdmissionOperationBinding::new(
                    command.request.operation_id.clone(),
                    command.request.request_binding_hash.clone(),
                )
                .map_err(|error| error.to_string())?,
            ),
            capability_id: command.request.capability_id.clone(),
            grant_index: command.request.grant_index,
            hold_id: Some(command.request.hold_id.clone()),
            event_id: Some(command.request.event_id.clone()),
            authority: Some(authority.clone()),
        },
        revocation_set,
        bound_revocation_set_digest: command.request.bound_revocation_set_digest.clone(),
        authorization_artifact_digests: command.request.authorization_artifact_digests.clone(),
        aggregate_root_capability_id: command.request.aggregate_root_capability_id.clone(),
        aggregate_root_binding_digest: command.request.aggregate_root_binding_digest.clone(),
        last_observed_revocation_index: command.request.last_observed_revocation_index,
    })
    .map_err(|error| error.to_string())?;
    let decision = match SqliteAdmissionCaptureAuthority::capture_admission_in_transaction(
        transaction,
        capture_request,
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_capture_rejection(error),
    };
    let response = match decision {
        AdmissionCaptureDecision::Captured { budget, metadata } => {
            let budget_seq = budget.metadata.budget_commit_index.ok_or_else(|| {
                "combined capture result has no persisted budget sequence".to_string()
            })?;
            let (metadata_view, commit_view) =
                consensus_budget_evidence(proof, &authority, budget_seq);
            let budget_request = CaptureInvocationReservationsRequest {
                operation_id: command.request.operation_id.clone(),
                request_binding_hash: command.request.request_binding_hash.clone(),
                capability_id: command.request.capability_id.clone(),
                grant_index: command.request.grant_index,
                hold_id: command.request.hold_id.clone(),
                event_id: command.request.event_id.clone(),
                budget_authority: command.request.budget_authority.clone(),
            };
            let budget = super::super::budget_handlers::invocation_capture_response_view(
                &budget_request,
                *budget,
                metadata_view,
                commit_view,
            )
            .map_err(|error| error.to_string())?;
            let invocation_quotas = capture_quota_transition_views(
                &command.invocation_quotas,
                &budget.invocation_counts_after,
            )?;
            let invocation_state = budget.invocation_state;
            let monetary_state = budget.monetary_state;
            CombinedAdmissionCaptureResponse {
                operation_id: command.request.operation_id.clone(),
                request_binding_hash: command.request.request_binding_hash.clone(),
                capability_id: command.request.capability_id.clone(),
                grant_index: command.request.grant_index,
                hold_id: command.request.hold_id.clone(),
                event_id: command.request.event_id.clone(),
                outcome: AdmissionCaptureOutcomeView::Captured,
                budget: Some(budget),
                revocation_set: command.request.revocation_set.clone(),
                revoked_capability_ids: Vec::new(),
                metadata: AdmissionCaptureMetadataView {
                    operation_id: command.request.operation_id.clone(),
                    hold_id: command.request.hold_id.clone(),
                    event_id: command.request.event_id.clone(),
                    checked_revocation_set_digest: metadata
                        .checked_revocation_set_digest()
                        .to_string(),
                    invocation_quotas,
                    authorization_artifact_digests: command
                        .request
                        .authorization_artifact_digests
                        .clone(),
                    aggregate_root_capability_id: metadata
                        .aggregate_root_capability_id()
                        .map(ToOwned::to_owned),
                    aggregate_root_binding_digest: metadata
                        .aggregate_root_binding_digest()
                        .map(ToOwned::to_owned),
                    budget_commit_index: metadata.budget_commit().budget_commit_index,
                    revocation_commit_index: metadata.revocation_commit_index(),
                    authority_commit_index: metadata.authority_commit_index(),
                    leader_epoch: proof.leader_epoch,
                    guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
                    authority: command.request.budget_authority.clone(),
                    invocation_state,
                    monetary_state,
                },
            }
        }
        AdmissionCaptureDecision::Denied(denial) => CombinedAdmissionCaptureResponse {
            operation_id: command.request.operation_id.clone(),
            request_binding_hash: command.request.request_binding_hash.clone(),
            capability_id: command.request.capability_id.clone(),
            grant_index: command.request.grant_index,
            hold_id: command.request.hold_id.clone(),
            event_id: command.request.event_id.clone(),
            outcome: AdmissionCaptureOutcomeView::DeniedRevoked,
            budget: None,
            revocation_set: command.request.revocation_set.clone(),
            revoked_capability_ids: denial.revoked_ids().to_vec(),
            metadata: AdmissionCaptureMetadataView {
                operation_id: command.request.operation_id.clone(),
                hold_id: command.request.hold_id.clone(),
                event_id: command.request.event_id.clone(),
                checked_revocation_set_digest: denial
                    .metadata()
                    .checked_revocation_set_digest()
                    .to_string(),
                invocation_quotas: command
                    .invocation_quotas
                    .into_iter()
                    .map(AdmissionCaptureInvocationQuotaView::Definition)
                    .collect(),
                authorization_artifact_digests: command
                    .request
                    .authorization_artifact_digests
                    .clone(),
                aggregate_root_capability_id: denial
                    .metadata()
                    .aggregate_root_capability_id()
                    .map(ToOwned::to_owned),
                aggregate_root_binding_digest: denial
                    .metadata()
                    .aggregate_root_binding_digest()
                    .map(ToOwned::to_owned),
                budget_commit_index: denial.metadata().budget_commit().budget_commit_index,
                revocation_commit_index: denial.metadata().revocation_commit_index(),
                authority_commit_index: denial.metadata().authority_commit_index(),
                leader_epoch: proof.leader_epoch,
                guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
                authority: command.request.budget_authority.clone(),
                invocation_state: BudgetInvocationReservationStateView::Authorized,
                monetary_state: BudgetMonetaryHoldStateView::Exposed,
            },
        },
    };
    canonical_result(&response)
}

fn capture_quota_transition_views(
    expected: &[BudgetInvocationQuotaView],
    captured: &[BudgetInvocationQuotaUsageView],
) -> Result<Vec<AdmissionCaptureInvocationQuotaView>, String> {
    if expected.len() != captured.len() {
        return Err("combined capture changed the persisted quota count".to_string());
    }
    expected
        .iter()
        .zip(captured)
        .map(|(expected, captured)| {
            if &captured.quota != expected {
                return Err(
                    "combined capture changed a persisted quota key or maximum".to_string(),
                );
            }
            let reserved_invocations_before = captured
                .reserved_invocations_after
                .checked_add(1)
                .ok_or_else(|| "combined capture reserved quota count overflowed".to_string())?;
            let captured_invocations_before = captured
                .captured_invocations_after
                .checked_sub(1)
                .ok_or_else(|| "combined capture captured quota count underflowed".to_string())?;
            Ok(AdmissionCaptureInvocationQuotaView::Transition(
                AdmissionCaptureInvocationQuotaTransitionView {
                    key: expected.key.clone(),
                    max_invocations: expected.max_invocations,
                    reserved_invocations_before,
                    reserved_invocations_after: captured.reserved_invocations_after,
                    captured_invocations_before,
                    captured_invocations_after: captured.captured_invocations_after,
                },
            ))
        })
        .collect()
}

fn budget_authority_from_view(
    view: &BudgetMutationAuthorityView,
) -> Result<BudgetEventAuthority, String> {
    if view.authority_id.is_empty() || view.lease_id.is_empty() || view.lease_epoch == 0 {
        return Err("admission budget authority is incomplete".to_string());
    }
    Ok(BudgetEventAuthority {
        authority_id: view.authority_id.clone(),
        lease_id: view.lease_id.clone(),
        lease_epoch: view.lease_epoch,
    })
}

fn consensus_budget_evidence(
    proof: &AdmissionCommitProof,
    authority: &BudgetEventAuthority,
    budget_seq: u64,
) -> (BudgetAuthorityMetadataView, BudgetWriteCommitView) {
    let metadata = BudgetAuthorityMetadataView {
        authority_id: authority.authority_id.clone(),
        leader_url: proof.leader_id.clone(),
        budget_term: authority.lease_epoch,
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
        lease_expires_at: u64::MAX,
        lease_ttl_ms: u64::MAX,
        guarantee_level: "ha_linearizable".to_string(),
        budget_commit_index: Some(proof.index),
    };
    let commit = BudgetWriteCommitView {
        budget_seq,
        commit_index: proof.index,
        quorum_committed: true,
        quorum_size: proof.quorum_size,
        committed_nodes: proof.witness_urls.len(),
        witness_urls: proof.witness_urls.clone(),
        authority_id: authority.authority_id.clone(),
        budget_term: authority.lease_epoch,
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    };
    (metadata, commit)
}

fn open_capture_authority(
    config: &TrustServiceConfig,
) -> Result<SqliteAdmissionCaptureAuthority, String> {
    let budget_path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "admission budget database is unavailable".to_string())?;
    let revocation_path = config
        .revocation_db_path
        .as_deref()
        .ok_or_else(|| "admission revocation database is unavailable".to_string())?;
    SqliteAdmissionCaptureAuthority::open_with_paths(budget_path, revocation_path)
        .map_err(|error| error.to_string())
}

fn canonical_result<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json_bytes(value).map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|_| "canonical admission result was not UTF-8".to_string())
}

fn canonical_rejection(status_code: u16, code: &str, message: String) -> Result<String, String> {
    canonical_result(&AdmissionConsensusRejectionEnvelope {
        admission_consensus_rejection: AdmissionConsensusRejection {
            status_code,
            code: code.to_string(),
            message,
        },
    })
}

fn frozen_budget_rejection(error: BudgetStoreError) -> Result<String, String> {
    match error {
        BudgetStoreError::Conflict(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "budget_state_conflict",
            message,
        ),
        BudgetStoreError::Overflow(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "budget_arithmetic_conflict",
            message,
        ),
        BudgetStoreError::Invariant(message) => Err(message),
        BudgetStoreError::Sqlite(error) => Err(error.to_string()),
        BudgetStoreError::Io(error) => Err(error.to_string()),
    }
}

fn frozen_capture_rejection(error: AdmissionCaptureError) -> Result<String, String> {
    match error {
        AdmissionCaptureError::InvalidRequest(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "admission_capture_conflict",
            message,
        ),
        AdmissionCaptureError::BudgetStore(error) => frozen_budget_rejection(error),
        AdmissionCaptureError::RevocationStore(error) => Err(error.to_string()),
        AdmissionCaptureError::Unavailable(message) => Err(message),
    }
}

fn accepted_consensus_result(
    result: AdmissionConsensusResult,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    let value: Value = serde_json::from_str(&result.response_json).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "committed admission result is invalid JSON: {error}"
        ))
    })?;
    if value.get("admissionConsensusRejection").is_none() {
        return Ok(result);
    }
    let envelope: AdmissionConsensusRejectionEnvelope =
        serde_json::from_value(value).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "committed admission rejection is malformed: {error}"
            ))
        })?;
    let rejection = envelope.admission_consensus_rejection;
    StatusCode::from_u16(rejection.status_code).map_err(|_| {
        AdmissionConsensusError::Protocol(
            "committed admission rejection has an invalid HTTP status".to_string(),
        )
    })?;
    Err(AdmissionConsensusError::Rejected {
        status_code: rejection.status_code,
        message: rejection.message,
    })
}

fn consensus_http_error(error: AdmissionConsensusError) -> Response {
    match error {
        AdmissionConsensusError::Protocol(message) => {
            plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &message)
        }
        AdmissionConsensusError::Storage(error) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("admission consensus storage failed: {error}"),
        ),
        AdmissionConsensusError::Apply(message) => {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
        AdmissionConsensusError::Rejected {
            status_code,
            message,
        } => plain_http_error(
            StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &message,
        ),
    }
}

pub(crate) async fn handle_internal_admission_proposal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionProposalRequest>,
) -> Response {
    if let Err(response) = validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_ADMISSION_PROPOSAL_PATH,
        &request,
    )
    {
        return response;
    }
    if let Err(error) = admission_members(&state) {
        return consensus_http_error(error);
    }
    let result = tokio::task::spawn_blocking(move || {
        propose_admission_command_local(
            &state,
            request.operation_id,
            request.command_kind,
            request.command,
        )
    })
    .await;
    match result {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission proposal worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_internal_admission_capture_query(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionCapturePointQueryRequest>,
) -> Response {
    if let Err(response) = validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_ADMISSION_CAPTURE_QUERY_PATH,
        &request,
    ) {
        return response;
    }
    let (node_id, _, membership) = match admission_members(&state) {
        Ok(members) => members,
        Err(error) => return consensus_http_error(error),
    };
    let config = state.config.clone();
    let result = tokio::task::spawn_blocking(move || {
        query_admission_capture_replica(&config, &membership, &node_id, &request)
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission capture replica query worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_internal_invocation_capture_query(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CaptureInvocationPointQueryRequest>,
) -> Response {
    if let Err(response) = validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_INVOCATION_CAPTURE_QUERY_PATH,
        &request,
    ) {
        return response;
    }
    let (node_id, _, membership) = match admission_members(&state) {
        Ok(members) => members,
        Err(error) => return consensus_http_error(error),
    };
    let config = state.config.clone();
    let result = tokio::task::spawn_blocking(move || {
        query_invocation_capture_replica(&config, &membership, &node_id, &request)
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invocation capture replica query worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_internal_admission_request_vote(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionRequestVoteRequest>,
) -> Response {
    let peer = match validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_ADMISSION_REQUEST_VOTE_PATH,
        &request,
    ) {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    if peer.term != Some(request.term) || peer.node_id != request.candidate_id {
        return plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission vote identity or term does not match peer authentication",
        );
    }
    let membership = match admission_members(&state) {
        Ok((_, _, membership)) => membership,
        Err(error) => return consensus_http_error(error),
    };
    match configured_admission_consensus_store(&state.config)
        .and_then(|store| store.request_vote(&membership, &request))
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => consensus_http_error(error),
    }
}

pub(crate) async fn handle_internal_admission_append_entries(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionAppendEntriesRequest>,
) -> Response {
    let peer = match validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_ADMISSION_APPEND_ENTRIES_PATH,
        &request,
    ) {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    if peer.term != Some(request.term) || peer.node_id != request.leader_id {
        return plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission append identity or term does not match peer authentication",
        );
    }
    let config = state.config.clone();
    let membership = match admission_members(&state) {
        Ok((_, _, membership)) => membership,
        Err(error) => return consensus_http_error(error),
    };
    let result = tokio::task::spawn_blocking(move || {
        let store = configured_admission_consensus_store(&config)?;
        store.append_entries(&membership, &request, |transaction, entry, proof| {
            apply_admission_log_entry(&config, transaction, entry, proof)
        })
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission append worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_internal_admission_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_cluster_peer_empty_request(
        &headers,
        &state.config,
        "GET",
        INTERNAL_ADMISSION_SNAPSHOT_PATH,
    )
    {
        return response;
    }
    let membership = match admission_members(&state) {
        Ok((_, _, membership)) => membership,
        Err(error) => return consensus_http_error(error),
    };
    match configured_admission_consensus_store(&state.config).and_then(|store| {
        store.bind_membership(&membership)?;
        store.snapshot()
    }) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => consensus_http_error(error),
    }
}

pub(crate) async fn handle_internal_admission_snapshot_install(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(snapshot): Json<AdmissionConsensusSnapshot>,
) -> Response {
    let peer = match validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_ADMISSION_SNAPSHOT_PATH,
        &snapshot,
    ) {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    if peer.term != Some(snapshot.meta.current_term)
        || snapshot.meta.voted_for.as_deref() != Some(peer.node_id.as_str())
    {
        return plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission snapshot leader or term does not match peer authentication",
        );
    }
    if snapshot.meta.current_term > i64::MAX as u64 {
        return consensus_http_error(AdmissionConsensusError::Protocol(
            "admission snapshot term exceeds the supported range".to_string(),
        ));
    }
    if let Err(error) = configured_admission_consensus_store(&state.config)
        .and_then(|store| store.observe_higher_term(snapshot.meta.current_term))
    {
        return consensus_http_error(error);
    }
    let config = state.config.clone();
    let membership = match admission_member_urls(&state).and_then(|(_, _, members)| match snapshot
        .genesis_projection
        .clone()
    {
        Some(genesis) => AdmissionMembership::new_with_genesis(members, genesis),
        None => AdmissionMembership::new_with_baseline(members, None),
    }) {
        Ok(membership) => membership,
        Err(error) => return consensus_http_error(error),
    };
    match tokio::task::spawn_blocking(move || {
        configured_admission_consensus_store(&config)?.install_snapshot(
            &membership,
            &snapshot,
            |transaction, entry, proof| {
                apply_admission_log_entry(&config, transaction, entry, proof)
            },
        )
    })
    .await
    {
        Ok(Ok(())) => Json(json!({"installed": true})).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission snapshot install failed before completion",
        ),
    }
}

fn configure_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
    )
}

fn initialize_schema(connection: &mut Connection) -> Result<(), AdmissionConsensusError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS admission_consensus_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL CHECK (schema_version = 3),
            current_term INTEGER NOT NULL CHECK (current_term >= 0),
            baseline_state_digest TEXT
                CHECK (
                    baseline_state_digest IS NULL
                    OR (
                        length(baseline_state_digest) = 64
                        AND baseline_state_digest NOT GLOB '*[^0-9a-f]*'
                    )
                ),
            membership_digest TEXT
                CHECK (
                    membership_digest IS NULL
                    OR (
                        length(membership_digest) = 64
                        AND membership_digest NOT GLOB '*[^0-9a-f]*'
                    )
                ),
            voted_for TEXT,
            last_log_index INTEGER NOT NULL CHECK (last_log_index >= 0),
            last_log_term INTEGER NOT NULL CHECK (last_log_term >= 0),
            commit_index INTEGER NOT NULL CHECK (commit_index >= 0),
            last_applied INTEGER NOT NULL CHECK (last_applied >= 0),
            applied_state_digest TEXT NOT NULL
                CHECK (
                    length(applied_state_digest) = 64
                    AND applied_state_digest NOT GLOB '*[^0-9a-f]*'
                ),
            CHECK (last_applied <= commit_index),
            CHECK (commit_index <= last_log_index)
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_log (
            log_index INTEGER PRIMARY KEY CHECK (log_index > 0),
            leader_epoch INTEGER NOT NULL CHECK (leader_epoch > 0),
            operation_id TEXT NOT NULL UNIQUE,
            command_kind TEXT NOT NULL CHECK (command_kind IN (
                'leadership_barrier', 'increment_invocation', 'composite_authorize',
                'capture_invocations',
                'reverse_exposure', 'release_exposure', 'reconcile_spend',
                'capture_exposure', 'revoke', 'combined_capture'
            )),
            canonical_command TEXT NOT NULL,
            command_digest TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_commits (
            log_index INTEGER PRIMARY KEY REFERENCES admission_consensus_log(log_index),
            leader_epoch INTEGER NOT NULL CHECK (leader_epoch > 0),
            current_term_commit_index INTEGER NOT NULL
                CHECK (current_term_commit_index >= log_index),
            leader_id TEXT NOT NULL,
            membership_digest TEXT NOT NULL
                CHECK (
                    length(membership_digest) = 64
                    AND membership_digest NOT GLOB '*[^0-9a-f]*'
                ),
            quorum_size INTEGER NOT NULL CHECK (quorum_size > 0),
            witness_urls_json TEXT NOT NULL,
            protocol_version TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_results (
            operation_id TEXT PRIMARY KEY REFERENCES admission_consensus_log(operation_id),
            log_index INTEGER NOT NULL UNIQUE REFERENCES admission_consensus_log(log_index),
            response_json TEXT NOT NULL,
            response_digest TEXT NOT NULL,
            security_projection_digest TEXT NOT NULL
                CHECK (
                    length(security_projection_digest) = 64
                    AND security_projection_digest NOT GLOB '*[^0-9a-f]*'
                )
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_genesis (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            projection_json TEXT NOT NULL,
            projection_digest TEXT NOT NULL
                CHECK (
                    length(projection_digest) = 64
                    AND projection_digest NOT GLOB '*[^0-9a-f]*'
                )
        );
        "#,
    )?;
    let has_baseline = {
        let mut statement = transaction.prepare("PRAGMA table_info(admission_consensus_meta)")?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        columns
            .iter()
            .any(|column| column == "baseline_state_digest")
    };
    if !has_baseline {
        transaction.execute_batch(
            r#"
            ALTER TABLE admission_consensus_meta
            ADD COLUMN baseline_state_digest TEXT
                CHECK (
                    baseline_state_digest IS NULL
                    OR (
                        length(baseline_state_digest) = 64
                        AND baseline_state_digest NOT GLOB '*[^0-9a-f]*'
                    )
                );
            "#,
        )?;
    }
    transaction.execute(
        r#"
        INSERT OR IGNORE INTO admission_consensus_meta (
            singleton, schema_version, current_term, baseline_state_digest,
            membership_digest, voted_for,
            last_log_index, last_log_term, commit_index, last_applied,
            applied_state_digest
        ) VALUES (1, 3, 0, NULL, NULL, NULL, 0, 0, 0, 0, ?1)
        "#,
        params![initial_applied_state_digest()],
    )?;
    transaction.commit()?;
    load_meta(connection)?;
    validate_consensus_result_schema(connection)?;
    Ok(())
}

fn validate_consensus_result_schema(
    connection: &Connection,
) -> Result<(), AdmissionConsensusError> {
    let mut statement = connection.prepare("PRAGMA table_info(admission_consensus_results)")?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|(name, value_type, not_null)| {
        name == "security_projection_digest"
            && value_type.eq_ignore_ascii_case("TEXT")
            && *not_null == 1
    }) {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus result schema does not provide the v2 security projection digest"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_integrity(connection: &Connection) -> Result<(), AdmissionConsensusError> {
    let meta = load_meta(connection)?;
    if meta
        .membership_digest
        .as_deref()
        .is_some_and(|digest| !is_lower_sha256(digest))
        || meta
            .baseline_state_digest
            .as_deref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        || (meta.membership_digest.is_none() && meta.baseline_state_digest.is_some())
        || !is_lower_sha256(&meta.applied_state_digest)
        || meta.current_term < meta.last_log_term
        || meta
            .voted_for
            .as_deref()
            .is_some_and(|candidate| validate_node_id(candidate).is_err())
        || (meta.membership_digest.is_none()
            && (meta.current_term != 0 || meta.last_log_index != 0))
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission persisted membership binding is invalid".to_string(),
        ));
    }
    let genesis_projection = load_genesis_projection(connection)?;
    match (
        meta.baseline_state_digest.as_deref(),
        genesis_projection.as_ref(),
    ) {
        (Some(expected), Some(projection))
            if admission_genesis_projection_digest(projection)? == expected => {}
        (None, None) => {}
        _ => {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted genesis projection does not match its baseline".to_string(),
            ));
        }
    }
    let entries = load_all_entries(connection)?;
    if entries.len() != usize_index(meta.last_log_index, "admission last log index")? {
        return Err(AdmissionConsensusError::Protocol(
            "admission log is not contiguous".to_string(),
        ));
    }
    for (offset, entry) in entries.iter().enumerate() {
        if entry.index != one_based_offset(offset, "admission log offset")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission log contains an index gap".to_string(),
            ));
        }
        validate_entry(entry)?;
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].leader_epoch > pair[1].leader_epoch)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission log terms are not monotonic".to_string(),
        ));
    }
    if let Some(last) = entries.last() {
        if last.index != meta.last_log_index || last.leader_epoch != meta.last_log_term {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted log head does not match the log".to_string(),
            ));
        }
    } else if meta.last_log_index != 0 || meta.last_log_term != 0 {
        return Err(AdmissionConsensusError::Protocol(
            "empty admission log has a nonzero head".to_string(),
        ));
    }
    for index in 1..=meta.commit_index {
        let proof = load_commit_proof(connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission commit proof {index} is missing"))
        })?;
        validate_commit_proof(&proof)?;
        if meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str()) {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof membership differs from persisted state".to_string(),
            ));
        }
        if proof.leader_epoch > meta.current_term {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof exceeds the persisted term".to_string(),
            ));
        }
        let entry = load_entry(connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission entry {index} is missing"))
        })?;
        if entry.leader_epoch > proof.leader_epoch {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof predates its log entry".to_string(),
            ));
        }
        if load_entry(connection, proof.current_term_commit_index)?
            .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof has no current-term commit target".to_string(),
            ));
        }
    }
    let results = load_results(connection)?;
    if results.len() != usize_index(meta.last_applied, "admission applied result index")? {
        return Err(AdmissionConsensusError::Protocol(
            "admission result coverage does not match last-applied".to_string(),
        ));
    }
    let mut applied_state_digest = initial_applied_state_digest();
    for (offset, result) in results.iter().enumerate() {
        let index = one_based_offset(offset, "admission result offset")?;
        let entry = load_entry(connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission entry {index} is missing"))
        })?;
        validate_canonical_json(&result.response_json, "admission persisted result")?;
        if result.log_index != index
            || result.operation_id != entry.operation_id
            || sha256_hex(result.response_json.as_bytes()) != result.response_digest
            || !is_lower_sha256(&result.security_projection_digest)
        {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission result {index} does not match its entry or digest"
            )));
        }
        applied_state_digest = next_applied_state_digest(
            &applied_state_digest,
            &result.response_digest,
            &result.security_projection_digest,
        )?;
    }
    if meta.applied_state_digest != applied_state_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission applied-state digest does not match persisted results".to_string(),
        ));
    }
    let expected_security_projection = if meta.baseline_state_digest.is_none() {
        None
    } else if let Some(result) = results.last() {
        Some(result.security_projection_digest.clone())
    } else if let Some(genesis_projection) = genesis_projection.as_ref() {
        Some(admission_security_projection_digest(genesis_projection)?)
    } else {
        None
    };
    if let Some(expected) = expected_security_projection {
        let live = capture_admission_security_projection_digest_from_connection(connection)?;
        if live != expected {
            return Err(AdmissionConsensusError::Protocol(
                "admission live security projection differs from the committed result chain"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn load_meta(
    connection: &Connection,
) -> Result<AdmissionConsensusMetaView, AdmissionConsensusError> {
    let raw = connection.query_row(
        r#"
        SELECT current_term, baseline_state_digest, membership_digest, voted_for,
               last_log_index, last_log_term, commit_index, last_applied,
               applied_state_digest
        FROM admission_consensus_meta
        WHERE singleton = 1 AND schema_version = ?1
        "#,
        params![CONSENSUS_SCHEMA_VERSION],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        },
    )?;
    Ok(AdmissionConsensusMetaView {
        current_term: nonnegative_u64(raw.0, "current term")?,
        baseline_state_digest: raw.1,
        membership_digest: raw.2,
        voted_for: raw.3,
        last_log_index: nonnegative_u64(raw.4, "last log index")?,
        last_log_term: nonnegative_u64(raw.5, "last log term")?,
        commit_index: nonnegative_u64(raw.6, "commit index")?,
        last_applied: nonnegative_u64(raw.7, "last applied")?,
        applied_state_digest: raw.8,
    })
}

fn load_genesis_projection(
    connection: &Connection,
) -> Result<Option<AdmissionGenesisProjection>, AdmissionConsensusError> {
    let stored = connection
        .query_row(
            r#"
            SELECT projection_json, projection_digest
            FROM admission_consensus_genesis
            WHERE singleton = 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((projection_json, projection_digest)) = stored else {
        return Ok(None);
    };
    let projection: AdmissionGenesisProjection =
        serde_json::from_str(&projection_json).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "persisted admission genesis projection is invalid: {error}"
            ))
        })?;
    let canonical = canonical_json_bytes(&projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "persisted admission genesis projection cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != projection_json.as_bytes()
        || admission_genesis_projection_digest(&projection)? != projection_digest
    {
        return Err(AdmissionConsensusError::Protocol(
            "persisted admission genesis projection or digest is noncanonical".to_string(),
        ));
    }
    Ok(Some(projection))
}

fn persist_genesis_projection(
    transaction: &Transaction<'_>,
    projection: &AdmissionGenesisProjection,
) -> Result<(), AdmissionConsensusError> {
    let projection_digest = admission_genesis_projection_digest(projection)?;
    let projection_json = String::from_utf8(canonical_json_bytes(projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission genesis projection cannot be canonicalized: {error}"
        ))
    })?)
    .map_err(|_| {
        AdmissionConsensusError::Protocol(
            "admission genesis projection canonical JSON is not UTF-8".to_string(),
        )
    })?;
    if let Some(existing) = load_genesis_projection(transaction)? {
        if existing != *projection {
            return Err(AdmissionConsensusError::Protocol(
                "admission genesis projection differs from persisted state".to_string(),
            ));
        }
        return Ok(());
    }
    transaction.execute(
        r#"
        INSERT INTO admission_consensus_genesis (
            singleton, projection_json, projection_digest
        ) VALUES (1, ?1, ?2)
        "#,
        params![projection_json, projection_digest],
    )?;
    Ok(())
}

fn bind_membership(
    transaction: &Transaction<'_>,
    membership: &AdmissionMembership,
) -> Result<AdmissionConsensusMetaView, AdmissionConsensusError> {
    let mut meta = load_meta(transaction)?;
    match meta.membership_digest.as_deref() {
        Some(digest)
            if digest == membership.digest()
                && meta.baseline_state_digest == membership.baseline_digest =>
        {
            if meta
                .voted_for
                .as_deref()
                .is_some_and(|candidate| !membership.contains(candidate))
            {
                return Err(AdmissionConsensusError::Protocol(
                    "admission persisted vote is not a configured member".to_string(),
                ));
            }
            match (
                membership.genesis_projection.as_ref(),
                load_genesis_projection(transaction)?,
            ) {
                (Some(expected), Some(persisted)) if *expected == persisted => {}
                (None, None) if membership.baseline_digest.is_none() => {}
                _ => {
                    return Err(AdmissionConsensusError::Protocol(
                        "admission membership genesis differs from persisted state".to_string(),
                    ));
                }
            }
            if membership.genesis_projection.is_some() {
                normalize_admission_transport_cache(transaction)?;
            }
            return Ok(meta);
        }
        Some(_) => {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus membership differs from persisted state".to_string(),
            ));
        }
        None => {}
    }
    match membership.genesis_projection.as_ref() {
        Some(projection) => {
            if membership.baseline_digest.as_deref()
                != Some(admission_genesis_projection_digest(projection)?.as_str())
            {
                return Err(AdmissionConsensusError::Protocol(
                    "admission membership baseline does not match its genesis projection"
                        .to_string(),
                ));
            }
            normalize_admission_transport_cache(transaction)?;
            persist_genesis_projection(transaction, projection)?;
        }
        None if membership.baseline_digest.is_none() => {}
        None => {
            return Err(AdmissionConsensusError::Protocol(
                "admission membership baseline omitted its genesis projection".to_string(),
            ));
        }
    }
    let updated = transaction.execute(
        r#"
        UPDATE admission_consensus_meta
        SET membership_digest = ?1, baseline_state_digest = ?2
        WHERE singleton = 1
          AND membership_digest IS NULL
          AND baseline_state_digest IS NULL
        "#,
        params![membership.digest(), membership.baseline_digest],
    )?;
    if updated != 1 {
        return Err(AdmissionConsensusError::Protocol(
            "admission membership binding changed concurrently".to_string(),
        ));
    }
    meta.membership_digest = Some(membership.digest().to_string());
    meta.baseline_state_digest = membership.baseline_digest.clone();
    Ok(meta)
}

fn vote_response(
    membership: &AdmissionMembership,
    term: u64,
    vote_granted: bool,
) -> AdmissionRequestVoteResponse {
    AdmissionRequestVoteResponse {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        term,
        vote_granted,
    }
}

fn append_rejection(
    membership: &AdmissionMembership,
    meta: &AdmissionConsensusMetaView,
    rejection: &str,
) -> AdmissionAppendEntriesResponse {
    AdmissionAppendEntriesResponse {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        term: meta.current_term,
        accepted: false,
        match_index: meta.last_log_index,
        commit_index: meta.commit_index,
        applied_index: meta.last_applied,
        applied_state_digest: meta.applied_state_digest.clone(),
        rejection: Some(rejection.to_string()),
    }
}

fn reject_append_after_hard_state(
    transaction: Transaction<'_>,
    membership: &AdmissionMembership,
    rejection: &str,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    transaction
        .execute_batch("ROLLBACK TO chio_admission_append; RELEASE chio_admission_append")?;
    let durable = load_meta(&transaction)?;
    let response = append_rejection(membership, &durable, rejection);
    transaction.commit()?;
    Ok(response)
}

fn validate_node_id(value: &str) -> Result<(), AdmissionConsensusError> {
    if value.is_empty() || value.len() > 2048 || value.bytes().any(|byte| byte == 0) {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus node id is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<(), AdmissionConsensusError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte == 0) {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus operation id is invalid".to_string(),
        ));
    }
    Ok(())
}

fn scoped_operation_id(
    command_kind: AdmissionCommandKind,
    external_operation_id: &str,
) -> Result<String, AdmissionConsensusError> {
    validate_operation_id(external_operation_id)?;
    let canonical = canonical_json_bytes(&json!({
        "commandKind": command_kind_label(command_kind),
        "operationId": external_operation_id,
    }))
    .map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission operation scope canonicalization failed: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(ADMISSION_OPERATION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ADMISSION_OPERATION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn initial_applied_state_digest() -> String {
    sha256_hex(ADMISSION_APPLIED_STATE_DOMAIN)
}

fn initial_security_projection_digest() -> String {
    sha256_hex(ADMISSION_SECURITY_PROJECTION_DOMAIN)
}

fn next_applied_state_digest(
    previous_digest: &str,
    result_digest: &str,
    security_projection_digest: &str,
) -> Result<String, AdmissionConsensusError> {
    if !is_lower_sha256(previous_digest)
        || !is_lower_sha256(result_digest)
        || !is_lower_sha256(security_projection_digest)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission applied-state digest input is invalid".to_string(),
        ));
    }
    let mut preimage = Vec::with_capacity(
        ADMISSION_APPLIED_STATE_DOMAIN.len()
            + previous_digest.len()
            + result_digest.len()
            + security_projection_digest.len(),
    );
    preimage.extend_from_slice(ADMISSION_APPLIED_STATE_DOMAIN);
    preimage.extend_from_slice(previous_digest.as_bytes());
    preimage.extend_from_slice(result_digest.as_bytes());
    preimage.extend_from_slice(security_projection_digest.as_bytes());
    Ok(sha256_hex(&preimage))
}

fn validate_entry(entry: &AdmissionLogEntry) -> Result<(), AdmissionConsensusError> {
    if entry.index == 0 || entry.leader_epoch == 0 {
        return Err(AdmissionConsensusError::Protocol(
            "admission log index and leader epoch must be positive".to_string(),
        ));
    }
    validate_operation_id(&entry.operation_id)?;
    validate_canonical_json(&entry.canonical_command, "admission command")?;
    if sha256_hex(entry.canonical_command.as_bytes()) != entry.command_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission command digest does not match canonical command bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_canonical_json(value: &str, label: &str) -> Result<(), AdmissionConsensusError> {
    let parsed: Value = serde_json::from_str(value).map_err(|error| {
        AdmissionConsensusError::Protocol(format!("{label} is not valid JSON: {error}"))
    })?;
    let canonical = canonical_json_bytes(&parsed).map_err(|error| {
        AdmissionConsensusError::Protocol(format!("{label} cannot be canonicalized: {error}"))
    })?;
    if canonical != value.as_bytes() {
        return Err(AdmissionConsensusError::Protocol(format!(
            "{label} is not canonical JSON"
        )));
    }
    Ok(())
}

fn validate_commit_proof(proof: &AdmissionCommitProof) -> Result<(), AdmissionConsensusError> {
    if proof.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || !is_lower_sha256(&proof.membership_digest)
        || proof.index == 0
        || proof.leader_epoch == 0
        || proof.current_term_commit_index < proof.index
        || proof.quorum_size == 0
        || proof.witness_urls.len() < proof.quorum_size
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit proof is incomplete".to_string(),
        ));
    }
    validate_node_id(&proof.leader_id)?;
    let unique = proof.witness_urls.iter().collect::<BTreeSet<_>>();
    if unique.len() != proof.witness_urls.len()
        || proof.witness_urls.windows(2).any(|pair| pair[0] >= pair[1])
        || !proof.witness_urls.iter().any(|url| url == &proof.leader_id)
        || proof
            .witness_urls
            .iter()
            .any(|url| validate_node_id(url).is_err())
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit proof witnesses are invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_commit_proof_for_membership(
    proof: &AdmissionCommitProof,
    membership: &AdmissionMembership,
) -> Result<(), AdmissionConsensusError> {
    validate_commit_proof(proof)?;
    if proof.membership_digest != membership.digest()
        || proof.quorum_size != membership.quorum_size()
        || proof
            .witness_urls
            .iter()
            .any(|witness| !membership.contains(witness))
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit proof does not match configured membership".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot(snapshot: &AdmissionConsensusSnapshot) -> Result<(), AdmissionConsensusError> {
    if snapshot.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || snapshot
            .meta
            .membership_digest
            .as_deref()
            .is_none_or(|digest| !is_lower_sha256(digest))
        || !is_lower_sha256(&snapshot.meta.applied_state_digest)
        || snapshot.meta.current_term > i64::MAX as u64
        || snapshot.meta.current_term < snapshot.meta.last_log_term
        || snapshot.meta.last_applied != snapshot.meta.commit_index
        || snapshot.entries.len()
            != usize_index(snapshot.meta.last_log_index, "admission snapshot log index")?
        || snapshot.commit_proofs.len()
            != usize_index(
                snapshot.meta.commit_index,
                "admission snapshot commit index",
            )?
        || snapshot.results.len()
            != usize_index(
                snapshot.meta.last_applied,
                "admission snapshot applied index",
            )?
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus snapshot metadata is inconsistent".to_string(),
        ));
    }
    match (
        snapshot.meta.baseline_state_digest.as_deref(),
        snapshot.genesis_projection.as_ref(),
    ) {
        (Some(expected), Some(projection))
            if admission_genesis_projection_digest(projection)? == expected => {}
        (None, None) => {}
        _ => {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus snapshot genesis is missing or corrupted".to_string(),
            ));
        }
    }
    for (offset, entry) in snapshot.entries.iter().enumerate() {
        validate_entry(entry)?;
        if entry.index != one_based_offset(offset, "admission snapshot log offset")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot log is not contiguous".to_string(),
            ));
        }
    }
    if snapshot
        .entries
        .windows(2)
        .any(|pair| pair[0].leader_epoch > pair[1].leader_epoch)
        || snapshot
            .entries
            .last()
            .map_or(snapshot.meta.last_log_term != 0, |entry| {
                entry.leader_epoch != snapshot.meta.last_log_term
            })
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission snapshot log terms are inconsistent".to_string(),
        ));
    }
    for (offset, proof) in snapshot.commit_proofs.iter().enumerate() {
        validate_commit_proof(proof)?;
        if proof.index != one_based_offset(offset, "admission snapshot proof offset")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot commit proofs are not exact and contiguous".to_string(),
            ));
        }
        if snapshot.meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str()) {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof membership does not match metadata".to_string(),
            ));
        }
        if proof.leader_epoch > snapshot.meta.current_term
            || proof.current_term_commit_index > snapshot.meta.commit_index
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof exceeds the committed term or index".to_string(),
            ));
        }
        let entry_offset = usize_index(
            checked_predecessor(proof.index, "admission snapshot proof index")?,
            "admission snapshot proof offset",
        )?;
        if snapshot
            .entries
            .get(entry_offset)
            .is_none_or(|entry| entry.leader_epoch > proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof does not match its entry".to_string(),
            ));
        }
        let current_term_offset = usize_index(
            checked_predecessor(
                proof.current_term_commit_index,
                "admission snapshot current-term commit index",
            )?,
            "admission snapshot current-term commit offset",
        )?;
        if snapshot
            .entries
            .get(current_term_offset)
            .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof has no current-term commit target".to_string(),
            ));
        }
    }
    let mut applied_state_digest = initial_applied_state_digest();
    for (offset, result) in snapshot.results.iter().enumerate() {
        validate_canonical_json(&result.response_json, "admission snapshot result")?;
        let expected_index = one_based_offset(offset, "admission snapshot result offset")?;
        let entry_offset = usize_index(
            checked_predecessor(result.log_index, "admission snapshot result index")?,
            "admission snapshot result offset",
        )?;
        if result.log_index != expected_index
            || sha256_hex(result.response_json.as_bytes()) != result.response_digest
            || !is_lower_sha256(&result.security_projection_digest)
            || snapshot
                .entries
                .get(entry_offset)
                .is_none_or(|entry| entry.operation_id != result.operation_id)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot result does not match its log entry".to_string(),
            ));
        }
        applied_state_digest = next_applied_state_digest(
            &applied_state_digest,
            &result.response_digest,
            &result.security_projection_digest,
        )?;
    }
    if snapshot.meta.applied_state_digest != applied_state_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission snapshot applied-state digest does not match its results".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot_for_membership(
    snapshot: &AdmissionConsensusSnapshot,
    membership: &AdmissionMembership,
) -> Result<(), AdmissionConsensusError> {
    validate_snapshot(snapshot)?;
    if snapshot.meta.membership_digest.as_deref() != Some(membership.digest())
        || snapshot.meta.baseline_state_digest != membership.baseline_digest
        || snapshot.genesis_projection != membership.genesis_projection
        || snapshot
            .meta
            .voted_for
            .as_deref()
            .is_some_and(|candidate| !membership.contains(candidate))
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission snapshot membership differs from configured membership".to_string(),
        ));
    }
    for proof in &snapshot.commit_proofs {
        validate_commit_proof_for_membership(proof, membership)?;
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn previous_entry_matches(
    connection: &Connection,
    index: u64,
    term: u64,
) -> Result<bool, AdmissionConsensusError> {
    if index == 0 {
        return Ok(term == 0);
    }
    Ok(load_entry(connection, index)?.is_some_and(|entry| entry.leader_epoch == term))
}

fn insert_entry(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
) -> Result<(), AdmissionConsensusError> {
    transaction.execute(
        r#"
        INSERT INTO admission_consensus_log (
            log_index, leader_epoch, operation_id, command_kind,
            canonical_command, command_digest
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            sqlite_u64(entry.index)?,
            sqlite_u64(entry.leader_epoch)?,
            entry.operation_id,
            command_kind_label(entry.command_kind),
            entry.canonical_command,
            entry.command_digest,
        ],
    )?;
    Ok(())
}

fn update_log_head(
    transaction: &Transaction<'_>,
    index: u64,
    term: u64,
) -> Result<(), AdmissionConsensusError> {
    transaction.execute(
        r#"
        UPDATE admission_consensus_meta
        SET last_log_index = ?1, last_log_term = ?2
        WHERE singleton = 1
        "#,
        params![sqlite_u64(index)?, sqlite_u64(term)?],
    )?;
    Ok(())
}

fn load_entry(
    connection: &Connection,
    index: u64,
) -> Result<Option<AdmissionLogEntry>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT log_index, leader_epoch, operation_id, command_kind,
                   canonical_command, command_digest
            FROM admission_consensus_log
            WHERE log_index = ?1
            "#,
            params![sqlite_u64(index)?],
            read_entry_raw,
        )
        .optional()?;
    raw.map(entry_from_raw).transpose()
}

fn load_entry_by_operation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<AdmissionLogEntry>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT log_index, leader_epoch, operation_id, command_kind,
                   canonical_command, command_digest
            FROM admission_consensus_log
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            read_entry_raw,
        )
        .optional()?;
    raw.map(entry_from_raw).transpose()
}

type EntryRaw = (i64, i64, String, String, String, String);

fn read_entry_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRaw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}
