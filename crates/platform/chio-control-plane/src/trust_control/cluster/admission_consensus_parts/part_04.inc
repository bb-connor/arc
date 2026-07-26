fn apply_combined_capture(
    config: &TrustServiceConfig,
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
    let partition_escrow_evidence = validated_partition_escrow_hold_evidence(
        config,
        transaction,
        &command.request.hold_id,
    )?;
    let decision = match SqliteAdmissionCaptureAuthority::capture_admission_in_transaction(
        transaction,
        capture_request,
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_capture_rejection(error),
    };
    let response = match decision {
        AdmissionCaptureDecision::Captured { budget, metadata } => {
            if metadata.budget_commit().partition_escrow_evidence
                != partition_escrow_evidence
            {
                return Err(
                    "combined capture changed its persisted partition escrow evidence".to_string(),
                );
            }
            let budget_seq = budget.metadata.budget_commit_index.ok_or_else(|| {
                "combined capture result has no persisted budget sequence".to_string()
            })?;
            let (metadata_view, commit_view) =
                consensus_budget_evidence(
                    proof,
                    &authority,
                    budget_seq,
                    partition_escrow_evidence.as_ref(),
                );
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
                    leader_epoch: partition_escrow_evidence
                        .is_none()
                        .then_some(proof.leader_epoch),
                    guarantee_level: if partition_escrow_evidence.is_some() {
                        BudgetGuaranteeLevelView::PartitionEscrowed
                    } else {
                        BudgetGuaranteeLevelView::HaLinearizable
                    },
                    partition_escrow_evidence: partition_escrow_evidence
                        .as_ref()
                        .map(partition_escrow_evidence_view),
                    authority: command.request.budget_authority.clone(),
                    invocation_state,
                    monetary_state,
                },
            }
        }
        AdmissionCaptureDecision::Denied(denial) => {
            if denial.metadata().budget_commit().partition_escrow_evidence
                != partition_escrow_evidence
            {
                return Err(
                    "combined capture denial changed its persisted partition escrow evidence"
                        .to_string(),
                );
            }
            CombinedAdmissionCaptureResponse {
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
                leader_epoch: partition_escrow_evidence
                    .is_none()
                    .then_some(proof.leader_epoch),
                guarantee_level: if partition_escrow_evidence.is_some() {
                    BudgetGuaranteeLevelView::PartitionEscrowed
                } else {
                    BudgetGuaranteeLevelView::HaLinearizable
                },
                partition_escrow_evidence: partition_escrow_evidence
                    .as_ref()
                    .map(partition_escrow_evidence_view),
                authority: command.request.budget_authority.clone(),
                invocation_state: BudgetInvocationReservationStateView::Authorized,
                monetary_state: BudgetMonetaryHoldStateView::Exposed,
            },
            }
        }
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
    partition_escrow_evidence: Option<&PartitionEscrowCommitEvidence>,
) -> (BudgetAuthorityMetadataView, BudgetWriteCommitView) {
    let metadata = BudgetAuthorityMetadataView {
        authority_id: authority.authority_id.clone(),
        leader_url: proof.leader_id.clone(),
        budget_term: authority.lease_epoch,
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
        lease_expires_at: u64::MAX,
        lease_ttl_ms: u64::MAX,
        guarantee_level: if partition_escrow_evidence.is_some() {
            "partition_escrowed".to_string()
        } else {
            "ha_linearizable".to_string()
        },
        budget_commit_index: Some(proof.index),
        partition_escrow_evidence: partition_escrow_evidence
            .map(partition_escrow_evidence_view),
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

fn partition_escrow_evidence_view(
    evidence: &PartitionEscrowCommitEvidence,
) -> BudgetPartitionEscrowEvidenceView {
    BudgetPartitionEscrowEvidenceView {
        canonical_json: evidence.canonical_json().to_string(),
        digest: evidence.evidence_digest().to_string(),
    }
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
        BudgetStoreError::MissingCommittedReplay(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "budget_committed_replay_missing",
            format!("budget_committed_replay_missing: {message}"),
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

pub(crate) async fn handle_internal_committed_composite_authorization_query(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(replica_request): Json<CommittedCompositeAuthorizationReplicaQueryRequest>,
) -> Response {
    if let Err(response) = validate_cluster_peer_json_request(
        &headers,
        &state.config,
        "POST",
        INTERNAL_COMPOSITE_AUTHORIZE_QUERY_PATH,
        &replica_request,
    ) {
        return response;
    }
    let CommittedCompositeAuthorizationReplicaQueryRequest {
        request_nonce,
        request,
    } = replica_request;
    if !request.existing_only {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "committed composite authorization query requires existingOnly",
        );
    }
    let (node_id, _, membership) = match admission_members_read_only(&state) {
        Ok(members) => members,
        Err(error) => return consensus_http_error(error),
    };
    let config = state.config.clone();
    let result = tokio::task::spawn_blocking(move || {
        query_committed_composite_authorization_replica(
            &config,
            &membership,
            &node_id,
            &request,
            &request_nonce,
        )
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "committed composite authorization replica query worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_budget_mutation_event_replica_query(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<BudgetMutationEventQueryRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (node_id, _, membership) = match admission_members_read_only(&state) {
        Ok(members) => members,
        Err(error) => return consensus_http_error(error),
    };
    let config = state.config.clone();
    let result = tokio::task::spawn_blocking(move || {
        query_budget_mutation_event_replica(&config, &membership, &node_id, &request)
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "budget mutation event replica query worker failed before completion",
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

fn validate_existing_consensus_file(path: &Path) -> Result<(), AdmissionConsensusError> {
    let path_text = path.to_string_lossy();
    let lower = path_text.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path_text.is_empty()
        || path_text == ":memory:"
        || memory_uri
        || lower.starts_with("file::memory:")
    {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay requires an existing durable SQLite file".to_string(),
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "committed admission replay database cannot be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay path is not an existing regular file".to_string(),
        ));
    }
    Ok(())
}

fn configure_read_only_consensus_connection(
    connection: &Connection,
) -> Result<(), AdmissionConsensusError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA query_only = ON; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;",
    )?;
    let query_only: i64 =
        connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if query_only != 1
        || foreign_keys != 1
        || trusted_schema != 0
        || !journal_mode.eq_ignore_ascii_case("wal")
    {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay did not obtain an exact query-only WAL reader"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_read_only_consensus_connection(
    connection: &Connection,
) -> Result<(), AdmissionConsensusError> {
    validate_read_only_consensus_schema(connection)?;
    load_meta(connection)?;
    validate_consensus_result_schema(connection)?;
    let integrity_check: String =
        connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
    if integrity_check != "ok" {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay database failed SQLite integrity_check".to_string(),
        ));
    }
    let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_key_check.query([])?.next()?.is_some() {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay database failed SQLite foreign_key_check".to_string(),
        ));
    }
    drop(foreign_key_check);
    validate_integrity(connection)
}

fn validate_read_only_consensus_schema(
    connection: &Connection,
) -> Result<(), AdmissionConsensusError> {
    const TABLE_PROBES: &[(&str, &str)] = &[
        (
            "admission_consensus_meta",
            r#"
            SELECT singleton, schema_version, current_term, baseline_state_digest,
                   membership_digest, voted_for, last_log_index, last_log_term,
                   commit_index, last_applied, applied_state_digest
            FROM admission_consensus_meta WHERE 0
            "#,
        ),
        (
            "admission_consensus_log",
            r#"
            SELECT log_index, leader_epoch, operation_id, command_kind,
                   canonical_command, command_digest
            FROM admission_consensus_log WHERE 0
            "#,
        ),
        (
            "admission_consensus_commits",
            r#"
            SELECT log_index, leader_epoch, current_term_commit_index,
                   leader_id, membership_digest, quorum_size,
                   witness_urls_json, protocol_version
            FROM admission_consensus_commits WHERE 0
            "#,
        ),
        (
            "admission_consensus_results",
            r#"
            SELECT operation_id, log_index, response_json, response_digest,
                   security_projection_digest
            FROM admission_consensus_results WHERE 0
            "#,
        ),
        (
            "admission_consensus_genesis",
            r#"
            SELECT singleton, projection_json, projection_digest
            FROM admission_consensus_genesis WHERE 0
            "#,
        ),
        (
            "admission_consensus_partition_escrow_authority",
            r#"
            SELECT singleton, descriptor_digest, membership_digest
            FROM admission_consensus_partition_escrow_authority WHERE 0
            "#,
        ),
    ];
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != chio_store_sqlite::CHIO_SQLITE_APPLICATION_ID {
        return Err(AdmissionConsensusError::Protocol(format!(
            "committed admission replay database has application_id {application_id:#x}, expected {:#x}",
            chio_store_sqlite::CHIO_SQLITE_APPLICATION_ID
        )));
    }
    let schema_versions_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'chio_store_schema_versions'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let schema_versions_sql = schema_versions_sql
        .as_deref()
        .map(normalize_consensus_schema_sql)
        .ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "committed admission replay schema is missing exact version metadata"
                    .to_string(),
            )
        })?;
    if !schema_versions_sql
        .contains(&normalize_consensus_schema_sql("store_key TEXT PRIMARY KEY"))
        || !schema_versions_sql
            .contains(&normalize_consensus_schema_sql("version INTEGER NOT NULL"))
    {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay version metadata does not match the v1 schema contract"
                .to_string(),
        ));
    }
    let (budget_schema_rows, minimum_version, maximum_version): (
        i64,
        Option<i32>,
        Option<i32>,
    ) = connection.query_row(
        r#"
        SELECT COUNT(*), MIN(version), MAX(version)
        FROM chio_store_schema_versions WHERE store_key = 'budget'
        "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if budget_schema_rows != 1 || minimum_version != Some(1) || maximum_version != Some(1) {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay requires exactly one budget schema version 1 row"
                .to_string(),
        ));
    }
    for (table, probe) in TABLE_PROBES {
        let object_type = connection
            .query_row(
                "SELECT type FROM sqlite_master WHERE name = ?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if object_type.as_deref() != Some("table") {
            return Err(AdmissionConsensusError::Protocol(format!(
                "committed admission replay schema is missing table `{table}`"
            )));
        }
        let _statement = connection.prepare(probe)?;
    }

    for (table, expected_sql) in [
        (
            "admission_consensus_meta",
            r#"
            CREATE TABLE admission_consensus_meta (
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
            )
            "#,
        ),
        (
            "admission_consensus_log",
            r#"
            CREATE TABLE admission_consensus_log (
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
            )
            "#,
        ),
        (
            "admission_consensus_commits",
            r#"
            CREATE TABLE admission_consensus_commits (
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
            )
            "#,
        ),
        (
            "admission_consensus_results",
            r#"
            CREATE TABLE admission_consensus_results (
                operation_id TEXT PRIMARY KEY REFERENCES admission_consensus_log(operation_id),
                log_index INTEGER NOT NULL UNIQUE REFERENCES admission_consensus_log(log_index),
                response_json TEXT NOT NULL,
                response_digest TEXT NOT NULL,
                security_projection_digest TEXT NOT NULL
                    CHECK (
                        length(security_projection_digest) = 64
                        AND security_projection_digest NOT GLOB '*[^0-9a-f]*'
                    )
            )
            "#,
        ),
        (
            "admission_consensus_genesis",
            r#"
            CREATE TABLE admission_consensus_genesis (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                projection_json TEXT NOT NULL,
                projection_digest TEXT NOT NULL
                    CHECK (
                        length(projection_digest) = 64
                        AND projection_digest NOT GLOB '*[^0-9a-f]*'
                    )
            )
            "#,
        ),
        (
            "admission_consensus_partition_escrow_authority",
            r#"
            CREATE TABLE admission_consensus_partition_escrow_authority (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                descriptor_digest TEXT NOT NULL
                    CHECK (
                        length(descriptor_digest) = 64
                        AND descriptor_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                membership_digest TEXT NOT NULL
                    CHECK (
                        length(membership_digest) = 64
                        AND membership_digest NOT GLOB '*[^0-9a-f]*'
                    )
            )
            "#,
        ),
    ] {
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if normalize_consensus_schema_sql(&sql) != normalize_consensus_schema_sql(expected_sql) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "committed admission replay table `{table}` does not match the v3 schema contract"
            )));
        }
    }

    for (name, expected) in [
        (
            "admission_revocation_insert_requires_authority",
            r#"
            CREATE TRIGGER admission_revocation_insert_requires_authority
            BEFORE INSERT ON revoked_capabilities
            BEGIN
                SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
            END
            "#,
        ),
        (
            "admission_revocation_update_requires_authority",
            r#"
            CREATE TRIGGER admission_revocation_update_requires_authority
            BEFORE UPDATE ON revoked_capabilities
            BEGIN
                SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
            END
            "#,
        ),
        (
            "admission_revocation_delete_requires_authority",
            r#"
            CREATE TRIGGER admission_revocation_delete_requires_authority
            BEFORE DELETE ON revoked_capabilities
            BEGIN
                SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
            END
            "#,
        ),
    ] {
        let sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if sql.as_deref().map(normalize_consensus_schema_sql)
            != Some(normalize_consensus_schema_sql(expected))
        {
            return Err(AdmissionConsensusError::Protocol(format!(
                "committed admission replay schema lacks exact authority guard `{name}`"
            )));
        }
    }
    Ok(())
}

include!("part_04_tail.inc");
