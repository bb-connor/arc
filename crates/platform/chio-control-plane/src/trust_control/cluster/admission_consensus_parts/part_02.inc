fn apply_committed_expected_in_transaction<F>(
    transaction: &Transaction<'_>,
    expected_results: &[AdmissionConsensusResult],
    apply: &mut F,
) -> Result<u64, AdmissionConsensusError>
where
    F: FnMut(&Transaction<'_>, &AdmissionLogEntry, &AdmissionCommitProof) -> Result<String, String>,
{
    loop {
        validate_integrity(transaction)?;
        let meta = load_meta(transaction)?;
        if meta.last_applied >= meta.commit_index {
            return Ok(meta.last_applied);
        }
        let next = meta.last_applied.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission applied index overflow".to_string())
        })?;
        let entry = load_entry(transaction, next)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!(
                "committed admission entry {next} is missing"
            ))
        })?;
        let proof = load_commit_proof(transaction, next)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!(
                "committed admission proof {next} is missing"
            ))
        })?;
        validate_commit_proof(&proof)?;
        if meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str())
            || entry.leader_epoch > proof.leader_epoch
            || load_entry(transaction, proof.current_term_commit_index)?
                .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof does not match persisted consensus state".to_string(),
            ));
        }
        let response_json =
            apply(transaction, &entry, &proof).map_err(AdmissionConsensusError::Apply)?;
        validate_canonical_json(&response_json, "admission result")?;
        let response_digest = sha256_hex(response_json.as_bytes());
        let current = load_meta(transaction)?;
        let security_projection_digest = if current.baseline_state_digest.is_some() {
            capture_admission_security_projection_digest_from_connection(transaction)?
        } else {
            initial_security_projection_digest()
        };
        let result = AdmissionConsensusResult {
            operation_id: entry.operation_id.clone(),
            log_index: entry.index,
            response_digest,
            response_json,
            security_projection_digest,
        };
        let offset = usize_index(
            checked_predecessor(next, "admission expected result index")?,
            "admission expected result offset",
        )?;
        if expected_results.get(offset) != Some(&result) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission replay result {next} differs from the authenticated snapshot"
            )));
        }
        let previous = checked_predecessor(next, "admission applied index")?;
        if current.last_applied != previous || current.commit_index < next {
            return Err(AdmissionConsensusError::Protocol(
                "admission apply order changed during deterministic replay".to_string(),
            ));
        }
        if let Some(existing) = load_result(transaction, &entry.operation_id)? {
            if existing != result {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission operation `{}` replay changed its result",
                    entry.operation_id
                )));
            }
        } else {
            transaction.execute(
                r#"
                INSERT INTO admission_consensus_results (
                    operation_id, log_index, response_json, response_digest,
                    security_projection_digest
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    &result.operation_id,
                    sqlite_u64(result.log_index)?,
                    &result.response_json,
                    &result.response_digest,
                    &result.security_projection_digest,
                ],
            )?;
        }
        let applied_state_digest = next_applied_state_digest(
            &current.applied_state_digest,
            &result.response_digest,
            &result.security_projection_digest,
        )?;
        let updated = transaction.execute(
            r#"
            UPDATE admission_consensus_meta
            SET last_applied = ?1, applied_state_digest = ?2
            WHERE singleton = 1
              AND last_applied = ?3
              AND applied_state_digest = ?4
              AND commit_index >= ?1
            "#,
            params![
                sqlite_u64(next)?,
                applied_state_digest,
                sqlite_u64(previous)?,
                current.applied_state_digest,
            ],
        )?;
        if updated != 1 {
            return Err(AdmissionConsensusError::Protocol(
                "admission last-applied compare-and-swap failed".to_string(),
            ));
        }
    }
}

pub(crate) async fn propose_admission_command<T: Serialize>(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: &T,
) -> Result<AdmissionConsensusResult, Response> {
    let command = serde_json::to_value(command).map_err(|error| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("admission command serialization failed: {error}"),
        )
    })?;
    let state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        propose_admission_command_blocking(&state, operation_id, command_kind, command)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission consensus worker failed before completion",
        )
    })?
    .map_err(consensus_http_error)?;
    accepted_consensus_result(result).map_err(consensus_http_error)
}

pub(crate) async fn query_admission_capture_consensus(
    state: &TrustServiceState,
    request: AdmissionCapturePointQueryRequest,
) -> Result<AdmissionCapturePointQueryResponse, Response> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        query_admission_capture_consensus_blocking(&state, &request)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission capture query worker failed before completion",
        )
    })?
    .map_err(consensus_http_error)
}

pub(crate) async fn query_invocation_capture_consensus(
    state: &TrustServiceState,
    request: CaptureInvocationPointQueryRequest,
) -> Result<CaptureInvocationPointQueryResponse, Response> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        query_invocation_capture_consensus_blocking(&state, &request)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invocation capture query worker failed before completion",
        )
    })?
    .map_err(consensus_http_error)
}

fn query_invocation_capture_consensus_blocking(
    state: &TrustServiceState,
    request: &CaptureInvocationPointQueryRequest,
) -> Result<CaptureInvocationPointQueryResponse, AdmissionConsensusError> {
    let (self_url, peers, membership) = admission_members(state)?;
    let mut response_count = 0usize;
    let mut completed_capture = None;
    let mut completed_canonical = None;
    let mut last_error = None;

    match query_invocation_capture_replica(&state.config, &membership, &self_url, request) {
        Ok(response) => {
            response_count = 1;
            merge_invocation_capture_replica_response(
                &membership,
                &self_url,
                request,
                response,
                &mut completed_capture,
                &mut completed_canonical,
            )?;
        }
        Err(error) => last_error = Some(error),
    }

    for peer in peers {
        let client = match service_runtime::client::build_cluster_peer_client(
            &peer,
            &state.config,
            &self_url,
        ) {
            Ok(client) => client,
            Err(error) => {
                last_error = Some(AdmissionConsensusError::Protocol(error.to_string()));
                continue;
            }
        };
        let response = match client.invocation_capture_replica_query(request) {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(AdmissionConsensusError::Protocol(error.to_string()));
                continue;
            }
        };
        if let Err(error) = merge_invocation_capture_replica_response(
            &membership,
            &peer,
            request,
            response,
            &mut completed_capture,
            &mut completed_canonical,
        ) {
            last_error = Some(error);
            continue;
        }
        response_count = response_count.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "invocation capture query response count overflowed".to_string(),
            )
        })?;
    }

    if response_count < membership.quorum_size() {
        return Err(last_error.unwrap_or_else(|| {
            AdmissionConsensusError::Protocol(
                "invocation capture query could not read an authenticated quorum".to_string(),
            )
        }));
    }
    Ok(CaptureInvocationPointQueryResponse {
        operation_id: request.capture_request.operation_id.clone(),
        request_binding_hash: request.capture_request.request_binding_hash.clone(),
        capture: completed_capture,
    })
}

fn merge_invocation_capture_replica_response(
    membership: &AdmissionMembership,
    expected_node_id: &str,
    request: &CaptureInvocationPointQueryRequest,
    response: CaptureInvocationReplicaQueryResponse,
    completed_capture: &mut Option<CaptureInvocationReservationsResponse>,
    completed_canonical: &mut Option<Vec<u8>>,
) -> Result<(), AdmissionConsensusError> {
    if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || response.membership_digest != membership.digest()
        || response.node_id != expected_node_id
        || response.query.operation_id != request.capture_request.operation_id
        || response.query.request_binding_hash != request.capture_request.request_binding_hash
    {
        return Err(AdmissionConsensusError::Protocol(
            "invocation capture replica response changed its membership or operation binding"
                .to_string(),
        ));
    }
    let Some(capture) = response.query.capture else {
        return Ok(());
    };
    validate_invocation_capture_query_response(&request.capture_request, &capture)?;
    let canonical = canonical_json_bytes(&capture).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "invocation capture replica response cannot be canonicalized: {error}"
        ))
    })?;
    if completed_canonical
        .as_ref()
        .is_some_and(|existing| existing != &canonical)
    {
        return Err(AdmissionConsensusError::Protocol(
            "invocation capture quorum returned conflicting completed outcomes".to_string(),
        ));
    }
    if completed_capture.is_none() {
        *completed_capture = Some(capture);
        *completed_canonical = Some(canonical);
    }
    Ok(())
}

fn validate_invocation_capture_query_response(
    request: &CaptureInvocationReservationsRequest,
    response: &CaptureInvocationReservationsResponse,
) -> Result<(), AdmissionConsensusError> {
    if response.operation_id != request.operation_id
        || response.request_binding_hash != request.request_binding_hash
        || response.capability_id != request.capability_id
        || response.grant_index != request.grant_index
        || response.hold_id != request.hold_id
        || response.event_id != request.event_id
        || response.invocation_state != BudgetInvocationReservationStateView::Captured
        || response.budget_authority.is_none()
        || response.budget_commit.is_none()
    {
        return Err(AdmissionConsensusError::Protocol(
            "invocation capture query response changed its exact request or commit evidence"
                .to_string(),
        ));
    }
    Ok(())
}

fn query_invocation_capture_replica(
    config: &TrustServiceConfig,
    membership: &AdmissionMembership,
    node_id: &str,
    request: &CaptureInvocationPointQueryRequest,
) -> Result<CaptureInvocationReplicaQueryResponse, AdmissionConsensusError> {
    let native_request = super::super::budget_handlers::invocation_capture_request_from_view(
        &request.capture_request,
    )
    .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "invocation capture query requires a budget database".to_string(),
        )
    })?;
    let budget_store = SqliteBudgetStore::open(path)
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let decision = budget_store
        .query_invocation_capture(&native_request)
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let consensus_store = configured_admission_consensus_store(config)?;
    let operation_id = scoped_operation_id(
        AdmissionCommandKind::CaptureInvocations,
        &request.capture_request.event_id,
    )?;
    let entry = consensus_store.entry_for_operation(&operation_id)?;
    let result = consensus_store.result_for_operation(&operation_id)?;
    let capture = match decision {
        None => {
            if result.is_some() {
                return Err(AdmissionConsensusError::Protocol(
                    "invocation capture result exists without its persisted budget event"
                        .to_string(),
                ));
            }
            None
        }
        Some(decision) => {
            let entry = entry.ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "persisted invocation capture has no consensus log entry".to_string(),
                )
            })?;
            let command = serde_json::to_value(&request.capture_request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "invocation capture query request cannot be serialized: {error}"
                ))
            })?;
            ensure_operation_command_matches(
                &entry,
                AdmissionCommandKind::CaptureInvocations,
                &command,
            )?;
            let result = result.ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "persisted invocation capture has no committed consensus result".to_string(),
                )
            })?;
            let capture: CaptureInvocationReservationsResponse =
                serde_json::from_str(&result.response_json).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "persisted invocation capture response is malformed: {error}"
                    ))
                })?;
            validate_invocation_capture_query_response(&request.capture_request, &capture)?;
            let authority = capture.budget_authority.clone().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "persisted invocation capture omitted authority evidence".to_string(),
                )
            })?;
            let commit = capture.budget_commit.clone().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "persisted invocation capture omitted commit evidence".to_string(),
                )
            })?;
            let replayed = super::super::budget_handlers::invocation_capture_response_view(
                &request.capture_request,
                decision,
                authority,
                commit,
            )
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            if canonical_json_bytes(&capture)
                .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?
                != canonical_json_bytes(&replayed)
                    .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?
            {
                return Err(AdmissionConsensusError::Protocol(
                    "persisted invocation capture diverges from its consensus result".to_string(),
                ));
            }
            Some(capture)
        }
    };
    Ok(CaptureInvocationReplicaQueryResponse {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        node_id: node_id.to_string(),
        query: CaptureInvocationPointQueryResponse {
            operation_id: request.capture_request.operation_id.clone(),
            request_binding_hash: request.capture_request.request_binding_hash.clone(),
            capture,
        },
    })
}

fn query_admission_capture_consensus_blocking(
    state: &TrustServiceState,
    request: &AdmissionCapturePointQueryRequest,
) -> Result<AdmissionCapturePointQueryResponse, AdmissionConsensusError> {
    let (self_url, peers, membership) = admission_members(state)?;
    let native_request =
        super::super::service_runtime::budget::admission_capture_request_from_view(
            &request.capture_request,
        )
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let mut response_count = 0usize;
    let mut completed_capture = None;
    let mut completed_canonical = None;
    let mut last_error = None;

    match query_admission_capture_replica(&state.config, &membership, &self_url, request) {
        Ok(response) => {
            response_count = 1;
            merge_capture_replica_response(
                &membership,
                &self_url,
                &native_request,
                request,
                response,
                &mut completed_capture,
                &mut completed_canonical,
            )?;
        }
        Err(error) => last_error = Some(error),
    }

    for peer in peers {
        let client = match service_runtime::client::build_cluster_peer_client(
            &peer,
            &state.config,
            &self_url,
        ) {
            Ok(client) => client,
            Err(error) => {
                last_error = Some(AdmissionConsensusError::Protocol(error.to_string()));
                continue;
            }
        };
        let response = match client.admission_capture_replica_query(request) {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(AdmissionConsensusError::Protocol(error.to_string()));
                continue;
            }
        };
        if let Err(error) = merge_capture_replica_response(
            &membership,
            &peer,
            &native_request,
            request,
            response,
            &mut completed_capture,
            &mut completed_canonical,
        ) {
            last_error = Some(error);
            continue;
        }
        response_count = response_count.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission capture query response count overflowed".to_string(),
            )
        })?;
    }

    if response_count < membership.quorum_size() {
        return Err(last_error.unwrap_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission capture query could not read an authenticated quorum".to_string(),
            )
        }));
    }
    Ok(AdmissionCapturePointQueryResponse {
        operation_id: request.capture_request.operation_id.clone(),
        request_binding_hash: request.capture_request.request_binding_hash.clone(),
        capture: completed_capture,
    })
}

fn merge_capture_replica_response(
    membership: &AdmissionMembership,
    expected_node_id: &str,
    native_request: &AdmissionCaptureRequest,
    request: &AdmissionCapturePointQueryRequest,
    response: AdmissionCaptureReplicaQueryResponse,
    completed_capture: &mut Option<CombinedAdmissionCaptureResponse>,
    completed_canonical: &mut Option<Vec<u8>>,
) -> Result<(), AdmissionConsensusError> {
    if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || response.membership_digest != membership.digest()
        || response.node_id != expected_node_id
        || response.query.operation_id != request.capture_request.operation_id
        || response.query.request_binding_hash != request.capture_request.request_binding_hash
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission capture replica response changed its membership or operation binding"
                .to_string(),
        ));
    }
    let Some(capture) = response.query.capture else {
        return Ok(());
    };
    super::super::service_runtime::budget::validate_remote_admission_capture_response(
        native_request,
        capture.clone(),
    )
    .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let canonical = canonical_json_bytes(&capture).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission capture replica response cannot be canonicalized: {error}"
        ))
    })?;
    if completed_canonical
        .as_ref()
        .is_some_and(|existing| existing != &canonical)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission capture quorum returned conflicting completed outcomes".to_string(),
        ));
    }
    if completed_capture.is_none() {
        *completed_capture = Some(capture);
        *completed_canonical = Some(canonical);
    }
    Ok(())
}

fn query_admission_capture_replica(
    config: &TrustServiceConfig,
    membership: &AdmissionMembership,
    node_id: &str,
    request: &AdmissionCapturePointQueryRequest,
) -> Result<AdmissionCaptureReplicaQueryResponse, AdmissionConsensusError> {
    let native_request =
        super::super::service_runtime::budget::admission_capture_request_from_view(
            &request.capture_request,
        )
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let authority = open_capture_authority(config)
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let decision = authority
        .query_admission_capture(&native_request)
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let store = configured_admission_consensus_store(config)?;
    let operation_id = scoped_operation_id(
        AdmissionCommandKind::CombinedCapture,
        &request.capture_request.operation_id,
    )?;
    let entry = store.entry_for_operation(&operation_id)?;
    let result = store.result_for_operation(&operation_id)?;
    let capture = match decision {
        None => {
            if result.is_some() {
                return Err(AdmissionConsensusError::Protocol(
                    "admission capture result exists without its persisted capture event"
                        .to_string(),
                ));
            }
            None
        }
        Some(decision) => {
            let entry = entry.ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "persisted admission capture has no consensus log entry".to_string(),
                )
            })?;
            let command = serde_json::to_value(&request.capture_request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "admission capture query request cannot be serialized: {error}"
                ))
            })?;
            ensure_operation_command_matches(
                &entry,
                AdmissionCommandKind::CombinedCapture,
                &command,
            )?;
            let result = result.ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "persisted admission capture has no committed consensus result".to_string(),
                )
            })?;
            let capture: CombinedAdmissionCaptureResponse =
                serde_json::from_str(&result.response_json).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "persisted admission capture response is malformed: {error}"
                    ))
                })?;
            let replayed =
                super::super::service_runtime::budget::validate_remote_admission_capture_response(
                    &native_request,
                    capture.clone(),
                )
                .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            if !capture_decisions_match(&decision, &replayed) {
                return Err(AdmissionConsensusError::Protocol(
                    "persisted admission capture event diverges from its consensus result"
                        .to_string(),
                ));
            }
            Some(capture)
        }
    };
    Ok(AdmissionCaptureReplicaQueryResponse {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        node_id: node_id.to_string(),
        query: AdmissionCapturePointQueryResponse {
            operation_id: request.capture_request.operation_id.clone(),
            request_binding_hash: request.capture_request.request_binding_hash.clone(),
            capture,
        },
    })
}

fn capture_decisions_match(
    persisted: &AdmissionCaptureDecision,
    replayed: &AdmissionCaptureDecision,
) -> bool {
    match (persisted, replayed) {
        (
            AdmissionCaptureDecision::Captured {
                budget: persisted_budget,
                metadata: persisted_metadata,
            },
            AdmissionCaptureDecision::Captured {
                budget: replayed_budget,
                metadata: replayed_metadata,
            },
        ) => {
            capture_metadata_matches(persisted_metadata, replayed_metadata)
                && budget_hold_decisions_match(persisted_budget, replayed_budget)
        }
        (
            AdmissionCaptureDecision::Denied(persisted),
            AdmissionCaptureDecision::Denied(replayed),
        ) => {
            persisted.reason() == replayed.reason()
                && persisted.revoked_ids() == replayed.revoked_ids()
                && capture_metadata_matches(persisted.metadata(), replayed.metadata())
        }
        _ => false,
    }
}

fn capture_metadata_matches(
    persisted: &AdmissionCaptureMetadata,
    replayed: &AdmissionCaptureMetadata,
) -> bool {
    persisted.operation_id() == replayed.operation_id()
        && persisted.checked_revocation_set_digest() == replayed.checked_revocation_set_digest()
        && persisted.revocation_commit_index() == replayed.revocation_commit_index()
        && persisted.authority_commit_index() == replayed.authority_commit_index()
        && budget_commit_metadata_matches(persisted.budget_commit(), replayed.budget_commit())
}

fn budget_hold_decisions_match(
    persisted: &BudgetHoldMutationDecision,
    replayed: &BudgetHoldMutationDecision,
) -> bool {
    persisted.hold_id == replayed.hold_id
        && persisted.exposure_units == replayed.exposure_units
        && persisted.realized_spend_units == replayed.realized_spend_units
        && persisted.committed_cost_units_after == replayed.committed_cost_units_after
        && persisted.invocation_count_after == replayed.invocation_count_after
        && persisted.invocation_counts_after == replayed.invocation_counts_after
        && persisted.invocation_state == replayed.invocation_state
        && persisted.monetary_state == replayed.monetary_state
        && persisted.revocation_set == replayed.revocation_set
        && budget_commit_metadata_matches(&persisted.metadata, &replayed.metadata)
}

fn budget_commit_metadata_matches(
    persisted: &BudgetCommitMetadata,
    replayed: &BudgetCommitMetadata,
) -> bool {
    persisted.authority == replayed.authority
        && persisted.budget_profile == replayed.budget_profile
        && persisted.metering_profile == replayed.metering_profile
        && persisted.budget_commit_index == replayed.budget_commit_index
        && persisted.event_id == replayed.event_id
}

pub(crate) fn initialize_admission_consensus(state: &TrustServiceState) -> Result<(), CliError> {
    if state.cluster.is_none() {
        return Ok(());
    }
    let (budget_path, revocation_path) = match (
        state.config.budget_db_path.as_deref(),
        state.config.revocation_db_path.as_deref(),
    ) {
        (None, None) => return Ok(()),
        (Some(budget_path), Some(revocation_path)) => (budget_path, revocation_path),
        _ => {
            return Err(CliError::cli_other_error(
                "HA admission consensus requires budget and revocation databases together"
                    .to_string(),
            ));
        }
    };
    SqliteAdmissionCaptureAuthority::open_with_paths(budget_path, revocation_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let store = AdmissionConsensusStore::open(budget_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let (_, _, membership) =
        admission_members(state).map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_integrity()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .bind_membership(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_membership_proofs(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .apply_committed(&mut |transaction, entry, proof| {
            apply_admission_log_entry(&state.config, transaction, entry, proof)
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(())
}

pub(crate) fn prepare_combined_capture_command(
    config: &TrustServiceConfig,
    request: CombinedAdmissionCaptureRequest,
) -> Result<ConsensusCombinedCaptureCommand, String> {
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "combined capture requires the exact persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let revocation_set = super::super::service_runtime::budget::canonical_revocation_set_from_view(
        &request.revocation_set,
    )
    .map_err(|error| error.to_string())?;
    let capture_request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
        operation_id: request.operation_id.clone(),
        budget: BudgetCaptureInvocationRequest {
            admission_operation: Some(
                BudgetAdmissionOperationBinding::new(
                    request.operation_id.clone(),
                    request.request_binding_hash.clone(),
                )
                .map_err(|error| error.to_string())?,
            ),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: Some(request.hold_id.clone()),
            event_id: Some(request.event_id.clone()),
            authority: Some(authority),
        },
        revocation_set,
        bound_revocation_set_digest: request.bound_revocation_set_digest.clone(),
        authorization_artifact_digests: request.authorization_artifact_digests.clone(),
        aggregate_root_capability_id: request.aggregate_root_capability_id.clone(),
        aggregate_root_binding_digest: request.aggregate_root_binding_digest.clone(),
        last_observed_revocation_index: request.last_observed_revocation_index,
    })
    .map_err(|error| error.to_string())?;
    validate_persisted_capture_hold(
        config,
        &request.capability_id,
        request.grant_index,
        &request.hold_id,
        &request.event_id,
        request.budget_authority.as_ref(),
    )?;
    open_capture_authority(config)?
        .validate_capture_request(&capture_request)
        .map_err(|error| error.to_string())?;
    let path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "combined capture requires a budget database".to_string())?;
    drop(SqliteBudgetStore::open(path).map_err(|error| error.to_string())?);
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT profile, owner_id, grant_index_key, max_invocations
            FROM budget_composite_authorization_quotas
            WHERE hold_id = ?1
            ORDER BY position ASC
            "#,
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![request.hold_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut invocation_quotas = Vec::new();
    for row in rows {
        let (profile, owner_id, grant_index, max_invocations) =
            row.map_err(|error| error.to_string())?;
        let profile = quota_profile_from_label(&profile)?;
        let grant_index = match profile {
            BudgetQuotaProfileView::GrantInvocation => Some(
                u32::try_from(grant_index)
                    .map_err(|_| "persisted grant quota index is invalid".to_string())?,
            ),
            _ if grant_index == -1 => None,
            _ => return Err("persisted aggregate quota carries a grant index".to_string()),
        };
        invocation_quotas.push(BudgetInvocationQuotaView {
            key: BudgetQuotaKeyView {
                profile,
                owner_id,
                grant_index,
            },
            max_invocations: u32::try_from(max_invocations)
                .map_err(|_| "persisted quota maximum is invalid".to_string())?,
        });
    }
    if invocation_quotas.is_empty() {
        return Err("combined capture hold has no persisted invocation quotas".to_string());
    }
    Ok(ConsensusCombinedCaptureCommand {
        request,
        invocation_quotas,
    })
}

fn validate_persisted_capture_hold(
    config: &TrustServiceConfig,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    event_id: &str,
    authority: Option<&BudgetMutationAuthorityView>,
) -> Result<(), String> {
    let authority = authority
        .ok_or_else(|| "capture requires the exact persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "capture requires a budget database".to_string())?;
    let store = SqliteBudgetStore::open(path).map_err(|error| error.to_string())?;
    if store
        .hold_authority(hold_id)
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(&authority)
    {
        return Err("capture authority does not match the persisted hold authority".to_string());
    }
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let persisted = connection
        .query_row(
            r#"
            SELECT capability_id, grant_index, disposition
            FROM budget_authorization_holds
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "capture hold does not exist".to_string())?;
    let event_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE event_id = ?1)",
            params![event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?
        != 0;
    if event_exists {
        return Err("capture event ID is already owned by a persisted mutation".to_string());
    }
    let persisted_grant_index = usize::try_from(persisted.1)
        .map_err(|_| "capture hold grant index is invalid".to_string())?;
    if persisted.0 != capability_id || persisted_grant_index != grant_index || persisted.2 != "open"
    {
        return Err("capture request does not match an open persisted hold".to_string());
    }
    Ok(())
}

fn validate_composite_quota_maxima(
    config: &TrustServiceConfig,
    request: &CompositeBudgetAuthorizeRequest,
) -> Result<(), String> {
    let path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "composite authorize requires a budget database".to_string())?;
    drop(SqliteBudgetStore::open(path).map_err(|error| error.to_string())?);
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let namespace_exists = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_authorization_claims WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_composite_authorizations
                WHERE hold_id = ?1 OR event_id = ?2
                UNION ALL
                SELECT 1 FROM budget_mutation_events WHERE event_id = ?2
                UNION ALL
                SELECT 1 FROM admission_capture_events WHERE capture_event_id = ?2
            )
            "#,
            params![request.hold_id, request.event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?
        != 0;
    if namespace_exists {
        return Err(
            "composite authorization hold or event namespace is already persisted".to_string(),
        );
    }
    for quota in &request.admission_evidence.invocation_quotas {
        let profile = match quota.key.profile {
            BudgetQuotaProfileView::GrantInvocation => "chio.grant-invocation.v1",
            BudgetQuotaProfileView::AggregateCapabilityInvocation => {
                "chio.aggregate-capability-invocation.v1"
            }
            BudgetQuotaProfileView::AggregateFamilyInvocation => {
                "chio.aggregate-family-invocation.v1"
            }
            BudgetQuotaProfileView::SupplementalBrokerExecution => {
                "chio.broker-capability-execution.v1"
            }
        };
        let grant_index = quota.key.grant_index.map_or(-1_i64, i64::from);
        let existing = connection
            .query_row(
                r#"
                SELECT max_invocations
                FROM budget_invocation_quota_usage
                WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                "#,
                params![profile, quota.key.owner_id, grant_index],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.is_some_and(|maximum| maximum != i64::from(quota.max_invocations)) {
            return Err(format!(
                "invocation quota `{profile}:{}` cannot change its persisted maximum",
                quota.key.owner_id
            ));
        }
    }
    Ok(())
}

fn propose_admission_command_blocking(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: Value,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    let (self_url, _, membership) = admission_members(state)?;
    let request = AdmissionProposalRequest {
        operation_id: operation_id.clone(),
        command_kind,
        command: command.clone(),
    };
    let mut last_error = None;
    for coordinator in &membership.members {
        if coordinator == &self_url {
            match propose_admission_command_local(
                state,
                operation_id.clone(),
                command_kind,
                command.clone(),
            ) {
                Ok(result) => return Ok(result),
                Err(error) => last_error = Some(error),
            }
        } else if let Ok(client) = service_runtime::client::build_cluster_peer_client(
            coordinator,
            &state.config,
            &self_url,
        ) {
            if let Ok(result) = client.admission_proposal(&request) {
                return Ok(result);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus could not reach any configured proposal coordinator".to_string(),
        )
    }))
}

fn propose_admission_command_local(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: Value,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    let (self_url, _, membership) = admission_members(state)?;
    let serializer = admission_proposal_serializer(&self_url);
    let _guard = match serializer.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    const MAX_ATTEMPTS: usize = 16;
    let retry_rank = membership
        .members
        .iter()
        .position(|member| member == &self_url)
        .unwrap_or(0);
    for attempt in 0..MAX_ATTEMPTS {
        match propose_admission_command_once(
            state,
            operation_id.clone(),
            command_kind,
            command.clone(),
        ) {
            Ok(result) => return Ok(result),
            Err(error) if attempt + 1 < MAX_ATTEMPTS && retryable_consensus_contention(&error) => {
                catch_up_admission_from_peers(state, &membership, &self_url)?;
                std::thread::sleep(consensus_retry_delay(&operation_id, attempt, retry_rank));
            }
            Err(error) => return Err(error),
        }
    }
    Err(AdmissionConsensusError::Protocol(
        "admission consensus exhausted bounded contention retries".to_string(),
    ))
}

fn admission_proposal_serializer(member_id: &str) -> Arc<Mutex<()>> {
    type SerializerRegistry = BTreeMap<String, std::sync::Weak<Mutex<()>>>;
    static SERIALIZERS: std::sync::OnceLock<Mutex<SerializerRegistry>> = std::sync::OnceLock::new();
    let registry = SERIALIZERS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    registry.retain(|_, serializer| serializer.strong_count() != 0);
    if let Some(serializer) = registry.get(member_id).and_then(std::sync::Weak::upgrade) {
        return serializer;
    }
    let serializer = Arc::new(Mutex::new(()));
    registry.insert(member_id.to_string(), Arc::downgrade(&serializer));
    serializer
}

fn catch_up_admission_from_peers(
    state: &TrustServiceState,
    membership: &AdmissionMembership,
    self_url: &str,
) -> Result<bool, AdmissionConsensusError> {
    let store = configured_admission_consensus_store(&state.config)?;
    let mut snapshots = Vec::new();
    for peer in &membership.members {
        if peer == self_url {
            continue;
        }
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config,
            self_url,
        ) else {
            continue;
        };
        let Ok(snapshot) = client.admission_snapshot() else {
            continue;
        };
        validate_snapshot_for_membership(&snapshot, membership)?;
        store.observe_higher_term(snapshot.meta.current_term)?;
        snapshots.push(snapshot);
    }
    for left in 0..snapshots.len() {
        for right in (left + 1)..snapshots.len() {
            let shared = usize_index(
                snapshots[left]
                    .meta
                    .commit_index
                    .min(snapshots[right].meta.commit_index),
                "admission peer snapshot overlap",
            )?;
            if snapshots[left].entries.get(..shared) != snapshots[right].entries.get(..shared)
                || snapshots[left].commit_proofs.get(..shared)
                    != snapshots[right].commit_proofs.get(..shared)
                || snapshots[left].results.get(..shared) != snapshots[right].results.get(..shared)
            {
                return Err(AdmissionConsensusError::Protocol(
                    "authenticated admission peer snapshots have conflicting committed prefixes"
                        .to_string(),
                ));
            }
        }
    }
    snapshots.sort_by(|left, right| {
        right
            .meta
            .commit_index
            .cmp(&left.meta.commit_index)
            .then_with(|| right.meta.current_term.cmp(&left.meta.current_term))
    });
    let mut advanced = false;
    for snapshot in snapshots {
        advanced |= store.merge_committed_snapshot(
            membership,
            &snapshot,
            |transaction, entry, proof| {
                apply_admission_log_entry(&state.config, transaction, entry, proof)
            },
        )?;
    }
    Ok(advanced)
}

fn retryable_consensus_contention(error: &AdmissionConsensusError) -> bool {
    let AdmissionConsensusError::Protocol(message) = error else {
        return false;
    };
    [
        "could not elect a majority leader",
        "lost quorum before commit",
        "leader epoch changed before commit",
        "leader epoch changed before local append",
        "reported a higher term",
        "returned another election term",
        "peer commit index is ahead of the elected leader",
        "majority apply acknowledgement was unavailable",
        "could not confirm one applied state on a majority",
    ]
    .iter()
    .any(|fragment| message.contains(fragment))
}

fn consensus_retry_delay(operation_id: &str, attempt: usize, member_rank: usize) -> Duration {
    let digest = sha256_hex(operation_id.as_bytes());
    let jitter = u64::from_str_radix(&digest[..2], 16).unwrap_or(0) % 7;
    let rank = u64::try_from(member_rank).unwrap_or(u64::MAX);
    let multiplier = 1_u64 << attempt.min(5);
    let base = rank.saturating_mul(40).saturating_add(4);
    Duration::from_millis(
        base.saturating_mul(multiplier)
            .saturating_add(jitter)
            .min(400),
    )
}

fn propose_admission_command_once(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: Value,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    if command_kind == AdmissionCommandKind::LeadershipBarrier {
        return Err(AdmissionConsensusError::Protocol(
            "leadership barriers cannot be submitted externally".to_string(),
        ));
    }
    let operation_id = scoped_operation_id(command_kind, &operation_id)?;
    let store = configured_admission_consensus_store(&state.config)?;
    let (self_url, peers, membership) = admission_members(state)?;
    let mut apply =
        |transaction: &Transaction<'_>, entry: &AdmissionLogEntry, proof: &AdmissionCommitProof| {
            apply_admission_log_entry(&state.config, transaction, entry, proof)
        };
    store.apply_committed(&mut apply)?;
    let existing = store.entry_for_operation(&operation_id)?;
    if let Some(existing) = existing.as_ref() {
        ensure_operation_command_matches(existing, command_kind, &command)?;
    }
    let existing_result = store.result_for_operation(&operation_id)?;
    let quorum_size = membership.quorum_size();
    let election = store.begin_election(&membership, &self_url)?;
    let vote_request = AdmissionRequestVoteRequest {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        term: election.term,
        candidate_id: self_url.clone(),
        last_log_index: election.last_log_index,
        last_log_term: election.last_log_term,
        commit_index: election.commit_index,
    };
    let mut votes = 1usize;
    for peer in &peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config,
            &self_url,
        ) else {
            continue;
        };
        let Ok(response) = client.admission_request_vote(&vote_request) else {
            continue;
        };
        if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
            || response.membership_digest != membership.digest()
        {
            continue;
        }
        if response.term > election.term {
            store.observe_higher_term(response.term)?;
            continue;
        }
        if response.term == election.term && response.vote_granted {
            votes = votes.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission election vote count overflow".to_string(),
                )
            })?;
        }
    }
    if votes < quorum_size || !store.recheck_elected_epoch(&membership, &election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus could not elect a majority leader".to_string(),
        ));
    }
    if let Some(result) = existing_result {
        confirm_committed_state(
            state,
            &store,
            &membership,
            &election,
            &self_url,
            &peers,
            quorum_size,
        )?;
        return Ok(result);
    }
    let entry = if existing.is_some() {
        let barrier_scope = format!("{}:{}", membership.digest(), election.term);
        let barrier_operation_id =
            scoped_operation_id(AdmissionCommandKind::LeadershipBarrier, &barrier_scope)?;
        let barrier_command = json!({
            "membershipDigest": membership.digest(),
            "term": election.term,
        });
        AdmissionConsensusStore::build_entry(
            &election,
            &barrier_operation_id,
            AdmissionCommandKind::LeadershipBarrier,
            &barrier_command,
        )?
    } else {
        let prepared_command = prepare_command(&state.config, command_kind, command, &election)?;
        AdmissionConsensusStore::build_entry(
            &election,
            &operation_id,
            command_kind,
            &prepared_command,
        )?
    };
    store.append_local(&election, &entry)?;
    let committed = replicate_and_commit_entry(
        state,
        &store,
        &membership,
        &election,
        &self_url,
        &peers,
        quorum_size,
        &entry,
        &mut apply,
    )?;
    if existing.is_some() {
        return store.result_for_operation(&operation_id)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "inherited admission operation was not committed by the current-term barrier"
                    .to_string(),
            )
        });
    }
    Ok(committed)
}

fn ensure_operation_command_matches(
    existing: &AdmissionLogEntry,
    command_kind: AdmissionCommandKind,
    command: &Value,
) -> Result<(), AdmissionConsensusError> {
    if existing.command_kind != command_kind {
        return Err(AdmissionConsensusError::Protocol(
            "admission operation was reused for another command kind".to_string(),
        ));
    }
    let persisted: Value = serde_json::from_str(&existing.canonical_command).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "persisted admission command is invalid: {error}"
        ))
    })?;
    let matches = match command_kind {
        AdmissionCommandKind::LeadershipBarrier => persisted == *command,
        AdmissionCommandKind::IncrementInvocation => persisted.get("request") == Some(command),
        AdmissionCommandKind::CompositeAuthorize => persisted.get("request") == Some(command),
        AdmissionCommandKind::Revoke => {
            let persisted: ConsensusRevocationCommand = serde_json::from_value(persisted.clone())
                .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "persisted revocation command is invalid: {error}"
                ))
            })?;
            let requested: ConsensusRevocationProposal = serde_json::from_value(command.clone())
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "requested revocation proposal is invalid: {error}"
                    ))
                })?;
            persisted.capability_id == requested.capability_id
        }
        AdmissionCommandKind::CaptureInvocations => persisted == *command,
        AdmissionCommandKind::ReverseExposure
        | AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => persisted == *command,
        AdmissionCommandKind::CombinedCapture => persisted.get("request") == Some(command),
    };
    if !matches {
        return Err(AdmissionConsensusError::Protocol(
            "admission operation retry changed its canonical command".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn confirm_committed_state(
    state: &TrustServiceState,
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    self_url: &str,
    peers: &[String],
    quorum_size: usize,
) -> Result<(), AdmissionConsensusError> {
    let local = store.meta()?;
    if local.commit_index == 0
        || local.last_applied != local.commit_index
        || !is_lower_sha256(&local.applied_state_digest)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission retry has no complete committed state to confirm".to_string(),
        ));
    }
    let mut matching_nodes = 1usize;
    for peer in peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config,
            self_url,
        ) else {
            continue;
        };
        let Ok(response) =
            synchronize_peer_through(store, membership, election, &client, local.commit_index)
        else {
            continue;
        };
        if response.applied_index == local.last_applied
            && response.applied_state_digest == local.applied_state_digest
        {
            matching_nodes = matching_nodes.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission confirmation count overflow".to_string(),
                )
            })?;
        }
    }
    if matching_nodes < quorum_size || !store.recheck_elected_epoch(membership, election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission retry could not confirm one applied state on a majority".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replicate_and_commit_entry<F>(
    state: &TrustServiceState,
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    self_url: &str,
    peers: &[String],
    quorum_size: usize,
    entry: &AdmissionLogEntry,
    apply: &mut F,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError>
where
    F: FnMut(&Transaction<'_>, &AdmissionLogEntry, &AdmissionCommitProof) -> Result<String, String>,
{
    if entry.leader_epoch != election.term {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit target was not created in the current leader term".to_string(),
        ));
    }
    let mut witnesses = vec![self_url.to_string()];
    for peer in peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config,
            self_url,
        ) else {
            continue;
        };
        let Ok(response) =
            synchronize_peer_through(store, membership, election, &client, entry.index)
        else {
            continue;
        };
        if response.match_index >= entry.index {
            witnesses.push(peer.clone());
        }
    }
    witnesses.sort();
    witnesses.dedup();
    if witnesses.len() < quorum_size || !store.recheck_elected_epoch(membership, election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus lost quorum before commit".to_string(),
        ));
    }
    let first_uncommitted =
        checked_successor(store.meta()?.commit_index, "admission leader commit index")?;
    let mut target_result = None;
    for index in first_uncommitted..=entry.index {
        let proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index,
            leader_epoch: election.term,
            current_term_commit_index: entry.index,
            leader_id: self_url.to_string(),
            quorum_size,
            witness_urls: witnesses.clone(),
        };
        let result = store.commit_local(membership, election, &proof, &mut *apply)?;
        if index == entry.index {
            target_result = Some(result);
        }
    }
    let committed_meta = store.meta()?;
    if committed_meta.last_applied != entry.index {
        return Err(AdmissionConsensusError::Protocol(
            "admission leader did not apply its committed prefix exactly".to_string(),
        ));
    }
    let mut applied_nodes = 1usize;
    for peer in peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config,
            self_url,
        ) else {
            continue;
        };
        let Ok(response) =
            synchronize_peer_through(store, membership, election, &client, entry.index)
        else {
            continue;
        };
        if response.applied_index == entry.index
            && response.applied_state_digest == committed_meta.applied_state_digest
        {
            applied_nodes = applied_nodes.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission applied acknowledgement count overflow".to_string(),
                )
            })?;
        }
    }
    if applied_nodes < quorum_size || !store.recheck_elected_epoch(membership, election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit was durable but a majority apply acknowledgement was unavailable"
                .to_string(),
        ));
    }
    target_result.ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission current-term commit target produced no result".to_string(),
        )
    })
}
