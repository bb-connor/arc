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

pub(crate) async fn query_committed_composite_authorization(
    state: &TrustServiceState,
    request: CompositeBudgetAuthorizeRequest,
) -> Result<String, Response> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        query_committed_composite_authorization_blocking(&state, &request)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "committed composite authorization query worker failed before completion",
        )
    })?
    .map_err(consensus_http_error)
}

fn query_committed_composite_authorization_blocking(
    state: &TrustServiceState,
    request: &CompositeBudgetAuthorizeRequest,
) -> Result<String, AdmissionConsensusError> {
    if !request.existing_only {
        return Err(AdmissionConsensusError::Protocol(
            "committed composite authorization query requires existingOnly".to_string(),
        ));
    }
    let (self_url, peers, membership) = admission_members_read_only(state)?;
    let request_nonce = uuid::Uuid::new_v4().to_string();
    let replica_request = CommittedCompositeAuthorizationReplicaQueryRequest {
        request_nonce: request_nonce.clone(),
        request: request.clone(),
    };
    let mut responses = Vec::with_capacity(membership.members.len());
    let mut last_error = None;

    match query_committed_composite_authorization_replica(
        &state.config,
        &membership,
        &self_url,
        request,
        &request_nonce,
    ) {
        Ok(response) => {
            match validate_committed_composite_authorization_replica_response(
                &membership,
                &self_url,
                &state.config,
                request,
                &request_nonce,
                response,
            ) {
                Ok(query) => responses.push(query),
                Err(error) => last_error = Some(error),
            }
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
        let response = match client.committed_composite_authorization_replica_query(&replica_request) {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(AdmissionConsensusError::Protocol(error.to_string()));
                continue;
            }
        };
        match validate_committed_composite_authorization_replica_response(
            &membership,
            &peer,
            &state.config,
            request,
            &request_nonce,
            response,
        ) {
            Ok(query) => responses.push(query),
            Err(error) => last_error = Some(error),
        }
    }

    if responses.len() < membership.quorum_size() {
        return Err(last_error.unwrap_or_else(|| {
            AdmissionConsensusError::Protocol(
                "committed composite authorization query could not read an authenticated quorum"
                    .to_string(),
            )
        }));
    }
    let saw_committed = responses
        .iter()
        .any(|response| response.result.is_some());
    let mut groups: BTreeMap<
        Vec<u8>,
        (usize, CommittedCompositeAuthorizationQueryView),
    > = BTreeMap::new();
    for response in responses {
        let canonical = canonical_json_bytes(&response).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "committed composite authorization read barrier cannot be canonicalized: {error}"
            ))
        })?;
        let group = groups.entry(canonical).or_insert((0, response));
        group.0 = group.0.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "committed composite authorization quorum count overflowed".to_string(),
            )
        })?;
    }
    let mut quorum_view = None;
    for (_, (count, view)) in groups {
        if count >= membership.quorum_size() {
            if quorum_view.is_some() {
                return Err(committed_replay_conflict(
                    "authenticated replicas returned multiple quorum read barriers",
                ));
            }
            quorum_view = Some(view);
        }
    }
    let Some(quorum_view) = quorum_view else {
        return Err(committed_replay_conflict(
            "authenticated replicas did not return one byte-identical quorum view",
        ));
    };
    if saw_committed && quorum_view.result.is_none() {
        return Err(committed_replay_conflict(
            "a committed replica result did not have a byte-identical quorum",
        ));
    }
    if let Some(rejection) = quorum_view.rejection {
        let result = quorum_view.result.ok_or_else(|| {
            committed_replay_conflict("quorum rejection omitted its committed result")
        })?;
        let envelope = CommittedCompositeAuthorizationRejectionEnvelopeView {
            admission_consensus_rejection: rejection.clone(),
        };
        let canonical = canonical_json_bytes(&envelope).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "committed composite authorization rejection cannot be canonicalized: {error}"
            ))
        })?;
        if canonical != result.response_json.as_bytes() {
            return Err(committed_replay_conflict(
                "quorum rejection bytes differ from the committed result",
            ));
        }
        return Err(AdmissionConsensusError::Rejected {
            status_code: rejection.status_code,
            message: rejection.message,
        });
    }
    let Some(authorization) = quorum_view.authorization else {
        return Err(committed_replay_missing(request));
    };
    let result = quorum_view.result.ok_or_else(|| {
        committed_replay_conflict("quorum authorization omitted its committed result")
    })?;
    let canonical = canonical_json_bytes(&authorization).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "committed composite authorization response cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != result.response_json.as_bytes() {
        return Err(committed_replay_conflict(
            "quorum authorization bytes differ from the committed result",
        ));
    }
    Ok(result.response_json)
}

fn query_committed_composite_authorization_replica(
    config: &TrustServiceConfig,
    membership: &AdmissionMembership,
    node_id: &str,
    request: &CompositeBudgetAuthorizeRequest,
    request_nonce: &str,
) -> Result<CommittedCompositeAuthorizationReplicaQueryResponse, AdmissionConsensusError> {
    let original_request = original_composite_authorization_request(request)?;
    let request_digest = committed_composite_authorization_request_digest(request)?;
    let path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed composite authorization query requires a budget database".to_string(),
        )
    })?;
    let budget_store = SqliteBudgetStore::open_existing_read_only(path)
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let stored_input = budget_store
        .query_composite_authorization_input(&request.event_id)
        .map_err(committed_replay_budget_error)?;
    let durable_decision = budget_store
        .query_composite_authorization(&request.event_id)
        .map_err(committed_replay_budget_error)?;

    let consensus_store = configured_admission_consensus_store_read_only(config)?;
    let scoped_operation_id = scoped_operation_id(
        AdmissionCommandKind::CompositeAuthorize,
        &request.event_id,
    )?;
    let snapshot = consensus_store.committed_operation_snapshot(&scoped_operation_id)?;
    consensus_store.validate_membership_proofs(membership)?;
    let meta = snapshot.meta;
    let leader_id = meta.voted_for.clone().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed authorization read barrier has no current leader".to_string(),
        )
    })?;
    let read_barrier = snapshot.read_barrier.ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed authorization query has no current-term read barrier".to_string(),
        )
    })?;
    validate_committed_composite_read_barrier(
        membership,
        &meta,
        &leader_id,
        &read_barrier,
    )?;
    let entry = snapshot.entry;
    let result = snapshot.result;
    let result_commit_proof = snapshot.result_commit_proof;
    let result_commit_target = snapshot.result_commit_target;

    if entry.is_none() && result.is_none() {
        if result_commit_proof.is_some()
            || result_commit_target.is_some()
            || stored_input.is_some()
            || durable_decision.is_some()
            || budget_store
                .composite_replay_namespace_exists(
                    &request.hold_id,
                    &request.event_id,
                    &request.operation_id,
                )
                .map_err(committed_replay_budget_error)?
        {
            return Err(committed_replay_conflict(
                "committed replay namespace exists without an exact consensus result",
            ));
        }
        return committed_composite_authorization_replica_response(
            membership,
            config,
            node_id,
            request,
            request_nonce,
            request_digest,
            scoped_operation_id,
            meta,
            leader_id,
            read_barrier,
            None,
            None,
            None,
            None,
            None,
            None,
        );
    }
    let (Some(entry), Some(result)) = (entry, result) else {
        return Err(committed_replay_conflict(
            "committed composite authorization contains a partial entry or result",
        ));
    };
    let result_commit_proof = result_commit_proof.ok_or_else(|| {
        committed_replay_conflict(
            "committed authorization result omitted its persisted commit proof",
        )
    })?;
    let result_commit_target = result_commit_target.ok_or_else(|| {
        committed_replay_conflict(
            "committed authorization result omitted its current-term commit target",
        )
    })?;
    validate_entry(&entry)?;
    if entry.command_kind != AdmissionCommandKind::CompositeAuthorize
        || entry.operation_id != scoped_operation_id
        || entry.operation_id != result.operation_id
        || entry.index != result.log_index
        || result.log_index > meta.commit_index
        || result.log_index > meta.last_applied
    {
        return Err(committed_replay_conflict(
            "committed authorization result does not match its consensus entry",
        ));
    }
    validate_commit_proof_for_membership(&result_commit_proof, membership)?;
    validate_entry(&result_commit_target)?;
    if result_commit_proof.index != entry.index
        || entry.leader_epoch > result_commit_proof.leader_epoch
        || result_commit_proof.current_term_commit_index < entry.index
        || result_commit_proof.current_term_commit_index > meta.commit_index
        || result_commit_target.index != result_commit_proof.current_term_commit_index
        || result_commit_target.leader_epoch != result_commit_proof.leader_epoch
    {
        return Err(committed_replay_conflict(
            "committed authorization proof does not match its entry or applied watermark",
        ));
    }
    let command: ConsensusCompositeAuthorizeCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| {
            committed_replay_conflict(format!(
                "persisted composite authorization command is malformed: {error}"
            ))
        })?;
    validate_committed_authorization_command_binding(
        membership,
        &original_request,
        &entry,
        &command,
    )?;
    if let Some(rejection) = committed_authorization_rejection(&result)? {
        return committed_composite_authorization_replica_response(
            membership,
            config,
            node_id,
            request,
            request_nonce,
            request_digest,
            scoped_operation_id,
            meta,
            leader_id,
            read_barrier,
            Some(entry),
            Some(result_commit_proof),
            Some(result_commit_target),
            Some(result),
            None,
            Some(rejection),
        );
    }
    let (Some(stored_input), Some(durable_decision)) = (stored_input, durable_decision) else {
        return Err(committed_replay_conflict(
            "committed authorization result has no exact durable budget decision",
        ));
    };
    let authority = budget_authority_from_view(&command.authority)
        .map_err(committed_replay_conflict)?;
    let prepared = super::super::budget_handlers::sqlite_composite_authorize_input(
        &original_request,
        authority,
        config.partition_escrow_authority.as_deref(),
    )
    .map_err(committed_replay_budget_error)?;
    let (expected_authorization, expected_family_evidence) = match prepared {
        super::super::budget_handlers::PreparedSqliteCompositeAuthorization::NonFamily(
            authorization,
        ) => (authorization, None),
        super::super::budget_handlers::PreparedSqliteCompositeAuthorization::AggregateFamily {
            authorization,
            evidence,
        } => (authorization, Some(evidence)),
    };
    if stored_input.authorization != expected_authorization
        || stored_input.aggregate_family_evidence != expected_family_evidence
    {
        return Err(committed_replay_conflict(
            "query does not match the exact durable composite authorization input",
        ));
    }

    let result = accepted_consensus_result(result)?;
    let response: CompositeBudgetAuthorizeResponse =
        serde_json::from_str(&result.response_json).map_err(|error| {
            committed_replay_conflict(format!(
                "persisted composite authorization response is malformed: {error}"
            ))
        })?;
    validate_committed_authorization_authority_binding(
        membership,
        &original_request,
        &entry,
        &result_commit_proof,
        &command,
        &response,
    )?;
    super::super::service_runtime::budget::validate_composite_authorize_response(
        &original_request,
        response.clone(),
    )
    .map_err(|error| committed_replay_conflict(error.to_string()))?;
    let authority = response.budget_authority.clone().ok_or_else(|| {
        committed_replay_conflict(
            "persisted composite authorization response omitted authority evidence",
        )
    })?;
    let commit = response.budget_commit.clone().ok_or_else(|| {
        committed_replay_conflict(
            "persisted composite authorization response omitted commit evidence",
        )
    })?;
    if commit.commit_index != result.log_index
        || authority.budget_commit_index != Some(result.log_index)
    {
        return Err(committed_replay_conflict(
            "persisted composite authorization response changed its consensus commit index",
        ));
    }
    let reconstructed = super::super::budget_handlers::composite_authorize_response_view(
        &original_request,
        durable_decision,
        authority,
        commit,
    )
    .map_err(committed_replay_budget_error)?;
    let reconstructed = canonical_json_bytes(&reconstructed).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "durable composite authorization cannot be canonicalized: {error}"
        ))
    })?;
    if reconstructed != result.response_json.as_bytes() {
        return Err(committed_replay_conflict(
            "durable composite authorization diverges from its committed consensus result",
        ));
    }
    committed_composite_authorization_replica_response(
        membership,
        config,
        node_id,
        request,
        request_nonce,
        request_digest,
        scoped_operation_id,
        meta,
        leader_id,
        read_barrier,
        Some(entry),
        Some(result_commit_proof),
        Some(result_commit_target),
        Some(result),
        Some(response),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn committed_composite_authorization_replica_response(
    membership: &AdmissionMembership,
    config: &TrustServiceConfig,
    node_id: &str,
    request: &CompositeBudgetAuthorizeRequest,
    request_nonce: &str,
    request_digest: String,
    scoped_operation_id: String,
    meta: AdmissionConsensusMetaView,
    leader_id: String,
    read_barrier: AdmissionCommitProof,
    entry: Option<AdmissionLogEntry>,
    result_commit_proof: Option<AdmissionCommitProof>,
    result_commit_target: Option<AdmissionLogEntry>,
    result: Option<AdmissionConsensusResult>,
    authorization: Option<CompositeBudgetAuthorizeResponse>,
    rejection: Option<CommittedCompositeAuthorizationRejectionView>,
) -> Result<CommittedCompositeAuthorizationReplicaQueryResponse, AdmissionConsensusError> {
    if uuid::Uuid::parse_str(request_nonce)
        .ok()
        .is_none_or(|nonce| nonce.get_version_num() != 4)
    {
        return Err(committed_replay_conflict(
            "committed composite authorization query nonce is invalid",
        ));
    }
    let issued_at = unix_timestamp_now();
    let expires_at = issued_at
        .checked_add(COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_MAX_TTL_SECS)
        .ok_or_else(|| {
            committed_replay_conflict(
                "committed composite authorization response expiry overflowed",
            )
        })?;
    let seed_path = config.cluster_node_seed_path.as_deref().ok_or_else(|| {
        committed_replay_conflict(
            "committed composite authorization response signer is not configured",
        )
    })?;
    let keypair = load_strict_cluster_node_keypair(seed_path)
        .map_err(|error| committed_replay_conflict(error.to_string()))?;
    let expected_signer = committed_replay_member_public_key(config, node_id)?;
    if keypair.public_key() != expected_signer {
        return Err(committed_replay_conflict(
            "committed composite authorization signer does not match pinned membership",
        ));
    }
    let body = CommittedCompositeAuthorizationReplicaQueryResponseBody {
        protocol_version: COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_PROTOCOL_VERSION.to_string(),
        consensus_protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        service: COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_SERVICE.to_string(),
        membership_digest: membership.digest().to_string(),
        node_id: node_id.to_string(),
        request_nonce: request_nonce.to_string(),
        issued_at,
        expires_at,
        query: CommittedCompositeAuthorizationQueryView {
            service_namespace: COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_NAMESPACE.to_string(),
            request_digest,
            operation_id: request.operation_id.clone(),
            request_binding_hash: request.request_binding_hash.clone(),
            hold_id: request.hold_id.clone(),
            event_id: request.event_id.clone(),
            scoped_operation_id,
            current_term: meta.current_term,
            leader_id,
            last_log_index: meta.last_log_index,
            last_log_term: meta.last_log_term,
            commit_index: meta.commit_index,
            last_applied: meta.last_applied,
            applied_state_digest: meta.applied_state_digest,
            read_barrier,
            entry,
            result_commit_proof,
            result_commit_target,
            result,
            authorization,
            rejection,
        },
    };
    CommittedCompositeAuthorizationReplicaQueryResponse::sign(body, &keypair)
        .map_err(committed_replay_conflict)
}

fn validate_committed_composite_authorization_replica_response(
    membership: &AdmissionMembership,
    expected_node_id: &str,
    config: &TrustServiceConfig,
    request: &CompositeBudgetAuthorizeRequest,
    request_nonce: &str,
    response: CommittedCompositeAuthorizationReplicaQueryResponse,
) -> Result<CommittedCompositeAuthorizationQueryView, AdmissionConsensusError> {
    let expected_signer = committed_replay_member_public_key(config, expected_node_id)?;
    response
        .verify_signature(&expected_signer)
        .map_err(committed_replay_conflict)?;
    let now = unix_timestamp_now();
    let response = response.body;
    if response.protocol_version != COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_PROTOCOL_VERSION
        || response.consensus_protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || response.service != COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_SERVICE
        || response.membership_digest != membership.digest()
        || response.node_id != expected_node_id
        || !membership.contains(expected_node_id)
        || response.request_nonce != request_nonce
        || response.issued_at > now
        || response.expires_at <= now
        || response.expires_at.saturating_sub(response.issued_at)
            != COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_MAX_TTL_SECS
    {
        return Err(committed_replay_conflict(
            "replica response changed its authenticated service or membership binding",
        ));
    }
    let query = response.query;
    let expected_scoped_operation_id = scoped_operation_id(
        AdmissionCommandKind::CompositeAuthorize,
        &request.event_id,
    )?;
    if query.service_namespace != COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_NAMESPACE
        || query.request_digest != committed_composite_authorization_request_digest(request)?
        || query.operation_id != request.operation_id
        || query.request_binding_hash != request.request_binding_hash
        || query.hold_id != request.hold_id
        || query.event_id != request.event_id
        || query.scoped_operation_id != expected_scoped_operation_id
        || !is_lower_sha256(&query.applied_state_digest)
    {
        return Err(committed_replay_conflict(
            "replica response changed its service namespace or request binding",
        ));
    }
    let meta = AdmissionConsensusMetaView {
        current_term: query.current_term,
        baseline_state_digest: None,
        membership_digest: Some(membership.digest().to_string()),
        voted_for: Some(query.leader_id.clone()),
        last_log_index: query.last_log_index,
        last_log_term: query.last_log_term,
        commit_index: query.commit_index,
        last_applied: query.last_applied,
        applied_state_digest: query.applied_state_digest.clone(),
    };
    validate_committed_composite_read_barrier(
        membership,
        &meta,
        &query.leader_id,
        &query.read_barrier,
    )?;
    match (
        query.entry.as_ref(),
        query.result_commit_proof.as_ref(),
        query.result_commit_target.as_ref(),
        query.result.as_ref(),
        query.authorization.as_ref(),
        query.rejection.as_ref(),
    ) {
        (None, None, None, None, None, None) => {}
        (
            Some(entry),
            Some(proof),
            Some(proof_target),
            Some(result),
            Some(authorization),
            None,
        ) => {
            validate_committed_query_result_evidence(
                membership,
                &expected_scoped_operation_id,
                query.commit_index,
                query.last_applied,
                entry,
                proof,
                proof_target,
                result,
            )?;
            let original_request = original_composite_authorization_request(request)?;
            let command: ConsensusCompositeAuthorizeCommand =
                serde_json::from_str(&entry.canonical_command).map_err(|error| {
                    committed_replay_conflict(format!(
                        "replica composite authorization command is malformed: {error}"
                    ))
                })?;
            validate_committed_authorization_authority_binding(
                membership,
                &original_request,
                entry,
                proof,
                &command,
                authorization,
            )?;
            super::super::service_runtime::budget::validate_composite_authorize_response(
                &original_request,
                authorization.clone(),
            )
            .map_err(|error| committed_replay_conflict(error.to_string()))?;
            if canonical_json_bytes(authorization).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "replica authorization cannot be canonicalized: {error}"
                ))
            })? != result.response_json.as_bytes()
            {
                return Err(committed_replay_conflict(
                    "replica authorization differs from its exact committed result bytes",
                ));
            }
        }
        (
            Some(entry),
            Some(proof),
            Some(proof_target),
            Some(result),
            None,
            Some(rejection),
        ) => {
            validate_committed_query_result_evidence(
                membership,
                &expected_scoped_operation_id,
                query.commit_index,
                query.last_applied,
                entry,
                proof,
                proof_target,
                result,
            )?;
            let original_request = original_composite_authorization_request(request)?;
            let command: ConsensusCompositeAuthorizeCommand =
                serde_json::from_str(&entry.canonical_command).map_err(|error| {
                    committed_replay_conflict(format!(
                        "replica composite authorization command is malformed: {error}"
                    ))
                })?;
            validate_committed_authorization_command_binding(
                membership,
                &original_request,
                entry,
                &command,
            )?;
            let envelope = CommittedCompositeAuthorizationRejectionEnvelopeView {
                admission_consensus_rejection: rejection.clone(),
            };
            if StatusCode::from_u16(rejection.status_code).is_err()
                || rejection.code.is_empty()
                || canonical_json_bytes(&envelope).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "replica rejection cannot be canonicalized: {error}"
                    ))
                })? != result.response_json.as_bytes()
            {
                return Err(committed_replay_conflict(
                    "replica rejection differs from its exact committed result bytes",
                ));
            }
        }
        _ => {
            return Err(committed_replay_conflict(
                "replica response contains a partial committed authorization",
            ));
        }
    }
    Ok(query)
}

#[allow(clippy::too_many_arguments)]
fn validate_committed_query_result_evidence(
    membership: &AdmissionMembership,
    expected_scoped_operation_id: &str,
    commit_index: u64,
    last_applied: u64,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    proof_target: &AdmissionLogEntry,
    result: &AdmissionConsensusResult,
) -> Result<(), AdmissionConsensusError> {
    validate_entry(entry)?;
    validate_entry(proof_target)?;
    validate_commit_proof_for_membership(proof, membership)?;
    if entry.command_kind != AdmissionCommandKind::CompositeAuthorize
        || entry.operation_id != expected_scoped_operation_id
        || entry.index != result.log_index
        || result.operation_id != expected_scoped_operation_id
        || result.log_index > commit_index
        || result.log_index > last_applied
        || proof.index != entry.index
        || entry.leader_epoch > proof.leader_epoch
        || proof.current_term_commit_index < entry.index
        || proof.current_term_commit_index > commit_index
        || proof_target.index != proof.current_term_commit_index
        || proof_target.leader_epoch != proof.leader_epoch
        || sha256_hex(result.response_json.as_bytes()) != result.response_digest
        || !is_lower_sha256(&result.security_projection_digest)
    {
        return Err(committed_replay_conflict(
            "replica result changed its scoped entry, proof, or commit watermark",
        ));
    }
    validate_canonical_json(&result.response_json, "committed replay result")
}

fn validate_committed_authorization_authority_binding(
    membership: &AdmissionMembership,
    original_request: &CompositeBudgetAuthorizeRequest,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    command: &ConsensusCompositeAuthorizeCommand,
    response: &CompositeBudgetAuthorizeResponse,
) -> Result<(), AdmissionConsensusError> {
    validate_committed_authorization_command_binding(
        membership,
        original_request,
        entry,
        command,
    )?;
    let authority = response.budget_authority.as_ref().ok_or_else(|| {
        committed_replay_conflict(
            "committed composite authorization omitted authority metadata",
        )
    })?;
    let commit = response.budget_commit.as_ref().ok_or_else(|| {
        committed_replay_conflict("committed composite authorization omitted quorum evidence")
    })?;
    if authority.authority_id != command.authority.authority_id
        || authority.lease_id != command.authority.lease_id
        || authority.lease_epoch != command.authority.lease_epoch
        || authority.budget_term != command.authority.lease_epoch
        || authority.leader_url != proof.leader_id
        || authority.guarantee_level != "ha_linearizable"
        || authority.budget_commit_index != Some(proof.index)
        || authority.lease_expires_at != u64::MAX
        || authority.lease_ttl_ms != u64::MAX
        || commit.authority_id != command.authority.authority_id
        || commit.lease_id != command.authority.lease_id
        || commit.lease_epoch != command.authority.lease_epoch
        || commit.budget_term != command.authority.lease_epoch
        || commit.commit_index != proof.index
        || !commit.quorum_committed
        || commit.quorum_size != proof.quorum_size
        || commit.committed_nodes != proof.witness_urls.len()
        || commit.witness_urls != proof.witness_urls
    {
        return Err(committed_replay_conflict(
            "composite authorization response changed its exact authority or quorum proof",
        ));
    }
    Ok(())
}

fn validate_committed_authorization_command_binding(
    membership: &AdmissionMembership,
    original_request: &CompositeBudgetAuthorizeRequest,
    entry: &AdmissionLogEntry,
    command: &ConsensusCompositeAuthorizeCommand,
) -> Result<(), AdmissionConsensusError> {
    let expected_lease_id = format!(
        "{}#admission-term-{}",
        command.authority.authority_id, entry.leader_epoch
    );
    if command.request.existing_only
        || canonical_json_bytes(&command.request).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "persisted composite authorization command cannot be canonicalized: {error}"
            ))
        })? != canonical_json_bytes(original_request).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "composite authorization request cannot be canonicalized: {error}"
            ))
        })?
        || !membership.contains(&command.authority.authority_id)
        || command.authority.lease_epoch != entry.leader_epoch
        || command.authority.lease_id != expected_lease_id
    {
        return Err(committed_replay_conflict(
            "composite authorization command changed its election-bound authority",
        ));
    }
    Ok(())
}

fn committed_authorization_rejection(
    result: &AdmissionConsensusResult,
) -> Result<Option<CommittedCompositeAuthorizationRejectionView>, AdmissionConsensusError> {
    let value: Value = serde_json::from_str(&result.response_json).map_err(|error| {
        committed_replay_conflict(format!(
            "committed composite authorization result is invalid JSON: {error}"
        ))
    })?;
    if value.get("admissionConsensusRejection").is_none() {
        return Ok(None);
    }
    let envelope: CommittedCompositeAuthorizationRejectionEnvelopeView =
        serde_json::from_value(value).map_err(|error| {
            committed_replay_conflict(format!(
                "committed composite authorization rejection is malformed: {error}"
            ))
        })?;
    let canonical = canonical_json_bytes(&envelope).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "committed composite authorization rejection cannot be canonicalized: {error}"
        ))
    })?;
    let rejection = envelope.admission_consensus_rejection;
    if canonical != result.response_json.as_bytes()
        || StatusCode::from_u16(rejection.status_code).is_err()
        || rejection.code.is_empty()
    {
        return Err(committed_replay_conflict(
            "committed composite authorization rejection is not exact",
        ));
    }
    Ok(Some(rejection))
}

fn committed_replay_member_public_key(
    config: &TrustServiceConfig,
    node_id: &str,
) -> Result<PublicKey, AdmissionConsensusError> {
    let node_id = normalize_cluster_url(node_id)
        .map_err(|error| committed_replay_conflict(error.to_string()))?;
    config
        .cluster_members
        .iter()
        .find_map(|member| {
            normalize_cluster_url(&member.node_url)
                .ok()
                .filter(|member_url| member_url == &node_id)
                .map(|_| member.public_key.clone())
        })
        .ok_or_else(|| {
            committed_replay_conflict(
                "committed composite authorization response signer is not pinned",
            )
        })
}

fn validate_committed_composite_read_barrier(
    membership: &AdmissionMembership,
    meta: &AdmissionConsensusMetaView,
    leader_id: &str,
    read_barrier: &AdmissionCommitProof,
) -> Result<(), AdmissionConsensusError> {
    validate_commit_proof_for_membership(read_barrier, membership)?;
    if meta.current_term == 0
        || !membership.contains(leader_id)
        || meta.membership_digest.as_deref() != Some(membership.digest())
        || meta.voted_for.as_deref() != Some(leader_id)
        || meta.commit_index == 0
        || meta.last_applied != meta.commit_index
        || meta.commit_index > meta.last_log_index
        || meta.last_log_term > meta.current_term
        || read_barrier.index != meta.commit_index
        || read_barrier.leader_epoch != meta.current_term
        || read_barrier.current_term_commit_index != meta.commit_index
        || read_barrier.leader_id != leader_id
    {
        return Err(committed_replay_conflict(
            "replica response lacks a fully applied current-term quorum read barrier",
        ));
    }
    Ok(())
}

fn committed_composite_authorization_request_digest(
    request: &CompositeBudgetAuthorizeRequest,
) -> Result<String, AdmissionConsensusError> {
    const DOMAIN: &[u8] = b"chio.committed-composite-authorization-query.request.v1\0";
    let canonical = canonical_json_bytes(request).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "committed composite authorization query cannot be canonicalized: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn original_composite_authorization_request(
    request: &CompositeBudgetAuthorizeRequest,
) -> Result<CompositeBudgetAuthorizeRequest, AdmissionConsensusError> {
    if !request.existing_only {
        return Err(AdmissionConsensusError::Protocol(
            "committed composite authorization query requires existingOnly".to_string(),
        ));
    }
    let mut original = request.clone();
    original.existing_only = false;
    Ok(original)
}

fn committed_replay_missing(
    request: &CompositeBudgetAuthorizeRequest,
) -> AdmissionConsensusError {
    AdmissionConsensusError::Rejected {
        status_code: StatusCode::CONFLICT.as_u16(),
        message: format!(
            "budget_committed_replay_missing: no authorization is committed for hold `{}` and event `{}`",
            request.hold_id, request.event_id
        ),
    }
}

fn committed_replay_conflict(message: impl Into<String>) -> AdmissionConsensusError {
    AdmissionConsensusError::Rejected {
        status_code: StatusCode::CONFLICT.as_u16(),
        message: format!("budget_committed_replay_conflict: {}", message.into()),
    }
}

fn committed_replay_budget_error(error: BudgetStoreError) -> AdmissionConsensusError {
    match error {
        BudgetStoreError::MissingCommittedReplay(message) => AdmissionConsensusError::Rejected {
            status_code: StatusCode::CONFLICT.as_u16(),
            message: format!("budget_committed_replay_missing: {message}"),
        },
        BudgetStoreError::Conflict(message)
        | BudgetStoreError::Overflow(message)
        | BudgetStoreError::Invariant(message) => committed_replay_conflict(message),
        BudgetStoreError::Sqlite(error) => AdmissionConsensusError::Storage(error),
        BudgetStoreError::Io(error) => AdmissionConsensusError::Protocol(error.to_string()),
    }
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

include!("part_02_tail.inc");
