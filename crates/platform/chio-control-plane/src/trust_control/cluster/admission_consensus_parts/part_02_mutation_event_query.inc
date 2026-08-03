fn query_budget_mutation_event_replica(
    config: &TrustServiceConfig,
    membership: &AdmissionMembership,
    node_id: &str,
    request: &BudgetMutationEventQueryRequest,
) -> Result<BudgetMutationEventReplicaResponse, AdmissionConsensusError> {
    if uuid::Uuid::parse_str(&request.request_nonce)
        .ok()
        .is_none_or(|nonce| nonce.get_version_num() != 4)
        || request.event_id.is_empty()
        || request.event_id.len() > 512
        || request.event_id.bytes().any(|byte| byte == 0)
    {
        return Err(committed_replay_conflict(
            "budget mutation event query identity is invalid",
        ));
    }
    if let Some(authority) = config.partition_escrow_authority.as_deref() {
        authority
            .verify_persisted_configuration()
            .map_err(committed_replay_budget_error)?;
        if authority.admission_membership_digest() != membership.digest() {
            return Err(committed_replay_conflict(
                "sealed partition escrow descriptor changed the admission membership digest",
            ));
        }
    }

    let path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "budget mutation event query requires a budget database".to_string(),
        )
    })?;
    let budget_store = SqliteBudgetStore::open_existing_read_only(path)
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
    let mutation_record = budget_store
        .get_mutation_event_by_id(&request.event_id)
        .map_err(committed_replay_budget_error)?;

    let consensus_store = configured_admission_consensus_store_read_only(config)?;
    consensus_store.validate_membership_proofs(membership)?;
    let (
        meta,
        read_barrier,
        command_kind,
        entry,
        result_commit_proof,
        result_commit_target,
        result,
    ) = if let Some(record) = mutation_record.as_ref() {
        let mut matched = None;
        for command_kind in mutation_event_candidate_command_kinds(record.kind)
            .iter()
            .copied()
        {
            let scoped = scoped_operation_id(command_kind, &request.event_id)?;
            let snapshot = consensus_store.committed_operation_snapshot(&scoped)?;
            if snapshot.entry.is_some() || snapshot.result.is_some() {
                if matched.is_some() {
                    return Err(committed_replay_conflict(
                        "budget mutation event collides across admission command namespaces",
                    ));
                }
                matched = Some((command_kind, snapshot));
            }
        }
        match matched {
            Some((command_kind, snapshot)) => (
                snapshot.meta,
                snapshot.read_barrier,
                Some(command_kind),
                snapshot.entry,
                snapshot.result_commit_proof,
                snapshot.result_commit_target,
                snapshot.result,
            ),
            None if record.admission_operation.is_none()
                && config.partition_escrow_authority.is_none() =>
            {
                let probe = scoped_operation_id(
                    AdmissionCommandKind::CompositeAuthorize,
                    &request.event_id,
                )?;
                let snapshot = consensus_store.committed_operation_snapshot(&probe)?;
                (
                    snapshot.meta,
                    snapshot.read_barrier,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            }
            None => {
                return Err(committed_replay_conflict(
                    "operation-owned budget mutation event has no exact consensus operation",
                ));
            }
        }
    } else {
        let probe =
            scoped_operation_id(AdmissionCommandKind::CompositeAuthorize, &request.event_id)?;
        let snapshot = consensus_store.committed_operation_snapshot(&probe)?;
        match (snapshot.entry.as_ref(), snapshot.result.as_ref()) {
            (None, None) => (
                snapshot.meta,
                snapshot.read_barrier,
                None,
                None,
                None,
                None,
                None,
            ),
            (Some(_), Some(_)) => (
                snapshot.meta,
                snapshot.read_barrier,
                Some(AdmissionCommandKind::CompositeAuthorize),
                snapshot.entry,
                snapshot.result_commit_proof,
                snapshot.result_commit_target,
                snapshot.result,
            ),
            _ => {
                return Err(committed_replay_conflict(
                    "budget mutation event query found a partial committed rejection",
                ));
            }
        }
    };
    let leader_id = meta.voted_for.clone().ok_or_else(|| {
        committed_replay_conflict("budget mutation event read barrier has no current leader")
    })?;
    let read_barrier = read_barrier.ok_or_else(|| {
        committed_replay_conflict("budget mutation event query has no current-term read barrier")
    })?;
    validate_committed_composite_read_barrier(membership, &meta, &leader_id, &read_barrier)?;

    let (mutation_event, budget_authority, budget_commit, rejection) = match (
        mutation_record,
        command_kind,
        entry.as_ref(),
        result_commit_proof.as_ref(),
        result_commit_target.as_ref(),
        result.as_ref(),
    ) {
        (None, None, None, None, None, None) => (None, None, None, None),
        (Some(record), None, None, None, None, None) => {
            validate_replicated_budget_mutation_record(membership, &record)?;
            (
                Some(super::budget_mutation_event_view(record)),
                None,
                None,
                None,
            )
        }
        (
            Some(record),
            Some(command_kind),
            Some(entry),
            Some(proof),
            Some(proof_target),
            Some(result),
        ) => {
            validate_budget_mutation_query_result(
                membership,
                command_kind,
                &request.event_id,
                meta.commit_index,
                meta.last_applied,
                entry,
                proof,
                proof_target,
                result,
            )?;
            let projection = budget_mutation_result_projection(command_kind, result)?;
            validate_budget_mutation_command_projection(
                membership,
                command_kind,
                entry,
                &record,
                &projection,
            )?;
            validate_budget_mutation_projection(
                config,
                &budget_store,
                &record,
                proof,
                &projection,
            )?;
            (
                Some(super::budget_mutation_event_view(record)),
                Some(projection.authority),
                Some(projection.commit),
                None,
            )
        }
        (
            None,
            Some(AdmissionCommandKind::CompositeAuthorize),
            Some(entry),
            Some(proof),
            Some(proof_target),
            Some(result),
        ) => {
            validate_budget_mutation_query_result(
                membership,
                AdmissionCommandKind::CompositeAuthorize,
                &request.event_id,
                meta.commit_index,
                meta.last_applied,
                entry,
                proof,
                proof_target,
                result,
            )?;
            let command: ConsensusCompositeAuthorizeCommand =
                serde_json::from_str(&entry.canonical_command)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let rejection = committed_authorization_rejection(result)?.ok_or_else(|| {
                committed_replay_conflict(
                    "committed composite authorization has no durable decision or typed rejection",
                )
            })?;
            if command.request.existing_only
                || command.request.event_id != request.event_id
                || command.request.hold_id.is_empty()
                || command.authority.lease_epoch != entry.leader_epoch
                || command.authority.lease_id
                    != format!(
                        "{}#admission-term-{}",
                        command.authority.authority_id, entry.leader_epoch
                    )
                || !membership.contains(&command.authority.authority_id)
            {
                return Err(committed_replay_conflict(
                    "committed composite authorization rejection changed its typed command",
                ));
            }
            let command_evidence = command
                .request
                .admission_evidence
                .partition_escrow_evidence
                .as_ref()
                .map(|evidence| {
                    PartitionEscrowCommitEvidence::from_canonical_json(
                        evidence.canonical_json.clone(),
                        evidence.digest.clone(),
                    )
                    .map_err(committed_replay_budget_error)
                })
                .transpose()?;
            match (
                config.partition_escrow_authority.as_deref(),
                command_evidence.as_ref(),
            ) {
                (Some(authority), Some(evidence)) => authority
                    .validate_persisted_commit_evidence(evidence)
                    .map_err(committed_replay_budget_error)?,
                (None, None) => {}
                (Some(_), None) => {
                    return Err(committed_replay_conflict(
                        "sealed committed rejection omitted partition escrow evidence",
                    ));
                }
                (None, Some(_)) => {
                    return Err(committed_replay_conflict(
                        "ordinary committed rejection carried partition escrow evidence",
                    ));
                }
            }
            (None, None, None, Some(rejection))
        }
        _ => {
            return Err(committed_replay_conflict(
                "budget mutation event query contains partial durable consensus evidence",
            ));
        }
    };

    let issued_at = unix_timestamp_now();
    let expires_at = issued_at
        .checked_add(BUDGET_MUTATION_EVENT_QUERY_MAX_TTL_SECS)
        .ok_or_else(|| {
            committed_replay_conflict("budget mutation event response expiry overflowed")
        })?;
    let seed_path = config.cluster_node_seed_path.as_deref().ok_or_else(|| {
        committed_replay_conflict("budget mutation event response signer is not configured")
    })?;
    let keypair = load_strict_cluster_node_keypair(seed_path)
        .map_err(|error| committed_replay_conflict(error.to_string()))?;
    let expected_signer = committed_replay_member_public_key(config, node_id)?;
    if keypair.public_key() != expected_signer {
        return Err(committed_replay_conflict(
            "budget mutation event signer does not match pinned membership",
        ));
    }
    let body = BudgetMutationEventReplicaResponseBody {
        protocol_version: BUDGET_MUTATION_EVENT_QUERY_PROTOCOL_VERSION.to_string(),
        consensus_protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        service: BUDGET_MUTATION_EVENT_QUERY_SERVICE.to_string(),
        membership_digest: membership.digest().to_string(),
        node_id: node_id.to_string(),
        request_nonce: request.request_nonce.clone(),
        issued_at,
        expires_at,
        query: BudgetMutationEventQueryView {
            service_namespace: BUDGET_MUTATION_EVENT_QUERY_NAMESPACE.to_string(),
            request_digest: budget_mutation_event_query_request_digest(request)
                .map_err(committed_replay_conflict)?,
            event_id: request.event_id.clone(),
            current_term: meta.current_term,
            leader_id,
            last_log_index: meta.last_log_index,
            last_log_term: meta.last_log_term,
            commit_index: meta.commit_index,
            last_applied: meta.last_applied,
            applied_state_digest: meta.applied_state_digest,
            read_barrier,
            command_kind,
            entry,
            result_commit_proof,
            result_commit_target,
            result,
            rejection,
            mutation_event,
            budget_authority,
            budget_commit,
        },
    };
    BudgetMutationEventReplicaResponse::sign(body, &keypair).map_err(committed_replay_conflict)
}

fn mutation_event_candidate_command_kinds(
    kind: BudgetMutationKind,
) -> &'static [AdmissionCommandKind] {
    match kind {
        BudgetMutationKind::IncrementInvocation => &[AdmissionCommandKind::IncrementInvocation],
        BudgetMutationKind::ReserveInvocations | BudgetMutationKind::AuthorizeExposure => {
            &[AdmissionCommandKind::CompositeAuthorize]
        }
        BudgetMutationKind::CaptureInvocations => &[
            AdmissionCommandKind::CombinedCapture,
            AdmissionCommandKind::CaptureInvocations,
        ],
        BudgetMutationKind::ReverseInvocations | BudgetMutationKind::ReverseExposure => {
            &[AdmissionCommandKind::ReverseExposure]
        }
        BudgetMutationKind::ReleaseExposure => &[AdmissionCommandKind::ReleaseExposure],
        BudgetMutationKind::ReconcileSpend => &[AdmissionCommandKind::ReconcileSpend],
        BudgetMutationKind::CaptureExposure => &[AdmissionCommandKind::CaptureExposure],
        BudgetMutationKind::ExpireHold => &[],
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_budget_mutation_query_result(
    membership: &AdmissionMembership,
    command_kind: AdmissionCommandKind,
    event_id: &str,
    commit_index: u64,
    last_applied: u64,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    proof_target: &AdmissionLogEntry,
    result: &AdmissionConsensusResult,
) -> Result<(), AdmissionConsensusError> {
    let scoped = scoped_operation_id(command_kind, event_id)?;
    validate_entry(entry)?;
    validate_entry(proof_target)?;
    validate_commit_proof_for_membership(proof, membership)?;
    if entry.command_kind != command_kind
        || entry.operation_id != scoped
        || result.operation_id != scoped
        || entry.index != result.log_index
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
            "budget mutation result changed its scoped entry, proof, or commit watermark",
        ));
    }
    validate_canonical_json(&result.response_json, "budget mutation event result")
}

struct BudgetMutationResultProjection {
    operation_id: Option<String>,
    request_binding_hash: Option<String>,
    capability_id: String,
    grant_index: usize,
    hold_id: Option<String>,
    event_id: Option<String>,
    allowed: Option<bool>,
    mutation_exposure_units: Option<u64>,
    reported_reduction_units: Option<u64>,
    invocation_count_after: u32,
    committed_cost_units_after: Option<u64>,
    total_cost_exposed_after: Option<u64>,
    total_cost_realized_spend_after: Option<u64>,
    admission_evidence: Option<BudgetInvocationAdmissionEvidenceView>,
    authority: BudgetAuthorityMetadataView,
    commit: BudgetWriteCommitView,
}

fn budget_mutation_result_projection(
    command_kind: AdmissionCommandKind,
    result: &AdmissionConsensusResult,
) -> Result<BudgetMutationResultProjection, AdmissionConsensusError> {
    let missing =
        || committed_replay_conflict("budget mutation result omitted authority or commit evidence");
    match command_kind {
        AdmissionCommandKind::IncrementInvocation => {
            let response: TryIncrementBudgetResponse = serde_json::from_str(&result.response_json)
                .map_err(|error| committed_replay_conflict(error.to_string()))?;
            Ok(BudgetMutationResultProjection {
                operation_id: None,
                request_binding_hash: None,
                capability_id: response.capability_id,
                grant_index: response.grant_index,
                hold_id: None,
                event_id: None,
                allowed: Some(response.allowed),
                mutation_exposure_units: None,
                reported_reduction_units: None,
                invocation_count_after: response.invocation_count.ok_or_else(missing)?,
                committed_cost_units_after: None,
                total_cost_exposed_after: None,
                total_cost_realized_spend_after: None,
                admission_evidence: None,
                authority: response.budget_authority.ok_or_else(missing)?,
                commit: response.budget_commit.ok_or_else(missing)?,
            })
        }
        AdmissionCommandKind::CompositeAuthorize => {
            let response: CompositeBudgetAuthorizeResponse =
                serde_json::from_str(&result.response_json)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let mutation_exposure_units = match (
                response.allowed,
                response.authorized_exposure_units,
                response.attempted_exposure_units,
            ) {
                (true, Some(exposure_units), None) | (false, None, Some(exposure_units)) => {
                    exposure_units
                }
                _ => {
                    return Err(committed_replay_conflict(
                        "composite authorization result changed its exposure decision shape",
                    ));
                }
            };
            Ok(BudgetMutationResultProjection {
                operation_id: Some(response.operation_id),
                request_binding_hash: Some(response.request_binding_hash),
                capability_id: response.capability_id,
                grant_index: response.grant_index,
                hold_id: Some(response.hold_id),
                event_id: Some(response.event_id),
                allowed: Some(response.allowed),
                mutation_exposure_units: Some(mutation_exposure_units),
                reported_reduction_units: None,
                invocation_count_after: response.invocation_count_after,
                committed_cost_units_after: Some(response.committed_cost_units_after),
                total_cost_exposed_after: None,
                total_cost_realized_spend_after: None,
                admission_evidence: Some(response.admission_evidence),
                authority: response.budget_authority.ok_or_else(missing)?,
                commit: response.budget_commit.ok_or_else(missing)?,
            })
        }
        AdmissionCommandKind::CaptureInvocations => {
            let response: CaptureInvocationReservationsResponse =
                serde_json::from_str(&result.response_json)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            Ok(BudgetMutationResultProjection {
                operation_id: Some(response.operation_id),
                request_binding_hash: Some(response.request_binding_hash),
                capability_id: response.capability_id,
                grant_index: response.grant_index,
                hold_id: Some(response.hold_id),
                event_id: Some(response.event_id),
                allowed: None,
                mutation_exposure_units: Some(response.exposure_units),
                reported_reduction_units: None,
                invocation_count_after: response.invocation_count_after,
                committed_cost_units_after: Some(response.committed_cost_units_after),
                total_cost_exposed_after: None,
                total_cost_realized_spend_after: None,
                admission_evidence: None,
                authority: response.budget_authority.ok_or_else(missing)?,
                commit: response.budget_commit.ok_or_else(missing)?,
            })
        }
        AdmissionCommandKind::ReverseExposure => {
            let response: ReverseChargeCostResponse =
                serde_json::from_str(&result.response_json)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let exposed = response.total_cost_exposed.ok_or_else(missing)?;
            let realized = response.total_cost_realized_spend.ok_or_else(missing)?;
            Ok(BudgetMutationResultProjection {
                operation_id: None,
                request_binding_hash: None,
                capability_id: response.capability_id,
                grant_index: response.grant_index,
                hold_id: None,
                event_id: None,
                allowed: None,
                mutation_exposure_units: None,
                reported_reduction_units: None,
                invocation_count_after: response.invocation_count.ok_or_else(missing)?,
                committed_cost_units_after: Some(exposed.checked_add(realized).ok_or_else(
                    || {
                        committed_replay_conflict(
                            "budget mutation result committed cost overflowed",
                        )
                    },
                )?),
                total_cost_exposed_after: Some(exposed),
                total_cost_realized_spend_after: Some(realized),
                admission_evidence: None,
                authority: response.budget_authority.ok_or_else(missing)?,
                commit: response.budget_commit.ok_or_else(missing)?,
            })
        }
        AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => {
            let response: ReduceChargeCostResponse = serde_json::from_str(&result.response_json)
                .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let exposed = response.total_cost_exposed.ok_or_else(missing)?;
            let realized = response.total_cost_realized_spend.ok_or_else(missing)?;
            let reduced = response.released_exposure_units.ok_or_else(missing)?;
            Ok(BudgetMutationResultProjection {
                operation_id: None,
                request_binding_hash: None,
                capability_id: response.capability_id,
                grant_index: response.grant_index,
                hold_id: None,
                event_id: None,
                allowed: None,
                mutation_exposure_units: (command_kind == AdmissionCommandKind::ReleaseExposure)
                    .then_some(reduced),
                reported_reduction_units: Some(reduced),
                invocation_count_after: response.invocation_count.ok_or_else(missing)?,
                committed_cost_units_after: Some(exposed.checked_add(realized).ok_or_else(
                    || {
                        committed_replay_conflict(
                            "budget mutation result committed cost overflowed",
                        )
                    },
                )?),
                total_cost_exposed_after: Some(exposed),
                total_cost_realized_spend_after: Some(realized),
                admission_evidence: None,
                authority: response.budget_authority.ok_or_else(missing)?,
                commit: response.budget_commit.ok_or_else(missing)?,
            })
        }
        AdmissionCommandKind::CombinedCapture => {
            let response: CombinedAdmissionCaptureResponse =
                serde_json::from_str(&result.response_json)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let budget = response.budget.ok_or_else(missing)?;
            let budget_authority = budget.budget_authority.ok_or_else(missing)?;
            let capture_authority = response.metadata.authority.as_ref().ok_or_else(missing)?;
            if budget.operation_id != response.operation_id
                || budget.request_binding_hash != response.request_binding_hash
                || budget.capability_id != response.capability_id
                || budget.grant_index != response.grant_index
                || budget.hold_id != response.hold_id
                || budget.event_id != response.event_id
                || response.metadata.operation_id != response.operation_id
                || response.metadata.hold_id != response.hold_id
                || response.metadata.event_id != response.event_id
                || capture_authority.authority_id != budget_authority.authority_id
                || capture_authority.lease_id != budget_authority.lease_id
                || capture_authority.lease_epoch != budget_authority.lease_epoch
                || response.metadata.partition_escrow_evidence
                    != budget_authority.partition_escrow_evidence
            {
                return Err(committed_replay_conflict(
                    "combined capture result changed its nested budget identity or authority",
                ));
            }
            Ok(BudgetMutationResultProjection {
                operation_id: Some(response.operation_id),
                request_binding_hash: Some(response.request_binding_hash),
                capability_id: budget.capability_id,
                grant_index: budget.grant_index,
                hold_id: Some(response.hold_id),
                event_id: Some(budget.event_id),
                allowed: None,
                mutation_exposure_units: Some(budget.exposure_units),
                reported_reduction_units: None,
                invocation_count_after: budget.invocation_count_after,
                committed_cost_units_after: Some(budget.committed_cost_units_after),
                total_cost_exposed_after: None,
                total_cost_realized_spend_after: None,
                admission_evidence: None,
                authority: budget_authority,
                commit: budget.budget_commit.ok_or_else(missing)?,
            })
        }
        AdmissionCommandKind::LeadershipBarrier | AdmissionCommandKind::Revoke => {
            Err(committed_replay_conflict(
                "non-budget admission command cannot own a budget mutation event",
            ))
        }
    }
}

fn validate_budget_mutation_command_projection(
    membership: &AdmissionMembership,
    command_kind: AdmissionCommandKind,
    entry: &AdmissionLogEntry,
    record: &BudgetMutationRecord,
    projection: &BudgetMutationResultProjection,
) -> Result<(), AdmissionConsensusError> {
    match command_kind {
        AdmissionCommandKind::IncrementInvocation => {
            let command: ConsensusIncrementInvocationCommand =
                serde_json::from_str(&entry.canonical_command)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            if command.request.capability_id != record.capability_id
                || command.request.grant_index != record.grant_index as usize
                || command.request.max_invocations != record.max_invocations
                || record.hold_id.is_some()
                || record.admission_operation.is_some()
                || record.exposure_units != 0
                || record.realized_spend_units != 0
                || record.max_cost_per_invocation.is_some()
                || record.max_total_cost_units.is_some()
            {
                return Err(committed_replay_conflict(
                    "invocation increment command changed its persisted event projection",
                ));
            }
            validate_budget_mutation_command_authority(
                membership,
                entry,
                record,
                projection,
                &command.authority,
            )
        }
        AdmissionCommandKind::CompositeAuthorize => {
            let command: ConsensusCompositeAuthorizeCommand =
                serde_json::from_str(&entry.canonical_command)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            validate_admission_owned_budget_command_identity(
                record,
                &command.request.operation_id,
                &command.request.request_binding_hash,
                &command.request.capability_id,
                command.request.grant_index,
                &command.request.hold_id,
                &command.request.event_id,
            )?;
            validate_projected_admission_budget_identity(
                projection,
                &command.request.operation_id,
                &command.request.request_binding_hash,
                &command.request.hold_id,
                &command.request.event_id,
            )?;
            if command.request.existing_only
                || command.request.requested_exposure_units != record.exposure_units
                || command.request.max_exposure_per_invocation != record.max_cost_per_invocation
                || command.request.max_total_exposure_units != record.max_total_cost_units
                || record.realized_spend_units != 0
                || projection.admission_evidence.as_ref()
                    != Some(&command.request.admission_evidence)
                || command
                    .request
                    .admission_evidence
                    .partition_escrow_evidence
                    .as_ref()
                    != projection.authority.partition_escrow_evidence.as_ref()
            {
                return Err(committed_replay_conflict(
                    "composite authorization command changed its persisted identity or admission evidence",
                ));
            }
            validate_budget_mutation_command_authority(
                membership,
                entry,
                record,
                projection,
                &command.authority,
            )
        }
        AdmissionCommandKind::CaptureInvocations => {
            let command: CaptureInvocationReservationsRequest =
                serde_json::from_str(&entry.canonical_command)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            validate_admission_owned_budget_command_identity(
                record,
                &command.operation_id,
                &command.request_binding_hash,
                &command.capability_id,
                command.grant_index,
                &command.hold_id,
                &command.event_id,
            )?;
            validate_projected_admission_budget_identity(
                projection,
                &command.operation_id,
                &command.request_binding_hash,
                &command.hold_id,
                &command.event_id,
            )?;
            if record.exposure_units != 0
                || record.realized_spend_units != 0
                || record.max_invocations.is_some()
                || record.max_cost_per_invocation.is_some()
                || record.max_total_cost_units.is_some()
            {
                return Err(committed_replay_conflict(
                    "invocation capture command changed its persisted mutation shape",
                ));
            }
            let authority = command.budget_authority.as_ref().ok_or_else(|| {
                committed_replay_conflict(
                    "invocation capture command omitted its persisted authority",
                )
            })?;
            validate_budget_mutation_command_authority(
                membership, entry, record, projection, authority,
            )
        }
        AdmissionCommandKind::ReverseExposure => {
            let command: ReverseChargeCostRequest = serde_json::from_str(&entry.canonical_command)
                .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let (operation_id, request_binding_hash, hold_id, event_id, authority) =
                required_terminal_budget_command_identity(
                    command.operation_id.as_deref(),
                    command.request_binding_hash.as_deref(),
                    command.hold_id.as_deref(),
                    command.event_id.as_deref(),
                    command.budget_authority.as_ref(),
                )?;
            validate_admission_owned_budget_command_identity(
                record,
                operation_id,
                request_binding_hash,
                &command.capability_id,
                command.grant_index,
                hold_id,
                event_id,
            )?;
            if command.cost_units != record.exposure_units
                || record.realized_spend_units != 0
                || record.max_invocations.is_some()
                || record.max_cost_per_invocation.is_some()
                || record.max_total_cost_units.is_some()
            {
                return Err(committed_replay_conflict(
                    "reverse exposure command changed its persisted mutation shape",
                ));
            }
            validate_budget_mutation_command_authority(
                membership, entry, record, projection, authority,
            )
        }
        AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => {
            let command: ReduceChargeCostRequest =
                serde_json::from_str(&entry.canonical_command)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            let (operation_id, request_binding_hash, hold_id, event_id, authority) =
                required_terminal_budget_command_identity(
                    command.operation_id.as_deref(),
                    command.request_binding_hash.as_deref(),
                    command.hold_id.as_deref(),
                    command.event_id.as_deref(),
                    command.budget_authority.as_ref(),
                )?;
            validate_admission_owned_budget_command_identity(
                record,
                operation_id,
                request_binding_hash,
                &command.capability_id,
                command.grant_index,
                hold_id,
                event_id,
            )?;
            let amounts_match = match command_kind {
                AdmissionCommandKind::ReleaseExposure => {
                    command.exposure_units.is_none()
                        && command.realized_spend_units.is_none()
                        && command.cost_units == record.exposure_units
                        && record.realized_spend_units == 0
                }
                AdmissionCommandKind::ReconcileSpend | AdmissionCommandKind::CaptureExposure => {
                    command
                        .exposure_units
                        .zip(command.realized_spend_units)
                        .is_some_and(|(exposure_units, realized_spend_units)| {
                            exposure_units == record.exposure_units
                                && realized_spend_units == record.realized_spend_units
                                && exposure_units.checked_sub(realized_spend_units)
                                    == Some(command.cost_units)
                        })
                }
                _ => false,
            };
            if !amounts_match
                || projection.reported_reduction_units != Some(command.cost_units)
                || record.max_invocations.is_some()
                || record.max_cost_per_invocation.is_some()
                || record.max_total_cost_units.is_some()
            {
                return Err(committed_replay_conflict(
                    "monetary transition command changed its persisted mutation shape",
                ));
            }
            validate_budget_mutation_command_authority(
                membership, entry, record, projection, authority,
            )
        }
        AdmissionCommandKind::CombinedCapture => {
            let command: ConsensusCombinedCaptureCommand =
                serde_json::from_str(&entry.canonical_command)
                    .map_err(|error| committed_replay_conflict(error.to_string()))?;
            validate_admission_owned_budget_command_identity(
                record,
                &command.request.operation_id,
                &command.request.request_binding_hash,
                &command.request.capability_id,
                command.request.grant_index,
                &command.request.hold_id,
                &command.request.event_id,
            )?;
            validate_projected_admission_budget_identity(
                projection,
                &command.request.operation_id,
                &command.request.request_binding_hash,
                &command.request.hold_id,
                &command.request.event_id,
            )?;
            if record.exposure_units != 0
                || record.realized_spend_units != 0
                || record.max_invocations.is_some()
                || record.max_cost_per_invocation.is_some()
                || record.max_total_cost_units.is_some()
            {
                return Err(committed_replay_conflict(
                    "combined capture command changed its persisted mutation shape",
                ));
            }
            let authority = command.request.budget_authority.as_ref().ok_or_else(|| {
                committed_replay_conflict(
                    "combined capture command omitted its persisted authority",
                )
            })?;
            validate_budget_mutation_command_authority(
                membership, entry, record, projection, authority,
            )
        }
        AdmissionCommandKind::LeadershipBarrier | AdmissionCommandKind::Revoke => {
            Err(committed_replay_conflict(
                "non-budget admission command cannot project a budget mutation event",
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_admission_owned_budget_command_identity(
    record: &BudgetMutationRecord,
    operation_id: &str,
    request_binding_hash: &str,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    event_id: &str,
) -> Result<(), AdmissionConsensusError> {
    let admission_operation = record.admission_operation.as_ref().ok_or_else(|| {
        committed_replay_conflict("admission-owned budget event omitted operation ownership")
    })?;
    if admission_operation.operation_id() != operation_id
        || admission_operation.request_binding_hash() != request_binding_hash
        || record.capability_id != capability_id
        || record.grant_index as usize != grant_index
        || record.hold_id.as_deref() != Some(hold_id)
        || record.event_id != event_id
    {
        return Err(committed_replay_conflict(
            "admission command identity diverges from its persisted budget event",
        ));
    }
    Ok(())
}

fn validate_projected_admission_budget_identity(
    projection: &BudgetMutationResultProjection,
    operation_id: &str,
    request_binding_hash: &str,
    hold_id: &str,
    event_id: &str,
) -> Result<(), AdmissionConsensusError> {
    if projection.operation_id.as_deref() != Some(operation_id)
        || projection.request_binding_hash.as_deref() != Some(request_binding_hash)
        || projection.hold_id.as_deref() != Some(hold_id)
        || projection.event_id.as_deref() != Some(event_id)
    {
        return Err(committed_replay_conflict(
            "admission result identity diverges from its committed command",
        ));
    }
    Ok(())
}

type RequiredTerminalBudgetCommandIdentity<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a BudgetMutationAuthorityView,
);

fn required_terminal_budget_command_identity<'a>(
    operation_id: Option<&'a str>,
    request_binding_hash: Option<&'a str>,
    hold_id: Option<&'a str>,
    event_id: Option<&'a str>,
    authority: Option<&'a BudgetMutationAuthorityView>,
) -> Result<RequiredTerminalBudgetCommandIdentity<'a>, AdmissionConsensusError> {
    operation_id
        .zip(request_binding_hash)
        .zip(hold_id)
        .zip(event_id)
        .zip(authority)
        .map(
            |((((operation_id, request_binding_hash), hold_id), event_id), authority)| {
                (
                    operation_id,
                    request_binding_hash,
                    hold_id,
                    event_id,
                    authority,
                )
            },
        )
        .ok_or_else(|| {
            committed_replay_conflict(
                "terminal budget command omitted operation, hold, event, or authority identity",
            )
        })
}

fn validate_budget_mutation_command_authority(
    membership: &AdmissionMembership,
    entry: &AdmissionLogEntry,
    record: &BudgetMutationRecord,
    projection: &BudgetMutationResultProjection,
    command_authority: &BudgetMutationAuthorityView,
) -> Result<(), AdmissionConsensusError> {
    let expected_lease_id = format!(
        "{}#admission-term-{}",
        command_authority.authority_id, entry.leader_epoch
    );
    let event_authority =
        budget_authority_from_view(command_authority).map_err(committed_replay_conflict)?;
    if command_authority.lease_epoch != entry.leader_epoch
        || command_authority.lease_id != expected_lease_id
        || !membership.contains(&command_authority.authority_id)
        || record.authority.as_ref() != Some(&event_authority)
        || projection.authority.authority_id != command_authority.authority_id
        || projection.authority.lease_id != command_authority.lease_id
        || projection.authority.lease_epoch != command_authority.lease_epoch
        || projection.authority.budget_term != command_authority.lease_epoch
        || projection.authority.lease_expires_at != u64::MAX
        || projection.authority.lease_ttl_ms != u64::MAX
        || projection.commit.authority_id != command_authority.authority_id
        || projection.commit.lease_id != command_authority.lease_id
        || projection.commit.lease_epoch != command_authority.lease_epoch
        || projection.commit.budget_term != command_authority.lease_epoch
    {
        return Err(committed_replay_conflict(
            "budget mutation command authority diverges from its entry term, membership, event, or result",
        ));
    }
    Ok(())
}

fn validate_budget_mutation_projection(
    config: &TrustServiceConfig,
    budget_store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
    proof: &AdmissionCommitProof,
    projection: &BudgetMutationResultProjection,
) -> Result<(), AdmissionConsensusError> {
    let record_authority = record.authority.as_ref().ok_or_else(|| {
        committed_replay_conflict("budget mutation event omitted its persisted authority")
    })?;
    let committed_cost = record
        .total_cost_exposed_after
        .checked_add(record.total_cost_realized_spend_after)
        .ok_or_else(|| committed_replay_conflict("budget mutation committed cost overflowed"))?;
    if projection
        .operation_id
        .as_deref()
        .is_some_and(|operation_id| {
            record
                .admission_operation
                .as_ref()
                .is_none_or(|binding| binding.operation_id() != operation_id)
        })
        || projection
            .request_binding_hash
            .as_deref()
            .is_some_and(|request_binding_hash| {
                record
                    .admission_operation
                    .as_ref()
                    .is_none_or(|binding| binding.request_binding_hash() != request_binding_hash)
            })
        || projection.capability_id != record.capability_id
        || projection.grant_index != record.grant_index as usize
        || projection
            .hold_id
            .as_deref()
            .is_some_and(|hold_id| record.hold_id.as_deref() != Some(hold_id))
        || projection
            .event_id
            .as_deref()
            .is_some_and(|event_id| event_id != record.event_id)
        || projection
            .allowed
            .is_some_and(|allowed| record.allowed != Some(allowed))
        || projection
            .mutation_exposure_units
            .is_some_and(|exposure_units| exposure_units != record.exposure_units)
        || projection.invocation_count_after != record.invocation_count_after
        || projection
            .committed_cost_units_after
            .is_some_and(|value| value != committed_cost)
        || projection
            .total_cost_exposed_after
            .is_some_and(|value| value != record.total_cost_exposed_after)
        || projection
            .total_cost_realized_spend_after
            .is_some_and(|value| value != record.total_cost_realized_spend_after)
        || projection.authority.authority_id != record_authority.authority_id
        || projection.authority.lease_id != record_authority.lease_id
        || projection.authority.lease_epoch != record_authority.lease_epoch
        || projection.authority.budget_term != record_authority.lease_epoch
        || projection.authority.leader_url != proof.leader_id
        || projection.authority.budget_commit_index != Some(proof.index)
        || projection.commit.budget_seq != record.event_seq
        || projection.commit.commit_index != proof.index
        || projection.commit.authority_id != record_authority.authority_id
        || projection.commit.lease_id != record_authority.lease_id
        || projection.commit.lease_epoch != record_authority.lease_epoch
        || projection.commit.budget_term != record_authority.lease_epoch
        || !projection.commit.quorum_committed
        || projection.commit.quorum_size != proof.quorum_size
        || projection.commit.committed_nodes != proof.witness_urls.len()
        || projection.commit.witness_urls != proof.witness_urls
    {
        return Err(committed_replay_conflict(
            "budget mutation event diverges from its exact consensus result or authority proof",
        ));
    }

    match config.partition_escrow_authority.as_deref() {
        None => {
            if projection.authority.guarantee_level != "ha_linearizable"
                || projection.authority.partition_escrow_evidence.is_some()
            {
                return Err(committed_replay_conflict(
                    "ordinary HA mutation event contains partition escrow evidence",
                ));
            }
        }
        Some(authority) => {
            let view = projection
                .authority
                .partition_escrow_evidence
                .as_ref()
                .ok_or_else(|| {
                    committed_replay_conflict(
                        "partition-escrowed mutation event omitted its signed allocation proof",
                    )
                })?;
            let evidence = PartitionEscrowCommitEvidence::from_canonical_json(
                view.canonical_json.clone(),
                view.digest.clone(),
            )
            .map_err(committed_replay_budget_error)?;
            authority
                .validate_persisted_commit_evidence(&evidence)
                .map_err(committed_replay_budget_error)?;
            let hold_id = record.hold_id.as_deref().ok_or_else(|| {
                committed_replay_conflict(
                    "partition-escrowed mutation event omitted its bound hold id",
                )
            })?;
            let persisted = budget_store
                .query_partition_escrow_evidence_for_hold(hold_id)
                .map_err(committed_replay_budget_error)?
                .ok_or_else(|| {
                    committed_replay_conflict(
                        "partition-escrowed mutation event has no persisted allocation proof",
                    )
                })?;
            if projection.authority.guarantee_level != "partition_escrowed" || evidence != persisted
            {
                return Err(committed_replay_conflict(
                    "partition-escrowed mutation event changed its persisted allocation proof",
                ));
            }
        }
    }
    Ok(())
}

fn validate_replicated_budget_mutation_record(
    membership: &AdmissionMembership,
    record: &BudgetMutationRecord,
) -> Result<(), AdmissionConsensusError> {
    let authority = record.authority.as_ref().ok_or_else(|| {
        committed_replay_conflict("replicated budget mutation event omitted its authority")
    })?;
    let expected_lease_id = format!("{}#term-{}", authority.authority_id, authority.lease_epoch);
    if record.admission_operation.is_some()
        || !record.invocation_counts_after.is_empty()
        || record.revocation_set.is_some()
        || record.event_seq == 0
        || record.usage_seq != Some(record.event_seq)
        || authority.lease_epoch == 0
        || authority.lease_id != expected_lease_id
        || !membership.contains(&authority.authority_id)
        || record
            .total_cost_exposed_after
            .checked_add(record.total_cost_realized_spend_after)
            .is_none()
    {
        return Err(committed_replay_conflict(
            "replicated budget mutation event is not a complete ordinary HA event",
        ));
    }
    Ok(())
}
