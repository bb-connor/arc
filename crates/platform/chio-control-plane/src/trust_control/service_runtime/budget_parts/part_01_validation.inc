fn cached_remote_composite_hold(
    holds: &Arc<Mutex<HashMap<String, RemoteCompositeHoldEvidence>>>,
    hold_id: &str,
) -> Option<RemoteCompositeHoldEvidence> {
    match holds.lock() {
        Ok(holds) => holds.get(hold_id).cloned(),
        Err(poisoned) => poisoned.into_inner().get(hold_id).cloned(),
    }
}

fn remote_composite_hold_immutable_evidence_matches(
    left: &RemoteCompositeHoldEvidence,
    right: &RemoteCompositeHoldEvidence,
) -> bool {
    left.authorization_event_id == right.authorization_event_id
        && left.admission_operation == right.admission_operation
        && left.capability_id == right.capability_id
        && left.grant_index == right.grant_index
        && left.invocation_quotas == right.invocation_quotas
        && left.revocation_set == right.revocation_set
        && left.authorized_exposure_units == right.authorized_exposure_units
        && left.authority == right.authority
        && left.partition_escrow_evidence == right.partition_escrow_evidence
}

fn remote_composite_hold_mutable_state_matches(
    left: &RemoteCompositeHoldEvidence,
    right: &RemoteCompositeHoldEvidence,
) -> bool {
    left.invocation_counts_after == right.invocation_counts_after
        && left.invocation_state == right.invocation_state
        && left.remaining_exposure_units == right.remaining_exposure_units
        && left.monetary_state == right.monetary_state
}

fn next_remote_composite_event(
    cached: &RemoteCompositeHoldEvidence,
    decision: &BudgetHoldMutationDecision,
) -> Result<Option<(String, u64)>, BudgetStoreError> {
    let event_id = decision.metadata.event_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote composite mutation omitted its durable event identity".to_string(),
        )
    })?;
    let event_seq = decision.metadata.budget_commit_index.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote composite mutation omitted its durable event sequence".to_string(),
        )
    })?;
    if decision.metadata.authority.as_ref() != Some(&cached.authority)
        || decision.metadata.partition_escrow_evidence != cached.partition_escrow_evidence
        || decision.revocation_set.as_ref() != Some(&cached.revocation_set)
    {
        return Err(BudgetStoreError::Conflict(
            "remote composite mutation changed its immutable cached evidence".to_string(),
        ));
    }
    if event_seq < cached.last_event_seq {
        return Ok(None);
    }
    if event_seq == cached.last_event_seq {
        if event_id != cached.last_event_id
            || decision.invocation_counts_after != cached.invocation_counts_after
            || decision.invocation_state != cached.invocation_state
            || decision.monetary_state != cached.monetary_state
        {
            return Err(BudgetStoreError::Conflict(
                "remote composite mutation reused a durable sequence with different state"
                    .to_string(),
            ));
        }
        return Ok(None);
    }
    Ok(Some((event_id.to_string(), event_seq)))
}

fn finish_remote_composite_event(cached: &mut RemoteCompositeHoldEvidence, event: (String, u64)) {
    cached.last_event_id = event.0;
    cached.last_event_seq = event.1;
}

fn update_remote_composite_hold(
    holds: &Arc<Mutex<HashMap<String, RemoteCompositeHoldEvidence>>>,
    hold_id: &str,
    update: impl FnOnce(&mut RemoteCompositeHoldEvidence) -> Result<(), BudgetStoreError>,
) -> Result<(), BudgetStoreError> {
    let mut holds = match holds.lock() {
        Ok(holds) => holds,
        Err(poisoned) => poisoned.into_inner(),
    };
    let hold = holds.get_mut(hold_id).ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "remote composite hold `{hold_id}` disappeared from its exact cache"
        ))
    })?;
    update(hold)
}

fn validate_remote_composite_hold_cache(
    sealed_authority: Option<&SealedPartitionEscrowRemoteAuthority>,
    cached: &RemoteCompositeHoldEvidence,
) -> Result<(), BudgetStoreError> {
    if cached.authorization_event_id.is_empty()
        || cached.last_event_id.is_empty()
        || cached.last_event_seq == 0
        || cached.invocation_quotas.is_empty()
        || cached.invocation_quotas.len() != cached.invocation_counts_after.len()
        || cached.remaining_exposure_units > cached.authorized_exposure_units
    {
        return Err(BudgetStoreError::Invariant(
            "remote composite hold cache is incomplete or contradictory".to_string(),
        ));
    }
    for (quota, usage) in cached
        .invocation_quotas
        .iter()
        .zip(&cached.invocation_counts_after)
    {
        usage.validate()?;
        if quota != &usage.quota {
            return Err(BudgetStoreError::Invariant(
                "remote composite hold cache changed an ordered quota".to_string(),
            ));
        }
    }
    cached.revocation_set.validate().map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "remote composite hold cache has an invalid revocation set: {error}"
        ))
    })?;
    match (sealed_authority, cached.partition_escrow_evidence.as_ref()) {
        (Some(authority), Some(evidence)) => authority.validate_persisted_commit_evidence(evidence),
        (None, None) => Ok(()),
        (Some(_), None) => Err(BudgetStoreError::Invariant(
            "sealed remote composite hold cache omitted its partition escrow proof".to_string(),
        )),
        (None, Some(_)) => Err(BudgetStoreError::Invariant(
            "ordinary remote composite hold cache contains partition escrow evidence".to_string(),
        )),
    }
}

fn validate_exact_invocation_capture_transition(
    before: &[BudgetInvocationQuotaUsage],
    after: &[BudgetInvocationQuotaUsage],
) -> Result<(), BudgetStoreError> {
    if before.len() != after.len() {
        return Err(BudgetStoreError::Conflict(
            "remote invocation capture changed its ordered quota count".to_string(),
        ));
    }
    for (before, after) in before.iter().zip(after) {
        before.validate()?;
        after.validate()?;
        if before.quota != after.quota
            || before.reserved_invocations_after
                != after
                    .reserved_invocations_after
                    .checked_add(1)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "remote invocation capture reserved count overflowed u32".to_string(),
                        )
                    })?
            || after.captured_invocations_after
                != before
                    .captured_invocations_after
                    .checked_add(1)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "remote invocation capture captured count overflowed u32".to_string(),
                        )
                    })?
        {
            return Err(BudgetStoreError::Conflict(
                "remote invocation capture is not the exact cached quota transition".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_exact_invocation_reverse_transition(
    before: &[BudgetInvocationQuotaUsage],
    after: &[BudgetInvocationQuotaUsage],
) -> Result<(), BudgetStoreError> {
    if before.len() != after.len() {
        return Err(BudgetStoreError::Conflict(
            "remote invocation reverse changed its ordered quota count".to_string(),
        ));
    }
    for (before, after) in before.iter().zip(after) {
        before.validate()?;
        after.validate()?;
        if before.quota != after.quota
            || before.reserved_invocations_after
                != after
                    .reserved_invocations_after
                    .checked_add(1)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "remote invocation reverse reserved count overflowed u32".to_string(),
                        )
                    })?
            || after.captured_invocations_after != before.captured_invocations_after
        {
            return Err(BudgetStoreError::Conflict(
                "remote invocation reverse is not the exact cached quota transition".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_exact_remote_authorization_decision(
    record: &BudgetMutationRecord,
    decision: &BudgetAuthorizeHoldDecision,
    request: &CompositeBudgetAuthorizeRequest,
) -> Result<(), BudgetStoreError> {
    let admission_operation = BudgetAdmissionOperationBinding::new(
        request.operation_id.clone(),
        request.request_binding_hash.clone(),
    )?;
    let committed_cost_units_after = record
        .total_cost_exposed_after
        .checked_add(record.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "remote exact authorization committed cost overflowed u64".to_string(),
            )
        })?;
    let (
        allowed,
        hold_id,
        exposure_units,
        committed_cost,
        invocation_count,
        invocation_counts,
        invocation_state,
        monetary_state,
        revocation_set,
        metadata,
    ) = match decision {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => (
            true,
            authorized.hold_id.as_deref(),
            authorized.authorized_exposure_units,
            authorized.committed_cost_units_after,
            authorized.invocation_count_after,
            &authorized.invocation_counts_after,
            authorized.invocation_state,
            authorized.monetary_state,
            authorized.revocation_set.as_ref(),
            &authorized.metadata,
        ),
        BudgetAuthorizeHoldDecision::Denied(denied) => (
            false,
            denied.hold_id.as_deref(),
            denied.attempted_exposure_units,
            denied.committed_cost_units_after,
            denied.invocation_count_after,
            &denied.invocation_counts_after,
            denied.invocation_state,
            denied.monetary_state,
            denied.revocation_set.as_ref(),
            &denied.metadata,
        ),
    };
    let grant_index = u32::try_from(request.grant_index).map_err(|_| {
        BudgetStoreError::Invariant(
            "remote composite authorization grant index does not fit u32".to_string(),
        )
    })?;
    let expected_usage_seq = allowed.then_some(record.event_seq);
    if record.event_id != request.event_id
        || record.hold_id.as_deref() != Some(request.hold_id.as_str())
        || hold_id != Some(request.hold_id.as_str())
        || record.admission_operation.as_ref() != Some(&admission_operation)
        || record.capability_id != request.capability_id
        || record.grant_index != grant_index
        || record.kind != BudgetMutationKind::ReserveInvocations
        || record.allowed != Some(allowed)
        || record.usage_seq != expected_usage_seq
        || record.exposure_units != request.requested_exposure_units
        || exposure_units != request.requested_exposure_units
        || record.realized_spend_units != 0
        || record.max_invocations.is_some()
        || record.max_cost_per_invocation != request.max_exposure_per_invocation
        || record.max_total_cost_units != request.max_total_exposure_units
        || record.invocation_count_after != invocation_count
        || record.invocation_counts_after.as_slice() != invocation_counts.as_slice()
        || record.invocation_state != invocation_state
        || record.monetary_state != monetary_state
        || record.revocation_set.as_ref() != revocation_set
        || committed_cost_units_after != committed_cost
        || metadata.event_id.as_deref() != Some(record.event_id.as_str())
        || metadata.budget_commit_index != Some(record.event_seq)
        || metadata.authority.as_ref() != record.authority.as_ref()
    {
        return Err(BudgetStoreError::Conflict(
            "remote composite authorization response does not equal its quorum-attested durable event"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_exact_remote_mutation_decision(
    record: &BudgetMutationRecord,
    decision: &BudgetHoldMutationDecision,
    expected_kind: BudgetMutationKind,
    expected_admission_operation: Option<&BudgetAdmissionOperationBinding>,
) -> Result<(), BudgetStoreError> {
    let committed_cost_units_after = record
        .total_cost_exposed_after
        .checked_add(record.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "remote exact mutation committed cost overflowed u64".to_string(),
            )
        })?;
    if decision.metadata.event_id.as_deref() != Some(record.event_id.as_str())
        || decision.metadata.budget_commit_index != Some(record.event_seq)
        || decision.metadata.authority.as_ref() != record.authority.as_ref()
        || record.hold_id != decision.hold_id
        || record.admission_operation.as_ref() != expected_admission_operation
        || record.kind != expected_kind
        || record.allowed.is_some()
        || record.usage_seq != Some(record.event_seq)
        || record.exposure_units != decision.exposure_units
        || record.realized_spend_units != decision.realized_spend_units
        || record.max_invocations.is_some()
        || record.max_cost_per_invocation.is_some()
        || record.max_total_cost_units.is_some()
        || record.invocation_count_after != decision.invocation_count_after
        || record.invocation_counts_after != decision.invocation_counts_after
        || record.invocation_state != decision.invocation_state
        || record.monetary_state != decision.monetary_state
        || record.revocation_set != decision.revocation_set
        || committed_cost_units_after != decision.committed_cost_units_after
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation response does not equal its quorum-attested durable event".to_string(),
        ));
    }
    Ok(())
}

fn validate_remote_mutation_event_replica_response(
    authority: Option<&SealedPartitionEscrowRemoteAuthority>,
    configured_endpoints: &[String],
    expected_node_id: &str,
    request: &BudgetMutationEventQueryRequest,
    response: BudgetMutationEventReplicaResponse,
) -> Result<(String, BudgetMutationEventQueryView), BudgetStoreError> {
    if let Some(authority) = authority {
        let expected_signer = authority
            .member_public_key(expected_node_id)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "remote mutation event response signer is outside pinned membership"
                        .to_string(),
                )
            })?;
        response
            .verify_signature(expected_signer)
            .map_err(BudgetStoreError::Invariant)?;
    } else {
        // Ordinary HA authenticates the exact configured endpoint through HTTPS or
        // numeric-loopback transport with redirects disabled. This self-signature
        // protects envelope integrity but is not treated as pinned node attribution.
        response
            .verify_signature(&response.signer_public_key)
            .map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "ordinary transport-bound mutation response has an invalid envelope signature: {error}"
                ))
            })?;
    }
    let now = current_unix_seconds_for_partition_escrow()?;
    let response = response.body;
    if response.protocol_version != BUDGET_MUTATION_EVENT_QUERY_PROTOCOL_VERSION
        || response.consensus_protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || response.service != BUDGET_MUTATION_EVENT_QUERY_SERVICE
        || !remote_mutation_is_lower_sha256(&response.membership_digest)
        || authority.is_some_and(|authority| {
            response.membership_digest != authority.admission_membership_digest()
        })
        || response.node_id != expected_node_id
        || !configured_endpoints
            .iter()
            .any(|endpoint| endpoint == expected_node_id)
        || response.request_nonce != request.request_nonce
        || response.issued_at > now
        || response.expires_at <= now
        || response.expires_at.saturating_sub(response.issued_at)
            != BUDGET_MUTATION_EVENT_QUERY_MAX_TTL_SECS
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event response changed its signed service or membership binding"
                .to_string(),
        ));
    }
    let membership_digest = response.membership_digest;
    let query = response.query;
    let request_digest =
        budget_mutation_event_query_request_digest(request).map_err(BudgetStoreError::Invariant)?;
    if query.service_namespace != BUDGET_MUTATION_EVENT_QUERY_NAMESPACE
        || query.request_digest != request_digest
        || query.event_id != request.event_id
        || !remote_mutation_is_lower_sha256(&query.applied_state_digest)
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event response changed its signed request binding".to_string(),
        ));
    }
    validate_remote_mutation_read_barrier(
        authority,
        configured_endpoints,
        &membership_digest,
        &query,
    )?;
    match (
        query.mutation_event.as_ref(),
        query.command_kind,
        query.entry.as_ref(),
        query.result_commit_proof.as_ref(),
        query.result_commit_target.as_ref(),
        query.result.as_ref(),
        query.rejection.as_ref(),
        query.budget_authority.as_ref(),
        query.budget_commit.as_ref(),
    ) {
        (None, None, None, None, None, None, None, None, None) => {}
        (
            Some(event),
            Some(command_kind),
            Some(entry),
            Some(proof),
            Some(proof_target),
            Some(result),
            None,
            Some(budget_authority),
            Some(budget_commit),
        ) => {
            let record = super::super::cluster::budget_mutation_record_from_view(event)
                .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
            validate_remote_mutation_record_shape(&record)?;
            validate_remote_mutation_consensus_binding(
                authority,
                configured_endpoints,
                &membership_digest,
                request,
                &query,
                &record,
                command_kind,
                entry,
                proof,
                proof_target,
                result,
                budget_authority,
                budget_commit,
            )?;
        }
        (
            None,
            Some(AdmissionCommandKind::CompositeAuthorize),
            Some(entry),
            Some(proof),
            Some(proof_target),
            Some(result),
            Some(rejection),
            None,
            None,
        ) => {
            validate_remote_committed_mutation_rejection(
                authority,
                configured_endpoints,
                &membership_digest,
                request,
                &query,
                entry,
                proof,
                proof_target,
                result,
                rejection,
            )?;
        }
        (Some(_), None, None, None, None, None, None, None, None) => {
            if authority.is_some() {
                return Err(BudgetStoreError::Conflict(
                    "sealed remote mutation query returned an ordinary HA replication proof"
                        .to_string(),
                ));
            }
            let record = super::super::cluster::budget_mutation_record_from_view(
                query.mutation_event.as_ref().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "ordinary remote mutation query lost its mutation event".to_string(),
                    )
                })?,
            )
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
            validate_remote_mutation_record_shape(&record)?;
            if record.admission_operation.is_some() {
                return Err(BudgetStoreError::Conflict(
                    "ordinary replication proof cannot replace admission consensus ownership"
                        .to_string(),
                ));
            }
            validate_remote_mutation_record_authority(
                &record,
                configured_endpoints,
                RemoteMutationAuthorityLease::ReplicationTerm,
            )?;
        }
        _ => {
            return Err(BudgetStoreError::Conflict(
                "remote mutation event response contains partial proof evidence".to_string(),
            ));
        }
    }
    Ok((membership_digest, query))
}

fn validate_remote_mutation_read_barrier(
    authority: Option<&SealedPartitionEscrowRemoteAuthority>,
    configured_endpoints: &[String],
    membership_digest: &str,
    query: &BudgetMutationEventQueryView,
) -> Result<(), BudgetStoreError> {
    validate_remote_mutation_commit_proof(
        authority,
        configured_endpoints,
        membership_digest,
        &query.read_barrier,
    )?;
    if query.current_term == 0
        || !configured_endpoints
            .iter()
            .any(|endpoint| endpoint == &query.leader_id)
        || query.commit_index == 0
        || query.last_applied != query.commit_index
        || query.commit_index > query.last_log_index
        || query.last_log_term > query.current_term
        || query.read_barrier.index != query.commit_index
        || query.read_barrier.leader_epoch != query.current_term
        || query.read_barrier.current_term_commit_index != query.commit_index
        || query.read_barrier.leader_id != query.leader_id
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event response lacks a fully applied current-term read barrier"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_remote_mutation_commit_proof(
    authority: Option<&SealedPartitionEscrowRemoteAuthority>,
    configured_endpoints: &[String],
    membership_digest: &str,
    proof: &AdmissionCommitProof,
) -> Result<(), BudgetStoreError> {
    let quorum_size = configured_endpoints.len() / 2 + 1;
    let witnesses = proof.witness_urls.iter().collect::<BTreeSet<_>>();
    if proof.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || proof.membership_digest != membership_digest
        || proof.index == 0
        || proof.leader_epoch == 0
        || proof.current_term_commit_index < proof.index
        || proof.quorum_size != quorum_size
        || proof.witness_urls.len() < quorum_size
        || witnesses.len() != proof.witness_urls.len()
        || proof
            .witness_urls
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        || !proof
            .witness_urls
            .iter()
            .any(|witness| witness == &proof.leader_id)
        || proof.witness_urls.iter().any(|witness| {
            !configured_endpoints
                .iter()
                .any(|endpoint| endpoint == witness)
        })
        || authority.is_some_and(|authority| {
            proof
                .witness_urls
                .iter()
                .any(|witness| authority.member_public_key(witness).is_none())
        })
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event commit proof does not match pinned membership".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_remote_committed_mutation_rejection(
    authority: Option<&SealedPartitionEscrowRemoteAuthority>,
    configured_endpoints: &[String],
    membership_digest: &str,
    request: &BudgetMutationEventQueryRequest,
    query: &BudgetMutationEventQueryView,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    proof_target: &AdmissionLogEntry,
    result: &AdmissionConsensusResult,
    rejection: &CommittedCompositeAuthorizationRejectionView,
) -> Result<(), BudgetStoreError> {
    validate_remote_mutation_commit_proof(
        authority,
        configured_endpoints,
        membership_digest,
        proof,
    )?;
    validate_remote_mutation_entry(entry)?;
    validate_remote_mutation_entry(proof_target)?;
    let expected_operation_id = remote_mutation_scoped_operation_id(
        AdmissionCommandKind::CompositeAuthorize,
        &request.event_id,
    )?;
    if entry.command_kind != AdmissionCommandKind::CompositeAuthorize
        || entry.operation_id != expected_operation_id
        || entry.index != result.log_index
        || entry.index != proof.index
        || entry.leader_epoch > proof.leader_epoch
        || proof.current_term_commit_index < entry.index
        || proof.current_term_commit_index > query.commit_index
        || proof_target.index != proof.current_term_commit_index
        || proof_target.leader_epoch != proof.leader_epoch
        || result.operation_id != entry.operation_id
        || result.log_index > query.commit_index
        || result.log_index > query.last_applied
        || sha256_hex(result.response_json.as_bytes()) != result.response_digest
        || !remote_mutation_is_canonical_json(&result.response_json)
        || !remote_mutation_is_lower_sha256(&result.security_projection_digest)
        || StatusCode::from_u16(rejection.status_code).is_err()
        || rejection.code.is_empty()
    {
        return Err(BudgetStoreError::Conflict(
            "remote committed mutation rejection changed its consensus proof".to_string(),
        ));
    }
    let envelope = CommittedCompositeAuthorizationRejectionEnvelopeView {
        admission_consensus_rejection: rejection.clone(),
    };
    let canonical = canonical_json_bytes(&envelope).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "remote mutation rejection cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != result.response_json.as_bytes() {
        return Err(BudgetStoreError::Conflict(
            "remote committed mutation rejection differs from its exact result bytes".to_string(),
        ));
    }
    let command: ConsensusCompositeAuthorizeCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "remote rejected composite command cannot be decoded: {error}"
            ))
        })?;
    let expected_lease_id = format!(
        "{}#admission-term-{}",
        command.authority.authority_id, entry.leader_epoch
    );
    if command.request.existing_only
        || command.request.event_id != request.event_id
        || command.request.hold_id.is_empty()
        || command.authority.lease_epoch != entry.leader_epoch
        || command.authority.lease_id != expected_lease_id
        || !configured_endpoints
            .iter()
            .any(|endpoint| endpoint == &command.authority.authority_id)
    {
        return Err(BudgetStoreError::Conflict(
            "remote committed mutation rejection changed its typed command".to_string(),
        ));
    }
    let command_evidence = command
        .request
        .admission_evidence
        .partition_escrow_evidence
        .as_ref()
        .map(partition_escrow_commit_evidence_from_view)
        .transpose()?;
    match (authority, command_evidence) {
        (Some(authority), Some(evidence)) => {
            authority.validate_persisted_commit_evidence(&evidence)
        }
        (None, None) => Ok(()),
        (Some(_), None) => Err(BudgetStoreError::Conflict(
            "sealed committed mutation rejection omitted partition escrow evidence".to_string(),
        )),
        (None, Some(_)) => Err(BudgetStoreError::Conflict(
            "ordinary committed mutation rejection carried partition escrow evidence".to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_remote_mutation_consensus_binding(
    authority: Option<&SealedPartitionEscrowRemoteAuthority>,
    configured_endpoints: &[String],
    membership_digest: &str,
    request: &BudgetMutationEventQueryRequest,
    query: &BudgetMutationEventQueryView,
    record: &BudgetMutationRecord,
    command_kind: AdmissionCommandKind,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    proof_target: &AdmissionLogEntry,
    result: &AdmissionConsensusResult,
    budget_authority: &BudgetAuthorityMetadataView,
    budget_commit: &BudgetWriteCommitView,
) -> Result<(), BudgetStoreError> {
    validate_remote_mutation_commit_proof(
        authority,
        configured_endpoints,
        membership_digest,
        proof,
    )?;
    validate_remote_mutation_entry(entry)?;
    validate_remote_mutation_entry(proof_target)?;
    let expected_operation_id =
        remote_mutation_scoped_operation_id(command_kind, &request.event_id)?;
    if !remote_mutation_kind_allows_command(record.kind, command_kind)
        || entry.command_kind != command_kind
        || entry.operation_id != expected_operation_id
        || entry.index != result.log_index
        || entry.index != proof.index
        || entry.leader_epoch > proof.leader_epoch
        || proof.current_term_commit_index < entry.index
        || proof.current_term_commit_index > query.commit_index
        || proof_target.index != proof.current_term_commit_index
        || proof_target.leader_epoch != proof.leader_epoch
        || result.log_index > query.commit_index
        || result.log_index > query.last_applied
        || result.operation_id != entry.operation_id
        || sha256_hex(result.response_json.as_bytes()) != result.response_digest
        || !remote_mutation_is_canonical_json(&result.response_json)
        || !remote_mutation_is_lower_sha256(&result.security_projection_digest)
        || record.event_id != request.event_id
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event changed its admission result or commit proof".to_string(),
        ));
    }
    let record_authority = record.authority.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant("remote mutation event omitted its authority".to_string())
    })?;
    validate_remote_mutation_record_authority(
        record,
        configured_endpoints,
        RemoteMutationAuthorityLease::AdmissionTerm,
    )?;
    let command_authority = remote_mutation_command_authority(entry)?;
    if command_authority.authority_id != record_authority.authority_id
        || command_authority.lease_id != record_authority.lease_id
        || command_authority.lease_epoch != record_authority.lease_epoch
        || command_authority.lease_epoch != entry.leader_epoch
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event changed the authority bound into its admission command"
                .to_string(),
        ));
    }
    if command_kind == AdmissionCommandKind::CompositeAuthorize {
        validate_remote_composite_command_projection(
            record,
            entry,
            result,
            budget_authority,
            budget_commit,
        )?;
    }
    if budget_authority.authority_id != record_authority.authority_id
        || budget_authority.lease_id != record_authority.lease_id
        || budget_authority.lease_epoch != record_authority.lease_epoch
        || budget_authority.budget_term != record_authority.lease_epoch
        || budget_authority.leader_url != proof.leader_id
        || budget_authority.budget_commit_index != Some(proof.index)
        || budget_commit.budget_seq != record.event_seq
        || budget_commit.commit_index != proof.index
        || budget_commit.authority_id != record_authority.authority_id
        || budget_commit.lease_id != record_authority.lease_id
        || budget_commit.lease_epoch != record_authority.lease_epoch
        || budget_commit.budget_term != record_authority.lease_epoch
        || !budget_commit.quorum_committed
        || budget_commit.quorum_size != proof.quorum_size
        || budget_commit.committed_nodes != proof.witness_urls.len()
        || budget_commit.witness_urls != proof.witness_urls
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event changed its authority or quorum commit evidence".to_string(),
        ));
    }
    let evidence = partition_escrow_evidence_from_mutation_authority(budget_authority)?;
    match (
        authority,
        budget_authority.guarantee_level.as_str(),
        evidence,
    ) {
        (Some(authority), "partition_escrowed", Some(evidence)) => {
            authority.validate_persisted_commit_evidence(&evidence)
        }
        (None, "ha_linearizable", None) => Ok(()),
        (Some(_), _, _) => Err(BudgetStoreError::Conflict(
            "sealed remote mutation event changed or omitted its partition escrow proof"
                .to_string(),
        )),
        (None, _, _) => Err(BudgetStoreError::Conflict(
            "ordinary HA mutation event contains an invalid guarantee or escrow proof".to_string(),
        )),
    }
}

fn remote_mutation_scoped_operation_id(
    command_kind: AdmissionCommandKind,
    event_id: &str,
) -> Result<String, BudgetStoreError> {
    const DOMAIN: &[u8] = b"chio.admission-consensus-operation.v1\0";
    let label = match command_kind {
        AdmissionCommandKind::LeadershipBarrier => "leadership_barrier",
        AdmissionCommandKind::IncrementInvocation => "increment_invocation",
        AdmissionCommandKind::CompositeAuthorize => "composite_authorize",
        AdmissionCommandKind::CaptureInvocations => "capture_invocations",
        AdmissionCommandKind::ReverseExposure => "reverse_exposure",
        AdmissionCommandKind::ReleaseExposure => "release_exposure",
        AdmissionCommandKind::ReconcileSpend => "reconcile_spend",
        AdmissionCommandKind::CaptureExposure => "capture_exposure",
        AdmissionCommandKind::Revoke => "revoke",
        AdmissionCommandKind::CombinedCapture => "combined_capture",
    };
    let canonical = canonical_json_bytes(&json!({
        "commandKind": label,
        "operationId": event_id,
    }))
    .map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "remote mutation event operation scope cannot be canonicalized: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn remote_mutation_command_authority(
    entry: &AdmissionLogEntry,
) -> Result<BudgetMutationAuthorityView, BudgetStoreError> {
    let command: serde_json::Value =
        serde_json::from_str(&entry.canonical_command).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "remote mutation event admission command cannot be decoded: {error}"
            ))
        })?;
    let authority = match entry.command_kind {
        AdmissionCommandKind::CompositeAuthorize | AdmissionCommandKind::IncrementInvocation => {
            command.get("authority")
        }
        AdmissionCommandKind::CombinedCapture => command.pointer("/request/budgetAuthority"),
        AdmissionCommandKind::CaptureInvocations
        | AdmissionCommandKind::ReverseExposure
        | AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => command.get("budgetAuthority"),
        AdmissionCommandKind::LeadershipBarrier | AdmissionCommandKind::Revoke => None,
    }
    .ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote mutation event admission command omitted its budget authority".to_string(),
        )
    })?;
    serde_json::from_value(authority.clone()).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "remote mutation event admission command authority is invalid: {error}"
        ))
    })
}

fn validate_remote_composite_command_projection(
    record: &BudgetMutationRecord,
    entry: &AdmissionLogEntry,
    result: &AdmissionConsensusResult,
    budget_authority: &BudgetAuthorityMetadataView,
    budget_commit: &BudgetWriteCommitView,
) -> Result<(), BudgetStoreError> {
    let command: ConsensusCompositeAuthorizeCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "remote composite admission command cannot be decoded: {error}"
            ))
        })?;
    let response: CompositeBudgetAuthorizeResponse = serde_json::from_str(&result.response_json)
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "remote composite admission result cannot be decoded: {error}"
            ))
        })?;
    let admission_operation = BudgetAdmissionOperationBinding::new(
        command.request.operation_id.clone(),
        command.request.request_binding_hash.clone(),
    )?;
    let grant_index = usize::try_from(record.grant_index).map_err(|_| {
        BudgetStoreError::Invariant(
            "remote composite event grant index does not fit usize".to_string(),
        )
    })?;
    let expected_quotas = command
        .request
        .admission_evidence
        .invocation_quotas
        .iter()
        .map(invocation_quota_from_view)
        .collect::<Result<Vec<_>, _>>()?;
    let invocation_counts =
        quota_usages_from_views(&expected_quotas, response.invocation_counts_after.clone())?;
    let revocation_set =
        canonical_revocation_set_from_view(&response.admission_evidence.revocation_set)?;
    let committed_cost = record
        .total_cost_exposed_after
        .checked_add(record.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "remote composite event committed cost overflowed u64".to_string(),
            )
        })?;
    let admission_evidence_matches = remote_mutation_canonical_equal(
        &command.request.admission_evidence,
        &response.admission_evidence,
    )?;
    let response_authority = response.budget_authority.as_ref().ok_or_else(|| {
        BudgetStoreError::Conflict(
            "remote composite mutation result omitted its budget authority".to_string(),
        )
    })?;
    let response_commit = response.budget_commit.as_ref().ok_or_else(|| {
        BudgetStoreError::Conflict(
            "remote composite mutation result omitted its budget commit".to_string(),
        )
    })?;
    let authority_matches = remote_mutation_canonical_equal(response_authority, budget_authority)?;
    let commit_matches = remote_mutation_canonical_equal(response_commit, budget_commit)?;
    let proof_matches = remote_mutation_canonical_equal(
        &command.request.admission_evidence.partition_escrow_evidence,
        &budget_authority.partition_escrow_evidence,
    )?;
    let amount_shape_matches = if response.allowed {
        response.authorized_exposure_units == Some(record.exposure_units)
            && response.attempted_exposure_units.is_none()
    } else {
        response.attempted_exposure_units == Some(record.exposure_units)
            && response.authorized_exposure_units.is_none()
    };
    if command.request.existing_only
        || command.request.operation_id != response.operation_id
        || command.request.request_binding_hash != response.request_binding_hash
        || command.request.capability_id != response.capability_id
        || command.request.grant_index != response.grant_index
        || command.request.hold_id != response.hold_id
        || command.request.event_id != response.event_id
        || command.request.operation_id != admission_operation.operation_id()
        || command.request.request_binding_hash != admission_operation.request_binding_hash()
        || record.admission_operation.as_ref() != Some(&admission_operation)
        || record.capability_id != command.request.capability_id
        || grant_index != command.request.grant_index
        || record.hold_id.as_deref() != Some(command.request.hold_id.as_str())
        || record.event_id != command.request.event_id
        || record.exposure_units != command.request.requested_exposure_units
        || record.realized_spend_units != 0
        || record.max_invocations.is_some()
        || record.max_cost_per_invocation != command.request.max_exposure_per_invocation
        || record.max_total_cost_units != command.request.max_total_exposure_units
        || record.allowed != Some(response.allowed)
        || !amount_shape_matches
        || record.invocation_count_after != response.invocation_count_after
        || record.invocation_counts_after != invocation_counts
        || record.invocation_state != invocation_state_from_view(response.invocation_state)
        || record.monetary_state != monetary_state_from_view(response.monetary_state)
        || record.revocation_set.as_ref() != Some(&revocation_set)
        || response.committed_cost_units_after != committed_cost
        || !admission_evidence_matches
        || !authority_matches
        || !commit_matches
        || !proof_matches
    {
        return Err(BudgetStoreError::Conflict(
            "remote composite mutation event changed its typed command or result projection"
                .to_string(),
        ));
    }
    Ok(())
}

fn remote_mutation_canonical_equal<L: serde::Serialize, R: serde::Serialize>(
    left: &L,
    right: &R,
) -> Result<bool, BudgetStoreError> {
    let left = canonical_json_bytes(left).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "remote mutation projection cannot be canonicalized: {error}"
        ))
    })?;
    let right = canonical_json_bytes(right).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "remote mutation projection cannot be canonicalized: {error}"
        ))
    })?;
    Ok(left == right)
}

#[derive(Clone, Copy)]
enum RemoteMutationAuthorityLease {
    AdmissionTerm,
    ReplicationTerm,
}

fn validate_remote_mutation_record_authority(
    record: &BudgetMutationRecord,
    configured_endpoints: &[String],
    lease: RemoteMutationAuthorityLease,
) -> Result<(), BudgetStoreError> {
    let authority = record.authority.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant("remote mutation event omitted its authority".to_string())
    })?;
    let expected_lease_id = match lease {
        RemoteMutationAuthorityLease::AdmissionTerm => format!(
            "{}#admission-term-{}",
            authority.authority_id, authority.lease_epoch
        ),
        RemoteMutationAuthorityLease::ReplicationTerm => {
            format!("{}#term-{}", authority.authority_id, authority.lease_epoch)
        }
    };
    if authority.lease_epoch == 0
        || authority.lease_id != expected_lease_id
        || !configured_endpoints
            .iter()
            .any(|endpoint| endpoint == &authority.authority_id)
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event authority is outside configured membership".to_string(),
        ));
    }
    Ok(())
}

fn validate_remote_mutation_entry(entry: &AdmissionLogEntry) -> Result<(), BudgetStoreError> {
    if entry.index == 0
        || entry.leader_epoch == 0
        || !remote_mutation_is_lower_sha256(&entry.command_digest)
        || sha256_hex(entry.canonical_command.as_bytes()) != entry.command_digest
        || !remote_mutation_is_canonical_json(&entry.canonical_command)
    {
        return Err(BudgetStoreError::Conflict(
            "remote mutation event admission entry is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_remote_mutation_record_shape(
    record: &BudgetMutationRecord,
) -> Result<(), BudgetStoreError> {
    let committed_cost = record
        .total_cost_exposed_after
        .checked_add(record.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "remote mutation event committed cost overflowed u64".to_string(),
            )
        })?;
    let _ = committed_cost;
    let expected_usage_seq = match record.allowed {
        Some(false) => None,
        Some(true) | None => Some(record.event_seq),
    };
    let allowed_shape_matches = match record.kind {
        BudgetMutationKind::IncrementInvocation
        | BudgetMutationKind::AuthorizeExposure
        | BudgetMutationKind::ReserveInvocations => record.allowed.is_some(),
        BudgetMutationKind::CaptureInvocations
        | BudgetMutationKind::ReverseInvocations
        | BudgetMutationKind::ReverseExposure
        | BudgetMutationKind::ReleaseExposure
        | BudgetMutationKind::ReconcileSpend
        | BudgetMutationKind::CaptureExposure
        | BudgetMutationKind::ExpireHold => record.allowed.is_none(),
    };
    if record.event_id.is_empty()
        || record.event_seq == 0
        || record.usage_seq != expected_usage_seq
        || !allowed_shape_matches
        || record.authority.is_none()
    {
        return Err(BudgetStoreError::Invariant(
            "remote mutation event is missing its durable identity or sequence".to_string(),
        ));
    }
    match record.admission_operation.as_ref() {
        Some(_) => {
            let hold_id = record.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "operation-owned remote mutation event omitted hold_id".to_string(),
                )
            })?;
            if hold_id.is_empty()
                || record.invocation_counts_after.is_empty()
                || record.revocation_set.is_none()
            {
                return Err(BudgetStoreError::Invariant(
                    "operation-owned remote mutation event omitted its frozen composite state"
                        .to_string(),
                ));
            }
            let primary_key = BudgetQuotaKey::grant(
                &record.capability_id,
                usize::try_from(record.grant_index).map_err(|_| {
                    BudgetStoreError::Invariant(
                        "remote mutation event grant index does not fit usize".to_string(),
                    )
                })?,
            )?;
            let primary_count = record
                .invocation_counts_after
                .iter()
                .find(|usage| usage.quota.key() == &primary_key)
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "remote mutation event omitted its primary frozen quota".to_string(),
                    )
                })?
                .invocation_count_after()?;
            if primary_count != record.invocation_count_after {
                return Err(BudgetStoreError::Invariant(
                    "remote mutation event primary quota diverged from invocation_count_after"
                        .to_string(),
                ));
            }
        }
        None => {
            if !record.invocation_counts_after.is_empty() || record.revocation_set.is_some() {
                return Err(BudgetStoreError::Invariant(
                    "ordinary remote mutation event contains composite frozen state".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn remote_mutation_kind_allows_command(
    kind: BudgetMutationKind,
    command_kind: AdmissionCommandKind,
) -> bool {
    match kind {
        BudgetMutationKind::IncrementInvocation => {
            command_kind == AdmissionCommandKind::IncrementInvocation
        }
        BudgetMutationKind::ReserveInvocations | BudgetMutationKind::AuthorizeExposure => {
            command_kind == AdmissionCommandKind::CompositeAuthorize
        }
        BudgetMutationKind::CaptureInvocations => matches!(
            command_kind,
            AdmissionCommandKind::CombinedCapture | AdmissionCommandKind::CaptureInvocations
        ),
        BudgetMutationKind::ReverseInvocations | BudgetMutationKind::ReverseExposure => {
            command_kind == AdmissionCommandKind::ReverseExposure
        }
        BudgetMutationKind::ReleaseExposure => {
            command_kind == AdmissionCommandKind::ReleaseExposure
        }
        BudgetMutationKind::ReconcileSpend => command_kind == AdmissionCommandKind::ReconcileSpend,
        BudgetMutationKind::CaptureExposure => {
            command_kind == AdmissionCommandKind::CaptureExposure
        }
        BudgetMutationKind::ExpireHold => false,
    }
}

fn partition_escrow_evidence_from_mutation_query(
    query: &BudgetMutationEventQueryView,
) -> Result<Option<PartitionEscrowCommitEvidence>, BudgetStoreError> {
    query
        .budget_authority
        .as_ref()
        .map(partition_escrow_evidence_from_mutation_authority)
        .transpose()
        .map(Option::flatten)
}

fn partition_escrow_evidence_from_mutation_authority(
    authority: &BudgetAuthorityMetadataView,
) -> Result<Option<PartitionEscrowCommitEvidence>, BudgetStoreError> {
    authority
        .partition_escrow_evidence
        .as_ref()
        .map(|evidence| {
            PartitionEscrowCommitEvidence::from_canonical_json(
                evidence.canonical_json.clone(),
                evidence.digest.clone(),
            )
        })
        .transpose()
}

fn remote_mutation_is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn remote_mutation_is_canonical_json(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .and_then(|parsed| canonical_json_bytes(&parsed).ok())
        .is_some_and(|canonical| canonical == value.as_bytes())
}

fn admission_evidence_view(
    evidence: BudgetInvocationAdmissionEvidence<'_>,
) -> Result<BudgetInvocationAdmissionEvidenceView, BudgetStoreError> {
    let supplemental_binding = match (
        evidence.supplemental_artifact_digest(),
        evidence.supplemental_verifier_id(),
        evidence.supplemental_request_binding_hash(),
        evidence.supplemental_negotiated_features_digest(),
        evidence.supplemental_issuer(),
        evidence.supplemental_not_before(),
        evidence.supplemental_expires_at(),
        evidence.supplemental_request_constraint_digest(),
        evidence.supplemental_broker_capability_id(),
        evidence.supplemental_claim_binding_digest(),
        evidence.supplemental_verified_at(),
    ) {
        (None, None, None, None, None, None, None, None, None, None, None) => None,
        (
            Some(artifact_digest),
            Some(verifier_id),
            Some(request_binding_hash),
            Some(negotiated_features_digest),
            Some(issuer),
            Some(not_before),
            Some(expires_at),
            Some(request_constraint_digest),
            Some(broker_capability_id),
            Some(claim_binding_digest),
            Some(verified_at),
        ) => Some(BudgetSupplementalQuotaBindingView {
            artifact_digest: artifact_digest.to_string(),
            verifier_id: verifier_id.to_string(),
            request_binding_hash: request_binding_hash.to_string(),
            negotiated_features_digest: negotiated_features_digest.to_string(),
            issuer: issuer.clone(),
            not_before,
            expires_at,
            request_constraint_digest: request_constraint_digest.to_string(),
            broker_capability_id: broker_capability_id.to_string(),
            claim_binding_digest: claim_binding_digest.to_string(),
            verified_at,
        }),
        _ => {
            return Err(BudgetStoreError::Invariant(
                "kernel supplemental admission evidence is incomplete".to_string(),
            ));
        }
    };
    let partition_escrow_evidence = evidence
        .partition_escrow_evidence()
        .map(
            |escrow| -> Result<BudgetPartitionEscrowEvidenceView, BudgetStoreError> {
            let canonical_json = String::from_utf8(escrow.canonical_bytes().map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "partition escrow admission evidence encoding failed: {error}"
                ))
            })?)
            .map_err(|_| {
                BudgetStoreError::Invariant(
                    "partition escrow admission evidence is not UTF-8".to_string(),
                )
            })?;
            let digest = escrow.digest().map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "partition escrow admission evidence digest failed: {error}"
                ))
            })?;
            Ok(BudgetPartitionEscrowEvidenceView {
                canonical_json,
                digest,
            })
        },
        )
        .transpose()?;
    Ok(BudgetInvocationAdmissionEvidenceView {
        invocation_quotas: evidence
            .quotas()
            .iter()
            .map(invocation_quota_view)
            .collect(),
        revocation_set: canonical_revocation_set_view(evidence.revocation_set()),
        aggregate_root_capability_id: evidence
            .aggregate_root_capability_id()
            .map(ToOwned::to_owned),
        aggregate_binding_digest: evidence.aggregate_binding_digest().map(ToOwned::to_owned),
        supplemental_binding,
        partition_escrow_evidence,
    })
}

fn quota_profile_view(profile: BudgetQuotaProfile) -> BudgetQuotaProfileView {
    match profile {
        BudgetQuotaProfile::GrantInvocation => BudgetQuotaProfileView::GrantInvocation,
        BudgetQuotaProfile::AggregateCapabilityInvocation => {
            BudgetQuotaProfileView::AggregateCapabilityInvocation
        }
        BudgetQuotaProfile::AggregateFamilyInvocation => {
            BudgetQuotaProfileView::AggregateFamilyInvocation
        }
        BudgetQuotaProfile::SupplementalBrokerExecution => {
            BudgetQuotaProfileView::SupplementalBrokerExecution
        }
    }
}

fn quota_profile_from_view(profile: BudgetQuotaProfileView) -> BudgetQuotaProfile {
    match profile {
        BudgetQuotaProfileView::GrantInvocation => BudgetQuotaProfile::GrantInvocation,
        BudgetQuotaProfileView::AggregateCapabilityInvocation => {
            BudgetQuotaProfile::AggregateCapabilityInvocation
        }
        BudgetQuotaProfileView::AggregateFamilyInvocation => {
            BudgetQuotaProfile::AggregateFamilyInvocation
        }
        BudgetQuotaProfileView::SupplementalBrokerExecution => {
            BudgetQuotaProfile::SupplementalBrokerExecution
        }
    }
}

pub(crate) fn invocation_quota_view(quota: &BudgetInvocationQuota) -> BudgetInvocationQuotaView {
    BudgetInvocationQuotaView {
        key: BudgetQuotaKeyView {
            profile: quota_profile_view(quota.key().profile()),
            owner_id: quota.key().owner_id().to_string(),
            grant_index: quota.key().grant_index(),
        },
        max_invocations: quota.max_invocations(),
    }
}

pub(crate) fn invocation_quota_from_view(
    quota: &BudgetInvocationQuotaView,
) -> Result<BudgetInvocationQuota, BudgetStoreError> {
    let key = BudgetQuotaKey::from_persisted_parts(
        quota_profile_from_view(quota.key.profile),
        quota.key.owner_id.clone(),
        quota.key.grant_index,
    )?;
    BudgetInvocationQuota::from_persisted_parts(key, quota.max_invocations)
}

pub(crate) fn canonical_revocation_set_view(
    set: &CanonicalRevocationSet,
) -> CanonicalRevocationSetView {
    CanonicalRevocationSetView {
        ids: set.ids().to_vec(),
        digest: set.digest().to_string(),
    }
}

pub(crate) fn canonical_revocation_set_from_view(
    set: &CanonicalRevocationSetView,
) -> Result<CanonicalRevocationSet, BudgetStoreError> {
    CanonicalRevocationSet::from_persisted_parts(set.ids.clone(), set.digest.clone()).map_err(
        |error| {
            BudgetStoreError::Invariant(format!(
                "remote response contains an invalid canonical revocation set: {error}"
            ))
        },
    )
}

pub(crate) fn admission_capture_request_from_view(
    request: &CombinedAdmissionCaptureRequest,
) -> Result<AdmissionCaptureRequest, AdmissionCaptureError> {
    let authority = request.budget_authority.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture request omitted persisted authority".to_string(),
        )
    })?;
    if authority.authority_id.is_empty()
        || authority.lease_id.is_empty()
        || authority.lease_epoch == 0
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture request contains incomplete persisted authority".to_string(),
        ));
    }
    let revocation_set = canonical_revocation_set_from_view(&request.revocation_set)?;
    AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
        operation_id: request.operation_id.clone(),
        budget: BudgetCaptureInvocationRequest {
            admission_operation: Some(BudgetAdmissionOperationBinding::new(
                request.operation_id.clone(),
                request.request_binding_hash.clone(),
            )?),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: Some(request.hold_id.clone()),
            event_id: Some(request.event_id.clone()),
            authority: Some(BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
        },
        revocation_set,
        bound_revocation_set_digest: request.bound_revocation_set_digest.clone(),
        authorization_artifact_digests: request.authorization_artifact_digests.clone(),
        aggregate_root_capability_id: request.aggregate_root_capability_id.clone(),
        aggregate_root_binding_digest: request.aggregate_root_binding_digest.clone(),
        last_observed_revocation_index: request.last_observed_revocation_index,
    })
}
