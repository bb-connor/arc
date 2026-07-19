fn invocation_state_from_view(
    state: BudgetInvocationReservationStateView,
) -> BudgetInvocationReservationState {
    match state {
        BudgetInvocationReservationStateView::Absent => BudgetInvocationReservationState::Absent,
        BudgetInvocationReservationStateView::Authorized => {
            BudgetInvocationReservationState::Authorized
        }
        BudgetInvocationReservationStateView::Captured => {
            BudgetInvocationReservationState::Captured
        }
        BudgetInvocationReservationStateView::Reversed => {
            BudgetInvocationReservationState::Reversed
        }
        BudgetInvocationReservationStateView::Denied => BudgetInvocationReservationState::Denied,
    }
}

fn monetary_state_from_view(state: BudgetMonetaryHoldStateView) -> BudgetMonetaryHoldState {
    match state {
        BudgetMonetaryHoldStateView::None => BudgetMonetaryHoldState::None,
        BudgetMonetaryHoldStateView::Exposed => BudgetMonetaryHoldState::Exposed,
        BudgetMonetaryHoldStateView::Released => BudgetMonetaryHoldState::Released,
        BudgetMonetaryHoldStateView::Reconciled => BudgetMonetaryHoldState::Reconciled,
        BudgetMonetaryHoldStateView::Captured => BudgetMonetaryHoldState::Captured,
        BudgetMonetaryHoldStateView::Reversed => BudgetMonetaryHoldState::Reversed,
    }
}

fn quota_usages_from_views(
    expected_quotas: &[BudgetInvocationQuota],
    usages: Vec<BudgetInvocationQuotaUsageView>,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    if usages.len() != expected_quotas.len() {
        return Err(BudgetStoreError::Invariant(
            "remote response changed the ordered invocation quota count".to_string(),
        ));
    }
    usages
        .into_iter()
        .zip(expected_quotas)
        .map(|(usage, expected)| {
            let quota = invocation_quota_from_view(&usage.quota)?;
            if &quota != expected {
                return Err(BudgetStoreError::Invariant(
                    "remote response changed an ordered invocation quota key or maximum"
                        .to_string(),
                ));
            }
            let usage = BudgetInvocationQuotaUsage {
                quota,
                reserved_invocations_after: usage.reserved_invocations_after,
                captured_invocations_after: usage.captured_invocations_after,
            };
            usage.validate()?;
            Ok(usage)
        })
        .collect()
}

fn validate_primary_invocation_count(
    capability_id: &str,
    grant_index: usize,
    reported_count: u32,
    usages: &[BudgetInvocationQuotaUsage],
) -> Result<(), BudgetStoreError> {
    let primary_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
    let actual = usages
        .iter()
        .find(|usage| usage.quota.key() == &primary_key)
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote response omitted the primary grant invocation quota".to_string(),
            )
        })?
        .invocation_count_after()?;
    if actual != reported_count {
        return Err(BudgetStoreError::Invariant(
            "remote response primary quota count does not match invocation_count_after".to_string(),
        ));
    }
    Ok(())
}

fn validate_remote_composite_evidence(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
    requested_authority: Option<&BudgetEventAuthority>,
) -> Result<ValidatedRemoteBudgetEvidence, BudgetStoreError> {
    if authority.is_none_or(|authority| authority.guarantee_level != "ha_linearizable")
        || commit.is_none()
    {
        return Err(BudgetStoreError::Invariant(
            "remote composite budget response is not HA-linearizable".to_string(),
        ));
    }
    let evidence = validate_remote_budget_evidence(authority, commit, requested_authority)?;
    if evidence.guarantee_level != BudgetGuaranteeLevel::HaLinearizable
        || evidence.authority.is_none()
        || evidence.commit_index.is_none()
    {
        return Err(BudgetStoreError::Invariant(
            "remote composite budget response is not HA-linearizable".to_string(),
        ));
    }
    Ok(evidence)
}

pub(crate) fn validate_composite_authorize_response(
    request: &CompositeBudgetAuthorizeRequest,
    response: CompositeBudgetAuthorizeResponse,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    if response.capability_id != request.capability_id
        || response.operation_id != request.operation_id
        || response.request_binding_hash != request.request_binding_hash
        || response.grant_index != request.grant_index
        || response.hold_id != request.hold_id
        || response.event_id != request.event_id
    {
        return Err(BudgetStoreError::Invariant(
            "remote composite authorization response identity does not match the request"
                .to_string(),
        ));
    }
    if response.admission_evidence != request.admission_evidence {
        return Err(BudgetStoreError::Invariant(
            "remote composite authorization response changed the admission evidence".to_string(),
        ));
    }
    let expected_quotas = request
        .admission_evidence
        .invocation_quotas
        .iter()
        .map(invocation_quota_from_view)
        .collect::<Result<Vec<_>, _>>()?;
    let invocation_counts_after =
        quota_usages_from_views(&expected_quotas, response.invocation_counts_after)?;
    validate_primary_invocation_count(
        &request.capability_id,
        request.grant_index,
        response.invocation_count_after,
        &invocation_counts_after,
    )?;
    let revocation_set =
        canonical_revocation_set_from_view(&response.admission_evidence.revocation_set)?;
    if revocation_set
        .ids()
        .binary_search(&request.capability_id)
        .is_err()
    {
        return Err(BudgetStoreError::Invariant(
            "remote composite authorization revocation set omits the leaf capability".to_string(),
        ));
    }
    let evidence = validate_remote_composite_evidence(
        response.budget_authority.as_ref(),
        response.budget_commit.as_ref(),
        None,
    )?;
    let invocation_state = invocation_state_from_view(response.invocation_state);
    let monetary_state = monetary_state_from_view(response.monetary_state);
    let monetary_present = request.requested_exposure_units > 0
        || request.max_exposure_per_invocation.is_some()
        || request.max_total_exposure_units.is_some();
    let expected_invocation_state = if response.allowed {
        BudgetInvocationReservationState::Authorized
    } else {
        BudgetInvocationReservationState::Denied
    };
    let expected_monetary_state = if response.allowed && monetary_present {
        BudgetMonetaryHoldState::Exposed
    } else {
        BudgetMonetaryHoldState::None
    };
    if invocation_state != expected_invocation_state || monetary_state != expected_monetary_state {
        return Err(BudgetStoreError::Invariant(
            "remote composite authorization response contains contradictory hold substates"
                .to_string(),
        ));
    }
    let amounts_match = if response.allowed {
        response.authorized_exposure_units == Some(request.requested_exposure_units)
            && response.attempted_exposure_units.is_none()
    } else {
        response.attempted_exposure_units == Some(request.requested_exposure_units)
            && response.authorized_exposure_units.is_none()
    };
    if !amounts_match {
        return Err(BudgetStoreError::Invariant(
            "remote composite authorization response contains contradictory exposure amounts"
                .to_string(),
        ));
    }
    let metadata = BudgetCommitMetadata {
        authority: evidence.authority,
        guarantee_level: evidence.guarantee_level,
        budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
        metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
        budget_commit_index: evidence.commit_index,
        event_id: Some(response.event_id),
    };
    if response.allowed {
        Ok(BudgetAuthorizeHoldDecision::Authorized(
            AuthorizedBudgetHold {
                hold_id: Some(response.hold_id),
                authorized_exposure_units: response
                    .authorized_exposure_units
                    .unwrap_or(request.requested_exposure_units),
                committed_cost_units_after: response.committed_cost_units_after,
                invocation_count_after: response.invocation_count_after,
                invocation_counts_after,
                invocation_state,
                monetary_state,
                revocation_set: Some(revocation_set),
                metadata,
            },
        ))
    } else {
        Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
            hold_id: Some(response.hold_id),
            attempted_exposure_units: response
                .attempted_exposure_units
                .unwrap_or(request.requested_exposure_units),
            committed_cost_units_after: response.committed_cost_units_after,
            invocation_count_after: response.invocation_count_after,
            invocation_counts_after,
            invocation_state,
            monetary_state,
            revocation_set: Some(revocation_set),
            metadata,
        }))
    }
}

pub(crate) fn validate_invocation_capture_response(
    request: &BudgetCaptureInvocationRequest,
    expected_quotas: &[BudgetInvocationQuota],
    expected_revocation_set: &CanonicalRevocationSet,
    expected_monetary_state: BudgetMonetaryHoldState,
    response: CaptureInvocationReservationsResponse,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    let hold_id = request.hold_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("remote invocation capture requires hold_id".to_string())
    })?;
    let event_id = request.event_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("remote invocation capture requires event_id".to_string())
    })?;
    let admission_operation = request.admission_operation.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote invocation capture requires admission operation ownership".to_string(),
        )
    })?;
    if response.capability_id != request.capability_id
        || response.operation_id != admission_operation.operation_id()
        || response.request_binding_hash != admission_operation.request_binding_hash()
        || response.grant_index != request.grant_index
        || response.hold_id != hold_id
        || response.event_id != event_id
    {
        return Err(BudgetStoreError::Invariant(
            "remote invocation capture response identity does not match the request".to_string(),
        ));
    }
    if response.exposure_units != 0 || response.realized_spend_units != 0 {
        return Err(BudgetStoreError::Invariant(
            "remote invocation capture response changed monetary amounts".to_string(),
        ));
    }
    let invocation_counts_after =
        quota_usages_from_views(expected_quotas, response.invocation_counts_after)?;
    validate_primary_invocation_count(
        &request.capability_id,
        request.grant_index,
        response.invocation_count_after,
        &invocation_counts_after,
    )?;
    let revocation_set = canonical_revocation_set_from_view(&response.revocation_set)?;
    if &revocation_set != expected_revocation_set {
        return Err(BudgetStoreError::Invariant(
            "remote invocation capture response changed the canonical revocation set".to_string(),
        ));
    }
    let invocation_state = invocation_state_from_view(response.invocation_state);
    let monetary_state = monetary_state_from_view(response.monetary_state);
    if invocation_state != BudgetInvocationReservationState::Captured
        || monetary_state != expected_monetary_state
    {
        return Err(BudgetStoreError::Invariant(
            "remote invocation capture response contains contradictory hold substates".to_string(),
        ));
    }
    let evidence = validate_remote_composite_evidence(
        response.budget_authority.as_ref(),
        response.budget_commit.as_ref(),
        request.authority.as_ref(),
    )?;
    Ok(BudgetHoldMutationDecision {
        hold_id: Some(response.hold_id),
        exposure_units: response.exposure_units,
        realized_spend_units: response.realized_spend_units,
        committed_cost_units_after: response.committed_cost_units_after,
        invocation_count_after: response.invocation_count_after,
        invocation_counts_after,
        invocation_state,
        monetary_state,
        revocation_set: Some(revocation_set),
        metadata: BudgetCommitMetadata {
            authority: evidence.authority,
            guarantee_level: evidence.guarantee_level,
            budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: evidence.commit_index,
            event_id: Some(response.event_id),
        },
    })
}

pub(crate) fn validate_remote_admission_capture_response(
    request: &AdmissionCaptureRequest,
    response: CombinedAdmissionCaptureResponse,
) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
    let budget_request = request.budget();
    let hold_id = budget_request.hold_id.as_deref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture request omitted hold_id".to_string(),
        )
    })?;
    let event_id = budget_request.event_id.as_deref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture request omitted event_id".to_string(),
        )
    })?;
    let admission_operation = budget_request.admission_operation.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture request omitted admission operation ownership".to_string(),
        )
    })?;
    if response.operation_id != request.operation_id()
        || response.request_binding_hash != admission_operation.request_binding_hash()
        || response.capability_id != budget_request.capability_id
        || response.grant_index != budget_request.grant_index
        || response.hold_id != hold_id
        || response.event_id != event_id
        || response.metadata.operation_id != request.operation_id()
        || response.metadata.hold_id != hold_id
        || response.metadata.event_id != event_id
        || response.metadata.checked_revocation_set_digest != request.bound_revocation_set_digest()
        || response.metadata.authorization_artifact_digests
            != request.authorization_artifact_digests()
        || response.metadata.aggregate_root_capability_id.as_deref()
            != request.aggregate_root_capability_id()
        || response.metadata.aggregate_root_binding_digest.as_deref()
            != request.aggregate_root_binding_digest()
        || response.metadata.guarantee_level != BudgetGuaranteeLevelView::HaLinearizable
        || response.metadata.leader_epoch == 0
        || response.metadata.authority_commit_index == 0
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture response changed its bound identity or authority evidence"
                .to_string(),
        ));
    }
    let revocation_set = canonical_revocation_set_from_view(&response.revocation_set)?;
    if &revocation_set != request.revocation_set() {
        return Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture response changed the canonical revocation set".to_string(),
        ));
    }
    let requested_authority = budget_request.authority.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture request omitted persisted authority".to_string(),
        )
    })?;
    let response_authority = response.metadata.authority.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture response omitted persisted authority".to_string(),
        )
    })?;
    if response_authority.authority_id != requested_authority.authority_id
        || response_authority.lease_id != requested_authority.lease_id
        || response_authority.lease_epoch != requested_authority.lease_epoch
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture response changed the persisted authority".to_string(),
        ));
    }
    let quotas = response
        .metadata
        .invocation_quotas
        .iter()
        .map(|projection| invocation_quota_from_view(&projection.quota()))
        .collect::<Result<Vec<_>, _>>()?;

    match (response.outcome, response.budget) {
        (AdmissionCaptureOutcomeView::Captured, Some(budget_response)) => {
            if !response.revoked_capability_ids.is_empty() {
                return Err(AdmissionCaptureError::InvalidRequest(
                    "captured admission response contains revoked IDs".to_string(),
                ));
            }
            let monetary_state = monetary_state_from_view(budget_response.monetary_state);
            let budget = validate_invocation_capture_response(
                budget_request,
                &quotas,
                request.revocation_set(),
                monetary_state,
                budget_response,
            )?;
            validate_remote_capture_projection(&response.metadata, &budget)?;
            if response.metadata.budget_commit_index != budget.metadata.budget_commit_index {
                return Err(AdmissionCaptureError::InvalidRequest(
                    "remote admission metadata changed the budget commit index".to_string(),
                ));
            }
            let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: response.metadata.checked_revocation_set_digest,
                aggregate_root_capability_id: response.metadata.aggregate_root_capability_id,
                aggregate_root_binding_digest: response.metadata.aggregate_root_binding_digest,
                budget_commit: budget.metadata.clone(),
                revocation_commit_index: response.metadata.revocation_commit_index,
                authority_commit_index: response.metadata.authority_commit_index,
                leader_epoch: Some(response.metadata.leader_epoch),
            })?;
            Ok(AdmissionCaptureDecision::Captured {
                budget: Box::new(budget),
                metadata,
            })
        }
        (AdmissionCaptureOutcomeView::DeniedRevoked, None) => {
            if response.revoked_capability_ids.iter().any(|id| {
                request
                    .revocation_set()
                    .ids()
                    .binary_search_by(|candidate| candidate.as_bytes().cmp(id.as_bytes()))
                    .is_err()
            }) {
                return Err(AdmissionCaptureError::InvalidRequest(
                    "remote admission denial contains an unbound revoked ID".to_string(),
                ));
            }
            let budget_commit = BudgetCommitMetadata {
                authority: Some(requested_authority.clone()),
                guarantee_level: BudgetGuaranteeLevel::HaLinearizable,
                budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
                metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                budget_commit_index: response.metadata.budget_commit_index,
                event_id: Some(event_id.to_string()),
            };
            let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: response.metadata.checked_revocation_set_digest,
                aggregate_root_capability_id: response.metadata.aggregate_root_capability_id,
                aggregate_root_binding_digest: response.metadata.aggregate_root_binding_digest,
                budget_commit,
                revocation_commit_index: response.metadata.revocation_commit_index,
                authority_commit_index: response.metadata.authority_commit_index,
                leader_epoch: Some(response.metadata.leader_epoch),
            })?;
            Ok(AdmissionCaptureDecision::Denied(
                AdmissionCaptureDenial::revoked(response.revoked_capability_ids, metadata)?,
            ))
        }
        _ => Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture outcome contradicts its budget body".to_string(),
        )),
    }
}

fn validate_remote_capture_projection(
    metadata: &AdmissionCaptureMetadataView,
    budget: &BudgetHoldMutationDecision,
) -> Result<(), AdmissionCaptureError> {
    if metadata.invocation_state != BudgetInvocationReservationStateView::Captured
        || invocation_state_from_view(metadata.invocation_state) != budget.invocation_state
        || monetary_state_from_view(metadata.monetary_state) != budget.monetary_state
        || metadata.invocation_quotas.len() != budget.invocation_counts_after.len()
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture metadata changed the authoritative capture substates"
                .to_string(),
        ));
    }
    for (projection, after) in metadata
        .invocation_quotas
        .iter()
        .zip(&budget.invocation_counts_after)
    {
        let AdmissionCaptureInvocationQuotaView::Transition(transition) = projection else {
            return Err(AdmissionCaptureError::InvalidRequest(
                "remote captured admission metadata omitted quota transitions".to_string(),
            ));
        };
        let quota = invocation_quota_from_view(&BudgetInvocationQuotaView {
            key: transition.key.clone(),
            max_invocations: transition.max_invocations,
        })?;
        let reserved_before = transition
            .reserved_invocations_after
            .checked_add(1)
            .ok_or_else(|| {
                AdmissionCaptureError::InvalidRequest(
                    "remote admission capture reserved quota transition overflowed".to_string(),
                )
            })?;
        let captured_after = transition
            .captured_invocations_before
            .checked_add(1)
            .ok_or_else(|| {
                AdmissionCaptureError::InvalidRequest(
                    "remote admission capture captured quota transition overflowed".to_string(),
                )
            })?;
        if quota != after.quota
            || transition.reserved_invocations_before != reserved_before
            || transition.reserved_invocations_after != after.reserved_invocations_after
            || transition.captured_invocations_after != captured_after
            || transition.captured_invocations_after != after.captured_invocations_after
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "remote admission capture metadata changed an authoritative quota transition"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ValidatedRemoteBudgetEvidence {
    authority: Option<BudgetEventAuthority>,
    guarantee_level: BudgetGuaranteeLevel,
    commit_index: Option<u64>,
}

fn required_remote_transition_snapshot(
    expected_capability_id: &str,
    expected_grant_index: usize,
    response_capability_id: &str,
    response_grant_index: usize,
    invocation_count: Option<u32>,
    total_cost_exposed: Option<u64>,
    total_cost_realized_spend: Option<u64>,
) -> Result<(u32, u64, u64, u64), BudgetStoreError> {
    if response_capability_id != expected_capability_id
        || response_grant_index != expected_grant_index
    {
        return Err(BudgetStoreError::Invariant(
            "remote budget transition response does not match capability/grant".to_string(),
        ));
    }
    let invocation_count = invocation_count.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote budget transition response omitted invocation_count".to_string(),
        )
    })?;
    let total_cost_exposed = total_cost_exposed.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote budget transition response omitted total exposed cost".to_string(),
        )
    })?;
    let total_cost_realized_spend = total_cost_realized_spend.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote budget transition response omitted total realized spend".to_string(),
        )
    })?;
    let committed_cost_units_after = total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "remote budget transition committed cost overflowed u64".to_string(),
            )
        })?;
    Ok((
        invocation_count,
        total_cost_exposed,
        total_cost_realized_spend,
        committed_cost_units_after,
    ))
}

fn validate_remote_budget_evidence(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
    requested_terminal_authority: Option<&BudgetEventAuthority>,
) -> Result<ValidatedRemoteBudgetEvidence, BudgetStoreError> {
    let metadata_authority = authority
        .map(|authority| {
            if authority.budget_term != authority.lease_epoch {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authority term does not match its lease epoch".to_string(),
                ));
            }
            if authority.authority_id.is_empty() || authority.lease_id.is_empty() {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authority identity is incomplete".to_string(),
                ));
            }
            Ok(BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            })
        })
        .transpose()?;

    let commit_authority = commit
        .map(|commit| {
            if commit.budget_term != commit.lease_epoch {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit term does not match its lease epoch".to_string(),
                ));
            }
            if commit.authority_id.is_empty() || commit.lease_id.is_empty() {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit authority identity is incomplete".to_string(),
                ));
            }
            if commit.budget_seq == 0 || commit.commit_index == 0 {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit omitted its budget cursor or consensus index".to_string(),
                ));
            }
            if !commit.quorum_committed {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit is not quorum committed".to_string(),
                ));
            }
            if commit.quorum_size == 0 || commit.committed_nodes < commit.quorum_size {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit does not contain a quorum of witnesses".to_string(),
                ));
            }
            let unique_witnesses = commit.witness_urls.iter().collect::<BTreeSet<_>>();
            if unique_witnesses.len() != commit.witness_urls.len() {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit contains duplicate witness URLs".to_string(),
                ));
            }
            if commit.witness_urls.len() != commit.committed_nodes {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit witness count does not match committed nodes".to_string(),
                ));
            }
            Ok(BudgetEventAuthority {
                authority_id: commit.authority_id.clone(),
                lease_id: commit.lease_id.clone(),
                lease_epoch: commit.lease_epoch,
            })
        })
        .transpose()?;

    if let (Some(metadata_authority), Some(commit_authority)) =
        (metadata_authority.as_ref(), commit_authority.as_ref())
    {
        if metadata_authority != commit_authority
            || authority.is_some_and(|authority| {
                authority.budget_term != commit.map_or(0, |commit| commit.budget_term)
            })
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget authority does not match budget commit authority".to_string(),
            ));
        }
    }

    if let Some(commit) = commit {
        if let Some(authority) = authority {
            if authority.budget_commit_index != Some(commit.commit_index) {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authority commit index does not match budget commit".to_string(),
                ));
            }
        }
    }

    if let Some(requested) = requested_terminal_authority {
        let Some(response_authority) = metadata_authority.as_ref() else {
            return Err(BudgetStoreError::Invariant(
                "remote budget transition response omitted the requested budget authority"
                    .to_string(),
            ));
        };
        if response_authority != requested {
            return Err(BudgetStoreError::Invariant(
                "remote budget transition response authority does not match the requested budget authority"
                    .to_string(),
            ));
        }
    }

    let guarantee_level = match authority.map(|authority| authority.guarantee_level.as_str()) {
        Some("single_node_atomic") if commit.is_none() => BudgetGuaranteeLevel::SingleNodeAtomic,
        Some("ha_quorum_commit") | Some("ha_linearizable") if commit.is_some() => {
            BudgetGuaranteeLevel::HaLinearizable
        }
        Some("partition_escrowed") if commit.is_none() => BudgetGuaranteeLevel::PartitionEscrowed,
        Some("ha_leader_visible") | Some("advisory_posthoc") if commit.is_none() => {
            BudgetGuaranteeLevel::AdvisoryPosthoc
        }
        Some("ha_quorum_commit") | Some("ha_linearizable") => {
            return Err(BudgetStoreError::Invariant(
                "remote HA budget authority omitted its quorum commit".to_string(),
            ));
        }
        Some(
            "single_node_atomic" | "partition_escrowed" | "ha_leader_visible" | "advisory_posthoc",
        ) => {
            return Err(BudgetStoreError::Invariant(
                "remote budget guarantee contradicts the supplied quorum commit".to_string(),
            ));
        }
        Some(unknown) => {
            return Err(BudgetStoreError::Invariant(format!(
                "remote budget response has unknown guarantee level `{unknown}`"
            )));
        }
        None if commit.is_some() => BudgetGuaranteeLevel::HaLinearizable,
        None => BudgetGuaranteeLevel::SingleNodeAtomic,
    };

    let response_authority = metadata_authority.or(commit_authority);
    let commit_index = commit
        .map(|commit| commit.budget_seq)
        .or_else(|| authority.and_then(|authority| authority.budget_commit_index));
    if commit.is_none()
        && authority.is_some_and(|authority| authority.budget_commit_index.is_some())
    {
        return Err(BudgetStoreError::Invariant(
            "remote budget authority supplied a commit index without quorum commit evidence"
                .to_string(),
        ));
    }

    Ok(ValidatedRemoteBudgetEvidence {
        authority: response_authority,
        guarantee_level,
        commit_index,
    })
}
