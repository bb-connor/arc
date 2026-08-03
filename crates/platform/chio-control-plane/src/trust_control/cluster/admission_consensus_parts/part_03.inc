fn synchronize_peer_through(
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    client: &TrustControlClient,
    target_index: u64,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let local = store.meta()?;
    if local.membership_digest.as_deref() != Some(membership.digest())
        || target_index == 0
        || target_index > local.last_log_index
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer synchronization target is outside the local log".to_string(),
        ));
    }
    let probe = send_peer_append_response(
        store,
        election,
        client,
        &AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: election.term,
            leader_id: election.candidate_id.clone(),
            previous_log_index: 0,
            previous_log_term: 0,
            entry: None,
            leader_commit: 0,
            commit_proof: None,
        },
    )?;
    if probe.commit_index > local.commit_index || probe.match_index < probe.commit_index {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer commit index is ahead of the elected leader".to_string(),
        ));
    }
    let follower_commit = probe.commit_index;
    let mut common_index = probe.match_index.min(target_index);
    loop {
        let previous_log_term = if common_index == 0 {
            0
        } else {
            store.entry_at(common_index)?.leader_epoch
        };
        let response = send_peer_append_response(
            store,
            election,
            client,
            &AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index: common_index,
                previous_log_term,
                entry: None,
                leader_commit: follower_commit,
                commit_proof: None,
            },
        )?;
        if response.accepted {
            break;
        }
        if common_index <= follower_commit {
            return Err(AdmissionConsensusError::Protocol(
                "admission peer diverges inside the committed prefix".to_string(),
            ));
        }
        common_index = common_index.checked_sub(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission log backtrack underflow".to_string())
        })?;
    }
    let first_missing_entry = common_index.checked_add(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission log index overflow".to_string())
    })?;
    for index in first_missing_entry..=target_index {
        let entry = store.entry_at(index)?;
        let (previous_log_index, previous_log_term) = previous_store_position(store, entry.index)?;
        send_peer_append(
            store,
            election,
            client,
            AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index,
                previous_log_term,
                entry: Some(entry),
                leader_commit: follower_commit,
                commit_proof: None,
            },
        )?;
    }
    let first_missing_commit = follower_commit.checked_add(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission commit index overflow".to_string())
    })?;
    for index in first_missing_commit..=local.commit_index {
        let entry = store.entry_at(index)?;
        let proof = store.proof_at(index)?;
        send_peer_append(
            store,
            election,
            client,
            AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index: entry.index,
                previous_log_term: entry.leader_epoch,
                entry: None,
                leader_commit: index,
                commit_proof: Some(proof),
            },
        )?;
    }
    let target = store.entry_at(target_index)?;
    send_peer_append(
        store,
        election,
        client,
        AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: election.term,
            leader_id: election.candidate_id.clone(),
            previous_log_index: target.index,
            previous_log_term: target.leader_epoch,
            entry: None,
            leader_commit: local.commit_index,
            commit_proof: None,
        },
    )
}

fn send_peer_append(
    store: &AdmissionConsensusStore,
    election: &AdmissionElection,
    client: &TrustControlClient,
    request: AdmissionAppendEntriesRequest,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let response = send_peer_append_response(store, election, client, &request)?;
    if !response.accepted {
        return Err(AdmissionConsensusError::Protocol(
            response
                .rejection
                .clone()
                .unwrap_or_else(|| "admission peer rejected the append".to_string()),
        ));
    }
    Ok(response)
}

fn send_peer_append_response(
    store: &AdmissionConsensusStore,
    election: &AdmissionElection,
    client: &TrustControlClient,
    request: &AdmissionAppendEntriesRequest,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let response = client.admission_append_entries(request).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission peer append failed before acknowledgement: {error}"
        ))
    })?;
    if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append used an unsupported protocol".to_string(),
        ));
    }
    if response.membership_digest != request.membership_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append membership digest changed".to_string(),
        ));
    }
    if !is_lower_sha256(&response.applied_state_digest) {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append returned an invalid applied-state digest".to_string(),
        ));
    }
    if response.term > election.term {
        store.observe_higher_term(response.term)?;
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append reported a higher term".to_string(),
        ));
    }
    if response.term != election.term {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append returned another election term".to_string(),
        ));
    }
    Ok(response)
}

fn previous_store_position(
    store: &AdmissionConsensusStore,
    index: u64,
) -> Result<(u64, u64), AdmissionConsensusError> {
    let previous = index.checked_sub(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission log index underflow".to_string())
    })?;
    if previous == 0 {
        return Ok((0, 0));
    }
    let entry = store.entry_at(previous)?;
    Ok((entry.index, entry.leader_epoch))
}

fn prepare_command(
    config: &TrustServiceConfig,
    command_kind: AdmissionCommandKind,
    command: Value,
    election: &AdmissionElection,
) -> Result<Value, AdmissionConsensusError> {
    match command_kind {
        AdmissionCommandKind::LeadershipBarrier => Err(AdmissionConsensusError::Protocol(
            "leadership barriers cannot be submitted as external commands".to_string(),
        )),
        AdmissionCommandKind::IncrementInvocation => {
            if config.partition_escrow_authority.is_some() {
                return Err(AdmissionConsensusError::Protocol(
                    "sealed partition escrow authority rejects legacy unbound invocation increments"
                        .to_string(),
                ));
            }
            let request: TryIncrementBudgetRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation increment command is invalid: {error}"
                    ))
                })?;
            if request.capability_id.is_empty()
                || request.capability_id.len() > 512
                || request.capability_id.bytes().any(|byte| byte == 0)
                || request.grant_index > i64::MAX as usize
            {
                return Err(AdmissionConsensusError::Protocol(
                    "invocation increment command fields are invalid".to_string(),
                ));
            }
            let authority = BudgetMutationAuthorityView {
                authority_id: election.candidate_id.clone(),
                lease_id: format!("{}#admission-term-{}", election.candidate_id, election.term),
                lease_epoch: election.term,
            };
            serde_json::to_value(ConsensusIncrementInvocationCommand { request, authority })
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation increment command preparation failed: {error}"
                    ))
                })
        }
        AdmissionCommandKind::CompositeAuthorize => {
            let request: CompositeBudgetAuthorizeRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "composite authorize command is invalid: {error}"
                    ))
                })?;
            if request.existing_only {
                return Err(AdmissionConsensusError::Protocol(
                    "existingOnly cannot be prepared as a composite authorization command"
                        .to_string(),
                ));
            }
            let authority = BudgetMutationAuthorityView {
                authority_id: election.candidate_id.clone(),
                lease_id: format!("{}#admission-term-{}", election.candidate_id, election.term),
                lease_epoch: election.term,
            };
            super::super::budget_handlers::sqlite_fresh_composite_authorize_input(
                &request,
                budget_authority_from_view(&authority)
                    .map_err(AdmissionConsensusError::Protocol)?,
                config.partition_escrow_authority.as_deref(),
            )
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            validate_composite_quota_maxima(config, &request)
                .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(ConsensusCompositeAuthorizeCommand { request, authority }).map_err(
                |error| {
                    AdmissionConsensusError::Protocol(format!(
                        "composite authorize command preparation failed: {error}"
                    ))
                },
            )
        }
        AdmissionCommandKind::CaptureInvocations => {
            let request: CaptureInvocationReservationsRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation capture command is invalid: {error}"
                    ))
                })?;
            BudgetAdmissionOperationBinding::new(
                request.operation_id.clone(),
                request.request_binding_hash.clone(),
            )
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                &request.hold_id,
                &request.event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "invocation capture command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::ReverseExposure => {
            let request: ReverseChargeCostRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "reverse exposure command is invalid: {error}"
                    ))
                })?;
            super::super::budget_handlers::budget_admission_operation_binding(
                request.operation_id.as_deref(),
                request.request_binding_hash.as_deref(),
            )
            .and_then(|binding| {
                binding.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "admission reverse command requires operation ownership".to_string(),
                    )
                })
            })
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "reverse exposure command requires hold_id".to_string(),
                )
            })?;
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "reverse exposure command requires event_id".to_string(),
                )
            })?;
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                hold_id,
                event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "reverse exposure command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => {
            let request: ReduceChargeCostRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "monetary transition command is invalid: {error}"
                    ))
                })?;
            super::super::budget_handlers::budget_admission_operation_binding(
                request.operation_id.as_deref(),
                request.request_binding_hash.as_deref(),
            )
            .and_then(|binding| {
                binding.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "admission monetary transition requires operation ownership".to_string(),
                    )
                })
            })
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "monetary transition command requires hold_id".to_string(),
                )
            })?;
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "monetary transition command requires event_id".to_string(),
                )
            })?;
            let shape_matches = match command_kind {
                AdmissionCommandKind::ReleaseExposure => {
                    request.exposure_units.is_none() && request.realized_spend_units.is_none()
                }
                AdmissionCommandKind::ReconcileSpend | AdmissionCommandKind::CaptureExposure => {
                    request
                        .exposure_units
                        .zip(request.realized_spend_units)
                        .is_some_and(|(exposure_units, realized_spend_units)| {
                            exposure_units.checked_sub(realized_spend_units)
                                == Some(request.cost_units)
                        })
                }
                _ => false,
            };
            if !shape_matches {
                return Err(AdmissionConsensusError::Protocol(
                    "monetary transition command fields contradict its kind".to_string(),
                ));
            }
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                hold_id,
                event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "monetary transition command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::Revoke => {
            let request: ConsensusRevocationProposal =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "revocation proposal is invalid: {error}"
                    ))
                })?;
            if request.capability_id.is_empty()
                || request.capability_id.len() > 512
                || request.capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(AdmissionConsensusError::Protocol(
                    "revocation proposal fields are invalid".to_string(),
                ));
            }
            let revoked_at = i64::try_from(unix_timestamp_now()).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "revocation timestamp exceeds the supported range".to_string(),
                )
            })?;
            serde_json::to_value(ConsensusRevocationCommand {
                capability_id: request.capability_id,
                revoked_at,
            })
            .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "revocation command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::CombinedCapture => {
            let request: CombinedAdmissionCaptureRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "combined capture command is invalid: {error}"
                    ))
                })?;
            let prepared = prepare_combined_capture_command(config, request)
                .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(prepared).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "combined capture command preparation failed: {error}"
                ))
            })
        }
    }
}

fn admission_members(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, AdmissionMembership), AdmissionConsensusError> {
    let (self_url, peers, members) = admission_member_urls(state)?;
    let store = configured_admission_consensus_store(&state.config)?;
    let meta = store.meta()?;
    let genesis_projection = if let Some(digest) = meta.baseline_state_digest {
        let projection = store.genesis_projection()?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission consensus baseline has no persisted genesis projection".to_string(),
            )
        })?;
        if admission_genesis_projection_digest(&projection)? != digest {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted genesis projection does not match its baseline digest"
                    .to_string(),
            ));
        }
        projection
    } else if meta.membership_digest.is_none() {
        let path = state.config.budget_db_path.as_deref().ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission consensus requires a budget database".to_string(),
            )
        })?;
        capture_admission_genesis_projection(path)?
    } else {
        return Err(AdmissionConsensusError::Protocol(
            "admission bound membership has no genesis baseline".to_string(),
        ));
    };
    let membership = AdmissionMembership::new_with_genesis(members, genesis_projection)?;
    Ok((self_url, peers, membership))
}

fn admission_members_read_only(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, AdmissionMembership), AdmissionConsensusError> {
    let (self_url, peers, members) = admission_member_urls(state)?;
    let store = configured_admission_consensus_store_read_only(&state.config)?;
    let meta = store.meta()?;
    let digest = meta.baseline_state_digest.ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed admission replay requires an already-bound genesis baseline".to_string(),
        )
    })?;
    let projection = store.genesis_projection()?.ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed admission replay baseline has no persisted genesis projection".to_string(),
        )
    })?;
    if admission_genesis_projection_digest(&projection)? != digest {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay genesis projection does not match its baseline digest"
                .to_string(),
        ));
    }
    let membership = AdmissionMembership::new_with_genesis(members, projection)?;
    if meta.membership_digest.as_deref() != Some(membership.digest()) {
        return Err(AdmissionConsensusError::Protocol(
            "committed admission replay membership differs from persisted state".to_string(),
        ));
    }
    Ok((self_url, peers, membership))
}

pub(crate) fn validate_partition_escrow_admission_membership(
    config: &TrustServiceConfig,
    authority: &super::super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
) -> Result<(), CliError> {
    let store = configured_admission_consensus_store_read_only(config)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_integrity()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let meta = store
        .meta()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let baseline_digest = meta.baseline_state_digest.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "partition escrow requires an already-bound admission consensus baseline"
                .to_string(),
        )
    })?;
    let genesis_projection = store
        .genesis_projection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .ok_or_else(|| {
            CliError::cli_other_error(
                "partition escrow admission consensus baseline projection is missing".to_string(),
            )
        })?;
    let observed_baseline = admission_genesis_projection_digest(&genesis_projection)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if observed_baseline != baseline_digest {
        return Err(CliError::cli_other_error(
            "partition escrow admission consensus baseline projection digest is invalid"
                .to_string(),
        ));
    }
    let membership = AdmissionMembership::new_with_genesis(
        authority.service_endpoints().to_vec(),
        genesis_projection,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if meta.membership_digest.as_deref() != Some(membership.digest())
        || authority.admission_membership_digest() != membership.digest()
    {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor, configured members, and persisted admission membership must have one exact digest"
                .to_string(),
        ));
    }
    store
        .validate_membership_proofs(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    validate_partition_escrow_authority_pin(&store, authority)?;
    validate_persisted_partition_escrow_authority(&store, authority)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PartitionEscrowAuthorityPin {
    descriptor_digest: String,
    membership_digest: String,
}

fn validate_partition_escrow_authority_pin(
    store: &AdmissionConsensusStore,
    authority: &super::super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
) -> Result<(), CliError> {
    let connection = store
        .connection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let evidence_count = persisted_partition_escrow_evidence_count_from_connection(&connection)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let pin = load_partition_escrow_authority_pin(&connection)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let pin = pin.ok_or_else(|| {
        if evidence_count == 0 {
            CliError::cli_other_error(
                "partition escrow authority is not provisioned in the HA admission database"
                    .to_string(),
            )
        } else {
            CliError::cli_other_error(
                "partition escrow evidence exists without an immutable authority pin"
                    .to_string(),
            )
        }
    })?;
    let meta = load_meta(&connection)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if pin.descriptor_digest != authority.descriptor_digest()
        || pin.membership_digest != authority.admission_membership_digest()
        || meta.membership_digest.as_deref() != Some(pin.membership_digest.as_str())
    {
        return Err(CliError::cli_other_error(
            "partition escrow authority descriptor differs from the immutable HA admission pin"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn bind_initial_partition_escrow_admission_membership(
    budget_db_path: &Path,
    revocation_db_path: &Path,
    service_endpoints: &[String],
) -> Result<String, CliError> {
    if !super::super::cluster_replay::cluster_replay_path_aliases(
        budget_db_path,
        revocation_db_path,
    )? {
        return Err(CliError::cli_other_error(
            "partition escrow provisioning requires one shared budget and revocation database"
                .to_string(),
        ));
    }
    SqliteAdmissionCaptureAuthority::open_with_paths(budget_db_path, revocation_db_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let store = AdmissionConsensusStore::open(budget_db_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_integrity()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let meta = store
        .meta()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if meta.current_term != 0
        || meta.voted_for.is_some()
        || meta.last_log_index != 0
        || meta.last_log_term != 0
        || meta.commit_index != 0
        || meta.last_applied != 0
    {
        return Err(CliError::cli_other_error(
            "partition escrow authority provisioning must precede every admission consensus term and command"
                .to_string(),
        ));
    }
    let projection = match (
        meta.baseline_state_digest.as_deref(),
        meta.membership_digest.as_deref(),
    ) {
        (Some(expected), Some(_)) => {
            let projection = store
                .genesis_projection()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "partition escrow provisioning baseline projection is missing"
                            .to_string(),
                    )
                })?;
            let observed = admission_genesis_projection_digest(&projection)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            if observed != expected {
                return Err(CliError::cli_other_error(
                    "partition escrow provisioning baseline projection digest is invalid"
                        .to_string(),
                ));
            }
            projection
        }
        (None, None) => capture_admission_genesis_projection(budget_db_path)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        _ => {
            return Err(CliError::cli_other_error(
                "partition escrow provisioning found a partial admission membership binding"
                    .to_string(),
            ));
        }
    };
    let membership =
        AdmissionMembership::new_with_genesis(service_endpoints.to_vec(), projection)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if load_partition_escrow_authority_pin(
        &store
            .connection()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?
    .is_some()
    {
        return Err(CliError::cli_other_error(
            "partition escrow authority provisioning is immutable and has already completed"
                .to_string(),
        ));
    }
    if persisted_partition_escrow_evidence_count(&store)? != 0 {
        return Err(CliError::cli_other_error(
            "partition escrow authority cannot be provisioned after allocation evidence exists"
                .to_string(),
        ));
    }
    store
        .bind_membership(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_membership_proofs(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(membership.digest().to_string())
}

pub(crate) fn persist_initial_partition_escrow_authority_pin(
    budget_db_path: &Path,
    revocation_db_path: &Path,
    descriptor_digest: &str,
    membership_digest: &str,
) -> Result<(), CliError> {
    if !is_lower_sha256(descriptor_digest) || !is_lower_sha256(membership_digest) {
        return Err(CliError::cli_other_error(
            "partition escrow authority pin digests are invalid".to_string(),
        ));
    }
    if !super::super::cluster_replay::cluster_replay_path_aliases(
        budget_db_path,
        revocation_db_path,
    )? {
        return Err(CliError::cli_other_error(
            "partition escrow provisioning requires one shared budget and revocation database"
                .to_string(),
        ));
    }
    let store = AdmissionConsensusStore::open_existing(budget_db_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let mut connection = store
        .connection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    validate_integrity(&transaction)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let meta = load_meta(&transaction)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if meta.membership_digest.as_deref() != Some(membership_digest) {
        return Err(CliError::cli_other_error(
            "partition escrow authority pin differs from the bound admission membership"
                .to_string(),
        ));
    }
    if load_partition_escrow_authority_pin(&transaction)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .is_some()
    {
        return Err(CliError::cli_other_error(
            "partition escrow authority pin is immutable and already exists".to_string(),
        ));
    }
    if persisted_partition_escrow_evidence_count_from_connection(&transaction)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        != 0
    {
        return Err(CliError::cli_other_error(
            "partition escrow authority pin cannot be created after allocation evidence exists"
                .to_string(),
        ));
    }
    transaction
        .execute(
            r#"
            INSERT INTO admission_consensus_partition_escrow_authority (
                singleton, descriptor_digest, membership_digest
            ) VALUES (1, ?1, ?2)
            "#,
            params![descriptor_digest, membership_digest],
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    transaction
        .commit()
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn validate_partition_escrow_authority_for_mutation(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
) -> Result<(), String> {
    let pin = load_partition_escrow_authority_pin(transaction).map_err(|error| error.to_string())?;
    let evidence_count = persisted_partition_escrow_evidence_count_from_connection(transaction)
        .map_err(|error| error.to_string())?;
    match (config.partition_escrow_authority.as_deref(), pin) {
        (Some(authority), Some(pin)) => {
            authority
                .verify_persisted_configuration()
                .map_err(|error| error.to_string())?;
            let meta = load_meta(transaction).map_err(|error| error.to_string())?;
            if pin.descriptor_digest != authority.descriptor_digest()
                || pin.membership_digest != authority.admission_membership_digest()
                || meta.membership_digest.as_deref() != Some(pin.membership_digest.as_str())
            {
                return Err(
                    "partition escrow mutation differs from its immutable authority or membership pin"
                        .to_string(),
                );
            }
            Ok(())
        }
        (Some(_), None) if evidence_count == 0 => {
            Err("partition escrow mutation requires a provisioned authority pin".to_string())
        }
        (Some(_), None) => Err(
            "partition escrow evidence exists without an immutable authority pin".to_string(),
        ),
        (None, Some(_)) => Err(
            "ordinary admission cannot mutate a partition-escrow-pinned database".to_string(),
        ),
        (None, None) if evidence_count != 0 => Err(
            "partition escrow evidence exists without an immutable authority pin".to_string(),
        ),
        (None, None) => Ok(()),
    }
}

fn load_partition_escrow_authority_pin(
    connection: &Connection,
) -> Result<Option<PartitionEscrowAuthorityPin>, AdmissionConsensusError> {
    let pin = connection
        .query_row(
            r#"
            SELECT descriptor_digest, membership_digest
            FROM admission_consensus_partition_escrow_authority
            WHERE singleton = 1
            "#,
            [],
            |row| {
                Ok(PartitionEscrowAuthorityPin {
                    descriptor_digest: row.get(0)?,
                    membership_digest: row.get(1)?,
                })
            },
        )
        .optional()?;
    if pin.as_ref().is_some_and(|pin| {
        !is_lower_sha256(&pin.descriptor_digest) || !is_lower_sha256(&pin.membership_digest)
    }) {
        return Err(AdmissionConsensusError::Protocol(
            "partition escrow authority pin contains an invalid digest".to_string(),
        ));
    }
    Ok(pin)
}

pub(crate) fn provisionable_partition_escrow_admission_membership_digest(
    budget_db_path: &Path,
    revocation_db_path: &Path,
    service_endpoints: &[String],
) -> Result<String, CliError> {
    let store = admission_consensus_store_read_only_from_paths(
        budget_db_path,
        revocation_db_path,
        "partition escrow descriptor provisioning",
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_integrity()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let meta = store
        .meta()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let baseline_digest = meta.baseline_state_digest.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "partition escrow descriptor provisioning requires an already-bound admission consensus baseline"
                .to_string(),
        )
    })?;
    let genesis_projection = store
        .genesis_projection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .ok_or_else(|| {
            CliError::cli_other_error(
                "partition escrow descriptor provisioning baseline projection is missing"
                    .to_string(),
            )
        })?;
    let observed_baseline = admission_genesis_projection_digest(&genesis_projection)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if observed_baseline != baseline_digest {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor provisioning baseline projection digest is invalid"
                .to_string(),
        ));
    }
    let membership =
        AdmissionMembership::new_with_genesis(service_endpoints.to_vec(), genesis_projection)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if meta.membership_digest.as_deref() != Some(membership.digest()) {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor endpoints differ from the persisted admission membership"
                .to_string(),
        ));
    }
    store
        .validate_membership_proofs(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if persisted_partition_escrow_evidence_count(&store)? != 0 {
        return Err(CliError::cli_other_error(
            "partition escrow descriptor provisioning is initial-generation only; online rollover and replacement after allocation evidence exists are unsupported"
                .to_string(),
        ));
    }
    Ok(membership.digest().to_string())
}

fn persisted_partition_escrow_evidence_count(
    store: &AdmissionConsensusStore,
) -> Result<u64, CliError> {
    let connection = store
        .connection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    persisted_partition_escrow_evidence_count_from_connection(&connection)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn persisted_partition_escrow_evidence_count_from_connection(
    connection: &Connection,
) -> Result<u64, AdmissionConsensusError> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM budget_composite_partition_escrow_evidence",
            [],
            |row| row.get::<_, i64>(0),
        )
        ?;
    u64::try_from(count).map_err(|_| {
        AdmissionConsensusError::Protocol(
            "partition escrow persisted evidence count is invalid".to_string(),
        )
    })
}

fn validate_persisted_partition_escrow_authority(
    store: &AdmissionConsensusStore,
    authority: &super::super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
) -> Result<(), CliError> {
    let connection = store
        .connection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT evidence_digest, canonical_evidence
            FROM budget_composite_partition_escrow_evidence
            ORDER BY hold_id ASC
            "#,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let mut rows = statement
        .query([])
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let mut evidence_count = 0usize;
    while let Some(row) = rows
        .next()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        evidence_count = evidence_count.checked_add(1).ok_or_else(|| {
            CliError::cli_other_error(
                "partition escrow persisted evidence inventory overflowed".to_string(),
            )
        })?;
        if evidence_count > MAX_ADMISSION_GENESIS_ROWS {
            return Err(CliError::cli_other_error(
                "partition escrow persisted evidence inventory exceeds its startup limit"
                    .to_string(),
            ));
        }
        let evidence_digest = row
            .get::<_, String>(0)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let canonical_evidence = row
            .get::<_, Vec<u8>>(1)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let canonical_evidence = String::from_utf8(canonical_evidence).map_err(|_| {
            CliError::cli_other_error(
                "partition escrow persisted evidence is not UTF-8 canonical JSON".to_string(),
            )
        })?;
        let evidence = chio_kernel::budget_store::PartitionEscrowCommitEvidence::from_canonical_json(
            canonical_evidence,
            evidence_digest,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        authority
            .validate_persisted_commit_evidence(&evidence)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "partition escrow authority replacement is unsupported while persisted allocation evidence exists: {error}"
                ))
            })?;
    }
    Ok(())
}

fn admission_member_urls(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, Vec<String>), AdmissionConsensusError> {
    let cluster = state.cluster.as_ref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "HA admission consensus requires configured peers".to_string(),
        )
    })?;
    let guard = match cluster.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut peers = guard.peers.keys().cloned().collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    if peers.is_empty() {
        return Err(AdmissionConsensusError::Protocol(
            "HA admission consensus requires at least two configured nodes".to_string(),
        ));
    }
    let self_url = guard.self_url.clone();
    let mut members = peers.clone();
    members.push(self_url.clone());
    drop(guard);
    Ok((self_url, peers, members))
}

fn configured_admission_consensus_store(
    config: &TrustServiceConfig,
) -> Result<AdmissionConsensusStore, AdmissionConsensusError> {
    let budget_path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus requires a budget database".to_string(),
        )
    })?;
    let revocation_path = config.revocation_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus requires a revocation database".to_string(),
        )
    })?;
    let canonical_budget = std::fs::canonicalize(budget_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission budget database cannot be resolved: {error}"
        ))
    })?;
    let canonical_revocation = std::fs::canonicalize(revocation_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission revocation database cannot be resolved: {error}"
        ))
    })?;
    if canonical_budget != canonical_revocation {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus requires one shared budget and revocation database".to_string(),
        ));
    }
    AdmissionConsensusStore::open_existing(canonical_budget)
}

fn configured_admission_consensus_store_read_only(
    config: &TrustServiceConfig,
) -> Result<AdmissionConsensusStore, AdmissionConsensusError> {
    let budget_path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed admission replay requires a budget database".to_string(),
        )
    })?;
    let revocation_path = config.revocation_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "committed admission replay requires a revocation database".to_string(),
        )
    })?;
    admission_consensus_store_read_only_from_paths(
        budget_path,
        revocation_path,
        "committed admission replay",
    )
}

fn admission_consensus_store_read_only_from_paths(
    budget_path: &Path,
    revocation_path: &Path,
    context: &str,
) -> Result<AdmissionConsensusStore, AdmissionConsensusError> {
    let canonical_budget = std::fs::canonicalize(budget_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "{context} budget database cannot be resolved: {error}"
        ))
    })?;
    let canonical_revocation = std::fs::canonicalize(revocation_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "{context} revocation database cannot be resolved: {error}"
        ))
    })?;
    if canonical_budget != canonical_revocation {
        return Err(AdmissionConsensusError::Protocol(format!(
            "{context} requires one shared budget and revocation database"
        )));
    }
    AdmissionConsensusStore::open_existing_read_only(canonical_budget)
}

fn capture_admission_genesis_projection(
    path: &Path,
) -> Result<AdmissionGenesisProjection, AdmissionConsensusError> {
    let mut connection = Connection::open(path)?;
    configure_connection(&connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let projection =
        capture_admission_genesis_projection_from_connection(&transaction, |_| Ok(()))?;
    transaction.commit()?;
    Ok(projection)
}

fn capture_admission_genesis_projection_from_connection<F>(
    connection: &Connection,
    mut after_table: F,
) -> Result<AdmissionGenesisProjection, AdmissionConsensusError>
where
    F: FnMut(&str) -> Result<(), AdmissionConsensusError>,
{
    validate_partition_escrow_projection_integrity(connection)?;
    let existing_tables = {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")?;
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        tables
    };
    for name in &existing_tables {
        let known_authoritative = ADMISSION_GENESIS_TABLES
            .iter()
            .any(|table| table.name == name);
        let known_excluded = name.starts_with("sqlite_")
            || name.starts_with("admission_consensus_")
            || ADMISSION_GENESIS_EXCLUDED_TABLES
                .iter()
                .any(|excluded| excluded == name);
        if !known_authoritative && !known_excluded {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis contains unknown table `{name}`"
            )));
        }
    }

    let mut tables = Vec::with_capacity(ADMISSION_GENESIS_TABLES.len());
    for spec in ADMISSION_GENESIS_TABLES {
        if !existing_tables.iter().any(|name| name == spec.name) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis is missing authoritative table `{}`",
                spec.name
            )));
        }
        validate_admission_genesis_table_schema(connection, spec)?;
        let select_columns = spec
            .columns
            .iter()
            .map(|(name, _)| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement =
            connection.prepare(&format!("SELECT {select_columns} FROM \"{}\"", spec.name))?;
        let mut rows = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = rows.next()? {
            let mut encoded = Vec::with_capacity(spec.columns.len());
            for (index, (_, expected_type)) in spec.columns.iter().enumerate() {
                let value = row.get_ref(index)?;
                let value = match value {
                    rusqlite::types::ValueRef::Null => AdmissionGenesisValue::Null,
                    rusqlite::types::ValueRef::Integer(value) => {
                        AdmissionGenesisValue::Integer(value)
                    }
                    rusqlite::types::ValueRef::Real(value) => {
                        AdmissionGenesisValue::RealBits(format!("{:016x}", value.to_bits()))
                    }
                    rusqlite::types::ValueRef::Text(value) => AdmissionGenesisValue::Text(
                        std::str::from_utf8(value)
                            .map_err(|_| {
                                AdmissionConsensusError::Protocol(format!(
                                    "admission genesis table `{}` contains invalid UTF-8 text",
                                    spec.name
                                ))
                            })?
                            .to_string(),
                    ),
                    rusqlite::types::ValueRef::Blob(value) => {
                        AdmissionGenesisValue::BlobHex(lower_hex(value))
                    }
                };
                if !admission_genesis_value_matches_type(&value, *expected_type) {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission genesis table `{}` contains a value with the wrong logical type",
                        spec.name
                    )));
                }
                encoded.push(value);
            }
            encoded_rows.push(encoded);
        }
        let mut keyed_rows = encoded_rows
            .into_iter()
            .map(|row| {
                canonical_json_bytes(&row)
                    .map(|key| (key, row))
                    .map_err(|error| {
                        AdmissionConsensusError::Protocol(format!(
                            "admission genesis row canonicalization failed: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        keyed_rows.sort_by(|left, right| left.0.cmp(&right.0));
        tables.push(AdmissionGenesisTable {
            name: spec.name.to_string(),
            columns: spec
                .columns
                .iter()
                .map(|(name, value_type)| AdmissionGenesisColumn {
                    name: (*name).to_string(),
                    value_type: *value_type,
                })
                .collect(),
            rows: keyed_rows.into_iter().map(|(_, row)| row).collect(),
        });
        after_table(spec.name)?;
    }
    let projection = AdmissionGenesisProjection { tables };
    validate_admission_genesis_projection(&projection)?;
    Ok(projection)
}

include!("part_03_tail.inc");
