use super::*;

pub(crate) async fn handle_internal_cluster_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_CLUSTER_STATUS_PATH)
    {
        return response;
    }

    let Some(cluster) = state.cluster.as_ref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "cluster replication is not configured",
        );
    };
    let (consensus, authority_lease) = cluster_consensus_and_authority_lease_view(&state)
        .unwrap_or_else(|| {
            (
                ClusterConsensusView {
                    self_url: String::new(),
                    leader_url: None,
                    role: "standalone",
                    has_quorum: false,
                    quorum_size: 1,
                    reachable_nodes: 1,
                    election_term: 0,
                },
                None,
            )
        });
    let replication = match cluster_replication_heads(&state) {
        Ok(replication) => replication,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let peers = match cluster.lock() {
        Ok(guard) => guard
            .peers
            .iter()
            .map(|(peer_url, peer_state)| PeerStatusView {
                peer_url: peer_url.clone(),
                health: peer_state.health.label().to_string(),
                partitioned: peer_state.partitioned,
                last_error: peer_state.last_error.clone(),
                last_contact_at: peer_state.last_contact_at,
                tool_seq: peer_state.tool_seq,
                child_seq: peer_state.child_seq,
                lineage_seq: peer_state.lineage_seq,
                revocation_cursor: peer_state
                    .revocation_cursor
                    .clone()
                    .map(revocation_cursor_view),
                budget_cursor: peer_state.budget_cursor.clone().map(budget_cursor_view),
                snapshot_applied_count: peer_state.snapshot_applied_count,
                last_snapshot_at: peer_state.last_snapshot_at,
                delta_records_since_snapshot: peer_state.delta_records_since_snapshot,
                force_snapshot: peer_state.force_snapshot,
            })
            .collect::<Vec<_>>(),
        Err(poisoned) => poisoned
            .into_inner()
            .peers
            .iter()
            .map(|(peer_url, peer_state)| PeerStatusView {
                peer_url: peer_url.clone(),
                health: peer_state.health.label().to_string(),
                partitioned: peer_state.partitioned,
                last_error: peer_state.last_error.clone(),
                last_contact_at: peer_state.last_contact_at,
                tool_seq: peer_state.tool_seq,
                child_seq: peer_state.child_seq,
                lineage_seq: peer_state.lineage_seq,
                revocation_cursor: peer_state
                    .revocation_cursor
                    .clone()
                    .map(revocation_cursor_view),
                budget_cursor: peer_state.budget_cursor.clone().map(budget_cursor_view),
                snapshot_applied_count: peer_state.snapshot_applied_count,
                last_snapshot_at: peer_state.last_snapshot_at,
                delta_records_since_snapshot: peer_state.delta_records_since_snapshot,
                force_snapshot: peer_state.force_snapshot,
            })
            .collect::<Vec<_>>(),
    };

    let budget_store = match state.optional_budget_store() {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error),
    };
    let budget_ack_heads = match budget_store.as_ref() {
        Some(store) => match store.budget_ack_heads() {
            Ok(heads) => heads
                .into_iter()
                .map(|(origin_id, event_seq)| BudgetOriginAck {
                    origin_id,
                    event_seq,
                })
                .collect(),
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        },
        None => Vec::new(),
    };

    Json(ClusterStatusResponse {
        self_url: consensus.self_url,
        leader_url: consensus.leader_url,
        role: consensus.role.to_string(),
        has_quorum: consensus.has_quorum,
        quorum_size: consensus.quorum_size,
        reachable_nodes: consensus.reachable_nodes,
        election_term: consensus.election_term,
        authority_lease,
        replication,
        peers,
        budget_ack_heads,
    })
    .into_response()
}

const UNPINNED_CLUSTER_AUTHORITY: &str = "clustered trust control requires an out-of-band pinned authority replication anchor in --authority-db; initialize it on the signing custodian with `chio federation authority replication-init` and pin it on every follower with `chio federation authority replication-pin` before starting";

pub(crate) fn build_cluster_state(
    config: &TrustServiceConfig,
    local_addr: SocketAddr,
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> Result<Option<Arc<Mutex<ClusterRuntimeState>>>, CliError> {
    config.validate()?;
    if !config.peer_urls.is_empty() && config.authority_seed_path.is_some() {
        return Err(CliError::cli_other_error(
            "clustered trust control requires --authority-db instead of --authority-seed-file"
                .to_string(),
        ));
    }

    if config.peer_urls.is_empty() {
        return Ok(None);
    }

    let self_url = normalize_cluster_config_url(
        config
            .advertise_url
            .as_deref()
            .unwrap_or(&format!("http://{local_addr}")),
        config.allow_local_peer_urls,
    )?;
    let mut peers = HashMap::new();
    for peer_url in &config.peer_urls {
        let peer_url = normalize_cluster_config_url(peer_url, config.allow_local_peer_urls)?;
        if peer_url != self_url {
            peers.insert(peer_url, PeerSyncState::default());
        }
    }
    if peers.is_empty() {
        return Ok(None);
    }
    let mut persisted_term = 0u64;
    let mut persisted_leader_url = None;
    if let Some(path) = config.authority_db_path.as_deref() {
        let authority = SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
            path,
            clock,
            config.authority_replication_clock_policy()?,
        )?;
        // Clustered authority replicates only as envelopes verified against an
        // anchor provisioned out of band. Without one every authority sync is
        // refused, so the node must not start.
        if authority.pinned_replication_anchor()?.is_none() {
            return Err(CliError::cli_other_error(UNPINNED_CLUSTER_AUTHORITY));
        }
        let status = authority.status()?;
        let fence = authority.cluster_fence()?;
        if fence.authority_generation == status.generation
            && fence.authority_rotated_at == status.rotated_at
        {
            persisted_term = fence.election_term;
            persisted_leader_url = fence
                .leader_url
                .and_then(|leader_url| normalize_cluster_url(&leader_url).ok())
                .filter(|leader_url| leader_url == &self_url || peers.contains_key(leader_url));
        } else if fence.election_term > 0 || fence.leader_url.is_some() {
            warn!(
                fence_generation = fence.authority_generation,
                authority_generation = status.generation,
                fence_rotated_at = fence.authority_rotated_at,
                authority_rotated_at = status.rotated_at,
                "discarding stale persisted authority fence after authority rotation"
            );
        }
    }
    Ok(Some(Arc::new(Mutex::new(ClusterRuntimeState {
        self_url,
        peers,
        election_term: persisted_term,
        last_leader_url: persisted_leader_url,
        term_started_at: None,
        lease_expires_at: None,
        lease_ttl_ms: u64::try_from(authority_lease_ttl(config.cluster_sync_interval).as_millis())
            .map_err(|_| {
                CliError::cli_other_error(
                    "authority lease duration exceeds milliseconds field".to_owned(),
                )
            })?,
    }))))
}

pub(crate) fn cluster_self_url(state: &TrustServiceState) -> Option<String> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(guard) => guard.self_url.clone(),
        Err(poisoned) => poisoned.into_inner().self_url.clone(),
    })
}

pub(crate) fn current_leader_url(state: &TrustServiceState) -> Option<String> {
    cluster_consensus_view(state).and_then(|view| view.leader_url)
}

pub(crate) fn authority_lease_ttl(sync_interval: Duration) -> Duration {
    let scaled = sync_interval
        .checked_mul(3)
        .unwrap_or_else(|| Duration::from_secs(5));
    scaled
        .max(Duration::from_millis(500))
        .min(Duration::from_secs(5))
}

pub(crate) fn cluster_authority_lease_view_locked(
    cluster: &mut ClusterRuntimeState,
    consensus: &ClusterConsensusView,
) -> Option<ClusterAuthorityLeaseView> {
    let clock_now = unix_timestamp_now().ok()?;
    let leader_url = consensus.leader_url.clone()?;
    let lease_epoch = consensus.election_term;
    let lease_id = format!("{leader_url}#term-{lease_epoch}");
    Some(ClusterAuthorityLeaseView {
        authority_id: leader_url.clone(),
        leader_url,
        term: consensus.election_term,
        lease_id,
        lease_epoch,
        term_started_at: cluster.term_started_at,
        lease_expires_at: cluster.lease_expires_at?,
        lease_ttl_ms: cluster.lease_ttl_ms,
        lease_valid: consensus.has_quorum
            && cluster
                .lease_expires_at
                .is_some_and(|expires_at| expires_at >= clock_now),
    })
}

pub(crate) fn cluster_authority_lease_view(
    state: &TrustServiceState,
) -> Option<ClusterAuthorityLeaseView> {
    let cluster = state.cluster.as_ref()?;
    match cluster.lock() {
        Ok(mut guard) => {
            let consensus = compute_cluster_consensus_locked(&mut guard);
            cluster_authority_lease_view_locked(&mut guard, &consensus)
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            let consensus = compute_cluster_consensus_locked(&mut guard);
            cluster_authority_lease_view_locked(&mut guard, &consensus)
        }
    }
}

pub(crate) fn current_budget_event_authority(
    state: &TrustServiceState,
) -> Result<Option<BudgetEventAuthority>, Response> {
    if state.cluster.is_none() {
        return Ok(None);
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for budget writes",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before budget write could start",
        ));
    }
    Ok(Some(BudgetEventAuthority {
        authority_id: authority_lease.authority_id,
        lease_id: authority_lease.lease_id,
        lease_epoch: authority_lease.lease_epoch,
    }))
}

pub(crate) fn budget_authority_metadata_view(
    state: &TrustServiceState,
    budget_commit_index: Option<u64>,
    guarantee_level: &'static str,
) -> Option<BudgetAuthorityMetadataView> {
    let authority_lease = cluster_authority_lease_view(state)?;
    Some(BudgetAuthorityMetadataView {
        authority_id: authority_lease.authority_id,
        leader_url: authority_lease.leader_url,
        budget_term: authority_lease.term,
        lease_id: authority_lease.lease_id,
        lease_epoch: authority_lease.lease_epoch,
        lease_expires_at: authority_lease.lease_expires_at,
        lease_ttl_ms: authority_lease.lease_ttl_ms,
        guarantee_level: guarantee_level.to_string(),
        budget_commit_index,
    })
}

pub(crate) fn budget_authority_guarantee_level(
    state: &TrustServiceState,
    _budget_commit_index: Option<u64>,
) -> &'static str {
    if state.cluster.is_some() {
        "advisory_posthoc"
    } else {
        "single_node_atomic"
    }
}

pub(crate) fn cluster_consensus_view(state: &TrustServiceState) -> Option<ClusterConsensusView> {
    cluster_consensus_and_authority_lease_view(state).map(|(consensus, _)| consensus)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClusterAuthorityReadContext {
    pub(crate) self_url: String,
    pub(crate) leader_url: String,
    pub(crate) election_term: u64,
}

#[derive(Clone)]
pub(crate) enum ClusterAuthorityServingEvidence {
    ElectedLeader {
        quorum_size: usize,
        agreements: Vec<AuthorityAgreementConfirmation>,
    },
    ConfirmedFollower {
        envelope_digest: String,
    },
}

#[derive(Clone)]
pub(crate) struct ClusterAuthorityReadRole {
    pub(crate) context: ClusterAuthorityReadContext,
    pub(crate) evidence: ClusterAuthorityServingEvidence,
    pub(crate) refused_history_commitments: Vec<String>,
}

pub(crate) fn cluster_authority_read_role(
    state: &TrustServiceState,
) -> Option<ClusterAuthorityReadRole> {
    let cluster = state.cluster.as_ref()?;
    let mut guard = cluster.lock().ok()?;
    let view = compute_cluster_consensus_locked(&mut guard);
    if !view.has_quorum {
        return None;
    }
    let leader = view.leader_url?;
    let context = ClusterAuthorityReadContext {
        self_url: view.self_url.clone(),
        leader_url: leader.clone(),
        election_term: view.election_term,
    };
    if guard.peers.values().any(|peer| {
        peer.authority_refused_history
            .as_ref()
            .is_some_and(AuthorityHistoryWitness::has_conflict)
    }) {
        return None;
    }
    let refused_history_commitments = guard
        .peers
        .values()
        .filter_map(|peer| {
            peer.authority_refused_history
                .as_ref()
                .map(|witness| witness.head().to_string())
        })
        .collect();
    let evidence = if leader == view.self_url {
        let lease_seconds = Duration::from_millis(guard.lease_ttl_ms).as_secs().max(1);
        let observed_now = guard.lease_expires_at?.saturating_sub(lease_seconds);
        let mut agreements = Vec::new();
        for peer in guard.peers.values() {
            let contact_is_fresh = peer
                .last_contact_at
                .is_some_and(|at| observed_now <= at.saturating_add(lease_seconds));
            if peer.partitioned
                || !peer.health.is_reachable()
                || !contact_is_fresh
                || peer.authority_error.is_some()
            {
                continue;
            }
            if let Some(agreement) = peer.authority_agreement_confirmation.as_ref() {
                if agreement.leader_url == leader && agreement.election_term == view.election_term {
                    agreements.push(agreement.clone());
                }
            }
        }
        if agreements.len().checked_add(1)? < view.quorum_size {
            return None;
        }
        ClusterAuthorityServingEvidence::ElectedLeader {
            quorum_size: view.quorum_size,
            agreements,
        }
    } else {
        let peer = guard.peers.get(&leader)?;
        if peer.authority_error.is_some() || !peer.health.is_reachable() || peer.partitioned {
            return None;
        }
        let confirmation = peer.authority_import_confirmation.as_ref()?;
        if confirmation.leader_url != leader || confirmation.election_term != view.election_term {
            return None;
        }
        ClusterAuthorityServingEvidence::ConfirmedFollower {
            envelope_digest: confirmation.envelope_digest.clone(),
        }
    };
    Some(ClusterAuthorityReadRole {
        context,
        evidence,
        refused_history_commitments,
    })
}

pub(crate) fn cluster_consensus_and_authority_lease_view(
    state: &TrustServiceState,
) -> Option<(ClusterConsensusView, Option<ClusterAuthorityLeaseView>)> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(mut guard) => {
            let consensus = compute_cluster_consensus_locked(&mut guard);
            let authority_lease = cluster_authority_lease_view_locked(&mut guard, &consensus);
            (consensus, authority_lease)
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            let consensus = compute_cluster_consensus_locked(&mut guard);
            let authority_lease = cluster_authority_lease_view_locked(&mut guard, &consensus);
            (consensus, authority_lease)
        }
    })
}

pub(crate) fn compute_cluster_consensus_locked(
    cluster: &mut ClusterRuntimeState,
) -> ClusterConsensusView {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(_) => return unavailable_cluster_consensus(cluster),
    };
    let now = clock_now;
    let lease_ttl_secs = Duration::from_millis(cluster.lease_ttl_ms).as_secs().max(1);
    let quorum_size = cluster.peers.len().div_ceil(2) + 1;
    let mut candidates = vec![cluster.self_url.clone()];
    for (peer_url, peer_state) in &cluster.peers {
        let contact_is_fresh = peer_state
            .last_contact_at
            .is_some_and(|last_contact_at| now <= last_contact_at.saturating_add(lease_ttl_secs));
        if peer_state.health.is_reachable() && !peer_state.partitioned && contact_is_fresh {
            candidates.push(peer_url.clone());
        }
    }
    candidates.sort();
    let reachable_nodes = candidates.len();
    let has_quorum = reachable_nodes >= quorum_size;
    let leader_url = if has_quorum {
        candidates.first().cloned()
    } else {
        None
    };
    if cluster.last_leader_url != leader_url {
        cluster.election_term = cluster.election_term.saturating_add(1);
        cluster.last_leader_url = leader_url.clone();
        cluster.term_started_at = leader_url.as_ref().map(|_| now);
    }
    cluster.lease_expires_at = if has_quorum {
        Some(now.saturating_add(lease_ttl_secs))
    } else {
        None
    };
    if !has_quorum {
        cluster.term_started_at = None;
    }
    let role = if !has_quorum {
        "candidate"
    } else if leader_url.as_deref() == Some(cluster.self_url.as_str()) {
        "leader"
    } else {
        "follower"
    };
    ClusterConsensusView {
        self_url: cluster.self_url.clone(),
        leader_url,
        role,
        has_quorum,
        quorum_size,
        reachable_nodes,
        election_term: cluster.election_term,
    }
}

fn unavailable_cluster_consensus(cluster: &mut ClusterRuntimeState) -> ClusterConsensusView {
    cluster.lease_expires_at = None;
    cluster.term_started_at = None;
    cluster.last_leader_url = None;
    ClusterConsensusView {
        self_url: cluster.self_url.clone(),
        leader_url: None,
        role: "candidate",
        has_quorum: false,
        quorum_size: cluster.peers.len().div_ceil(2) + 1,
        reachable_nodes: 1,
        election_term: cluster.election_term,
    }
}
