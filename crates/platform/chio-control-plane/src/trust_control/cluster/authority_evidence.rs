//! Authority convergence and serving evidence are separate from transport,
//! budget witnesses and revocations. Internal exports never require admission.
use super::*;
use chio_store_sqlite::authority::{AuthorityPeerHistory, SqliteAuthorityInspection};

const UNRESOLVED: &str = "authority replication from the elected leader is unresolved";
const SOURCE_IDENTITY_MISMATCH: &str =
    "authority peer self identity does not match configured source";

fn identity_refused() -> CliError {
    CliError::cli_other_error(SOURCE_IDENTITY_MISMATCH.to_string())
}

/// Clear serving evidence as soon as authenticated peer metadata identifies
/// a different logical node. Transport and independent replication continue.
pub(super) fn observe_peer_authority_identity(
    state: &TrustServiceState,
    peer_url: &str,
    status: &ClusterStatusResponse,
) {
    if state.config.authority_db_path.is_some() && status.self_url != peer_url {
        update_peer_authority_error(state, peer_url, identity_refused().to_string());
    }
}

pub(super) fn authority_sync_context(
    state: &TrustServiceState,
) -> Option<ClusterAuthorityReadContext> {
    let view = cluster_consensus_view(state)?;
    let leader_url = view.leader_url.filter(|_| view.has_quorum)?;
    Some(ClusterAuthorityReadContext {
        self_url: view.self_url,
        leader_url,
        election_term: view.election_term,
    })
}

fn unresolved() -> CliError {
    CliError::cli_other_error(json!({"error": UNRESOLVED}).to_string())
}

fn inspection_error(error: chio_store_sqlite::authority::AuthorityInspectionError) -> CliError {
    match error {
        chio_store_sqlite::authority::AuthorityInspectionError::Store(error) => error.into(),
        chio_store_sqlite::authority::AuthorityInspectionError::Uninitialized => unresolved(),
    }
}

fn open_inspection(state: &TrustServiceState) -> Result<SqliteAuthorityInspection, CliError> {
    let path = state
        .config
        .authority_db_path
        .as_deref()
        .ok_or_else(unresolved)?;
    SqliteAuthorityInspection::open_existing_with_clock_and_replication_policy(
        path,
        state.finding_challenge_clock.clone(),
        state.config.authority_replication_clock_policy()?,
    )
    .map_err(inspection_error)
}

fn apply_envelope(
    state: &TrustServiceState,
    snapshot: &AuthoritySnapshotView,
) -> Result<(), CliError> {
    let path = state
        .config
        .authority_db_path
        .as_deref()
        .ok_or_else(unresolved)?;
    SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
        path,
        state.finding_challenge_clock.clone(),
        state.config.authority_replication_clock_policy()?,
    )?
    .apply_signed_snapshot(snapshot)?;
    Ok(())
}

fn refuse_history(reason: &str) -> CliError {
    chio_kernel::AuthorityStoreError::Fence(reason.to_string()).into()
}

/// Accept a peer envelope according to the context sampled before its fetch.
/// Nonleaders never replace a follower's leader-confirmed state/envelope.
pub(super) fn accept_peer_authority_envelope(
    state: &TrustServiceState,
    peer_url: &str,
    snapshot: &AuthoritySnapshotView,
    context: &Option<ClusterAuthorityReadContext>,
) -> Result<Option<AuthorityAgreementConfirmation>, CliError> {
    let evidence = open_inspection(state)?
        .peer_chain_evidence(snapshot)
        .map_err(inspection_error)?;
    // Authenticated newer/fork knowledge survives an import or context refusal.
    // Transport errors and envelopes that fail authentication never get here.
    if matches!(
        evidence.history,
        AuthorityPeerHistory::Newer | AuthorityPeerHistory::Conflicting
    ) {
        update_peer_state(state, peer_url, |peer| {
            if let Some(witness) = peer.authority_refused_history.as_mut() {
                witness.observe(&evidence);
            } else {
                peer.authority_refused_history = Some(AuthorityHistoryWitness::new(&evidence));
            }
        });
    }
    if state.cluster.is_some() && *context != authority_sync_context(state) {
        return Err(unresolved());
    }
    let Some(context) = context else {
        if state.cluster.is_none() {
            apply_envelope(state, snapshot)?;
            return Ok(None);
        }
        // No quorum admits trust. A genuine extension can still converge;
        // an old/same-state relay must not replace prior confirmation.
        if evidence.history == AuthorityPeerHistory::Newer {
            apply_envelope(state, snapshot)?;
        } else if evidence.history == AuthorityPeerHistory::Conflicting {
            return Err(refuse_history(
                "peer authority history conflicts with local authenticated history",
            ));
        }
        return Err(unresolved());
    };
    if context.leader_url == peer_url && context.self_url != peer_url {
        apply_envelope(state, snapshot)?;
        return Ok(None);
    }
    match evidence.history {
        AuthorityPeerHistory::ConsistentPrefix => {}
        AuthorityPeerHistory::Newer if context.leader_url == context.self_url => {
            // The elected node may learn a recovered head, but import never
            // gives it private custody. Admission checks the actual live head.
            apply_envelope(state, snapshot)?;
        }
        AuthorityPeerHistory::Newer => {
            return Err(refuse_history(
                "nonleader peer advertises newer authenticated authority history",
            ));
        }
        AuthorityPeerHistory::Conflicting => {
            return Err(refuse_history(
                "peer authority history conflicts with local authenticated history",
            ));
        }
    }
    if context.leader_url == context.self_url {
        Ok(Some(AuthorityAgreementConfirmation {
            leader_url: context.leader_url.clone(),
            election_term: context.election_term,
            chain_commitment: evidence.chain_commitment,
            expires_at: evidence.expires_at,
        }))
    } else {
        Ok(None)
    }
}

fn source_is_stable_leader(
    before: &ClusterStatusResponse,
    after: &ClusterStatusResponse,
    peer_url: &str,
) -> bool {
    before.self_url == peer_url
        && after.self_url == peer_url
        && before.leader_url.as_deref() == Some(peer_url)
        && after.leader_url.as_deref() == Some(peer_url)
        && before.role == "leader"
        && after.role == "leader"
        && before.has_quorum
        && after.has_quorum
        && before.election_term == after.election_term
}

fn status_matches_signed_state(
    status: &TrustAuthorityStatus,
    snapshot: &AuthoritySnapshotView,
) -> bool {
    status.configured
        && status.backend.as_deref() == Some("sqlite")
        && status.public_key.as_deref() == Some(snapshot.snapshot.public_key_hex.as_str())
        && status.generation == Some(snapshot.snapshot.generation)
        && status.rotated_at == Some(snapshot.snapshot.rotated_at)
        && status.issuer_state.as_ref() == Some(&snapshot.snapshot)
}

/// A convergence import does not authorize serving. The elected source must
/// itself admit that exact signed state under a stable leader/quorum/term.
pub(super) fn sync_authority_serving_evidence(
    state: &TrustServiceState,
    peer_url: &str,
    client: &TrustControlClient,
    peer_before: &ClusterStatusResponse,
) -> Result<(), CliError> {
    if state.config.authority_db_path.is_none() {
        return Ok(());
    }
    let context = authority_sync_context(state);
    let snapshot = client.authority_snapshot()?;
    let agreement = accept_peer_authority_envelope(state, peer_url, &snapshot, &context)?;
    if peer_before.self_url != peer_url {
        return Err(identity_refused());
    }
    let confirmation = if context
        .as_ref()
        .is_some_and(|context| context.leader_url == peer_url && context.self_url != peer_url)
    {
        // Internal export remains available while this public admission is
        // unresolved, so replicas can seed the leader's signed prefix quorum.
        let admitted = client.authority_status()?;
        let peer_after = client.cluster_status()?;
        if !source_is_stable_leader(peer_before, &peer_after, peer_url)
            || !status_matches_signed_state(&admitted, &snapshot)
        {
            return Err(unresolved());
        }
        let context = context.as_ref().ok_or_else(unresolved)?;
        Some(AuthorityImportConfirmation {
            leader_url: context.leader_url.clone(),
            election_term: context.election_term,
            envelope_digest: snapshot.envelope_digest()?,
        })
    } else if agreement.is_some() {
        // Prefix agreement must come from the configured logical peer before
        // and after its envelope. This internal sample never calls public
        // serving admission and cannot create a convergence bootstrap cycle.
        let peer_after = client.cluster_status()?;
        observe_peer_authority_identity(state, peer_url, &peer_after);
        if peer_after.self_url != peer_url {
            return Err(identity_refused());
        }
        None
    } else {
        None
    };
    if state.cluster.is_some() && context != authority_sync_context(state) {
        return Err(unresolved());
    }
    clear_peer_authority_error(state, peer_url, confirmation, agreement);
    Ok(())
}
