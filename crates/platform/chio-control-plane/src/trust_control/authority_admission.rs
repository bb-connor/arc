//! Bounded authority inspection and process-local admission checks.
use super::super::cluster::cluster_consensus_view;
use super::*;

const AUTHORITY_CHANGED: &str = "authority state changed during inspection";
const CLUSTER_CHANGED: &str = "cluster authority context changed during inspection";

#[derive(PartialEq, Eq)]
struct InspectionClusterContext {
    self_url: String,
    leader_url: String,
    election_term: u64,
}

fn inspection_cluster_context(
    state: &TrustServiceState,
) -> Result<Option<InspectionClusterContext>, Response> {
    if state.cluster.is_none() {
        return Ok(None);
    }
    let view = cluster_consensus_view(state)
        .ok_or_else(|| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, CLUSTER_CHANGED))?;
    let leader_url = view
        .leader_url
        .filter(|_| view.has_quorum)
        .ok_or_else(|| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, CLUSTER_CHANGED))?;
    Ok(Some(InspectionClusterContext {
        self_url: view.self_url,
        leader_url,
        election_term: view.election_term,
    }))
}

/// Bound blocking work before submission. The blocking task owns admission
/// through completion even when the caller aborts its async future.
pub(crate) async fn run_blocking_authority_operation<T, F>(
    state: &TrustServiceState,
    operation: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    run_blocking_authority_task(state, move |state| {
        let context = inspection_cluster_context(state)?;
        let result = operation(state)?;
        if context != inspection_cluster_context(state)? {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                CLUSTER_CHANGED,
            ));
        }
        Ok(result)
    })
    .await
}

/// Submit an operation that owns final admission inside its commit transaction.
/// The worker checks initial quorum/context and holds the same process permit;
/// it adds no refusal after an operation may have durably committed. A guard
/// observation is not atomic with an unrelated database's commit.
pub(crate) async fn run_authority_commit<T, F>(
    state: &TrustServiceState,
    commit: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    run_blocking_authority_task(state, move |state| {
        inspection_cluster_context(state)?;
        commit(state)
    })
    .await
}

async fn run_blocking_authority_task<T, F>(
    state: &TrustServiceState,
    operation: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    let permit = state
        .authority_inspection_lane
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority inspection is at capacity",
            )
        })?;
    let inspected_state = state.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(&inspected_state)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority inspection did not complete",
        )
    })?
}

/// Inspect inside an already-admitted, bounded blocking worker. This guard
/// creates no task, permit or file lock. Complete it successfully before the
/// surrounding registry transaction persists any mutation. The caller binds
/// any artifact's actual signer to the admitted live head before and after
/// signing; an opaque result cannot establish that binding for the caller.
pub(crate) fn inspect_authority_state_blocking<T, F>(
    state: &TrustServiceState,
    inspect: F,
) -> Result<T, Response>
where
    F: FnOnce(&TrustServiceState) -> Result<T, Response>,
{
    let context = inspection_cluster_context(state)?;
    let before = authority_view_bytes(state)?;
    let result = inspect(state)?;
    if before != authority_view_bytes(state)? {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            AUTHORITY_CHANGED,
        ));
    }
    if context != inspection_cluster_context(state)? {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            CLUSTER_CHANGED,
        ));
    }
    Ok(result)
}

fn authority_view_bytes(state: &TrustServiceState) -> Result<Vec<u8>, Response> {
    canonical_json_bytes(&load_authority_status_for_state(state)?).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority inspection could not authenticate its view",
        )
    })
}

pub(super) fn role_accepts_view(
    role: &ClusterAuthorityReadRole,
    view: &chio_store_sqlite::authority::AuthorityVerificationStatus,
    now: chio_security_types::clock::UnixMillis,
) -> bool {
    if !view.is_live_at(now)
        || role
            .refused_history_commitments
            .iter()
            .any(|commitment| !view.contains_authenticated_history(commitment))
    {
        return false;
    }
    match &role.evidence {
        ClusterAuthorityServingEvidence::ConfirmedFollower { envelope_digest } => {
            view.matches_imported_envelope(envelope_digest)
        }
        ClusterAuthorityServingEvidence::ElectedLeader {
            quorum_size,
            agreements,
        } => {
            view.holds_current_signing_custody
                && view
                    .status
                    .trusted_public_keys
                    .contains(&view.status.public_key)
                && agreements
                    .iter()
                    .filter(|agreement| {
                        now.as_secs() < agreement.expires_at
                            && view.contains_authenticated_history(&agreement.chain_commitment)
                    })
                    .count()
                    .saturating_add(1)
                    >= *quorum_size
        }
    }
}

const UNRESOLVED_SIGNER: &str = "authority replication from the elected leader is unresolved";

pub(super) fn signing_admission(
    state: &TrustServiceState,
    expected: &PublicKey,
) -> Result<Option<super::super::cluster::ClusterAuthorityReadContext>, Response> {
    let unavailable = || plain_http_error(StatusCode::SERVICE_UNAVAILABLE, UNRESOLVED_SIGNER);
    let before = if state.cluster.is_some() {
        let role = cluster_authority_read_role(state).ok_or_else(unavailable)?;
        if !matches!(
            role.evidence,
            ClusterAuthorityServingEvidence::ElectedLeader { .. }
        ) {
            return Err(unavailable());
        }
        Some(role.context)
    } else {
        None
    };
    let status = load_authority_status_for_state(state)?;
    let expected_hex = expected.to_hex();
    if status.public_key.as_deref() != Some(expected_hex.as_str())
        || !status.trusted_public_keys.contains(&expected_hex)
    {
        return Err(unavailable());
    }
    if state.cluster.is_some() {
        let after = cluster_authority_read_role(state).ok_or_else(unavailable)?;
        if before.as_ref() != Some(&after.context)
            || !matches!(
                after.evidence,
                ClusterAuthorityServingEvidence::ElectedLeader { .. }
            )
        {
            return Err(unavailable());
        }
    }
    Ok(before)
}

pub(super) fn admit_capability_authority(
    state: &TrustServiceState,
    inner: Box<dyn CapabilityAuthority>,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    let key = inner.authority_public_key();
    let context = signing_admission(state, &key)?;
    Ok(Box::new(AdmittedCapabilityAuthority {
        state: state.clone(),
        inner,
        key,
        context,
    }))
}

struct AdmittedCapabilityAuthority {
    state: TrustServiceState,
    inner: Box<dyn CapabilityAuthority>,
    key: PublicKey,
    context: Option<super::super::cluster::ClusterAuthorityReadContext>,
}

impl AdmittedCapabilityAuthority {
    fn check(&self) -> Result<(), chio_kernel::KernelError> {
        let context = signing_admission(&self.state, &self.key).map_err(|_| {
            chio_kernel::KernelError::CapabilityIssuanceDenied(UNRESOLVED_SIGNER.to_string())
        })?;
        if context != self.context {
            return Err(chio_kernel::KernelError::CapabilityIssuanceDenied(
                "cluster authority context changed before capability return".to_string(),
            ));
        }
        Ok(())
    }

    fn issue(
        &self,
        issue: impl FnOnce(
            &dyn CapabilityAuthority,
        ) -> Result<CapabilityToken, chio_kernel::KernelError>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.check()?;
        let token = issue(self.inner.as_ref())?;
        if token.issuer != self.key {
            return Err(chio_kernel::KernelError::CapabilityIssuanceDenied(
                "capability signer differs from admitted live authority head".to_string(),
            ));
        }
        self.check()?;
        Ok(token)
    }
}

impl CapabilityAuthority for AdmittedCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.key.clone()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        load_authority_status_for_state(&self.state)
            .and_then(|status| {
                trusted_public_keys_from_status(&status).map_err(|error| {
                    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
                })
            })
            .unwrap_or_default()
    }

    fn check_issuer_lifecycle(
        &self,
        issuer: &PublicKey,
        issued_at: u64,
        now: u64,
    ) -> Result<(), chio_kernel::KernelError> {
        self.check()?;
        self.inner.check_issuer_lifecycle(issuer, issued_at, now)
    }

    fn workload_binding(
        &self,
    ) -> Option<chio_kernel::authority::CapabilityAuthorityWorkloadBinding> {
        self.inner.workload_binding()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue(|authority| authority.issue_capability(subject, scope, ttl_seconds))
    }

    fn issue_aggregate_family_root(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        max_invocations: u32,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue(|authority| {
            authority.issue_aggregate_family_root(subject, scope, ttl_seconds, max_invocations)
        })
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue(|authority| {
            authority.issue_capability_with_attestation(subject, scope, ttl_seconds, attestation)
        })
    }

    fn issue_capability_with_security_context(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        attestation: Option<RuntimeAttestationEvidence>,
        security: &chio_kernel::authority::CapabilityIssuanceContext,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue(|authority| {
            authority.issue_capability_with_security_context(
                subject,
                scope,
                ttl_seconds,
                attestation,
                security,
            )
        })
    }
}
