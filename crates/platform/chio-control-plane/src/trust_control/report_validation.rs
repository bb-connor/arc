#[path = "authority_admission.rs"]
mod authority_admission;
pub(crate) use authority_admission::{
    inspect_authority_state_blocking, run_blocking_authority_task,
};

use super::cluster::{
    cluster_authority_lease_view, cluster_authority_read_role, ClusterAuthorityReadRole,
    ClusterAuthorityServingEvidence,
};
use super::*;

/// Inspect an admitted authority view on the blocking pool. A term/quorum or
/// authority-head/live-key-set change before return refuses the result. The
/// caller must additionally bind any artifact's actual signer to this view.
pub(crate) async fn inspect_authority_state<T, F>(
    state: &TrustServiceState,
    inspect: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    authority_admission::run_blocking_authority_operation(state, move |state| {
        inspect_authority_state_blocking(state, inspect)
    })
    .await
}

/// Run a bounded commit whose operation checks final authority admission inside
/// its transaction before persistence. There is no outer post-commit refusal.
pub(crate) async fn run_authority_commit<T, F>(
    state: &TrustServiceState,
    commit: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    authority_admission::run_authority_commit(state, commit).await
}

pub(crate) fn budget_visibility_matches(
    allowed: bool,
    invocation_count: Option<u32>,
    max_invocations: Option<u32>,
) -> bool {
    match (allowed, invocation_count, max_invocations) {
        (true, Some(_), _) => true,
        (true, None, _) => false,
        (false, Some(count), Some(max)) => count >= max,
        (false, Some(_), None) => true,
        (false, None, Some(0)) => true,
        (false, None, Some(_)) => false,
        (false, None, None) => false,
    }
}

pub(crate) fn normalize_cluster_url(value: &str) -> Result<String, CliError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CliError::cli_other_error(
            "cluster URL must not be empty".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

/// Shape of a configured cluster URL: http(s), plaintext only to a loopback
/// literal, no credentials, query or fragment, and never a link-local or cloud
/// metadata literal. Every other address class is enforced by the peer client's
/// egress contract when it connects.
pub(crate) fn normalize_cluster_config_url(value: &str) -> Result<String, CliError> {
    let normalized = normalize_cluster_url(value)?;
    let parsed = Url::parse(&normalized).map_err(|error| {
        CliError::cli_other_error(format!("cluster URL must be valid: {error}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(CliError::cli_other_error(format!(
                "cluster URL scheme `{scheme}` is not allowed"
            )));
        }
    }
    if parsed.scheme() == "http"
        && !matches!(parsed.host(),
        Some(Host::Ipv4(address)) if address.is_loopback())
        && !matches!(parsed.host(), Some(Host::Ipv6(address)) if address.is_loopback())
    {
        return Err(CliError::cli_other_error(
            "plaintext cluster URLs require a literal loopback address".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain username or password material".to_string(),
        ));
    }
    if parsed.query().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain a query string".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain a fragment".to_string(),
        ));
    }
    let reserved = match parsed.host() {
        Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
        Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
        Some(Host::Domain(_)) => None,
        None => {
            return Err(CliError::cli_other_error(
                "cluster URL must include a host".to_string(),
            ))
        }
    }
    .filter(|address| chio_egress_contract::address_is_reserved(*address));
    if let Some(address) = reserved {
        let host = address.to_string();
        let link_local = match address {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or_else(|| v6.is_unicast_link_local(), |v4| v4.is_link_local()),
        };
        let refusal = if link_local {
            chio_egress_contract::HttpEgressError::LinkLocalDenied { host }
        } else {
            chio_egress_contract::HttpEgressError::ReservedAddressDenied { host }
        };
        return Err(super::service_runtime::client::egress_refusal(refusal));
    }
    Ok(normalized)
}

pub(crate) fn bearer_token_from_headers(headers: &HeaderMap) -> Result<String, Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided = header.strip_prefix("Bearer ").unwrap_or_default();
    if !provided.is_empty() {
        return Ok(provided.to_string());
    }
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid issuance bearer token",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"chio-passport-issuance\""),
    );
    Err(response)
}

/// Header a follower sets when it forwards an authority mutation to the
/// leader: the authority lease term the follower observed. It only narrows a
/// request; a mismatching term refuses and it grants nothing.
pub(crate) const FORWARDED_AUTHORITY_TERM_HEADER: &str = "x-chio-forwarded-authority-term";

/// Authenticate the bearer caller credential and require `scope`.
pub(crate) fn validate_caller(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    scope: super::caller_credentials::Scope,
) -> Result<super::caller_credentials::AuthenticatedCaller, Response> {
    config
        .access
        .credentials()
        .validate_caller(headers, scope)
        .map_err(super::caller_credentials::CallerAuthError::into_response)
}

fn forwarded_authority_term(headers: &HeaderMap) -> Result<Option<u64>, Response> {
    let mut values = headers.get_all(FORWARDED_AUTHORITY_TERM_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "forwarded authority term header must appear once",
        ));
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Some)
        .ok_or_else(|| {
            plain_http_error(StatusCode::BAD_REQUEST, "invalid forwarded authority term")
        })
}

/// Authenticate an authority mutation (`authority:admin`) and return the
/// forwarded authority term when a follower forwarded it.
pub(crate) fn validate_authority_mutation_auth(
    headers: &HeaderMap,
    state: &TrustServiceState,
) -> Result<Option<u64>, Response> {
    validate_caller(
        headers,
        &state.config,
        super::caller_credentials::Scope::AuthorityAdmin,
    )?;
    let term = forwarded_authority_term(headers)?;
    validate_authority_mutation_term(state, term)?;
    Ok(term)
}

/// Recheck a forwarded mutation against the live lease at execution time.
/// Queueing must not transfer a request from an earlier election into a new term.
pub(crate) fn validate_authority_mutation_term(
    state: &TrustServiceState,
    term: Option<u64>,
) -> Result<(), Response> {
    let Some(term) = term else {
        return Ok(());
    };
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for authority mutation",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority mutation",
        ));
    }
    if term != authority_lease.term {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "cluster authority mutation term does not match the current lease",
        ));
    }
    Ok(())
}

/// Authenticate capability issuance (`capabilities:issue`) and return the
/// forwarded authority term when a follower forwarded it.
pub(crate) fn validate_authority_issue_auth(
    headers: &HeaderMap,
    state: &TrustServiceState,
) -> Result<Option<u64>, Response> {
    validate_caller(
        headers,
        &state.config,
        super::caller_credentials::Scope::CapabilitiesIssue,
    )?;
    let term = forwarded_authority_term(headers)?;
    validate_authority_mutation_term(state, term)?;
    Ok(term)
}

pub(crate) fn enforce_authority_mutation_fence(
    state: &TrustServiceState,
) -> Result<Option<ClusterAuthorityLeaseView>, Response> {
    if state.cluster.is_some() {
        let status = load_authority_status_for_state(state)?;
        let public = status.public_key.as_deref().ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority replication from the elected leader is unresolved",
            )
        })?;
        let key = PublicKey::from_hex(public).map_err(|error| {
            plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
        })?;
        authority_admission::signing_admission(state, &key)?;
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Ok(None);
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority mutation",
        ));
    }
    if let Some(path) = state.config.authority_db_path.as_deref() {
        open_authority_for_state(state, path)
            .and_then(|authority| {
                authority
                    .enforce_cluster_fence(&authority_lease.leader_url, authority_lease.term)
                    .map_err(CliError::from)
            })
            .map_err(|error| plain_http_error(StatusCode::CONFLICT, &error.to_string()))?;
    }
    Ok(Some(authority_lease))
}

pub(crate) fn refresh_authority_mutation_fence(state: &TrustServiceState) -> Result<(), Response> {
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Ok(());
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority fence refresh",
        ));
    }
    let Some(path) = state.config.authority_db_path.as_deref() else {
        return Ok(());
    };
    open_authority_for_state(state, path)
        .and_then(|authority| {
            authority
                .seed_cluster_fence(Some(&authority_lease.leader_url), authority_lease.term)
                .map_err(CliError::from)
        })
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedControlReadPrincipal {
    AdminService,
    TenantRead { tenant_id: String },
}

impl ResolvedControlReadPrincipal {
    pub(crate) fn receipt_read_context(&self) -> ReceiptReadContext {
        match self {
            Self::AdminService => ReceiptReadContext::admin_service(),
            Self::TenantRead { tenant_id } => {
                ReceiptReadContext::authenticated_tenant(tenant_id.clone())
            }
        }
    }

    pub(crate) fn authorize_evidence_export_query(
        &self,
        mut query: EvidenceExportQuery,
    ) -> Result<EvidenceExportQuery, Response> {
        match self {
            Self::AdminService => Ok(query),
            Self::TenantRead { tenant_id } => {
                match &query.read_boundary {
                    Some(ReceiptReadBoundary::AdminAll) => {
                        return Err(plain_http_error(
                            StatusCode::FORBIDDEN,
                            "tenant credential cannot request admin-all evidence export",
                        ));
                    }
                    Some(ReceiptReadBoundary::TenantScoped { tenant }) if tenant != tenant_id => {
                        return Err(plain_http_error(
                            StatusCode::FORBIDDEN,
                            "tenant credential cannot export evidence for another tenant",
                        ));
                    }
                    Some(ReceiptReadBoundary::TenantScoped { .. }) => {}
                    None => {
                        query.read_boundary = Some(ReceiptReadBoundary::TenantScoped {
                            tenant: tenant_id.clone(),
                        });
                    }
                }
                if query
                    .tenant
                    .as_deref()
                    .is_some_and(|tenant| tenant != tenant_id)
                {
                    return Err(plain_http_error(
                        StatusCode::FORBIDDEN,
                        "tenant credential cannot narrow evidence export to another tenant",
                    ));
                }
                query.tenant = Some(tenant_id.clone());
                Ok(query)
            }
        }
    }
}

/// Authenticate a read caller requiring `scope` and resolve its read boundary:
/// a `Deployment` credential reads its deployment, a `Tenant(t)` credential
/// only tenant `t`.
pub(crate) fn resolve_control_read_principal(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    scope: super::caller_credentials::Scope,
) -> Result<ResolvedControlReadPrincipal, Response> {
    let caller = validate_caller(headers, config, scope)?;
    Ok(match caller.tenant_authority {
        super::caller_credentials::TenantAuthority::Deployment => {
            ResolvedControlReadPrincipal::AdminService
        }
        super::caller_credentials::TenantAuthority::Tenant(tenant_id) => {
            ResolvedControlReadPrincipal::TenantRead { tenant_id }
        }
    })
}

pub(crate) fn validate_metered_billing_reconciliation_request(
    request: &MeteredBillingReconciliationUpdateRequest,
) -> Result<(), String> {
    if request.receipt_id.trim().is_empty() {
        return Err("receiptId must not be empty".to_string());
    }
    if request.adapter_kind.trim().is_empty() {
        return Err("adapterKind must not be empty".to_string());
    }
    if request.evidence_id.trim().is_empty() {
        return Err("evidenceId must not be empty".to_string());
    }
    if request.observed_units == 0 {
        return Err("observedUnits must be greater than zero".to_string());
    }
    if request.billed_cost.units == 0 {
        return Err("billedCost.units must be greater than zero".to_string());
    }
    if request.billed_cost.currency.trim().is_empty() {
        return Err("billedCost.currency must not be empty".to_string());
    }
    if request.recorded_at == 0 {
        return Err("recordedAt must be greater than zero".to_string());
    }
    if request
        .evidence_sha256
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("evidenceSha256 must not be empty when provided".to_string());
    }
    Ok(())
}

fn open_authority_for_state(
    state: &TrustServiceState,
    path: &Path,
) -> Result<SqliteCapabilityAuthority, CliError> {
    SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
        path,
        state.finding_challenge_clock.clone(),
        state.config.authority_replication_clock_policy()?,
    )
    .map_err(CliError::from)
}

pub(crate) fn load_capability_authority(
    state: &TrustServiceState,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    load_capability_authority_with_lineage_mode(state, true)
}

pub(crate) fn load_capability_authority_with_deferred_lineage(
    state: &TrustServiceState,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    load_capability_authority_with_lineage_mode(state, false)
}

fn load_capability_authority_with_lineage_mode(
    state: &TrustServiceState,
    persist_lineage_immediately: bool,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    let config = &state.config;
    let wrap = |inner: Box<dyn CapabilityAuthority>| match state.receipt_store.as_ref() {
        Some(receipt_store) => issuance::wrap_capability_authority_with_receipt_store(
            inner,
            config.issuance_policy.clone(),
            config.runtime_assurance_policy.clone(),
            Arc::clone(receipt_store),
            config.budget_db_path.as_deref(),
            persist_lineage_immediately,
        ),
        None if persist_lineage_immediately => issuance::wrap_capability_authority(
            inner,
            config.issuance_policy.clone(),
            config.runtime_assurance_policy.clone(),
            None,
            config.budget_db_path.as_deref(),
        ),
        None => issuance::wrap_capability_authority_with_deferred_lineage(
            inner,
            config.issuance_policy.clone(),
            config.runtime_assurance_policy.clone(),
            None,
            config.budget_db_path.as_deref(),
        ),
    };
    if let Some(keyring) = state.authority_keyring.as_ref() {
        let authority = keyring.capability_authority().map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "witnessed capability authority is unavailable",
            )
        })?;
        return authority_admission::admit_capability_authority(state, wrap(Box::new(authority)));
    }
    match (
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    ) {
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires either --authority-seed-file or --authority-db, not both",
        )),
        (Some(path), None) => {
            let keypair = crate::load_existing_authority_keypair(path).map_err(|error| {
                plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
            })?;
            authority_admission::admit_capability_authority(state, wrap(Box::new(LocalCapabilityAuthority::new_with_clock(keypair, state.finding_challenge_clock.clone()))))
        }
        (None, Some(path)) => {
            let authority = open_authority_for_state(state, path).map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
            authority_admission::admit_capability_authority(state, wrap(Box::new(authority)))
        },
        (None, None) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        )),
    }
}

pub(crate) fn load_authority_status_for_state(
    state: &TrustServiceState,
) -> Result<TrustAuthorityStatus, Response> {
    let Some(keyring) = state.authority_keyring.as_ref() else {
        if let Some(path) = state.config.authority_db_path.as_deref() {
            let unavailable = || {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority replication from the elected leader is unresolved",
                )
            };
            let role = if state.cluster.is_some() {
                Some(cluster_authority_read_role(state).ok_or_else(unavailable)?)
            } else {
                None
            };
            let verification = if matches!(
                &role,
                Some(ClusterAuthorityReadRole {
                    evidence: ClusterAuthorityServingEvidence::ConfirmedFollower { .. },
                    ..
                })
            ) {
                public_replicated_authority_verification_status(
                    path,
                    &state.config,
                    &state.finding_challenge_clock,
                )
            } else {
                public_authority_verification_status(
                    path,
                    &state.config,
                    &state.finding_challenge_clock,
                )
            }
            .map_err(|error| {
                plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
            })?;
            let now = state
                .finding_challenge_clock
                .unix_millis()
                .map_err(|error| {
                    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
                })?;
            if !verification.is_live_at(now) {
                return Err(unavailable());
            }
            if let Some(before) = role.as_ref() {
                let after = cluster_authority_read_role(state).ok_or_else(unavailable)?;
                if before.context != after.context
                    || !authority_admission::role_accepts_view(before, &verification, now)
                    || !authority_admission::role_accepts_view(&after, &verification, now)
                {
                    return Err(unavailable());
                }
            }
            return Ok(authority_status_response(
                "sqlite".to_string(),
                verification.status,
            ));
        }
        return load_authority_status(&state.config);
    };
    let status = keyring.authority_status().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "witnessed capability authority state is unavailable",
        )
    })?;
    let generation = status.signing_epoch.checked_add(1).ok_or_else(|| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "witnessed capability authority generation overflow",
        )
    })?;
    Ok(TrustAuthorityStatus {
        configured: true,
        backend: Some("enterprise_keyring".to_string()),
        public_key: Some(status.public_key.to_hex()),
        generation: Some(generation),
        rotated_at: status.activated_at,
        issuer_state: None,
        applies_to_future_sessions_only: true,
        trusted_public_keys: status
            .witnessed_verification_keys
            .into_iter()
            .map(|key| key.to_hex())
            .collect(),
    })
}

pub(crate) fn load_authority_status(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Ok(TrustAuthorityStatus {
            configured: false,
            backend: None,
            public_key: None,
            generation: None,
            rotated_at: None,
            issuer_state: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        });
    };
    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            issuer_state: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Ok(None) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: None,
            generation: None,
            rotated_at: None,
            issuer_state: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

pub(crate) fn rotate_authority(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        ));
    };
    match rotate_authority_keypair(path) {
        Ok(public_key) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            issuer_state: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

pub(crate) fn rotate_authority_for_state(
    state: &TrustServiceState,
) -> Result<TrustAuthorityStatus, Response> {
    let Some(keyring) = state.authority_keyring.as_ref() else {
        if let Some(path) = state.config.authority_db_path.as_deref() {
            let status = open_authority_for_state(state, path)
                .and_then(|authority| authority.rotate().map_err(CliError::from))
                .map_err(|error| {
                    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
                })?;
            return Ok(authority_status_response("sqlite".to_string(), status));
        }
        return rotate_authority(&state.config);
    };
    let seed_path = state
        .authority_keyring_seed_path
        .as_deref()
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "witnessed capability authority seed custody is unavailable",
            )
        })?;
    keyring
        .rotate_remote_authority_seed(seed_path)
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "witnessed capability authority rotation failed",
            )
        })?;
    load_authority_status_for_state(state)
}

pub(crate) fn authority_status_response(
    backend: String,
    status: AuthorityStatus,
) -> TrustAuthorityStatus {
    TrustAuthorityStatus {
        configured: true,
        backend: Some(backend),
        public_key: Some(status.public_key.to_hex()),
        generation: Some(status.generation),
        rotated_at: Some(status.rotated_at),
        issuer_state: Some(status.issuer_state),
        applies_to_future_sessions_only: false,
        trusted_public_keys: status
            .trusted_public_keys
            .into_iter()
            .map(|public_key| public_key.to_hex())
            .collect(),
    }
}
