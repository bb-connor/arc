use super::cluster_replay::consume_cluster_peer_nonce_durably;
use super::*;

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
    if value.is_empty() {
        return Err(CliError::cli_other_error(
            "cluster URL must not be empty".to_string(),
        ));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain whitespace or control characters".to_string(),
        ));
    }
    let mut parsed = Url::parse(value).map_err(|error| {
        CliError::cli_other_error(format!("cluster URL must be valid: {error}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(CliError::cli_other_error(format!(
            "cluster URL scheme `{}` is not allowed",
            parsed.scheme()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain username or password material".to_string(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain a query string or fragment".to_string(),
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain a path".to_string(),
        ));
    }
    if parsed.host().is_none() {
        return Err(CliError::cli_other_error(
            "cluster URL must include a host".to_string(),
        ));
    }
    parsed.set_path("");
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub(crate) fn normalize_cluster_config_url(
    value: &str,
    allow_local: bool,
) -> Result<String, CliError> {
    let normalized = normalize_cluster_url(value)?;
    let parsed = Url::parse(&normalized).map_err(|error| {
        CliError::cli_other_error(format!("cluster URL must be valid: {error}"))
    })?;
    if parsed.scheme() != "https" && !allow_local {
        return Err(CliError::cli_other_error(
            "cluster URL must use HTTPS unless --allow-local-peer-urls is enabled".to_string(),
        ));
    }
    if allow_local {
        return Ok(normalized);
    }
    validate_cluster_url_host(&parsed)?;
    Ok(normalized)
}

fn validate_cluster_url_host(parsed: &Url) -> Result<(), CliError> {
    match parsed.host() {
        Some(Host::Ipv4(address)) => {
            if chio_external_guards::denied_external_guard_ip(IpAddr::V4(address)) {
                return Err(CliError::cli_other_error(format!(
                    "cluster URL must not target disallowed address `{address}` without --allow-local-peer-urls"
                )));
            }
        }
        Some(Host::Ipv6(address)) => {
            if chio_external_guards::denied_external_guard_ip(IpAddr::V6(address)) {
                return Err(CliError::cli_other_error(format!(
                    "cluster URL must not target disallowed address `{address}` without --allow-local-peer-urls"
                )));
            }
        }
        Some(Host::Domain(host)) => {
            let lower = host.to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                return Err(CliError::cli_other_error(
                    "cluster URL must not target localhost without --allow-local-peer-urls"
                        .to_string(),
                ));
            }
            let port = parsed.port_or_known_default().ok_or_else(|| {
                CliError::cli_other_error("cluster URL must include a resolvable port".to_string())
            })?;
            let addrs = (host, port).to_socket_addrs().map_err(|error| {
                CliError::cli_other_error(format!(
                    "cluster URL host `{host}` could not be resolved: {error}"
                ))
            })?;
            for addr in addrs {
                if chio_external_guards::denied_external_guard_ip(addr.ip()) {
                    return Err(CliError::cli_other_error(format!(
                        "cluster URL host `{host}` resolved to disallowed address `{}` without --allow-local-peer-urls",
                        addr.ip()
                    )));
                }
            }
        }
        None => {
            return Err(CliError::cli_other_error(
                "cluster URL must include a host".to_string(),
            ));
        }
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClusterPeerAuthContext {
    pub(crate) node_id: String,
    pub(crate) issued_at: i64,
    pub(crate) term: Option<u64>,
}

static CLUSTER_PEER_AUTH_FAILURES: LazyLock<Mutex<HashMap<String, Vec<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_cluster_peer_auth_failures(failures: &mut Vec<u64>, now: u64) {
    let cutoff = now.saturating_sub(CLUSTER_AUTH_FAILURE_WINDOW_SECS);
    failures.retain(|recorded_at| *recorded_at >= cutoff);
}

fn cluster_peer_auth_is_rate_limited(node_id: &str, now: u64) -> bool {
    let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() else {
        return false;
    };
    let Some(history) = failures.get_mut(node_id) else {
        return false;
    };
    prune_cluster_peer_auth_failures(history, now);
    if history.is_empty() {
        failures.remove(node_id);
        return false;
    }
    history.len() >= CLUSTER_AUTH_FAILURE_BURST
}

fn record_cluster_peer_auth_failure(node_id: &str) {
    let now = unix_timestamp_now();
    let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() else {
        return;
    };
    let history = failures.entry(node_id.to_string()).or_default();
    prune_cluster_peer_auth_failures(history, now);
    history.push(now);
}

pub(crate) fn clear_cluster_peer_auth_failures(node_id: &str) {
    if let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() {
        failures.remove(node_id);
    }
}

pub(crate) fn cluster_peer_auth_unverified_failure_key(node_id: &str, endpoint: &str) -> String {
    let payload = format!("{node_id}\0{endpoint}");
    format!("unverified:{}", sha256_hex(payload.as_bytes()))
}

pub(crate) fn cluster_request_body_digest<T: Serialize>(body: &T) -> Result<String, CliError> {
    canonical_json_bytes(body)
        .map(|canonical| sha256_hex(&canonical))
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to canonicalize cluster request body: {error}"
            ))
        })
}

pub(crate) fn cluster_empty_body_digest() -> String {
    sha256_hex(&[])
}

fn cluster_peer_auth_payload(
    node_id: &str,
    receiver_id: &str,
    method: &str,
    endpoint: &str,
    issued_at: i64,
    nonce: &str,
    term: Option<u64>,
    body_digest: &str,
) -> Result<Vec<u8>, CliError> {
    let node_id = normalize_cluster_url(node_id)?;
    let receiver_id = normalize_cluster_url(receiver_id)?;
    canonical_json_bytes(&json!({
        "bodyDigest": body_digest,
        "domain": CLUSTER_AUTH_SCHEME,
        "endpoint": endpoint,
        "issuedAt": issued_at,
        "method": method,
        "nonce": nonce,
        "peerId": node_id,
        "receiverId": receiver_id,
        "term": term,
    }))
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to encode cluster membership request: {error}"
        ))
    })
}

pub(crate) fn cluster_peer_auth_signature(
    signing_key: &Keypair,
    node_id: &str,
    receiver_id: &str,
    method: &str,
    endpoint: &str,
    issued_at: i64,
    nonce: &str,
    term: Option<u64>,
    body_digest: &str,
) -> Result<String, CliError> {
    let payload = cluster_peer_auth_payload(
        node_id,
        receiver_id,
        method,
        endpoint,
        issued_at,
        nonce,
        term,
        body_digest,
    )?;
    Ok(signing_key.sign(&payload).to_hex())
}

pub(crate) fn validate_cluster_peer_request(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    expected_method: &str,
    endpoint: &str,
    expected_body_digest: &str,
) -> Result<ClusterPeerAuthContext, Response> {
    let node_id = unique_cluster_auth_header(headers, CLUSTER_NODE_ID_HEADER)?
        .and_then(|value| normalize_cluster_url(value).ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let issued_at = unique_cluster_auth_header(headers, CLUSTER_AUTH_ISSUED_AT_HEADER)?
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let signature = unique_cluster_auth_header(headers, CLUSTER_AUTH_SIGNATURE_HEADER)?
        .and_then(|value| Signature::from_hex(value).ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let method = unique_cluster_auth_header(headers, CLUSTER_AUTH_METHOD_HEADER)?
        .filter(|value| *value == expected_method)
        .ok_or_else(cluster_peer_auth_error)?;
    let nonce = unique_cluster_auth_header(headers, CLUSTER_AUTH_NONCE_HEADER)?
        .filter(|value| {
            uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.get_version_num() == 4)
        })
        .ok_or_else(cluster_peer_auth_error)?;
    let term = unique_cluster_auth_header(headers, CLUSTER_AUTH_TERM_HEADER)?
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                plain_http_error(StatusCode::UNAUTHORIZED, "invalid cluster peer term header")
            })
        })
        .transpose()?;
    let body_digest = unique_cluster_auth_header(headers, CLUSTER_AUTH_BODY_DIGEST_HEADER)?
        .ok_or_else(cluster_peer_auth_error)?;
    if body_digest.len() != 64
        || !body_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "invalid cluster peer body digest",
        ));
    }
    if !bool::from(
        body_digest
            .as_bytes()
            .ct_eq(expected_body_digest.as_bytes()),
    ) {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer body digest does not match the request",
        ));
    }
    let unverified_failure_key = cluster_peer_auth_unverified_failure_key(&node_id, endpoint);
    let pinned_key = config
        .cluster_members
        .iter()
        .filter_map(|member| {
            normalize_cluster_url(&member.node_url)
                .ok()
                .filter(|member_url| member_url == &node_id)
                .map(|_| member.public_key.clone())
        })
        .next()
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::FORBIDDEN,
                "cluster peer is not in the pinned membership",
            )
        })?;
    let receiver_id = config
        .advertise_url
        .as_deref()
        .and_then(|value| normalize_cluster_url(value).ok())
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster receiver identity is not configured",
            )
        })?;
    let payload = cluster_peer_auth_payload(
        &node_id,
        &receiver_id,
        method,
        endpoint,
        issued_at,
        nonce,
        term,
        body_digest,
    )
    .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let now = unix_timestamp_now() as i64;
    if !pinned_key.verify(&payload, &signature) {
        if cluster_peer_auth_is_rate_limited(&unverified_failure_key, now as u64) {
            let mut response = plain_http_error(
                StatusCode::TOO_MANY_REQUESTS,
                "cluster peer authentication temporarily rate limited after repeated invalid signatures",
            );
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("60"),
            );
            return Err(response);
        }
        record_cluster_peer_auth_failure(&unverified_failure_key);
        return Err(cluster_peer_auth_error());
    }
    if cluster_peer_auth_is_rate_limited(&node_id, now as u64) {
        let mut response = plain_http_error(
            StatusCode::TOO_MANY_REQUESTS,
            "cluster peer authentication temporarily rate limited after repeated verified failures",
        );
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("60"),
        );
        return Err(response);
    }
    if issued_at > now.saturating_add(CLUSTER_AUTH_MAX_SKEW_SECS) {
        record_cluster_peer_auth_failure(&node_id);
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer auth timestamp is in the future",
        ));
    }
    if issued_at < now.saturating_sub(CLUSTER_AUTH_MAX_SKEW_SECS) {
        record_cluster_peer_auth_failure(&node_id);
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer auth timestamp expired outside the allowed skew window",
        ));
    }
    let replay_db_path = config.cluster_replay_db_path.as_deref().ok_or_else(|| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database is not configured",
        )
    })?;
    consume_cluster_peer_nonce_durably(replay_db_path, &node_id, nonce, issued_at, now)?;
    clear_cluster_peer_auth_failures(&node_id);
    Ok(ClusterPeerAuthContext {
        node_id,
        issued_at,
        term,
    })
}

fn unique_cluster_auth_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, Response> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(cluster_peer_auth_error());
    }
    first
        .map(|value| value.to_str().map_err(|_| cluster_peer_auth_error()))
        .transpose()
}

pub(crate) fn validate_cluster_peer_json_request<T: Serialize>(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    method: &str,
    endpoint: &str,
    body: &T,
) -> Result<ClusterPeerAuthContext, Response> {
    let body_digest = cluster_request_body_digest(body).map_err(|error| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("cluster request body cannot be canonicalized: {error}"),
        )
    })?;
    validate_cluster_peer_request(headers, config, method, endpoint, &body_digest)
}

pub(crate) fn validate_cluster_peer_empty_request(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    method: &str,
    endpoint: &str,
) -> Result<ClusterPeerAuthContext, Response> {
    validate_cluster_peer_request(
        headers,
        config,
        method,
        endpoint,
        &cluster_empty_body_digest(),
    )
}

fn cluster_peer_auth_error() -> Response {
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid cluster peer authentication",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(CLUSTER_AUTH_SCHEME),
    );
    response
}

pub(crate) fn enforce_authority_mutation_fence(
    state: &TrustServiceState,
) -> Result<Option<ClusterAuthorityLeaseView>, Response> {
    if state.cluster.is_some() {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "clustered capability-authority mutation is unsupported without a linearizable shared signing selector",
        ));
    }
    Ok(None)
}

pub(crate) fn refresh_authority_mutation_fence(state: &TrustServiceState) -> Result<(), Response> {
    if state.cluster.is_some() {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "clustered capability-authority mutation is unsupported without a linearizable shared signing selector",
        ));
    }
    Ok(())
}

pub(crate) fn validate_service_auth(
    headers: &HeaderMap,
    service_token: &str,
) -> Result<(), Response> {
    if service_token.is_empty() {
        return Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "control service token must be non-empty",
        ));
    }
    let Some(provided) = control_bearer_token(headers) else {
        return Err(missing_or_invalid_control_token());
    };
    if bool::from(provided.as_bytes().ct_eq(service_token.as_bytes())) {
        return Ok(());
    }
    Err(missing_or_invalid_control_token())
}

fn control_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut authorization_headers = headers.get_all(AUTHORIZATION).iter();
    let header = authorization_headers.next()?.to_str().ok()?;
    if authorization_headers.next().is_some() {
        return None;
    }
    let provided = header.strip_prefix("Bearer ")?;
    (!provided.is_empty()).then_some(provided)
}

fn missing_or_invalid_control_token() -> Response {
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid control bearer token",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedControlReadPrincipal {
    AdminService,
    DashboardRead,
    TenantRead { tenant_id: String },
}

impl ResolvedControlReadPrincipal {
    pub(crate) fn protect_response(&self, response: Response) -> Response {
        if matches!(self, Self::DashboardRead) {
            super::dashboard_auth::with_dashboard_no_store(response)
        } else {
            response
        }
    }

    pub(crate) fn receipt_read_context(&self) -> ReceiptReadContext {
        match self {
            Self::AdminService | Self::DashboardRead => ReceiptReadContext::admin_service(),
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
            Self::AdminService | Self::DashboardRead => Ok(query),
            Self::TenantRead { tenant_id } => {
                match &query.read_boundary {
                    Some(ReceiptReadBoundary::AdminAll) => {
                        return Err(plain_http_error(
                            StatusCode::FORBIDDEN,
                            "tenant read token cannot request admin-all evidence export",
                        ));
                    }
                    Some(ReceiptReadBoundary::TenantScoped { tenant }) if tenant != tenant_id => {
                        return Err(plain_http_error(
                            StatusCode::FORBIDDEN,
                            "tenant read token cannot export evidence for another tenant",
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
                        "tenant read token cannot narrow evidence export to another tenant",
                    ));
                }
                query.tenant = Some(tenant_id.clone());
                Ok(query)
            }
        }
    }
}

pub(crate) fn resolve_control_read_principal(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
) -> Result<ResolvedControlReadPrincipal, Response> {
    config
        .validate()
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let Some(provided) = control_bearer_token(headers) else {
        return Err(missing_or_invalid_control_token());
    };
    if bool::from(provided.as_bytes().ct_eq(config.service_token.as_bytes())) {
        return Ok(ResolvedControlReadPrincipal::AdminService);
    }
    for (tenant_id, token) in &config.tenant_read_tokens {
        if bool::from(provided.as_bytes().ct_eq(token.as_bytes())) {
            return Ok(ResolvedControlReadPrincipal::TenantRead {
                tenant_id: tenant_id.clone(),
            });
        }
    }
    Err(missing_or_invalid_control_token())
}

pub(crate) fn resolve_dashboard_or_control_read_principal(
    headers: &HeaderMap,
    state: &TrustServiceState,
) -> Result<ResolvedControlReadPrincipal, Response> {
    if headers.contains_key(AUTHORIZATION) {
        return resolve_control_read_principal(headers, &state.config)
            .map_err(super::dashboard_auth::with_dashboard_no_store);
    }
    super::dashboard_auth::validate_dashboard_session(headers, state)?;
    Ok(ResolvedControlReadPrincipal::DashboardRead)
}

pub(crate) fn validate_dashboard_or_service_auth(
    headers: &HeaderMap,
    state: &TrustServiceState,
) -> Result<ResolvedControlReadPrincipal, Response> {
    if headers.contains_key(AUTHORIZATION) {
        validate_service_auth(headers, &state.config.service_token)
            .map_err(super::dashboard_auth::with_dashboard_no_store)?;
        return Ok(ResolvedControlReadPrincipal::AdminService);
    }
    super::dashboard_auth::validate_dashboard_session(headers, state)?;
    Ok(ResolvedControlReadPrincipal::DashboardRead)
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

pub(crate) fn load_capability_authority(
    config: &TrustServiceConfig,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    match (
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    ) {
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires either --authority-seed-file or --authority-db, not both",
        )),
        (Some(path), None) => {
            let keypair = load_existing_authority_keypair(path).map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "capability authority signing custody is unavailable",
                )
            })?;
            issuance::wrap_capability_authority(
                Box::new(LocalCapabilityAuthority::new(keypair)),
                config.issuance_policy.clone(),
                config.runtime_assurance_policy.clone(),
                config.receipt_db_path.as_deref(),
                config.budget_db_path.as_deref(),
            )
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "capability issuance storage is unavailable",
                )
            })
        }
        (None, Some(path)) => SqliteCapabilityAuthority::open_existing(path)
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "capability authority storage is unavailable",
                )
            })
            .and_then(|authority| {
                issuance::wrap_capability_authority(
                    Box::new(authority),
                    config.issuance_policy.clone(),
                    config.runtime_assurance_policy.clone(),
                    config.receipt_db_path.as_deref(),
                    config.budget_db_path.as_deref(),
                )
                .map_err(|_| {
                    plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "capability issuance storage is unavailable",
                    )
                })
            }),
        (None, None) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        )),
    }
}

pub(crate) struct AuthoritySigningContext {
    pub(crate) keypair: Keypair,
    pub(crate) generation: u64,
    pub(crate) rotated_at: u64,
}

pub(crate) fn load_existing_authority_signing_context(
    config: &TrustServiceConfig,
) -> Result<AuthoritySigningContext, Response> {
    match (
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    ) {
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires one authority backend",
        )),
        (Some(path), None) => load_existing_authority_keypair(path)
            .map(|keypair| AuthoritySigningContext {
                keypair,
                generation: 1,
                rotated_at: 0,
            })
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority signing custody is unavailable",
                )
            }),
        (None, Some(path)) => {
            let authority = SqliteCapabilityAuthority::open_existing(path).map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority signing custody is unavailable",
                )
            })?;
            let status = authority.status().map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority state is unavailable",
                )
            })?;
            let keypair = authority.current_keypair().map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority signing custody is unavailable",
                )
            })?;
            if keypair.public_key() != status.public_key {
                return Err(plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority signing custody does not match authority state",
                ));
            }
            Ok(AuthoritySigningContext {
                keypair,
                generation: status.generation,
                rotated_at: status.rotated_at,
            })
        }
        (None, None) => Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority signing custody is not configured",
        )),
    }
}

pub(crate) fn load_authority_status(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open_existing(path)
            .and_then(|authority| authority.status())
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "capability authority state is unavailable",
                )
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
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Ok(None) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: None,
            generation: None,
            rotated_at: None,
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
        let status = SqliteCapabilityAuthority::open_existing(path)
            .and_then(|authority| authority.rotate())
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "capability authority rotation storage is unavailable",
                )
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
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
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
        applies_to_future_sessions_only: true,
        trusted_public_keys: status
            .trusted_public_keys
            .into_iter()
            .map(|public_key| public_key.to_hex())
            .collect(),
    }
}
