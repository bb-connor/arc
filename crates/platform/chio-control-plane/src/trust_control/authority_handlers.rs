//! HTTP handlers for the capability-authority admin surface: authority status
//! and rotation, capability issuance and revocation, SCIM user lifecycle,
//! enterprise-provider records, and federation admission policies.

use super::cluster::respond_after_leader_visible_write;
use super::report_rendering::{
    forward_post_to_leader, forward_scim_delete_to_leader, forward_scim_post_to_leader,
    json_response_with_leader_visibility,
};
use super::report_validation::{
    enforce_authority_mutation_fence, load_authority_status, refresh_authority_mutation_fence,
    rotate_authority, validate_service_auth,
};
use super::*;

fn authority_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
}

fn authority_role_auth_error() -> Response {
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid authority role bearer token",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn validate_authority_admin_auth<'a>(
    headers: &HeaderMap,
    config: &'a TrustServiceConfig,
) -> Result<&'a str, Response> {
    let expected = config
        .authority_admin_token
        .as_deref()
        .ok_or_else(authority_role_auth_error)?;
    let provided = authority_bearer_token(headers).ok_or_else(authority_role_auth_error)?;
    if bool::from(provided.as_bytes().ct_eq(expected.as_bytes())) {
        return Ok(expected);
    }
    Err(authority_role_auth_error())
}

fn authority_workload_for_headers<'a>(
    headers: &HeaderMap,
    config: &'a TrustServiceConfig,
) -> Result<&'a AuthorityWorkloadPolicy, Response> {
    let provided = authority_bearer_token(headers).ok_or_else(authority_role_auth_error)?;
    let mut matched = None;
    for workload in &config.authority_workloads {
        let is_match = provided
            .as_bytes()
            .ct_eq(workload.credential_token.as_bytes());
        if bool::from(is_match) {
            matched = Some(workload);
        }
    }
    matched.ok_or_else(authority_role_auth_error)
}

fn validate_authority_status_auth(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
) -> Result<(), Response> {
    if validate_service_auth(headers, &config.service_token).is_ok()
        || validate_authority_admin_auth(headers, config).is_ok()
        || authority_workload_for_headers(headers, config).is_ok()
    {
        return Ok(());
    }
    Err(authority_role_auth_error())
}

fn keyring_authority_status(state: &TrustServiceState) -> Result<TrustAuthorityStatus, Response> {
    if let Some(composition) = state.authority_keyring.as_ref() {
        let status = composition.authority_status().map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority state is unavailable",
            )
        })?;
        let generation = status.signing_epoch.checked_add(1).ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority generation overflow",
            )
        })?;
        return Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("enterprise_keyring".to_string()),
            public_key: Some(status.public_key.to_hex()),
            generation: Some(generation),
            rotated_at: status.activated_at,
            applies_to_future_sessions_only: true,
            trusted_public_keys: status
                .witnessed_verification_keys
                .into_iter()
                .map(|key| key.to_hex())
                .collect(),
        });
    }
    #[cfg(test)]
    if let Some(backend) = state.authority_test_backend.as_ref() {
        let public_key = backend.public_key();
        return Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("test_signing_backend".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: Some(1),
            rotated_at: Some(1),
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        });
    }
    load_authority_status(&state.config)
}

pub(crate) async fn handle_authority_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_authority_status_auth(&headers, &state.config) {
        return response;
    }
    match keyring_authority_status(&state) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

pub(crate) async fn handle_authority_key_log_sync(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AuthorityKeyLogSyncRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(keyring) = state.authority_keyring.as_ref() else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority key-log synchronization is unavailable",
        );
    };
    let response = match keyring.key_log_synchronization_response(request.base.as_ref()) {
        Ok(response) => response,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority key-log synchronization could not read witnessed history",
            );
        }
    };
    let body = match canonical_json_bytes(&response) {
        Ok(body) => body,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority key-log synchronization could not encode witnessed history",
            );
        }
    };
    ([(CONTENT_TYPE, "application/json")], body).into_response()
}

pub(crate) async fn handle_rotate_authority(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_authority_admin_auth(&headers, &state.config) {
        return response;
    }
    if let Err(response) = enforce_authority_mutation_fence(&state) {
        return response;
    }
    let now = match checked_unix_timestamp_now() {
        Ok(now) => now,
        Err(()) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "system clock is unavailable for authority rotation",
            );
        }
    };
    let _issuance_rotation_guard = match state.authority_issuance_rotation_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "capability authority issuance-rotation lock is poisoned",
            );
        }
    };
    if let Err(response) = fence_rotation_against_pending_issuance(&state, now) {
        return response;
    }
    match rotate_authority_with_configured_custody(&state) {
        Ok(status) => {
            if let Err(response) = refresh_authority_mutation_fence(&state) {
                return response;
            }
            respond_after_leader_visible_write(
                &state,
                "rotated authority was not visible on the leader after write",
                || {
                    let visible_status = keyring_authority_status(&state)?;
                    if visible_status.generation == status.generation
                        && visible_status.public_key == status.public_key
                    {
                        Ok(Some(visible_status))
                    } else {
                        Ok(None)
                    }
                },
            )
        }
        Err(response) => response,
    }
}

fn fence_rotation_against_pending_issuance(
    state: &TrustServiceState,
    now: u64,
) -> Result<(), Response> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(());
    };
    let store = SqliteReceiptStore::open_existing(path).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance state is unavailable before authority rotation",
        )
    })?;
    store.ensure_causal_lineage_ready().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance state failed validation before authority rotation",
        )
    })?;
    store
        .abort_expired_capability_issuance_intents(now)
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "expired capability issuance intents could not be closed before rotation",
            )
        })?;
    if store
        .has_pending_capability_issuance_intents()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "pending capability issuance state could not be inspected before rotation",
            )
        })?
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "authority rotation is blocked by a live pending capability issuance intent",
        ));
    }
    Ok(())
}

fn rotate_authority_with_configured_custody(
    state: &TrustServiceState,
) -> Result<TrustAuthorityStatus, Response> {
    if let Some(composition) = state.authority_keyring.as_ref() {
        let seed_path = state.config.authority_seed_path.as_deref().ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority seed custody is unavailable",
            )
        })?;
        composition
            .rotate_remote_authority_seed(seed_path)
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "witnessed capability authority rotation failed",
                )
            })?;
        return keyring_authority_status(state);
    }
    let config = &state.config;
    if config.authority_db_path.is_some() || config.authority_seed_path.is_none() {
        return rotate_authority(config);
    }
    with_seed_authority_exclusion(config, || rotate_authority(config))
}

fn with_seed_authority_exclusion<T>(
    config: &TrustServiceConfig,
    action: impl FnOnce() -> Result<T, Response>,
) -> Result<T, Response> {
    let path = config.receipt_db_path.as_deref().ok_or_else(|| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "seed-file authority mutation requires durable exclusion storage",
        )
    })?;
    let mut connection = rusqlite::Connection::open(path).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "seed-file authority exclusion storage is unavailable",
        )
    })?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "seed-file authority exclusion storage is unavailable",
            )
        })?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "seed-file authority exclusion storage is unavailable",
            )
        })?;
    let result = action()?;
    transaction.commit().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "seed-file authority exclusion storage could not commit",
        )
    })?;
    Ok(result)
}

struct GovernedIssuanceStores {
    freeze_admission: IssuanceFreezeAdmission,
    security_store: Arc<SqliteSecurityStateStore>,
    receipt_store: SqliteReceiptStore,
}

fn load_governed_issuance_stores(
    config: &TrustServiceConfig,
) -> Result<GovernedIssuanceStores, Response> {
    let path = config.receipt_db_path.as_deref().ok_or_else(|| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance requires a durable receipt and security-state database",
        )
    })?;
    let receipt_store = SqliteReceiptStore::open(path).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance receipt authority is unavailable",
        )
    })?;
    receipt_store.ensure_causal_lineage_ready().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance causal-lineage authority is unavailable",
        )
    })?;
    receipt_store
        .ensure_causal_lineage_fences_ready()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "capability issuance causal-fence authority is unavailable",
            )
        })?;
    let security_store = Arc::new(SqliteSecurityStateStore::open(path).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance freeze authority is unavailable",
        )
    })?);
    security_store
        .ensure_issuance_freezes_ready()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "capability issuance freeze authority is unavailable",
            )
        })?;
    let freeze_store: Arc<dyn IssuanceFreezeStore> = security_store.clone();
    Ok(GovernedIssuanceStores {
        freeze_admission: IssuanceFreezeAdmission::new(freeze_store),
        security_store,
        receipt_store,
    })
}

fn freeze_admission_response(error: PortError) -> Response {
    match error.kind() {
        PortErrorKind::Conflict => plain_http_error(
            StatusCode::FORBIDDEN,
            "capability issuance is blocked by an active issuance freeze",
        ),
        PortErrorKind::InvalidData => plain_http_error(
            StatusCode::BAD_REQUEST,
            "capability issuance security context is invalid",
        ),
        PortErrorKind::Unavailable | PortErrorKind::IntegrityFailure => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance freeze authority is unavailable",
        ),
    }
}

fn capability_issuance_store_response(error: chio_kernel::CapabilityLineageError) -> Response {
    match error {
        chio_kernel::CapabilityLineageError::ReceiptStore(ReceiptStoreError::Conflict(reason))
            if matches!(
                reason.as_str(),
                "capability issuance is blocked by an active issuance freeze"
                    | "capability issuance or delegation is blocked by an active causal lineage fence"
            ) =>
        {
            plain_http_error(StatusCode::FORBIDDEN, &reason)
        }
        chio_kernel::CapabilityLineageError::ReceiptStore(ReceiptStoreError::Conflict(reason)) => {
            plain_http_error(StatusCode::CONFLICT, &reason)
        }
        _ => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "capability issuance evidence could not be committed",
        ),
    }
}

const CAPABILITY_ISSUANCE_INTENT_SCHEMA: &str = "chio.capability-issuance-intent.v1";
const CAPABILITY_ISSUANCE_INTENT_ENVELOPE_SCHEMA: &str =
    "chio.capability-issuance-intent-envelope.v1";
const CAPABILITY_ISSUANCE_INTENT_SIGNATURE_DOMAIN: &str =
    "chio.capability-issuance-intent-envelope.v1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapabilityIssuanceIntentBody {
    schema: String,
    request_digest: String,
    freeze_generation: u64,
    authority_generation: u64,
    authority_rotated_at: u64,
    capability_body: CapabilityTokenBody,
    security_binding: CapabilitySecurityBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapabilityIssuanceIntent {
    schema: String,
    body: CapabilityIssuanceIntentBody,
    signer_public_key: PublicKey,
    algorithm: chio_core::SigningAlgorithm,
    signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityIssuanceIntentSigningPayload<'a> {
    schema: &'a str,
    body: &'a CapabilityIssuanceIntentBody,
    signer_public_key: &'a PublicKey,
    algorithm: chio_core::SigningAlgorithm,
}

fn derive_authoritative_security_context_digest(
    payload: &IssueCapabilityRequest,
) -> Result<String, Response> {
    canonical_json_bytes(&json!({
        "schema": "chio.remote-capability-security-context.v1",
        "tenantId": payload.tenant_id.as_str(),
        "securitySessionId": payload.security_session_id,
        "principalId": payload.principal_id,
        "contextGeneration": payload.context_generation,
        "serverId": payload.server_id,
        "subjectPublicKey": payload.subject_public_key,
        "workloadSignerPublicKey": payload.workload_signer_public_key,
        "sessionAdmissionSignerPublicKey": payload.session_admission.signer_public_key,
    }))
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "capability issuance security context cannot be canonicalized",
        )
    })
}

fn validate_authority_workload_request(
    workload: &AuthorityWorkloadPolicy,
    payload: &IssueCapabilityRequest,
) -> Result<(ChioScope, u64), Response> {
    if payload.tenant_id.as_str() != workload.tenant_id
        || payload.workload_id != workload.workload_id
        || payload.server_id != workload.server_id
        || payload.workload_signer_public_key != workload.signer_public_key
        || payload.session_admission.signer_public_key != workload.session_admission_public_key
    {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "capability issuance request does not match the authenticated workload policy",
        ));
    }
    payload
        .session_admission
        .verify_for_request(
            payload,
            &workload.session_admission_public_key,
            payload.requested_at,
        )
        .map_err(|reason| plain_http_error(StatusCode::FORBIDDEN, &reason))?;
    let context_digest = derive_authoritative_security_context_digest(payload)?;
    if payload.lineage_id.as_str() != format!("mcp-lineage:{context_digest}")
        || payload.isolation_epoch_id != format!("mcp-isolation:{context_digest}")
    {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "capability issuance lineage or isolation binding is not centrally derived",
        ));
    }
    workload
        .derive_capability(&payload.scope, payload.ttl_seconds)
        .map_err(|reason| plain_http_error(StatusCode::FORBIDDEN, &reason))
}

fn keyring_issuance_backend(
    state: &TrustServiceState,
) -> Result<(Arc<dyn chio_core::crypto::SigningBackend>, u64, u64), Response> {
    if let Some(composition) = state.authority_keyring.as_ref() {
        composition.ensure_bound_signing_topology().map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority topology is unavailable",
            )
        })?;
        let status = composition.authority_status().map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority state is unavailable",
            )
        })?;
        let generation = status.signing_epoch.checked_add(1).ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority generation overflow",
            )
        })?;
        let activated_at = status.activated_at.ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority activation time is not witnessed",
            )
        })?;
        let backend = composition.authority_signing_backend();
        if backend.public_key() != status.public_key {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability authority selector changed during status capture",
            ));
        }
        return Ok((backend, generation, activated_at));
    }
    #[cfg(test)]
    if let Some(backend) = state.authority_test_backend.as_ref() {
        return Ok((Arc::clone(backend), 1, 1));
    }
    Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "capability issuance requires an enforced enterprise keyring authority",
    ))
}

fn issuance_freeze_generation(
    stores: &GovernedIssuanceStores,
    payload: &IssueCapabilityRequest,
) -> Result<u64, Response> {
    stores
        .security_store
        .load_issuance_freezes(&IssuanceFreezeKey {
            tenant_id: payload.tenant_id.clone(),
            lineage_id: payload.lineage_id.clone(),
        })
        .map(|snapshot| snapshot.map_or(0, |snapshot| snapshot.generation))
        .map_err(freeze_admission_response)
}

fn issuance_storage_nonce(payload: &IssueCapabilityRequest) -> Result<String, Response> {
    canonical_json_bytes(&json!({
        "schema": "chio.capability-issuance-storage.v2",
        "requestNonce": payload.request_nonce,
        "tenantId": payload.tenant_id.as_str(),
        "workloadId": payload.workload_id,
        "serverId": payload.server_id,
    }))
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "capability issuance operation identity cannot be canonicalized",
        )
    })
}

fn build_capability_issuance_intent(
    payload: &IssueCapabilityRequest,
    subject: PublicKey,
    scope: ChioScope,
    ttl_seconds: u64,
    freeze_generation: u64,
    authority_generation: u64,
    authority_rotated_at: u64,
    issued_at: u64,
) -> Result<CapabilityIssuanceIntentBody, Response> {
    let request_digest = payload.binding_digest().map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "capability issuance request binding is invalid",
        )
    })?;
    let expires_at = issued_at.checked_add(ttl_seconds).ok_or_else(|| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "derived capability expiry overflows the Unix timestamp range",
        )
    })?;
    let capability_id = format!(
        "cap-{}",
        sha256_hex(
            format!("{request_digest}\0{freeze_generation}\0{authority_generation}").as_bytes()
        )
    );
    Ok(CapabilityIssuanceIntentBody {
        schema: CAPABILITY_ISSUANCE_INTENT_SCHEMA.to_string(),
        request_digest,
        freeze_generation,
        authority_generation,
        authority_rotated_at,
        capability_body: CapabilityTokenBody {
            id: capability_id,
            issuer: payload.expected_authority_public_key.clone(),
            subject,
            scope,
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        security_binding: CapabilitySecurityBinding {
            schema: CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
            tenant_id: payload.tenant_id.to_string(),
            lineage_id: payload.lineage_id.to_string(),
            session_id: payload.security_session_id.clone(),
            principal_id: payload.principal_id.clone(),
            isolation_epoch_id: payload.isolation_epoch_id.clone(),
            context_generation: payload.context_generation,
            workload_id: payload.workload_id.clone(),
            server_id: payload.server_id.clone(),
            workload_signer_public_key: payload.workload_signer_public_key.to_hex(),
        },
    })
}

fn capability_issuance_intent_signing_bytes(
    body: &CapabilityIssuanceIntentBody,
    signer_public_key: &PublicKey,
    algorithm: chio_core::SigningAlgorithm,
) -> Result<Vec<u8>, Response> {
    let payload = CapabilityIssuanceIntentSigningPayload {
        schema: CAPABILITY_ISSUANCE_INTENT_ENVELOPE_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|_| {
        plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capability issuance intent authorization cannot be canonicalized",
        )
    })?;
    let mut bytes =
        Vec::with_capacity(CAPABILITY_ISSUANCE_INTENT_SIGNATURE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(CAPABILITY_ISSUANCE_INTENT_SIGNATURE_DOMAIN.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn authorize_capability_issuance_intent(
    body: CapabilityIssuanceIntentBody,
    backend: &dyn chio_core::crypto::SigningBackend,
) -> Result<CapabilityIssuanceIntent, Response> {
    let signer_public_key = backend.public_key();
    if body.capability_body.issuer != signer_public_key {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "capability issuance intent issuer does not match the active authority",
        ));
    }
    let algorithm = signer_public_key.algorithm();
    let signing_bytes =
        capability_issuance_intent_signing_bytes(&body, &signer_public_key, algorithm)?;
    let outcome = backend
        .sign_bytes_for_identity(&signer_public_key, &signing_bytes)
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability intent authorization failed",
            )
        })?;
    if outcome.public_key != signer_public_key
        || outcome.algorithm != algorithm
        || outcome.signature.algorithm() != algorithm
        || !signer_public_key.verify(&signing_bytes, &outcome.signature)
    {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "keyring returned an invalid capability intent authorization",
        ));
    }
    Ok(CapabilityIssuanceIntent {
        schema: CAPABILITY_ISSUANCE_INTENT_ENVELOPE_SCHEMA.to_string(),
        body,
        signer_public_key,
        algorithm,
        signature: outcome.signature,
    })
}

fn verify_capability_issuance_intent_authorization(
    intent: &CapabilityIssuanceIntent,
    expected_signer: &PublicKey,
) -> Result<(), Response> {
    if intent.schema != CAPABILITY_ISSUANCE_INTENT_ENVELOPE_SCHEMA
        || intent.body.schema != CAPABILITY_ISSUANCE_INTENT_SCHEMA
        || &intent.signer_public_key != expected_signer
        || intent.algorithm != expected_signer.algorithm()
        || intent.signature.algorithm() != intent.algorithm
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance intent authorization is not pinned",
        ));
    }
    let signing_bytes = capability_issuance_intent_signing_bytes(
        &intent.body,
        &intent.signer_public_key,
        intent.algorithm,
    )?;
    if !intent
        .signer_public_key
        .verify(&signing_bytes, &intent.signature)
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance intent authorization is invalid",
        ));
    }
    Ok(())
}

fn issuance_policy_response(error: chio_kernel::KernelError) -> Response {
    match error {
        chio_kernel::KernelError::CapabilityIssuanceDenied(reason) => {
            plain_http_error(StatusCode::FORBIDDEN, &reason)
        }
        chio_kernel::KernelError::CapabilityIssuanceFailed(reason) => {
            plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &reason)
        }
        other => plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &other.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_persisted_capability_issuance_intent(
    payload: &IssueCapabilityRequest,
    intent_bytes: &[u8],
    authorization_bytes: &[u8],
    recorded_at: u64,
    subject: PublicKey,
    scope: ChioScope,
    ttl_seconds: u64,
    freeze_generation: u64,
    authority_generation: u64,
    authority_rotated_at: u64,
    authority_public_key: &PublicKey,
) -> Result<CapabilityIssuanceIntent, Response> {
    if recorded_at
        > payload
            .requested_at
            .saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        || recorded_at
            < payload
                .requested_at
                .saturating_sub(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance time is outside the authenticated request window",
        ));
    }
    let body: CapabilityIssuanceIntentBody =
        serde_json::from_slice(intent_bytes).map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persisted capability issuance intent body is invalid",
            )
        })?;
    let canonical_intent = canonical_json_bytes(&body).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted capability issuance intent body is not canonicalizable",
        )
    })?;
    if canonical_intent != intent_bytes {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance intent body is not canonical",
        ));
    }
    let intent: CapabilityIssuanceIntent =
        serde_json::from_slice(authorization_bytes).map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persisted capability issuance authorization is invalid",
            )
        })?;
    let canonical_authorization = canonical_json_bytes(&intent).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted capability issuance authorization is not canonicalizable",
        )
    })?;
    let canonical_authorized_body = canonical_json_bytes(&intent.body).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted capability issuance authorization body is not canonicalizable",
        )
    })?;
    if canonical_authorization != authorization_bytes
        || canonical_authorized_body != canonical_intent
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance authorization does not bind its immutable body",
        ));
    }
    verify_capability_issuance_intent_authorization(&intent, authority_public_key)?;
    let expected = build_capability_issuance_intent(
        payload,
        subject,
        scope,
        ttl_seconds,
        freeze_generation,
        authority_generation,
        authority_rotated_at,
        recorded_at,
    )?;
    let expected_bytes = canonical_json_bytes(&expected).map_err(|_| {
        plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capability issuance intent serialization failed",
        )
    })?;
    if canonical_intent != expected_bytes
        || body.request_digest != expected.request_digest
        || intent.body.freeze_generation != freeze_generation
        || intent.body.authority_generation != authority_generation
        || intent.body.authority_rotated_at != authority_rotated_at
        || intent.body.capability_body.issuer != *authority_public_key
        || intent.body.capability_body.issued_at != recorded_at
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance intent does not match the authenticated request and active authority state",
        ));
    }
    Ok(intent)
}

fn validate_recovered_pending_capability_issuance_intent(
    payload: &IssueCapabilityRequest,
    intent_bytes: &[u8],
    authorization_bytes: &[u8],
    recorded_at: u64,
) -> Result<CapabilityIssuanceIntent, Response> {
    let _body =
        validate_recovered_unsigned_capability_issuance_intent(payload, intent_bytes, recorded_at)?;
    let intent: CapabilityIssuanceIntent =
        serde_json::from_slice(authorization_bytes).map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persisted capability issuance authorization is invalid",
            )
        })?;
    let canonical_authorized_body = canonical_json_bytes(&intent.body).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted capability issuance authorization body is not canonicalizable",
        )
    })?;
    if canonical_json_bytes(&intent).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted capability issuance authorization is not canonicalizable",
        )
    })? != authorization_bytes
        || canonical_authorized_body != intent_bytes
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance authorization does not bind its immutable body",
        ));
    }
    verify_capability_issuance_intent_authorization(
        &intent,
        &payload.expected_authority_public_key,
    )?;
    Ok(intent)
}

fn validate_recovered_unsigned_capability_issuance_intent(
    payload: &IssueCapabilityRequest,
    intent_bytes: &[u8],
    recorded_at: u64,
) -> Result<CapabilityIssuanceIntentBody, Response> {
    if recorded_at
        > payload
            .requested_at
            .saturating_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        || recorded_at
            < payload
                .requested_at
                .saturating_sub(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance time is outside the authenticated request window",
        ));
    }
    let body: CapabilityIssuanceIntentBody =
        serde_json::from_slice(intent_bytes).map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persisted capability issuance intent body is invalid",
            )
        })?;
    let canonical = canonical_json_bytes(&body).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted capability issuance intent body is not canonicalizable",
        )
    })?;
    if canonical != intent_bytes {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance intent body is not canonical",
        ));
    }
    let body = &body;
    let expected_digest = payload.binding_digest().map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "capability issuance request binding is invalid",
        )
    })?;
    let expected_id = format!(
        "cap-{}",
        sha256_hex(
            format!(
                "{}\0{}\0{}",
                expected_digest, body.freeze_generation, body.authority_generation
            )
            .as_bytes(),
        )
    );
    let expected_binding = CapabilitySecurityBinding {
        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
        tenant_id: payload.tenant_id.to_string(),
        lineage_id: payload.lineage_id.to_string(),
        session_id: payload.security_session_id.clone(),
        principal_id: payload.principal_id.clone(),
        isolation_epoch_id: payload.isolation_epoch_id.clone(),
        context_generation: payload.context_generation,
        workload_id: payload.workload_id.clone(),
        server_id: payload.server_id.clone(),
        workload_signer_public_key: payload.workload_signer_public_key.to_hex(),
    };
    let subject = PublicKey::from_hex(&payload.subject_public_key).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "capability issuance subject public key is invalid",
        )
    })?;
    let issued_ttl = body
        .capability_body
        .expires_at
        .checked_sub(body.capability_body.issued_at)
        .filter(|ttl| *ttl > 0 && *ttl <= payload.ttl_seconds);
    if body.schema != CAPABILITY_ISSUANCE_INTENT_SCHEMA
        || body.request_digest != expected_digest
        || body.authority_generation != payload.expected_authority_generation
        || body.authority_rotated_at == 0
        || body.authority_rotated_at > recorded_at
        || body.capability_body.id != expected_id
        || body.capability_body.issuer != payload.expected_authority_public_key
        || body.capability_body.subject != subject
        || body.capability_body.issued_at != recorded_at
        || issued_ttl.is_none()
        || !body.capability_body.scope.is_subset_of(&payload.scope)
        || !body.capability_body.delegation_chain.is_empty()
        || body.capability_body.aggregate_invocation_budget.is_some()
        || body.security_binding != expected_binding
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "persisted capability issuance intent does not match its authenticated request",
        ));
    }
    Ok(body.clone())
}

pub(crate) async fn handle_issue_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<IssueCapabilityRequest>,
) -> Response {
    let workload = match authority_workload_for_headers(&headers, &state.config) {
        Ok(workload) => workload.clone(),
        Err(response) => return response,
    };
    let now = match checked_unix_timestamp_now() {
        Ok(now) => now,
        Err(()) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "system clock is unavailable for capability issuance",
            );
        }
    };
    if let Err(error) = payload.validate_structure_and_signature() {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }
    let (workload_scope, ttl_seconds) =
        match validate_authority_workload_request(&workload, &payload) {
            Ok(derived) => derived,
            Err(response) => return response,
        };
    if let Err(response) = enforce_authority_mutation_fence(&state) {
        return response;
    }
    let _issuance_rotation_guard = match state.authority_issuance_rotation_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "capability authority issuance-rotation lock is poisoned",
            );
        }
    };
    let governed_stores = match load_governed_issuance_stores(&state.config) {
        Ok(stores) => stores,
        Err(response) => return response,
    };
    let request_digest = match payload.binding_digest() {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    let storage_nonce = match issuance_storage_nonce(&payload) {
        Ok(nonce) => nonce,
        Err(response) => return response,
    };
    let recovered = match governed_stores
        .receipt_store
        .recover_capability_issuance_intent(
            &storage_nonce,
            &request_digest,
            &payload.tenant_id,
            &payload.lineage_id,
        ) {
        Ok(recovered) => recovered,
        Err(error) => return capability_issuance_store_response(error),
    };
    let recovered_pending = match recovered {
        Some(PreparedCapabilityIssuance::Finalized(response_bytes)) => {
            return canonical_issue_capability_response_bytes(response_bytes);
        }
        Some(PreparedCapabilityIssuance::Aborted { reason }) => {
            return plain_http_error(StatusCode::CONFLICT, &reason);
        }
        Some(PreparedCapabilityIssuance::Pending {
            intent_bytes,
            authorization_bytes,
            recorded_at,
        }) => Some((intent_bytes, authorization_bytes, recorded_at)),
        None => None,
    };
    let admission_query = IssuanceFreezeAdmissionQuery {
        tenant_id: payload.tenant_id.clone(),
        lineage_id: payload.lineage_id.clone(),
        operation: CapabilityIssuanceOperation::Issue,
        parent_capability_id: None,
    };
    let subject = match PublicKey::from_hex(&payload.subject_public_key) {
        Ok(subject) => subject,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let (backend, intent, intent_bytes, authorization_bytes) = match recovered_pending {
        Some((intent_bytes, stored_authorization, recorded_at)) => {
            let intent_body = match validate_recovered_unsigned_capability_issuance_intent(
                &payload,
                &intent_bytes,
                recorded_at,
            ) {
                Ok(intent) => intent,
                Err(response) => return response,
            };
            if intent_body.capability_body.expires_at <= now {
                let reason = "capability issuance intent expired before finalization";
                if let Err(error) = governed_stores
                    .receipt_store
                    .abort_capability_issuance_intent(&storage_nonce, &request_digest, reason, now)
                {
                    return capability_issuance_store_response(error);
                }
                return plain_http_error(StatusCode::CONFLICT, reason);
            }
            let (backend, active_generation, _) = match keyring_issuance_backend(&state) {
                Ok(context) => context,
                Err(response) => return response,
            };
            if backend.public_key() != intent_body.capability_body.issuer
                || active_generation != intent_body.authority_generation
            {
                return plain_http_error(
                    StatusCode::CONFLICT,
                    "live pending capability issuance intent lost its signing epoch",
                );
            }
            let authorization_bytes = match stored_authorization {
                Some(authorization) => authorization,
                None => {
                    let authorization =
                        match authorize_capability_issuance_intent(intent_body, backend.as_ref()) {
                            Ok(authorization) => authorization,
                            Err(response) => return response,
                        };
                    let candidate = match canonical_json_bytes(&authorization) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "capability issuance authorization serialization failed",
                            );
                        }
                    };
                    match governed_stores
                        .receipt_store
                        .authorize_capability_issuance_intent(
                            &storage_nonce,
                            &request_digest,
                            &intent_bytes,
                            &candidate,
                        ) {
                        Ok(PreparedCapabilityIssuance::Pending {
                            intent_bytes: persisted_intent,
                            authorization_bytes: Some(persisted_authorization),
                            recorded_at: persisted_recorded_at,
                        }) if persisted_intent == intent_bytes
                            && persisted_recorded_at == recorded_at =>
                        {
                            persisted_authorization
                        }
                        Ok(PreparedCapabilityIssuance::Finalized(response_bytes)) => {
                            return canonical_issue_capability_response_bytes(response_bytes);
                        }
                        Ok(PreparedCapabilityIssuance::Aborted { reason }) => {
                            return plain_http_error(StatusCode::CONFLICT, &reason);
                        }
                        Ok(PreparedCapabilityIssuance::Pending { .. }) => {
                            return plain_http_error(
                                StatusCode::CONFLICT,
                                "capability issuance authorization CAS returned inconsistent state",
                            );
                        }
                        Err(error) => return capability_issuance_store_response(error),
                    }
                }
            };
            let intent = match validate_recovered_pending_capability_issuance_intent(
                &payload,
                &intent_bytes,
                &authorization_bytes,
                recorded_at,
            ) {
                Ok(intent) => intent,
                Err(response) => return response,
            };
            (backend, intent, intent_bytes, authorization_bytes)
        }
        None => {
            if let Err(error) = payload.validate_freshness_at(now) {
                return plain_http_error(StatusCode::BAD_REQUEST, &error);
            }
            let (backend, authority_generation, authority_rotated_at) =
                match keyring_issuance_backend(&state) {
                    Ok(context) => context,
                    Err(response) => return response,
                };
            if payload.expected_authority_public_key != backend.public_key()
                || payload.expected_authority_generation != authority_generation
            {
                return plain_http_error(
                    StatusCode::CONFLICT,
                    "capability issuance request does not match the active witnessed authority generation",
                );
            }
            if let Err(error) = governed_stores.freeze_admission.authorize(&admission_query) {
                return freeze_admission_response(error);
            }
            let freeze_generation = match issuance_freeze_generation(&governed_stores, &payload) {
                Ok(generation) => generation,
                Err(response) => return response,
            };
            let trusted_kernel_keys = vec![backend.public_key().to_hex()];
            let scope = match crate::issuance::apply_authoritative_issuance_policy(
                &subject,
                workload_scope,
                ttl_seconds,
                payload.runtime_attestation.as_ref(),
                state.config.issuance_policy.as_ref(),
                state.config.runtime_assurance_policy.as_ref(),
                state.config.receipt_db_path.as_deref(),
                state.config.budget_db_path.as_deref(),
                &trusted_kernel_keys,
                now,
            ) {
                Ok(scope) => scope,
                Err(error) => return issuance_policy_response(error),
            };
            let candidate_body = match build_capability_issuance_intent(
                &payload,
                subject.clone(),
                scope.clone(),
                ttl_seconds,
                freeze_generation,
                authority_generation,
                authority_rotated_at,
                now,
            ) {
                Ok(intent) => intent,
                Err(response) => return response,
            };
            let candidate_intent_bytes = match canonical_json_bytes(&candidate_body) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "capability issuance intent serialization failed",
                    );
                }
            };
            let prepared = governed_stores
                .receipt_store
                .prepare_capability_issuance_intent(PrepareCapabilityIssuanceIntentInput {
                    request_nonce: &storage_nonce,
                    request_digest: &request_digest,
                    tenant_id: &payload.tenant_id,
                    lineage_root_id: &payload.lineage_id,
                    intent_bytes: &candidate_intent_bytes,
                    session_admission: &CapabilitySessionAdmissionRegistration {
                        admission_nonce: payload.session_admission.body.admission_nonce.clone(),
                        operation_nonce: storage_nonce.clone(),
                        admission_digest: match payload.session_admission.binding_digest() {
                            Ok(digest) => digest,
                            Err(error) => {
                                return plain_http_error(StatusCode::BAD_REQUEST, &error);
                            }
                        },
                        binding_bytes: match canonical_json_bytes(&payload.session_admission) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                return plain_http_error(
                                    StatusCode::BAD_REQUEST,
                                    "capability session admission cannot be canonicalized",
                                );
                            }
                        },
                    },
                    recorded_at: now,
                    expires_at: candidate_body.capability_body.expires_at,
                    expected_freeze_generation: freeze_generation,
                });
            let (intent_bytes, stored_authorization, recorded_at) = match prepared {
                Ok(PreparedCapabilityIssuance::Finalized(response_bytes)) => {
                    return canonical_issue_capability_response_bytes(response_bytes);
                }
                Ok(PreparedCapabilityIssuance::Aborted { reason }) => {
                    return plain_http_error(StatusCode::CONFLICT, &reason);
                }
                Ok(PreparedCapabilityIssuance::Pending {
                    intent_bytes,
                    authorization_bytes,
                    recorded_at,
                }) => (intent_bytes, authorization_bytes, recorded_at),
                Err(error) => return capability_issuance_store_response(error),
            };
            let persisted_body = match validate_recovered_unsigned_capability_issuance_intent(
                &payload,
                &intent_bytes,
                recorded_at,
            ) {
                Ok(body) => body,
                Err(response) => return response,
            };
            if intent_bytes != candidate_intent_bytes {
                return plain_http_error(
                    StatusCode::CONFLICT,
                    "persisted capability issuance body changed before authorization",
                );
            }
            let authorization_bytes = match stored_authorization {
                Some(authorization) => authorization,
                None => {
                    let authorization = match authorize_capability_issuance_intent(
                        persisted_body,
                        backend.as_ref(),
                    ) {
                        Ok(authorization) => authorization,
                        Err(response) => return response,
                    };
                    let candidate = match canonical_json_bytes(&authorization) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "capability issuance authorization serialization failed",
                            );
                        }
                    };
                    match governed_stores
                        .receipt_store
                        .authorize_capability_issuance_intent(
                            &storage_nonce,
                            &request_digest,
                            &intent_bytes,
                            &candidate,
                        ) {
                        Ok(PreparedCapabilityIssuance::Pending {
                            intent_bytes: persisted_intent,
                            authorization_bytes: Some(persisted_authorization),
                            recorded_at: persisted_recorded_at,
                        }) if persisted_intent == intent_bytes
                            && persisted_recorded_at == recorded_at =>
                        {
                            persisted_authorization
                        }
                        Ok(PreparedCapabilityIssuance::Finalized(response_bytes)) => {
                            return canonical_issue_capability_response_bytes(response_bytes);
                        }
                        Ok(PreparedCapabilityIssuance::Aborted { reason }) => {
                            return plain_http_error(StatusCode::CONFLICT, &reason);
                        }
                        Ok(PreparedCapabilityIssuance::Pending { .. }) => {
                            return plain_http_error(
                                StatusCode::CONFLICT,
                                "capability issuance authorization CAS returned inconsistent state",
                            );
                        }
                        Err(error) => return capability_issuance_store_response(error),
                    }
                }
            };
            let intent = match validate_persisted_capability_issuance_intent(
                &payload,
                &intent_bytes,
                &authorization_bytes,
                recorded_at,
                subject,
                scope,
                ttl_seconds,
                freeze_generation,
                authority_generation,
                authority_rotated_at,
                &backend.public_key(),
            ) {
                Ok(intent) => intent,
                Err(response) => return response,
            };
            (backend, intent, intent_bytes, authorization_bytes)
        }
    };
    let capability = match CapabilityToken::sign_with_security_binding_backend(
        intent.body.capability_body.clone(),
        intent.body.security_binding.clone(),
        backend.as_ref(),
    ) {
        Ok(capability) => capability,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability artifact signing failed",
            );
        }
    };
    let signed_result = match state.authority_keyring.as_ref() {
        Some(composition) => SignedIssueCapabilityResponse::sign_with_keyring_evidence(
            &payload,
            capability.clone(),
            composition,
            intent.body.authority_generation,
            intent.body.authority_rotated_at,
            intent.body.capability_body.issued_at,
        ),
        None => {
            #[cfg(test)]
            {
                SignedIssueCapabilityResponse::sign_with_backend(
                    &payload,
                    capability.clone(),
                    backend.as_ref(),
                    intent.body.authority_generation,
                    intent.body.authority_rotated_at,
                    intent.body.capability_body.issued_at,
                )
            }
            #[cfg(not(test))]
            {
                Err("keyring capability response evidence is unavailable".to_string())
            }
        }
    };
    let signed = match signed_result {
        Ok(signed) => signed,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "keyring capability response signing failed",
            );
        }
    };
    let response_bytes = match canonical_issue_capability_response_body(&signed) {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    if let Err(response) = enforce_authority_mutation_fence(&state) {
        return response;
    }
    match governed_stores.receipt_store.finalize_capability_issuance(
        FinalizeCapabilityIssuanceInput {
            request_nonce: &storage_nonce,
            request_digest: &intent.body.request_digest,
            intent_bytes: &intent_bytes,
            authorization_bytes: &authorization_bytes,
            tenant_id: &payload.tenant_id,
            lineage_root_id: &payload.lineage_id,
            capability,
            response_bytes: &response_bytes,
        },
    ) {
        Ok(finalized) => canonical_issue_capability_response_bytes(finalized.response_bytes()),
        Err(error) => capability_issuance_store_response(error),
    }
}

fn canonical_issue_capability_response_body(
    signed: &SignedIssueCapabilityResponse,
) -> Result<Vec<u8>, Response> {
    let body = match canonical_json_bytes(signed) {
        Ok(body) => body,
        Err(_) => {
            return Err(plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "capability issuance response serialization failed",
            ));
        }
    };
    let body_len = match u64::try_from(body.len()) {
        Ok(body_len) => body_len,
        Err(_) => {
            return Err(plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "capability issuance response length overflow",
            ));
        }
    };
    if body_len > CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES {
        return Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capability issuance response exceeds its byte bound",
        ));
    }
    Ok(body)
}

fn canonical_issue_capability_response_bytes(body: Vec<u8>) -> Response {
    if body.len() > CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES as usize {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "persisted capability issuance response exceeds its byte bound",
        );
    }
    ([(CONTENT_TYPE, "application/json")], body).into_response()
}

include!("authority_handlers_tail.inc");
