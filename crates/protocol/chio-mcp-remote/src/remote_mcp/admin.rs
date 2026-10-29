use super::*;
use chio_kernel::ReceiptReadContext;
use subtle::ConstantTimeEq;

#[path = "admin/revocation_batch.rs"]
mod revocation_batch;
#[path = "admin/stop.rs"]
mod stop;

pub(super) fn install_admin_routes(router: Router<RemoteAppState>) -> Router<RemoteAppState> {
    let router = remote_mcp_session_credentials::install_routes(router);
    router
        .route(ADMIN_HEALTH_PATH, get(handle_admin_health))
        .route(
            ADMIN_AUTHORITY_PATH,
            get(handle_admin_authority).post(handle_admin_rotate_authority),
        )
        .route(ADMIN_TOOL_RECEIPTS_PATH, get(handle_admin_tool_receipts))
        .route(ADMIN_CHILD_RECEIPTS_PATH, get(handle_admin_child_receipts))
        .route(ADMIN_BUDGETS_PATH, get(handle_admin_budgets))
        .route(
            ADMIN_REVOCATIONS_PATH,
            get(handle_admin_revocations).post(handle_admin_revoke_capability),
        )
        .route(
            ADMIN_SESSION_TRUST_PATH,
            get(handle_admin_session_trust).post(handle_admin_revoke_session_trust),
        )
        .route(ADMIN_SESSIONS_PATH, get(handle_admin_sessions))
        .route(ADMIN_EMERGENCY_STOP_PATH, post(stop::handle_stop))
        .route(ADMIN_EMERGENCY_RESUME_PATH, post(stop::handle_resume))
        .route(ADMIN_EMERGENCY_STATUS_PATH, get(stop::handle_status))
        .route(
            "/admin/approvals",
            post(super::remote_mcp_approvals::submit),
        )
        .route(
            "/admin/approvals/{id}",
            get(super::remote_mcp_approvals::get_record),
        )
        .route(
            "/admin/approvals/{id}/decision",
            post(super::remote_mcp_approvals::decide),
        )
        .route("/admin/metrics", get(handle_admin_metrics))
        .route(ADMIN_SESSION_DRAIN_PATH, post(handle_admin_session_drain))
        .route(
            ADMIN_SESSION_SHUTDOWN_PATH,
            post(handle_admin_session_shutdown),
        )
}

async fn handle_admin_authority(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    match load_authority_status(&state) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

async fn handle_admin_health(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    if let Err(error) = state.sessions.cleanup_due_sessions().await {
        return input::with_source(
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "MCP lifecycle cleanup unavailable",
            ),
            error,
        );
    }
    let (active, terminal) = state.sessions.snapshot().await;
    let authority = match load_authority_status(&state) {
        Ok(status) => status,
        Err(response) => return response,
    };

    let enterprise_provider_summary = match state
        .enterprise_provider_registry
        .as_ref()
        .map(EnterpriseProviderRegistryFile::load_for_health)
    {
        Some(Ok(registry)) => json!({
            "configured": true,
            "available": true,
            "count": registry.providers.len(),
            "validatedCount": registry
                .providers
                .values()
                .filter(|record| record.is_validated_enabled())
                .count(),
            "invalidCount": registry
                .providers
                .values()
                .filter(|record| !record.validation_errors.is_empty())
                .count(),
        }),
        Some(Err(_)) => json!({
            "configured": true,
            "available": false,
            "count": 0,
            "validatedCount": 0,
            "invalidCount": 0,
        }),
        None => json!({
            "configured": false,
            "available": false,
            "count": 0,
            "validatedCount": 0,
            "invalidCount": 0,
        }),
    };
    let shared_hosted_owner_stats =
        state
            .factory
            .shared_upstream_owner
            .lock()
            .ok()
            .and_then(|owner| {
                owner
                    .as_ref()
                    .map(|owner| owner.notification_stats_snapshot())
            });

    Json(json!({
        "ok": true,
        "server": {
            "serverId": &state.factory.config.server_id,
            "serverName": &state.factory.config.server_name,
            "serverVersion": &state.factory.config.server_version,
            "sharedHostedOwner": state.factory.config.shared_hosted_owner,
            "sharedHostedOwnerStats": shared_hosted_owner_stats,
        },
        "auth": {
            "mode": remote_auth_mode_label(&state.auth_mode),
            "scopes": &state.factory.config.auth_scopes,
            "issuerConfigured": state.factory.config.auth_jwt_issuer.is_some(),
            "audienceConfigured": state.factory.config.auth_jwt_audience.is_some(),
            "adminTokenConfigured": state.admin_token.is_some(),
        },
        "controlPlane": {
            "proxied": state.factory.config.control_url.is_some(),
            "controlUrl": &state.factory.config.control_url,
            "controlTokenConfigured": state.factory.config.control_token.is_some(),
            "workloadTokenConfigured": state.factory.config.remote_authority_workload_token.is_some(),
            "authorityCurrentKeyPinned": state.factory.config.control_authority_public_key.is_some(),
            "authorityAdditionalTrustedKeyCount": state.factory.config.control_authority_trusted_public_keys.len(),
        },
        "stores": {
            "receiptsConfigured": state.factory.config.receipt_db_path.is_some(),
            "revocationsConfigured": state.factory.config.control_url.is_some()
                || state.factory.durable_admission.is_some(),
            "authorityDbConfigured": state.factory.config.authority_db_path.is_some(),
            "authoritySeedConfigured": state.factory.config.authority_seed_path.is_some(),
            "budgetsConfigured": state.factory.config.control_url.is_some()
                || state.factory.config.budget_db_path.is_some()
                || state.factory.durable_admission.is_some(),
            "sessionTombstonesConfigured": state.factory.config.session_db_path.is_some(),
        },
        "sessions": {
            "activeCount": active.len(),
            "terminalCount": terminal.len(),
            "idleExpiryMillis": state.factory.lifecycle_policy.idle_expiry_millis,
            "drainGraceMillis": state.factory.lifecycle_policy.drain_grace_millis,
            "reaperIntervalMillis": state.factory.lifecycle_policy.reaper_interval_millis,
            "tombstoneRetentionMillis": state.factory.lifecycle_policy.tombstone_retention_millis,
        },
        "authority": authority,
        "federation": {
            "identityFederationConfigured": state.factory.config.identity_federation_seed_path.is_some(),
            "enterpriseProviders": enterprise_provider_summary,
        },
        "oauth": {
            "protectedResourceMetadata": state.protected_resource_metadata.is_some(),
            "authorizationServerMetadata": state.authorization_server_metadata.is_some(),
            "localAuthorizationServer": state.local_auth_server.is_some(),
        },
    }))
    .into_response()
}

async fn handle_admin_rotate_authority(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.rotate_authority() {
            Ok(status) => Json(json!({
                "configured": status.configured,
                "backend": status.backend,
                "rotated": true,
                "publicKey": status.public_key,
                "generation": status.generation,
                "rotatedAt": status.rotated_at,
                "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
                "trustedPublicKeys": status.trusted_public_keys,
            }))
            .into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }

    if let Some(path) = state.factory.config.authority_db_path.as_deref() {
        return match chio_store_sqlite::SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
        {
            Ok(status) => Json(json!({
                "configured": true,
                "backend": "sqlite",
                "rotated": true,
                "publicKey": status.public_key.to_hex(),
                "generation": status.generation,
                "rotatedAt": status.rotated_at,
                "appliesToFutureSessionsOnly": true,
                "trustedPublicKeys": status.trusted_public_keys.into_iter().map(|key| key.to_hex()).collect::<Vec<_>>(),
            }))
            .into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }

    let Some(path) = state.factory.config.authority_seed_path.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "remote authority admin requires --authority-seed-file or --authority-db",
        );
    };

    match rotate_authority_keypair(path) {
        Ok(public_key) => Json(json!({
            "configured": true,
            "backend": "seed_file",
            "rotated": true,
            "publicKey": public_key.to_hex(),
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": vec![public_key.to_hex()],
        }))
        .into_response(),
        Err(error) => admin_backend_failure(error),
    }
}

async fn handle_admin_tool_receipts(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminToolReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_admin_request(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_tool_receipts(&ToolReceiptQuery {
            receipt_id: None,
            capability_id: query.capability_id.clone(),
            tool_server: query.tool_server.clone(),
            tool_name: query.tool_name.clone(),
            decision: query.decision.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }
    let store = match open_receipt_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let read_context = ReceiptReadContext::admin_service();
    let receipts = match store.list_tool_receipts_with_context(
        &read_context,
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
        query.tool_server.as_deref(),
        query.tool_name.as_deref(),
        query.decision.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return admin_backend_failure(error);
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return admin_backend_failure(error);
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "kind": "tool",
        "count": receipts.len(),
        "filters": {
            "capabilityId": query.capability_id,
            "toolServer": query.tool_server,
            "toolName": query.tool_name,
            "decision": query.decision,
        },
        "receipts": receipts,
    }))
    .into_response()
}

async fn handle_admin_child_receipts(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminChildReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_admin_request(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_child_receipts(&ChildReceiptQuery {
            receipt_id: None,
            session_id: query.session_id.clone(),
            parent_request_id: query.parent_request_id.clone(),
            request_id: query.request_id.clone(),
            operation_kind: query.operation_kind.clone(),
            terminal_state: query.terminal_state.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }
    let store = match open_receipt_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let read_context = ReceiptReadContext::admin_service();
    let receipts = match store.list_child_receipts_with_context(
        &read_context,
        admin_list_limit(query.limit),
        query.session_id.as_deref(),
        query.parent_request_id.as_deref(),
        query.request_id.as_deref(),
        query.operation_kind.as_deref(),
        query.terminal_state.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return admin_backend_failure(error);
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return admin_backend_failure(error);
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "kind": "child",
        "count": receipts.len(),
        "filters": {
            "sessionId": query.session_id,
            "parentRequestId": query.parent_request_id,
            "requestId": query.request_id,
            "operationKind": query.operation_kind,
            "terminalState": query.terminal_state,
        },
        "receipts": receipts,
    }))
    .into_response()
}

async fn handle_admin_budgets(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminBudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_admin_request(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_budgets(&trust_control::BudgetQuery {
            capability_id: query.capability_id.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }

    let store = match open_budget_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match chio_kernel::BudgetStore::list_usages(
        &store,
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
    ) {
        Ok(usages) => usages,
        Err(error) => {
            return admin_backend_failure(error);
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": query.capability_id,
        "count": usages.len(),
        "usages": usages.into_iter().map(|usage| json!({
            "capabilityId": usage.capability_id,
            "grantIndex": usage.grant_index,
            "invocationCount": usage.invocation_count,
            "updatedAt": usage.updated_at,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// The fixed refusal for every malformed revocation request.
const INVALID_REVOCATION_REQUEST: &str = "invalid revocation request";
/// The largest accepted revocation request body.
const MAX_REVOCATION_REQUEST_BYTES: usize = 4096;
const DEFAULT_REVOCATION_PAGE: usize = 100;
const MAX_REVOCATION_PAGE: usize = 500;

fn invalid_revocation_request() -> Response {
    plain_http_error(StatusCode::BAD_REQUEST, INVALID_REVOCATION_REQUEST)
}

/// A page request or a capability check parsed from the query.
enum RevocationListing {
    Capability(String),
    Page {
        after: u64,
        limit: usize,
        kind: Option<chio_core::root_authority::RevocationTargetKind>,
    },
}

impl RevocationListing {
    fn parse(query: AdminRevocationQuery) -> Option<Self> {
        if let Some(capability_id) = query.capability_id {
            if query.after.is_some() || query.limit.is_some() || query.kind.is_some() {
                return None;
            }
            chio_core::root_authority::RevocationTarget::capability(&capability_id).ok()?;
            return Some(Self::Capability(capability_id));
        }
        let after = query.after.map_or(Some(0), |after| after.parse().ok())?;
        let limit = query
            .limit
            .map_or(Some(DEFAULT_REVOCATION_PAGE), |limit| limit.parse().ok())?;
        if !(1..=MAX_REVOCATION_PAGE).contains(&limit) {
            return None;
        }
        let kind = query
            .kind
            .map(|kind| chio_core::root_authority::RevocationTargetKind::parse(&kind).ok())
            .map_or(Some(None), |kind| kind.map(Some))?;
        Some(Self::Page { after, limit, kind })
    }
}

async fn handle_admin_revocations(
    State(state): State<RemoteAppState>,
    query: Result<Query<AdminRevocationQuery>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_admin_request(&headers, state.admin_token.as_deref()) {
        return response;
    }
    let Some(listing) = query
        .ok()
        .and_then(|Query(query)| RevocationListing::parse(query))
    else {
        return invalid_revocation_request();
    };

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        let (capability_id, limit) = match &listing {
            RevocationListing::Capability(capability_id) => (Some(capability_id.clone()), 1),
            RevocationListing::Page { limit, .. } => (None, *limit),
        };
        return match client.list_revocations(&RevocationQuery {
            after: None,
            kind: None,
            capability_id,
            limit: Some(limit),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }
    let store = match open_revocation_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match listing {
        RevocationListing::Capability(capability_id) => {
            match store.revocation_entry(&capability_id) {
                Ok(entry_id) => Json(json!({
                    "capability_id": capability_id,
                    "revoked": entry_id.is_some(),
                    "entry_id": entry_id,
                }))
                .into_response(),
                Err(error) => revocation_store_failure(error),
            }
        }
        RevocationListing::Page { after, limit, kind } => {
            match store.list_revocation_entries_after(after, limit, kind) {
                Ok((entries, head)) => {
                    let next_after = entries.last().map_or(after, |(entry_seq, _)| *entry_seq);
                    Json(json!({
                        "entries": entries
                            .iter()
                            .map(|(entry_seq, entry)| json!({
                                "entry_seq": entry_seq,
                                "entry": entry,
                            }))
                            .collect::<Vec<_>>(),
                        "next_after": next_after,
                        "head": head,
                    }))
                    .into_response()
                }
                Err(error) => revocation_store_failure(error),
            }
        }
    }
}

async fn handle_admin_revoke_capability(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }
    let Ok(body) = axum::body::to_bytes(request.into_body(), MAX_REVOCATION_REQUEST_BYTES).await
    else {
        return invalid_revocation_request();
    };
    let Ok(AdminRevokeRequest { target, reason }) = serde_json::from_slice(&body) else {
        return invalid_revocation_request();
    };
    let AdminRevocationTarget::CapabilityId { capability_id } = target;
    let Ok(target) = chio_core::root_authority::RevocationTarget::capability(&capability_id) else {
        return invalid_revocation_request();
    };

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.revoke_capability(&capability_id) {
            Ok(response) => Json(response).into_response(),
            Err(error) => admin_backend_failure(error),
        };
    }
    let store = match open_revocation_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.revoke_target(&target, &[], None, reason) {
        Ok(revocation) => {
            info!(
                entry_id = %revocation.entry.entry_id,
                kind = revocation.entry.target_kind.as_str(),
                reason = reason.as_str(),
                "remote MCP admin recorded a revocation entry"
            );
            Json(json!({
                "reason_conflict": revocation.entry.reason != reason,
                "entry": revocation.entry,
                "newly_revoked": revocation.newly_revoked,
                "roots_matched": revocation.roots_matched,
                "roots_revoked": revocation.roots_revoked,
            }))
            .into_response()
        }
        Err(error) => revocation_store_failure(error),
    }
}

async fn handle_admin_session_trust(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let (record, statuses) = match entry {
        RemoteSessionEntry::Active(session) => {
            let record = session.diagnostic_record();
            let statuses = match load_session_revocation_status(&state, &record.capabilities) {
                Ok(statuses) => statuses,
                Err(response) => return response,
            };
            (record, statuses)
        }
        RemoteSessionEntry::Terminal(record) => {
            let statuses = match load_session_revocation_status(&state, &record.capabilities) {
                Ok(statuses) => statuses,
                Err(response) => return response,
            };
            ((*record).clone(), statuses)
        }
    };

    Json(json!({
        "sessionId": session_id,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": statuses,
    }))
    .into_response()
}

async fn handle_admin_revoke_session_trust(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => session.diagnostic_record(),
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    revocation_batch::revoke(state, record).await
}

async fn handle_admin_sessions(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    if let Err(error) = state.sessions.cleanup_due_sessions().await {
        return input::with_source(
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "MCP lifecycle cleanup unavailable",
            ),
            error,
        );
    }
    let (active, terminal) = state.sessions.snapshot().await;
    Json(json!({
        "configured": true,
        "idleExpiryMillis": state.factory.lifecycle_policy.idle_expiry_millis,
        "drainGraceMillis": state.factory.lifecycle_policy.drain_grace_millis,
        "reaperIntervalMillis": state.factory.lifecycle_policy.reaper_interval_millis,
        "activeCount": active.len(),
        "terminalCount": terminal.len(),
        "activeSessions": active.iter().map(serialize_session_diagnostic_record).collect::<Vec<_>>(),
        "terminalSessions": terminal.iter().map(serialize_session_diagnostic_record).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_session_drain(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => {
            if let Err(error) = state.sessions.mark_draining(&session).await {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "failed to drain MCP session without resumable-state risk"
                );
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to drain MCP session safely",
                );
            }
            session.diagnostic_record()
        }
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    Json(json!({
        "sessionId": session_id,
        "draining": true,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
    }))
    .into_response()
}

async fn handle_admin_session_shutdown(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => {
            if let Err(error) = state.sessions.mark_closed(&session).await {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "failed to shut down MCP session without resumable-state risk"
                );
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to shut down MCP session safely",
                );
            }
            state.sessions.remove_active(&session_id).await;
            session.diagnostic_record()
        }
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    Json(json!({
        "sessionId": session_id,
        "shutdown": true,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
    }))
    .into_response()
}

/// Admin-gated Prometheus scrape endpoint, composed from the kernel guard
/// families and the alert-pack families.
async fn handle_admin_metrics(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }
    let alert_pack = || {
        let mut out = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut out);
        out
    };
    let body = chio_metrics_spec::runtime::compose_metrics_body(&[
        &chio_kernel::render_guard_metrics_prometheus,
        &alert_pack,
    ]);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

pub(super) fn validate_admin_request(
    headers: &HeaderMap,
    admin_token: Option<&str>,
) -> Result<(), Response> {
    validate_origin(headers)?;
    validate_admin_auth(headers, admin_token)
}

fn validate_admin_auth(headers: &HeaderMap, admin_token: Option<&str>) -> Result<(), Response> {
    let Some(expected_token) = admin_token else {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "remote admin API is disabled",
        ));
    };
    let token = extract_bearer_token(headers, None)?;
    if token.as_bytes().ct_eq(expected_token.as_bytes()).into() {
        Ok(())
    } else {
        Err(unauthorized_bearer_response(
            "missing or invalid admin bearer token",
            None,
        ))
    }
}

fn admin_list_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_ADMIN_LIST_LIMIT)
        .clamp(1, MAX_ADMIN_LIST_LIMIT)
}

fn control_client(
    state: &RemoteAppState,
) -> Result<Option<trust_control::TrustControlClient>, Response> {
    let Some(url) = state.factory.config.control_url.as_deref() else {
        return Ok(None);
    };
    let Some(token) = state.factory.config.control_token.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote trust admin requires --control-token when --control-url is configured",
        ));
    };
    trust_control::service_runtime::client::build_client(url, token)
        .map(Some)
        .map_err(admin_backend_failure)
}

/// A trust backend failure answers the fixed 500 URN. The cause stays in the
/// server log because it can name store paths, peer URLs and backend bodies.
fn admin_backend_failure(error: impl std::fmt::Display) -> Response {
    error!(error = %error, "remote MCP admin backend operation failed");
    plain_http_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        chio_errors::_generated::error_codes::TRANSPORT_ADMIN_BACKEND_FAILED.urn,
    )
}

/// The response for a revocation store error. An unknown commit outcome
/// poisons the serving owner until the provider restarts; every other error
/// left nothing committed.
pub(super) fn revocation_store_failure(error: chio_kernel::RevocationStoreError) -> Response {
    error!(error = %error, "remote MCP admin revocation store operation failed");
    let body = match error {
        chio_kernel::RevocationStoreError::OutcomeUnknown(_) => {
            "revocation outcome unknown; restart the provider, then retry the same request"
        }
        _ => "revocation store unavailable",
    };
    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, body)
}

fn open_receipt_store(
    state: &RemoteAppState,
) -> Result<chio_store_sqlite::SqliteReceiptStore, Response> {
    let Some(path) = state.factory.config.receipt_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote receipt admin requires --receipt-db",
        ));
    };
    chio_store_sqlite::SqliteReceiptStore::open(path).map_err(admin_backend_failure)
}

fn open_revocation_store(
    state: &RemoteAppState,
) -> Result<chio_store_sqlite::SqliteRevocationStore, Response> {
    state
        .factory
        .durable_admission
        .as_ref()
        .and_then(|runtime| runtime.local_revocation_store())
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::CONFLICT,
                "remote trust admin requires durable revocation state",
            )
        })
}

fn open_budget_store(
    state: &RemoteAppState,
) -> Result<chio_store_sqlite::SqliteBudgetStore, Response> {
    if let Some(runtime) = state.factory.durable_admission.as_ref() {
        if let Some(store) = runtime.local_budget_store() {
            return Ok(store);
        }
    }
    let Some(path) = state.factory.config.budget_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote budget admin requires durable budget state",
        ));
    };
    chio_store_sqlite::SqliteBudgetStore::open(path).map_err(admin_backend_failure)
}

fn load_authority_status(state: &RemoteAppState) -> Result<Value, Response> {
    if let Some(client) = control_client(state)? {
        let status = client.authority_status().map_err(admin_backend_failure)?;
        return Ok(json!({
            "configured": status.configured,
            "backend": status.backend,
            "publicKey": status.public_key,
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
            "trustedPublicKeys": status.trusted_public_keys,
        }));
    }

    if let Some(path) = state.factory.config.authority_db_path.as_deref() {
        let status = chio_store_sqlite::SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(admin_backend_failure)?;
        return Ok(json!({
            "configured": true,
            "backend": "sqlite",
            "publicKey": status.public_key.to_hex(),
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": status.trusted_public_keys.into_iter().map(|key| key.to_hex()).collect::<Vec<_>>(),
        }));
    }

    let Some(path) = state.factory.config.authority_seed_path.as_deref() else {
        return Ok(json!({
            "configured": false,
            "backend": Value::Null,
            "publicKey": Value::Null,
            "appliesToFutureSessionsOnly": true,
        }));
    };

    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(json!({
            "configured": true,
            "backend": "seed_file",
            "publicKey": public_key.to_hex(),
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": vec![public_key.to_hex()],
        })),
        Ok(None) => Ok(json!({
            "configured": true,
            "backend": "seed_file",
            "publicKey": Value::Null,
            "materialized": false,
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": Vec::<String>::new(),
        })),
        Err(error) => Err(admin_backend_failure(error)),
    }
}

fn load_session_revocation_status(
    state: &RemoteAppState,
    capabilities: &[RemoteSessionCapability],
) -> Result<Vec<Value>, Response> {
    if let Some(client) = control_client(state)? {
        return capabilities
            .iter()
            .map(|capability| {
                client
                    .list_revocations(&RevocationQuery {
                        after: None,
                        kind: None,
                        capability_id: Some(capability.id.clone()),
                        limit: Some(1),
                    })
                    .map(|response| {
                        json!({
                            "capabilityId": capability.id,
                            "issuerPublicKey": capability.issuer_public_key,
                            "subjectPublicKey": capability.subject_public_key,
                            "revoked": response.revoked.unwrap_or(false),
                        })
                    })
                    .map_err(admin_backend_failure)
            })
            .collect();
    }

    let store = open_revocation_store(state)?;
    capabilities
        .iter()
        .map(|capability| {
            store
                .is_revoked(&capability.id)
                .map(|revoked| {
                    json!({
                        "capabilityId": capability.id,
                        "issuerPublicKey": capability.issuer_public_key,
                        "subjectPublicKey": capability.subject_public_key,
                        "revoked": revoked,
                    })
                })
                .map_err(admin_backend_failure)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_admin_request_accepts_local_origin_and_matching_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer admin-token"),
        );

        assert!(validate_admin_request(&headers, Some("admin-token")).is_ok());
    }

    #[test]
    fn validate_admin_request_rejects_disallowed_origin_before_bearer_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://remote.example"));

        let response = match validate_admin_request(&headers, Some("admin-token")) {
            Ok(()) => panic!("origin validation should run before bearer auth"),
            Err(response) => response,
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
