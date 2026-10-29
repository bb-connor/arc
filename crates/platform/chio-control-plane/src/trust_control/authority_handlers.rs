//! HTTP handlers for the capability-authority admin surface: authority status
//! and rotation, capability issuance and revocation, SCIM user lifecycle,
//! enterprise-provider records, and federation admission policies.

use super::cluster::respond_after_leader_visible_write;
use super::report_rendering::{
    forward_authority_post_to_leader, forward_post_to_leader, forward_scim_delete_to_leader,
    forward_scim_post_to_leader,
};
use super::report_validation::{
    enforce_authority_mutation_fence, inspect_authority_state, load_authority_status_for_state,
    load_capability_authority, refresh_authority_mutation_fence, rotate_authority_for_state,
    run_authority_commit, validate_authority_issue_auth, validate_authority_mutation_auth,
    validate_authority_mutation_term, validate_caller,
};
use super::*;

pub(crate) async fn handle_authority_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::AuthorityRead) {
        return response;
    }
    match inspect_authority_state(&state, load_authority_status_for_state).await {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

pub(crate) async fn handle_authority_key_log_sync(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AuthorityKeyLogSyncRequest>,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::AuthorityAdmin) {
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
    match canonical_json_bytes(&response) {
        Ok(body) => ([(CONTENT_TYPE, "application/json")], body).into_response(),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority key-log synchronization could not encode witnessed history",
        ),
    }
}

pub(crate) async fn handle_rotate_authority(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    let forwarded = match validate_authority_mutation_auth(&headers, &state) {
        Ok(forwarded) => forwarded,
        Err(response) => return response,
    };
    match forward_authority_post_to_leader(&state, &headers, AUTHORITY_PATH, &json!({})).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    run_authority_commit(&state, move |state| {
        validate_authority_mutation_term(state, forwarded)?;
        Ok(rotate_authority_blocking(state))
    })
    .await
    .unwrap_or_else(std::convert::identity)
}

fn rotate_authority_blocking(state: &TrustServiceState) -> Response {
    if let Err(response) = enforce_authority_mutation_fence(state) {
        return response;
    }
    match rotate_authority_for_state(state) {
        Ok(status) => {
            if let Err(response) = refresh_authority_mutation_fence(state) {
                return response;
            }
            respond_after_leader_visible_write(
                state,
                "rotated authority was not visible on the leader after write",
                || {
                    let visible_status = load_authority_status_for_state(state)?;
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

pub(crate) async fn handle_issue_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<IssueCapabilityRequest>,
) -> Response {
    let forwarded = match validate_authority_issue_auth(&headers, &state) {
        Ok(forwarded) => forwarded,
        Err(response) => return response,
    };
    match forward_authority_post_to_leader(&state, &headers, ISSUE_CAPABILITY_PATH, &payload).await
    {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    inspect_authority_state(&state, move |state| {
        validate_authority_mutation_term(state, forwarded)?;
        Ok(issue_capability_blocking(state, payload))
    })
    .await
    .unwrap_or_else(std::convert::identity)
}

fn issue_capability_blocking(
    state: &TrustServiceState,
    payload: IssueCapabilityRequest,
) -> Response {
    if let Err(response) = enforce_authority_mutation_fence(state) {
        return response;
    }
    let subject = match PublicKey::from_hex(&payload.subject_public_key) {
        Ok(subject) => subject,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(runtime_attestation) = payload.runtime_attestation.as_ref() {
        if let Err(error) = runtime_attestation.validate_workload_identity_binding() {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                &format!("runtime attestation workload identity is invalid: {error}"),
            );
        }
    }
    match load_capability_authority(state) {
        Ok(authority) => {
            match authority.issue_capability_with_attestation(
                &subject,
                payload.scope,
                payload.ttl_seconds,
                payload.runtime_attestation,
            ) {
                Ok(capability) => Json(IssueCapabilityResponse { capability }).into_response(),
                Err(chio_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
                    plain_http_error(StatusCode::FORBIDDEN, &error)
                }
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
        Err(response) => response,
    }
}

pub(crate) async fn handle_scim_create_user(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserResource>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_caller(&headers, &state.config, Scope::ScimWrite) {
        return response;
    }
    match forward_scim_post_to_leader(&state, &headers, SCIM_USERS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let provider = match validated_scim_provider_for_request(&state.config, &payload) {
        Ok(provider) => provider,
        Err(error) => return scim_error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let (path, mut registry) = match load_scim_lifecycle_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return scim_error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = clock_now;
    let mut record = match build_scim_user_record(&provider, payload, now, None) {
        Ok(record) => record,
        Err(error) => return scim_error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    record.scim_user.meta = Some(crate::scim_lifecycle::ScimMeta {
        resource_type: Some("User".to_string()),
        location: Some(scim_user_location(&record.user_id)),
    });
    if let Err(error) = registry.insert(record.clone()) {
        return scim_error_response(StatusCode::CONFLICT, &error.to_string());
    }
    if let Err(error) = registry.save(&path) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    scim_json_response(StatusCode::CREATED, &record.scim_user)
}

pub(crate) async fn handle_scim_delete_user(
    State(state): State<TrustServiceState>,
    AxumPath(user_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_caller(&headers, &state.config, Scope::ScimWrite) {
        return response;
    }
    match forward_scim_delete_to_leader(&state, &headers, &scim_user_location(&user_id)).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (path, mut registry) = match load_scim_lifecycle_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return scim_error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    let Some(record) = registry.get(&user_id).cloned() else {
        return scim_error_response(
            StatusCode::NOT_FOUND,
            &format!("scim user `{user_id}` was not found"),
        );
    };
    if !record.active() {
        return scim_json_response(StatusCode::OK, &record.scim_user);
    }
    let now = clock_now;
    let revocation_store = match state.revocation_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let mut revoked_capability_ids = Vec::new();
    for capability_id in &record.tracked_capability_ids {
        match revocation_store.is_revoked(capability_id) {
            Ok(true) => {}
            Ok(false) => match revocation_store.revoke(capability_id) {
                Ok(_) => revoked_capability_ids.push(capability_id.clone()),
                Err(error) => {
                    return scim_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &error.to_string(),
                    );
                }
            },
            Err(error) => {
                return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    }
    let receipt_store = match state.receipt_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipt = match build_scim_deprovision_receipt(
        &state.config,
        &record,
        &revoked_capability_ids,
        now,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return scim_error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = receipt_store.append_chio_receipt(&receipt) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let updated =
        match registry.deactivate(&user_id, now, &revoked_capability_ids, Some(&receipt.id)) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return scim_error_response(
                    StatusCode::NOT_FOUND,
                    &format!("scim user `{user_id}` was not found"),
                );
            }
            Err(error) => {
                return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
    if let Err(error) = registry.save(&path) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    scim_json_response(StatusCode::OK, &updated.scim_user)
}

pub(crate) async fn handle_list_enterprise_providers(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationRead) {
        return response;
    }
    match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(EnterpriseProviderListResponse {
            configured: true,
            count: registry.providers.len(),
            providers: registry.providers.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_get_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationRead) {
        return response;
    }
    let registry = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.providers.get(&provider_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("enterprise provider `{provider_id}` was not found"),
        ),
    }
}

pub(crate) async fn handle_upsert_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut record): Json<EnterpriseProviderRecord>,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationWrite) {
        return response;
    }
    use super::registry_write_lane::{
        configured_registry_file, run_registry_transaction, RegistryOperationError,
    };
    let path = match configured_registry_file(
        state.config.enterprise_providers_file.as_deref(),
        "--enterprise-providers-file",
        "enterprise provider",
    ) {
        Ok(path) => path,
        Err(response) => return response,
    };
    record.provider_id = provider_id;
    let lane = state.operator_registry_write_lane.clone();
    run_registry_transaction(&lane, move || {
        EnterpriseProviderRegistry::update(&path, |registry| {
            Ok::<_, RegistryOperationError>(registry.upsert(record))
        })
    })
    .await
}

pub(crate) async fn handle_delete_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationWrite) {
        return response;
    }
    use super::registry_write_lane::{
        configured_registry_file, run_registry_transaction, RegistryOperationError,
    };
    let path = match configured_registry_file(
        state.config.enterprise_providers_file.as_deref(),
        "--enterprise-providers-file",
        "enterprise provider",
    ) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let lane = state.operator_registry_write_lane.clone();
    run_registry_transaction(&lane, move || {
        EnterpriseProviderRegistry::update(&path, |registry| {
            let deleted = registry.remove(&provider_id);
            Ok::<_, RegistryOperationError>(EnterpriseProviderDeleteResponse {
                provider_id,
                deleted,
            })
        })
    })
    .await
}

pub(crate) async fn handle_list_federation_policies(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationRead) {
        return response;
    }
    match load_federation_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(FederationAdmissionPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_get_federation_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationRead) {
        return response;
    }
    let registry = match load_federation_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&policy_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("federation policy `{policy_id}` was not found"),
        ),
    }
}

pub(crate) async fn handle_upsert_federation_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
    Json(record): Json<FederationAdmissionPolicyRecord>,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationWrite) {
        return response;
    }
    if record.policy.body.policy_id != policy_id {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "federation policy path id must match the signed policy body policy_id",
        );
    }
    let (path, mut registry) = match load_federation_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = registry.upsert(record.clone()) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let Some(saved) = registry.get(&policy_id).cloned() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "federation policy upsert did not persist the requested record",
        );
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(saved).into_response()
}

pub(crate) async fn handle_delete_federation_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationWrite) {
        return response;
    }
    let (path, mut registry) = match load_federation_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&policy_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(FederationAdmissionPolicyDeleteResponse { policy_id, deleted }).into_response()
}

pub(crate) async fn handle_evaluate_federation_policy(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FederationAdmissionEvaluationRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_caller(&headers, &state.config, Scope::FederationWrite) {
        return response;
    }
    match forward_post_to_leader(&state, &headers, FEDERATION_POLICY_EVALUATE_PATH, &request).await
    {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let now = clock_now;
    match service_runtime::issuance::evaluate_federation_policy_request(&state, &request, now) {
        Ok(response) => Json(response).into_response(),
        Err(error) if error.to_string().contains("was not found") => {
            plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_list_revocations(
    State(state): State<TrustServiceState>,
    Query(query): Query<RevocationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_caller(&headers, &state.config, Scope::RevocationsRead) {
        return response;
    }
    let Some(listing) = query.listing() else {
        return plain_http_error(StatusCode::BAD_REQUEST, INVALID_REVOCATION_REQUEST);
    };
    let store = match state.revocation_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    match listing {
        RevocationListing::Status(capability_id) => match store.revocation_entry(&capability_id) {
            Ok(entry_id) => Json(RevocationStatusResponse {
                capability_id,
                revoked: entry_id.is_some(),
                entry_id,
            })
            .into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        RevocationListing::Page { after, limit, kind } => {
            match store.list_revocation_entries_after(after, limit, kind) {
                Ok((entries, head)) => Json(RevocationEntryPage {
                    next_after: entries.last().map_or(after, |(entry_seq, _)| *entry_seq),
                    entries: entries
                        .into_iter()
                        .map(|(entry_seq, entry)| RevocationEntryPageItem { entry_seq, entry })
                        .collect(),
                    head,
                })
                .into_response(),
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
    }
}

pub(crate) async fn handle_revoke_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeCapabilityRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_caller(&headers, &state.config, Scope::RevocationsWrite) {
        return response;
    }
    let Ok(target) =
        chio_core_types::root_authority::RevocationTarget::capability(&payload.capability_id)
    else {
        return plain_http_error(StatusCode::BAD_REQUEST, INVALID_REVOCATION_REQUEST);
    };
    match forward_post_to_leader(&state, &headers, REVOCATIONS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match state.revocation_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.revoke_target(&target, &[], None, payload.reason) {
        Ok(revocation) => {
            if revocation.roots_revoked > 0 {
                // A locally originated capability revoke: the revoke instant is
                // now, so the propagation lag is ~0. Emit so the
                // capability-revocation SLO reflects real capability revokes.
                let revoked_now = i64::try_from(clock_now).unwrap_or(0);
                super::cluster::observe_capability_revocation_lag(revoked_now);
            }
            respond_after_leader_visible_write(
                &state,
                "revocation was not visible on the leader after write",
                || {
                    let visible = store
                        .revocation_entry(&payload.capability_id)
                        .map_err(|error| {
                            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                        })?
                        .is_some();
                    Ok(visible.then(|| RevokeCapabilityResponse {
                        entry: revocation.entry.clone(),
                        newly_revoked: revocation.newly_revoked,
                        roots_matched: revocation.roots_matched,
                        roots_revoked: revocation.roots_revoked,
                    }))
                },
            )
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}
