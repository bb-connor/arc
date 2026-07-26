pub(crate) async fn handle_scim_create_user(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserResource>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_scim_post_to_leader(&state, SCIM_USERS_PATH, &payload).await {
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
    let now = unix_timestamp_now();
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_scim_delete_to_leader(&state, &scim_user_location(&user_id)).await {
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
    let now = unix_timestamp_now();
    let revocation_store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let mut revoked_capability_ids = Vec::new();
    for capability_id in &record.tracked_capability_ids {
        match revocation_store.is_revoked(capability_id) {
            Ok(true) => {}
            Ok(false) if state.cluster.is_some() => {
                let revoked_at = match i64::try_from(now) {
                    Ok(revoked_at) => revoked_at,
                    Err(_) => {
                        return scim_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "revocation timestamp exceeds the supported range",
                        );
                    }
                };
                match apply_cluster_revocation(&state, capability_id, revoked_at).await {
                    Ok(response) if response.newly_revoked => {
                        revoked_capability_ids.push(capability_id.clone());
                    }
                    Ok(_) => {}
                    Err(response) => return response,
                }
            }
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
    let receipt_store = match open_receipt_store(&state.config) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    record.provider_id = provider_id.clone();
    registry.upsert(record);
    let Some(saved) = registry.providers.get(&provider_id).cloned() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "enterprise provider upsert did not persist the requested record",
        );
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(saved).into_response()
}

pub(crate) async fn handle_delete_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&provider_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(EnterpriseProviderDeleteResponse {
        provider_id,
        deleted,
    })
    .into_response()
}

pub(crate) async fn handle_list_federation_policies(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FEDERATION_POLICY_EVALUATE_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let now = unix_timestamp_now();
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
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let revocations =
        match store.list_revocations(list_limit(query.limit), query.capability_id.as_deref()) {
            Ok(revocations) => revocations,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
    let revoked = query
        .capability_id
        .as_deref()
        .map(|capability_id| store.is_revoked(capability_id))
        .transpose();
    let revoked = match revoked {
        Ok(value) => value,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(revocation_list_response(
        query.capability_id,
        revoked,
        revocations,
    ))
    .into_response()
}

pub(crate) async fn handle_revoke_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.cluster.is_some() {
        let revoked_at = match i64::try_from(unix_timestamp_now()) {
            Ok(revoked_at) => revoked_at,
            Err(_) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "revocation timestamp exceeds the supported range",
                );
            }
        };
        return match apply_cluster_revocation(&state, &payload.capability_id, revoked_at).await {
            Ok(response) => json_response_with_leader_visibility(&state, response),
            Err(response) => return response,
        };
    }
    match forward_post_to_leader(&state, REVOCATIONS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.revoke(&payload.capability_id) {
        Ok(newly_revoked) => {
            if newly_revoked {
                // A locally originated capability revoke: the revoke instant is
                // now, so the propagation lag is ~0. Emit so the
                // capability-revocation SLO reflects real capability revokes.
                let revoked_now = i64::try_from(unix_timestamp_now()).unwrap_or(0);
                super::cluster::observe_capability_revocation_lag(revoked_now);
            }
            respond_after_leader_visible_write(
                &state,
                "revocation was not visible on the leader after write",
                || {
                    let revoked = store.is_revoked(&payload.capability_id).map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                    if revoked {
                        Ok(Some(RevokeCapabilityResponse {
                            capability_id: payload.capability_id.clone(),
                            revoked: true,
                            newly_revoked,
                        }))
                    } else {
                        Ok(None)
                    }
                },
            )
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn apply_cluster_revocation(
    state: &TrustServiceState,
    capability_id: &str,
    revoked_at: i64,
) -> Result<RevokeCapabilityResponse, Response> {
    let command = ConsensusRevocationProposal {
        capability_id: capability_id.to_string(),
    };
    let result = super::cluster::propose_admission_command(
        state,
        cluster_revocation_operation_id(capability_id),
        AdmissionCommandKind::Revoke,
        &command,
    )
    .await?;
    let response = serde_json::from_str::<RevokeCapabilityResponse>(&result.response_json)
        .map_err(|error| {
            plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("persisted revocation consensus result is invalid: {error}"),
            )
        })?;
    if response.newly_revoked {
        super::cluster::observe_capability_revocation_lag(revoked_at);
    }
    Ok(response)
}

pub(super) fn cluster_revocation_operation_id(capability_id: &str) -> String {
    format!("revocation:sha256:{}", sha256_hex(capability_id.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_security_types::ports::{
        response_affected_set_hash, ActionId, CausalLineageCommitMetadata,
        CausalLineageCommitRequest, CausalLineageCommitStore, CausalLineageEdges,
        CausalLineageFenceRequest, CausalLineageNode, CausalLineageNodeKind, CausalLineageNodes,
        LineageFenceRequest, LineageId, RecordId, RecordIdSet, TenantId,
    };
    use chio_test_support::prelude::*;

    fn unique_test_directory() -> PathBuf {
        chio_test_support::private_fs::private_tempdir("chio-signed-capability-issuance-")
            .test_unwrap()
            .keep()
    }

    fn test_state(
        receipt_db_path: PathBuf,
        authority_signer: &Keypair,
        tenant_id: &TenantId,
        allowed_scope: ChioScope,
        workload_signer: &Keypair,
        session_admission_signer: &Keypair,
    ) -> TrustServiceState {
        TrustServiceState {
            config: TrustServiceConfig {
                listen: "127.0.0.1:0".parse().test_unwrap(),
                service_token: "service-secret".to_string(),
                dashboard_read_token: None,
                dashboard_report_origin: None,
                dashboard_report_token: None,
                dashboard_allow_insecure_report_origin: false,
                authority_admin_token: None,
                authority_workloads: vec![AuthorityWorkloadPolicy {
                    credential_token: "workload-secret".to_string(),
                    tenant_id: tenant_id.to_string(),
                    workload_id: "workload-signed-issuance".to_string(),
                    server_id: "signed-issuance".to_string(),
                    signer_public_key: workload_signer.public_key(),
                    session_admission_public_key: session_admission_signer.public_key(),
                    allowed_capabilities: vec![crate::policy::DefaultCapability {
                        scope: allowed_scope,
                        ttl: 60,
                    }],
                }],
                tenant_read_tokens: BTreeMap::new(),
                receipt_db_path: Some(receipt_db_path),
                revocation_db_path: None,
                authority_seed_path: None,
                authority_db_path: None,
                authority_keyring_config_path: None,
                budget_db_path: None,
                partition_escrow_authority: None,
                enterprise_providers_file: None,
                federation_policies_file: None,
                scim_lifecycle_file: None,
                verifier_policies_file: None,
                verifier_challenge_db_path: None,
                passport_statuses_file: None,
                passport_issuance_offers_file: None,
                certification_registry_file: None,
                certification_discovery_file: None,
                issuance_policy: None,
                runtime_assurance_policy: None,
                advertise_url: Some("http://node-a".to_string()),
                allow_local_peer_urls: true,
                certification_public_metadata_ttl_seconds: PUBLIC_DISCOVERY_TTL_SECS,
                peer_urls: Vec::new(),
                cluster_node_seed_path: None,
                cluster_replay_db_path: None,
                cluster_members: Vec::new(),
                cluster_sync_interval: Duration::from_millis(25),
                roster_policy: None,
                memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            },
            dashboard_sessions: dashboard_auth::DashboardSessionStore::production(),
            dashboard_report_bridge: None,
            authority_keyring: None,
            authority_test_backend: Some(Arc::new(chio_core::Ed25519Backend::new(
                authority_signer.clone(),
            ))),
            active_defense: service_runtime::TrustControlActiveDefenseService::disabled(),
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            authority_issuance_rotation_lock: Arc::new(Mutex::new(())),
            cluster: None,
            cluster_progress: None,
        }
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workload-secret"),
        );
        headers
    }

    fn signed_issuance_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "signed-issuance".to_string(),
                tool_name: "invoke".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_issue_request(
        request_nonce: String,
        requested_at: u64,
        tenant_id: TenantId,
        subject: &PublicKey,
        scope: ChioScope,
        authority_signer: &Keypair,
        workload_signer: &Keypair,
        session_admission_signer: &Keypair,
    ) -> IssueCapabilityRequest {
        let security_session_id = "session-signed-issuance".to_string();
        let principal_id = "principal-signed-issuance".to_string();
        let context_generation = 1;
        let context_digest = sha256_hex(
            &canonical_json_bytes(&json!({
                "schema": "chio.remote-capability-security-context.v1",
                "tenantId": tenant_id.as_str(),
                "securitySessionId": security_session_id.as_str(),
                "principalId": principal_id.as_str(),
                "contextGeneration": context_generation,
                "serverId": "signed-issuance",
                "subjectPublicKey": subject.to_hex(),
                "workloadSignerPublicKey": workload_signer.public_key(),
                "sessionAdmissionSignerPublicKey": session_admission_signer.public_key(),
            }))
            .test_unwrap(),
        );
        IssueCapabilityRequest::new(
            request_nonce,
            requested_at,
            tenant_id,
            LineageId::new(format!("mcp-lineage:{context_digest}")).test_unwrap(),
            security_session_id,
            principal_id,
            format!("mcp-isolation:{context_digest}"),
            context_generation,
            "workload-signed-issuance".to_string(),
            "signed-issuance".to_string(),
            authority_signer.public_key(),
            1,
            subject,
            scope,
            60,
            None,
            workload_signer,
            session_admission_signer,
        )
        .test_unwrap()
    }

    #[tokio::test]
    async fn capability_issuance_handler_returns_request_bound_signed_envelope() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        drop(SqliteReceiptStore::open(&receipt_path).test_unwrap());
        let authority = Keypair::generate();
        let workload_signer = Keypair::generate();
        let session_admission_signer = Keypair::generate();
        let subject = Keypair::generate();
        let now = unix_timestamp_now();
        let tenant_id = TenantId::new("tenant-signed-issuance").test_unwrap();
        let scope = signed_issuance_scope();
        let request = signed_issue_request(
            "da".repeat(32),
            now,
            tenant_id.clone(),
            &subject.public_key(),
            scope.clone(),
            &authority,
            &workload_signer,
            &session_admission_signer,
        );
        let state = test_state(
            receipt_path,
            &authority,
            &tenant_id,
            scope,
            &workload_signer,
            &session_admission_signer,
        );

        let response =
            handle_issue_capability(State(state.clone()), auth_headers(), Json(request.clone()))
                .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(
            response.into_body(),
            CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES as usize,
        )
        .await
        .test_unwrap();
        let signed: SignedIssueCapabilityResponse = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(body.as_ref(), canonical_json_bytes(&signed).test_unwrap());
        signed
            .verify(
                &authority.public_key(),
                1,
                &request,
                unix_timestamp_now(),
            )
            .test_unwrap();
        assert_eq!(signed.body.capability.subject, subject.public_key());
        assert!(signed.body.capability.scope.is_subset_of(&request.scope));
        let receipt_store = SqliteReceiptStore::open(
            state
                .config
                .receipt_db_path
                .as_deref()
                .unwrap_or_else(|| panic!("test receipt path missing")),
        )
        .test_unwrap();
        assert!(receipt_store
            .capability_snapshot_has_issuance_admission(
                &request.tenant_id,
                &request.lineage_id,
                &signed.body.capability,
                None,
            )
            .test_unwrap());
    }

    #[tokio::test]
    async fn active_freeze_fence_denies_http_capability_issuance_before_evidence_commit() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("frozen-receipts.db");
        let receipt_store = SqliteReceiptStore::open(&receipt_path).test_unwrap();
        let authority = Keypair::generate();
        let workload_signer = Keypair::generate();
        let session_admission_signer = Keypair::generate();
        let subject = Keypair::generate();
        let tenant_id = TenantId::new("tenant-frozen-issuance").test_unwrap();
        let scope = ChioScope::default();
        let request = signed_issue_request(
            "fb".repeat(32),
            unix_timestamp_now(),
            tenant_id.clone(),
            &subject.public_key(),
            scope.clone(),
            &authority,
            &workload_signer,
            &session_admission_signer,
        );
        let lineage_id = request.lineage_id.clone();
        let root_id = RecordId::new(lineage_id.as_str()).test_unwrap();
        receipt_store
            .commit_causal_lineage(&CausalLineageCommitRequest {
                tenant_id: tenant_id.clone(),
                metadata: CausalLineageCommitMetadata {
                    source_lineage_version: 1,
                    observed_commit_index: 1,
                    authoritative_commit_index: 1,
                    completeness_watermark: Some(1),
                },
                nodes: CausalLineageNodes::new(vec![CausalLineageNode {
                    tenant_id: tenant_id.clone(),
                    node_id: root_id.clone(),
                    kind: CausalLineageNodeKind::Capability,
                }])
                .test_unwrap(),
                edges: CausalLineageEdges::new(Vec::new()).test_unwrap(),
            })
            .test_unwrap();
        let frozen_ids = RecordIdSet::new(vec![root_id]).test_unwrap();
        let affected_set_hash = response_affected_set_hash(&tenant_id, &frozen_ids).test_unwrap();
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .test_unwrap()
                .as_millis(),
        )
        .test_unwrap();
        receipt_store
            .acquire_causal_fence(&CausalLineageFenceRequest {
                fence: LineageFenceRequest {
                    tenant_id: tenant_id.clone(),
                    action_id: ActionId::new("freeze-http-issuance").test_unwrap(),
                    expected_commit_index: 1,
                    expected_affected_set_hash: affected_set_hash,
                    scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
                        "freeze-http-worker",
                    )
                    .test_unwrap(),
                    scheduler_fencing_token: 1,
                    expires_at_unix_ms: now_ms.saturating_add(30_000),
                },
                frozen_affected_ids: frozen_ids,
            })
            .test_unwrap();
        let lineage_seq_before_issuance = receipt_store.max_lineage_seq().test_unwrap();
        let state = test_state(
            receipt_path,
            &authority,
            &tenant_id,
            scope,
            &workload_signer,
            &session_admission_signer,
        );

        let response = handle_issue_capability(State(state), auth_headers(), Json(request)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            receipt_store.max_lineage_seq().test_unwrap(),
            lineage_seq_before_issuance
        );
    }
}
