//! HTTP handlers for the portable-passport surface: OID4VCI issuance, OID4VP
//! presentation and wallet exchange, passport status lifecycle, verifier
//! policies, presentation challenges, and federated issuance.

use super::report_rendering::{
    forward_post_to_leader, forward_public_passport_challenge_to_leader,
};
use super::report_validation::{
    bearer_token_from_headers, load_capability_authority,
    load_capability_authority_with_deferred_lineage, validate_service_auth,
};
use super::*;

#[path = "passport_handlers/public_authority_trust.rs"]
mod public_authority_trust;
use public_authority_trust::{public_oid4vp_trusted_keys, run_public_authority_trust_read};

pub(crate) async fn handle_passport_issuer_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        match public_passport_credential_issuer_with_status(
            &state.config,
            &state.finding_challenge_clock,
            status,
        ) {
            Ok(metadata) => Json(metadata).into_response(),
            Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        }
    })
    .await
}

pub(crate) async fn handle_public_passport_issuer_discovery(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        match build_public_issuer_discovery_with_status(
            &state.config,
            &state.finding_challenge_clock,
            status,
        ) {
            Ok(document) => Json(document).into_response(),
            Err(error) => public_discovery_error_response(&error),
        }
    })
    .await
}

pub(crate) async fn handle_public_passport_verifier_discovery(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        match build_public_verifier_discovery_with_status(
            &state.config,
            &state.finding_challenge_clock,
            status,
        ) {
            Ok(document) => Json(document).into_response(),
            Err(error) => public_discovery_error_response(&error),
        }
    })
    .await
}

pub(crate) async fn handle_public_passport_discovery_transparency(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        let document = match status {
            Some(status) => build_public_discovery_transparency_with_status(
                &state.config,
                &state.finding_challenge_clock,
                Some(status),
            ),
            None => {
                build_public_discovery_transparency(&state.config, &state.finding_challenge_clock)
            }
        };
        match document {
            Ok(document) => Json(document).into_response(),
            Err(error) => public_discovery_error_response(&error),
        }
    })
    .await
}

pub(crate) async fn handle_oid4vp_verifier_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        let metadata = match status {
            Some(status) => build_oid4vp_verifier_metadata_from_status(&state.config, status),
            None => build_oid4vp_verifier_metadata(&state.config, &state.finding_challenge_clock),
        };
        match metadata {
            Ok(metadata) => Json(metadata).into_response(),
            Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        }
    })
    .await
}

pub(crate) async fn handle_passport_issuer_jwks(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        let jwks = match status {
            Some(status) => build_oid4vp_verifier_jwks_from_status(&state.config, status),
            None => build_oid4vp_verifier_jwks(&state.config, &state.finding_challenge_clock),
        };
        match jwks {
            Ok(jwks) => Json(jwks).into_response(),
            Err(error) => {
                let message = error.to_string();
                let status = if message.contains("configured authority")
                    || message.contains("did not publish any signing keys")
                    || message.contains("--authority-seed-file or --authority-db")
                {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::CONFLICT
                };
                plain_http_error(status, &message)
            }
        }
    })
    .await
}

pub(crate) fn public_discovery_error_response(error: &CliError) -> Response {
    let message = error.to_string();
    let status = if message.contains("configured authority")
        || message.contains("authority signing seed")
        || message.contains("did not publish any signing keys")
        || message.contains("--authority-seed-file or --authority-db")
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::CONFLICT
    };
    plain_http_error(status, &message)
}

pub(crate) async fn handle_passport_sd_jwt_type_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    let Some(advertise_url) = state.config.advertise_url.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "portable credential type metadata requires --advertise-url on the trust-control service",
        );
    };
    if state.config.authority_seed_path.is_none() && state.config.authority_db_path.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "portable credential type metadata is unavailable because no authority signing key is configured",
        );
    }
    match build_chio_passport_sd_jwt_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_passport_jwt_vc_json_type_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    let Some(advertise_url) = state.config.advertise_url.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "portable credential type metadata requires --advertise-url on the trust-control service",
        );
    };
    if state.config.authority_seed_path.is_none() && state.config.authority_db_path.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "portable credential type metadata is unavailable because no authority signing key is configured",
        );
    }
    match build_chio_passport_jwt_vc_json_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_create_passport_issuance_offer(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreatePassportIssuanceOfferRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_ISSUANCE_OFFERS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    use super::registry_write_lane::{run_registry_transaction, RegistryOperationError};
    let Some(path) = state.config.passport_issuance_offers_file.clone() else {
        return plain_http_error(StatusCode::CONFLICT,
            "passport issuance requires --passport-issuance-offers-file on the trust-control service");
    };
    let lane = state.operator_registry_write_lane.clone();
    run_registry_transaction(&lane, move || {
        PassportIssuanceOfferRegistry::update_for_issuance(&path, |registry| {
            issuer_authority::run(&state, |state, signer| {
                let metadata = issuer_authority::metadata(&state.config, signer)?;
                if state.config.passport_statuses_file.is_some() {
                    let clock_now =
                        super::json_ingress::wallet_time(&state.finding_challenge_clock)
                            .map_err(RegistryOperationError::authority)?;
                    portable_passport_status_reference_for_service(
                        &state.config,
                        &payload.passport,
                        clock_now,
                    )
                    .map_err(RegistryOperationError::bad_request)?;
                }
                let clock_now = super::json_ingress::wallet_time(&state.finding_challenge_clock)
                    .map_err(RegistryOperationError::authority)?;
                registry
                    .issue_offer(
                        &metadata,
                        payload.passport,
                        payload.credential_configuration_id.as_deref(),
                        payload.ttl_seconds,
                        clock_now,
                    )
                    .map_err(RegistryOperationError::bad_request)
            })
        })
    })
    .await
}

pub(crate) async fn handle_redeem_passport_issuance_token(
    State(state): State<TrustServiceState>,
    Json(payload): Json<Oid4vciTokenRequest>,
) -> Response {
    use super::registry_write_lane::{run_registry_transaction, RegistryOperationError};
    let Some(path) = state.config.passport_issuance_offers_file.clone() else {
        return plain_http_error(StatusCode::CONFLICT,
            "passport issuance requires --passport-issuance-offers-file on the trust-control service");
    };
    if let Err(error) = payload.validate() {
        return plain_http_error(StatusCode::BAD_REQUEST, &CliError::from(error).to_string());
    }
    let lane = state.public_passport_issuance_lane.clone();
    run_registry_transaction(&lane, move || {
        PassportIssuanceOfferRegistry::update(&path, |registry| {
            issuer_authority::run(&state, |state, signer| {
                let metadata = issuer_authority::metadata(&state.config, signer)?;
                let clock_now = super::json_ingress::wallet_time(&state.finding_challenge_clock)
                    .map_err(RegistryOperationError::authority)?;
                let response = registry
                    .redeem_pre_authorized_code(&metadata, &payload, clock_now, 300)
                    .map_err(RegistryOperationError::bad_request)?;
                registry.prune_dead(clock_now);
                Ok(response)
            })
        })
    })
    .await
}

pub(crate) async fn handle_redeem_passport_issuance_credential(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<Oid4vciCredentialRequest>,
) -> Response {
    let access_token = match bearer_token_from_headers(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    use super::registry_write_lane::{run_registry_transaction, RegistryOperationError};
    let Some(path) = state.config.passport_issuance_offers_file.clone() else {
        return plain_http_error(StatusCode::CONFLICT,
            "passport issuance requires --passport-issuance-offers-file on the trust-control service");
    };
    let lane = state.public_passport_issuance_lane.clone();
    run_registry_transaction(&lane, move || {
        PassportIssuanceOfferRegistry::update(&path, |registry| {
            let issuer = state.config.advertise_url.as_deref().ok_or_else(|| {
                RegistryOperationError::Configuration(
                    "passport issuance requires --advertise-url on the trust-control service"
                        .to_string(),
                )
            })?;
            let clock_now = super::json_ingress::wallet_time(&state.finding_challenge_clock)
                .map_err(RegistryOperationError::authority)?;
            // An upload can outlive its entitlement. Check the fresh locked
            // state before metadata resolution can create signing material.
            registry
                .validate_credential_entitlement(issuer, &access_token, clock_now)
                .map_err(RegistryOperationError::invalid_entitlement)?;
            issuer_authority::run(&state, |state, signer| {
                let metadata = issuer_authority::metadata(&state.config, signer)?;
                let portable_status_registry = state
                    .config
                    .passport_statuses_file
                    .as_deref()
                    .map(PassportStatusRegistry::load)
                    .transpose()
                    .map_err(RegistryOperationError::configuration)?;
                // Signing custody and status reads can outlive the first
                // entitlement check. Recheck at current owner time before the
                // final redemption; request/profile failures remain 400.
                let clock_now = super::json_ingress::wallet_time(&state.finding_challenge_clock)
                    .map_err(RegistryOperationError::authority)?;
                registry
                    .validate_credential_entitlement(
                        &metadata.credential_issuer,
                        &access_token,
                        clock_now,
                    )
                    .map_err(RegistryOperationError::invalid_entitlement)?;
                let response = registry
                    .redeem_credential(
                        &metadata,
                        &access_token,
                        &payload,
                        clock_now,
                        signer,
                        portable_status_registry.as_ref(),
                    )
                    .map_err(RegistryOperationError::bad_request)?;
                registry.prune_dead(clock_now);
                Ok(response)
            })
        })
    })
    .await
}

pub(crate) async fn handle_list_passport_statuses(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(PassportStatusListResponse {
            configured: true,
            count: registry.passports.len(),
            passports: registry.passports.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_get_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&passport_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("passport `{passport_id}` was not found in the lifecycle registry"),
        ),
    }
}

pub(crate) async fn handle_publish_passport_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(mut request): Json<PublishPassportStatusRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    use super::registry_write_lane::{configured_registry_file, run_registry_update};
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let path = match configured_registry_file(
        state.config.passport_statuses_file.as_deref(),
        "--passport-statuses-file",
        "passport lifecycle",
    ) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if request.distribution.resolve_urls.is_empty() {
        request.distribution = default_passport_status_distribution(&state.config);
    }
    let lane = state.operator_registry_write_lane.clone();
    run_registry_update(&lane, move || {
        PassportStatusRegistry::update(&path, |registry| {
            registry.publish(&request.passport, clock_now, request.distribution)
        })
    })
    .await
}

pub(crate) async fn handle_resolve_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut resolution = registry.resolve_at(&passport_id, clock_now);
    resolution.source = Some("registry:trust-control".to_string());
    match resolution.validate() {
        Ok(()) => Json(resolution).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_public_resolve_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut resolution = registry.resolve_at(&passport_id, clock_now);
    resolution.source = Some("registry:trust-control".to_string());
    match resolution.validate() {
        Ok(()) => Json(resolution).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_revoke_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<PassportStatusRevocationRequest>,
) -> Response {
    use super::registry_write_lane::{configured_registry_file, run_registry_update};
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let path = match configured_registry_file(
        state.config.passport_statuses_file.as_deref(),
        "--passport-statuses-file",
        "passport lifecycle",
    ) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let lane = state.operator_registry_write_lane.clone();
    run_registry_update(&lane, move || {
        PassportStatusRegistry::update(&path, |registry| {
            registry.revoke(&passport_id, request.reason.as_deref(), request.revoked_at)
        })
    })
    .await
}

pub(crate) async fn handle_list_verifier_policies(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_verifier_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(VerifierPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_get_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.policies.get(&policy_id) {
        Some(document) => Json(document.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("verifier policy `{policy_id}` was not found"),
        ),
    }
}

pub(crate) async fn handle_upsert_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut document): Json<SignedPassportVerifierPolicy>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    use super::registry_write_lane::{
        configured_registry_file, run_registry_transaction, RegistryOperationError,
    };
    let path = match configured_registry_file(
        state.config.verifier_policies_file.as_deref(),
        "--verifier-policies-file",
        "verifier policy",
    ) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let lane = state.operator_registry_write_lane.clone();
    run_registry_transaction(&lane, move || {
        VerifierPolicyRegistry::update(&path, |registry| {
            document.body.policy_id = policy_id;
            verify_signed_passport_verifier_policy(&document)
                .map_err(RegistryOperationError::bad_request)?;
            registry
                .upsert(document.clone())
                .map_err(RegistryOperationError::bad_request)?;
            Ok(document)
        })
    })
    .await
}

pub(crate) async fn handle_delete_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    use super::registry_write_lane::{
        configured_registry_file, run_registry_transaction, RegistryOperationError,
    };
    let path = match configured_registry_file(
        state.config.verifier_policies_file.as_deref(),
        "--verifier-policies-file",
        "verifier policy",
    ) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let lane = state.operator_registry_write_lane.clone();
    run_registry_transaction(&lane, move || {
        VerifierPolicyRegistry::update(&path, |registry| {
            let deleted = registry.remove(&policy_id);
            Ok::<_, RegistryOperationError>(VerifierPolicyDeleteResponse { policy_id, deleted })
        })
    })
    .await
}

pub(crate) async fn handle_create_passport_challenge(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreatePassportChallengeRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_CHALLENGES_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if payload.policy_id.is_some() && payload.policy.is_some() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "challenge creation accepts either policy_id or policy, not both",
        );
    }
    let now = clock_now;
    let (policy_ref, policy) = if let Some(policy_id) = payload.policy_id.as_deref() {
        let Some(registry) = state.verifier_policy_registry() else {
            return plain_http_error(
                StatusCode::CONFLICT,
                "trust service is missing --verifier-policies-file for policy references",
            );
        };
        let document = match registry.active_policy(policy_id, now) {
            Ok(document) => document,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        if document.body.verifier != payload.verifier {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "stored verifier policy verifier must match the requested challenge verifier",
            );
        }
        (
            Some(PassportVerifierPolicyReference {
                policy_id: document.body.policy_id.clone(),
            }),
            None,
        )
    } else {
        (None, payload.policy.clone())
    };
    let challenge = match create_passport_presentation_challenge_with_reference(
        chio_credentials::PassportPresentationChallengeArgs {
            verifier: payload.verifier,
            challenge_id: Some(Keypair::generate().public_key().to_hex()),
            nonce: Keypair::generate().public_key().to_hex(),
            issued_at: now,
            expires_at: now.saturating_add(payload.ttl_seconds),
            options: chio_credentials::PassportPresentationOptions {
                issuer_allowlist: payload.issuers.into_iter().collect::<BTreeSet<_>>(),
                max_credentials: payload.max_credentials,
            },
            policy_ref,
            policy,
        },
    ) {
        Ok(challenge) => challenge,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = store.register(&challenge) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let transport = match passport_presentation_transport_for_service(&state.config, &challenge) {
        Ok(transport) => transport,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(CreatePassportChallengeResponse {
        challenge,
        transport,
    })
    .into_response()
}

fn verify_passport_challenge_payload(
    state: &TrustServiceState,
    payload: &VerifyPassportChallengeRequest,
    expected_challenge: Option<&PassportPresentationChallenge>,
    consume: bool,
) -> Result<PassportPresentationVerification, Response> {
    let clock_now = unix_timestamp_now()
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()))?;
    if let Err(error) = configured_verifier_challenge_db_path(&state.config) {
        return Err(plain_http_error(StatusCode::CONFLICT, &error.to_string()));
    }
    let now = clock_now;
    let challenge = expected_challenge.unwrap_or(&payload.presentation.challenge);
    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => {
            return Err(plain_http_error(
                StatusCode::BAD_REQUEST,
                &error.to_string(),
            ));
        }
    };
    if resolved_policy
        .as_ref()
        .is_some_and(|policy| policy.require_active_lifecycle)
        && state.config.passport_statuses_file.is_none()
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "passport verifier policy requires active lifecycle enforcement, but the trust-control service is missing --passport-statuses-file",
        ));
    }
    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        expected_challenge,
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
    };
    match resolve_passport_lifecycle_for_service(&state.config, &payload.presentation.passport, now)
    {
        Ok(lifecycle) => {
            verification.passport_lifecycle = lifecycle.clone();
            if let Some(policy_evaluation) = verification.policy_evaluation.as_mut() {
                if policy_evaluation.policy.require_active_lifecycle {
                    if let Some(lifecycle) = lifecycle {
                        if lifecycle.state != PassportLifecycleState::Active {
                            let reason = passport_lifecycle_reason(&lifecycle);
                            policy_evaluation.accepted = false;
                            policy_evaluation.matched_credential_indexes.clear();
                            policy_evaluation.matched_issuers.clear();
                            if !policy_evaluation
                                .passport_reasons
                                .iter()
                                .any(|existing| existing == &reason)
                            {
                                policy_evaluation.passport_reasons.push(reason);
                            }
                            verification.accepted = false;
                        }
                    }
                }
            }
        }
        Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
    }
    if consume {
        match consume_challenge_if_configured(&state.config, challenge, now) {
            Ok(replay_state) => verification.replay_state = replay_state,
            Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
        }
    }
    Ok(verification)
}

pub(crate) async fn handle_verify_passport_challenge(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyPassportChallengeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_CHALLENGE_VERIFY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    match verify_passport_challenge_payload(
        &state,
        &payload,
        payload.expected_challenge.as_ref(),
        true,
    ) {
        Ok(verification) => Json(verification).into_response(),
        Err(response) => response,
    }
}

pub(crate) async fn handle_public_get_passport_challenge(
    State(state): State<TrustServiceState>,
    AxumPath(challenge_id): AxumPath<String>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match store.fetch_active(&challenge_id, clock_now) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(error) if error.to_string().contains("not registered") => {
            plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_public_verify_passport_challenge(
    State(state): State<TrustServiceState>,
    Json(payload): Json<VerifyPassportChallengeRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    match forward_public_passport_challenge_to_leader(&state, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let lane = Arc::clone(&state.public_passport_challenge_lane);
    verify_public_passport_challenge_in_lane(&lane, state, payload, clock_now).await
}

/// Verifies one public holder submission on the blocking pool under a permit
/// from `lane`.
///
/// Admission never waits: without a free permit the submission is refused at
/// once with 503. The permit moves into the blocking closure and is released
/// only after the response is built, so a submission dropped mid-verification
/// keeps its permit until that work has ended.
pub(super) async fn verify_public_passport_challenge_in_lane(
    lane: &Arc<tokio::sync::Semaphore>,
    state: TrustServiceState,
    payload: VerifyPassportChallengeRequest,
    clock_now: u64,
) -> Response {
    let Ok(permit) = Arc::clone(lane).try_acquire_owned() else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "public passport challenge verification is at capacity",
        );
    };
    tokio::task::spawn_blocking(move || {
        let response = verify_public_passport_challenge(&state, &payload, clock_now);
        drop(permit);
        response
    })
    .await
    .unwrap_or_else(|_| {
        plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "public passport challenge verification did not complete",
        )
    })
}

/// Checks one public holder submission against its stored challenge and
/// builds the response.
fn verify_public_passport_challenge(
    state: &TrustServiceState,
    payload: &VerifyPassportChallengeRequest,
    clock_now: u64,
) -> Response {
    let challenge_id = match payload
        .presentation
        .challenge
        .challenge_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(challenge_id) => challenge_id.to_string(),
        None => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "public holder submission requires a non-empty challenge_id",
            );
        }
    };
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let stored_challenge = match store.fetch_active(&challenge_id, clock_now) {
        Ok(challenge) => challenge,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(expected_challenge) = payload.expected_challenge.as_ref() {
        if canonical_json_bytes(expected_challenge).ok()
            != canonical_json_bytes(&stored_challenge).ok()
        {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "provided expected challenge does not match the stored verifier challenge",
            );
        }
    }
    match verify_passport_challenge_payload(state, payload, Some(&stored_challenge), true) {
        Ok(verification) => Json(verification).into_response(),
        Err(response) => response,
    }
}

pub(crate) async fn handle_create_oid4vp_request(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOid4vpRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_OID4VP_REQUESTS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = clock_now;
    let request = match build_oid4vp_request_for_service(&state.config, &payload, now) {
        Ok(request) => request,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let signing_key = match resolve_oid4vp_verifier_signing_key(&state.config) {
        Ok(keypair) => keypair,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut transport = match build_oid4vp_request_transport(&request, &signing_key) {
        Ok(transport) => transport,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    transport.same_device_url = oid4vp_same_device_url(&request.request_uri);
    transport.cross_device_url =
        match oid4vp_cross_device_url(&state.config, &request.jti, &request.request_uri) {
            Ok(url) => url,
            Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = store.register(&request, &transport.request_jwt) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let wallet_exchange = match build_oid4vp_wallet_exchange_response(
        &state.config,
        &request,
        &transport.request_jwt,
        WalletExchangeTransactionState::issued(
            &request.jti,
            &request.jti,
            request.iat,
            request.exp,
        ),
        &transport.same_device_url,
        &transport.cross_device_url,
    ) {
        Ok(wallet_exchange) => wallet_exchange,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(CreateOid4vpRequestResponse {
        request,
        transport,
        wallet_exchange,
    })
    .into_response()
}

pub(crate) async fn handle_public_get_wallet_exchange(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let snapshot = match store.snapshot(&request_id, clock_now) {
        Ok(snapshot) => snapshot,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let same_device_url = oid4vp_same_device_url(&snapshot.request.request_uri);
    let cross_device_url = match oid4vp_cross_device_url(
        &state.config,
        &snapshot.request.jti,
        &snapshot.request.request_uri,
    ) {
        Ok(url) => url,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match build_oid4vp_wallet_exchange_response(
        &state.config,
        &snapshot.request,
        &snapshot.request_jwt,
        snapshot.transaction,
        &same_device_url,
        &cross_device_url,
    ) {
        Ok(response) => Json::<WalletExchangeStatusResponse>(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_public_get_oid4vp_request(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    run_public_authority_trust_read(&state, move |state, status| {
        get_public_oid4vp_request(state, request_id, status)
    })
    .await
}

fn get_public_oid4vp_request(
    state: &TrustServiceState,
    request_id: String,
    admitted_status: Option<&TrustAuthorityStatus>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let (request, request_jwt) = match store.fetch_active(&request_id, clock_now) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let keys = match admitted_status {
        Some(status) => trusted_public_keys_from_status(status),
        None => resolve_public_oid4vp_verifier_trusted_public_keys(
            &state.config,
            &state.finding_challenge_clock,
        ),
    };
    let trusted_public_keys = match keys {
        Ok(keys) => keys,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = verify_signed_oid4vp_request_object_with_any_key(
        &request_jwt,
        &trusted_public_keys,
        clock_now,
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    if request.jti != request_id {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored OID4VP request payload did not match its request_id",
        );
    }
    let mut response = request_jwt.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/oauth-authz-req+jwt"),
    );
    response
}

pub(crate) async fn handle_public_launch_oid4vp_request(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let (request, _) = match store.fetch_active(&request_id, clock_now) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    Redirect::temporary(&oid4vp_same_device_url(&request.request_uri)).into_response()
}

pub(crate) async fn handle_public_submit_oid4vp_response(
    State(state): State<TrustServiceState>,
    Form(payload): Form<Oid4vpDirectPostForm>,
) -> Response {
    // Acceptance time comes from the request-handling state clock, sampled both
    // before and after the untrusted remote waits. A slow issuer or lifecycle
    // response therefore cannot carry acceptance past the request's expiry under
    // a stale timestamp. A clock failure fails closed.
    let clock = state.finding_challenge_clock.as_ref();
    let clock_now = match clock_unix_secs(clock) {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let unverified_response = match inspect_oid4vp_direct_post_response(&payload.response) {
        Ok(response) => response,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let request_id = unverified_response.presentation_submission.id.clone();
    if request_id.trim().is_empty() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "OID4VP direct-post response requires a non-empty presentation_submission.id",
        );
    }
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = clock_now;
    let (request, request_jwt) = match store.fetch_active(&request_id, now) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let credential = match inspect_chio_passport_sd_jwt_vc_unverified(&unverified_response.vp_token)
    {
        Ok(credential) => credential,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let requested_issuer_allowlist = request
        .dcql_query
        .credentials
        .first()
        .map(|credential| credential.issuer_allowlist.iter().cloned().collect())
        .unwrap_or_default();
    // Trust is decided before any network I/O: our own advertised issuer uses
    // local keys, every other issuer must be in the verifier request's signed
    // issuer allowlist, and an empty allowlist trusts only the local issuer.
    let issuer_public_keys =
        if state.config.advertise_url.as_deref() == Some(credential.issuer.as_str()) {
            match public_oid4vp_trusted_keys(&state).await {
                Ok(keys) => keys,
                Err(response) => return response,
            }
        } else {
            match plan_portable_issuer_keys(
                &state.config,
                &credential.issuer,
                &requested_issuer_allowlist,
                &state.finding_challenge_clock,
            ) {
                Ok(PortableIssuerResolution::Local(keys)) => keys,
                Ok(PortableIssuerResolution::Untrusted) => {
                    return plain_http_error(
                        StatusCode::FORBIDDEN,
                        "portable credential issuer is not trusted by the verifier request",
                    );
                }
                Ok(PortableIssuerResolution::Remote(fetch)) => {
                    match run_portable_issuer_fetch(move || fetch.resolve()).await {
                        Ok(Ok(keys)) => keys,
                        Ok(Err(error)) => {
                            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
                        }
                        Err(refusal) => return refusal.into_response(plain_http_error),
                    }
                }
                Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
            }
        };
    // Refresh trusted time after the issuer-key wait and verify the signed
    // response against it. This yields the passport identity used to plan the
    // lifecycle resolution; it runs before the signed lifecycle URL is fetched.
    let verify_now = match clock_unix_secs(clock) {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let verified = match verify_oid4vp_direct_post_response_with_any_issuer_key(
        &payload.response,
        &request,
        &issuer_public_keys,
        verify_now,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    let lifecycle = match plan_oid4vp_passport_lifecycle(
        &state.config,
        &verified.passport_id,
        verified.passport_status.as_ref(),
        verify_now,
    ) {
        Ok(PassportLifecyclePlan::Resolved(lifecycle)) => lifecycle,
        Ok(PassportLifecyclePlan::Remote(fetch)) => {
            match run_portable_issuer_fetch(move || fetch.resolve()).await {
                Ok(Ok(lifecycle)) => Some(lifecycle),
                Ok(Err(error)) => {
                    return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
                }
                Err(refusal) => return refusal.into_response(plain_http_error),
            }
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(lifecycle) = lifecycle.as_ref() {
        if lifecycle.state != PassportLifecycleState::Active {
            return plain_http_error(StatusCode::FORBIDDEN, &passport_lifecycle_reason(lifecycle));
        }
    }
    // Refresh trusted time after the lifecycle wait and revalidate the signed
    // response at that final acceptance time, so a credential or holder proof
    // that expired during either remote wait is refused even while the verifier
    // request is still live. The atomic consume then enforces request expiry
    // against the same time and records it as the consumption instant.
    let accept_now = match clock_unix_secs(clock) {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let mut verification = match verify_oid4vp_direct_post_response_with_any_issuer_key(
        &payload.response,
        &request,
        &issuer_public_keys,
        accept_now,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    if let Err(error) = store.consume(&request, &request_jwt, accept_now) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    verification.exchange_transaction = Some(WalletExchangeTransactionState::consumed(
        &request.jti,
        &request.jti,
        request.iat,
        request.exp,
        accept_now,
    ));
    verification.identity_assertion = request.identity_assertion.clone();
    Json(verification).into_response()
}

pub(crate) async fn handle_federated_issue(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<FederatedIssueRequest>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FEDERATED_ISSUE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Some(advertise_url) = state.config.advertise_url.as_deref() {
        if payload.expected_challenge.verifier != advertise_url {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "expected challenge verifier must match the trust-control service advertise URL",
            );
        }
    }
    let now = clock_now;
    if let Some(policy) = payload.delegation_policy.as_ref() {
        if let Err(error) = verify_federated_delegation_policy(policy)
            .and_then(|_| ensure_federated_delegation_policy_active(policy, now))
        {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
        if policy.body.verifier != payload.expected_challenge.verifier {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "federated delegation policy verifier must match the expected passport challenge verifier",
            );
        }
        if let Some(advertise_url) = state.config.advertise_url.as_deref() {
            if policy.body.verifier != advertise_url {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "federated delegation policy verifier must match the trust-control service advertise URL",
                );
            }
        }
        if let Err(error) =
            ensure_requested_capability_within_delegation_policy(&payload.capability, policy, now)
        {
            return plain_http_error(StatusCode::FORBIDDEN, &error.to_string());
        }
    }
    if let Some(upstream_capability_id) = payload.upstream_capability_id.as_deref() {
        match payload
            .delegation_policy
            .as_ref()
            .and_then(|policy| policy.body.parent_capability_id.as_deref())
        {
            Some(parent_capability_id) if parent_capability_id == upstream_capability_id => {}
            _ => {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "multi-hop federated issuance requires a delegation policy bound to the exact upstream capability id",
                );
            }
        }
    } else if payload
        .delegation_policy
        .as_ref()
        .and_then(|policy| policy.body.parent_capability_id.as_deref())
        .is_some()
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "delegation policy parent_capability_id requires --upstream-capability-id on the issuance request",
        );
    }

    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        &payload.expected_challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if resolved_policy.is_none() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "federated issuance requires an embedded or stored verifier policy",
        );
    }
    if resolved_policy
        .as_ref()
        .is_some_and(|policy| policy.require_active_lifecycle)
        && state.config.passport_statuses_file.is_none()
    {
        return plain_http_error(
            StatusCode::CONFLICT,
            "passport verifier policy requires active lifecycle enforcement, but the trust-control service is missing --passport-statuses-file",
        );
    }

    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        Some(&payload.expected_challenge),
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    match resolve_passport_lifecycle_for_service(&state.config, &payload.presentation.passport, now)
    {
        Ok(lifecycle) => {
            verification.passport_lifecycle = lifecycle.clone();
            if let Some(policy_evaluation) = verification.policy_evaluation.as_mut() {
                if policy_evaluation.policy.require_active_lifecycle {
                    if let Some(lifecycle) = lifecycle {
                        if lifecycle.state != PassportLifecycleState::Active {
                            let reason = passport_lifecycle_reason(&lifecycle);
                            policy_evaluation.accepted = false;
                            policy_evaluation.matched_credential_indexes.clear();
                            policy_evaluation.matched_issuers.clear();
                            if !policy_evaluation
                                .passport_reasons
                                .iter()
                                .any(|existing| existing == &reason)
                            {
                                policy_evaluation.passport_reasons.push(reason);
                            }
                            verification.accepted = false;
                        }
                    }
                }
            }
        }
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
    match consume_challenge_if_configured(&state.config, &payload.expected_challenge, now) {
        Ok(replay_state) => verification.replay_state = replay_state,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
    if !verification.accepted {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "passport presentation did not satisfy the verifier policy",
        );
    }
    let subject_did = match DidChio::from_str(&verification.subject) {
        Ok(subject_did) => subject_did,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let subject_public_key = subject_did.public_key();
    let subject_public_key_hex = subject_public_key.to_hex();
    let mut enterprise_audit = None;
    let mut scim_lifecycle_record = None;
    if let Some(identity) = payload.enterprise_identity.as_ref() {
        let validated_provider = identity
            .provider_record_id
            .as_deref()
            .and_then(|provider_id| state.validated_enterprise_provider(provider_id));
        let lane_active = identity.provider_record_id.is_some();
        let mut audit =
            build_enterprise_admission_audit(identity, &subject_public_key_hex, validated_provider);
        if identity.provider_id.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing provider_id".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires provider_id",
                &audit,
            );
        }
        if identity.principal.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing principal".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires principal",
                &audit,
            );
        }
        if identity.subject_key.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing subject_key".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires subject_key",
                &audit,
            );
        }
        if lane_active {
            let Some(provider) = validated_provider else {
                audit.decision_reason = Some(
                    "enterprise-provider lane is active but provider_record_id is not validated"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise-provider lane requires a validated provider record",
                    &audit,
                );
            };
            let Some(policy) = payload.admission_policy.as_ref() else {
                audit.decision_reason = Some(
                    "enterprise-provider lane is active but no admission policy was provided"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise-provider lane requires an admission policy with enterprise origin rules",
                    &audit,
                );
            };
            let Some(profile_id) = chio_policy::selected_origin_profile_id(
                policy,
                &enterprise_origin_context(identity),
            ) else {
                audit.decision_reason = Some(
                    "enterprise identity did not match any configured enterprise origin profile"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise identity did not satisfy any configured origin profile",
                    &audit,
                );
            };
            audit.matched_origin_profile = Some(profile_id);
            if matches!(provider.kind, EnterpriseProviderKind::Scim) {
                match resolve_scim_lifecycle_record_for_federated_issue(
                    &state.config,
                    provider,
                    identity,
                ) {
                    Ok(Some(record)) => {
                        scim_lifecycle_record = Some(record);
                        audit.decision_reason = Some(
                            "enterprise-provider lane matched the configured enterprise origin profile and active scim lifecycle identity"
                                .to_string(),
                        );
                    }
                    Ok(None) => {
                        audit.decision_reason = Some(
                            "enterprise-provider lane matched the configured enterprise origin profile"
                                .to_string(),
                        );
                    }
                    Err(error) => {
                        audit.decision_reason = Some(error.to_string());
                        return enterprise_admission_response(
                            StatusCode::FORBIDDEN,
                            &error.to_string(),
                            &audit,
                        );
                    }
                }
            } else {
                audit.decision_reason = Some(
                    "enterprise-provider lane matched the configured enterprise origin profile"
                        .to_string(),
                );
            }
        } else {
            audit.decision_reason = Some(
                "enterprise observability is present but no validated provider-admin record activated the enterprise-provider lane"
                    .to_string(),
            );
        }
        enterprise_audit = Some(audit);
    }
    let mut store =
        if payload.delegation_policy.is_some() || payload.upstream_capability_id.is_some() {
            match state.receipt_store() {
                Ok(store) => Some(store),
                Err(response) => return response,
            }
        } else {
            None
        };
    let upstream_parent = if let Some(upstream_capability_id) =
        payload.upstream_capability_id.as_deref()
    {
        let Some(store) = store.as_ref() else {
            return plain_http_error(
                StatusCode::CONFLICT,
                "multi-hop federated issuance requires --receipt-db so imported upstream evidence can be resolved",
            );
        };
        match store.get_federated_share_for_capability(upstream_capability_id) {
            Ok(Some((share, snapshot))) => {
                if let Some(policy) = payload.delegation_policy.as_ref() {
                    if share.signer_public_key != policy.body.signer_public_key.to_hex() {
                        return plain_http_error(
                            StatusCode::FORBIDDEN,
                            "delegation policy signer must match the signer that shared the imported upstream evidence package",
                        );
                    }
                }
                if let Err(error) = ensure_requested_capability_within_parent_snapshot(
                    &payload.capability,
                    &snapshot,
                    now,
                ) {
                    return plain_http_error(StatusCode::FORBIDDEN, &error.to_string());
                }
                Some((share.share_id, snapshot))
            }
            Ok(None) => {
                return plain_http_error(
                    StatusCode::NOT_FOUND,
                    "imported upstream capability was not found in the local federated evidence-share index",
                );
            }
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    } else {
        None
    };
    let authority = if payload.delegation_policy.is_some() {
        load_capability_authority_with_deferred_lineage(&state)
    } else {
        load_capability_authority(&state)
    };
    match authority {
        Ok(authority) => {
            if let Some(policy) = payload.delegation_policy.as_ref() {
                if !authority
                    .trusted_public_keys()
                    .iter()
                    .any(|key| key == &policy.body.signer_public_key)
                {
                    return plain_http_error(
                        StatusCode::FORBIDDEN,
                        "federated delegation policy signer is not trusted by the local capability authority",
                    );
                }
            }
            match authority.issue_capability(
                subject_public_key,
                payload.capability.scope.clone(),
                payload.capability.ttl,
            ) {
                Ok(capability) => {
                    if let Some(record) = scim_lifecycle_record.as_ref() {
                        if let Err(error) = bind_scim_capability_to_identity(
                            &state.config,
                            &record.provider_id,
                            &record.enterprise_identity.subject_key,
                            &capability.id,
                            now,
                        ) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                    }
                    let mut delegation_anchor_capability_id = None;
                    if let Some(policy) = payload.delegation_policy.as_ref() {
                        let Some(store) = store.as_mut() else {
                            return plain_http_error(
                                StatusCode::CONFLICT,
                                "federated delegation issuance requires --receipt-db so the lineage anchor can be persisted",
                            );
                        };
                        let anchor_snapshot = match build_federated_delegation_anchor_snapshot(
                            policy,
                            &subject_public_key_hex,
                            &payload.expected_challenge,
                            now,
                            upstream_parent.as_ref().map(|(_, snapshot)| snapshot),
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                );
                            }
                        };
                        let signed_parent_capability_id = capability
                            .delegation_chain
                            .last()
                            .map(|link| link.capability_id.clone());
                        let mut child_snapshot = match build_capability_snapshot(
                            &capability,
                            crate::integer::count(capability.delegation_chain.len()),
                            signed_parent_capability_id,
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                );
                            }
                        };
                        child_snapshot.federated_parent_capability_id =
                            Some(anchor_snapshot.capability_id.clone());
                        let upstream_bridge =
                            upstream_parent.as_ref().map(|(share_id, parent_snapshot)| {
                                (parent_snapshot.capability_id.as_str(), share_id.as_str())
                            });
                        if let Err(error) = store.persist_federated_delegation_lineage(
                            &anchor_snapshot,
                            upstream_bridge,
                            &child_snapshot,
                        ) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                        delegation_anchor_capability_id = Some(anchor_snapshot.capability_id);
                    }
                    Json(FederatedIssueResponse {
                        subject: verification.subject.clone(),
                        subject_public_key: subject_public_key_hex,
                        verification,
                        capability,
                        enterprise_identity_provenance: payload
                            .enterprise_identity
                            .as_ref()
                            .map(EnterpriseIdentityProvenance::from),
                        enterprise_audit,
                        delegation_anchor_capability_id,
                    })
                    .into_response()
                }
                Err(chio_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
                    if let Some(audit) = enterprise_audit.as_ref() {
                        enterprise_admission_response(StatusCode::FORBIDDEN, &error, audit)
                    } else {
                        plain_http_error(StatusCode::FORBIDDEN, &error)
                    }
                }
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
        Err(response) => response,
    }
}

#[cfg(test)]
#[path = "passport_handlers/oid4vp_issuer_fetch_tests.rs"]
mod oid4vp_issuer_fetch_tests;

#[path = "passport_handlers/issuer_authority.rs"]
mod issuer_authority;

#[cfg(test)]
pub(crate) use issuer_authority::provisional_test_observer::observe_provisional_issuer_once;
