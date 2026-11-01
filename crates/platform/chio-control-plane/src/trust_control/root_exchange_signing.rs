//! `POST /v1/root-exchange/sign`: sign what an edge built, after checking it
//! against the provider registry. It has no message or byte path to the key.

use chio_core_types::root_authority::{
    check_snapshot_sign, RootExchangeSignRefusal, RootExchangeSignRequest, RootExchangeSignResponse,
};

use super::caller_credentials::Scope;
use super::report_rendering::forward_authority_post_to_leader;
use super::report_validation::{
    enforce_authority_mutation_fence, inspect_authority_state, open_authority_for_state,
    validate_authority_mutation_term, validate_authority_scope_auth,
};
use super::*;
use crate::enterprise_federation::{EnterpriseProviderRegistry, ProviderIdentityError};

#[derive(Debug, thiserror::Error)]
enum SignRouteError {
    #[error("root exchange signing is not configured")]
    NotConfigured,
    #[error("trust-control exchange signer requires lifecycle state")]
    NoLifecycleState,
    #[error(transparent)]
    Refused(#[from] RootExchangeSignRefusal),
    #[error(transparent)]
    ProviderIdentity(#[from] ProviderIdentityError),
    #[error("provider registry is unavailable: {0}")]
    Registry(CliError),
    #[error("exchange authority is unavailable: {0}")]
    Authority(String),
}

impl IntoResponse for SignRouteError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::NotConfigured | Self::NoLifecycleState => StatusCode::CONFLICT,
            Self::Refused(RootExchangeSignRefusal::Canonicalization(_)) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Refused(_) | Self::ProviderIdentity(_) => StatusCode::FORBIDDEN,
            Self::Registry(_) | Self::Authority(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        plain_http_error(status, &self.to_string())
    }
}

fn sign(
    state: &TrustServiceState,
    request: &RootExchangeSignRequest,
) -> Result<RootExchangeSignResponse, SignRouteError> {
    let RootExchangeSignRequest::IdpKeySnapshot {
        provider_record_id,
        provider_identity_digest,
        body,
    } = request;
    let registry_path = state
        .config
        .enterprise_providers_file
        .as_deref()
        .ok_or(SignRouteError::NotConfigured)?;
    let authority_path = match (
        state.authority_keyring.as_ref(),
        state.config.authority_db_path.as_deref(),
    ) {
        (None, Some(path)) => path,
        _ => return Err(SignRouteError::NoLifecycleState),
    };
    let registry =
        EnterpriseProviderRegistry::load(registry_path).map_err(SignRouteError::Registry)?;
    let record = registry
        .providers
        .get(provider_record_id.as_str())
        .ok_or(RootExchangeSignRefusal::ProviderRecordUnknown)?;
    if !record.is_validated_enabled() {
        return Err(RootExchangeSignRefusal::ProviderRecordDisabled.into());
    }
    let identity = record.identity()?;
    let unavailable = |error: &dyn std::fmt::Display| SignRouteError::Authority(error.to_string());
    let authority =
        open_authority_for_state(state, authority_path).map_err(|error| unavailable(&error))?;
    let exchange_key = authority
        .status()
        .map_err(|error| unavailable(&error))?
        .public_key;
    let now = state
        .finding_challenge_clock
        .unix_millis()
        .map_err(|error| unavailable(&error))?
        .as_secs();
    check_snapshot_sign(
        body,
        &identity,
        provider_identity_digest,
        &exchange_key,
        now,
    )?;
    authority
        .sign_idp_key_snapshot(body)
        .map(RootExchangeSignResponse::idp_key_snapshot)
        .map_err(|error| unavailable(&error))
}

pub(crate) async fn handle_root_exchange_sign(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RootExchangeSignRequest>,
) -> Response {
    let forwarded = match validate_authority_scope_auth(&headers, &state, Scope::RootExchangeSign) {
        Ok(forwarded) => forwarded,
        Err(response) => return response,
    };
    match forward_authority_post_to_leader(&state, &headers, ROOT_EXCHANGE_SIGN_PATH, &payload)
        .await
    {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    inspect_authority_state(&state, move |state| {
        validate_authority_mutation_term(state, forwarded)?;
        enforce_authority_mutation_fence(state)?;
        Ok(match sign(state, &payload) {
            Ok(signed) => Json(signed).into_response(),
            Err(error) => error.into_response(),
        })
    })
    .await
    .unwrap_or_else(std::convert::identity)
}
