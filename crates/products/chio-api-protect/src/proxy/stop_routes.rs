//! Operator stop routes over the sidecar's shared stop control.
use chio_kernel::stop::{
    ResumeCommand, ResumeRequestBody, StopAuthorizer, StopCommand, StopControlError,
    StopRequestBody, StopRequestPath,
};
use serde::de::DeserializeOwned;

use super::*;

const CONTROL_CREDENTIAL_ID: &str = "api-protect:sidecar-control-token";
const MAX_STOP_BODY_BYTES: usize = 16 * 1024;

fn authorizer() -> StopAuthorizer {
    StopAuthorizer::shared_credential(CONTROL_CREDENTIAL_ID)
}

fn requested_via(state: &ProxyState) -> StopRequestPath {
    StopRequestPath::Route {
        host_id: state.signer_keypair.public_key().to_hex(),
    }
}

fn refusal(error: &StopControlError) -> Response {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    (status, Json(error.body())).into_response()
}

async fn decode_body<T: DeserializeOwned>(request: Request<Body>) -> Result<T, Response> {
    let bytes = axum::body::to_bytes(request.into_body(), MAX_STOP_BODY_BYTES)
        .await
        .map_err(|_| sidecar_bad_request("failed to read stop request body").into_response())?;
    input::decode(&bytes, MAX_STOP_BODY_BYTES).map_err(input::rejected)
}

/// The refusal a sidecar issuance route returns while a stop holds.
pub(crate) fn stopped_refusal() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "kernel_stopped",
            "message": chio_kernel::EMERGENCY_STOP_DENY_REASON,
        })),
    )
        .into_response()
}

pub(crate) async fn stop_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let body: StopRequestBody = match decode_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let command = StopCommand {
        reason: body.reason,
        authorizer: authorizer(),
        requested_via: requested_via(&state),
        allow_containment: body.allow_containment,
    };
    match state.stop.stop(command) {
        Ok(status) => Json(status).into_response(),
        Err(error) => refusal(&error),
    }
}

pub(crate) async fn resume_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let body: ResumeRequestBody = match decode_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let command = ResumeCommand {
        expected_epoch: Some(body.expected_epoch),
        authorizer: authorizer(),
        requested_via: requested_via(&state),
    };
    match state.stop.resume(command) {
        Ok(status) => Json(status).into_response(),
        Err(error) => refusal(&error),
    }
}

pub(crate) async fn status_handler(State(state): State<Arc<ProxyState>>) -> Response {
    Json(state.stop.status()).into_response()
}
