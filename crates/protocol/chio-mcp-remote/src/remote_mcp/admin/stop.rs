//! Operator stop routes over the hosted edge's shared stop control.
use chio_kernel::stop::{
    ResumeCommand, ResumeRequestBody, StopAuthorizer, StopCommand, StopControlError,
    StopRequestBody, StopRequestPath,
};

use super::*;

const ADMIN_CREDENTIAL_ID: &str = "hosted-mcp:admin-token";

fn authorizer() -> StopAuthorizer {
    StopAuthorizer::shared_credential(ADMIN_CREDENTIAL_ID)
}

fn requested_via(state: &RemoteAppState) -> StopRequestPath {
    StopRequestPath::Route {
        host_id: state.factory.config.server_id.clone(),
    }
}

fn refusal(error: &StopControlError) -> Response {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    (status, Json(error.body())).into_response()
}

pub(super) async fn handle_stop(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    BoundedJson(body): BoundedJson<StopRequestBody>,
) -> Response {
    if let Err(response) = validate_admin_request(&headers, state.admin_token.as_deref()) {
        return response;
    }
    let command = StopCommand {
        reason: body.reason,
        authorizer: authorizer(),
        requested_via: requested_via(&state),
        allow_containment: body.allow_containment,
    };
    match state.factory.stop.stop(command) {
        Ok(status) => Json(status).into_response(),
        Err(error) => refusal(&error),
    }
}

pub(super) async fn handle_resume(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    BoundedJson(body): BoundedJson<ResumeRequestBody>,
) -> Response {
    if let Err(response) = validate_admin_request(&headers, state.admin_token.as_deref()) {
        return response;
    }
    let command = ResumeCommand {
        expected_epoch: Some(body.expected_epoch),
        authorizer: authorizer(),
        requested_via: requested_via(&state),
    };
    match state.factory.stop.resume(command) {
        Ok(status) => Json(status).into_response(),
        Err(error) => refusal(&error),
    }
}

pub(super) async fn handle_status(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_admin_request(request.headers(), state.admin_token.as_deref()) {
        return response;
    }
    Json(state.factory.stop.status()).into_response()
}
