//! Operator stop routes over the kernel scope of this node's admission authority.
//!
//! The routes authenticate with the service token. With a joint admission
//! authority the stop is durable on its store, and the admission authority RPC
//! refuses to begin admissions while it holds, so remote edges observe it.
use chio_kernel::stop::{
    ResumeCommand, ResumeRequestBody, StopAuthorizer, StopCommand, StopControl, StopControlError,
    StopRequestBody, StopRequestPath,
};
use chio_store_sqlite::SqliteAdmissionOperationStore;

use super::report_validation::validate_service_auth;
use super::*;

pub(crate) const EMERGENCY_STOP_PATH: &str = "/v1/admin/emergency-stop";
pub(crate) const EMERGENCY_RESUME_PATH: &str = "/v1/admin/emergency-resume";
pub(crate) const EMERGENCY_STATUS_PATH: &str = "/v1/admin/emergency-status";

const SERVICE_CREDENTIAL_ID: &str = "trust-control:service-token";

/// The kernel-scope stop of one trust-control node.
#[derive(Clone)]
pub(crate) struct TrustStop {
    control: StopControl,
    _store: Option<Arc<SqliteAdmissionOperationStore>>,
}

impl TrustStop {
    pub(crate) fn process_local() -> Self {
        Self {
            control: StopControl::process_local(),
            _store: None,
        }
    }

    /// Durable on the joint admission authority when one is configured.
    pub(crate) fn for_authority(authority: Option<&Arc<SqliteAuthorityStore>>) -> Self {
        let Some(authority) = authority else {
            return Self::process_local();
        };
        let store = Arc::new(authority.admission_operation_store());
        Self {
            control: StopControl::durable(&store, authority.mutation_fence()),
            _store: Some(store),
        }
    }

    pub(crate) fn control(&self) -> &StopControl {
        &self.control
    }
}

fn authorizer() -> StopAuthorizer {
    StopAuthorizer::shared_credential(SERVICE_CREDENTIAL_ID)
}

fn requested_via(state: &TrustServiceState) -> StopRequestPath {
    StopRequestPath::Route {
        host_id: state
            .config
            .advertise_url
            .clone()
            .unwrap_or_else(|| state.config.listen.to_string()),
    }
}

fn refusal(error: &StopControlError) -> Response {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    (status, Json(error.body())).into_response()
}

pub(crate) async fn handle_emergency_stop(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(body): Json<StopRequestBody>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let command = StopCommand {
        reason: body.reason,
        authorizer: authorizer(),
        requested_via: requested_via(&state),
        allow_containment: body.allow_containment,
    };
    match state.stop.control().stop(command) {
        Ok(status) => Json(status).into_response(),
        Err(error) => refusal(&error),
    }
}

pub(crate) async fn handle_emergency_resume(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(body): Json<ResumeRequestBody>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let command = ResumeCommand {
        expected_epoch: Some(body.expected_epoch),
        authorizer: authorizer(),
        requested_via: requested_via(&state),
    };
    match state.stop.control().resume(command) {
        Ok(status) => Json(status).into_response(),
        Err(error) => refusal(&error),
    }
}

pub(crate) async fn handle_emergency_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    Json(state.stop.control().status()).into_response()
}
