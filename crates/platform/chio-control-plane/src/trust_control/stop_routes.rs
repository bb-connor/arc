//! Operator stop routes over the kernel scope of this node's admission authority.
//!
//! The routes require a credential with deployment tenant authority holding
//! `admin:emergency`. With a joint admission authority the stop is durable on
//! its store, and the admission authority RPC refuses to begin admissions
//! while it holds, so remote edges observe it.
use chio_kernel::stop::{
    ResumeCommand, ResumeRequestBody, StopAuthorizer, StopCommand, StopControl, StopControlError,
    StopRequestBody, StopRequestPath,
};
use chio_store_sqlite::SqliteAdmissionOperationStore;

use super::report_validation::validate_caller;
use super::*;

pub(crate) const EMERGENCY_STOP_PATH: &str = "/v1/admin/emergency-stop";
pub(crate) const EMERGENCY_RESUME_PATH: &str = "/v1/admin/emergency-resume";
pub(crate) const EMERGENCY_STATUS_PATH: &str = "/v1/admin/emergency-status";

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

    /// The stop of a node serving purchases is the purchase executor's, so the
    /// routes drive the same control every purchase kernel holds.
    pub(crate) fn for_serving(
        authority: Option<&Arc<SqliteAuthorityStore>>,
        purchase_executor: Option<&super::finding_purchase_routes::SharedFindingPurchaseExecutor>,
    ) -> Result<Self, CliError> {
        let Some(executor) = purchase_executor else {
            return Ok(Self::for_authority(authority));
        };
        let control = executor.stop_control();
        if !control.is_durable() {
            return Err(CliError::cli_other_error(
                "finding purchase executor stop control is not durable".to_string(),
            ));
        }
        Ok(Self {
            control,
            _store: None,
        })
    }

    pub(crate) fn control(&self) -> &StopControl {
        &self.control
    }
}

/// The stop record names the trust-control credential that authorized it.
fn authorizer(caller: &super::caller_credentials::AuthenticatedCaller) -> StopAuthorizer {
    StopAuthorizer::shared_credential(&format!("trust-control:{}", caller.credential_id))
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
    let caller = match validate_caller(&headers, &state.config, Scope::AdminEmergency) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let command = StopCommand {
        reason: body.reason,
        authorizer: authorizer(&caller),
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
    let caller = match validate_caller(&headers, &state.config, Scope::AdminEmergency) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let command = ResumeCommand {
        expected_epoch: Some(body.expected_epoch),
        authorizer: authorizer(&caller),
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
    if let Err(response) = validate_caller(&headers, &state.config, Scope::AdminEmergency) {
        return response;
    }
    Json(state.stop.control().status()).into_response()
}
