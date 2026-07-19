use super::*;

use crate::fiscal_state_recovery::FiscalStartupRecoveryAction;
use crate::trust_control::report_validation::validate_service_auth;

pub(crate) async fn handle_fiscal_runtime_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "trust control service has no fiscal runtime configured",
        );
    };
    match runtime.reconcile() {
        Ok(startup) => Json(json!({
            "schema": "chio.fiscal.runtime-status.v1",
            "recoveryAction": recovery_action_name(startup.recovery_action),
            "checkpoint": startup.checkpoint.signed(),
            "readiness": startup.readiness.signed(),
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    }
}

const fn recovery_action_name(action: FiscalStartupRecoveryAction) -> &'static str {
    match action {
        FiscalStartupRecoveryAction::Ready => "ready",
        FiscalStartupRecoveryAction::DiscardedUnanchoredStage => "discarded_unanchored_stage",
        FiscalStartupRecoveryAction::FinalizedAnchoredStage => "finalized_anchored_stage",
    }
}
