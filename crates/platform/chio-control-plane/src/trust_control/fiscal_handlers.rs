use super::*;
use chio_fiscal::SignedFiscalProposal;
use chio_store_sqlite::fiscal_store::FiscalStoreError;

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

pub(crate) async fn handle_fiscal_proposal_preview(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(proposal): Json<SignedFiscalProposal>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.preview_proposal(proposal) {
        Ok(proposal) => Json(json!({
            "schema": "chio.fiscal.proposal-preview.v1",
            "proposal": proposal.signed(),
            "proposalDigest": proposal.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

pub(crate) async fn handle_fiscal_proposal_persist(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(proposal): Json<SignedFiscalProposal>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.persist_proposal(proposal) {
        Ok(proposal) => Json(json!({
            "schema": "chio.fiscal.proposal-persisted.v1",
            "proposal": proposal.signed(),
            "proposalDigest": proposal.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

fn fiscal_runtime_not_configured() -> Response {
    plain_http_error(
        StatusCode::CONFLICT,
        "trust control service has no fiscal runtime configured",
    )
}

fn fiscal_operation_error(error: TrustFiscalOperationError) -> Response {
    let status = match &error {
        TrustFiscalOperationError::InvalidProposal(_) => StatusCode::UNPROCESSABLE_ENTITY,
        TrustFiscalOperationError::Store(FiscalStoreError::Conflict) => StatusCode::CONFLICT,
        TrustFiscalOperationError::Startup(_) | TrustFiscalOperationError::Store(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    plain_http_error(status, &error.to_string())
}

const fn recovery_action_name(action: FiscalStartupRecoveryAction) -> &'static str {
    match action {
        FiscalStartupRecoveryAction::Ready => "ready",
        FiscalStartupRecoveryAction::DiscardedUnanchoredStage => "discarded_unanchored_stage",
        FiscalStartupRecoveryAction::FinalizedAnchoredStage => "finalized_anchored_stage",
    }
}
