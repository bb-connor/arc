//! Validate original JSON bytes before Axum can discard keys or numeric spelling.
//!
//! The route table is checked against actual request extractors and router bindings
//! by check-trust-boundaries.py. Signature, authentication and semantic validation
//! remain the owning handler's responsibility. Binary and Form routes stay with
//! their existing format-specific readers.
use super::frost::*;
use super::*;
use axum::body::Body;
use axum::extract::{MatchedPath, NestedPath, Request};
use axum::middleware::Next;
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use futures_util::StreamExt;

#[derive(Debug, thiserror::Error)]
enum InputError {
    #[error("JSON request body exceeds its limit")]
    TooLarge,
    #[error("JSON request body transport failed")]
    Transport(#[source] axum::Error),
    #[error(transparent)]
    Json(#[from] UntrustedJsonError),
}

impl IntoResponse for InputError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Transport(_) | Self::Json(_) => StatusCode::BAD_REQUEST,
        };
        plain_http_error(status, &self.to_string())
    }
}

async fn read_body(body: Body, bound: usize) -> Result<Vec<u8>, InputError> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(InputError::Transport)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|len| len > bound)
        {
            return Err(InputError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum Mode {
    Signed,
    Document,
}

fn contract(method: &str, path: &str) -> Option<(Mode, usize)> {
    match (method, path) {
        ("POST", AUTHORITY_KEY_LOG_SYNC_PATH) => Some((Mode::Signed, 4 * 1024)),
        ("POST", ISSUE_CAPABILITY_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FEDERATED_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", SCIM_USERS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("PUT", FEDERATION_PROVIDER_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("PUT", FEDERATION_POLICY_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FEDERATION_POLICY_EVALUATE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CERTIFICATIONS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CERTIFICATION_DISCOVERY_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CERTIFICATION_DISCOVERY_CONSUME_PATH) => Some((Mode::Document, 1024 * 1024)),
        ("POST", CERTIFICATION_REVOKE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CERTIFICATION_DISPUTE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", GENERIC_TRUST_ACTIVATION_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", GENERIC_TRUST_ACTIVATION_EVALUATE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", GENERIC_GOVERNANCE_CASE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", GENERIC_GOVERNANCE_CASE_EVALUATE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", OPEN_MARKET_PENALTY_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", OPEN_MARKET_PENALTY_EVALUATE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_PROPOSALS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_PROPOSAL_ADMIT_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_APPROVALS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_ACTIVATIONS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_RESOLVE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_MARKETPLACE_PRICE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FISCAL_PROPOSAL_PREVIEW_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_ISSUANCE_OFFERS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_ISSUANCE_TOKEN_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_ISSUANCE_CREDENTIAL_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_STATUSES_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_STATUS_REVOKE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("PUT", PASSPORT_VERIFIER_POLICY_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_CHALLENGES_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_CHALLENGE_VERIFY_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PASSPORT_OID4VP_REQUESTS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", REVOCATIONS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", TOOL_RECEIPTS_PATH) => Some((Mode::Signed, 128 * 1024 * 1024)),
        ("POST", CHILD_RECEIPTS_PATH) => Some((Mode::Signed, 128 * 1024 * 1024)),
        ("POST", BUDGET_INCREMENT_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", BUDGET_AUTHORIZE_EXPOSURE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", BUDGET_CAPTURE_INVOCATION_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", BUDGET_RELEASE_EXPOSURE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", BUDGET_RECONCILE_SPEND_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_AUTHORIZE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_AUTHORIZE_CUMULATIVE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_FENCED_REVERSE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_RELEASE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_RECONCILE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", STRUCTURED_BUDGET_CAPTURE_SPEND_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", INTERNAL_CLUSTER_PARTITION_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", EVIDENCE_EXPORT_PATH) => Some((Mode::Document, 1024 * 1024)),
        ("POST", EVIDENCE_IMPORT_PATH) => Some((Mode::Signed, 64 * 1024 * 1024)),
        ("POST", RUNTIME_ATTESTATION_APPRAISAL_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CAPITAL_INSTRUCTION_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CAPITAL_ALLOCATION_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CREDIT_FACILITY_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CREDIT_BOND_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", CREDIT_BONDED_EXECUTION_SIMULATION_PATH) => Some((Mode::Document, 1024 * 1024)),
        ("POST", CREDIT_LOSS_LIFECYCLE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_PROVIDER_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_QUOTE_REQUEST_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_QUOTE_RESPONSE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_PRICING_AUTHORITY_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_PLACEMENT_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_BOUND_COVERAGE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_CLAIM_PACKAGE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_CLAIM_RESPONSE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_CLAIM_DISPUTE_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH) => {
            Some((Mode::Signed, 1024 * 1024))
        }
        ("POST", LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH) => {
            Some((Mode::Signed, 1024 * 1024))
        }
        ("POST", LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH) => {
            Some((Mode::Signed, 1024 * 1024))
        }
        ("POST", SETTLEMENT_RECONCILE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", METERED_BILLING_RECONCILE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", UNDERWRITING_SIMULATION_PATH) => Some((Mode::Document, 1024 * 1024)),
        ("POST", UNDERWRITING_DECISION_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", UNDERWRITING_APPEALS_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", UNDERWRITING_APPEAL_RESOLVE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", REPUTATION_COMPARE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PORTABLE_NEGATIVE_EVENT_ISSUE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", PORTABLE_REPUTATION_EVALUATE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", LINEAGE_RECORD_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FINDINGS_SEARCH_PATH) => Some((Mode::Document, 1024 * 1024)),
        ("POST", FINDINGS_COLLATERAL_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FINDING_ACTIVATE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FINDING_PARTICIPATION_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_CLAIM_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_RENEW_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_COMMITMENT_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_PACKAGE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_SHARE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_COMPLETE_PATH) => Some((Mode::Signed, 1024 * 1024)),
        ("POST", FROST_COORDINATOR_CANCEL_PATH) => Some((Mode::Signed, 1024 * 1024)),
        _ => None,
    }
}

fn validate_signed(bytes: &[u8], bound: usize) -> Result<(), UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)?.decode_signed::<serde_json::Value>()?;
    Ok(())
}

fn validate_document(bytes: &[u8], bound: usize) -> Result<(), UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)?.decode_document::<serde_json::Value>()?;
    Ok(())
}

pub(super) async fn validate(request: Request, next: Next) -> Response {
    let Some(path) = request.extensions().get::<MatchedPath>() else {
        return next.run(request).await;
    };
    // Axum includes every outer nest prefix in MatchedPath. NestedPath is
    // framework-owned route context, so parameterized mounts can be removed
    // without guessing a suffix or trusting caller-controlled URI text.
    let path = match request.extensions().get::<NestedPath>() {
        Some(prefix) => match path
            .as_str()
            .strip_prefix(prefix.as_str().trim_end_matches('/'))
        {
            Some(relative) => relative,
            None => return plain_http_error(StatusCode::BAD_REQUEST, "invalid JSON route context"),
        },
        None => path.as_str(),
    };
    let Some((mode, bound)) = contract(request.method().as_str(), path) else {
        return next.run(request).await;
    };
    // Let Axum retain its own media-type rejection and +json handling. Only
    // requests whose media type can select Json need original-token validation.
    let is_json = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            let lower = value.to_ascii_lowercase();
            lower == "application/json"
                || (lower.starts_with("application/") && lower.ends_with("+json"))
        });
    if !is_json {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let bytes = match read_body(body, bound).await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let parsed = match mode {
        Mode::Signed => validate_signed(&bytes, bound),
        Mode::Document => validate_document(&bytes, bound),
    };
    if let Err(error) = parsed {
        return InputError::Json(error).into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}
