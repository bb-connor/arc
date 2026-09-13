//! Trusted executor control routes. An agent-facing reservation is not a start.
use super::*;
use chio_kernel::caller_delivery::{
    SignedCallerDeliveryReportV1, SignedCallerDispatchAuthorizationV1,
};

const PROTOCOL: &str = "chio.caller-delivery.v1";
const MAX_REQUEST_BYTES: usize = 1024 * 1024 + 32 * 1024;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    protocol: String,
    execution_nonce: SignedExecutionNonce,
    arguments: serde_json::Value,
    #[serde(default)]
    credentials: chio_kernel::CallerStartCredentials,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRequest {
    protocol: String,
    authorization: SignedCallerDispatchAuthorizationV1,
    report: SignedCallerDeliveryReportV1,
}

async fn parse<T: serde::de::DeserializeOwned>(request: Request<Body>) -> Result<T, Response> {
    let bytes = axum::body::to_bytes(request.into_body(), MAX_REQUEST_BYTES)
        .await
        .map_err(|_| {
            sidecar_bad_request("caller delivery request exceeds its bound").into_response()
        })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| sidecar_bad_request("invalid caller delivery request").into_response())
}

fn rejected() -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": "chio_caller_delivery_rejected",
            "message": "original committed caller delivery could not be authenticated or finalized"
        })),
    )
        .into_response()
}

pub(crate) async fn start(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let request: StartRequest = match parse(request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.protocol != PROTOCOL {
        return sidecar_bad_request("unsupported caller delivery protocol").into_response();
    }
    if state
        .capability_is_revoked(&request.execution_nonce.nonce.bound_to.capability_id)
        .await
    {
        return rejected();
    }
    let Some(kernel) = state.mediation_kernel.as_ref() else {
        return rejected();
    };
    let result = kernel
        .lock()
        .await
        .start_caller_execution_with_credentials_blocking(
            &request.execution_nonce,
            &request.arguments,
            request.credentials,
        );
    match result {
        Ok(chio_kernel::CallerStartResponse::Authorized(authorization)) => {
            (StatusCode::OK, axum::Json(serde_json::json!({
                "status": "dispatch_committed", "protocol": PROTOCOL, "authorization": authorization,
            }))).into_response()
        }
        Ok(chio_kernel::CallerStartResponse::Denied(response)) => {
            (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({
                "status": "deny", "protocol": PROTOCOL, "receipt": response.receipt,
            }))).into_response()
        }
        Err(_) => rejected(),
    }
}

pub(crate) async fn report(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let request: ReportRequest = match parse(request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request.protocol != PROTOCOL {
        return sidecar_bad_request("unsupported caller delivery protocol").into_response();
    }
    if state
        .capability_is_revoked(
            request
                .authorization
                .authorization
                .invocation
                .capability_id
                .as_str(),
        )
        .await
    {
        return rejected();
    }
    let Some(kernel) = state.mediation_kernel.as_ref() else {
        return rejected();
    };
    let result = kernel
        .lock()
        .await
        .reconcile_authenticated_caller_execution_blocking(&request.authorization, &request.report);
    match result {
        Ok(response) => {
            // This route returns only the kernel's guard-evaluated value. The
            // executor report is never reflected as agent-visible output.
            let output = match response.output {
                Some(chio_kernel::ToolCallOutput::Value(value)) => Some(value),
                None => None,
                Some(chio_kernel::ToolCallOutput::Stream(_)) => return rejected(),
            };
            (StatusCode::OK, axum::Json(serde_json::json!({
            "status": if matches!(response.verdict, chio_kernel::Verdict::Allow) { "reconciled" } else { "deny" },
            "protocol": PROTOCOL, "receipt": response.receipt, "output": output,
            "execution_authorized": false,
        }))).into_response()
        }
        Err(_) => rejected(),
    }
}
