//! Shared bounded HTTP transport. Rust alone owns recovery transitions.
use super::{RecoveryCommandResultV1, RecoveryRuntime, RecoveryRuntimeError};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use chio_core_types::recovery::{decode_contract, decode_recovery_capability};
use chio_kernel::recovery::RecoveryPermission;
use chio_security_types::recovery::{
    ProtectedText, RecoveryCommandV1, WorkflowId, MAX_RECOVERY_WIRE_BYTES,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

mod admission;
mod authentication;
pub(super) use admission::PrincipalWorkLimiter;
use admission::{command_class, command_permission, NativeAdmission, WorkClass};
pub(super) use authentication::AuthenticationLane;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransportRequestV1 {
    pub capability: ProtectedText<32768>,
    pub command: ProtectedText<32768>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryReviewRequestV1 {
    capability: ProtectedText<32768>,
    workflow_id: WorkflowId,
}
impl core::fmt::Debug for RecoveryTransportRequestV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryTransportRequestV1([redacted])")
    }
}
/// Mount only on the host's authenticated private control listener. The scoped
/// signed capability is reverified inside every handler and owning mutation.
#[derive(Clone)]
struct RecoveryHost {
    runtime: Arc<RecoveryRuntime>,
    native: Arc<NativeAdmission>,
    planning_authentication: Arc<AuthenticationLane>,
    existing_authentication: Arc<AuthenticationLane>,
    settlement_authentication: Arc<AuthenticationLane>,
    settlement_principals: Arc<PrincipalWorkLimiter>,
    settlement: Arc<super::settlement::SettlementExecutor>,
}
impl RecoveryHost {
    fn new(runtime: Arc<RecoveryRuntime>) -> Result<Self, RecoveryRuntimeError> {
        Ok(Self {
            runtime,
            native: Arc::new(NativeAdmission::new(Arc::new(Semaphore::new(4)))),
            planning_authentication: AuthenticationLane::new("chio-recovery-auth-planning")?,
            existing_authentication: AuthenticationLane::new("chio-recovery-auth-existing")?,
            settlement_authentication: AuthenticationLane::new("chio-recovery-auth-settle")?,
            settlement_principals: PrincipalWorkLimiter::new(),
            settlement: Arc::new(super::settlement::SettlementExecutor::new()?),
        })
    }
    fn authentication(&self, class: WorkClass) -> &AuthenticationLane {
        match class {
            WorkClass::Planning => &self.planning_authentication,
            WorkClass::Existing => &self.existing_authentication,
        }
    }
}

pub fn recovery_router(runtime: Arc<RecoveryRuntime>) -> Result<Router, RecoveryRuntimeError> {
    let host = RecoveryHost::new(runtime)?;
    Ok(Router::new()
        .route("/v1/recovery/commands", post(command))
        .route("/v1/recovery/review", post(review))
        .route("/v1/recovery/settle", post(settle))
        .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
        .with_state(host))
}
pub(super) fn response<T: Serialize>(
    result: Result<T, RecoveryRuntimeError>,
) -> axum::response::Response {
    match result {
        Ok(value) => match chio_core_types::canonical_json_bytes(&value) {
            Ok(bytes) if bytes.len() <= 262144 => (
                StatusCode::OK,
                [("content-type", "application/json")],
                bytes,
            )
                .into_response(),
            Ok(_) => response::<()>(Err(RecoveryRuntimeError::ProjectionTooLarge)),
            Err(_) => response::<()>(Err(RecoveryRuntimeError::Unavailable)),
        },
        Err(error) => {
            let (status, category) = match error {
                RecoveryRuntimeError::InvalidCommand => {
                    (StatusCode::BAD_REQUEST, "recovery.invalid_command")
                }
                RecoveryRuntimeError::AuthorityDenied => {
                    (StatusCode::FORBIDDEN, "recovery.authority_denied")
                }
                RecoveryRuntimeError::Conflict => (StatusCode::CONFLICT, "recovery.conflict"),
                RecoveryRuntimeError::OriginRefused => {
                    (StatusCode::CONFLICT, "recovery.origin_refused")
                }
                RecoveryRuntimeError::UnsupportedProfile => {
                    (StatusCode::CONFLICT, "recovery.unsupported_profile")
                }
                RecoveryRuntimeError::UncoveredMediation => {
                    (StatusCode::CONFLICT, "recovery.uncovered_mediation")
                }
                RecoveryRuntimeError::RestartRequired => {
                    (StatusCode::CONFLICT, "recovery.restart_required")
                }
                RecoveryRuntimeError::UnknownEffect => {
                    (StatusCode::CONFLICT, "recovery.unknown_effect")
                }
                RecoveryRuntimeError::ProbeExpired => {
                    (StatusCode::CONFLICT, "recovery.probe_expired")
                }
                RecoveryRuntimeError::ProjectionTooLarge => (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "recovery.projection_too_large",
                ),
                RecoveryRuntimeError::Busy => (StatusCode::SERVICE_UNAVAILABLE, "recovery.busy"),
                RecoveryRuntimeError::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "recovery.unavailable")
                }
            };
            (status, category).into_response()
        }
    }
}
// Envelope bounds and current actor authentication precede native admission.
// No unbounded blocking work queue: every native permit is retained inside its
// worker, including when the HTTP caller disconnects. Native entry points repeat
// authentication; advisory authentication cannot authorize an effect itself.
async fn command(State(host): State<RecoveryHost>, bytes: Bytes) -> axum::response::Response {
    response(command_result(host, bytes).await)
}
async fn command_result(
    host: RecoveryHost,
    bytes: Bytes,
) -> Result<RecoveryCommandResultV1, RecoveryRuntimeError> {
    let request: RecoveryTransportRequestV1 =
        decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let command: RecoveryCommandV1 = decode_contract(request.command.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let capability = decode_recovery_capability(request.capability.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let class = command_class(&command.command);
    let actor = host
        .authentication(class)
        .authenticate(
            host.runtime.clone(),
            &capability,
            command_permission(&command.command),
        )
        .await?;
    let permit = host.native.try_acquire(class, &actor)?;
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        handle.block_on(host.runtime.execute_command(&capability, &command))
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
}
async fn review(State(host): State<RecoveryHost>, bytes: Bytes) -> axum::response::Response {
    response(review_result(host, bytes).await)
}
async fn review_result(
    host: RecoveryHost,
    bytes: Bytes,
) -> Result<chio_kernel::recovery::RecoveryReviewDocumentV1, RecoveryRuntimeError> {
    let request: RecoveryReviewRequestV1 =
        decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let capability = decode_recovery_capability(request.capability.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let actor = host
        .existing_authentication
        .authenticate(
            host.runtime.clone(),
            &capability,
            RecoveryPermission::Approve,
        )
        .await?;
    let permit = host.native.try_acquire(WorkClass::Existing, &actor)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        host.runtime
            .review_document(&capability, &request.workflow_id)
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
}
async fn settle(State(host): State<RecoveryHost>, bytes: Bytes) -> axum::response::Response {
    response(settle_result(host, bytes).await)
}
async fn settle_result(
    host: RecoveryHost,
    bytes: Bytes,
) -> Result<chio_kernel::recovery::RecoveryCommandResponseV1, RecoveryRuntimeError> {
    let request: RecoveryReviewRequestV1 =
        decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let capability = decode_recovery_capability(request.capability.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let actor = host
        .settlement_authentication
        .authenticate(
            host.runtime.clone(),
            &capability,
            RecoveryPermission::Settle,
        )
        .await?;
    let principal = host.settlement_principals.try_acquire(&actor)?;
    let runtime = host.runtime.clone();
    let submitted = host.settlement.try_submit(Box::new(move || {
        let _principal = principal;
        runtime.settle(&capability, &request.workflow_id)
    }))?;
    submitted
        .await
        .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
}

#[cfg(test)]
#[path = "transport/admission_test_support.rs"]
pub(super) mod admission_test_support;

#[cfg(test)]
#[path = "transport/authentication_backlog_test_support.rs"]
pub(super) mod authentication_backlog_test_support;
