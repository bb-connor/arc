//! Independent bounded capacity; explanation work cannot occupy effect or
//! settlement slots. The response is always the separately signed safe view.
use super::RecoveryExplanationService;
use crate::recovery::transport::{AuthenticationLane, PrincipalWorkLimiter};
use crate::recovery::{RecoveryRuntime, RecoveryRuntimeError};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    routing::post,
    Router,
};
use chio_core_types::recovery::{
    decode_contract, decode_recovery_capability, SignedRecoveryExplanationViewV1,
};
use chio_kernel::recovery::RecoveryPermission;
use chio_security_types::recovery::{ProtectedText, WorkflowId, MAX_RECOVERY_WIRE_BYTES};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplanationRequest {
    capability: ProtectedText<32768>,
    workflow_id: WorkflowId,
}
#[derive(Clone)]
struct ExplanationHost {
    runtime: Arc<RecoveryRuntime>,
    service: Arc<RecoveryExplanationService>,
    authentication: Option<Arc<AuthenticationLane>>,
    principals: Arc<PrincipalWorkLimiter>,
    capacity: Arc<Semaphore>,
}

pub fn recovery_explanation_router(
    runtime: Arc<RecoveryRuntime>,
    service: Arc<RecoveryExplanationService>,
) -> Router {
    Router::new()
        .route("/v1/recovery/explain", post(explain))
        .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
        .with_state(ExplanationHost {
            runtime,
            service,
            // Preserve the public Router API while refusing all requests if
            // the independent authentication worker cannot be started.
            authentication: AuthenticationLane::new("chio-recovery-auth-explain").ok(),
            principals: PrincipalWorkLimiter::new(),
            capacity: Arc::new(Semaphore::new(2)),
        })
}
async fn explain(State(host): State<ExplanationHost>, bytes: Bytes) -> axum::response::Response {
    crate::recovery::transport::response(explain_result(host, bytes).await)
}
async fn explain_result(
    host: ExplanationHost,
    bytes: Bytes,
) -> Result<SignedRecoveryExplanationViewV1, RecoveryRuntimeError> {
    let request: ExplanationRequest =
        decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let capability = decode_recovery_capability(request.capability.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let authentication = host
        .authentication
        .as_ref()
        .ok_or(RecoveryRuntimeError::Unavailable)?;
    let actor = authentication
        .authenticate(
            host.runtime.clone(),
            &capability,
            RecoveryPermission::Inspect,
        )
        .await?;
    let principal = host.principals.try_acquire(&actor)?;
    let permit = host
        .capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| RecoveryRuntimeError::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _principal = principal;
        host.runtime
            .explain(&capability, &request.workflow_id, &host.service)
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
}

#[cfg(test)]
impl RecoveryExplanationService {
    pub(in crate::recovery) async fn call_with_native_authentication_backlog(
        runtime: Arc<RecoveryRuntime>,
        service: Arc<RecoveryExplanationService>,
        capability: &chio_core_types::capability::token::CapabilityToken,
        store: chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore,
        bytes: Vec<u8>,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        use crate::recovery::transport::authentication_backlog_test_support::NativeAuthenticationBacklog;
        use axum::{body::Body, http::Request};
        use std::time::Duration;
        use tower::ServiceExt;

        let authentication = AuthenticationLane::new("chio-recovery-auth-backlog-explain")?;
        let backlog = NativeAuthenticationBacklog::start(
            authentication.clone(),
            runtime.clone(),
            capability.clone(),
            RecoveryPermission::Inspect,
            store,
        )
        .await?;
        let host = ExplanationHost {
            runtime,
            service,
            authentication: Some(authentication),
            principals: PrincipalWorkLimiter::new(),
            capacity: Arc::new(Semaphore::new(2)),
        };
        let router = Router::new()
            .route("/v1/recovery/explain", post(explain))
            .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
            .with_state(host);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            router.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/recovery/explain")
                    .body(Body::from(bytes))?,
            ),
        )
        .await;
        backlog.finish().await?;
        Ok(response.map_err(|_| "forged explanation token waited for native auth backlog")??)
    }
}
