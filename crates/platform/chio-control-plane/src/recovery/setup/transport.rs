//! Bounded setup admission retains native ownership after caller disconnect.
use super::*;
use crate::recovery::transport::{AuthenticationLane, PrincipalWorkLimiter};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    routing::post,
    Router,
};
use chio_core_types::recovery::{decode_contract, decode_recovery_capability};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    capability: ProtectedText<32768>,
    workflow_id: WorkflowId,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifyRequest {
    capability: ProtectedText<32768>,
    probe: ProtectedText<32768>,
}
#[derive(Clone)]
struct Host {
    service: Arc<RecoverySetupService>,
    authentication: Arc<AuthenticationLane>,
    principals: Arc<PrincipalWorkLimiter>,
    capacity: Arc<Semaphore>,
}
impl Host {
    fn new(
        service: Arc<RecoverySetupService>,
        capacity: Arc<Semaphore>,
    ) -> Result<Self, RecoveryRuntimeError> {
        Ok(Self {
            service,
            authentication: AuthenticationLane::new("chio-recovery-auth-setup")?,
            principals: PrincipalWorkLimiter::new(),
            capacity,
        })
    }
}
pub fn protected_recovery_router(
    service: Arc<RecoverySetupService>,
) -> Result<Router, RecoveryRuntimeError> {
    let recovery = super::super::transport::recovery_router(service.runtime.clone())?;
    let host = Host::new(service, Arc::new(Semaphore::new(2)))?;
    Ok(recovery.merge(
        Router::new()
            .route("/v1/recovery/setup/probe", post(probe))
            .route("/v1/recovery/setup/qualify", post(qualify))
            .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
            .with_state(host),
    ))
}
async fn probe(State(host): State<Host>, bytes: Bytes) -> axum::response::Response {
    super::super::transport::response(probe_result(host, bytes).await)
}
async fn probe_result(
    host: Host,
    bytes: Bytes,
) -> Result<SignedRecoverySetupProbeV1, RecoveryRuntimeError> {
    let input: ProbeRequest =
        decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let capability = decode_recovery_capability(input.capability.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let actor = host
        .authentication
        .authenticate(
            host.service.runtime.clone(),
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
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _principal = principal;
        // This call still reads the current deployment, verifies the live
        // mediator binding and freshly authenticates Inspect inside its actor.
        handle.block_on(host.service.probe(&capability, &input.workflow_id))
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
}
async fn qualify(State(host): State<Host>, bytes: Bytes) -> axum::response::Response {
    super::super::transport::response(qualify_result(host, bytes).await)
}
async fn qualify_result(
    host: Host,
    bytes: Bytes,
) -> Result<SignedRecoverySetupReportV1, RecoveryRuntimeError> {
    let input: QualifyRequest =
        decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let capability = decode_recovery_capability(input.capability.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let probe: SignedRecoverySetupProbeV1 = decode_contract(input.probe.as_str().as_bytes())
        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
    let actor = host
        .authentication
        .authenticate(
            host.service.runtime.clone(),
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
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _principal = principal;
        // Probe identity, current writer/fence, operator authority, mediator
        // binding and freshly authenticated Inspect remain service/store checks.
        handle.block_on(host.service.qualify(&capability, &probe))
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
}

#[cfg(test)]
pub(in crate::recovery) async fn call_with_occupied_setup_capacity(
    service: Arc<RecoverySetupService>,
    route: &str,
    bytes: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let capacity = Arc::new(Semaphore::new(2));
    let _occupied = capacity.clone().acquire_many_owned(2).await?;
    let host = Host::new(service, capacity)?;
    match route {
        "/v1/recovery/setup/probe" => Ok(probe(State(host), Bytes::from(bytes)).await),
        "/v1/recovery/setup/qualify" => Ok(qualify(State(host), Bytes::from(bytes)).await),
        _ => Err("unsupported setup admission test route".into()),
    }
}
