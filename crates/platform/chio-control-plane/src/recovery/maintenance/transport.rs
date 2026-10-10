//! Bounded private projections authenticate before native work and repeat owning checks.
use super::super::{transport::response, RecoveryRuntimeError};
use super::RecoveryMaintenanceRuntime;
use crate::recovery::transport::{AuthenticationLane, PrincipalWorkLimiter};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    routing::post,
    Router,
};
use chio_core_types::{
    capability::token::CapabilityToken,
    recovery::{decode_contract, decode_recovery_capability},
};
use chio_kernel::recovery::{AuthenticatedRecoveryActor, RecoveryPermission};
use chio_security_types::recovery::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
struct Host {
    service: Arc<RecoveryMaintenanceRuntime>,
    authentication: Option<Arc<AuthenticationLane>>,
    principals: Arc<PrincipalWorkLimiter>,
    capacity: Arc<Semaphore>,
}
impl Host {
    fn new(service: Arc<RecoveryMaintenanceRuntime>, capacity: Arc<Semaphore>) -> Self {
        Self {
            service,
            // Preserve the existing public Router signature. Failure to start
            // this independent verifier leaves every valid request unavailable.
            authentication: AuthenticationLane::new("chio-recovery-auth-maintenance").ok(),
            principals: PrincipalWorkLimiter::new(),
            capacity,
        }
    }
    async fn authenticate(
        &self,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, RecoveryRuntimeError> {
        self.authentication
            .as_ref()
            .ok_or(RecoveryRuntimeError::Unavailable)?
            .authenticate(self.service.runtime.clone(), capability, permission)
            .await
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submit {
    capability: ProtectedText<32768>,
    command_id: CommandId,
    report: ProtectedText<32768>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    capability: ProtectedText<32768>,
    report_id: EvidenceRef,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Propose {
    capability: ProtectedText<32768>,
    proposal: ProtectedText<32768>,
}

/// Operator mounts this on the authenticated private control listener.
/// No report or proposal route can apply a policy or invoke an effect.
pub fn recovery_maintenance_router(service: Arc<RecoveryMaintenanceRuntime>) -> Router {
    Router::new()
        .route("/v1/recovery/reports/submit", post(submit))
        .route("/v1/recovery/reports/read", post(read))
        .route("/v1/recovery/policy/propose", post(propose))
        .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
        .with_state(Host::new(service, Arc::new(Semaphore::new(2))))
}
async fn run<T, F>(
    host: Host,
    actor: AuthenticatedRecoveryActor,
    work: F,
) -> axum::response::Response
where
    T: Serialize + Send + 'static,
    F: FnOnce(&RecoveryMaintenanceRuntime) -> Result<T, RecoveryRuntimeError> + Send + 'static,
{
    // Both native permits roll back if admission fails. A duplicate verified
    // principal cannot transiently occupy another principal's capacity.
    let principal = match host.principals.try_acquire(&actor) {
        Ok(principal) => principal,
        Err(error) => return response::<T>(Err(error)),
    };
    let Ok(permit) = host.capacity.clone().try_acquire_owned() else {
        return response::<T>(Err(RecoveryRuntimeError::Unavailable));
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _principal = principal;
        work(&host.service)
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable));
    response(result)
}
fn invalid<T>(_: T) -> RecoveryRuntimeError {
    RecoveryRuntimeError::InvalidCommand
}
async fn submit(State(host): State<Host>, bytes: Bytes) -> axum::response::Response {
    let request: Submit = match decode_contract(&bytes) {
        Ok(request) => request,
        Err(error) => return response::<DecisionReportViewV1>(Err(invalid(error))),
    };
    let capability = match decode_recovery_capability(request.capability.as_str().as_bytes()) {
        Ok(capability) => capability,
        Err(error) => return response::<DecisionReportViewV1>(Err(invalid(error))),
    };
    let report: DecisionReportV1 = match decode_contract(request.report.as_str().as_bytes()) {
        Ok(report) => report,
        Err(error) => return response::<DecisionReportViewV1>(Err(invalid(error))),
    };
    if let Err(error) = report.validate() {
        return response::<DecisionReportViewV1>(Err(invalid(error)));
    }
    let actor = match host
        .authenticate(&capability, RecoveryPermission::Report)
        .await
    {
        Ok(actor) => actor,
        Err(error) => return response::<DecisionReportViewV1>(Err(error)),
    };
    run(host, actor, move |service| {
        // Current Report authorization, conditional KnowledgeRead, classified
        // reader binding, live attachments and writer checks repeat natively.
        let value = service.submit_report(&capability, &request.command_id, &report)?;
        Ok(DecisionReportViewV1 {
            domain_version: VersionV1,
            id: value.id,
            digest: value.digest,
            report: value.report,
            label: value.label,
            influence: value.influence,
        })
    })
    .await
}
async fn read(State(host): State<Host>, bytes: Bytes) -> axum::response::Response {
    let request: Read = match decode_contract(&bytes) {
        Ok(request) => request,
        Err(error) => return response::<DecisionReportViewV1>(Err(invalid(error))),
    };
    let capability = match decode_recovery_capability(request.capability.as_str().as_bytes()) {
        Ok(capability) => capability,
        Err(error) => return response::<DecisionReportViewV1>(Err(invalid(error))),
    };
    let actor = match host
        .authenticate(&capability, RecoveryPermission::Inspect)
        .await
    {
        Ok(actor) => actor,
        Err(error) => return response::<DecisionReportViewV1>(Err(error)),
    };
    run(host, actor, move |service| {
        let value = service.read_report(&capability, &request.report_id)?;
        Ok(DecisionReportViewV1 {
            domain_version: VersionV1,
            id: value.id,
            digest: value.digest,
            report: value.report,
            label: value.label,
            influence: value.influence,
        })
    })
    .await
}
async fn propose(State(host): State<Host>, bytes: Bytes) -> axum::response::Response {
    let request: Propose = match decode_contract(&bytes) {
        Ok(request) => request,
        Err(error) => return response::<PolicyMaintenanceViewV1>(Err(invalid(error))),
    };
    let capability = match decode_recovery_capability(request.capability.as_str().as_bytes()) {
        Ok(capability) => capability,
        Err(error) => return response::<PolicyMaintenanceViewV1>(Err(invalid(error))),
    };
    let proposal: PolicyMaintenanceProposalV1 =
        match decode_contract(request.proposal.as_str().as_bytes()) {
            Ok(proposal) => proposal,
            Err(error) => return response::<PolicyMaintenanceViewV1>(Err(invalid(error))),
        };
    if let Err(error) = proposal.validate() {
        return response::<PolicyMaintenanceViewV1>(Err(invalid(error)));
    }
    let actor = match host
        .authenticate(&capability, RecoveryPermission::Maintain)
        .await
    {
        Ok(actor) => actor,
        Err(error) => return response::<PolicyMaintenanceViewV1>(Err(error)),
    };
    let reader = match host
        .authenticate(&capability, RecoveryPermission::KnowledgeRead)
        .await
    {
        Ok(reader) => reader,
        Err(error) => return response::<PolicyMaintenanceViewV1>(Err(error)),
    };
    if reader.scope() != actor.scope()
        || reader.principal() != actor.principal()
        || reader.capability().subject != actor.capability().subject
    {
        return response::<PolicyMaintenanceViewV1>(Err(RecoveryRuntimeError::AuthorityDenied));
    }
    run(host, actor, move |service| {
        // Both native actors are reauthenticated; the owning writer repeats
        // their same scope, principal, subject and current reader binding.
        let value = service.propose(&capability, &proposal)?;
        Ok(PolicyMaintenanceViewV1 {
            domain_version: VersionV1,
            digest: value.digest,
            proposal: value.proposal,
            label: value.label,
            influence: value.influence,
        })
    })
    .await
}

#[cfg(test)]
pub(in crate::recovery) async fn call_with_occupied_maintenance_capacity(
    service: Arc<RecoveryMaintenanceRuntime>,
    route: &str,
    bytes: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let capacity = Arc::new(Semaphore::new(2));
    let _occupied = capacity.clone().acquire_many_owned(2).await?;
    let host = Host::new(service, capacity);
    match route {
        "/v1/recovery/reports/submit" => Ok(submit(State(host), Bytes::from(bytes)).await),
        "/v1/recovery/reports/read" => Ok(read(State(host), Bytes::from(bytes)).await),
        "/v1/recovery/policy/propose" => Ok(propose(State(host), Bytes::from(bytes)).await),
        _ => Err("unsupported maintenance admission test route".into()),
    }
}
