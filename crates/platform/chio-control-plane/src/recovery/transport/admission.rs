//! Native work keeps bounded existing-work headroom and verified-principal fairness.
use crate::recovery::RecoveryRuntimeError;
use chio_kernel::recovery::{AuthenticatedRecoveryActor, RecoveryPermission};
use chio_security_types::{flow::PrincipalId, recovery::RecoveryCommandBodyV1};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy)]
pub(super) enum WorkClass {
    Planning,
    Existing,
}
pub(super) fn command_class(body: &RecoveryCommandBodyV1) -> WorkClass {
    match body {
        RecoveryCommandBodyV1::CreateWorkflow { .. }
        | RecoveryCommandBodyV1::SelectOffer { .. }
        | RecoveryCommandBodyV1::SubmitApproval { .. } => WorkClass::Planning,
        RecoveryCommandBodyV1::InspectWorkflow { .. }
        | RecoveryCommandBodyV1::ResumeWorkflow { .. }
        | RecoveryCommandBodyV1::CancelWorkflow { .. }
        | RecoveryCommandBodyV1::ReportDecision { .. } => WorkClass::Existing,
    }
}
pub(super) fn command_permission(body: &RecoveryCommandBodyV1) -> RecoveryPermission {
    match body {
        RecoveryCommandBodyV1::CreateWorkflow { .. } => RecoveryPermission::Create,
        RecoveryCommandBodyV1::InspectWorkflow { .. } => RecoveryPermission::Inspect,
        RecoveryCommandBodyV1::SelectOffer { .. } => RecoveryPermission::Select,
        RecoveryCommandBodyV1::SubmitApproval { .. } => RecoveryPermission::Approve,
        RecoveryCommandBodyV1::ResumeWorkflow { .. } => RecoveryPermission::Resume,
        RecoveryCommandBodyV1::CancelWorkflow { .. } => RecoveryPermission::Cancel,
        RecoveryCommandBodyV1::ReportDecision { .. } => RecoveryPermission::Report,
    }
}

/// Active identities are bounded by two, never retained after their work ends.
/// Token rotation cannot allocate a second native slot for one principal.
pub(in crate::recovery) struct PrincipalWorkLimiter {
    active: Mutex<BTreeSet<PrincipalId>>,
}
pub(in crate::recovery) struct PrincipalWorkPermit {
    limiter: Arc<PrincipalWorkLimiter>,
    principal: PrincipalId,
}
impl PrincipalWorkLimiter {
    pub(in crate::recovery) fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(BTreeSet::new()),
        })
    }
    pub(in crate::recovery) fn try_acquire(
        self: &Arc<Self>,
        actor: &AuthenticatedRecoveryActor,
    ) -> Result<PrincipalWorkPermit, RecoveryRuntimeError> {
        let principal = actor.principal();
        let mut active = self
            .active
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        if active.contains(principal) || active.len() >= 2 {
            return Err(RecoveryRuntimeError::Unavailable);
        }
        active.insert(principal.clone());
        Ok(PrincipalWorkPermit {
            limiter: self.clone(),
            principal: principal.clone(),
        })
    }
}
impl Drop for PrincipalWorkPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.limiter.active.lock() {
            active.remove(&self.principal);
        }
    }
}

struct Lane {
    capacity: Arc<Semaphore>,
    principals: Arc<PrincipalWorkLimiter>,
}
impl Lane {
    fn new() -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(2)),
            principals: PrincipalWorkLimiter::new(),
        }
    }
}
/// Two planning jobs and two existing-control jobs share the four native limit.
pub(super) struct NativeAdmission {
    pub(super) total: Arc<Semaphore>,
    planning: Lane,
    existing: Lane,
}
pub(super) struct NativeWorkPermit {
    _principal: PrincipalWorkPermit,
    _class: OwnedSemaphorePermit,
    _total: OwnedSemaphorePermit,
}
impl NativeAdmission {
    pub(super) fn new(total: Arc<Semaphore>) -> Self {
        Self {
            total,
            planning: Lane::new(),
            existing: Lane::new(),
        }
    }
    pub(super) fn try_acquire(
        &self,
        class: WorkClass,
        actor: &AuthenticatedRecoveryActor,
    ) -> Result<NativeWorkPermit, RecoveryRuntimeError> {
        let lane = match class {
            WorkClass::Planning => &self.planning,
            WorkClass::Existing => &self.existing,
        };
        // Reject a duplicate verified principal before it can transiently
        // occupy another principal's class or total capacity. The bounded
        // principal permit rolls back if either native permit is unavailable.
        let principal = lane.principals.try_acquire(actor)?;
        // A planning submission cannot transiently consume a total permit
        // before learning that its independent two-job lane is already full.
        let class = lane
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        let total = self
            .total
            .clone()
            .try_acquire_owned()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(NativeWorkPermit {
            _principal: principal,
            _class: class,
            _total: total,
        })
    }
}
