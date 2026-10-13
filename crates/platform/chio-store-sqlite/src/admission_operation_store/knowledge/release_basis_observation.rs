//! Default-off test observations carry no native writer or read authority.
use super::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactReleaseBasisObservation {
    Accepted,
    PolicyRejected,
    ContractRejected,
    PolicyAndContractRejected,
    RejectedWithoutBasisMismatch,
    ObservationOverflow,
}

struct Registration {
    scope: RecoveryScopeV1,
    principal: chio_security_types::PrincipalId,
    request: RequestId,
    observations: Vec<ArtifactReleaseBasisObservation>,
}

thread_local! {
    static OBSERVER: RefCell<Option<Registration>> = const { RefCell::new(None) };
}

pub struct ArtifactReleaseBasisObservationScope {
    scope: RecoveryScopeV1,
    principal: chio_security_types::PrincipalId,
    request: RequestId,
    _thread: PhantomData<Rc<()>>,
}

/// Registers only a thread-local observer, without authorizing an operation.
pub fn observe_artifact_release_basis(
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<ArtifactReleaseBasisObservationScope, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeRead {
        return Err(invariant("artifact release observer permission"));
    }
    OBSERVER.with(|cell| {
        let mut current = cell
            .try_borrow_mut()
            .map_err(|_| invariant("artifact release observer borrowed"))?;
        if current.is_some() {
            return Err(invariant("artifact release observer already registered"));
        }
        *current = Some(Registration {
            scope: actor.scope().clone(),
            principal: actor.principal().clone(),
            request: request.clone(),
            observations: Vec::new(),
        });
        Ok(ArtifactReleaseBasisObservationScope {
            scope: actor.scope().clone(),
            principal: actor.principal().clone(),
            request: request.clone(),
            _thread: PhantomData,
        })
    })
}

impl ArtifactReleaseBasisObservationScope {
    pub fn observations(
        &self,
    ) -> Result<Vec<ArtifactReleaseBasisObservation>, AdmissionOperationStoreError> {
        OBSERVER.with(|cell| {
            let current = cell
                .try_borrow()
                .map_err(|_| invariant("artifact release observer borrowed"))?;
            let registration = current
                .as_ref()
                .ok_or_else(|| invariant("artifact release observer absent"))?;
            if registration.scope != self.scope
                || registration.principal != self.principal
                || registration.request != self.request
            {
                return Err(invariant("artifact release observer identity"));
            }
            Ok(registration.observations.clone())
        })
    }
}

impl Drop for ArtifactReleaseBasisObservationScope {
    fn drop(&mut self) {
        OBSERVER.with(|cell| {
            if let Ok(mut current) = cell.try_borrow_mut() {
                if current.as_ref().is_some_and(|registration| {
                    registration.scope == self.scope
                        && registration.principal == self.principal
                        && registration.request == self.request
                }) {
                    *current = None;
                }
            }
        });
    }
}

pub(super) fn record_artifact_release_basis(
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
    artifact: &NativeArtifactRecordV1,
    profile: &NativeKnowledgeInstallationV1,
    result: &Result<(), AdmissionOperationStoreError>,
) {
    OBSERVER.with(|cell| {
        let Ok(mut current) = cell.try_borrow_mut() else {
            return;
        };
        let Some(registration) = current.as_mut() else {
            return;
        };
        if registration.scope != *actor.scope()
            || registration.principal != *actor.principal()
            || registration.request != *request
        {
            return;
        }
        let observation = if result.is_ok() {
            ArtifactReleaseBasisObservation::Accepted
        } else {
            match (
                artifact.metadata.policy != profile.policy,
                artifact.metadata.contract != profile.contract,
            ) {
                (true, false) => ArtifactReleaseBasisObservation::PolicyRejected,
                (false, true) => ArtifactReleaseBasisObservation::ContractRejected,
                (true, true) => ArtifactReleaseBasisObservation::PolicyAndContractRejected,
                (false, false) => ArtifactReleaseBasisObservation::RejectedWithoutBasisMismatch,
            }
        };
        if registration.observations.len() < 4 {
            registration.observations.push(observation);
        } else if let Some(last) = registration.observations.last_mut() {
            *last = ArtifactReleaseBasisObservation::ObservationOverflow;
        }
    });
}
