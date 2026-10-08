//! Known sink fate retains affine original RETURN custody across write refusal.
use super::*;

struct PendingReturnAcknowledgement {
    actor: AuthenticatedRecoveryActor,
    request: RequestId,
    admission: ReturnAdmissionV1,
    delivered: bool,
}

/// A pending error owns its original RETURN identity and known sink result.
/// Reconciliation records that result and never calls a sink or dispatches.
///
/// ```compile_fail
/// use chio_control_plane::confinement::ConfinedDeliveryError;
/// fn duplicate(value: ConfinedDeliveryError) { let _ = value.clone(); }
/// ```
pub struct ConfinedDeliveryError {
    failure: KernelError,
    pending: Option<Box<PendingReturnAcknowledgement>>,
}

impl From<KernelError> for ConfinedDeliveryError {
    fn from(failure: KernelError) -> Self {
        Self {
            failure,
            pending: None,
        }
    }
}

impl core::fmt::Debug for ConfinedDeliveryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConfinedDeliveryError([redacted])")
    }
}

impl core::fmt::Display for ConfinedDeliveryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.pending {
            Some(pending) if pending.delivered => {
                formatter.write_str("delivered; acknowledgement pending")
            }
            Some(_) => formatter.write_str("delivery outcome acknowledgement pending"),
            None => core::fmt::Display::fmt(&self.failure, formatter),
        }
    }
}

impl std::error::Error for ConfinedDeliveryError {}

impl ConfinedDeliveryError {
    pub(super) fn pending(
        failure: KernelError,
        actor: AuthenticatedRecoveryActor,
        request: RequestId,
        admission: ReturnAdmissionV1,
        delivered: bool,
    ) -> Self {
        Self {
            failure,
            pending: Some(Box::new(PendingReturnAcknowledgement {
                actor,
                request,
                admission,
                delivered,
            })),
        }
    }

    /// The current serving owner records only the retained original sink fate.
    /// A refused write returns the same custody for a subsequent attempt.
    pub fn reconcile(
        mut self,
        store: &SqliteAdmissionOperationStore,
        fence: &chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<ReturnAdmissionV1, Self> {
        let Some(pending) = &self.pending else {
            return Err(self);
        };
        let at = match now() {
            Ok(at) => at,
            Err(error) => {
                self.failure = error;
                return Err(self);
            }
        };
        let acknowledged = match store.acknowledge_confined_return(
            &pending.actor,
            &pending.request,
            &pending.admission,
            pending.delivered,
            fence,
            at,
        ) {
            Ok(state) => state,
            Err(error) => {
                self.failure = refused(error);
                return Err(self);
            }
        };
        let Some(mut pending) = self.pending.take() else {
            return Err(self);
        };
        pending.admission.admitted.state = acknowledged;
        Ok(pending.admission)
    }
}
