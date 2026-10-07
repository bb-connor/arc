//! Stop authority preserves private lifecycle custody and reveals no progress.
use super::*;

/// Generic acknowledgement for a named child's native stop request. Its exact
/// public shape contains the stop identity and a constant acceptance value.
/// It does not describe execution progress, return delivery or classified input.
#[derive(Serialize)]
pub struct NativeConfinedCancellation {
    child: ProcessId,
    request_accepted: bool,
}

impl NativeConfinedCancellation {
    fn accepted(child: ProcessId) -> Self {
        Self {
            child,
            request_accepted: true,
        }
    }

    /// The host-issued identity needed to stop the same journal child.
    pub fn child(&self) -> &ProcessId {
        &self.child
    }

    /// Acceptance describes this request, independent of prior child progress.
    pub const fn request_accepted(&self) -> bool {
        self.request_accepted
    }
}

impl core::fmt::Debug for NativeConfinedCancellation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeConfinedCancellation([redacted])")
    }
}

impl SqliteAdmissionOperationStore {
    /// Stopping never requires source preview and never releases diagnostics,
    /// resets observation, refunds resources or reports child-derived status.
    pub fn cancel_confined_child(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeConfinedCancellation, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedCancel {
            return Err(refused("cancel authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let mut record = record(&tx, actor.scope(), request)?;
            if !record.stop_requested {
                record.stop_requested = true;
                if !matches!(
                    record.reservation.state,
                    IsolationStateV1::Closed
                        | IsolationStateV1::Failed
                        | IsolationStateV1::Cancelled
                        | IsolationStateV1::Quarantined
                ) {
                    record.reservation.state = IsolationStateV1::Cancelled;
                }
                retain(&tx, &self.serving_owner, &record)?;
            }
            let accepted = NativeConfinedCancellation::accepted(record.reservation.boundary.child);
            Ok((tx, accepted))
        })
    }
}
