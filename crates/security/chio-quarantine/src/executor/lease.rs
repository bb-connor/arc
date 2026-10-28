//! Scheduler lease checks the response executor makes before it writes.

use chio_security_types::ports::{
    EffectPort, PortErrorKind, ResponseSchedulerStore, ScheduledWork, SecurityAlertPort,
    SecurityReceiptSink,
};
use chio_security_types::ResponseSnapshot;

use super::{ExecutorError, ResponseExecutor};

impl<
        S: ResponseSchedulerStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > ResponseExecutor<S, E, R, A>
{
    pub(super) fn validate_work(
        &self,
        snapshot: &ResponseSnapshot,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<(), ExecutorError> {
        if work.tenant_id != snapshot.plan.tenant_id || work.action_id != snapshot.plan.action_id {
            return Err(ExecutorError::WorkMismatch);
        }
        if work.lease_expires_at_unix_ms <= now_unix_ms {
            return Err(ExecutorError::StaleLease);
        }
        self.require_live_lease(work)
    }

    /// Names a lost lease or a retired store before any write. The scheduled CAS still checks the
    /// exact live lease in its own transaction and stays the authoritative fence.
    pub(super) fn require_live_lease(&self, work: &ScheduledWork) -> Result<(), ExecutorError> {
        self.store.validate_lease(work).map_err(|error| {
            if error.is_retired() {
                ExecutorError::StoreRetired
            } else if error.kind() == PortErrorKind::Conflict {
                ExecutorError::StaleLease
            } else {
                ExecutorError::Store(error)
            }
        })
    }
}
