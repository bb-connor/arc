use super::{DurableAttestedFindingBatchPlanner, PortError, PortResult};

/// Default spacing between scheduled full-history store audits.
pub(super) const DEFAULT_STORE_AUDIT_INTERVAL_MS: u64 = 300_000;

/// Longest configurable spacing between scheduled store audits.
pub const MAX_STORE_AUDIT_INTERVAL_MS: u64 = 86_400_000;

impl DurableAttestedFindingBatchPlanner {
    /// Sets the spacing between scheduled full-history store audits. Zero and
    /// values above the maximum are rejected.
    pub fn with_store_audit_interval_ms(mut self, interval_ms: u64) -> PortResult<Self> {
        if interval_ms == 0 || interval_ms > MAX_STORE_AUDIT_INTERVAL_MS {
            return Err(PortError::invalid_data());
        }
        self.audit_interval_ms = interval_ms;
        Ok(self)
    }

    /// Re-runs the store audit when the interval has elapsed on the injected
    /// clock since the last audit. Called from the worker recovery pass only,
    /// never from readiness probes. An audit that cannot run records a failed
    /// verdict, so a stale pass is never kept. A clock that moved backwards, or
    /// an audit with no recorded time, counts as due.
    pub(super) fn run_scheduled_store_audit(&self) -> PortResult<()> {
        let now_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        let due = {
            let health = self.lock_health()?;
            match health.audited_at_ms {
                Some(audited_at_ms) => {
                    now_ms < audited_at_ms || now_ms - audited_at_ms >= self.audit_interval_ms
                }
                None => true,
            }
        };
        if due {
            self.run_store_audit()
        } else {
            Ok(())
        }
    }
}
