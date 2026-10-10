//! An actual immutable Process closure permanently prevents finalization.
use super::{ProcessError, ProcessRuntime, RecoveryCallReservation};
mod closure_data;
pub use closure_data::UnusedRecoveryReservationClosureData;

/// An affine Process-owned closure role, never a decoded reservation receipt.
///
/// ```compile_fail
/// use chio_process::ClosedUnusedRecoveryReservation;
/// fn duplicate(role: ClosedUnusedRecoveryReservation<'_>) { let _ = role.clone(); }
/// ```
///
/// ```compile_fail
/// use chio_process::ClosedUnusedRecoveryReservation;
/// let _: Result<ClosedUnusedRecoveryReservation<'_>, _> = serde_json::from_str("{}");
/// ```
pub struct ClosedUnusedRecoveryReservation<'runtime> {
    runtime: &'runtime ProcessRuntime,
    data: UnusedRecoveryReservationClosureData,
}

impl ClosedUnusedRecoveryReservation<'_> {
    /// Identity data only. Native closure must independently prove its history
    /// and consume the actual role rather than accepting this described value.
    pub fn reservation(&self) -> &RecoveryCallReservation {
        self.data.reservation()
    }

    pub fn runtime_id(&self) -> &str {
        self.runtime.runtime_id()
    }

    /// Reverify the immutable marker and all original Process custody through
    /// the same actual runtime. This grants no native admission or refund.
    pub fn verify_for(
        &self,
        expected: &RecoveryCallReservation,
        authority_domain: &str,
    ) -> Result<(), ProcessError> {
        self.runtime.verify_unused_reservation_host(expected)?;
        if self.reservation() != expected
            || self.data.authority_domain() != authority_domain
            || self.runtime.kernel.durable_admission_store_uuid() != Some(authority_domain)
            || self.data.kernel_key() != self.runtime.kernel.public_key().to_hex()
        {
            return Err(ProcessError::Conflict);
        }
        self.runtime
            .with_store(|store| store.verify_unused_recovery_reservation_closure(&self.data))
    }

    /// Historical data may be persisted only after the native consumer has
    /// checked its own no-future history and retained this actual role.
    pub fn historical_data(&self) -> &UnusedRecoveryReservationClosureData {
        &self.data
    }

    pub fn into_historical_data(self) -> UnusedRecoveryReservationClosureData {
        self.data
    }
}

impl core::fmt::Debug for ClosedUnusedRecoveryReservation<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ClosedUnusedRecoveryReservation([redacted])")
    }
}

impl ProcessRuntime {
    /// The committed Process writer must permanently prevent future admission.
    /// Closure preserves the reservation and its original logical debit.
    pub fn close_unused_recovery_reservation(
        &self,
        reservation: &RecoveryCallReservation,
    ) -> Result<ClosedUnusedRecoveryReservation<'_>, ProcessError> {
        self.verify_unused_reservation_host(reservation)?;
        let authority =
            self.kernel
                .durable_admission_store_uuid()
                .ok_or(ProcessError::Configuration(
                    "unused recovery closure lacks its native authority",
                ))?;
        let key = self.kernel.public_key().to_hex();
        let data = self.with_store(|store| {
            store.close_unused_recovery_reservation((authority, &key), reservation)
        })?;
        let role = ClosedUnusedRecoveryReservation {
            runtime: self,
            data,
        };
        role.verify_for(reservation, authority)?;
        Ok(role)
    }

    fn verify_unused_reservation_host(
        &self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        if reservation.runtime_id != self.namespace
            || reservation.request_id
                != self.request_id(&reservation.process_id, &reservation.operation_key)?
            || reservation.host_binding != self.recovery_host_binding(&reservation.server_id)?
        {
            return Err(ProcessError::Conflict);
        }
        Ok(())
    }
}
