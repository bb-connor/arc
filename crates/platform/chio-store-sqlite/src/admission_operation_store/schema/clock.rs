//! Decision time is part of the signed evidence, not a global commit clock.
//!
//! Independent kernels can arrive out of timestamp order. Observe authority
//! time only after acquiring the transaction, compare that clock to durable
//! history, and never rewrite a caller's evidence to impose a total order.

use super::*;

pub(crate) fn verify_trusted_time(
    transaction: &Transaction<'_>,
    decision_time: u64,
) -> Result<(), AdmissionOperationStoreError> {
    authority_validation_time(transaction, decision_time).map(|_| ())
}

/// Time for live authorization checks, not for serialized decision evidence.
/// Neither a delayed request nor a caller clock ahead of this authority may
/// extend the lifetime of a lease, nonce, approval, or other expiring authority.
pub(in crate::admission_operation_store) fn authority_validation_time(
    transaction: &Transaction<'_>,
    decision_time: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    validate_trusted_time(decision_time, "trusted_now_unix_ms")?;
    let observed = observe_authority_time(transaction)?;
    if decision_time.abs_diff(observed) > MAX_TRUSTED_CLOCK_SKEW_MS {
        return Err(invariant(
            "trusted_now_unix_ms exceeds the permitted system-clock skew",
        ));
    }
    Ok(decision_time.max(observed))
}

pub(in crate::admission_operation_store) fn observe_authority_time(
    transaction: &Transaction<'_>,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = match chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        Some(fixed) => fixed
            .checked_mul(1_000)
            .ok_or_else(|| invariant("authority clock exceeds the persisted trusted-time range"))?,
        None => {
            let elapsed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invariant("system clock precedes the Unix epoch"))?;
            u64::try_from(elapsed.as_millis()).map_err(|_| {
                invariant("authority clock exceeds the persisted trusted-time range")
            })?
        }
    };
    validate_trusted_time(observed, "observed_at_unix_ms")?;
    let high_water: i64 = transaction
        .query_row(
            "SELECT trusted_time_high_water_unix_ms FROM admission_operation_commit_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if observed < stored_u64(high_water, "trusted_time_high_water_unix_ms")? {
        return Err(invariant("trusted admission authority time regressed"));
    }
    Ok(observed)
}
