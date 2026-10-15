use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use chio_kernel::dpop::authority::{DpopReplayAuthority, DpopReplayAuthorityInput};
use chio_kernel::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use chio_kernel::dpop::{DpopConfig, DpopNonceStore};
use chio_security_types::clock::{Clock, ClockReading};
use chio_store_sqlite::SqliteAuthorityStore;
use std::sync::Arc;

use crate::CliError;

/// Read an existing active authority selected by trusted deployment configuration.
pub fn load_local_dpop_authority(
    store: &SqliteAuthorityStore,
    authority_id: &AdmissionIdentifier,
    now: ClockReading,
) -> Result<DpopReplayAuthority, CliError> {
    let operations = store.admission_operation_store();
    let fence = store.mutation_fence();
    let record = operations
        .load_dpop_replay_migration(authority_id, &fence, now.unix_millis().get())
        .map_err(failure)?
        .ok_or_else(|| failure("DPoP authority is not registered"))?;
    let authority = record
        .authority()
        .filter(|_| record.is_active())
        .ok_or_else(|| failure("DPoP authority is not activated"))?;
    operations
        .load_dpop_replay_activation(authority, &fence, now.unix_millis().get())
        .map_err(failure)
}

/// Provision a new replay authority during explicit deployment initialization.
/// An existing record must already be active with the exact requested policy.
pub fn initialize_local_dpop_authority(
    store: &SqliteAuthorityStore,
    authority_id: &AdmissionIdentifier,
    policy: &DpopConfig,
    clock: Arc<dyn Clock>,
) -> Result<DpopReplayAuthority, CliError> {
    use chio_kernel::dpop::authority::{
        MAX_DURABLE_DPOP_CLOCK_SKEW_SECS, MAX_DURABLE_DPOP_TTL_SECS,
    };
    if !(1..=MAX_DURABLE_DPOP_TTL_SECS).contains(&policy.proof_ttl_secs)
        || policy.max_clock_skew_secs > MAX_DURABLE_DPOP_CLOCK_SKEW_SECS
    {
        return Err(failure("DPoP freshness policy exceeds its bounds"));
    }
    let operations = store.admission_operation_store();
    let fence = store.mutation_fence();
    let now = clock.read()?;
    let now_ms = now.unix_millis().get();
    if operations
        .load_dpop_replay_migration(authority_id, &fence, now_ms)
        .map_err(failure)?
        .is_some()
    {
        let authority = load_local_dpop_authority(store, authority_id, now)?;
        if authority.proof_ttl_secs() != policy.proof_ttl_secs
            || authority.max_clock_skew_secs() != policy.max_clock_skew_secs
        {
            return Err(failure("DPoP authority freshness policy does not match"));
        }
        return Ok(authority);
    }
    let source = DpopNonceStore::with_clock(
        policy.nonce_store_capacity,
        policy.nonce_store_capacity,
        chio_kernel::dpop::DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
        std::time::Duration::from_secs(policy.proof_ttl_secs),
        clock,
    )
    .map_err(failure)?;
    let destination =
        AdmissionIdentifier::try_new("destination", &fence.store_uuid).map_err(failure)?;
    let snapshot = source
        .preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: authority_id.clone(),
            destination_authority_id: destination.clone(),
        })
        .map_err(failure)?;
    let instance =
        AdmissionIdentifier::try_new("instance", snapshot.instance_id()).map_err(failure)?;
    let expected = operations
        .expect_dpop_replay_source(&instance, authority_id, &source, &fence, now_ms)
        .map_err(failure)?;
    operations
        .import_dpop_replay_source(
            authority_id,
            expected.expectation_id(),
            &source,
            &fence,
            now_ms,
        )
        .map_err(failure)?;
    let authority = DpopReplayAuthority::new(DpopReplayAuthorityInput {
        destination_store_uuid: destination,
        dpop_authority_id: authority_id.clone(),
        expectation_id: AdmissionDigest::try_new("expectation", expected.expectation_id().as_str())
            .map_err(failure)?,
        proof_ttl_secs: policy.proof_ttl_secs,
        max_clock_skew_secs: policy.max_clock_skew_secs,
    })
    .map_err(failure)?;
    operations
        .activate_dpop_replay_source(&authority, &source, &fence, now_ms)
        .map_err(failure)?;
    load_local_dpop_authority(store, authority_id, now)
}

fn failure(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(error.to_string())
}

#[cfg(test)]
#[path = "dpop_runtime/tests.rs"]
mod tests;
