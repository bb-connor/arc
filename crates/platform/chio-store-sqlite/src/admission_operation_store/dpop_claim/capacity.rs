//! V2 occupancy is domain separated from the immutable legacy import. Expiry
//! frees live capacity, never spent identity or operation ownership history.
use super::*;

pub(super) fn require_available(
    connection: &Connection,
    source: &dpop_replay::DpopReplayMigrationRecordV1,
    operation: &AdmissionOperationV1,
    intent: &DpopReplayClaimIntentV1,
    observed: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let credential = intent.credential();
    let authority = credential.authority().dpop_authority_id().as_str();
    let occupied: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM dpop_replay_claim_resources AS resource
         WHERE dpop_authority_id = ?1 AND capability_id = ?2 AND nonce = ?3
           AND NOT EXISTS(SELECT 1 FROM dpop_replay_claim_releases AS released
             WHERE released.operation_id = resource.operation_id AND released.episode_id = resource.episode_id))",
        params![authority, credential.capability_id(), credential.nonce()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if occupied {
        return Err(invariant(
            "DPoP replay identity is already owned or historically spent",
        ));
    }
    let (live, per_capability, bytes): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(capability_id = ?2), 0),
          COALESCE(SUM(2 * length(CAST(capability_id AS BLOB)) + length(CAST(nonce AS BLOB))
            + length(CAST(operation_id AS BLOB)) + length(CAST(episode_id AS BLOB))), 0)
         FROM dpop_replay_claim_resources AS resource WHERE dpop_authority_id = ?1 AND valid_through >= ?3
           AND NOT EXISTS(SELECT 1 FROM dpop_replay_claim_releases AS released
             WHERE released.operation_id = resource.operation_id AND released.episode_id = resource.episode_id)",
        params![authority, credential.capability_id(), sqlite_i64(observed / 1000, "dpop_clock")?],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(sqlite_error)?;
    let limits = source
        .snapshot()
        .replay_capacity_limits()
        .map_err(|error| invariant(error.to_string()))?;
    // Logical live key/count-index and owner charge, not a whole-database bound.
    // Canonical history has separate per-record and per-operation limits.
    let charge = credential.capability_id().len() as u64 * 2
        + credential.nonce().len() as u64
        + operation.binding().operation_id().as_str().len() as u64
        + intent.episode_id().as_str().len() as u64;
    if stored_u64(live, "dpop_live_count")? >= limits.markers
        || stored_u64(per_capability, "dpop_capability_count")? >= limits.per_capability
        || stored_u64(bytes, "dpop_identity_bytes")?
            .checked_add(charge)
            .is_none_or(|total| total > limits.identity_bytes)
    {
        return Err(invariant(
            "DPoP replay count or identity-byte capacity exhausted",
        ));
    }
    Ok(())
}
