//! Historical operation-lease evidence shared by native journal families.
//! Verification reconstructs the original claim; it grants no current lease.
use super::*;

impl LeaseHistory {
    pub(in crate::admission_operation_store::security_participant_state) fn validate_operation(
        &self,
        connection: &Connection,
        operation: &AdmissionOperationV1,
        observed_at: u64,
        decision_at: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        super::super::super::schema::validate_trusted_time(observed_at, "native observation time")?;
        super::super::super::schema::validate_trusted_time(decision_at, "native decision time")?;
        if observed_at.abs_diff(decision_at) > MAX_TRUSTED_CLOCK_SKEW_MS {
            return Err(invalid("native decision and observation clocks differ"));
        }
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation.binding().operation_id().clone(),
            self.claimant.clone(),
            self.lease_id.clone(),
            operation.coordinator_lease_epoch(),
            operation.version(),
            self.expires_at,
            self.fence.clone(),
        )?;
        if observed_at.max(decision_at) >= claim.expires_at_unix_ms() {
            return Err(invalid("native mutation used an expired lease"));
        }
        let qualified: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operation_commits
             WHERE operation_id = ?1 AND operation_version = ?2 AND operation_digest = ?3
               AND recovery_claim_digest = ?4 AND store_uuid = ?5 AND store_lease_id = ?6
               AND store_owner_epoch = ?7 AND recorded_at_unix_ms <= ?8
               AND COALESCE(observed_at_unix_ms, recorded_at_unix_ms) <= ?9)",
                params![
                    operation.binding().operation_id().as_str(),
                    i64::try_from(operation.version()).map_err(invalid)?,
                    sha256_hex(&encode_operation(operation)?),
                    recovery_claim_digest(&claim)?,
                    claim.store_fence().store_uuid,
                    claim.store_fence().lease_id,
                    i64::try_from(claim.store_fence().owner_epoch).map_err(invalid)?,
                    i64::try_from(decision_at).map_err(invalid)?,
                    i64::try_from(observed_at).map_err(invalid)?
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !qualified {
            return Err(invalid(
                "native mutation lacks its historical operation lease commit",
            ));
        }
        Ok(())
    }
}
