//! Activate the serving owner's factor-assignment authority set.

use super::*;

impl SqliteAdmissionOperationStore {
    pub fn factor_assignment_authority_set_head(
        &self,
    ) -> Result<Option<FactorAssignmentAuthoritySetHeadV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let head = transaction
            .query_row(
                r#"
                SELECT generation, active_set_digest
                FROM factor_assignment_authority_sets
                ORDER BY generation DESC
                LIMIT 1
                "#,
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?
            .map(|(generation, digest)| {
                Ok::<_, AdmissionOperationStoreError>(FactorAssignmentAuthoritySetHeadV1 {
                    generation: stored_u64(generation, "factor_authority_set_generation")?,
                    digest,
                })
            })
            .transpose()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(head)
    }

    pub fn activate_factor_assignment_authorities(
        &self,
        authorities: FactorAssignmentAuthorityRegistryV1,
        expected_generation: u64,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<SqliteFactorAssignmentStore, AdmissionOperationStoreError> {
        let active_set_digest = authorities.active_set_digest().to_owned();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
        let current = transaction
            .query_row(
                r#"
                SELECT generation, active_set_digest
                FROM factor_assignment_authority_sets
                ORDER BY generation DESC
                LIMIT 1
                "#,
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let current_generation = current
            .as_ref()
            .map(|(generation, _)| stored_u64(*generation, "factor_authority_set_generation"))
            .transpose()?
            .unwrap_or(0);
        if current_generation != expected_generation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let generation = if current
            .as_ref()
            .is_some_and(|(_, digest)| digest == &active_set_digest)
        {
            current_generation
        } else {
            let generation = current_generation
                .checked_add(1)
                .ok_or_else(|| invariant("factor authority set generation overflow"))?;
            let previous_digest = current.as_ref().map(|(_, digest)| digest.as_str());
            transaction
                .execute(
                    r#"
                    INSERT INTO factor_assignment_authority_sets (
                        generation, active_set_digest, previous_active_set_digest,
                        activated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    "#,
                    params![
                        sqlite_i64(generation, "factor_authority_set_generation")?,
                        &active_set_digest,
                        previous_digest,
                        sqlite_i64(trusted_now_unix_ms, "factor_authority_set_activated_at")?,
                        &active_fence.store_uuid,
                        &active_fence.lease_id,
                        sqlite_i64(active_fence.owner_epoch, "factor_authority_set_owner_epoch")?,
                    ],
                )
                .map_err(factor_sqlite_error)?;
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    "factor_assignment_authority_set",
                    "factor_assignment_authority_set",
                    "active",
                    generation,
                )
                .map_err(map_owner_error)?;
            generation
        };
        self.commit_write(transaction)?;
        if generation != current_generation {
            self.sync_after_write(&connection)?;
        }
        Ok(SqliteFactorAssignmentStore {
            store: self.clone(),
            authorities: Arc::new(authorities),
            authority_set_generation: generation,
        })
    }
}
