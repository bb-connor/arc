use super::*;

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        if operation.binding().participant_requirements().channel {
            return Err(invariant(
                "channel operations require the atomic channel prepared begin",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        let encoded =
            match begin_prepared_operation_tx(&transaction, operation, fence, trusted_now_unix_ms)?
            {
                PreparedAdmissionBeginTxResult::Created { encoded } => encoded,
                PreparedAdmissionBeginTxResult::ExactReplay {
                    operation,
                    terminal_replay,
                } => {
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(AdmissionBeginResult::ExactReplay {
                        operation: *operation,
                        terminal_replay,
                    });
                }
                PreparedAdmissionBeginTxResult::Conflict {
                    existing_operation_id,
                } => {
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(AdmissionBeginResult::Conflict {
                        existing_operation_id,
                    });
                }
            };
        append_operation_commit(
            &transaction,
            operation,
            &encoded,
            None,
            "begin",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionBeginResult::Created(operation.clone()))
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation =
            load_by_operation_id_tx(&transaction, operation_id)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation = load_by_replay_key_tx(&transaction, replay_key)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let fence = command.recovery_lease().store_fence();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let result = self.apply_in_transaction(&transaction, command, trusted_now_unix_ms)?;
        if matches!(result, AdmissionCommandResult::Idempotent(_)) {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(result)
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        let request = RecoveryClaimRequest {
            operation_id,
            expected_version,
            claimant_id,
            expires_at_unix_ms,
            fence,
        };
        validate_claim_request(&request, trusted_now_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        match self.claim_in_transaction(&transaction, &stored, request, trusted_now_unix_ms)? {
            ClaimWrite::Active(active) => {
                transaction.commit().map_err(sqlite_error)?;
                Ok(active)
            }
            ClaimWrite::Written(claim) => {
                self.commit_write(transaction)?;
                self.sync_after_write(&connection)?;
                Ok(claim)
            }
        }
    }

    /// One durable write carries the claim and the command it authorizes. The
    /// command is verified against the claim row as persisted in this
    /// transaction, exactly as a separately committed claim would be, and a
    /// refused command or a fenced mutation rolls the claim back with it.
    fn claim_and_compare_and_swap(
        &self,
        request: RecoveryClaimRequest<'_>,
        trusted_now_unix_ms: u64,
        command: &mut ClaimedCommand<'_>,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        validate_claim_request(&request, trusted_now_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(request.fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, request.operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        let (ClaimWrite::Active(claim) | ClaimWrite::Written(claim)) =
            self.claim_in_transaction(&transaction, &stored, request, trusted_now_unix_ms)?;
        let command = command(&stored.operation, claim)?;
        let result = self.apply_in_transaction(&transaction, &command, trusted_now_unix_ms)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(result)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(current_store_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, claim.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation != *operation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            claim,
            trusted_now_unix_ms,
            current_store_fence,
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        if limit > MAX_RECOVERY_BATCH {
            return Err(invariant("recovery batch limit exceeds 256"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT operation_id, request_namespace_digest, request_id,
                       operation_json, state, terminal, coordinator_lease_epoch,
                       version, created_at_unix_ms, updated_at_unix_ms,
                       recovery_claimant_id, recovery_coordinator_lease_id,
                       recovery_coordinator_lease_epoch, recovery_claimed_version,
                       recovery_expires_at_unix_ms, recovery_store_uuid,
                       recovery_store_lease_id, recovery_store_owner_epoch
                FROM admission_operations
                WHERE terminal = 0
                  AND state <> 'approval_required'
                  AND (recovery_expires_at_unix_ms IS NULL
                       OR recovery_expires_at_unix_ms <= ?1
                       OR recovery_store_uuid <> ?2
                       OR recovery_store_lease_id <> ?3
                       OR recovery_store_owner_epoch <> ?4)
                ORDER BY updated_at_unix_ms, operation_id
                LIMIT ?5
                "#,
            )
            .map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                sqlite_i64(not_after_unix_ms, "not_after_unix_ms")?,
                &self.serving_owner.fence.store_uuid,
                &self.serving_owner.fence.lease_id,
                sqlite_i64(self.serving_owner.fence.owner_epoch, "store_owner_epoch")?,
                i64::try_from(limit).map_err(|_| invariant("recovery limit overflow"))?,
            ])
            .map_err(sqlite_error)?;
        let mut operations = Vec::with_capacity(limit);
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
            verify_latest_commit(&transaction, &stored)?;
            operations.push(stored.operation);
        }
        drop(rows);
        drop(statement);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operations)
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let replay = load_by_replay_key_tx(&transaction, replay_key)?
            .and_then(|stored| stored.operation.terminal_replay().cloned());
        transaction.commit().map_err(sqlite_error)?;
        Ok(replay)
    }
}

/// Outcome of persisting a recovery claim inside a write transaction.
pub(super) enum ClaimWrite {
    /// The stored claim already authorizes this claimant; nothing was written.
    Active(UntrustedAdmissionRecoveryClaim),
    /// The claim row was written and its commit appended.
    Written(UntrustedAdmissionRecoveryClaim),
}

impl ClaimWrite {
    pub(super) fn into_claim(self) -> UntrustedAdmissionRecoveryClaim {
        match self {
            Self::Active(claim) | Self::Written(claim) => claim,
        }
    }
}

/// Persist a recovery claim for the operation as stored in this transaction
/// and qualify it through `lease`, so a joint transaction in any store on
/// this database can claim and mutate in one durable write. The claim row is
/// re-read by the mutation's own verification, exactly as a separately
/// committed claim would be.
pub(crate) fn claim_lease_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    request: RecoveryClaimRequest<'_>,
    trusted_now_unix_ms: u64,
    lease: &mut ClaimedLease<'_>,
) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError> {
    validate_claim_request(&request, trusted_now_unix_ms)?;
    let stored = load_by_operation_id_tx(transaction, request.operation_id)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let claim =
        claim_recovery_tx(transaction, owner, &stored, request, trusted_now_unix_ms)?.into_claim();
    lease(&stored.operation, claim)
}

pub(super) fn validate_claim_request(
    request: &RecoveryClaimRequest<'_>,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_time(trusted_now_unix_ms, "trusted_now_unix_ms")?;
    validate_trusted_time(request.expires_at_unix_ms, "expires_at_unix_ms")?;
    if request.expected_version == 0 {
        return Err(AdmissionOperationError::ZeroVersionOrEpoch.into());
    }
    if trusted_now_unix_ms >= request.expires_at_unix_ms {
        return Err(AdmissionOperationError::LeaseExpired.into());
    }
    if request.expires_at_unix_ms - trusted_now_unix_ms > MAX_RECOVERY_LEASE_DURATION_MS {
        return Err(invariant("recovery lease exceeds its maximum duration"));
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    fn claim_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        stored: &StoredOperation,
        request: RecoveryClaimRequest<'_>,
        trusted_now_unix_ms: u64,
    ) -> Result<ClaimWrite, AdmissionOperationStoreError> {
        claim_recovery_tx(
            transaction,
            &self.serving_owner,
            stored,
            request,
            trusted_now_unix_ms,
        )
    }
}

/// Persist a recovery claim for `stored`, or accept the compatible claim it
/// already carries, inside the caller's write transaction.
pub(super) fn claim_recovery_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    stored: &StoredOperation,
    request: RecoveryClaimRequest<'_>,
    trusted_now_unix_ms: u64,
) -> Result<ClaimWrite, AdmissionOperationStoreError> {
    {
        let RecoveryClaimRequest {
            operation_id,
            expected_version,
            claimant_id,
            expires_at_unix_ms,
            fence,
        } = request;
        if stored.operation.state().is_terminal() {
            return Err(invariant("terminal operation cannot be recovery-claimed"));
        }
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        if stored.operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: stored.operation.version(),
            }
            .into());
        }
        if crate::economic_state_cache::has_reserved_terminal_stage(
            transaction,
            operation_id.as_str(),
        )
        .map_err(map_economic_cache_error)?
        {
            if let Some(active) = stored.recovery_claim.as_ref().filter(|active| {
                active.expires_at_unix_ms() > trusted_now_unix_ms
                    && active.store_fence() == fence
                    && active.claimant_id() == claimant_id
                    && active.claimed_version() == expected_version
            }) {
                return Ok(ClaimWrite::Active(active.clone()));
            }
            return Err(AdmissionOperationStoreError::Fenced);
        }

        let coordinator_lease_id = coordinator_lease_id_for_epoch(
            transaction,
            owner,
            stored.operation.coordinator_lease_epoch(),
        )?;
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            coordinator_lease_id,
            stored.operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        if let Some(active) = stored
            .recovery_claim
            .as_ref()
            .filter(|active| active.expires_at_unix_ms() > trusted_now_unix_ms)
        {
            if active.store_fence() == fence {
                let same_claimant = active.claimant_id() == claimant_id
                    && active.coordinator_lease_id() == claim.coordinator_lease_id()
                    && active.coordinator_lease_epoch() == claim.coordinator_lease_epoch();
                if same_claimant && active.claimed_version() == expected_version {
                    return Ok(ClaimWrite::Active(active.clone()));
                }
                if !same_claimant || active.claimed_version() >= expected_version {
                    return Err(AdmissionOperationStoreError::Fenced);
                }
            }
        }

        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET recovery_claimant_id = ?1,
                    recovery_coordinator_lease_id = ?2,
                    recovery_coordinator_lease_epoch = ?3,
                    recovery_claimed_version = ?4,
                    recovery_expires_at_unix_ms = ?5,
                    recovery_store_uuid = ?6,
                    recovery_store_lease_id = ?7,
                    recovery_store_owner_epoch = ?8,
                    updated_at_unix_ms = ?9
                WHERE operation_id = ?10 AND version = ?4 AND terminal = 0
                "#,
                params![
                    claimant_id.as_str(),
                    claim.coordinator_lease_id().as_str(),
                    sqlite_i64(claim.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(expected_version, "claimed_version")?,
                    sqlite_i64(expires_at_unix_ms, "expires_at_unix_ms")?,
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    operation_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let encoded = encode_operation(&stored.operation)?;
        append_operation_commit(
            transaction,
            &stored.operation,
            &encoded,
            Some(&claim),
            "recovery_claim",
            owner,
            trusted_now_unix_ms,
        )?;
        Ok(ClaimWrite::Written(claim))
    }
}

impl SqliteAdmissionOperationStore {
    /// Verify the command against the operation and claim as stored in this
    /// transaction, then apply it. Appends the transition's commit; the caller
    /// commits.
    fn apply_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let fence = command.recovery_lease().store_fence();
        let stored = load_by_operation_id_tx(transaction, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        ensure_no_reserved_terminal_stage(transaction, command.operation_id())?;
        qualify_generic_channel_command(transaction, &stored.operation, command)?;
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        verify_stored_recovery_claim(
            transaction,
            &self.serving_owner,
            &stored,
            command.recovery_lease().untrusted_claim(),
            trusted_now_unix_ms,
            fence,
        )?;

        let result = stored
            .operation
            .apply_command(command, trusted_now_unix_ms)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            return Ok(result);
        };
        let encoded = encode_operation(&updated)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_json = ?1, state = ?2, terminal = ?3,
                    coordinator_lease_epoch = ?4, version = ?5,
                    updated_at_unix_ms = ?6
                WHERE operation_id = ?7 AND version = ?8
                "#,
                params![
                    encoded,
                    state_name(updated.state()),
                    i64::from(updated.state().is_terminal()),
                    sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(updated.version(), "version")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    updated.binding().operation_id().as_str(),
                    sqlite_i64(stored.operation.version(), "expected_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        append_operation_commit(
            transaction,
            &updated,
            &encoded,
            stored.recovery_claim.as_ref(),
            "compare_and_swap",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        Ok(AdmissionCommandResult::Applied(updated))
    }
}
