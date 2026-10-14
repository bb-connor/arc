use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;

/// Load limits from the committed original inside the reader's transaction.
/// Bounds are storage data, never a source of mutation or release authority.
pub(crate) fn original_output_read_bounds(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<(u64, u64)>, AdmissionOperationStoreError> {
    let operation_id = AdmissionOperationId::from_persisted(operation_id.to_owned())?;
    // Older dispatches have no retained request and a NULL begin participant.
    // Authenticate that literal absence before adding profile-specific reads;
    // it supplies no output bound and never supplies a financing purpose.
    let legacy_without_original: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM admission_operations AS operation
                 JOIN admission_operation_commits AS begin_commit
                   ON begin_commit.operation_id=operation.operation_id
                  AND begin_commit.mutation_kind='begin'
                  AND begin_commit.participant_digest IS NULL
                 WHERE operation.operation_id=?1
                   AND NOT EXISTS(SELECT 1 FROM admission_operation_tool_requests AS original
                                  WHERE original.operation_id=operation.operation_id))",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if legacy_without_original {
        return Ok(None);
    }
    let Some(stored) = load_output_bound_owner(connection, &operation_id)? else {
        let has_outcome: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tool_outcomes WHERE operation_id=?1
                 UNION ALL SELECT 1 FROM post_return_evaluations WHERE operation_id=?1)",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        return if has_outcome {
            Err(invariant("stored outcome has no owning original operation"))
        } else {
            Ok(None)
        };
    };
    let original = load_retained_request_tx(connection, &stored.operation)?;
    Ok(original.and_then(|original| {
        original
            .native_output_retention()
            .map(|profile| (profile.envelopes().raw(), profile.envelopes().evaluation()))
    }))
}

/// Authenticate only the immutable binding/current canonical row and its commit
/// before reading the original envelope. Full native/terminal verification is
/// the caller's responsibility and itself reads Raw/evaluation bytes; invoking
/// it here would reenter the output loader being verified. This private leaf
/// returns no recovery, capture, release or writer authority.
fn load_output_bound_owner(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = connection
        .query_row(
            "SELECT operation_id, request_namespace_digest, request_id,
                CASE WHEN length(operation_json) BETWEEN 1 AND 262144
                     THEN operation_json ELSE zeroblob(0) END,
                state, terminal, coordinator_lease_epoch, version,
                created_at_unix_ms, updated_at_unix_ms,
                recovery_claimant_id, recovery_coordinator_lease_id,
                recovery_coordinator_lease_epoch, recovery_claimed_version,
                recovery_expires_at_unix_ms, recovery_store_uuid,
                recovery_store_lease_id, recovery_store_owner_epoch
         FROM main.admission_operations WHERE operation_id=?1",
            [operation_id.as_str()],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(connection, stored)?;
    }
    Ok(stored)
}

pub(super) fn verify_retained_request_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM admission_operation_tool_requests AS request
                WHERE NOT EXISTS (
                    SELECT 1 FROM admission_operations AS operation
                    WHERE operation.operation_id = request.operation_id
                )
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "retained tool request has no owning admission operation",
        ));
    }
    Ok(())
}

/// Resolve retained original material within an already fenced transaction.
/// Ambiguous request IDs fail closed across every admission namespace.
pub(super) fn load_unambiguous_original_request_tx(
    transaction: &Transaction<'_>,
    request_id: &AdmissionIdentifier,
    trusted_now_unix_ms: u64,
) -> Result<
    Option<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)>,
    AdmissionOperationStoreError,
> {
    let identifiers = {
        let mut statement = transaction
            .prepare(
                "SELECT operation_id FROM admission_operations
             WHERE request_id = ?1 ORDER BY operation_id LIMIT 2",
            )
            .map_err(sqlite_error)?;
        let identifiers = statement
            .query_map([request_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        identifiers
    };
    let operation_id = match identifiers.as_slice() {
        [] => {
            return Ok(None);
        }
        [operation_id] => AdmissionOperationId::from_persisted(operation_id.clone())?,
        _ => {
            return Err(invariant(
                "original request ID is ambiguous across admission operations",
            ))
        }
    };
    let stored = load_by_operation_id_tx(transaction, &operation_id)?
        .ok_or_else(|| invariant("selected original request operation disappeared"))?;
    stored.verify_decision_time(trusted_now_unix_ms)?;
    if stored.operation.binding().request_id() != request_id {
        return Err(invariant(
            "original request selector does not match its operation",
        ));
    }
    let retained = load_retained_request_tx(transaction, &stored.operation)?;
    Ok(retained.map(|request| (stored.operation, request)))
}

impl SqliteAdmissionOperationStore {
    pub(super) fn load_unambiguous_original_request(
        &self,
        request_id: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)>,
        AdmissionOperationStoreError,
    > {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let result =
            load_unambiguous_original_request_tx(&transaction, request_id, trusted_now_unix_ms)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(result)
    }

    pub(super) fn begin_retaining_tool_request(
        &self,
        operation: &AdmissionOperationV1,
        request: Option<&RetainedToolAdmissionRequestV1>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        if operation.binding().participant_requirements().channel {
            return Err(invariant(
                "channel operations require the atomic channel prepared begin",
            ));
        }
        if let Some(request) = request {
            request.validate_binding(operation.binding())?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        let recovery_begin =
            super::recovery::prepare_begin_tx(&transaction, operation, trusted_now_unix_ms)?;
        let encoded =
            match begin_prepared_operation_tx(&transaction, operation, fence, trusted_now_unix_ms)?
            {
                PreparedAdmissionBeginTxResult::Created { encoded } => encoded,
                PreparedAdmissionBeginTxResult::ExactReplay {
                    operation,
                    terminal_replay,
                } => {
                    let retained = load_retained_request_tx(&transaction, &operation)?;
                    if let Some(request) = request {
                        if retained.as_ref().is_none_or(|retained| {
                            retained.canonical_bytes() != request.canonical_bytes()
                        }) {
                            return Err(invariant(
                                "original tool request replay is missing or changed",
                            ));
                        }
                    }
                    let published = super::recovery::publish_begin_tx(
                        &transaction,
                        &self.serving_owner,
                        recovery_begin,
                    )?;
                    if published {
                        self.commit_write(transaction)?;
                        self.sync_after_write(&connection)?;
                    } else {
                        transaction.commit().map_err(sqlite_error)?;
                    }
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
        let participant_digest = if let Some(request) = request {
            transaction
                .execute(
                    "INSERT INTO admission_operation_tool_requests (operation_id, request_json)
                     VALUES (?1, ?2)",
                    params![
                        operation.binding().operation_id().as_str(),
                        request.canonical_bytes()
                    ],
                )
                .map_err(sqlite_error)?;
            Some(sha256_hex(request.canonical_bytes()))
        } else {
            None
        };
        append_operation_commit_with_participant(
            &transaction,
            operation,
            &encoded,
            None,
            "begin",
            participant_digest.as_deref(),
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        super::recovery::publish_begin_tx(&transaction, &self.serving_owner, recovery_begin)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionBeginResult::Created(operation.clone()))
    }
}

/// The begin participant digest is immutable even as the operation progresses.
/// Missing material is allowed only for legacy operations with no such digest.
pub(super) fn load_retained_request_tx(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<RetainedToolAdmissionRequestV1>, AdmissionOperationStoreError> {
    let operation_id = operation.binding().operation_id().as_str();
    // Check SQLite's length before allocating an untrusted BLOB into Rust memory.
    let row: Option<(i64, Option<Vec<u8>>)> = connection
        .query_row(
            r#"
            SELECT length(request_json),
                   CASE WHEN length(request_json) BETWEEN 1 AND 262144
                        THEN request_json END
            FROM admission_operation_tool_requests WHERE operation_id = ?1
            "#,
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.binding().participant_requirements().channel
    {
        return if row.is_some() {
            Err(invariant(
                "retained tool request belongs to an incompatible operation",
            ))
        } else {
            Ok(None)
        };
    }
    let committed_digest: Option<String> = connection
        .query_row(
            "SELECT participant_digest FROM admission_operation_commits
             WHERE operation_id = ?1 AND mutation_kind = 'begin'",
            [operation_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let Some((_length, encoded)) = row else {
        return if committed_digest.is_some() {
            Err(invariant("committed original tool request is missing"))
        } else {
            Ok(None)
        };
    };
    let encoded =
        encoded.ok_or_else(|| invariant("retained tool request exceeds its artifact bound"))?;
    if committed_digest.as_deref() != Some(sha256_hex(&encoded).as_str()) {
        return Err(invariant(
            "retained tool request does not match its begin commit",
        ));
    }
    let request = RetainedToolAdmissionRequestV1::from_canonical_bytes(&encoded)?;
    request.validate_binding(operation.binding())?;
    Ok(Some(request))
}
