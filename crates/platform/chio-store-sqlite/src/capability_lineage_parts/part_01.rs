use chio_core::capability::token::CapabilityToken;
use chio_core::sha256;
pub use chio_kernel::capability_lineage::{
    CapabilityLineageError, CapabilitySnapshot, StoredCapabilitySnapshot,
};
use chio_security_types::ports::{
    response_affected_set_hash, ActionId, CausalLineageCommitMetadata, CausalLineageCommitRequest,
    CausalLineageCommitStore, CausalLineageEdge, CausalLineageEdgeKind, CausalLineageEdges,
    CausalLineageFenceRequest, CausalLineageFenceStore, CausalLineageNode, CausalLineageNodeKind,
    CausalLineageNodes, CausalLineageSnapshot, CausalLineageSnapshotRequest, CausalLineageStore,
    Digest32, LeaseOwnerId, LineageFence, LineageFenceRelease, LineageFenceRenewal,
    LineageFenceRequest, LineageFenceStore, LineageFenceTakeover, LineageId, PortError, PortResult,
    RecordId, RecordIdSet, TenantId, TenantScopedId,
};
use rusqlite::types::Type;
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::receipt_store::SqliteReceiptStore;

const CAUSAL_LINEAGE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS causal_lineage_heads (
    tenant_id TEXT PRIMARY KEY,
    source_lineage_version INTEGER NOT NULL,
    observed_commit_index INTEGER NOT NULL,
    authoritative_commit_index INTEGER NOT NULL,
    completeness_watermark INTEGER
);
CREATE TABLE IF NOT EXISTS causal_lineage_nodes (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    node_kind TEXT NOT NULL,
    first_commit_index INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_causal_lineage_nodes_commit
    ON causal_lineage_nodes(tenant_id, first_commit_index, node_id);
CREATE TABLE IF NOT EXISTS causal_lineage_edges (
    tenant_id TEXT NOT NULL,
    parent_id TEXT NOT NULL,
    child_id TEXT NOT NULL,
    edge_kind TEXT NOT NULL,
    first_commit_index INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, parent_id, child_id, edge_kind)
);
CREATE INDEX IF NOT EXISTS idx_causal_lineage_edges_parent
    ON causal_lineage_edges(parent_id, first_commit_index, tenant_id, child_id);
CREATE TABLE IF NOT EXISTS causal_lineage_fence_sequences (
    tenant_id TEXT PRIMARY KEY,
    last_fencing_token INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS causal_lineage_fences (
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    fence_id TEXT NOT NULL,
    commit_index INTEGER NOT NULL,
    affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
    fencing_token INTEGER NOT NULL,
    scheduler_lease_owner_id TEXT NOT NULL,
    scheduler_fencing_token INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    PRIMARY KEY (tenant_id, action_id),
    UNIQUE (tenant_id, fence_id)
);
CREATE TABLE IF NOT EXISTS causal_lineage_fence_targets (
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, action_id, target_id),
    FOREIGN KEY (tenant_id, action_id)
        REFERENCES causal_lineage_fences(tenant_id, action_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_causal_lineage_active_fence_targets
    ON causal_lineage_fence_targets(tenant_id, target_id, action_id);
CREATE TABLE IF NOT EXISTS capability_lineage_admissions (
    capability_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    lineage_root_id TEXT NOT NULL,
    parent_capability_id TEXT,
    operation TEXT NOT NULL CHECK (operation IN ('issue', 'delegate'))
);
CREATE INDEX IF NOT EXISTS idx_capability_lineage_admission_context
    ON capability_lineage_admissions(tenant_id, lineage_root_id, capability_id);
CREATE TABLE IF NOT EXISTS capability_issuance_operations (
    request_nonce TEXT PRIMARY KEY NOT NULL,
    request_digest TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    lineage_root_id TEXT NOT NULL,
    intent_bytes BLOB NOT NULL,
    authorization_bytes BLOB,
    capability_id TEXT,
    response_bytes BLOB,
    recorded_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    aborted_at INTEGER,
    abort_reason TEXT
);
CREATE TABLE IF NOT EXISTS capability_session_admissions (
    admission_nonce TEXT PRIMARY KEY NOT NULL,
    operation_nonce TEXT NOT NULL,
    admission_digest TEXT NOT NULL,
    binding_bytes BLOB NOT NULL,
    recorded_at INTEGER NOT NULL
);
"#;

pub(crate) fn ensure_causal_lineage_schema(
    connection: &mut Connection,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    connection.execute_batch(CAUSAL_LINEAGE_SCHEMA)?;
    let mut statement = connection.prepare("PRAGMA table_info(causal_lineage_fences)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    drop(statement);
    if !columns.contains("scheduler_lease_owner_id") {
        connection.execute(
            "ALTER TABLE causal_lineage_fences ADD COLUMN scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !columns.contains("scheduler_fencing_token") {
        connection.execute(
            "ALTER TABLE causal_lineage_fences ADD COLUMN scheduler_fencing_token INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    let mut statement = connection.prepare("PRAGMA table_info(capability_session_admissions)")?;
    let admission_columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    drop(statement);
    if !admission_columns.contains("operation_nonce") {
        connection.execute(
            "ALTER TABLE capability_session_admissions ADD COLUMN operation_nonce TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    let mut statement = connection.prepare("PRAGMA table_info(capability_issuance_operations)")?;
    let operation_columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    drop(statement);
    if !operation_columns.contains("expires_at") {
        connection.execute(
            "ALTER TABLE capability_issuance_operations ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !operation_columns.contains("authorization_bytes") {
        connection.execute(
            "ALTER TABLE capability_issuance_operations ADD COLUMN authorization_bytes BLOB",
            [],
        )?;
    }
    if !operation_columns.contains("aborted_at") {
        connection.execute(
            "ALTER TABLE capability_issuance_operations ADD COLUMN aborted_at INTEGER",
            [],
        )?;
    }
    if !operation_columns.contains("abort_reason") {
        connection.execute(
            "ALTER TABLE capability_issuance_operations ADD COLUMN abort_reason TEXT",
            [],
        )?;
    }
    Ok(())
}

fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
    Ok(CapabilitySnapshot {
        capability_id: row.get::<_, String>(0)?,
        subject_key: row.get::<_, String>(1)?,
        issuer_key: row.get::<_, String>(2)?,
        issued_at: non_negative_u64_from_column(row, 3, "issued_at")?,
        expires_at: non_negative_u64_from_column(row, 4, "expires_at")?,
        grants_json: row.get::<_, String>(5)?,
        delegation_depth: non_negative_u64_from_column(row, 6, "delegation_depth")?,
        parent_capability_id: row.get::<_, Option<String>>(7)?,
    })
}

fn non_negative_u64_from_column(
    row: &Row<'_>,
    column: usize,
    field_name: &'static str,
) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(column)?;
    if value < 0 {
        return Err(negative_lineage_integer_error(column, field_name, value));
    }
    Ok(value as u64)
}

fn negative_lineage_integer_error(
    column: usize,
    field_name: &'static str,
    value: i64,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("capability_lineage.{field_name} must be non-negative, got {value}"),
        )),
    )
}

impl SqliteReceiptStore {
    /// Recover an existing issuance without creating a new pending operation.
    ///
    /// This read path exists so a signed request whose freshness window has
    /// elapsed can recover an already finalized response. It never creates an
    /// intent and therefore cannot turn a stale request into new signing work.
    pub fn recover_capability_issuance_intent(
        &self,
        request_nonce: &str,
        request_digest: &str,
        tenant_id: &TenantId,
        lineage_root_id: &LineageId,
    ) -> Result<Option<PreparedCapabilityIssuance>, CapabilityLineageError> {
        let connection = self.connection()?;
        let existing = connection
            .query_row(
                r#"
                SELECT request_digest, tenant_id, lineage_root_id,
                       intent_bytes, authorization_bytes, response_bytes,
                       recorded_at, aborted_at, abort_reason
                FROM capability_issuance_operations
                WHERE request_nonce = ?1
                "#,
                params![request_nonce],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        non_negative_u64_from_column(row, 6, "issuance recorded_at")?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            stored_digest,
            stored_tenant,
            stored_lineage,
            intent_bytes,
            authorization_bytes,
            response,
            recorded_at,
            aborted_at,
            abort_reason,
        )) = existing
        else {
            return Ok(None);
        };
        if stored_digest != request_digest
            || stored_tenant != tenant_id.as_str()
            || stored_lineage != lineage_root_id.as_str()
        {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "capability issuance nonce was reused for a different request binding".to_string(),
            )
            .into());
        }
        Ok(Some(match (response, aborted_at, abort_reason) {
            (Some(response), None, None) => PreparedCapabilityIssuance::Finalized(response),
            (None, Some(_), Some(reason)) => PreparedCapabilityIssuance::Aborted { reason },
            (None, None, None) => PreparedCapabilityIssuance::Pending {
                intent_bytes,
                authorization_bytes,
                recorded_at,
            },
            _ => {
                return Err(chio_kernel::ReceiptStoreError::ReadBoundary(
                    "capability issuance operation has an invalid terminal state".to_string(),
                )
                .into());
            }
        }))
    }

    /// Persist or recover the immutable unsigned intent for one issuance.
    ///
    /// The intent commits before an external keyring is asked to sign. A
    /// retry recovers the exact original bytes, so a crash after key-log
    /// persistence can replay the same artifact instead of minting a new ID
    /// or timestamp. A finalized operation returns its exact response bytes.
    pub fn prepare_capability_issuance_intent(
        &self,
        input: PrepareCapabilityIssuanceIntentInput<'_>,
    ) -> Result<PreparedCapabilityIssuance, CapabilityLineageError> {
        let PrepareCapabilityIssuanceIntentInput {
            request_nonce,
            request_digest,
            tenant_id,
            lineage_root_id,
            intent_bytes,
            session_admission,
            recorded_at,
            expires_at,
            expected_freeze_generation,
        } = input;
        if expires_at <= recorded_at {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "capability issuance intent expiry must follow its recorded time".to_string(),
            )
            .into());
        }
        let request_nonce = request_nonce.to_string();
        let request_digest = request_digest.to_string();
        let tenant_id = tenant_id.as_str().to_string();
        let lineage_root_id = lineage_root_id.as_str().to_string();
        let intent_bytes = intent_bytes.to_vec();
        let session_admission = session_admission.clone();
        Ok(self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing_admission = transaction
                .query_row(
                    r#"
                    SELECT operation_nonce, admission_digest, binding_bytes
                    FROM capability_session_admissions
                    WHERE admission_nonce = ?1
                    "#,
                    params![session_admission.admission_nonce],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .optional()?;
            match existing_admission {
                Some((operation_nonce, digest, binding_bytes))
                    if operation_nonce != session_admission.operation_nonce
                        || digest != session_admission.admission_digest
                        || binding_bytes != session_admission.binding_bytes =>
                {
                    return Err(chio_kernel::ReceiptStoreError::Conflict(
                        "capability session admission nonce was reused for another security binding"
                            .to_string(),
                    ));
                }
                Some(_) => {}
                None => {
                    transaction.execute(
                        r#"
                        INSERT INTO capability_session_admissions (
                            admission_nonce, operation_nonce, admission_digest,
                            binding_bytes, recorded_at
                        ) VALUES (?1, ?2, ?3, ?4, ?5)
                        "#,
                        params![
                            session_admission.admission_nonce,
                            session_admission.operation_nonce,
                            session_admission.admission_digest,
                            session_admission.binding_bytes,
                            sqlite_i64(recorded_at, "session admission recorded_at")?,
                        ],
                    )?;
                }
            }
            let existing = transaction
                .query_row(
                    r#"
                    SELECT request_digest, tenant_id, lineage_root_id,
                           intent_bytes, authorization_bytes, response_bytes,
                           recorded_at, aborted_at, abort_reason
                    FROM capability_issuance_operations
                    WHERE request_nonce = ?1
                    "#,
                    params![request_nonce],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, Option<Vec<u8>>>(5)?,
                            non_negative_u64_from_column(row, 6, "issuance recorded_at")?,
                            row.get::<_, Option<i64>>(7)?,
                            row.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((
                stored_digest,
                stored_tenant,
                stored_lineage,
                stored_intent,
                authorization_bytes,
                response,
                stored_recorded_at,
                aborted_at,
                abort_reason,
            )) = existing
            {
                if stored_digest != request_digest
                    || stored_tenant != tenant_id
                    || stored_lineage != lineage_root_id
                {
                    return Err(chio_kernel::ReceiptStoreError::Conflict(
                        "capability issuance nonce was reused for a different request binding"
                            .to_string(),
                    ));
                }
                transaction.commit()?;
                return Ok(match (response, aborted_at, abort_reason) {
                    (Some(response), None, None) => {
                        PreparedCapabilityIssuance::Finalized(response)
                    }
                    (None, Some(_), Some(reason)) => {
                        PreparedCapabilityIssuance::Aborted { reason }
                    }
                    (None, None, None) => PreparedCapabilityIssuance::Pending {
                        intent_bytes: stored_intent,
                        authorization_bytes,
                        recorded_at: stored_recorded_at,
                    },
                    _ => {
                        return Err(chio_kernel::ReceiptStoreError::ReadBoundary(
                            "capability issuance operation has an invalid terminal state"
                                .to_string(),
                        ));
                    }
                });
            }
            let trusted_now_unix_ms =
                crate::security_state::SecurityStateClock::now_unix_ms(
                    &crate::security_state::SystemSecurityStateClock,
                )
                .map_err(|error| {
                    chio_kernel::ReceiptStoreError::ReadBoundary(format!(
                        "security-state trusted clock is unavailable: {error}"
                    ))
                })?;
            let freeze_generation =
                crate::security_state::authorize_capability_issuance_in_transaction(
                    &transaction,
                    &TenantId::new(tenant_id.clone()).map_err(|_| {
                        chio_kernel::ReceiptStoreError::Conflict(
                            "capability issuance tenant binding is invalid".to_string(),
                        )
                    })?,
                    &LineageId::new(lineage_root_id.clone()).map_err(|_| {
                        chio_kernel::ReceiptStoreError::Conflict(
                            "capability issuance lineage binding is invalid".to_string(),
                        )
                    })?,
                    trusted_now_unix_ms,
                )
                .map_err(|error| match error.kind() {
                    chio_security_types::ports::PortErrorKind::Conflict => {
                        chio_kernel::ReceiptStoreError::Conflict(
                            "capability issuance is blocked by an active issuance freeze"
                                .to_string(),
                        )
                    }
                    _ => chio_kernel::ReceiptStoreError::ReadBoundary(
                        "capability issuance freeze state failed validation".to_string(),
                    ),
                })?;
            if freeze_generation != expected_freeze_generation {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "capability issuance freeze generation changed before intent commit"
                        .to_string(),
                ));
            }
            transaction.execute(
                r#"
                INSERT INTO capability_issuance_operations (
                    request_nonce, request_digest, tenant_id, lineage_root_id,
                    intent_bytes, recorded_at, expires_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request_nonce,
                    request_digest,
                    tenant_id,
                    lineage_root_id,
                    intent_bytes,
                    sqlite_i64(recorded_at, "capability issuance replay recorded_at")?,
                    sqlite_i64(expires_at, "capability issuance expires_at")?,
                ],
            )?;
            transaction.commit()?;
            Ok(PreparedCapabilityIssuance::Pending {
                intent_bytes,
                authorization_bytes: None,
                recorded_at,
            })
        })?)
    }

    /// Attach the authority authorization to an already committed unsigned
    /// intent. The compare-and-set binds the exact body bytes and permits only
    /// an identical authorization on retry.
    pub fn authorize_capability_issuance_intent(
        &self,
        request_nonce: &str,
        request_digest: &str,
        intent_bytes: &[u8],
        authorization_bytes: &[u8],
    ) -> Result<PreparedCapabilityIssuance, CapabilityLineageError> {
        let request_nonce = request_nonce.to_string();
        let request_digest = request_digest.to_string();
        let intent_bytes = intent_bytes.to_vec();
        let authorization_bytes = authorization_bytes.to_vec();
        Ok(self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing = transaction
                .query_row(
                    r#"
                    SELECT request_digest, intent_bytes, authorization_bytes,
                           response_bytes, recorded_at, aborted_at, abort_reason
                    FROM capability_issuance_operations
                    WHERE request_nonce = ?1
                    "#,
                    params![request_nonce],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                            row.get::<_, Option<Vec<u8>>>(3)?,
                            non_negative_u64_from_column(row, 4, "issuance recorded_at")?,
                            row.get::<_, Option<i64>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                stored_digest,
                stored_intent,
                stored_authorization,
                response,
                recorded_at,
                aborted_at,
                abort_reason,
            )) = existing
            else {
                return Err(chio_kernel::ReceiptStoreError::NotFound(
                    "capability issuance intent is absent".to_string(),
                ));
            };
            if stored_digest != request_digest || stored_intent != intent_bytes {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "capability issuance authorization does not match its immutable intent"
                        .to_string(),
                ));
            }
            if let Some(response) = response {
                transaction.commit()?;
                return Ok(PreparedCapabilityIssuance::Finalized(response));
            }
            if let Some(reason) = abort_reason {
                if aborted_at.is_none() {
                    return Err(chio_kernel::ReceiptStoreError::ReadBoundary(
                        "capability issuance abort reason has no terminal time".to_string(),
                    ));
                }
                transaction.commit()?;
                return Ok(PreparedCapabilityIssuance::Aborted { reason });
            }
            if aborted_at.is_some() {
                return Err(chio_kernel::ReceiptStoreError::ReadBoundary(
                    "capability issuance abort time has no terminal reason".to_string(),
                ));
            }
            if let Some(stored_authorization) = stored_authorization {
                if stored_authorization != authorization_bytes {
                    return Err(chio_kernel::ReceiptStoreError::Conflict(
                        "capability issuance intent already has a different authorization"
                            .to_string(),
                    ));
                }
                transaction.commit()?;
                return Ok(PreparedCapabilityIssuance::Pending {
                    intent_bytes,
                    authorization_bytes: Some(stored_authorization),
                    recorded_at,
                });
            }
            let changed = transaction.execute(
                r#"
                UPDATE capability_issuance_operations
                SET authorization_bytes = ?4
                WHERE request_nonce = ?1 AND request_digest = ?2
                  AND intent_bytes = ?3 AND authorization_bytes IS NULL
                  AND response_bytes IS NULL AND aborted_at IS NULL
                "#,
                params![
                    request_nonce,
                    request_digest,
                    intent_bytes,
                    authorization_bytes,
                ],
            )?;
            if changed != 1 {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "capability issuance authorization lost its pending intent".to_string(),
                ));
            }
            transaction.commit()?;
            Ok(PreparedCapabilityIssuance::Pending {
                intent_bytes,
                authorization_bytes: Some(authorization_bytes),
                recorded_at,
            })
        })?)
    }

    /// Mark expired pending issuance operations terminal before authority
    /// rotation. This prevents an abandoned operation from retaining the old
    /// signing epoch indefinitely while ensuring it can never be resurrected.
    pub fn abort_expired_capability_issuance_intents(
        &self,
        now: u64,
    ) -> Result<usize, CapabilityLineageError> {
        Ok(self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = transaction.execute(
                r#"
                UPDATE capability_issuance_operations
                SET aborted_at = ?1,
                    abort_reason = 'capability issuance intent expired before finalization'
                WHERE response_bytes IS NULL
                  AND aborted_at IS NULL
                  AND expires_at <= ?1
                "#,
                params![sqlite_i64(now, "capability issuance abort time")?],
            )?;
            transaction.commit()?;
            Ok(changed)
        })?)
    }

    pub fn has_pending_capability_issuance_intents(
        &self,
    ) -> Result<bool, CapabilityLineageError> {
        let connection = self.connection()?;
        connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM capability_issuance_operations
                    WHERE response_bytes IS NULL AND aborted_at IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(chio_kernel::ReceiptStoreError::from)
            .map_err(CapabilityLineageError::from)
    }

    pub fn abort_capability_issuance_intent(
        &self,
        request_nonce: &str,
        request_digest: &str,
        reason: &str,
        now: u64,
    ) -> Result<(), CapabilityLineageError> {
        let request_nonce = request_nonce.to_string();
        let request_digest = request_digest.to_string();
        let reason = reason.to_string();
        Ok(self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = transaction.execute(
                r#"
                UPDATE capability_issuance_operations
                SET aborted_at = ?3, abort_reason = ?4
                WHERE request_nonce = ?1 AND request_digest = ?2
                  AND response_bytes IS NULL AND aborted_at IS NULL
                "#,
                params![
                    request_nonce,
                    request_digest,
                    sqlite_i64(now, "capability issuance abort time")?,
                    reason,
                ],
            )?;
            if changed != 1 {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "capability issuance intent is not live pending work".to_string(),
                ));
            }
            transaction.commit()?;
            Ok(())
        })?)
    }

    /// Atomically publish one signed issuance and its exact HTTP response.
    ///
    /// The contextual capability snapshot and response become visible in the
    /// same writer transaction. Concurrent or restarted finalizers may supply
    /// only the exact same response for the persisted intent.
    pub fn finalize_capability_issuance(
        &self,
        input: FinalizeCapabilityIssuanceInput<'_>,
    ) -> Result<IdempotentCapabilityIssuance, CapabilityLineageError> {
        let FinalizeCapabilityIssuanceInput {
            request_nonce,
            request_digest,
            intent_bytes,
            authorization_bytes,
            tenant_id,
            lineage_root_id,
            capability,
            response_bytes,
        } = input;
        let request_nonce = request_nonce.to_string();
        let request_digest = request_digest.to_string();
        let intent_bytes = intent_bytes.to_vec();
        let authorization_bytes = authorization_bytes.to_vec();
        let tenant_id = tenant_id.as_str().to_string();
        let lineage_root_id = lineage_root_id.as_str().to_string();
        let response_bytes = response_bytes.to_vec();
        Ok(self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing = transaction
                .query_row(
                    r#"
                    SELECT request_digest, tenant_id, lineage_root_id,
                           intent_bytes, authorization_bytes, response_bytes, aborted_at
                    FROM capability_issuance_operations
                    WHERE request_nonce = ?1
                    "#,
                    params![request_nonce],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, Option<Vec<u8>>>(5)?,
                            row.get::<_, Option<i64>>(6)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                stored_digest,
                stored_tenant,
                stored_lineage,
                stored_intent,
                stored_authorization,
                stored_response,
                aborted_at,
            )) = existing
            else {
                return Err(chio_kernel::ReceiptStoreError::NotFound(
                    "capability issuance intent is absent".to_string(),
                ));
            };
            if stored_digest != request_digest
                || stored_tenant != tenant_id
                || stored_lineage != lineage_root_id
                || stored_intent != intent_bytes
                || stored_authorization.as_deref() != Some(authorization_bytes.as_slice())
            {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "capability issuance finalization does not match its immutable intent"
                        .to_string(),
                ));
            }
            if aborted_at.is_some() {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "aborted capability issuance intent cannot be finalized".to_string(),
                ));
            }
            if let Some(stored_response) = stored_response {
                if stored_response != response_bytes {
                    return Err(chio_kernel::ReceiptStoreError::Conflict(
                        "capability issuance finalizer produced a different signed response"
                            .to_string(),
                    ));
                }
                transaction.commit()?;
                return Ok(IdempotentCapabilityIssuance::Existing(stored_response));
            }

            let grants_json = serde_json::to_string(&capability.scope)?;
            let subject_key = capability.subject.to_hex();
            let issuer_key = capability.issuer.to_hex();
            record_contextual_capability_snapshot_tx(
                &transaction,
                ContextualCapabilitySnapshot {
                    tenant_id: &tenant_id,
                    lineage_root_id: &lineage_root_id,
                    capability_id: &capability.id,
                    subject_key: &subject_key,
                    issuer_key: &issuer_key,
                    issued_at: capability.issued_at,
                    expires_at: capability.expires_at,
                    grants_json: &grants_json,
                    parent_capability_id: None,
                },
            )?;
            transaction.execute(
                r#"
                UPDATE capability_issuance_operations
                SET capability_id = ?2, response_bytes = ?3
                WHERE request_nonce = ?1 AND response_bytes IS NULL
                  AND authorization_bytes IS NOT NULL AND aborted_at IS NULL
                "#,
                params![request_nonce, capability.id, response_bytes],
            )?;
            if transaction.changes() != 1 {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "capability issuance finalization lost its pending intent".to_string(),
                ));
            }
            transaction.commit()?;
            Ok(IdempotentCapabilityIssuance::Created(response_bytes))
        })?)
    }

    /// Record a capability snapshot at issuance time.
    ///
    /// Uses INSERT OR IGNORE for idempotency -- duplicate inserts are silently
    /// dropped, preserving the first-writer-wins record.
    ///
    /// The `parent_capability_id` argument must refer to a capability already
    /// present in the lineage table. If it is `Some` but the parent is missing,
    /// the depth defaults to 1 (the minimum delegation depth).
    pub fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CapabilityLineageError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();

        // Compute delegation depth from parent if present.
        let delegation_depth: u64 = if let Some(parent_id) = parent_capability_id {
            let parent_depth: Option<u64> = self
                .connection()?
                .query_row(
                    "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                    params![parent_id],
                    |row: &Row<'_>| non_negative_u64_from_column(row, 0, "delegation_depth"),
                )
                .optional()?;

            parent_depth.map(|d| d.saturating_add(1)).unwrap_or(1)
        } else {
            0
        };

        let capability_id = token.id.clone();
        let issued_at = token.issued_at;
        let expires_at = token.expires_at;
        let parent_capability_id = parent_capability_id.map(ToString::to_string);
        self.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT OR IGNORE INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at as i64,
                    expires_at as i64,
                    grants_json,
                    delegation_depth as i64,
                    parent_capability_id,
                ],
            )?;
            Ok(())
        })?;

        Ok(())
    }

    /// Record first visibility of a capability under authoritative security
    /// context while holding the same SQLite writer transaction used by causal
    /// fence acquisition.
    ///
    /// Existing, exactly bound capabilities remain usable while a later fence
    /// is active. A previously unseen capability, or a legacy snapshot that has
    /// not yet been context-bound, must pass the live fence check before its
    /// binding becomes visible.
    pub fn record_capability_snapshot_with_issuance_admission(
        &self,
        tenant_id: &TenantId,
        lineage_root_id: &LineageId,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CapabilityLineageError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let tenant_id = tenant_id.as_str().to_string();
        let lineage_root_id = lineage_root_id.as_str().to_string();
        let capability_id = token.id.clone();
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();
        let issued_at = token.issued_at;
        let expires_at = token.expires_at;
        let parent_capability_id = parent_capability_id.map(ToString::to_string);
        self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            record_contextual_capability_snapshot_tx(
                &transaction,
                ContextualCapabilitySnapshot {
                    tenant_id: &tenant_id,
                    lineage_root_id: &lineage_root_id,
                    capability_id: &capability_id,
                    subject_key: &subject_key,
                    issuer_key: &issuer_key,
                    issued_at,
                    expires_at,
                    grants_json: &grants_json,
                    parent_capability_id: parent_capability_id.as_deref(),
                },
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }

    /// Verify that the exact token and authoritative context were admitted by
    /// a prior contextual snapshot transaction.
    pub fn capability_snapshot_has_issuance_admission(
        &self,
        tenant_id: &TenantId,
        lineage_root_id: &LineageId,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<bool, CapabilityLineageError> {
        let connection = self.connection()?;
        let existing = connection
            .query_row(
                r#"
                SELECT capability_id, subject_key, issuer_key, issued_at, expires_at,
                       grants_json, delegation_depth, parent_capability_id
                FROM capability_lineage
                WHERE capability_id = ?1
                "#,
                params![token.id.as_str()],
                snapshot_from_row,
            )
            .optional()?;
        let binding = connection
            .query_row(
                r#"
                SELECT tenant_id, lineage_root_id, parent_capability_id, operation
                FROM capability_lineage_admissions
                WHERE capability_id = ?1
                "#,
                params![token.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((bound_tenant, bound_lineage, bound_parent, bound_operation)) = binding else {
            return Ok(false);
        };
        let existing = existing.ok_or_else(|| {
            chio_kernel::ReceiptStoreError::Conflict(
                "capability issuance admission exists without a capability snapshot".to_string(),
            )
        })?;
        let (operation, delegation_depth) = match parent_capability_id {
            None => ("issue", 0),
            Some(parent_id) => {
                let parent_context = connection
                    .query_row(
                        r#"
                        SELECT tenant_id, lineage_root_id
                        FROM capability_lineage_admissions
                        WHERE capability_id = ?1
                        "#,
                        params![parent_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                if parent_context
                    .as_ref()
                    .is_none_or(|(parent_tenant, parent_lineage)| {
                        parent_tenant != tenant_id.as_str()
                            || parent_lineage != lineage_root_id.as_str()
                    })
                {
                    return Err(chio_kernel::ReceiptStoreError::Conflict(
                        "delegation parent is not bound to the authoritative tenant and lineage"
                            .to_string(),
                    )
                    .into());
                }
                let parent_depth = connection
                    .query_row(
                        "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                        params![parent_id],
                        |row| non_negative_u64_from_column(row, 0, "delegation_depth"),
                    )
                    .optional()?
                    .ok_or_else(|| {
                        chio_kernel::ReceiptStoreError::Conflict(
                            "delegation parent capability snapshot is missing".to_string(),
                        )
                    })?;
                (
                    "delegate",
                    parent_depth.checked_add(1).ok_or_else(|| {
                        chio_kernel::ReceiptStoreError::Conflict(
                            "capability delegation depth overflowed".to_string(),
                        )
                    })?,
                )
            }
        };
        let expected = CapabilitySnapshot {
            capability_id: token.id.clone(),
            subject_key: token.subject.to_hex(),
            issuer_key: token.issuer.to_hex(),
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            grants_json: serde_json::to_string(&token.scope)?,
            delegation_depth,
            parent_capability_id: parent_capability_id.map(ToString::to_string),
        };
        if existing != expected
            || bound_tenant != tenant_id.as_str()
            || bound_lineage != lineage_root_id.as_str()
            || bound_parent.as_deref() != parent_capability_id
            || bound_operation != operation
        {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "capability issuance admission binding changed".to_string(),
            )
            .into());
        }
        Ok(true)
    }

    /// Upsert an already-materialized capability snapshot.
    ///
    /// This is used by cluster replication so followers can converge on the
    /// leader's lineage table without reconstructing full signed tokens.
    pub fn upsert_capability_snapshot(
        &mut self,
        snapshot: &CapabilitySnapshot,
    ) -> Result<(), CapabilityLineageError> {
        let snapshot = snapshot.clone();
        self.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(capability_id) DO UPDATE SET
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    issued_at = excluded.issued_at,
                    expires_at = excluded.expires_at,
                    grants_json = excluded.grants_json,
                    delegation_depth = excluded.delegation_depth,
                    parent_capability_id = excluded.parent_capability_id
                "#,
                params![
                    snapshot.capability_id,
                    snapshot.subject_key,
                    snapshot.issuer_key,
                    snapshot.issued_at as i64,
                    snapshot.expires_at as i64,
                    snapshot.grants_json,
                    snapshot.delegation_depth as i64,
                    snapshot.parent_capability_id,
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Retrieve a single capability snapshot by its ID.
    ///
    /// Returns `None` if no snapshot exists for the given capability_id.
    pub fn get_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, CapabilityLineageError> {
        let row = self
            .connection()?
            .query_row(
                r#"
                SELECT
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                FROM capability_lineage
                WHERE capability_id = ?1
                "#,
                params![capability_id],
                snapshot_from_row,
            )
            .optional()?;

        Ok(row)
    }

    /// Walk the delegation chain for a capability, returning root-first ordering.
    ///
    /// Uses a WITH RECURSIVE CTE that walks from the given capability up through
    /// its parent chain, tracking depth level. The ORDER BY level DESC produces
    /// root-first ordering because the root has the highest level value.
    ///
    /// A max-depth guard (level < 20) prevents infinite recursion caused by
    /// accidental cycles in the parent chain.
    pub fn get_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            WITH RECURSIVE chain(
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id,
                level
            ) AS (
                SELECT
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id,
                    0 AS level
                FROM capability_lineage
                WHERE capability_id = ?1

                UNION ALL

                SELECT
                    cl.capability_id,
                    cl.subject_key,
                    cl.issuer_key,
                    cl.issued_at,
                    cl.expires_at,
                    cl.grants_json,
                    cl.delegation_depth,
                    cl.parent_capability_id,
                    chain.level + 1
                FROM capability_lineage cl
                INNER JOIN chain ON cl.capability_id = chain.parent_capability_id
                WHERE chain.level < 20
            )
            SELECT
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            FROM chain
            ORDER BY level DESC
            "#,
        )?;

        let rows = stmt.query_map(params![capability_id], snapshot_from_row)?;

        let mut chain = Vec::new();
        for row in rows {
            chain.push(row?);
        }

        Ok(chain)
    }

    /// List all capability snapshots for a given subject key.
    ///
    /// Returns snapshots ordered newest-first by issued_at.
    pub fn list_capabilities_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        self.list_capability_snapshots(Some(subject_key), None)
    }

    /// List capability snapshots filtered by subject and/or issuer.
    ///
    /// If both filters are present they are combined with AND semantics.
    /// Results are ordered deterministically oldest-first to keep reputation
    /// corpus construction stable across runs.
    pub fn list_capability_snapshots(
        &self,
        subject_key: Option<&str>,
        issuer_key: Option<&str>,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            SELECT
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            FROM capability_lineage
            WHERE (?1 IS NULL OR subject_key = ?1)
              AND (?2 IS NULL OR issuer_key = ?2)
            ORDER BY issued_at ASC, capability_id ASC
            "#,
        )?;

        let rows = stmt.query_map(params![subject_key, issuer_key], snapshot_from_row)?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Return capability lineage snapshots added after a given local sequence.
    ///
    /// The sequence is the SQLite `rowid`, which is monotonic for this
    /// append-only table and therefore suitable as a replication cursor.
    pub fn list_capability_snapshots_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredCapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            SELECT
                rowid,
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            FROM capability_lineage
            WHERE rowid > ?1
            ORDER BY rowid ASC
            LIMIT ?2
            "#,
        )?;

        let rows = stmt.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok(StoredCapabilitySnapshot {
                seq: non_negative_u64_from_column(row, 0, "rowid")?,
                snapshot: CapabilitySnapshot {
                    capability_id: row.get::<_, String>(1)?,
                    subject_key: row.get::<_, String>(2)?,
                    issuer_key: row.get::<_, String>(3)?,
                    issued_at: non_negative_u64_from_column(row, 4, "issued_at")?,
                    expires_at: non_negative_u64_from_column(row, 5, "expires_at")?,
                    grants_json: row.get::<_, String>(6)?,
                    delegation_depth: non_negative_u64_from_column(row, 7, "delegation_depth")?,
                    parent_capability_id: row.get::<_, Option<String>>(8)?,
                },
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Highest lineage snapshot seq (capability_lineage rowid), or 0 when empty.
    /// list_capability_snapshots_after_seq paginates on rowid, so the head is
    /// MAX(rowid). Returns ReceiptStoreError so the cluster status
    /// path converts it through the same CliError variant as the receipt heads.
    pub fn max_lineage_seq(&self) -> Result<u64, chio_kernel::ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }
}
