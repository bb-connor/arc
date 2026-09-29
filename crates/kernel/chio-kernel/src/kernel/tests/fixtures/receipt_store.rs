//! SQLite receipt journal fixture; corruption hooks stay with the owner.
use super::*;

fn signed_capability_from_row(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<CapabilityToken>> {
    row.get::<_, Option<String>>(column)?
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

pub(in crate::kernel::tests) struct SqliteReceiptStore {
    connection: Mutex<Connection>,
    // Test-double analogue of the real store's writer-actor signer install
    // (`enable_background_checkpoints`). `None` until installed;
    // `max_batch == 0` disables checkpointing (ADR-0008).
    background_checkpoint_signer: Mutex<Option<(std::sync::Arc<Keypair>, u64)>>,
    checkpoint_status_flip: Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}

impl SqliteReceiptStore {
    pub(in crate::kernel::tests) fn open(
        path: impl AsRef<Path>,
    ) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    timestamp INTEGER NOT NULL,
                    capability_id TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chio_child_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    timestamp INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    parent_request_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    operation_kind TEXT NOT NULL,
                    terminal_state TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    outcome_hash TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                    checkpoint_seq INTEGER PRIMARY KEY,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS capability_lineage (
                    capability_id TEXT PRIMARY KEY,
                    subject_key TEXT NOT NULL,
                    issuer_key TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    grants_json TEXT NOT NULL,
                    delegation_depth INTEGER NOT NULL DEFAULT 0,
                    parent_capability_id TEXT,
                    signed_capability_json TEXT
                );

                CREATE TABLE IF NOT EXISTS credit_bonds (
                    bond_id TEXT PRIMARY KEY,
                    lifecycle_state TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS session_anchors (
                    anchor_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    auth_context_fingerprint TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    supersedes_anchor_id TEXT,
                    is_current INTEGER NOT NULL DEFAULT 1,
                    raw_json TEXT NOT NULL
                );
                "#,
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            background_checkpoint_signer: Mutex::new(None),
            checkpoint_status_flip: Mutex::new(None),
        })
    }

    /// Locked analogue of the `ReceiptStore::load_latest_checkpoint` default,
    /// usable from a call site that already holds `self.connection`'s guard
    /// (avoids re-locking the non-reentrant `Mutex<Connection>`).
    pub(in crate::kernel::tests) fn load_latest_checkpoint_locked(
        connection: &Connection,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let mut checkpoint_seq = 1;
        let mut latest = None;
        loop {
            let Some(checkpoint) = Self::load_checkpoint_by_seq_locked(connection, checkpoint_seq)?
            else {
                return Ok(latest);
            };
            checkpoint_seq = checkpoint
                .body
                .checkpoint_seq
                .checked_add(1)
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "checkpoint_seq overflow while loading latest".to_string(),
                    )
                })?;
            latest = Some(checkpoint);
        }
    }

    fn receipts_canonical_bytes_range_locked(
        connection: &Connection,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut statement = connection.prepare(
            r#"
                SELECT seq, raw_json
                FROM chio_tool_receipts
                WHERE seq >= ?1 AND seq <= ?2
                ORDER BY seq ASC
                "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            let value = serde_json::from_str::<serde_json::Value>(&raw_json)?;
            let bytes = canonical_json_bytes(&value)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            Ok((seq.max(0) as u64, bytes))
        })
        .collect()
    }

    fn store_checkpoint_locked(
        connection: &Connection,
        checkpoint: &KernelCheckpoint,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(checkpoint)?;
        connection.execute(
            r#"
                INSERT INTO kernel_checkpoints (checkpoint_seq, raw_json)
                VALUES (?1, ?2)
                ON CONFLICT(checkpoint_seq) DO UPDATE SET raw_json = excluded.raw_json
                "#,
            params![checkpoint.body.checkpoint_seq as i64, raw_json],
        )?;
        Ok(())
    }

    pub(in crate::kernel::tests) fn create_next_receipt_checkpoint_locked(
        connection: &Connection,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        if max_batch == 0 {
            return Err(ReceiptStoreError::Conflict(
                "checkpoint max_batch must be greater than zero".to_string(),
            ));
        }
        let latest_committed_entry_seq = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let latest_committed_entry_seq = latest_committed_entry_seq.max(0) as u64;
        let previous_checkpoint = Self::load_latest_checkpoint_locked(connection)?;
        let latest_checkpointed_entry_seq = previous_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        if latest_committed_entry_seq <= latest_checkpointed_entry_seq {
            return Ok(ReceiptCheckpointCreateReport {
                created: false,
                checkpoint_seq: None,
                batch_start_seq: None,
                batch_end_seq: None,
                latest_committed_entry_seq,
                latest_checkpointed_entry_seq,
            });
        }
        let batch_start_seq = latest_checkpointed_entry_seq + 1;
        let batch_end_seq = latest_committed_entry_seq
            .min(batch_start_seq.saturating_add(max_batch.saturating_sub(1)));
        let receipt_bytes_with_seqs = Self::receipts_canonical_bytes_range_locked(
            connection,
            batch_start_seq,
            batch_end_seq,
        )?;
        let expected_len = batch_end_seq - batch_start_seq + 1;
        if receipt_bytes_with_seqs.len() as u64 != expected_len
            || receipt_bytes_with_seqs
                .first()
                .map(|(seq, _)| *seq)
                .unwrap_or(0)
                != batch_start_seq
            || receipt_bytes_with_seqs
                .last()
                .map(|(seq, _)| *seq)
                .unwrap_or(0)
                != batch_end_seq
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint receipt range {}..={} is not contiguous",
                batch_start_seq, batch_end_seq
            )));
        }
        let receipt_bytes = receipt_bytes_with_seqs
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = previous_checkpoint.as_ref().map_or(Ok(1), |checkpoint| {
            checkpoint
                .body
                .checkpoint_seq
                .checked_add(1)
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "checkpoint_seq overflow while creating receipt checkpoint".to_string(),
                    )
                })
        })?;
        let mut prior_chain_leaf_hashes = Vec::new();
        if let Some(previous) = previous_checkpoint.as_ref() {
            for seq in 1..=previous.body.checkpoint_seq {
                let chained =
                    Self::load_checkpoint_by_seq_locked(connection, seq)?.ok_or_else(|| {
                        ReceiptStoreError::Conflict(format!(
                            "checkpoint chain has a gap at seq {seq}"
                        ))
                    })?;
                prior_chain_leaf_hashes.push(
                    crate::checkpoint::checkpoint_chain_leaf_hash(&chained.body).map_err(
                        |error| {
                            ReceiptStoreError::Conflict(format!(
                                "checkpoint chain leaf failed: {error}"
                            ))
                        },
                    )?,
                );
            }
        }
        let checkpoint = build_checkpoint_with_previous(
            checkpoint_seq,
            batch_start_seq,
            batch_end_seq,
            &receipt_bytes,
            keypair,
            previous_checkpoint.as_ref(),
            &prior_chain_leaf_hashes,
        )
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!("checkpoint build failed: {error}"))
        })?;
        Self::store_checkpoint_locked(connection, &checkpoint)?;
        Ok(ReceiptCheckpointCreateReport {
            created: true,
            checkpoint_seq: Some(checkpoint.body.checkpoint_seq),
            batch_start_seq: Some(checkpoint.body.batch_start_seq),
            batch_end_seq: Some(checkpoint.body.batch_end_seq),
            latest_committed_entry_seq,
            latest_checkpointed_entry_seq: checkpoint.body.batch_end_seq,
        })
    }

    /// Test-double analogue of the real store's writer-actor checkpoint
    /// construction: synchronous, but performed under the same
    /// connection lock as the triggering append, so concurrent callers see
    /// contiguous batches without needing a conflict-retry loop.
    fn maybe_build_background_checkpoint_locked(
        connection: &Connection,
        seq: u64,
        signer: &(std::sync::Arc<Keypair>, u64),
    ) -> Result<(), ReceiptStoreError> {
        let (keypair, max_batch) = signer;
        if *max_batch == 0 {
            return Ok(());
        }
        let latest_checkpointed_entry_seq = Self::load_latest_checkpoint_locked(connection)?
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        if seq <= latest_checkpointed_entry_seq
            || (seq - latest_checkpointed_entry_seq) < *max_batch
        {
            return Ok(());
        }
        Self::create_next_receipt_checkpoint_locked(connection, *max_batch, keypair)?;
        Ok(())
    }

    pub(in crate::kernel::tests) fn get_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
            let signed_capability = signed_capability_from_row(row, 8)?;
            Ok(CapabilitySnapshot {
                capability_id: row.get::<_, String>(0)?,
                subject_key: row.get::<_, String>(1)?,
                issuer_key: row.get::<_, String>(2)?,
                issued_at: row.get::<_, i64>(3)?.max(0) as u64,
                expires_at: row.get::<_, i64>(4)?.max(0) as u64,
                grants_json: row.get::<_, String>(5)?,
                delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
                parent_capability_id: row.get::<_, Option<String>>(7)?,
                federated_parent_capability_id: None,
                provenance: if signed_capability.is_some() {
                    crate::CapabilitySnapshotProvenance::SignedToken
                } else {
                    crate::CapabilitySnapshotProvenance::LegacyProjection
                },
                signed_capability,
            })
        }

        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());

        while let Some(current_id) = current.take() {
            let snapshot = self
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
                            parent_capability_id,
                            signed_capability_json
                        FROM capability_lineage
                        WHERE capability_id = ?1
                        "#,
                    params![current_id],
                    snapshot_from_row,
                )
                .optional()?;
            let Some(snapshot) = snapshot else {
                break;
            };
            current = snapshot.parent_capability_id.clone();
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }

    fn get_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, CapabilityLineageError> {
        self.connection()?
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
                        parent_capability_id,
                        signed_capability_json
                    FROM capability_lineage
                    WHERE capability_id = ?1
                "#,
                params![capability_id],
                |row| {
                    let signed_capability = signed_capability_from_row(row, 8)?;
                    Ok(CapabilitySnapshot {
                        capability_id: row.get::<_, String>(0)?,
                        subject_key: row.get::<_, String>(1)?,
                        issuer_key: row.get::<_, String>(2)?,
                        issued_at: row.get::<_, i64>(3)?.max(0) as u64,
                        expires_at: row.get::<_, i64>(4)?.max(0) as u64,
                        grants_json: row.get::<_, String>(5)?,
                        delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
                        parent_capability_id: row.get::<_, Option<String>>(7)?,
                        federated_parent_capability_id: None,
                        provenance: if signed_capability.is_some() {
                            crate::CapabilitySnapshotProvenance::SignedToken
                        } else {
                            crate::CapabilitySnapshotProvenance::LegacyProjection
                        },
                        signed_capability,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(in crate::kernel::tests) fn record_credit_bond(
        &self,
        bond: &SignedCreditBond,
        lifecycle_state: CreditBondLifecycleState,
    ) -> Result<(), ReceiptStoreError> {
        self.connection()?.execute(
            "INSERT OR REPLACE INTO credit_bonds (bond_id, lifecycle_state, expires_at, raw_json)
                 VALUES (?1, ?2, ?3, ?4)",
            params![
                bond.body.bond_id,
                match lifecycle_state {
                    CreditBondLifecycleState::Active => "active",
                    CreditBondLifecycleState::Superseded => "superseded",
                    CreditBondLifecycleState::Released => "released",
                    CreditBondLifecycleState::Impaired => "impaired",
                    CreditBondLifecycleState::Expired => "expired",
                },
                bond.body.expires_at as i64,
                serde_json::to_string(bond)?,
            ],
        )?;
        Ok(())
    }
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt)?;
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        self.load_chio_receipt_for_test(receipt_id)
    }

    fn load_retained_chio_receipt_commitment(
        &self,
        receipt_id: &str,
    ) -> Result<Option<crate::receipt_store::RetainedReceiptCommitment>, ReceiptStoreError> {
        self.load_retained_chio_receipt_commitment_for_test(receipt_id)
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn enable_background_checkpoints(
        &self,
        keypair: Keypair,
        max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        let mut signer = self.background_checkpoint_signer.lock().map_err(|_| {
            ReceiptStoreError::Conflict("background checkpoint signer lock poisoned".to_string())
        })?;
        *signer = Some((std::sync::Arc::new(keypair), max_batch));
        Ok(true)
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let connection = self.connection()?;
        let rows = connection.execute(
            r#"
                INSERT INTO chio_tool_receipts (
                    receipt_id,
                    timestamp,
                    capability_id,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
            params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.capability_id,
                raw_json,
            ],
        )?;
        let seq = (rows > 0).then(|| connection.last_insert_rowid().max(0) as u64);
        if let Some(seq) = seq {
            // Test-double analogue of the real store's writer-actor checkpoint
            // construction: performed synchronously, still under the
            // connection lock this append holds, so it never observes a
            // concurrent writer's half-committed state.
            let signer = self.background_checkpoint_signer.lock().map_err(|_| {
                ReceiptStoreError::Conflict(
                    "background checkpoint signer lock poisoned".to_string(),
                )
            })?;
            if let Some(signer) = signer.as_ref() {
                Self::maybe_build_background_checkpoint_locked(&connection, seq, signer)?;
            }
        }
        Ok(seq)
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        // The double builds checkpoints synchronously, in-line with each
        // append (see `append_chio_receipt_returning_seq`), so there is
        // nothing queued to drain; report the current committed and
        // checkpointed positions.
        let connection = self.connection()?;
        let latest_committed_entry_seq = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let latest_committed_entry_seq = latest_committed_entry_seq.max(0) as u64;
        let latest_checkpoint = Self::load_latest_checkpoint_locked(&connection)?;
        let latest_checkpointed_entry_seq = latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        let latest_checkpoint_seq =
            latest_checkpoint.map(|checkpoint| checkpoint.body.checkpoint_seq);
        Ok(ReceiptFlushReport {
            latest_committed_entry_seq,
            latest_checkpoint_seq,
            latest_checkpointed_entry_seq,
            ..Default::default()
        })
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection()?.execute(
            r#"
                INSERT INTO chio_child_receipts (
                    receipt_id,
                    timestamp,
                    session_id,
                    parent_request_id,
                    request_id,
                    operation_kind,
                    terminal_state,
                    policy_hash,
                    outcome_hash,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
            params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                match &receipt.terminal_state {
                    OperationTerminalState::Completed => "completed",
                    OperationTerminalState::Cancelled { .. } => "cancelled",
                    OperationTerminalState::Incomplete { .. } => "incomplete",
                },
                receipt.policy_hash,
                receipt.outcome_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
                SELECT seq, raw_json
                FROM chio_tool_receipts
                WHERE seq >= ?1 AND seq <= ?2
                ORDER BY seq ASC
                "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            let value = serde_json::from_str::<serde_json::Value>(&raw_json)?;
            let bytes = canonical_json_bytes(&value)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            Ok((seq.max(0) as u64, bytes))
        })
        .collect()
    }

    fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        Self::store_checkpoint_locked(&connection, checkpoint)
    }

    fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        self.create_next_receipt_checkpoint_with_status_flip(max_batch, keypair)
    }

    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        SqliteReceiptStore::load_checkpoint_by_seq(self, checkpoint_seq)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        self.connection()?
            .query_row(
                "SELECT raw_json, lifecycle_state FROM credit_bonds WHERE bond_id = ?1",
                params![bond_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(raw_json, lifecycle_state)| {
                let bond = serde_json::from_str::<SignedCreditBond>(&raw_json)?;
                let lifecycle_state = match lifecycle_state.as_str() {
                    "active" => CreditBondLifecycleState::Active,
                    "superseded" => CreditBondLifecycleState::Superseded,
                    "released" => CreditBondLifecycleState::Released,
                    "impaired" => CreditBondLifecycleState::Impaired,
                    "expired" => CreditBondLifecycleState::Expired,
                    other => {
                        return Err(ReceiptStoreError::Conflict(format!(
                            "unknown credit bond lifecycle state `{other}`"
                        )));
                    }
                };
                Ok(CreditBondRow {
                    bond,
                    lifecycle_state,
                    superseded_by_bond_id: None,
                })
            })
            .transpose()
    }

    fn record_session_anchor(
        &self,
        session_id: &str,
        anchor_id: &str,
        auth_context_fingerprint: &str,
        issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        let replaces_current_anchor = match supersedes_anchor_id {
            Some(supersedes_anchor_id) => connection
                .query_row(
                    r#"
                    SELECT is_current
                    FROM session_anchors
                    WHERE session_id = ?1
                      AND anchor_id = ?2
                    "#,
                    params![session_id, supersedes_anchor_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|is_current| is_current != 0)
                .unwrap_or(false),
            None => false,
        };
        let existing_anchor = connection
            .query_row(
                r#"
                    SELECT anchor_id
                    FROM session_anchors
                    WHERE session_id = ?1
                      AND auth_context_fingerprint = ?2
                      AND anchor_id <> ?3
                    LIMIT 1
                    "#,
                params![session_id, auth_context_fingerprint, anchor_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_anchor) = existing_anchor {
            if !replaces_current_anchor {
                return Err(ReceiptStoreError::Conflict(format!(
                    "session anchor replay detected for session `{session_id}` auth_context_fingerprint `{auth_context_fingerprint}` existing `{existing_anchor}`"
                )));
            }
        }

        connection.execute(
            "UPDATE session_anchors SET is_current = 0 WHERE session_id = ?1 AND anchor_id <> ?2",
            params![session_id, anchor_id],
        )?;
        connection.execute(
            r#"
                INSERT INTO session_anchors (
                    anchor_id,
                    session_id,
                    auth_context_fingerprint,
                    issued_at,
                    supersedes_anchor_id,
                    is_current,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
                ON CONFLICT(anchor_id) DO UPDATE SET
                    auth_context_fingerprint = excluded.auth_context_fingerprint,
                    issued_at = excluded.issued_at,
                    supersedes_anchor_id = COALESCE(excluded.supersedes_anchor_id, session_anchors.supersedes_anchor_id),
                    is_current = 1,
                    raw_json = excluded.raw_json
                "#,
            params![
                anchor_id,
                session_id,
                auth_context_fingerprint,
                issued_at as i64,
                supersedes_anchor_id,
                serde_json::to_string(anchor_json)?,
            ],
        )?;
        Ok(())
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let signed_capability_json = serde_json::to_string(token)?;
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();
        let delegation_depth = if let Some(parent_id) = parent_capability_id {
            self.connection()?
                .query_row(
                    "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                    params![parent_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|depth| depth.max(0) as u64 + 1)
                .unwrap_or(1)
        } else {
            0
        };

        self.connection()?.execute(
            r#"
                INSERT OR REPLACE INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id,
                    signed_capability_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
            params![
                token.id,
                subject_key,
                issuer_key,
                token.issued_at as i64,
                token.expires_at as i64,
                grants_json,
                delegation_depth as i64,
                parent_capability_id,
                signed_capability_json,
            ],
        )?;
        Ok(())
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        self.get_lineage(capability_id)
            .map_err(|error| match error {
                CapabilityLineageError::ReceiptStore(error) => error,
                CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
                CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            })
    }

    fn get_capability_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
        self.get_delegation_chain(capability_id)
            .map_err(|error| match error {
                CapabilityLineageError::ReceiptStore(error) => error,
                CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
                CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            })
    }
}

#[path = "../support_receipt_store_extensions.rs"]
mod extensions;
