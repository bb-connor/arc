use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::canonical::canonical_json_bytes;
use pact_core::capability::CapabilityToken;
use pact_core::crypto::Signature;
use pact_core::receipt::{
    ChildRequestReceipt, Decision, FinancialReceiptMetadata, PactReceipt,
    ReceiptAttributionMetadata,
};
use pact_core::session::OperationTerminalState;
use pact_kernel::checkpoint::{KernelCheckpoint, KernelCheckpointBody};
use pact_kernel::cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
use pact_kernel::operator_report::{
    ComplianceReport, OperatorReportQuery, SharedEvidenceQuery, SharedEvidenceReferenceReport,
    SharedEvidenceReferenceRow, SharedEvidenceReferenceSummary,
};
use pact_kernel::receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
use pact_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
use pact_kernel::{
    EvidenceChildReceiptScope, EvidenceExportQuery, FederatedEvidenceShareImport,
    FederatedEvidenceShareSummary, ReceiptStore, ReceiptStoreError, RetentionConfig,
    StoredChildReceipt, StoredToolReceipt,
};
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteReceiptStore {
    pub(crate) connection: Connection,
}

impl SqliteReceiptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS pact_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_timestamp
                ON pact_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_capability
                ON pact_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_subject
                ON pact_tool_receipts(subject_key);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_grant
                ON pact_tool_receipts(capability_id, grant_index);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_tool
                ON pact_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_decision
                ON pact_tool_receipts(decision_kind);

            CREATE TABLE IF NOT EXISTS pact_child_receipts (
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

            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_timestamp
                ON pact_child_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_session
                ON pact_child_receipts(session_id);
            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_parent
                ON pact_child_receipts(parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_request
                ON pact_child_receipts(request_id);

            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issuer
                ON capability_lineage(issuer_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
                ON capability_lineage(issued_at);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_lineage_bridges (
                local_capability_id TEXT PRIMARY KEY REFERENCES capability_lineage(capability_id) ON DELETE CASCADE,
                parent_capability_id TEXT NOT NULL,
                share_id TEXT REFERENCES federated_evidence_shares(share_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_lineage_bridges_parent
                ON federated_lineage_bridges(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_evidence_shares (
                share_id TEXT PRIMARY KEY,
                manifest_hash TEXT NOT NULL,
                imported_at INTEGER NOT NULL,
                exported_at INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                partner TEXT NOT NULL,
                signer_public_key TEXT NOT NULL,
                require_proofs INTEGER NOT NULL DEFAULT 0,
                query_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_federated_evidence_shares_imported_at
                ON federated_evidence_shares(imported_at);

            CREATE TABLE IF NOT EXISTS federated_share_tool_receipts (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                receipt_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (share_id, seq),
                UNIQUE (share_id, receipt_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_capability
                ON federated_share_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_subject
                ON federated_share_tool_receipts(subject_key);

            CREATE TABLE IF NOT EXISTS federated_share_capability_lineage (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                capability_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT,
                PRIMARY KEY (share_id, capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_capability
                ON federated_share_capability_lineage(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_subject
                ON federated_share_capability_lineage(subject_key);
            "#,
        )?;
        ensure_tool_receipt_attribution_columns(&connection)?;
        backfill_tool_receipt_attribution_columns(&connection)?;

        Ok(Self { connection })
    }

    pub fn tool_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection
                .query_row("SELECT COUNT(*) FROM pact_tool_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok(count)
    }

    pub fn child_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection
                .query_row("SELECT COUNT(*) FROM pact_child_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok(count)
    }

    pub fn list_tool_receipts(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        tool_server: Option<&str>,
        tool_name: Option<&str>,
        decision_kind: Option<&str>,
    ) -> Result<Vec<PactReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT raw_json
            FROM pact_tool_receipts
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR tool_server = ?2)
              AND (?3 IS NULL OR tool_name = ?3)
              AND (?4 IS NULL OR decision_kind = ?4)
            ORDER BY seq DESC
            LIMIT ?5
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                limit as i64,
            ],
            |row| row.get::<_, String>(0),
        )?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    /// List all tool receipts attributed to a given subject public key.
    ///
    /// Uses the persisted `subject_key` column when present and falls back to
    /// the capability lineage join for older rows.
    pub fn list_tool_receipts_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<PactReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT r.raw_json
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE COALESCE(r.subject_key, cl.subject_key) = ?1
            ORDER BY r.timestamp ASC, r.seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![subject_key], |row| row.get::<_, String>(0))?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    pub fn list_tool_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredToolReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM pact_tool_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            Ok(StoredToolReceipt {
                seq: seq.max(0) as u64,
                receipt: serde_json::from_str(&raw_json)?,
            })
        })
        .collect()
    }

    pub fn list_child_receipts(
        &self,
        limit: usize,
        session_id: Option<&str>,
        parent_request_id: Option<&str>,
        request_id: Option<&str>,
        operation_kind: Option<&str>,
        terminal_state: Option<&str>,
    ) -> Result<Vec<ChildRequestReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT raw_json
            FROM pact_child_receipts
            WHERE (?1 IS NULL OR session_id = ?1)
              AND (?2 IS NULL OR parent_request_id = ?2)
              AND (?3 IS NULL OR request_id = ?3)
              AND (?4 IS NULL OR operation_kind = ?4)
              AND (?5 IS NULL OR terminal_state = ?5)
            ORDER BY seq DESC
            LIMIT ?6
            "#,
        )?;
        let rows = statement.query_map(
            params![
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                limit as i64,
            ],
            |row| row.get::<_, String>(0),
        )?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    pub fn list_child_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredChildReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM pact_child_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            Ok(StoredChildReceipt {
                seq: seq.max(0) as u64,
                receipt: serde_json::from_str(&raw_json)?,
            })
        })
        .collect()
    }

    pub fn import_federated_evidence_share(
        &mut self,
        import: &FederatedEvidenceShareImport,
    ) -> Result<FederatedEvidenceShareSummary, ReceiptStoreError> {
        let imported_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let tx = self.connection.transaction()?;
        tx.execute(
            r#"
            INSERT INTO federated_evidence_shares (
                share_id,
                manifest_hash,
                imported_at,
                exported_at,
                issuer,
                partner,
                signer_public_key,
                require_proofs,
                query_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(share_id) DO UPDATE SET
                manifest_hash = excluded.manifest_hash,
                imported_at = excluded.imported_at,
                exported_at = excluded.exported_at,
                issuer = excluded.issuer,
                partner = excluded.partner,
                signer_public_key = excluded.signer_public_key,
                require_proofs = excluded.require_proofs,
                query_json = excluded.query_json
            "#,
            params![
                import.share_id,
                import.manifest_hash,
                imported_at as i64,
                import.exported_at as i64,
                import.issuer,
                import.partner,
                import.signer_public_key,
                if import.require_proofs { 1_i64 } else { 0_i64 },
                import.query_json,
            ],
        )?;

        let lineage_by_capability = import
            .capability_lineage
            .iter()
            .map(|snapshot| (snapshot.capability_id.as_str(), snapshot))
            .collect::<BTreeMap<_, _>>();

        for snapshot in &import.capability_lineage {
            tx.execute(
                r#"
                INSERT INTO federated_share_capability_lineage (
                    share_id,
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(share_id, capability_id) DO UPDATE SET
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    issued_at = excluded.issued_at,
                    expires_at = excluded.expires_at,
                    grants_json = excluded.grants_json,
                    delegation_depth = excluded.delegation_depth,
                    parent_capability_id = excluded.parent_capability_id
                "#,
                params![
                    import.share_id,
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
        }

        for record in &import.tool_receipts {
            let attribution = extract_receipt_attribution(&record.receipt);
            let lineage_subject = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .map(|snapshot| snapshot.subject_key.as_str());
            let lineage_issuer = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .map(|snapshot| snapshot.issuer_key.as_str());
            tx.execute(
                r#"
                INSERT INTO federated_share_tool_receipts (
                    share_id,
                    seq,
                    receipt_id,
                    timestamp,
                    capability_id,
                    subject_key,
                    issuer_key,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(share_id, seq) DO UPDATE SET
                    receipt_id = excluded.receipt_id,
                    timestamp = excluded.timestamp,
                    capability_id = excluded.capability_id,
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    raw_json = excluded.raw_json
                "#,
                params![
                    import.share_id,
                    record.seq as i64,
                    record.receipt.id,
                    record.receipt.timestamp as i64,
                    record.receipt.capability_id,
                    attribution
                        .subject_key
                        .or_else(|| lineage_subject.map(ToOwned::to_owned)),
                    attribution
                        .issuer_key
                        .or_else(|| lineage_issuer.map(ToOwned::to_owned)),
                    serde_json::to_string(&record.receipt)?,
                ],
            )?;
        }

        tx.commit()?;

        Ok(FederatedEvidenceShareSummary {
            share_id: import.share_id.clone(),
            manifest_hash: import.manifest_hash.clone(),
            imported_at,
            exported_at: import.exported_at,
            issuer: import.issuer.clone(),
            partner: import.partner.clone(),
            signer_public_key: import.signer_public_key.clone(),
            require_proofs: import.require_proofs,
            tool_receipts: import.tool_receipts.len() as u64,
            capability_lineage: import.capability_lineage.len() as u64,
        })
    }

    pub fn get_federated_share_for_capability(
        &self,
        capability_id: &str,
    ) -> Result<
        Option<(
            FederatedEvidenceShareSummary,
            pact_kernel::CapabilitySnapshot,
        )>,
        ReceiptStoreError,
    > {
        let row = self
            .connection
            .query_row(
                r#"
                SELECT
                    s.share_id,
                    s.manifest_hash,
                    s.imported_at,
                    s.exported_at,
                    s.issuer,
                    s.partner,
                    s.signer_public_key,
                    s.require_proofs,
                    (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                    (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id),
                    l.capability_id,
                    l.subject_key,
                    l.issuer_key,
                    l.issued_at,
                    l.expires_at,
                    l.grants_json,
                    l.delegation_depth,
                    l.parent_capability_id
                FROM federated_share_capability_lineage l
                INNER JOIN federated_evidence_shares s ON s.share_id = l.share_id
                WHERE l.capability_id = ?1
                ORDER BY s.imported_at DESC, s.share_id DESC
                LIMIT 1
                "#,
                params![capability_id],
                |row| {
                    Ok((
                        FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        },
                        pact_kernel::CapabilitySnapshot {
                            capability_id: row.get::<_, String>(10)?,
                            subject_key: row.get::<_, String>(11)?,
                            issuer_key: row.get::<_, String>(12)?,
                            issued_at: row.get::<_, i64>(13)?.max(0) as u64,
                            expires_at: row.get::<_, i64>(14)?.max(0) as u64,
                            grants_json: row.get::<_, String>(15)?,
                            delegation_depth: row.get::<_, i64>(16)?.max(0) as u64,
                            parent_capability_id: row.get::<_, Option<String>>(17)?,
                        },
                    ))
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn record_federated_lineage_bridge(
        &mut self,
        local_capability_id: &str,
        parent_capability_id: &str,
        share_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.connection.execute(
            r#"
            INSERT INTO federated_lineage_bridges (
                local_capability_id,
                parent_capability_id,
                share_id
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(local_capability_id) DO UPDATE SET
                parent_capability_id = excluded.parent_capability_id,
                share_id = excluded.share_id
            "#,
            params![local_capability_id, parent_capability_id, share_id],
        )?;
        Ok(())
    }

    fn federated_lineage_bridge_parent(
        &self,
        local_capability_id: &str,
    ) -> Result<Option<String>, ReceiptStoreError> {
        self.connection
            .query_row(
                r#"
                SELECT parent_capability_id
                FROM federated_lineage_bridges
                WHERE local_capability_id = ?1
                "#,
                params![local_capability_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_combined_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<pact_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        if let Some(mut snapshot) =
            self.get_lineage(capability_id)
                .map_err(|error| match error {
                    pact_kernel::CapabilityLineageError::Sqlite(error) => {
                        ReceiptStoreError::Sqlite(error)
                    }
                    pact_kernel::CapabilityLineageError::Json(error) => {
                        ReceiptStoreError::Json(error)
                    }
                })?
        {
            if snapshot.parent_capability_id.is_none() {
                snapshot.parent_capability_id =
                    self.federated_lineage_bridge_parent(&snapshot.capability_id)?;
            }
            return Ok(Some(snapshot));
        }
        Ok(self
            .get_federated_share_for_capability(capability_id)?
            .map(|(_, snapshot)| snapshot))
    }

    pub fn get_combined_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<pact_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());
        let mut seen = BTreeSet::new();

        while let Some(current_capability_id) = current.take() {
            if !seen.insert(current_capability_id.clone()) || chain.len() >= 32 {
                break;
            }
            let Some(snapshot) = self.get_combined_lineage(&current_capability_id)? else {
                break;
            };
            current = snapshot.parent_capability_id.clone();
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }

    /// Append a PactReceipt and return the AUTOINCREMENT seq assigned.
    ///
    /// Returns 0 if the receipt was a duplicate (ON CONFLICT DO NOTHING).
    pub fn append_pact_receipt_returning_seq(
        &mut self,
        receipt: &PactReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        self.connection.execute(
            r#"
            INSERT INTO pact_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                attribution.subject_key,
                attribution.issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        let seq = self.connection.last_insert_rowid().max(0) as u64;
        Ok(seq)
    }

    /// Store a signed KernelCheckpoint in the kernel_checkpoints table.
    pub fn store_checkpoint(
        &mut self,
        checkpoint: &KernelCheckpoint,
    ) -> Result<(), ReceiptStoreError> {
        let statement_json = serde_json::to_string(&checkpoint.body)?;
        self.connection.execute(
            r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                checkpoint.body.checkpoint_seq as i64,
                checkpoint.body.batch_start_seq as i64,
                checkpoint.body.batch_end_seq as i64,
                checkpoint.body.tree_size as i64,
                checkpoint.body.merkle_root.to_hex(),
                checkpoint.body.issued_at as i64,
                statement_json,
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
            ],
        )?;
        Ok(())
    }

    /// Load a KernelCheckpoint by its checkpoint_seq.
    pub fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let row = self
            .connection
            .query_row(
                r#"
                SELECT statement_json, signature
                FROM kernel_checkpoints
                WHERE checkpoint_seq = ?1
                "#,
                params![checkpoint_seq as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        match row {
            None => Ok(None),
            Some((statement_json, signature_hex)) => {
                let body: KernelCheckpointBody = serde_json::from_str(&statement_json)?;
                let signature = Signature::from_hex(&signature_hex)
                    .map_err(|e| ReceiptStoreError::CryptoDecode(e.to_string()))?;
                Ok(Some(KernelCheckpoint { body, signature }))
            }
        }
    }

    /// Return canonical JSON bytes for receipts with seq in [start_seq, end_seq], ordered by seq.
    ///
    /// Uses RFC 8785 canonical JSON for deterministic Merkle leaf hashing.
    pub fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM pact_tool_receipts
            WHERE seq >= ?1 AND seq <= ?2
            ORDER BY seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt: PactReceipt = serde_json::from_str(&raw_json)?;
            let canonical = canonical_json_bytes(&receipt)
                .map_err(|e| ReceiptStoreError::Canonical(e.to_string()))?;
            result.push((seq.max(0) as u64, canonical));
        }
        Ok(result)
    }

    /// Return the current on-disk size of the database in bytes.
    ///
    /// Uses `PRAGMA page_count` and `PRAGMA page_size` to compute the size
    /// without requiring a filesystem stat, which is consistent in WAL mode.
    pub fn db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let page_count: i64 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        Ok((page_count.max(0) as u64) * (page_size.max(0) as u64))
    }

    /// Return the Unix timestamp (seconds) of the oldest receipt in the live
    /// database, or `None` if there are no receipts.
    pub fn oldest_receipt_timestamp(&self) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection.query_row(
            "SELECT MIN(timestamp) FROM pact_tool_receipts",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Archive all receipts with `timestamp < cutoff_unix_secs` to an external
    /// SQLite file, then delete them from the live database.
    ///
    /// Checkpoint rows whose entire batch (`batch_end_seq`) falls within the
    /// archived receipt range are also copied to the archive. Partial batches
    /// are never archived to avoid breaking inclusion proofs.
    ///
    /// Returns the number of receipt rows deleted from the live database.
    pub fn archive_receipts_before(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
    ) -> Result<u64, ReceiptStoreError> {
        // Escape single quotes in the path to safely embed it in an ATTACH statement.
        let escaped_path = archive_path.replace('\'', "''");

        // Attach the archive database.
        self.connection
            .execute_batch(&format!("ATTACH DATABASE '{escaped_path}' AS archive"))?;

        // Create archive tables with the same schema as the main database.
        self.connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS archive.pact_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.pact_child_receipts (
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

            CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT
            );
            "#,
        )?;

        let cutoff = cutoff_unix_secs as i64;

        // Copy qualifying receipts to the archive (ignore duplicates from prior runs).
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.pact_tool_receipts \
             SELECT * FROM main.pact_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.pact_child_receipts \
             SELECT * FROM main.pact_child_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.capability_lineage
             SELECT DISTINCT cl.*
             FROM main.capability_lineage cl
             INNER JOIN main.pact_tool_receipts r ON r.capability_id = cl.capability_id
             WHERE r.timestamp < ?1",
            params![cutoff],
        )?;

        // Find the maximum seq among archived receipts (for checkpoint filtering).
        let max_archived_seq: Option<i64> = self.connection.query_row(
            "SELECT MAX(seq) FROM main.pact_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
            |row| row.get(0),
        )?;

        if let Some(max_seq) = max_archived_seq {
            // Copy checkpoint rows whose full batch is covered by the archived receipts.
            // Never archive a checkpoint whose batch_end_seq exceeds the max archived seq
            // because that would leave a partial batch in the archive.
            self.connection.execute(
                "INSERT OR IGNORE INTO archive.kernel_checkpoints \
                 SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
            )?;

            // Verify that every checkpoint covering the archived range is now present
            // in the archive. If any checkpoint failed to transfer, refuse to delete the
            // receipts from the live database to preserve inclusion-proof integrity.
            let live_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
                |row| row.get(0),
            )?;
            let archive_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM archive.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
                |row| row.get(0),
            )?;
            if archive_count < live_count {
                // Detach the archive before returning the error to avoid leaving
                // the database in an attached state.
                let _ = self.connection.execute_batch("DETACH DATABASE archive");
                return Err(ReceiptStoreError::Canonical(format!(
                    "checkpoint co-archival incomplete: {live_count} checkpoints in live, \
                     only {archive_count} transferred to archive; aborting receipt deletion \
                     to preserve inclusion-proof integrity"
                )));
            }
        }

        // Delete archived receipts from the live database.
        let deleted = self.connection.execute(
            "DELETE FROM main.pact_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )? as u64;
        self.connection.execute(
            "DELETE FROM main.pact_child_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;

        // Detach the archive and checkpoint WAL.
        self.connection.execute_batch("DETACH DATABASE archive")?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

        Ok(deleted)
    }

    /// Check time and size thresholds and archive receipts if either is exceeded.
    ///
    /// - Time threshold: receipts older than `config.retention_days` days are archived.
    /// - Size threshold: if `db_size_bytes()` exceeds `config.max_size_bytes`, receipts
    ///   older than the median timestamp are archived (removes roughly half the receipts).
    ///
    /// Returns the number of receipt rows archived (0 if no threshold was exceeded).
    pub fn rotate_if_needed(&mut self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        // Check time threshold.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let time_cutoff = now.saturating_sub(config.retention_days.saturating_mul(86_400));
        let oldest = self.oldest_receipt_timestamp()?;

        if let Some(oldest_ts) = oldest {
            if oldest_ts < time_cutoff {
                return self.archive_receipts_before(time_cutoff, &config.archive_path);
            }
        }

        // Check size threshold.
        let size = self.db_size_bytes()?;
        if size > config.max_size_bytes {
            // Use the median timestamp as the cutoff to archive roughly half the receipts.
            let median_cutoff: Option<i64> = self
                .connection
                .query_row(
                    r#"
                    SELECT timestamp FROM pact_tool_receipts
                    ORDER BY timestamp
                    LIMIT 1
                    OFFSET (SELECT COUNT(*) FROM pact_tool_receipts) / 2
                    "#,
                    [],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(cutoff) = median_cutoff {
                return self.archive_receipts_before(cutoff.max(0) as u64, &config.archive_path);
            }
        }

        Ok(0)
    }

    /// Internal implementation for `query_receipts` (called from `receipt_query` module).
    ///
    /// Requires access to the private `connection` field, so it lives here in `receipt_store`.
    pub(crate) fn query_receipts_impl(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        // Validate the `outcome` filter against the known decision_kind values.
        // Silently accepting unknown values would return zero results and could
        // mask caller bugs; fail explicitly instead.
        const VALID_OUTCOMES: &[&str] = &["allow", "deny", "cancelled", "incomplete"];
        if let Some(outcome) = query.outcome.as_deref() {
            if !VALID_OUTCOMES.contains(&outcome) {
                return Err(ReceiptStoreError::InvalidOutcome(format!(
                    "unknown outcome filter {:?}; valid values are: allow, deny, cancelled, incomplete",
                    outcome
                )));
            }
        }

        let limit = query.limit.clamp(1, MAX_QUERY_LIMIT);

        // Both queries share the same 9 filter parameters.
        // Parameters:
        //   ?1  capability_id
        //   ?2  tool_server
        //   ?3  tool_name
        //   ?4  outcome (decision_kind)
        //   ?5  since (timestamp >=, inclusive)
        //   ?6  until (timestamp <=, inclusive)
        //   ?7  min_cost (json_extract cost_charged >=)
        //   ?8  max_cost (json_extract cost_charged <=)
        //   ?9  agent_subject (receipt subject_key, falling back to capability_lineage)
        //
        // Data query also uses:
        //   ?10 cursor (seq >, exclusive)
        //   ?11 limit
        //
        // When agent_subject is None, the LEFT JOIN produces NULL for cl.subject_key,
        // and the (?9 IS NULL OR ...) guard passes -- no rows are filtered out.
        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
              AND (?10 IS NULL OR r.seq > ?10)
            ORDER BY r.seq ASC
            LIMIT ?11
        "#;

        // Count query uses identical WHERE clause but no cursor and no LIMIT.
        // total_count reflects the full filtered set regardless of pagination.
        let count_sql = r#"
            SELECT COUNT(*)
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
        "#;

        let cap_id = query.capability_id.as_deref();
        let tool_srv = query.tool_server.as_deref();
        let tool_nm = query.tool_name.as_deref();
        let outcome = query.outcome.as_deref();
        let since = query.since.map(|v| v as i64);
        let until = query.until.map(|v| v as i64);
        let min_cost = query.min_cost.map(|v| v as i64);
        let max_cost = query.max_cost.map(|v| v as i64);
        let agent_sub = query.agent_subject.as_deref();
        // Convert cursor to signed i64 for SQLite. SQLite AUTOINCREMENT seq
        // values are bounded by i64::MAX; a cursor above that can never be
        // exceeded. Convert with a checked cast: on overflow return an empty
        // receipts page (the cursor excludes everything) while still reporting
        // the correct total_count for the uncursored filter set.
        let cursor_i64: Option<i64> = match query.cursor {
            None => None,
            Some(c) => match i64::try_from(c) {
                Ok(v) => Some(v),
                Err(_) => {
                    // cursor > i64::MAX: no AUTOINCREMENT seq can exceed it.
                    // Run only the count query (no cursor applied) and return empty.
                    let total_count: u64 = self
                        .connection
                        .query_row(
                            count_sql,
                            params![
                                cap_id, tool_srv, tool_nm, outcome, since, until, min_cost,
                                max_cost, agent_sub,
                            ],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|n| n.max(0) as u64)?;
                    return Ok(ReceiptQueryResult {
                        receipts: Vec::new(),
                        total_count,
                        next_cursor: None,
                    });
                }
            },
        };

        // Execute data query.
        let mut stmt = self.connection.prepare(data_sql)?;
        let rows = stmt.query_map(
            params![
                cap_id,
                tool_srv,
                tool_nm,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                agent_sub,
                cursor_i64,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt: PactReceipt = serde_json::from_str(&raw_json)?;
            receipts.push(StoredToolReceipt {
                seq: seq.max(0) as u64,
                receipt,
            });
        }

        // Execute count query (same filters, no cursor, no limit).
        let total_count: u64 = self
            .connection
            .query_row(
                count_sql,
                params![
                    cap_id, tool_srv, tool_nm, outcome, since, until, min_cost, max_cost,
                    agent_sub,
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)?;

        // next_cursor is Some(last_seq) when the page is full (more results may exist).
        let next_cursor = if receipts.len() == limit {
            receipts.last().map(|r| r.seq)
        } else {
            None
        };

        Ok(ReceiptQueryResult {
            receipts,
            total_count,
            next_cursor,
        })
    }

    pub fn query_receipt_analytics(
        &self,
        query: &ReceiptAnalyticsQuery,
    ) -> Result<ReceiptAnalyticsResponse, ReceiptStoreError> {
        let group_limit = query
            .group_limit
            .unwrap_or(50)
            .clamp(1, MAX_ANALYTICS_GROUP_LIMIT);
        let time_bucket = query.time_bucket.unwrap_or(AnalyticsTimeBucket::Day);
        let bucket_width = time_bucket.width_secs() as i64;

        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;
        let summary = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok(ReceiptAnalyticsMetrics::from_raw(
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                ))
            },
        )?;

        let by_agent_sql = r#"
            SELECT
                COALESCE(r.subject_key, cl.subject_key) AS subject_key,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND COALESCE(r.subject_key, cl.subject_key) IS NOT NULL
            GROUP BY COALESCE(r.subject_key, cl.subject_key)
            ORDER BY total_receipts DESC, subject_key ASC
            LIMIT ?7
        "#;
        let by_agent = self
            .connection
            .prepare(by_agent_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit as i64
                ],
                |row| {
                    Ok(AgentAnalyticsRow {
                        subject_key: row.get(0)?,
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_tool_sql = r#"
            SELECT
                r.tool_server,
                r.tool_name,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            GROUP BY r.tool_server, r.tool_name
            ORDER BY total_receipts DESC, r.tool_server ASC, r.tool_name ASC
            LIMIT ?7
        "#;
        let by_tool = self
            .connection
            .prepare(by_tool_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit as i64
                ],
                |row| {
                    Ok(ToolAnalyticsRow {
                        tool_server: row.get(0)?,
                        tool_name: row.get(1)?,
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                            row.get::<_, i64>(8)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_time_sql = r#"
            SELECT
                CAST((r.timestamp / ?7) * ?7 AS INTEGER) AS bucket_start,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            LIMIT ?8
        "#;
        let by_time = self
            .connection
            .prepare(by_time_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    bucket_width,
                    group_limit as i64
                ],
                |row| {
                    let bucket_start = row.get::<_, i64>(0)?.max(0) as u64;
                    Ok(TimeAnalyticsRow {
                        bucket_start,
                        bucket_end: bucket_start
                            .saturating_add(bucket_width.max(1) as u64)
                            .saturating_sub(1),
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ReceiptAnalyticsResponse {
            summary,
            by_agent,
            by_tool,
            by_time,
        })
    }

    pub fn query_cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, ReceiptStoreError> {
        let limit = query
            .limit
            .unwrap_or(100)
            .clamp(1, MAX_COST_ATTRIBUTION_LIMIT);
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let count_sql = r#"
            SELECT COUNT(*)
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND json_type(r.raw_json, '$.metadata.financial') = 'object'
        "#;

        let matching_receipts = self
            .connection
            .query_row(
                count_sql,
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value.max(0) as u64)?;

        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND json_type(r.raw_json, '$.metadata.financial') = 'object'
            ORDER BY r.seq ASC
        "#;

        let rows = self
            .connection
            .prepare(data_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, String>(1)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut receipts = Vec::with_capacity(rows.len().min(limit));
        let mut by_root = BTreeMap::<String, RootAggregate>::new();
        let mut by_leaf = BTreeMap::<(String, String), LeafAggregate>::new();
        let mut distinct_roots = BTreeSet::new();
        let mut distinct_leaves = BTreeSet::new();
        let mut total_cost_charged = 0_u64;
        let mut total_attempted_cost = 0_u64;
        let mut max_delegation_depth = 0_u64;
        let mut lineage_gap_count = 0_u64;

        for (seq, raw_json) in rows {
            let receipt: PactReceipt = serde_json::from_str(&raw_json)?;
            let Some(financial) = extract_financial_metadata(&receipt) else {
                continue;
            };
            let attribution = extract_receipt_attribution(&receipt);
            let chain_snapshots = self
                .get_combined_delegation_chain(&receipt.capability_id)
                .unwrap_or_default();
            let lineage_complete = chain_is_complete(&receipt.capability_id, &chain_snapshots);
            if !lineage_complete {
                lineage_gap_count = lineage_gap_count.saturating_add(1);
            }

            let chain = chain_snapshots
                .iter()
                .map(|snapshot| CostAttributionChainHop {
                    capability_id: snapshot.capability_id.clone(),
                    subject_key: snapshot.subject_key.clone(),
                    issuer_key: snapshot.issuer_key.clone(),
                    delegation_depth: snapshot.delegation_depth,
                    parent_capability_id: snapshot.parent_capability_id.clone(),
                })
                .collect::<Vec<_>>();

            let root_subject_key = chain_snapshots
                .first()
                .map(|snapshot| snapshot.subject_key.clone())
                .or_else(|| Some(financial.root_budget_holder.clone()));
            let leaf_subject_key = attribution.subject_key.clone().or_else(|| {
                chain_snapshots
                    .last()
                    .map(|snapshot| snapshot.subject_key.clone())
            });
            let attempted_cost = financial.attempted_cost.unwrap_or(0);
            let decision = decision_kind(&receipt.decision).to_string();

            total_cost_charged = total_cost_charged.saturating_add(financial.cost_charged);
            total_attempted_cost = total_attempted_cost.saturating_add(attempted_cost);
            max_delegation_depth = max_delegation_depth.max(financial.delegation_depth as u64);

            if let Some(root_key) = root_subject_key.clone() {
                distinct_roots.insert(root_key.clone());
                let root_entry = by_root.entry(root_key.clone()).or_default();
                root_entry.receipt_count = root_entry.receipt_count.saturating_add(1);
                root_entry.total_cost_charged = root_entry
                    .total_cost_charged
                    .saturating_add(financial.cost_charged);
                root_entry.total_attempted_cost = root_entry
                    .total_attempted_cost
                    .saturating_add(attempted_cost);
                root_entry.max_delegation_depth = root_entry
                    .max_delegation_depth
                    .max(financial.delegation_depth as u64);

                if let Some(leaf_key) = leaf_subject_key.clone() {
                    root_entry.leaf_subjects.insert(leaf_key.clone());
                    let leaf_entry = by_leaf.entry((root_key, leaf_key)).or_default();
                    leaf_entry.receipt_count = leaf_entry.receipt_count.saturating_add(1);
                    leaf_entry.total_cost_charged = leaf_entry
                        .total_cost_charged
                        .saturating_add(financial.cost_charged);
                    leaf_entry.total_attempted_cost = leaf_entry
                        .total_attempted_cost
                        .saturating_add(attempted_cost);
                    leaf_entry.max_delegation_depth = leaf_entry
                        .max_delegation_depth
                        .max(financial.delegation_depth as u64);
                }
            }

            if let Some(leaf_key) = leaf_subject_key.clone() {
                distinct_leaves.insert(leaf_key);
            }

            if receipts.len() < limit {
                receipts.push(CostAttributionReceiptRow {
                    seq,
                    receipt_id: receipt.id.clone(),
                    timestamp: receipt.timestamp,
                    capability_id: receipt.capability_id.clone(),
                    tool_server: receipt.tool_server.clone(),
                    tool_name: receipt.tool_name.clone(),
                    decision_kind: decision,
                    root_subject_key,
                    leaf_subject_key,
                    grant_index: Some(financial.grant_index),
                    delegation_depth: financial.delegation_depth as u64,
                    cost_charged: financial.cost_charged,
                    attempted_cost: financial.attempted_cost,
                    currency: financial.currency.clone(),
                    budget_total: Some(financial.budget_total),
                    budget_remaining: Some(financial.budget_remaining),
                    settlement_status: Some(financial.settlement_status),
                    payment_reference: financial.payment_reference.clone(),
                    lineage_complete,
                    chain,
                });
            }
        }

        let mut by_root = by_root
            .into_iter()
            .map(|(root_subject_key, aggregate)| RootCostAttributionRow {
                root_subject_key,
                receipt_count: aggregate.receipt_count,
                total_cost_charged: aggregate.total_cost_charged,
                total_attempted_cost: aggregate.total_attempted_cost,
                distinct_leaf_subjects: aggregate.leaf_subjects.len() as u64,
                max_delegation_depth: aggregate.max_delegation_depth,
            })
            .collect::<Vec<_>>();
        by_root.sort_by(|left, right| {
            right
                .total_cost_charged
                .cmp(&left.total_cost_charged)
                .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
        });

        let mut by_leaf = by_leaf
            .into_iter()
            .map(
                |((root_subject_key, leaf_subject_key), aggregate)| LeafCostAttributionRow {
                    root_subject_key,
                    leaf_subject_key,
                    receipt_count: aggregate.receipt_count,
                    total_cost_charged: aggregate.total_cost_charged,
                    total_attempted_cost: aggregate.total_attempted_cost,
                    max_delegation_depth: aggregate.max_delegation_depth,
                },
            )
            .collect::<Vec<_>>();
        by_leaf.sort_by(|left, right| {
            right
                .total_cost_charged
                .cmp(&left.total_cost_charged)
                .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
                .then_with(|| left.leaf_subject_key.cmp(&right.leaf_subject_key))
        });

        Ok(CostAttributionReport {
            summary: CostAttributionSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                total_cost_charged,
                total_attempted_cost,
                max_delegation_depth,
                distinct_root_subjects: distinct_roots.len() as u64,
                distinct_leaf_subjects: distinct_leaves.len() as u64,
                lineage_gap_count,
                truncated: matching_receipts > receipts.len() as u64,
            },
            by_root,
            by_leaf,
            receipts,
        })
    }

    pub fn query_shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, ReceiptStoreError> {
        let limit = query.limit_or_default();
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let issuer = query.issuer.as_deref();
        let partner = query.partner.as_deref();

        let rows = self
            .connection
            .prepare(
                r#"
                SELECT r.receipt_id, r.timestamp, r.capability_id, r.decision_kind
                FROM pact_tool_receipts r
                LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
                WHERE (?1 IS NULL OR r.capability_id = ?1)
                  AND (?2 IS NULL OR r.tool_server = ?2)
                  AND (?3 IS NULL OR r.tool_name = ?3)
                  AND (?4 IS NULL OR r.timestamp >= ?4)
                  AND (?5 IS NULL OR r.timestamp <= ?5)
                  AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
                ORDER BY r.seq ASC
                "#,
            )?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut share_cache = BTreeMap::<String, Option<FederatedEvidenceShareSummary>>::new();
        let mut references = BTreeMap::<(String, String), SharedEvidenceReferenceRow>::new();
        let mut matched_local_receipts = BTreeSet::<String>::new();

        for (receipt_id, timestamp, local_capability_id, decision) in rows {
            let chain = self.get_combined_delegation_chain(&local_capability_id)?;
            if chain.is_empty() {
                continue;
            }

            let mut matched_this_receipt = false;
            for (index, snapshot) in chain.iter().enumerate() {
                let share = match share_cache.get(&snapshot.capability_id) {
                    Some(cached) => cached.clone(),
                    None => {
                        let loaded = self
                            .get_federated_share_for_capability(&snapshot.capability_id)?
                            .map(|(share, _)| share);
                        share_cache.insert(snapshot.capability_id.clone(), loaded.clone());
                        loaded
                    }
                };
                let Some(share) = share else {
                    continue;
                };
                if issuer.is_some_and(|expected| share.issuer != expected) {
                    continue;
                }
                if partner.is_some_and(|expected| share.partner != expected) {
                    continue;
                }

                let local_anchor_capability_id =
                    chain.iter().skip(index + 1).find_map(|candidate| {
                        match share_cache.get(&candidate.capability_id) {
                            Some(Some(_)) => None,
                            Some(None) => Some(candidate.capability_id.clone()),
                            None => {
                                let loaded = self
                                    .get_federated_share_for_capability(&candidate.capability_id)
                                    .ok()
                                    .and_then(|value| value.map(|(share, _)| share));
                                share_cache.insert(candidate.capability_id.clone(), loaded.clone());
                                if loaded.is_some() {
                                    None
                                } else {
                                    Some(candidate.capability_id.clone())
                                }
                            }
                        }
                    });

                let key = (share.share_id.clone(), snapshot.capability_id.clone());
                let entry = references
                    .entry(key)
                    .or_insert_with(|| SharedEvidenceReferenceRow {
                        share: share.clone(),
                        capability_id: snapshot.capability_id.clone(),
                        subject_key: snapshot.subject_key.clone(),
                        issuer_key: snapshot.issuer_key.clone(),
                        delegation_depth: snapshot.delegation_depth,
                        parent_capability_id: snapshot.parent_capability_id.clone(),
                        local_anchor_capability_id: local_anchor_capability_id.clone(),
                        matched_local_receipts: 0,
                        allow_count: 0,
                        deny_count: 0,
                        cancelled_count: 0,
                        incomplete_count: 0,
                        first_seen: Some(timestamp),
                        last_seen: Some(timestamp),
                    });

                entry.local_anchor_capability_id = entry
                    .local_anchor_capability_id
                    .clone()
                    .or(local_anchor_capability_id);
                entry.matched_local_receipts = entry.matched_local_receipts.saturating_add(1);
                entry.first_seen = Some(
                    entry
                        .first_seen
                        .map_or(timestamp, |value| value.min(timestamp)),
                );
                entry.last_seen = Some(
                    entry
                        .last_seen
                        .map_or(timestamp, |value| value.max(timestamp)),
                );
                match decision.as_str() {
                    "allow" => entry.allow_count = entry.allow_count.saturating_add(1),
                    "deny" => entry.deny_count = entry.deny_count.saturating_add(1),
                    "cancelled" => entry.cancelled_count = entry.cancelled_count.saturating_add(1),
                    _ => entry.incomplete_count = entry.incomplete_count.saturating_add(1),
                }
                matched_this_receipt = true;
            }

            if matched_this_receipt {
                matched_local_receipts.insert(receipt_id);
            }
        }

        let mut returned_references = references.into_values().collect::<Vec<_>>();
        returned_references.sort_by(|left, right| {
            right
                .matched_local_receipts
                .cmp(&left.matched_local_receipts)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
                .then_with(|| right.share.imported_at.cmp(&left.share.imported_at))
                .then_with(|| left.share.share_id.cmp(&right.share.share_id))
                .then_with(|| left.capability_id.cmp(&right.capability_id))
        });

        let mut distinct_shares = BTreeMap::<String, FederatedEvidenceShareSummary>::new();
        let mut distinct_remote_subjects = BTreeSet::<String>::new();
        for reference in &returned_references {
            distinct_shares
                .entry(reference.share.share_id.clone())
                .or_insert_with(|| reference.share.clone());
            distinct_remote_subjects.insert(reference.subject_key.clone());
        }

        let matching_references = returned_references.len() as u64;
        let truncated = returned_references.len() > limit;
        if truncated {
            returned_references.truncate(limit);
        }

        Ok(SharedEvidenceReferenceReport {
            summary: SharedEvidenceReferenceSummary {
                matching_shares: distinct_shares.len() as u64,
                matching_references,
                matching_local_receipts: matched_local_receipts.len() as u64,
                remote_tool_receipts: distinct_shares
                    .values()
                    .map(|share| share.tool_receipts)
                    .sum(),
                remote_lineage_records: distinct_shares
                    .values()
                    .map(|share| share.capability_lineage)
                    .sum(),
                distinct_remote_subjects: distinct_remote_subjects.len() as u64,
                proof_required_shares: distinct_shares
                    .values()
                    .filter(|share| share.require_proofs)
                    .count() as u64,
                truncated,
            },
            references: returned_references,
        })
    }

    pub fn query_compliance_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ComplianceReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN EXISTS(
                            SELECT 1
                            FROM kernel_checkpoints kc
                            WHERE r.seq BETWEEN kc.batch_start_seq AND kc.batch_end_seq
                        ) THEN 1
                        ELSE 0
                    END
                ), 0) AS evidence_ready_receipts,
                COALESCE(SUM(CASE WHEN cl.capability_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS lineage_covered_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0) AS pending_settlement_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0) AS failed_settlement_receipts
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            evidence_ready_receipts,
            lineage_covered_receipts,
            pending_settlement_receipts,
            failed_settlement_receipts,
        ) = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                ))
            },
        )?;

        let uncheckpointed_receipts = matching_receipts.saturating_sub(evidence_ready_receipts);
        let lineage_gap_receipts = matching_receipts.saturating_sub(lineage_covered_receipts);
        let export_query = query.to_evidence_export_query();

        Ok(ComplianceReport {
            matching_receipts,
            evidence_ready_receipts,
            uncheckpointed_receipts,
            checkpoint_coverage_rate: ratio_option(evidence_ready_receipts, matching_receipts),
            lineage_covered_receipts,
            lineage_gap_receipts,
            lineage_coverage_rate: ratio_option(lineage_covered_receipts, matching_receipts),
            pending_settlement_receipts,
            failed_settlement_receipts,
            direct_evidence_export_supported: query.direct_evidence_export_supported(),
            child_receipt_scope: export_query.child_receipt_scope(),
            proofs_complete: uncheckpointed_receipts == 0,
            export_query: export_query.clone(),
            export_scope_note: compliance_export_scope_note(query, &export_query),
        })
    }
}

#[derive(Default)]
struct RootAggregate {
    receipt_count: u64,
    total_cost_charged: u64,
    total_attempted_cost: u64,
    max_delegation_depth: u64,
    leaf_subjects: BTreeSet<String>,
}

#[derive(Default)]
struct LeafAggregate {
    receipt_count: u64,
    total_cost_charged: u64,
    total_attempted_cost: u64,
    max_delegation_depth: u64,
}

#[derive(Default)]
struct ReceiptAttributionColumns {
    subject_key: Option<String>,
    issuer_key: Option<String>,
    grant_index: Option<u32>,
}

fn extract_receipt_attribution(receipt: &PactReceipt) -> ReceiptAttributionColumns {
    let Some(metadata) = receipt.metadata.as_ref() else {
        return ReceiptAttributionColumns::default();
    };

    let attribution = metadata
        .get("attribution")
        .cloned()
        .and_then(|value| serde_json::from_value::<ReceiptAttributionMetadata>(value).ok());
    let grant_index = attribution
        .as_ref()
        .and_then(|value| value.grant_index)
        .or_else(|| {
            metadata
                .get("financial")
                .and_then(|value| value.get("grant_index"))
                .and_then(serde_json::Value::as_u64)
                .map(|value| value as u32)
        });

    ReceiptAttributionColumns {
        subject_key: attribution.as_ref().map(|value| value.subject_key.clone()),
        issuer_key: attribution.as_ref().map(|value| value.issuer_key.clone()),
        grant_index,
    }
}

fn extract_financial_metadata(receipt: &PactReceipt) -> Option<FinancialReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .and_then(|value| serde_json::from_value::<FinancialReceiptMetadata>(value).ok())
}

fn chain_is_complete(capability_id: &str, chain: &[pact_kernel::CapabilitySnapshot]) -> bool {
    if chain.is_empty() {
        return false;
    }
    let Some(leaf) = chain.last() else {
        return false;
    };
    if leaf.capability_id != capability_id {
        return false;
    }
    if chain
        .first()
        .and_then(|snapshot| snapshot.parent_capability_id.as_ref())
        .is_some()
    {
        return false;
    }
    if chain.windows(2).any(|window| {
        window[1].parent_capability_id.as_deref() != Some(window[0].capability_id.as_str())
    }) {
        return false;
    }
    if leaf.parent_capability_id.is_some() && chain.len() == 1 {
        return false;
    }
    if leaf.delegation_depth as usize != chain.len().saturating_sub(1) {
        return false;
    }
    true
}

fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn compliance_export_scope_note(
    query: &OperatorReportQuery,
    export_query: &EvidenceExportQuery,
) -> Option<String> {
    let mut notes = Vec::new();

    if !query.direct_evidence_export_supported() {
        notes.push(
            "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window".to_string(),
        );
    }

    match export_query.child_receipt_scope() {
        EvidenceChildReceiptScope::TimeWindowContextOnly => notes.push(
            "child receipts are included only as time-window context for this export scope".to_string(),
        ),
        EvidenceChildReceiptScope::OmittedNoJoinPath => notes.push(
            "child receipts are omitted for this export scope because no truthful capability/agent join exists yet".to_string(),
        ),
        EvidenceChildReceiptScope::FullQueryWindow => {}
    }

    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" "))
    }
}

fn ensure_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(pact_tool_receipts)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "subject_key") {
        connection.execute(
            "ALTER TABLE pact_tool_receipts ADD COLUMN subject_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "issuer_key") {
        connection.execute(
            "ALTER TABLE pact_tool_receipts ADD COLUMN issuer_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "grant_index") {
        connection.execute(
            "ALTER TABLE pact_tool_receipts ADD COLUMN grant_index INTEGER",
            [],
        )?;
    }

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_subject ON pact_tool_receipts(subject_key)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_grant ON pact_tool_receipts(capability_id, grant_index)",
        [],
    )?;
    Ok(())
}

fn backfill_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        UPDATE pact_tool_receipts
        SET grant_index = CAST(COALESCE(
            json_extract(raw_json, '$.metadata.attribution.grant_index'),
            json_extract(raw_json, '$.metadata.financial.grant_index')
        ) AS INTEGER)
        WHERE grant_index IS NULL
          AND COALESCE(
                json_extract(raw_json, '$.metadata.attribution.grant_index'),
                json_extract(raw_json, '$.metadata.financial.grant_index')
              ) IS NOT NULL;

        UPDATE pact_tool_receipts
        SET subject_key = COALESCE(
            subject_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
            (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = pact_tool_receipts.capability_id)
        )
        WHERE subject_key IS NULL;

        UPDATE pact_tool_receipts
        SET issuer_key = COALESCE(
            issuer_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
            (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = pact_tool_receipts.capability_id)
        )
        WHERE issuer_key IS NULL;
        "#,
    )?;
    Ok(())
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_pact_receipt(&mut self, receipt: &PactReceipt) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        self.connection.execute(
            r#"
            INSERT INTO pact_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                attribution.subject_key,
                attribution.issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }

    fn append_pact_receipt_returning_seq(
        &mut self,
        receipt: &PactReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        Ok(Some(SqliteReceiptStore::append_pact_receipt_returning_seq(
            self, receipt,
        )?))
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        SqliteReceiptStore::receipts_canonical_bytes_range(self, start_seq, end_seq)
    }

    fn store_checkpoint(&mut self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::store_checkpoint(self, checkpoint)
    }

    fn record_capability_snapshot(
        &mut self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::record_capability_snapshot(self, token, parent_capability_id).map_err(
            |error| match error {
                pact_kernel::CapabilityLineageError::Sqlite(error) => {
                    ReceiptStoreError::Sqlite(error)
                }
                pact_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            },
        )
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection.execute(
            r#"
            INSERT INTO pact_child_receipts (
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                terminal_state_kind(&receipt.terminal_state),
                receipt.policy_hash,
                receipt.outcome_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }
}

fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use pact_core::capability::{
        CapabilityToken, CapabilityTokenBody, MonetaryAmount, Operation, PactScope, ToolGrant,
    };
    use pact_core::crypto::Keypair;
    use pact_core::receipt::{
        ChildRequestReceipt, ChildRequestReceiptBody, Decision, FinancialReceiptMetadata,
        PactReceipt, PactReceiptBody, ReceiptAttributionMetadata, SettlementStatus, ToolCallAction,
    };
    use pact_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
    use pact_kernel::{build_checkpoint, AnalyticsTimeBucket, ReceiptAnalyticsQuery};

    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn sample_receipt() -> PactReceipt {
        let keypair = Keypair::generate();
        PactReceipt::sign(
            PactReceiptBody {
                id: "rcpt-test-001".to_string(),
                timestamp: 1,
                capability_id: "cap-1".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    fn sample_child_receipt() -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            ChildRequestReceiptBody {
                id: "child-rcpt-test-001".to_string(),
                timestamp: 2,
                session_id: SessionId::new("sess-1"),
                parent_request_id: RequestId::new("parent-1"),
                request_id: RequestId::new("child-1"),
                operation_kind: OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: "outcome-1".to_string(),
                policy_hash: "policy-1".to_string(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    #[test]
    fn sqlite_receipt_store_persists_across_reopen() {
        let path = unique_db_path("pact-receipts");
        {
            let mut store = SqliteReceiptStore::open(&path).unwrap();
            store.append_pact_receipt(&sample_receipt()).unwrap();
            store.append_child_receipt(&sample_child_receipt()).unwrap();
            assert_eq!(store.tool_receipt_count().unwrap(), 1);
            assert_eq!(store.child_receipt_count().unwrap(), 1);
        }

        let reopened = SqliteReceiptStore::open(&path).unwrap();
        assert_eq!(reopened.tool_receipt_count().unwrap(), 1);
        assert_eq!(reopened.child_receipt_count().unwrap(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_receipt_store_lists_filtered_receipts() {
        let path = unique_db_path("pact-receipts-filtered");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        store.append_pact_receipt(&sample_receipt()).unwrap();
        store.append_child_receipt(&sample_child_receipt()).unwrap();

        let tool_receipts = store
            .list_tool_receipts(
                10,
                Some("cap-1"),
                Some("shell"),
                Some("bash"),
                Some("allow"),
            )
            .unwrap();
        assert_eq!(tool_receipts.len(), 1);
        assert_eq!(tool_receipts[0].capability_id, "cap-1");
        assert_eq!(tool_receipts[0].tool_name, "bash");

        let child_receipts = store
            .list_child_receipts(
                10,
                Some("sess-1"),
                Some("parent-1"),
                Some("child-1"),
                Some("create_message"),
                Some("completed"),
            )
            .unwrap();
        assert_eq!(child_receipts.len(), 1);
        assert_eq!(child_receipts[0].session_id.as_str(), "sess-1");
        assert_eq!(child_receipts[0].request_id.as_str(), "child-1");

        let _ = fs::remove_file(path);
    }

    fn sample_receipt_with_id(id: &str) -> PactReceipt {
        let keypair = Keypair::generate();
        PactReceipt::sign(
            PactReceiptBody {
                id: id.to_string(),
                timestamp: 1,
                capability_id: "cap-1".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    #[test]
    fn open_creates_kernel_checkpoints_table() {
        let path = unique_db_path("pact-receipts-cp-table");
        let store = SqliteReceiptStore::open(&path).unwrap();
        // Query the table to confirm it exists.
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_pact_receipt_returning_seq_returns_seq() {
        let path = unique_db_path("pact-receipts-seq");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let receipt = sample_receipt_with_id("rcpt-seq-001");
        let seq = store.append_pact_receipt_returning_seq(&receipt).unwrap();
        assert!(seq > 0, "seq should be non-zero for a new insert");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_100_receipts_seqs_span_1_to_100() {
        let path = unique_db_path("pact-receipts-100");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let mut seqs = Vec::new();
        for i in 0..100usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-{i:04}"));
            let seq = store.append_pact_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }
        assert_eq!(seqs[0], 1);
        assert_eq!(seqs[99], 100);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn store_and_load_checkpoint_by_seq() {
        let path = unique_db_path("pact-receipts-cp-store");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        // Append 5 receipts.
        let mut seqs = Vec::new();
        for i in 0..5usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-store-{i}"));
            let seq = store.append_pact_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }

        // Build checkpoint.
        let kp = Keypair::generate();
        let bytes: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("receipt-bytes-{i}").into_bytes())
            .collect();
        let cp = build_checkpoint(1, seqs[0], seqs[4], &bytes, &kp).unwrap();

        // Store and retrieve.
        store.store_checkpoint(&cp).unwrap();
        let loaded = store.load_checkpoint_by_seq(1).unwrap();
        assert!(loaded.is_some(), "checkpoint should be loadable");
        let loaded = loaded.unwrap();
        assert_eq!(loaded.body.checkpoint_seq, 1);
        assert_eq!(loaded.body.tree_size, 5);
        assert_eq!(loaded.body.batch_start_seq, seqs[0]);
        assert_eq!(loaded.body.batch_end_seq, seqs[4]);
        assert_eq!(
            loaded.signature.to_hex(),
            cp.signature.to_hex(),
            "signature should round-trip"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_checkpoint_by_seq_returns_none_for_missing() {
        let path = unique_db_path("pact-receipts-cp-missing");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let result = store.load_checkpoint_by_seq(999).unwrap();
        assert!(result.is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn receipts_canonical_bytes_range_returns_correct_count() {
        let path = unique_db_path("pact-receipts-canon-range");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..10usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-canon-{i}"));
            store.append_pact_receipt_returning_seq(&receipt).unwrap();
        }

        // Fetch seqs 3..=7 (5 receipts).
        let range = store.receipts_canonical_bytes_range(3, 7).unwrap();
        assert_eq!(range.len(), 5, "should return 5 receipts in range 3..=7");
        assert_eq!(range[0].0, 3);
        assert_eq!(range[4].0, 7);

        // Verify all bytes are non-empty canonical JSON.
        for (_, bytes) in &range {
            assert!(!bytes.is_empty());
            // Should be valid JSON.
            let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn receipt_analytics_groups_by_agent_tool_and_time() {
        let path = unique_db_path("pact-receipts-analytics");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let keypair = Keypair::generate();

        let make_receipt = |id: &str,
                            subject_key: &str,
                            tool_server: &str,
                            tool_name: &str,
                            decision: Decision,
                            timestamp: u64,
                            cost_charged: u64,
                            attempted_cost: Option<u64>| {
            let financial = if cost_charged > 0 || attempted_cost.is_some() {
                Some(FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged,
                    currency: "USD".to_string(),
                    budget_remaining: 1_000,
                    budget_total: 2_000,
                    delegation_depth: 0,
                    root_budget_holder: "root-agent".to_string(),
                    payment_reference: None,
                    settlement_status: if attempted_cost.is_some() {
                        SettlementStatus::NotApplicable
                    } else {
                        SettlementStatus::Settled
                    },
                    cost_breakdown: None,
                    attempted_cost,
                })
            } else {
                None
            };
            let metadata = serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: "issuer-key".to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": financial,
            });

            PactReceipt::sign(
                PactReceiptBody {
                    id: id.to_string(),
                    timestamp,
                    capability_id: format!("cap-{subject_key}"),
                    tool_server: tool_server.to_string(),
                    tool_name: tool_name.to_string(),
                    action: ToolCallAction {
                        parameters: serde_json::json!({}),
                        parameter_hash: "abc123".to_string(),
                    },
                    decision,
                    content_hash: format!("content-{id}"),
                    policy_hash: "policy-analytics".to_string(),
                    evidence: Vec::new(),
                    metadata: Some(metadata),
                    kernel_key: keypair.public_key(),
                },
                &keypair,
            )
            .unwrap()
        };

        store
            .append_pact_receipt(&make_receipt(
                "analytics-1",
                "agent-a",
                "shell",
                "bash",
                Decision::Allow,
                86_400,
                100,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "analytics-2",
                "agent-a",
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                86_450,
                0,
                Some(50),
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "analytics-3",
                "agent-b",
                "files",
                "read",
                Decision::Incomplete {
                    reason: "stream ended".to_string(),
                },
                172_800,
                0,
                None,
            ))
            .unwrap();

        let analytics = store
            .query_receipt_analytics(&ReceiptAnalyticsQuery {
                group_limit: Some(10),
                time_bucket: Some(AnalyticsTimeBucket::Day),
                ..ReceiptAnalyticsQuery::default()
            })
            .unwrap();

        assert_eq!(analytics.summary.total_receipts, 3);
        assert_eq!(analytics.summary.allow_count, 1);
        assert_eq!(analytics.summary.deny_count, 1);
        assert_eq!(analytics.summary.incomplete_count, 1);
        assert_eq!(analytics.summary.total_cost_charged, 100);
        assert_eq!(analytics.summary.total_attempted_cost, 50);
        assert_eq!(
            analytics.summary.reliability_score,
            Some(0.5),
            "allow / (allow + incomplete)"
        );
        assert_eq!(
            analytics.summary.compliance_rate,
            Some(2.0 / 3.0),
            "1 - deny / total"
        );
        assert_eq!(
            analytics.summary.budget_utilization_rate,
            Some(100.0 / 150.0)
        );

        assert_eq!(analytics.by_agent.len(), 2);
        assert_eq!(analytics.by_agent[0].subject_key, "agent-a");
        assert_eq!(analytics.by_agent[0].metrics.total_receipts, 2);

        assert_eq!(analytics.by_tool.len(), 2);
        assert_eq!(analytics.by_tool[0].tool_server, "shell");
        assert_eq!(analytics.by_tool[0].tool_name, "bash");
        assert_eq!(analytics.by_tool[0].metrics.total_receipts, 2);

        assert_eq!(analytics.by_time.len(), 2);
        assert_eq!(analytics.by_time[0].bucket_start, 86_400);
        assert_eq!(analytics.by_time[1].bucket_start, 172_800);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cost_attribution_report_aggregates_matching_corpus_and_limits_detail_rows() {
        let path = unique_db_path("pact-receipts-cost-attribution");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let issuer_kp = Keypair::generate();
        let root_kp = Keypair::generate();
        let leaf_kp = Keypair::generate();
        let receipt_kp = Keypair::generate();
        let root_hex = root_kp.public_key().to_hex();
        let leaf_hex = leaf_kp.public_key().to_hex();
        let issuer_hex = issuer_kp.public_key().to_hex();

        let root = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-root".to_string(),
                issuer: issuer_kp.public_key(),
                subject: root_kp.public_key(),
                scope: PactScope::default(),
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer_kp,
        )
        .unwrap();
        let child = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-child".to_string(),
                issuer: issuer_kp.public_key(),
                subject: leaf_kp.public_key(),
                scope: PactScope::default(),
                issued_at: 1_100,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer_kp,
        )
        .unwrap();

        store.record_capability_snapshot(&root, None).unwrap();
        store
            .record_capability_snapshot(&child, Some("cap-root"))
            .unwrap();

        let make_financial_receipt =
            |id: &str,
             capability_id: &str,
             subject_key: Option<String>,
             root_budget_holder: &str,
             delegation_depth: u32,
             timestamp: u64,
             decision: Decision,
             cost_charged: u64,
             attempted_cost: Option<u64>| {
                let attribution = subject_key.map(|subject_key| ReceiptAttributionMetadata {
                    subject_key,
                    issuer_key: issuer_hex.clone(),
                    delegation_depth,
                    grant_index: Some(0),
                });
                let metadata = serde_json::json!({
                    "attribution": attribution,
                    "financial": FinancialReceiptMetadata {
                        grant_index: 0,
                        cost_charged,
                        currency: "USD".to_string(),
                        budget_remaining: 900,
                        budget_total: 1_000,
                        delegation_depth,
                        root_budget_holder: root_budget_holder.to_string(),
                        payment_reference: None,
                        settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                            SettlementStatus::NotApplicable
                        } else {
                            SettlementStatus::Settled
                        },
                        cost_breakdown: None,
                        attempted_cost,
                    }
                });

                PactReceipt::sign(
                    PactReceiptBody {
                        id: id.to_string(),
                        timestamp,
                        capability_id: capability_id.to_string(),
                        tool_server: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        action: ToolCallAction {
                            parameters: serde_json::json!({}),
                            parameter_hash: format!("param-{id}"),
                        },
                        decision,
                        content_hash: format!("content-{id}"),
                        policy_hash: "policy-cost".to_string(),
                        evidence: Vec::new(),
                        metadata: Some(metadata),
                        kernel_key: receipt_kp.public_key(),
                    },
                    &receipt_kp,
                )
                .unwrap()
            };

        store
            .append_pact_receipt(&make_financial_receipt(
                "cost-1",
                "cap-child",
                Some(leaf_hex.clone()),
                &root_hex,
                1,
                1_200,
                Decision::Allow,
                125,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_financial_receipt(
                "cost-2",
                "cap-child",
                Some(leaf_hex.clone()),
                &root_hex,
                1,
                1_201,
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                0,
                Some(75),
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_financial_receipt(
                "cost-3",
                "cap-orphan",
                None,
                "orphan-root",
                2,
                1_202,
                Decision::Allow,
                50,
                None,
            ))
            .unwrap();

        let report = store
            .query_cost_attribution_report(&CostAttributionQuery {
                limit: Some(1),
                ..CostAttributionQuery::default()
            })
            .unwrap();

        assert_eq!(report.summary.matching_receipts, 3);
        assert_eq!(report.summary.returned_receipts, 1);
        assert_eq!(report.summary.total_cost_charged, 175);
        assert_eq!(report.summary.total_attempted_cost, 75);
        assert_eq!(report.summary.max_delegation_depth, 2);
        assert_eq!(report.summary.distinct_root_subjects, 2);
        assert_eq!(report.summary.distinct_leaf_subjects, 1);
        assert_eq!(report.summary.lineage_gap_count, 1);
        assert!(report.summary.truncated);

        assert_eq!(report.by_root.len(), 2);
        assert_eq!(
            report.by_root[0].root_subject_key.as_str(),
            root_hex.as_str()
        );
        assert_eq!(report.by_root[0].receipt_count, 2);
        assert_eq!(report.by_root[0].total_cost_charged, 125);
        assert_eq!(report.by_root[0].total_attempted_cost, 75);
        assert_eq!(report.by_root[0].distinct_leaf_subjects, 1);

        assert_eq!(report.by_leaf.len(), 1);
        assert_eq!(
            report.by_leaf[0].root_subject_key.as_str(),
            root_hex.as_str()
        );
        assert_eq!(
            report.by_leaf[0].leaf_subject_key.as_str(),
            leaf_hex.as_str()
        );
        assert_eq!(report.by_leaf[0].receipt_count, 2);
        assert_eq!(report.by_leaf[0].total_cost_charged, 125);
        assert_eq!(report.by_leaf[0].total_attempted_cost, 75);

        assert_eq!(report.receipts.len(), 1);
        assert_eq!(report.receipts[0].capability_id, "cap-child");
        assert_eq!(
            report.receipts[0].root_subject_key.as_deref(),
            Some(root_hex.as_str())
        );
        assert_eq!(
            report.receipts[0].leaf_subject_key.as_deref(),
            Some(leaf_hex.as_str())
        );
        assert!(report.receipts[0].lineage_complete);
        assert_eq!(report.receipts[0].chain.len(), 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn compliance_report_counts_proof_and_lineage_coverage_truthfully() {
        let path = unique_db_path("pact-receipts-compliance");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let issuer_kp = Keypair::generate();
        let subject_kp = Keypair::generate();
        let checkpoint_kp = Keypair::generate();
        let subject_hex = subject_kp.public_key().to_hex();
        let issuer_hex = issuer_kp.public_key().to_hex();

        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-compliance".to_string(),
                issuer: issuer_kp.public_key(),
                subject: subject_kp.public_key(),
                scope: PactScope {
                    grants: vec![ToolGrant {
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(4),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 500,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 1000,
                            currency: "USD".to_string(),
                        }),
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer_kp,
        )
        .unwrap();
        store.record_capability_snapshot(&token, None).unwrap();

        let make_receipt = |id: &str,
                            timestamp: u64,
                            decision: Decision,
                            settlement_status: SettlementStatus,
                            attempted_cost: Option<u64>| {
            let metadata = serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex.clone(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: if attempted_cost.is_some() { 0 } else { 250 },
                    currency: "USD".to_string(),
                    budget_remaining: 750,
                    budget_total: 1000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: None,
                    settlement_status,
                    cost_breakdown: None,
                    attempted_cost,
                }
            });

            PactReceipt::sign(
                PactReceiptBody {
                    id: id.to_string(),
                    timestamp,
                    capability_id: "cap-compliance".to_string(),
                    tool_server: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    action: ToolCallAction {
                        parameters: serde_json::json!({}),
                        parameter_hash: format!("param-{id}"),
                    },
                    decision,
                    content_hash: format!("content-{id}"),
                    policy_hash: "policy-compliance".to_string(),
                    evidence: Vec::new(),
                    metadata: Some(metadata),
                    kernel_key: checkpoint_kp.public_key(),
                },
                &checkpoint_kp,
            )
            .unwrap()
        };

        let seq = store
            .append_pact_receipt_returning_seq(&make_receipt(
                "compliance-1",
                2_000,
                Decision::Allow,
                SettlementStatus::Settled,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "compliance-2",
                2_001,
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                SettlementStatus::Pending,
                Some(100),
            ))
            .unwrap();

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .unwrap()
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint = build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).unwrap();
        store.store_checkpoint(&checkpoint).unwrap();

        let report = store
            .query_compliance_report(&OperatorReportQuery {
                agent_subject: Some(subject_hex.clone()),
                tool_server: Some("shell".to_string()),
                tool_name: Some("bash".to_string()),
                ..OperatorReportQuery::default()
            })
            .unwrap();

        assert_eq!(report.matching_receipts, 2);
        assert_eq!(report.evidence_ready_receipts, 1);
        assert_eq!(report.uncheckpointed_receipts, 1);
        assert_eq!(report.lineage_covered_receipts, 2);
        assert_eq!(report.lineage_gap_receipts, 0);
        assert_eq!(report.pending_settlement_receipts, 1);
        assert_eq!(report.failed_settlement_receipts, 0);
        assert!(!report.direct_evidence_export_supported);
        assert_eq!(
            report.child_receipt_scope,
            crate::EvidenceChildReceiptScope::OmittedNoJoinPath
        );
        assert!(report
            .export_scope_note
            .as_deref()
            .is_some_and(|note| note.contains("tool filters narrow the operator report only")));

        let _ = fs::remove_file(path);
    }
}
