//! Capability lineage index for PACT kernel.
//!
//! This module provides persistence and query functions for capability snapshots.
//! Snapshots are recorded at issuance time and co-located with the receipt database
//! for efficient JOINs. The delegation chain can be walked via WITH RECURSIVE CTE.

use serde::{Deserialize, Serialize};

use pact_core::capability::CapabilityToken;
use rusqlite::{params, OptionalExtension, Row};

use crate::receipt_store::SqliteReceiptStore;

/// A point-in-time snapshot of a capability token persisted at issuance.
///
/// Stored in the `capability_lineage` table alongside `pact_tool_receipts`
/// for efficient JOINs during audit queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// The unique token ID (matches CapabilityToken.id).
    pub capability_id: String,
    /// Hex-encoded subject public key (agent bound to this capability).
    pub subject_key: String,
    /// Hex-encoded issuer public key (Capability Authority or delegating agent).
    pub issuer_key: String,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// JSON-serialized PactScope (grants, resource_grants, prompt_grants).
    pub grants_json: String,
    /// Depth in the delegation chain. Root capabilities have depth 0.
    pub delegation_depth: u64,
    /// Parent capability_id if this was delegated from another token.
    pub parent_capability_id: Option<String>,
}

/// Errors from capability lineage operations.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityLineageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Extract a CapabilitySnapshot from a rusqlite Row.
///
/// Column order must match SELECT order in all queries:
///   0: capability_id, 1: subject_key, 2: issuer_key,
///   3: issued_at, 4: expires_at, 5: grants_json,
///   6: delegation_depth, 7: parent_capability_id
fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
    Ok(CapabilitySnapshot {
        capability_id: row.get::<_, String>(0)?,
        subject_key: row.get::<_, String>(1)?,
        issuer_key: row.get::<_, String>(2)?,
        issued_at: row.get::<_, i64>(3)?.max(0) as u64,
        expires_at: row.get::<_, i64>(4)?.max(0) as u64,
        grants_json: row.get::<_, String>(5)?,
        delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
        parent_capability_id: row.get::<_, Option<String>>(7)?,
    })
}

impl SqliteReceiptStore {
    /// Record a capability snapshot at issuance time.
    ///
    /// Uses INSERT OR IGNORE for idempotency -- duplicate inserts are silently
    /// dropped, preserving the first-writer-wins record.
    ///
    /// The `parent_capability_id` argument must refer to a capability already
    /// present in the lineage table. If it is `Some` but the parent is missing,
    /// the depth defaults to 1 (the minimum delegation depth).
    pub fn record_capability_snapshot(
        &mut self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CapabilityLineageError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();

        // Compute delegation depth from parent if present.
        let delegation_depth: u64 = if let Some(parent_id) = parent_capability_id {
            let parent_depth: Option<u64> = self
                .connection
                .query_row(
                    "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                    params![parent_id],
                    |row: &Row<'_>| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|d: i64| d.max(0) as u64);

            parent_depth.map(|d| d + 1).unwrap_or(1)
        } else {
            0
        };

        self.connection.execute(
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
                token.id,
                subject_key,
                issuer_key,
                token.issued_at as i64,
                token.expires_at as i64,
                grants_json,
                delegation_depth as i64,
                parent_capability_id,
            ],
        )?;

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
            .connection
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
        let mut stmt = self.connection.prepare(
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
        let mut stmt = self.connection.prepare(
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
            WHERE subject_key = ?1
            ORDER BY issued_at DESC
            "#,
        )?;

        let rows = stmt.query_map(params![subject_key], snapshot_from_row)?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use pact_core::capability::{
        CapabilityToken, CapabilityTokenBody, Operation, PactScope, ToolGrant,
    };
    use pact_core::crypto::Keypair;
    use rusqlite::params;

    use crate::receipt_store::SqliteReceiptStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    /// Build a test CapabilityToken with the given ID and subject/issuer keypairs.
    fn make_token(
        id: &str,
        subject_kp: &Keypair,
        issuer_kp: &Keypair,
        issued_at: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: PactScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at,
            expires_at,
            delegation_chain: vec![],
        };
        CapabilityToken::sign(body, issuer_kp).expect("sign failed")
    }

    #[test]
    fn record_and_get_lineage_returns_matching_fields() {
        let path = unique_db_path("cl-persist");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-001", &subject_kp, &issuer_kp, 1000, 2000);

        store.record_capability_snapshot(&token, None).unwrap();

        let snap = store.get_lineage("cap-001").unwrap().unwrap();
        assert_eq!(snap.capability_id, "cap-001");
        assert_eq!(snap.subject_key, subject_kp.public_key().to_hex());
        assert_eq!(snap.issuer_key, issuer_kp.public_key().to_hex());
        assert_eq!(snap.issued_at, 1000);
        assert_eq!(snap.expires_at, 2000);
        assert_eq!(snap.delegation_depth, 0);
        assert!(snap.parent_capability_id.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn record_capability_snapshot_is_idempotent() {
        let path = unique_db_path("cl-idempotent");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-idem-001", &subject_kp, &issuer_kp, 1000, 2000);

        // Insert twice -- must not panic or error.
        store.record_capability_snapshot(&token, None).unwrap();
        store.record_capability_snapshot(&token, None).unwrap();

        // Only one row should exist.
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM capability_lineage WHERE capability_id = ?1",
                params!["cap-idem-001"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn grants_json_round_trips_without_field_loss() {
        let path = unique_db_path("cl-json-rt");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-json-001", &subject_kp, &issuer_kp, 1000, 2000);

        store.record_capability_snapshot(&token, None).unwrap();

        let snap = store.get_lineage("cap-json-001").unwrap().unwrap();
        let round_tripped: PactScope = serde_json::from_str(&snap.grants_json).unwrap();

        assert_eq!(round_tripped.grants.len(), token.scope.grants.len());
        assert_eq!(round_tripped.grants[0].server_id, "shell");
        assert_eq!(round_tripped.grants[0].tool_name, "bash");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_lineage_returns_none_for_missing_capability() {
        let path = unique_db_path("cl-missing");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let result = store.get_lineage("nonexistent-cap").unwrap();
        assert!(result.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_returns_root_first_for_three_level_chain() {
        let path = unique_db_path("cl-chain-3");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let kp_root = Keypair::generate();
        let kp_mid = Keypair::generate();
        let kp_leaf = Keypair::generate();

        // root -> parent -> child
        let root = make_token("cap-root", &kp_root, &kp_root, 1000, 9000);
        let parent = make_token("cap-parent", &kp_mid, &kp_root, 1100, 8000);
        let child = make_token("cap-child", &kp_leaf, &kp_mid, 1200, 7000);

        store.record_capability_snapshot(&root, None).unwrap();
        store
            .record_capability_snapshot(&parent, Some("cap-root"))
            .unwrap();
        store
            .record_capability_snapshot(&child, Some("cap-parent"))
            .unwrap();

        // Walking the chain from child should return root, parent, child (root-first).
        let chain = store.get_delegation_chain("cap-child").unwrap();
        assert_eq!(chain.len(), 3, "should have 3 entries in chain");
        assert_eq!(chain[0].capability_id, "cap-root", "root should be first");
        assert_eq!(
            chain[1].capability_id, "cap-parent",
            "parent should be second"
        );
        assert_eq!(chain[2].capability_id, "cap-child", "child should be last");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_returns_single_entry_for_root_capability() {
        let path = unique_db_path("cl-chain-root");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let kp = Keypair::generate();
        let root = make_token("cap-solo", &kp, &kp, 1000, 9000);

        store.record_capability_snapshot(&root, None).unwrap();

        let chain = store.get_delegation_chain("cap-solo").unwrap();
        assert_eq!(chain.len(), 1, "root has no parent -- only itself in chain");
        assert_eq!(chain[0].capability_id, "cap-solo");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_enforces_max_depth_guard() {
        let path = unique_db_path("cl-depth-guard");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        // Build a chain of 25 entries (exceeds the level < 20 guard).
        let kp = Keypair::generate();
        let mut prev_id: Option<String> = None;
        for i in 0..25usize {
            let id = format!("cap-depth-{i:03}");
            let token = make_token(&id, &kp, &kp, 1000 + i as u64, 9000);
            store
                .record_capability_snapshot(&token, prev_id.as_deref())
                .unwrap();
            prev_id = Some(id);
        }

        // Walking the chain from the deepest node should be capped at 21 entries (depth guard).
        let chain = store.get_delegation_chain("cap-depth-024").unwrap();
        // With level < 20, the recursion visits at most 21 distinct rows.
        assert!(
            chain.len() <= 21,
            "chain length {} exceeds max depth guard of 21",
            chain.len()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn capability_lineage_table_created_by_open() {
        let path = unique_db_path("cl-table-exists");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // Query the table to verify it exists; COUNT(*) fails if the table is absent.
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM capability_lineage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "table should exist and be empty");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn subject_key_index_exists() {
        let path = unique_db_path("cl-index-check");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // PRAGMA index_list returns rows for each index on the table.
        let mut stmt = store
            .connection
            .prepare("PRAGMA index_list(capability_lineage)")
            .unwrap();
        let index_names: Vec<String> = stmt
            .query_map([], |row: &rusqlite::Row<'_>| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r: Result<String, _>| r.ok())
            .collect();

        assert!(
            index_names
                .iter()
                .any(|n| n == "idx_capability_lineage_subject"),
            "subject_key index not found; found: {index_names:?}"
        );

        let _ = fs::remove_file(path);
    }
}
