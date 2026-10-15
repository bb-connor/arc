use chio_core_types::PublicKey;
use chio_security_types::clock::ClockError;
use chio_swarm_authority::{verify_swarm_authority_extension, SwarmAuthorityBundle};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};
use crate::hash::canonical_sha256;
use crate::validation::validate_non_empty;
use crate::ChioRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn insert_swarm_authority_bundle(
        &self,
        bundle: SwarmAuthorityBundle,
    ) -> Result<(), ChioRuntimeError> {
        validate_non_empty(
            &bundle.task_graph.graph_id,
            "runtime_swarm_authority_empty_graph_id",
        )?;
        let created_at =
            i64::try_from(self.clock.unix_millis()?.get()).map_err(|_| ClockError::Overflow)?;
        let bundle_sha256 = canonical_sha256(&bundle)?;
        let raw_json = serde_json::to_string(&bundle).map_err(ChioRuntimeError::Json)?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT bundle_sha256 FROM runtime_swarm_authority_bundles WHERE task_graph_id = ?1",
                params![bundle.task_graph.graph_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == bundle_sha256 {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_swarm_authority_bundle_mismatch",
                detail:
                    "runtime swarm authority bundle graph id already exists with a different hash"
                        .to_string(),
            });
        }
        tx.execute(
            r#"
            INSERT INTO runtime_swarm_authority_bundles (
                task_graph_id, bundle_sha256, raw_json, created_at_unix_ms
            )
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                bundle.task_graph.graph_id,
                bundle_sha256,
                raw_json,
                created_at
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub(super) fn load_swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        validate_non_empty(task_graph_id, "runtime_swarm_authority_empty_graph_id")?;
        let connection = self.lock_connection()?;
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT bundle_sha256, raw_json FROM runtime_swarm_authority_bundles WHERE task_graph_id = ?1",
                params![task_graph_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(hash, json)| decode_bundle(task_graph_id, &hash, &json))
            .transpose()
    }

    /// Install a strictly additive successor under locally configured trust.
    /// Root provisioning remains a separate trusted operation. Comparing the
    /// complete parent digest serializes competing proposals, including their
    /// unsigned budget accounting. No issued allocation is reclaimed, and the
    /// replaced head stays readable by its task-graph digest.
    pub fn extend_swarm_authority_bundle(
        &self,
        expected_bundle_sha256: &str,
        candidate: SwarmAuthorityBundle,
        trusted_keys: &[PublicKey],
    ) -> Result<(), ChioRuntimeError> {
        let graph_id = &candidate.task_graph.graph_id;
        validate_non_empty(graph_id, "runtime_swarm_authority_empty_graph_id")?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let stored: Option<(String, String)> = tx
            .query_row(
                "SELECT bundle_sha256, raw_json FROM runtime_swarm_authority_bundles WHERE task_graph_id = ?1",
                params![graph_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((parent_hash, parent_json)) = stored else {
            return Err(extension_conflict("graph has not been provisioned"));
        };
        let parent = decode_bundle(graph_id, &parent_hash, &parent_json)?;
        if parent_hash != expected_bundle_sha256 {
            return Err(extension_conflict(
                "parent bundle is no longer the current head",
            ));
        }
        let now = self.clock.unix_millis()?.get();
        verify_swarm_authority_extension(&parent, &candidate, trusted_keys, now).map_err(
            |error| ChioRuntimeError::Rejected {
                code: "runtime_swarm_extension_rejected",
                detail: error.runtime_detail(),
            },
        )?;
        let timestamp = i64::try_from(now).map_err(|_| ClockError::Overflow)?;
        let parent_graph_sha256 = canonical_sha256(&parent.task_graph)?;
        let successor_sha256 = canonical_sha256(&candidate)?;
        let successor_json = serde_json::to_string(&candidate).map_err(ChioRuntimeError::Json)?;
        tx.execute(
            r#"
            INSERT INTO runtime_swarm_authority_versions (
                task_graph_id, graph_sha256, bundle_sha256, raw_json,
                archived_at_unix_ms, successor_bundle_sha256
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                graph_id,
                parent_graph_sha256,
                parent_hash,
                parent_json,
                timestamp,
                successor_sha256
            ],
        )
        .map_err(sqlite_error)?;
        tx.execute(
            "UPDATE runtime_swarm_authority_bundles SET bundle_sha256 = ?1, raw_json = ?2, created_at_unix_ms = ?3 WHERE task_graph_id = ?4",
            params![successor_sha256, successor_json, timestamp, graph_id],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub(super) fn load_swarm_authority_bundle_for_graph(
        &self,
        task_graph_id: &str,
        graph_sha256: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        let Some(current) = self.load_swarm_authority_bundle(task_graph_id)? else {
            return Ok(None);
        };
        if canonical_sha256(&current.task_graph)? == graph_sha256 {
            return Ok(Some(current));
        }
        let connection = self.lock_connection()?;
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT bundle_sha256, raw_json FROM runtime_swarm_authority_versions WHERE task_graph_id = ?1 AND graph_sha256 = ?2",
                params![task_graph_id, graph_sha256],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((hash, json)) = row else {
            return Ok(Some(current));
        };
        let archived = decode_bundle(task_graph_id, &hash, &json)?;
        if canonical_sha256(&archived.task_graph)? != graph_sha256 {
            return Err(binding_mismatch());
        }
        Ok(Some(archived))
    }
}

fn decode_bundle(
    task_graph_id: &str,
    stored_hash: &str,
    json: &str,
) -> Result<SwarmAuthorityBundle, ChioRuntimeError> {
    let bundle: SwarmAuthorityBundle = chio_core_types::canonical::UntrustedJsonText::from_wire(
        json.as_bytes(),
        64 * 1024 * 1024,
    )?
    .decode_signed()?;
    if bundle.task_graph.graph_id != task_graph_id || canonical_sha256(&bundle)? != stored_hash {
        return Err(binding_mismatch());
    }
    Ok(bundle)
}

fn binding_mismatch() -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_stored_bundle_binding_mismatch",
        detail: "stored bundle does not match its index and digest".to_owned(),
    }
}

fn extension_conflict(detail: &str) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_swarm_extension_conflict",
        detail: detail.to_owned(),
    }
}
