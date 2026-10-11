use chio_security_types::clock::ClockError;
use chio_swarm_authority::SwarmAuthorityBundle;
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
        row.map(|(stored_hash, json)| {
            let bundle: SwarmAuthorityBundle =
                chio_core_types::canonical::UntrustedJsonText::from_wire(
                    json.as_bytes(),
                    64 * 1024 * 1024,
                )?
                .decode_signed()?;
            if bundle.task_graph.graph_id != task_graph_id
                || canonical_sha256(&bundle)? != stored_hash
            {
                return Err(ChioRuntimeError::Rejected {
                    code: "runtime_stored_bundle_binding_mismatch",
                    detail: "stored bundle does not match its index and digest".to_owned(),
                });
            }
            Ok(bundle)
        })
        .transpose()
    }
}
