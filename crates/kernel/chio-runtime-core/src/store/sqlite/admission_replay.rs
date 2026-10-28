use rusqlite::{params, OptionalExtension, TransactionBehavior};

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};
use crate::hash::runtime_admission_bundle_sha256;
use crate::store::traits::RuntimeAdmissionStore;
use crate::types::{RuntimeAdmissionBundle, RuntimeTrustFloorEntry, TreatyRuntimeArtifactRecord};
use crate::ChioRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        let raw_json = serde_json::to_string(&bundle).map_err(ChioRuntimeError::Json)?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT bundle_sha256 FROM runtime_admission_bundles WHERE admission_id = ?1",
                params![bundle.admission_id],
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
                code: "duplicate_admission_bundle_mismatch",
                detail: "runtime admission bundle id already exists with a different hash"
                    .to_string(),
            });
        }
        tx.execute(
            "INSERT INTO runtime_admission_bundles (admission_id, bundle_sha256, raw_json, created_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            params![bundle.admission_id, bundle_sha256, raw_json, 0_i64],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }
}

impl RuntimeAdmissionStore for SqliteRuntimeOrchestrationStore {
    fn verify_operation_owned_runtime_source(
        &self,
        expected: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
    ) -> Result<(), ChioRuntimeError> {
        self.verify_runtime_source(expected)
    }

    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT bundle_sha256, raw_json FROM runtime_admission_bundles WHERE admission_id = ?1",
                params![admission_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(stored_hash, json)| {
            let bundle: RuntimeAdmissionBundle =
                chio_core_types::canonical::UntrustedJsonText::from_wire(
                    json.as_bytes(),
                    64 * 1024 * 1024,
                )?
                .decode_signed()?;
            if bundle.admission_id != admission_id
                || runtime_admission_bundle_sha256(&bundle)? != stored_hash
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

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        SqliteRuntimeOrchestrationStore::treaty_runtime_artifact(self, evidence_kind, evidence_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.load_runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.store_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        self.validate_and_store_runtime_trust_floor(entry, previous_hash_sha256)
    }
}
