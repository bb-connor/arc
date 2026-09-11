use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, RuntimeReplaySourcePort,
    RuntimeReplaySourceSnapshotV1,
};

use super::*;

impl SqliteRuntimeOrchestrationStore {
    /// Observe the complete candidate seal without retiring any legacy writer.
    /// The returned data is not proof of a seal, a destination expectation or
    /// authority. A qualified destination must independently pin its identity.
    /// Already sealed or partially sealed sources cannot establish a preview.
    pub fn preview_legacy_replay_source(
        &self,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<RuntimeReplaySourceSnapshotV1, ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        ensure_legacy_replay_writable(&tx)?;
        let candidate = self.candidate_replay_source_seal(&tx, binding)?;
        let snapshot =
            RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&candidate.canonical_bytes()?)
                .map_err(|error| invalid(format!("replay source snapshot is invalid: {error}")))?;
        tx.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    /// Seal only the exact complete source observed earlier. Both the identity
    /// and inventory comparison occur before the barrier writes in their same
    /// IMMEDIATE transaction. Exact committed retries return the original seal.
    /// This method does not authenticate destination provisioning or activate it.
    pub fn seal_expected_legacy_replay_source(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
        let binding = snapshot_binding(expected)?;
        self.seal_replay_source(&binding, Some(expected.canonical_bytes()))
    }

    pub(in crate::store::sqlite) fn verify_expected_replay_source(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), ChioRuntimeError> {
        let binding = snapshot_binding(expected)?;
        let seal = self
            .load_legacy_replay_source_seal(&binding)?
            .ok_or_else(|| invalid("expected replay source seal is missing"))?;
        require_expected_bytes(&seal, Some(expected.canonical_bytes()))
    }
}

/// This adapter is trusted installed code, not authority conveyed by the DTO.
/// Destination provisioning chooses the adapter and pins the independent source
/// expectation before asking it to seal or verify anything.
impl RuntimeReplaySourcePort for SqliteRuntimeOrchestrationStore {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        let binding = RuntimeReplaySourceBinding::new(
            source_id.as_str(),
            runtime_authority_id.as_str(),
            destination_authority_id.as_str(),
        )
        .map_err(port_error)?;
        self.preview_legacy_replay_source(&binding)
            .map_err(port_error)
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.seal_expected_legacy_replay_source(expected)
            .map(|_| ())
            .map_err(port_error)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_expected_replay_source(expected)
            .map_err(port_error)
    }
}

fn snapshot_binding(
    expected: &RuntimeReplaySourceSnapshotV1,
) -> Result<RuntimeReplaySourceBinding, ChioRuntimeError> {
    RuntimeReplaySourceBinding::new(
        expected.source_id(),
        expected.runtime_authority_id(),
        expected.destination_authority_id(),
    )
}

fn port_error(error: ChioRuntimeError) -> AdmissionOperationStoreError {
    match error {
        ChioRuntimeError::Rejected { .. } | ChioRuntimeError::DuplicateAdmissionBundle => {
            AdmissionOperationStoreError::Invariant(error.to_string())
        }
        _ => AdmissionOperationStoreError::Unavailable(error.to_string()),
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_source_cannot_seal_even_a_structurally_valid_expected_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("unsupported-expected-source.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let binding = RuntimeReplaySourceBinding::new("source", "runtime", "destination")?;
        let candidate = RuntimeReplaySourceSeal::from_inventory(
            binding.clone(),
            SqliteFileIdentity {
                device: 1,
                inode: 2,
                link_count: 1,
            },
            schema::barrier_sha256()?,
            Vec::new(),
        )?;
        let expected =
            RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&candidate.canonical_bytes()?)?;
        let error = store
            .seal_expected_legacy_replay_source(&expected)
            .err()
            .ok_or("unsupported source accepted an expected snapshot")?;
        assert_eq!(error.code(), "runtime_replay_source_invalid");
        assert!(error.to_string().contains("requires Unix"));
        assert!(RuntimeReplaySourcePort::seal_exact(&store, &expected).is_err());
        assert!(RuntimeReplaySourcePort::verify_exact(&store, &expected).is_err());
        assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
        let raw = Connection::open(&path)?;
        let objects: i64 = raw.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE lower(name) GLOB '*runtime_replay_source*'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(objects, 0);
        Ok(())
    }
}
