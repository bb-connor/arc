use super::*;

use std::sync::{Arc, Mutex};

use chio_kernel::admission_operation::{RuntimeReplaySourcePort, RuntimeReplaySourceSnapshotV1};

#[path = "runtime_replay/activation.rs"]
mod activation;
#[path = "runtime_replay/claims.rs"]
mod claims;
#[path = "runtime_replay/cutpoints.rs"]
mod cutpoints;
#[path = "runtime_replay/integrity.rs"]
mod integrity;
#[path = "runtime_replay/lifecycle.rs"]
mod lifecycle;

const SOURCE_ID: &str = "runtime-replay-source";
const RUNTIME_ID: &str = "runtime-authority";

#[derive(Default)]
struct SourceState {
    empty: bool,
    revision: u64,
    sealed: Option<Vec<u8>>,
    lose_seal_ack_once: bool,
    calls: Vec<&'static str>,
}

/// A trusted-source test double. This deliberately does not claim to test the
/// runtime SQLite barrier; its purpose is the qualified destination protocol.
struct Source {
    connection: Arc<Mutex<Connection>>,
    state: Mutex<SourceState>,
}

impl Source {
    fn new(fixture: &Fixture, empty: bool) -> Self {
        Self {
            connection: Arc::clone(&fixture.store.connection),
            state: Mutex::new(SourceState {
                empty,
                ..SourceState::default()
            }),
        }
    }

    fn observe(&self, call: &'static str) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection.try_lock().map_err(|_| {
            AdmissionOperationStoreError::Invariant(
                "source callback entered under the destination connection lock".into(),
            )
        })?;
        assert!(
            connection.is_autocommit(),
            "no destination transaction crosses the port"
        );
        self.state.lock().expect("source state").calls.push(call);
        Ok(())
    }

    fn snapshot(
        &self,
        source_id: &str,
        runtime_authority_id: &str,
        destination_authority_id: &str,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        let state = self.state.lock().expect("source state");
        let markers = if state.empty {
            serde_json::json!([])
        } else {
            serde_json::json!([
                {"kind":"destructive_lease","resourceId":"same-resource","admissionId":format!("historical-admission-{}", state.revision)},
                {"kind":"treaty_continuation","resourceId":"same-resource","admissionId":"historical-treaty"},
                {"kind":"swarm_continuation","resourceId":"same-resource","admissionId":"historical-swarm"}
            ])
        };
        let body = serde_json::json!({
            "schema":"chio.runtime-replay-source-seal.v1",
            "binding":{
                "sourceId":source_id,
                "runtimeAuthorityId":runtime_authority_id,
                "destinationAuthorityId":destination_authority_id
            },
            "device":"18446744073709551615",
            "inode":"18446744073709551614",
            "linkCount":1,
            "barrierSha256":"b".repeat(64),
            "markerCounts":if state.empty { [0,0,0] } else { [1,1,1] },
            "markers":markers
        });
        let encoded = canonical_json_bytes(&body).expect("canonical fixture body");
        let mut preimage = b"chio.runtime-replay-source-seal.v1\0".to_vec();
        preimage.extend_from_slice(&encoded);
        let evidence = canonical_json_bytes(&serde_json::json!({
            "body":body,
            "inventorySha256":sha256_hex(&preimage)
        }))
        .expect("canonical fixture evidence");
        RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&evidence)
    }

    fn calls(&self) -> Vec<&'static str> {
        self.state.lock().expect("source state").calls.clone()
    }
}

impl RuntimeReplaySourcePort for Source {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        self.observe("preview")?;
        if self.state.lock().expect("source state").sealed.is_some() {
            return Err(AdmissionOperationStoreError::Invariant(
                "fixture preview rejects an already sealed source".into(),
            ));
        }
        self.snapshot(
            source_id.as_str(),
            runtime_authority_id.as_str(),
            destination_authority_id.as_str(),
        )
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.observe("seal")?;
        let current = self.snapshot(
            expected.source_id(),
            expected.runtime_authority_id(),
            expected.destination_authority_id(),
        )?;
        if current.canonical_bytes() != expected.canonical_bytes() {
            return Err(AdmissionOperationStoreError::Invariant(
                "fixture source changed before sealing".into(),
            ));
        }
        let mut state = self.state.lock().expect("source state");
        if state
            .sealed
            .as_deref()
            .is_some_and(|sealed| sealed != expected.canonical_bytes())
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "fixture source is sealed to different evidence".into(),
            ));
        }
        state.sealed = Some(expected.canonical_bytes().to_vec());
        if std::mem::take(&mut state.lose_seal_ack_once) {
            return Err(AdmissionOperationStoreError::OutcomeUnknown(
                "fixture seal committed but acknowledgement was lost".into(),
            ));
        }
        Ok(())
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.observe("verify")?;
        let current = self.snapshot(
            expected.source_id(),
            expected.runtime_authority_id(),
            expected.destination_authority_id(),
        )?;
        if current.canonical_bytes() != expected.canonical_bytes()
            || self.state.lock().expect("source state").sealed.as_deref()
                != Some(expected.canonical_bytes())
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "fixture live source does not match its retained seal".into(),
            ));
        }
        Ok(())
    }
}

fn pin(
    fixture: &Fixture,
    source: &Source,
) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture.store.expect_runtime_replay_source(
        &identifier("source_id", SOURCE_ID),
        &identifier("runtime_authority_id", RUNTIME_ID),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn import(
    fixture: &Fixture,
    source: &Source,
    pin: &RuntimeReplayMigrationRecordV1,
) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture.store.import_runtime_replay_source(
        &identifier("runtime_authority_id", RUNTIME_ID),
        pin.expectation_id(),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn load(
    fixture: &Fixture,
) -> Result<Option<RuntimeReplayMigrationRecordV1>, AdmissionOperationStoreError> {
    fixture.store.load_runtime_replay_migration(
        &identifier("runtime_authority_id", RUNTIME_ID),
        &fixture.fence,
        now_ms(),
    )
}

fn global_count(store: &SqliteAdmissionOperationStore) -> i64 {
    store
        .connection()
        .expect("destination connection")
        .query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .expect("global commit count")
}

fn assert_record_equal(
    actual: &RuntimeReplayMigrationRecordV1,
    expected: &RuntimeReplayMigrationRecordV1,
) {
    assert_eq!(
        actual.snapshot().canonical_bytes(),
        expected.snapshot().canonical_bytes()
    );
    assert_eq!(actual.expectation_id(), expected.expectation_id());
    assert_eq!(actual.expectation_digest(), expected.expectation_digest());
    assert_eq!(actual.event_sequence(), expected.event_sequence());
    assert_eq!(actual.imported_inactive(), expected.imported_inactive());
}

/// Historical fixture shaping only. Dropping a nonempty migration namespace
/// would erase security history and is never an acceptable schema downgrade.
pub(super) fn remove_empty_v19_runtime_tables(connection: &Connection) -> rusqlite::Result<()> {
    super::governed_approval_replay::remove_empty_v22_approval_tables(connection)?;
    for table in [
        "runtime_replay_claim_releases",
        "runtime_replay_claim_resources",
        "runtime_replay_claim_episodes",
        "runtime_replay_legacy_tombstones",
        "runtime_replay_migration_events",
        "runtime_replay_migration_expectations",
    ] {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            count, 0,
            "only an empty fixture may be shaped as historical schema"
        );
        connection.execute_batch(&format!("DROP TABLE {table};"))?;
    }
    Ok(())
}
