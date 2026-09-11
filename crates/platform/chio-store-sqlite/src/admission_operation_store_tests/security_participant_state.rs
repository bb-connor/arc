use super::super::security_participant_state as native;
use super::*;
use std::cell::Cell;

#[path = "security_participant_state/dispatch_ledger.rs"]
mod dispatch_ledger;
#[path = "security_participant_state/output.rs"]
mod output;

#[cfg(unix)]
#[path = "security_participant_state/cutpoints.rs"]
mod cutpoints;
#[cfg(unix)]
#[path = "security_participant_state/egress.rs"]
mod egress;
#[cfg(unix)]
#[path = "security_participant_state/integrity.rs"]
mod integrity;
#[cfg(unix)]
#[path = "security_participant_state/lifecycle.rs"]
mod lifecycle;
#[path = "security_participant_state/migration.rs"]
mod migration;
#[cfg(unix)]
#[path = "security_participant_state/mutations.rs"]
mod mutations;
#[cfg(unix)]
#[path = "security_participant_state/observation.rs"]
mod observation;

thread_local! { static FAIL_AFTER: Cell<u8> = const { Cell::new(0) }; }

pub(crate) fn cutpoint(stage: u8) -> Result<(), AdmissionOperationStoreError> {
    if FAIL_AFTER.get() == stage {
        return Err(invariant("injected native hydration failure"));
    }
    crash_cutpoint(stage);
    Ok(())
}

pub(crate) fn crash_cutpoint(stage: u8) {
    if std::env::var("CHIO_SECURITY_NATIVE_CRASH_STAGE")
        .ok()
        .as_deref()
        == Some(stage.to_string().as_str())
    {
        std::process::abort();
    }
}

#[cfg(unix)]
struct ResetCutpoint;
#[cfg(unix)]
impl Drop for ResetCutpoint {
    fn drop(&mut self) {
        FAIL_AFTER.set(0);
    }
}

#[cfg(unix)]
fn imported(
    fixture: &Fixture,
    name: &str,
) -> AnchoredTestResult<SecurityParticipantMigrationRecord> {
    let path = fixture._temp.path().join(format!("{name}.db"));
    drop(crate::security_state::seeded_security_history(&path)?);
    seed_isolation_history(&path)?;
    let source = crate::security_state::SqliteSecurityParticipantSource::open(path)?;
    let authority = identifier("security_authority_id", name);
    let expected = fixture.store.expect_security_participant_source(
        &identifier("source_id", name),
        &authority,
        &source,
        &fixture.fence,
        now_ms(),
    )?;
    Ok(fixture.store.import_security_participant_source(
        &authority,
        expected.expectation_id(),
        &source,
        &fixture.fence,
        now_ms(),
    )?)
}

#[cfg(unix)]
fn seed_isolation_history(path: &std::path::Path) -> AnchoredTestResult {
    use chio_security_types::ports::{
        FlowStateStore, IsolationEpochEvidenceVerifierPort, IsolationEpochTransition, PortResult,
        VerifiedIsolationEvidence,
    };
    struct Verifier;
    impl IsolationEpochEvidenceVerifierPort for Verifier {
        fn verify(&self, _: &IsolationEpochTransition) -> PortResult<VerifiedIsolationEvidence> {
            Ok(VerifiedIsolationEvidence {
                verifier_id: chio_security_types::ports::RecordId::new("native-fixture-verifier")?,
                receipt_ref: chio_security_types::ports::OpaqueReceiptRef::new(
                    "native-fixture-receipt",
                )?,
            })
        }
    }
    let store = crate::SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
        path,
        Arc::new(Verifier),
    )?;
    store.open_isolation_epoch(&IsolationEpochTransition {
        tenant_id: chio_security_types::ports::TenantId::new("tenant")?,
        principal_id: chio_security_types::PrincipalId::new("principal")?,
        lineage_id: chio_security_types::ports::LineageId::new("lineage")?,
        previous_isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch")?,
        new_isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("new-epoch")?,
        new_session_id: chio_security_types::ports::SessionId::new("new-session")?,
        verification_evidence_hash: chio_security_types::ports::Digest32::new([7; 32]),
        transition_id: chio_security_types::ports::RecordId::new("isolation-transition")?,
        effective_at_unix_ms: 1_000,
    })?;
    Ok(())
}

#[cfg(unix)]
fn hydrate(
    fixture: &Fixture,
    imported: &SecurityParticipantMigrationRecord,
) -> AnchoredTestResult<SecurityParticipantStateInitialization> {
    Ok(fixture.store.hydrate_security_participant_state(
        &identifier(
            "security_authority_id",
            imported
                .snapshot()
                .binding()
                .security_authority_id()
                .as_str(),
        ),
        imported.expectation_id(),
        &fixture.fence,
        now_ms(),
    )?)
}

#[cfg(unix)]
fn global_count(connection: &Connection) -> rusqlite::Result<i64> {
    connection.query_row("SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'security_participant_state'", [], |row| row.get(0))
}

/// Exercise internal SQL semantics against the actual catalog and imported
/// parents. The callback must roll back speculative writes. This is not native
/// activation, an admission claim, or a serving path.
#[cfg(unix)]
pub(crate) fn with_flow_sql_fixture(
    initialized: bool,
    run: impl FnOnce(&mut Connection) -> AnchoredTestResult,
) -> AnchoredTestResult {
    let fixture = fixture();
    for authority in ["authority-a", "authority-b"] {
        let source = imported(&fixture, authority)?;
        if initialized {
            hydrate(&fixture, &source)?;
        }
    }
    {
        let mut connection = fixture.store.connection()?;
        run(&mut connection)?;
        assert!(connection.is_autocommit());
    }
    for authority in ["authority-a", "authority-b"] {
        assert_eq!(
            fixture
                .store
                .load_security_participant_state(
                    &identifier("security_authority_id", authority),
                    &fixture.fence,
                    now_ms()
                )?
                .is_some(),
            initialized
        );
    }
    Ok(())
}

/// Construct genuine predecessor fixtures without discarding any retained rows.
pub(super) fn remove_empty_v28_tables(connection: &Connection) -> rusqlite::Result<()> {
    dispatch_ledger::remove_empty_v31_ledger(connection)?;
    let mut tables = native::schema::TABLES
        .iter()
        .map(|table| table.native)
        .collect::<Vec<_>>();
    // Dependency order matters even when foreign keys are enabled.
    tables.sort_by_key(|table| match *table {
        "security_participant_state_declassification_receipt_outbox" => 0,
        "security_participant_state_declassification_tombstones" => 1,
        "security_participant_state_declassification_uses" => 2,
        _ => 3,
    });
    tables.push("security_participant_state_initializations");
    tables.insert(0, "security_participant_state_mutations");
    tables.insert(0, "security_participant_egress_events");
    for table in tables {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            continue;
        }
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0, "predecessor fixture cannot discard native state");
        connection.execute_batch(&format!("DROP TABLE {table}"))?;
    }
    Ok(())
}
