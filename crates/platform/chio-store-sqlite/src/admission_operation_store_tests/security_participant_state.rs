use super::super::security_participant_state as native;
use super::*;
use std::cell::Cell;

#[path = "security_participant_state/nonce_preflight.rs"]
mod nonce_preflight;
#[path = "security_participant_state/output.rs"]
mod output;

#[path = "security_participant_state/barrier.rs"]
mod barrier;
#[cfg(unix)]
#[path = "security_participant_state/checkpoint.rs"]
mod checkpoint;
#[cfg(unix)]
#[path = "security_participant_state/checkpoint_history.rs"]
mod checkpoint_history;
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
#[cfg(unix)]
#[path = "security_participant_state/mutations.rs"]
mod mutations;
#[cfg(unix)]
pub(super) use mutations::prepare_issuance_fixture;
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
        FlowStateStore, IsolationEpochEvidenceVerifierPort, IsolationEpochTransition,
        IsolationVerificationRecord, PortResult,
    };
    struct Verifier;
    impl IsolationEpochEvidenceVerifierPort for Verifier {
        fn verify(&self, _: &IsolationEpochTransition) -> PortResult<IsolationVerificationRecord> {
            Ok(IsolationVerificationRecord {
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
