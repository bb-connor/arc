use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Weak;

use super::*;

struct FixedVerifier;

impl IsolationEpochEvidenceVerifierPort for FixedVerifier {
    fn verify(&self, _: &IsolationEpochTransition) -> PortResult<VerifiedIsolationEvidence> {
        Ok(VerifiedIsolationEvidence {
            verifier_id: RecordId::new("competitor-verifier")?,
            receipt_ref: OpaqueReceiptRef::new("competitor-receipt")?,
        })
    }
}

enum DuringVerification {
    JoinLineage,
    SameTransition,
    ConflictingTransition,
    #[cfg(unix)]
    RetireSource,
}

struct WritingVerifier {
    path: std::path::PathBuf,
    store: Mutex<Weak<SqliteSecurityStateStore>>,
    calls: AtomicUsize,
    action: DuringVerification,
}

impl IsolationEpochEvidenceVerifierPort for WritingVerifier {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<VerifiedIsolationEvidence> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let store = self
            .store
            .lock()
            .map_err(|_| PortError::unavailable())?
            .upgrade()
            .ok_or_else(PortError::unavailable)?;
        // A nonblocking probe makes a regression fail rather than hang while
        // proving that this exact store does not hold its mutex over the port.
        drop(
            store
                .connection
                .try_lock()
                .map_err(|_| PortError::unavailable())?,
        );
        match self.action {
            DuringVerification::JoinLineage => {
                let other = SqliteSecurityStateStore::open(&self.path)?;
                let mut join = request("verifier-join").map_err(|_| PortError::invalid_data())?;
                join.lineage_join = classified_label()?;
                other.join(&join)?;
            }
            DuringVerification::SameTransition | DuringVerification::ConflictingTransition => {
                let other = SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
                    &self.path,
                    Arc::new(FixedVerifier),
                )?;
                let mut competitor = transition.clone();
                if matches!(self.action, DuringVerification::ConflictingTransition) {
                    competitor.transition_id = RecordId::new("competing-transition")?;
                }
                other.open_isolation_epoch(&competitor)?;
            }
            #[cfg(unix)]
            DuringVerification::RetireSource => {
                let source = SqliteSecurityParticipantSource::open(&self.path)
                    .map_err(|_| PortError::unavailable())?;
                let binding =
                    SecurityParticipantSourceBinding::new("source", "authority", "destination")
                        .map_err(|_| PortError::invalid_data())?;
                let snapshot = source
                    .preview(&binding)
                    .map_err(|_| PortError::integrity_failure())?;
                source
                    .seal_exact(&snapshot)
                    .map_err(|_| PortError::conflict())?;
            }
        }
        Ok(VerifiedIsolationEvidence {
            verifier_id: RecordId::new("outer-verifier")?,
            receipt_ref: OpaqueReceiptRef::new("outer-receipt")?,
        })
    }
}

fn classified_label() -> PortResult<InformationLabel> {
    InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([chio_security_types::Compartment::new("restricted")
            .map_err(|_| PortError::invalid_data())?]),
    )
    .map_err(|_| PortError::invalid_data())
}

struct Fixture {
    store: Arc<SqliteSecurityStateStore>,
    verifier: Arc<WritingVerifier>,
    transition: IsolationEpochTransition,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(action: DuringVerification) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let verifier = Arc::new(WritingVerifier {
            path: path.clone(),
            store: Mutex::new(Weak::new()),
            calls: AtomicUsize::new(0),
            action,
        });
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_isolation_epoch_verifier(&path, verifier.clone())?,
        );
        *verifier
            .store
            .lock()
            .map_err(|_| "verifier lock poisoned")? = Arc::downgrade(&store);
        let join = request("initial-join")?;
        store.join(&join)?;
        let transition = IsolationEpochTransition {
            tenant_id: join.key.tenant_id,
            principal_id: join.key.principal_id,
            lineage_id: join.key.lineage_id,
            previous_isolation_epoch_id: join.key.isolation_epoch_id,
            new_isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("new-epoch")?,
            new_session_id: chio_security_types::ports::SessionId::new("new-session")?,
            verification_evidence_hash: Digest32::new([7; 32]),
            transition_id: RecordId::new("isolation-transition")?,
            effective_at_unix_ms: 1_000,
        };
        Ok(Self {
            store,
            verifier,
            transition,
            _directory: directory,
        })
    }
}

#[test]
fn verifier_runs_without_locks_and_epoch_uses_post_verification_lineage() -> TestResult {
    let fixture = Fixture::new(DuringVerification::JoinLineage)?;
    let snapshot = fixture.store.open_isolation_epoch(&fixture.transition)?;
    assert_eq!(snapshot.lineage_label, classified_label()?);
    assert_eq!(snapshot.session_label, classified_label()?);
    assert_eq!(snapshot.principal_label, InformationLabel::bottom());
    assert_eq!(
        fixture.store.open_isolation_epoch(&fixture.transition)?,
        snapshot
    );
    assert_eq!(fixture.verifier.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn identical_transition_committed_during_verification_is_exact_replay() -> TestResult {
    let fixture = Fixture::new(DuringVerification::SameTransition)?;
    let snapshot = fixture.store.open_isolation_epoch(&fixture.transition)?;
    assert_eq!(fixture.store.load(&snapshot.key)?, Some(snapshot));
    let verifier: String = fixture.store.connection()?.query_row(
        "SELECT evidence_verifier_id FROM security_isolation_epochs WHERE isolation_epoch_id = 'new-epoch'",
        [], |row| row.get(0),
    )?;
    assert_eq!(verifier, "competitor-verifier");
    assert_eq!(fixture.verifier.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn conflicting_epoch_committed_during_verification_is_not_overwritten() -> TestResult {
    let fixture = Fixture::new(DuringVerification::ConflictingTransition)?;
    let error = fixture
        .store
        .open_isolation_epoch(&fixture.transition)
        .err()
        .ok_or("conflicting epoch accepted")?;
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    let transition_id: String = fixture.store.connection()?.query_row(
        "SELECT transition_id FROM security_isolation_epochs WHERE isolation_epoch_id = 'new-epoch'",
        [], |row| row.get(0),
    )?;
    assert_eq!(transition_id, "competing-transition");
    Ok(())
}

#[test]
#[cfg(unix)]
fn source_retired_during_verification_cannot_open_a_new_epoch() -> TestResult {
    let fixture = Fixture::new(DuringVerification::RetireSource)?;
    let error = fixture
        .store
        .open_isolation_epoch(&fixture.transition)
        .err()
        .ok_or("retired source accepted epoch")?;
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::Conflict
    );
    let connection = Connection::open(&fixture.verifier.path)?;
    let epochs: i64 = connection.query_row(
        "SELECT count(*) FROM security_isolation_epochs WHERE isolation_epoch_id = 'new-epoch'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(epochs, 0);
    Ok(())
}
