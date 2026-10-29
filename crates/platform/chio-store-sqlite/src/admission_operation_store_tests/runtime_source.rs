use super::*;

#[path = "runtime_source/encoding.rs"]
mod encoding;
use chio_kernel::admission_operation::{RuntimeSourcePort, RuntimeSourceQualificationV1};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[path = "runtime_source/claims.rs"]
mod claims;

#[path = "runtime_source/requalification.rs"]
mod requalification;

const SOURCE_ID: &str = "runtime-source";
const RUNTIME_ID: &str = "runtime-authority";

#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    Refuse,
    Reenter,
    ChangeOwner,
}

struct Source {
    store: SqliteAdmissionOperationStore,
    fence: StoreMutationFence,
    behavior: Behavior,
    qualification: Mutex<Option<RuntimeSourceQualificationV1>>,
    calls: AtomicUsize,
}

impl Source {
    fn new(fixture: &Fixture, behavior: Behavior) -> Self {
        Self {
            store: fixture.store.clone(),
            fence: fixture.fence.clone(),
            behavior,
            qualification: Mutex::new(None),
            calls: AtomicUsize::new(0),
        }
    }
}

impl RuntimeSourcePort for Source {
    fn qualify(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeSourceQualificationV1, AdmissionOperationStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        {
            let connection = self
                .store
                .connection
                .try_lock()
                .expect("callback outside destination lock");
            assert!(connection.is_autocommit());
        }
        match self.behavior {
            Behavior::Refuse => {
                return Err(AdmissionOperationStoreError::Invariant(
                    "injected source qualification refusal".into(),
                ))
            }
            Behavior::Reenter => {
                self.store.install_runtime_source(
                    source_id,
                    runtime_authority_id,
                    self,
                    &self.fence,
                    now_ms(),
                )?;
                return Err(AdmissionOperationStoreError::Invariant(
                    "reentrant installation unexpectedly succeeded".into(),
                ));
            }
            Behavior::ChangeOwner => {
                self.store.connection()?.execute(
                    "UPDATE chio_serving_owner SET owner_epoch = ?1, lease_id = 'replacement-lease' WHERE singleton = 1",
                    [i64::try_from(self.fence.owner_epoch + 1).expect("epoch")],
                ).expect("advance actual owner row during callback");
            }
            Behavior::Normal => {}
        }
        let candidate = RuntimeSourceQualificationV1::new(
            source_id.clone(),
            runtime_authority_id.clone(),
            destination_authority_id.clone(),
            1,
            2,
            1,
        )?;
        let mut retained = self.qualification.lock().expect("source qualification");
        if retained.as_ref().is_some_and(|value| value != &candidate) {
            return Err(AdmissionOperationStoreError::Invariant(
                "test source binding changed".into(),
            ));
        }
        *retained = Some(candidate.clone());
        Ok(candidate)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeSourceQualificationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self
            .store
            .connection
            .try_lock()
            .expect("verify outside destination lock");
        assert!(connection.is_autocommit());
        if self
            .qualification
            .lock()
            .expect("source qualification")
            .as_ref()
            != Some(expected)
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "test source qualification differs".into(),
            ));
        }
        Ok(())
    }
}

fn install(
    fixture: &Fixture,
    source: &Source,
) -> Result<RuntimeSourceRecordV1, AdmissionOperationStoreError> {
    fixture.store.install_runtime_source(
        &identifier("source", SOURCE_ID),
        &identifier("runtime", RUNTIME_ID),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn load(fixture: &Fixture) -> Result<Option<RuntimeSourceRecordV1>, AdmissionOperationStoreError> {
    fixture
        .store
        .load_runtime_source(&identifier("runtime", RUNTIME_ID), &fixture.fence, now_ms())
}

fn global_count(store: &SqliteAdmissionOperationStore) -> i64 {
    store
        .connection()
        .expect("destination connection")
        .query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .expect("global count")
}

fn source_count(store: &SqliteAdmissionOperationStore) -> i64 {
    store
        .connection()
        .expect("destination connection")
        .query_row(
            "SELECT COUNT(*) FROM runtime_source_qualifications",
            [],
            |row| row.get(0),
        )
        .expect("source count")
}

#[test]
fn qualification_refusal_precedes_destination_mutation() -> Result<(), Box<dyn Error>> {
    for behavior in [Behavior::Normal, Behavior::Refuse] {
        let fixture = fixture();
        let source = Source::new(&fixture, behavior);
        let before = global_count(&fixture.store);
        let result = install(&fixture, &source);
        if matches!(behavior, Behavior::Normal) {
            let installed = result?;
            assert_eq!(load(&fixture)?, Some(installed.clone()));
            assert_eq!(install(&fixture, &source)?, installed);
            assert_eq!(source_count(&fixture.store), 1);
            assert_eq!(global_count(&fixture.store), before + 1);
        } else {
            assert_eq!(
                result,
                Err(AdmissionOperationStoreError::Invariant(
                    "injected source qualification refusal".into()
                ))
            );
            assert_eq!(source_count(&fixture.store), 0);
            assert_eq!(global_count(&fixture.store), before);
        }
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn reentrant_source_installation_refuses_without_destination_mutation() {
    let fixture = fixture();
    let source = Source::new(&fixture, Behavior::Reenter);
    let before = global_count(&fixture.store);
    assert_eq!(
        install(&fixture, &source),
        Err(AdmissionOperationStoreError::Invariant(
            "invalid sqlite authority store: replay source migration is already in progress".into(),
        ))
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(source_count(&fixture.store), 0);
    assert_eq!(global_count(&fixture.store), before);
}

#[test]
fn owner_fence_change_during_source_callback_refuses_destination_installation() {
    let fixture = fixture();
    let source = Source::new(&fixture, Behavior::ChangeOwner);
    let before = global_count(&fixture.store);
    assert_eq!(
        install(&fixture, &source),
        Err(AdmissionOperationStoreError::Fenced)
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(source_count(&fixture.store), 0);
    assert_eq!(global_count(&fixture.store), before);
}

#[test]
fn runtime_and_governed_authority_projection_coverage_and_pristine_are_independent(
) -> Result<(), Box<dyn Error>> {
    use crate::admission_operation_store::{
        verify_governed_approval_authority_pristine,
        verify_governed_approval_authority_projection_coverage, verify_runtime_source_pristine,
        verify_runtime_source_projection_coverage,
    };
    use crate::serving_owner::SqliteServingOwnerError;

    let fixture = fixture();
    {
        let connection = fixture.store.connection()?;
        verify_runtime_source_pristine(&connection)?;
        verify_governed_approval_authority_pristine(&connection)?;
        verify_runtime_source_projection_coverage(&connection)?;
        verify_governed_approval_authority_projection_coverage(&connection)?;
    }
    let source = Source::new(&fixture, Behavior::Normal);
    install(&fixture, &source)?;
    {
        let connection = fixture.store.connection()?;
        verify_governed_approval_authority_pristine(&connection)?;
        verify_runtime_source_projection_coverage(&connection)?;
        verify_governed_approval_authority_projection_coverage(&connection)?;
        assert!(matches!(verify_runtime_source_pristine(&connection),
            Err(SqliteServingOwnerError::Invalid(detail))
            if detail == "runtime source qualification integrity: runtime source qualification state is not pristine"));
    }
    let approval_binding = chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1::new(
        identifier("authority", "approval-authority"),
        identifier("generation", "approval-generation"),
    );
    fixture.store.install_governed_approval_authority(
        &approval_binding,
        8,
        &fixture.fence,
        now_ms(),
    )?;
    {
        let connection = fixture.store.connection()?;
        verify_runtime_source_projection_coverage(&connection)?;
        verify_governed_approval_authority_projection_coverage(&connection)?;
        verify_admission_operation_invariants(&connection)?;
        assert!(
            matches!(verify_governed_approval_authority_pristine(&connection),
            Err(SqliteServingOwnerError::Invalid(detail))
            if detail == "governed approval authority integrity: governed approval authority state is not pristine")
        );
    }
    Ok(())
}
