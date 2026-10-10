//! Checkpoint identity controls use the protected writer and real serving anchors.
use super::*;
use std::error::Error;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct CheckpointFixture {
    _directory: tempfile::TempDir,
    _authority: crate::SqliteAuthorityStore,
    store: SqliteAdmissionOperationStore,
    scope: RecoveryScopeV1,
}

impl CheckpointFixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
        crate::SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = crate::SqliteAuthorityStore::open_serving(&database, &locks)?;
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new(&authority.mutation_fence().store_uuid)?,
            tenant_id: RecoveryTenantId::new("tenant")?,
            process_id: ProcessId::new("process")?,
        };
        let store = authority.admission_operation_store();
        Ok(Self {
            _directory: directory,
            _authority: authority,
            store,
            scope,
        })
    }

    fn checkpoint(
        &self,
        id: &str,
        revision: u64,
        artifact: &str,
    ) -> TestResult<LabeledCheckpointV1> {
        Ok(LabeledCheckpointV1 {
            domain_version: VersionV1,
            checkpoint: CheckpointId::new(id)?,
            revision: SafeInteger::new(revision)?,
            scope: self.scope.clone(),
            runtime: ProtectedText::new("runtime")?,
            artifacts: NonEmptyBoundedList::new(vec![ArtifactVersionRefV1 {
                scope: self.scope.clone(),
                artifact: ArtifactId::new(artifact)?,
                version: ArtifactRevisionId::new("revision")?,
                provenance: ProvenanceDigest::from_bytes([1; 32]),
            }])?,
            model_contexts: BoundedList::new(vec![])?,
            label: InformationLabel::bottom(),
            influence: ArtifactInfluenceV1 {
                commitment: CanonicalPayloadDigest::from_bytes([2; 32]),
                externally_influenced: false,
                unknown: false,
            },
            lineage: IsolationLineageId::new("lineage")?,
            isolation_epoch: ProtectedText::new("epoch")?,
            native_evidence_sequence: SafeInteger::new(1)?,
            policy: PolicyDigest::from_bytes([3; 32]),
        })
    }

    fn seed(&self, key: &str, checkpoint: &LabeledCheckpointV1) -> TestResult {
        let mut connection = self.store.connection()?;
        let tx = self.store.begin_write(&mut connection, None)?;
        save(&tx, &self.store.serving_owner, &self.scope, key, checkpoint)?;
        self.store.commit_write(tx)?;
        self.store.sync_after_write(&connection)?;
        Ok(())
    }

    fn read(&self, id: &str, revision: u64) -> TestResult<Option<LabeledCheckpointV1>> {
        let mut connection = self.store.connection()?;
        let tx = self.store.begin_read(&mut connection)?;
        let checkpoint = load_checkpoint(&tx, &self.scope, &CheckpointId::new(id)?, revision)?;
        tx.commit()?;
        Ok(checkpoint)
    }

    fn retain(&self, checkpoint: &LabeledCheckpointV1) -> TestResult {
        let mut connection = self.store.connection()?;
        let tx = self.store.begin_write(&mut connection, None)?;
        retain_checkpoint_revision(&tx, &self.store.serving_owner, checkpoint)?;
        self.store.commit_write(tx)?;
        self.store.sync_after_write(&connection)?;
        Ok(())
    }

    fn rows(&self) -> TestResult<Vec<(String, i64, Vec<u8>)>> {
        let connection = self.store.connection()?;
        let mut statement = connection.prepare(
            "SELECT record_key,version,payload FROM admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-checkpoint:*' ORDER BY record_key",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[test]
fn checkpoint_retained_revision_never_upserts_an_existing_envelope() -> TestResult {
    let fixture = CheckpointFixture::new()?;
    let first = fixture.checkpoint("job", 1, "first")?;
    fixture.retain(&first)?;
    let retained = fixture.rows()?;
    fixture.retain(&first)?;
    assert_eq!(
        fixture.rows()?,
        retained,
        "identical retention must not add a mutation"
    );
    let substituted = fixture.checkpoint("job", 1, "substituted")?;
    assert!(fixture.retain(&substituted).is_err());
    assert_eq!(fixture.rows()?, retained);
    assert_eq!(fixture.read("job", 1)?, Some(first));
    Ok(())
}

#[test]
fn checkpoint_mismatched_record_refuses_identity_substitution() -> TestResult {
    let fixture = CheckpointFixture::new()?;
    let first = fixture.checkpoint("job", 1, "first")?;
    let foreign = fixture.checkpoint("foreign", 1, "foreign")?;
    fixture.seed(
        &checkpoint_revision_key(&fixture.scope, &first.checkpoint, 1)?,
        &foreign,
    )?;
    assert!(fixture.read("job", 1).is_err());
    Ok(())
}

#[test]
fn checkpoint_record_with_a_wrong_revision_or_scope_fails_closed() -> TestResult {
    for wrong_scope in [false, true] {
        let fixture = CheckpointFixture::new()?;
        let mut malformed = fixture.checkpoint("job", if wrong_scope { 1 } else { 2 }, "first")?;
        if wrong_scope {
            malformed.scope.process_id = ProcessId::new("other-process")?;
        }
        fixture.seed(
            &checkpoint_revision_key(&fixture.scope, &CheckpointId::new("job")?, 1)?,
            &malformed,
        )?;
        assert!(fixture.read("job", 1).is_err());
    }
    Ok(())
}
