//! Framed counter readers only. This fixture mints no native owner or allowance.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    connection: Connection,
    scope: RecoveryScopeV1,
    value: ReferenceCapacity,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(crate::admission_operation_store::recovery::SQL)?;
        connection.execute_batch(
            "CREATE TABLE authority_global_commits(
                commit_sequence INTEGER PRIMARY KEY,projection_kind TEXT NOT NULL,
                projection_key TEXT NOT NULL,projection_sequence INTEGER NOT NULL,
                projection_reference_digest TEXT NOT NULL,chain_digest TEXT NOT NULL
             );
             CREATE INDEX authority_global_commits_projection ON authority_global_commits
                (projection_kind,projection_key,projection_sequence);
             CREATE TABLE authority_global_commit_meta(
                singleton INTEGER PRIMARY KEY,head_sequence INTEGER NOT NULL,
                head_chain_digest TEXT NOT NULL
             );",
        )?;
        let initial = hex::encode([17_u8; 32]);
        connection.execute(
            "INSERT INTO authority_global_commits VALUES(1,'fixture','baseline',1,?1,?1)",
            [&initial],
        )?;
        connection.execute(
            "INSERT INTO authority_global_commit_meta VALUES(1,1,?1)",
            [&initial],
        )?;
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("reference-counter-authority")?,
            tenant_id: RecoveryTenantId::new("reference-counter-tenant")?,
            process_id: ProcessId::new("reference-counter-process")?,
        };
        // Cutoff is evidence data. The fixture does not call an intake factory.
        let cutoff = serde_json::from_value(serde_json::json!({
            "sequence":1,"chain_digest":vec![17_u8;32]
        }))?;
        let value = ReferenceCapacity {
            schema: ReferenceCapacitySchema::V1,
            account: ReferenceAccount::from_scope(&scope),
            baseline: CapacityBaseline {
                cutoff,
                cohort_digest: CanonicalPayloadDigest::from_bytes([21; 32]),
                census_digest: CanonicalPayloadDigest::from_bytes([22; 32]),
                artifact_count: 1,
                active_owners: 0,
            },
            admitted: 0,
            retired: 0,
            batches: 0,
        };
        let fixture = Self {
            connection,
            scope,
            value,
        };
        fixture.append(&fixture.value)?;
        Ok(fixture)
    }

    fn append(&self, value: &ReferenceCapacity) -> TestResult<(u64, Vec<u8>)> {
        let (key, scope) = identity(&self.scope)?;
        let version = raw(&self.connection, &key)?.map_or(1, |row| row.version + 1);
        let payload = encode(value)?;
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
             VALUES(?1,?2,'command',?3,?4) ON CONFLICT(record_key)
             DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![key,scope,i64::try_from(version)?,&payload],
        )?;
        let last: Option<(i64,String)> = self.connection.query_row(
            "SELECT sequence,event_digest FROM admission_operation_recovery_events ORDER BY sequence DESC LIMIT 1",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let (event_sequence, previous) =
            last.map_or((1, "0".repeat(64)), |(n, digest)| (n + 1, digest));
        let event_sequence_u64 = u64::try_from(event_sequence)?;
        let digest = record_digest(&key, &scope, "command", version, &payload, None, None)?;
        let event = event_digest(
            event_sequence_u64,
            &key,
            version,
            &digest,
            &previous,
            event_sequence_u64,
        )?;
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?1)",
            params![event_sequence,key,i64::try_from(version)?,digest,previous,event],
        )?;
        let global: i64 = self.connection.query_row(
            "SELECT head_sequence+1 FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        self.connection.execute(
            "INSERT INTO authority_global_commits VALUES(?1,'recovery',?2,?3,?4,?4)",
            params![global, key, i64::try_from(version)?, event],
        )?;
        self.connection.execute(
            "UPDATE authority_global_commit_meta SET head_sequence=?1,head_chain_digest=?2 WHERE singleton=1",
            params![global,event],
        )?;
        Ok((version, payload))
    }

    fn advanced(&self) -> TestResult<(u64, Vec<u8>)> {
        let mut value = self.value.clone();
        value.admitted = 2;
        value.batches = 1;
        let prior = self.append(&value)?;
        value.retired = 1;
        value.batches = 2;
        self.append(&value)?;
        assert_eq!(load_capacity(&self.connection, &self.scope)?.0.active()?, 1);
        Ok(prior)
    }

    fn refuses(&self) {
        let before = self.connection.total_changes();
        assert!(matches!(
            load_capacity(&self.connection, &self.scope),
            Err(AdmissionOperationStoreError::Invariant(_))
        ));
        assert_eq!(self.connection.total_changes(), before);
    }

    fn later_global(&self, duplicate: bool) -> TestResult {
        let (key, _) = identity(&self.scope)?;
        let row = raw(&self.connection, &key)?.ok_or("counter absent")?;
        let reference: String = self.connection.query_row(
            "SELECT event_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
            params![key,i64::try_from(row.version)?], |row| row.get(0),
        )?;
        let version = row.version + u64::from(!duplicate);
        self.connection.execute(
            "INSERT INTO authority_global_commits
             SELECT max(commit_sequence)+1,'recovery',?1,?2,?3,?3 FROM authority_global_commits",
            params![key, i64::try_from(version)?, reference],
        )?;
        Ok(())
    }
}

#[test]
fn current_reference_counter_head_is_read_only() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.advanced()?;
    let before = fixture.connection.total_changes();
    assert_eq!(
        load_capacity(&fixture.connection, &fixture.scope)?
            .0
            .active()?,
        1
    );
    assert_eq!(fixture.connection.total_changes(), before);
    Ok(())
}

#[test]
fn authentic_prior_reference_counter_cannot_mint_current_capacity() -> TestResult {
    let fixture = Fixture::new()?;
    let (version, payload) = fixture.advanced()?;
    fixture
        .connection
        .execute_batch("DROP TRIGGER admission_operation_recovery_identity")?;
    let (key, _) = identity(&fixture.scope)?;
    fixture.connection.execute(
        "UPDATE admission_operation_recovery_records SET version=?2,payload=?3 WHERE record_key=?1",
        params![key, i64::try_from(version)?, payload],
    )?;
    assert_eq!(
        raw(&fixture.connection, &key)?
            .ok_or("prior authentic counter absent")?
            .version,
        version
    );
    fixture.refuses();
    Ok(())
}

#[test]
fn newer_reference_counter_global_reference_refuses_read_only() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.advanced()?;
    fixture.later_global(false)?;
    fixture.refuses();
    Ok(())
}

#[test]
fn duplicate_current_reference_counter_global_reference_refuses_read_only() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.advanced()?;
    fixture.later_global(true)?;
    fixture.refuses();
    Ok(())
}

#[test]
fn reference_counter_projection_loss_cannot_initialize_zero() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.advanced()?;
    fixture
        .connection
        .execute_batch("DROP TRIGGER admission_operation_recovery_no_delete")?;
    let (key, _) = identity(&fixture.scope)?;
    fixture.connection.execute(
        "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
        [&key],
    )?;
    assert!(raw(&fixture.connection, &key)?.is_none());
    fixture.refuses();
    Ok(())
}

#[test]
fn authenticated_current_reference_counter_retains_immutable_first_census() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.advanced()?;
    let mut value = load_capacity(&fixture.connection, &fixture.scope)?.0;
    value.admitted = 3;
    value.batches = 3;
    value.baseline.cohort_digest = CanonicalPayloadDigest::from_bytes([99; 32]);
    fixture.append(&value)?;
    // The altered current frame is genuine in this isolated fixture. Its
    // immutable first body still carries the original cohort.
    fixture.refuses();
    Ok(())
}
