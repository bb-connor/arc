//! Current metadata reader contracts, independent of native owner adoption.
//! Deliberate projection damage preserves authentic immutable event references.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    connection: Connection,
    scope: RecoveryScopeV1,
    workflow: WorkflowId,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(super::super::super::SQL)?;
        connection.execute_batch(
            "CREATE TABLE authority_global_commits (
                commit_sequence INTEGER PRIMARY KEY,
                projection_kind TEXT NOT NULL, projection_key TEXT NOT NULL,
                projection_sequence INTEGER NOT NULL,
                projection_reference_digest TEXT NOT NULL
            );
            CREATE INDEX authority_global_commits_projection ON authority_global_commits
                (projection_kind,projection_key,projection_sequence);",
        )?;
        Ok(Self {
            connection,
            scope: RecoveryScopeV1 {
                authority_domain: AuthorityDomainId::new("metadata-head-authority")?,
                tenant_id: RecoveryTenantId::new("metadata-head-tenant")?,
                process_id: ProcessId::new("metadata-head-process")?,
            },
            workflow: WorkflowId::new("metadata-head-workflow")?,
        })
    }

    fn append<T: Serialize>(
        &self,
        key: &str,
        scope: &str,
        kind: &str,
        value: &T,
    ) -> TestResult<(u64, Vec<u8>, String)> {
        let old = raw(&self.connection, key)?;
        let version = old.map_or(1, |row| row.version + 1);
        let payload = encode(value)?;
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(record_key) DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![key, scope, kind, i64::try_from(version)?, &payload],
        )?;
        let last: Option<(i64, String)> = self
            .connection
            .query_row(
                "SELECT sequence,event_digest FROM admission_operation_recovery_events
             ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (sequence, previous) = last.map_or((1, "0".repeat(64)), |(n, hash)| (n + 1, hash));
        let sequence = u64::try_from(sequence)?;
        let digest = record_digest(key, scope, kind, version, &payload, None, None)?;
        let event = event_digest(sequence, key, version, &digest, &previous, sequence)?;
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?1)",
            params![i64::try_from(sequence)?, key, i64::try_from(version)?, &digest, previous, &event],
        )?;
        self.connection.execute(
            "INSERT INTO authority_global_commits
             (commit_sequence,projection_kind,projection_key,projection_sequence,projection_reference_digest)
             VALUES(?1,'recovery',?2,?3,?4)",
            params![i64::try_from(sequence)?, key, i64::try_from(version)?, event],
        )?;
        Ok((version, payload, digest))
    }

    fn capacity(&self) -> TestResult<(String, u64, Vec<u8>)> {
        let value = Capacity {
            schema: CapacitySchema::V1,
            authority_domain: self.scope.authority_domain.clone(),
            tenant_id: None,
            legacy_cutoff: SafeInteger::ZERO,
            baseline: SafeInteger::ZERO,
            admitted: SafeInteger::ZERO,
            retired: SafeInteger::ZERO,
        };
        let (key, scope) = capacity_identity(&value.authority_domain, None)?;
        self.append(&key, &scope, "command", &value)?;
        let mut value = value;
        value.admitted = SafeInteger::new(1)?;
        let (version, payload, _) = self.append(&key, &scope, "command", &value)?;
        value.retired = SafeInteger::new(1)?;
        self.append(&key, &scope, "command", &value)?;
        assert_eq!(self.load_capacity()?.ok_or("capacity absent")?.active()?, 0);
        Ok((key, version, payload))
    }

    fn allocation(&self) -> TestResult<(String, u64, Vec<u8>)> {
        let scope = scope_key(&self.scope)?;
        let source = workflow_key(&self.scope, &self.workflow)?;
        // These source event preimages exercise the allocation's exact digest
        // links. They do not represent a native workflow or terminal proof.
        let (version, _, digest) = self.append(&source, &scope, "workflow", &"created")?;
        let value = Allocation {
            schema: AllocationSchema::V1,
            scope: self.scope.clone(),
            workflow_id: self.workflow.clone(),
            creation_version: SafeInteger::new(version)?,
            creation_digest: digest,
            retirement: None,
        };
        let key = allocation_key(&self.scope, &self.workflow)?;
        let (version, payload, _) = self.append(&key, &scope, "command", &value)?;
        let (terminal_version, _, terminal_digest) =
            self.append(&source, &scope, "workflow", &"closed")?;
        let mut value = value;
        value.retirement = Some(Retirement {
            workflow_version: SafeInteger::new(terminal_version)?,
            workflow_digest: terminal_digest,
            captured_terminal: None,
        });
        self.append(&key, &scope, "command", &value)?;
        assert!(self
            .load_allocation()?
            .ok_or("allocation absent")?
            .retirement
            .is_some());
        Ok((key, version, payload))
    }

    fn load_capacity(&self) -> Result<Option<Capacity>, AdmissionOperationStoreError> {
        load_capacity(&self.connection, &self.scope.authority_domain, None)
    }

    fn load_allocation(&self) -> Result<Option<Allocation>, AdmissionOperationStoreError> {
        load_allocation(&self.connection, &self.scope, &self.workflow)
    }

    fn restore(&self, key: &str, version: u64, payload: &[u8]) -> TestResult {
        self.connection
            .execute_batch("DROP TRIGGER admission_operation_recovery_identity")?;
        self.connection.execute(
            "UPDATE admission_operation_recovery_records SET version=?2,payload=?3 WHERE record_key=?1",
            params![key, i64::try_from(version)?, payload],
        )?;
        assert_eq!(
            raw(&self.connection, key)?
                .ok_or("authentic old row absent")?
                .version,
            version
        );
        Ok(())
    }

    fn later_global(&self, key: &str, duplicate: bool) -> TestResult {
        let current = raw(&self.connection, key)?.ok_or("current row absent")?;
        let (version, digest) = if duplicate {
            let reference: String = self.connection.query_row(
                "SELECT event_digest FROM admission_operation_recovery_events
                 WHERE record_key=?1 AND record_version=?2",
                params![key, i64::try_from(current.version)?],
                |row| row.get(0),
            )?;
            (current.version, reference)
        } else {
            (current.version + 1, "1".repeat(64))
        };
        self.connection.execute(
            "INSERT INTO authority_global_commits
             (commit_sequence,projection_kind,projection_key,projection_sequence,projection_reference_digest)
             SELECT max(commit_sequence)+1,'recovery',?1,?2,?3 FROM authority_global_commits",
            params![key, i64::try_from(version)?, digest],
        )?;
        Ok(())
    }

    fn refuses<T>(&self, read: impl FnOnce() -> Result<Option<T>, AdmissionOperationStoreError>) {
        let before = self.connection.total_changes();
        assert!(
            matches!(read(), Err(AdmissionOperationStoreError::Invariant(_))),
            "current metadata consumer accepted an obsolete or ambiguous authenticated head"
        );
        assert_eq!(self.connection.total_changes(), before);
    }
}

#[test]
fn current_capacity_head_is_read_only() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.capacity()?;
    let before = fixture.connection.total_changes();
    assert_eq!(
        fixture
            .load_capacity()?
            .ok_or("capacity absent")?
            .active()?,
        0
    );
    assert_eq!(fixture.connection.total_changes(), before);
    Ok(())
}

#[test]
fn authentic_prior_capacity_cannot_replace_current_counts() -> TestResult {
    let fixture = Fixture::new()?;
    let (key, version, payload) = fixture.capacity()?;
    fixture.restore(&key, version, &payload)?;
    fixture.refuses(|| fixture.load_capacity());
    Ok(())
}

#[test]
fn newer_global_capacity_reference_refuses_current_counter() -> TestResult {
    let fixture = Fixture::new()?;
    let (key, _, _) = fixture.capacity()?;
    fixture.later_global(&key, false)?;
    fixture.refuses(|| fixture.load_capacity());
    Ok(())
}

#[test]
fn duplicate_current_capacity_global_reference_refuses_counter() -> TestResult {
    let fixture = Fixture::new()?;
    let (key, _, _) = fixture.capacity()?;
    fixture.later_global(&key, true)?;
    fixture.refuses(|| fixture.load_capacity());
    Ok(())
}

#[test]
fn current_retired_allocation_head_is_read_only() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.allocation()?;
    let before = fixture.connection.total_changes();
    assert!(fixture
        .load_allocation()?
        .ok_or("allocation absent")?
        .retirement
        .is_some());
    assert_eq!(fixture.connection.total_changes(), before);
    Ok(())
}

#[test]
fn authentic_pending_allocation_cannot_replace_retirement() -> TestResult {
    let fixture = Fixture::new()?;
    let (key, version, payload) = fixture.allocation()?;
    fixture.restore(&key, version, &payload)?;
    fixture.refuses(|| fixture.load_allocation());
    Ok(())
}

#[test]
fn newer_global_allocation_reference_refuses_current_lease() -> TestResult {
    let fixture = Fixture::new()?;
    let (key, _, _) = fixture.allocation()?;
    fixture.later_global(&key, false)?;
    fixture.refuses(|| fixture.load_allocation());
    Ok(())
}

#[test]
fn duplicate_current_allocation_global_reference_refuses_lease() -> TestResult {
    let fixture = Fixture::new()?;
    let (key, _, _) = fixture.allocation()?;
    fixture.later_global(&key, true)?;
    fixture.refuses(|| fixture.load_allocation());
    Ok(())
}
