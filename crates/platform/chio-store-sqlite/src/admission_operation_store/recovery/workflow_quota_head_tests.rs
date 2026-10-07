//! Current quota readers require the latest authenticated metadata head.
//! These framed reader fixtures do not claim native owner adoption or capture.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    connection: Connection,
    record: RecoveryWorkflowRecordV1,
    old_quota: Vec<u8>,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        use chio_core::capability::{scope::ChioScope, token::CapabilityTokenBody};
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
        let signer = chio_core::Keypair::from_seed(&[41; 32]);
        let capability = chio_core::capability::token::CapabilityToken::sign(
            CapabilityTokenBody {
                id: "quota-reader-capability".into(),
                issuer: signer.public_key(),
                subject: signer.public_key(),
                scope: ChioScope::default(),
                issued_at: 1,
                expires_at: 100,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &signer,
        )?;
        let seed: ToolCallRequest = serde_json::from_value(serde_json::json!({
            "request_id":"quota-reader-original",
            "capability":capability,
            "tool_name":"quota-reader-tool",
            "server_id":"quota-reader-server",
            "agent_id":signer.public_key().to_hex(),
            "arguments":{}
        }))?;
        let record = RecoveryWorkflowRecordV1 {
            scope: RecoveryScopeV1 {
                authority_domain: AuthorityDomainId::new("quota-head-authority")?,
                tenant_id: RecoveryTenantId::new("quota-head-tenant")?,
                process_id: ProcessId::new("quota-head-process")?,
            },
            origin: None,
            workflow_id: WorkflowId::new("quota-head-workflow")?,
            step_id: StepId::new("quota-head-step")?,
            continuation_id: ContinuationId::new("quota-head-continuation")?,
            revision: SafeInteger::new(1)?,
            control: WorkflowControlV1::Active,
            creation_seed: ProtectedText::new(std::str::from_utf8(&encode(&seed)?)?)?,
            seed,
            deployment_digest: DeploymentDigest::from_bytes([7; 32]),
            created_by: chio_security_types::PrincipalId::new("quota-head-principal")?,
            effect_cardinality: SafeInteger::new(1)?,
            action: None,
            process_reservation: None,
            selected: false,
            review: None,
            approval: None,
            issuance: None,
            signed_grant: None,
            envelope: None,
            admission: None,
            admission_closed: false,
            native_link: None,
            captured: false,
            captured_deployment: None,
            historical_hold: None,
            effect: EffectObservationV1::NeverAdmitted,
            release: ReleaseDispositionV1::NotAvailable,
            original_flow: None,
            reported_decision: None,
            provider_finality: None,
            provider_lookups: SafeInteger::ZERO,
        };
        let mut fixture = Self {
            connection,
            record,
            old_quota: Vec::new(),
        };
        let scope = scope_key(&fixture.record.scope)?;
        fixture.append(
            &workflow_key(&fixture.record.scope, &fixture.record.workflow_id)?,
            &scope,
            "workflow",
            &fixture.record,
        )?;
        let mut quota = WorkflowQuota {
            schema: WorkflowQuotaSchema::V1,
            scope: fixture.record.scope.clone(),
            workflow_id: fixture.record.workflow_id.clone(),
            baseline_revision: SafeInteger::ZERO,
            baseline_commands: SafeInteger::ZERO,
            planning: SafeInteger::new(1)?,
            control: SafeInteger::ZERO,
            native: SafeInteger::ZERO,
            commands: [SafeInteger::ZERO; 6],
            native_archive: None,
            native_hold: None,
            native_terminal: None,
            native_release: None,
        };
        let key = fixture.quota_key()?;
        fixture.old_quota = encode(&quota)?;
        fixture.append(&key, &scope, "command", &quota)?;
        let body = RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: fixture.record.workflow_id.clone(),
            expected_revision: fixture.record.revision,
        };
        let command_id = CommandId::new("first-quota-head-resume")?;
        let command_key = format!(
            "command:{}",
            sha256_hex(&encode(&(
                &fixture.record.scope,
                &fixture.record.created_by,
                body.permission(),
                &command_id,
            ))?)
        );
        let response = RecoveryCommandResponseV1 {
            command_id,
            workflow_id: fixture.record.workflow_id.clone(),
            revision: fixture.record.revision,
            control: fixture.record.control,
            effect: fixture.record.effect.clone(),
            release: fixture.record.release.clone(),
        };
        fixture.append(
            &command_key,
            &scope,
            "command",
            &serde_json::json!({
                "digest":CommandDigest::from_bytes(hash(RecoveryDigestDomain::Command,&body)?),
                "response":response,
            }),
        )?;
        quota.commands[3] = SafeInteger::new(1)?;
        fixture.append(&key, &scope, "command", &quota)?;
        assert_eq!(fixture.read()?.commands[3].get(), 1);
        Ok(fixture)
    }

    fn quota_key(&self) -> TestResult<String> {
        Ok(quota_key(&self.record.scope, &self.record.workflow_id)?)
    }

    fn append<T: Serialize>(&self, key: &str, scope: &str, kind: &str, value: &T) -> TestResult {
        let version = raw(&self.connection, key)?.map_or(1, |row| row.version + 1);
        let payload = encode(value)?;
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(record_key) DO UPDATE SET version=excluded.version,payload=excluded.payload",
            params![key, scope, kind, i64::try_from(version)?, payload],
        )?;
        let prior: Option<(i64, String)> = self.connection.query_row(
            "SELECT sequence,event_digest FROM admission_operation_recovery_events ORDER BY sequence DESC LIMIT 1",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let (sequence, previous) = prior.map_or((1, "0".repeat(64)), |(n, hash)| (n + 1, hash));
        let sequence = u64::try_from(sequence)?;
        let digest = record_digest(key, scope, kind, version, &encode(value)?, None, None)?;
        let event = event_digest(sequence, key, version, &digest, &previous, sequence)?;
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?1)",
            params![i64::try_from(sequence)?,key,i64::try_from(version)?,digest,previous,&event],
        )?;
        self.connection.execute(
            "INSERT INTO authority_global_commits
             (commit_sequence,projection_kind,projection_key,projection_sequence,projection_reference_digest)
             VALUES(?1,'recovery',?2,?3,?4)",
            params![i64::try_from(sequence)?,key,i64::try_from(version)?,event],
        )?;
        Ok(())
    }

    fn read(&self) -> Result<WorkflowQuota, AdmissionOperationStoreError> {
        workflow_quota(
            &self.connection,
            &self.record.scope,
            &self.record.workflow_id,
        )
    }

    fn later_global(&self, duplicate: bool) -> TestResult {
        let key = self.quota_key()?;
        let current = raw(&self.connection, &key)?.ok_or("quota absent")?;
        let (version, reference) = if duplicate {
            let reference: String = self.connection.query_row(
                "SELECT event_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
                params![&key,i64::try_from(current.version)?], |row| row.get(0),
            )?;
            (current.version, reference)
        } else {
            (current.version + 1, "2".repeat(64))
        };
        self.connection.execute(
            "INSERT INTO authority_global_commits
             (commit_sequence,projection_kind,projection_key,projection_sequence,projection_reference_digest)
             SELECT max(commit_sequence)+1,'recovery',?1,?2,?3 FROM authority_global_commits",
            params![key,i64::try_from(version)?,reference],
        )?;
        Ok(())
    }

    fn refuses(&self) {
        let before = self.connection.total_changes();
        assert!(
            matches!(self.read(), Err(AdmissionOperationStoreError::Invariant(_))),
            "workflow quota reader accepted an obsolete or ambiguous authenticated head"
        );
        assert_eq!(self.connection.total_changes(), before);
    }
}

#[test]
fn current_workflow_quota_head_is_read_only() -> TestResult {
    let fixture = Fixture::new()?;
    let before = fixture.connection.total_changes();
    assert_eq!(fixture.read()?.commands[3].get(), 1);
    assert_eq!(fixture.connection.total_changes(), before);
    Ok(())
}

#[test]
fn authentic_prior_quota_cannot_remove_an_accepted_resume_marker() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .connection
        .execute_batch("DROP TRIGGER admission_operation_recovery_identity")?;
    fixture.connection.execute(
        "UPDATE admission_operation_recovery_records SET version=1,payload=?2 WHERE record_key=?1",
        params![fixture.quota_key()?, fixture.old_quota],
    )?;
    assert_eq!(
        raw_checked(&fixture.connection, &fixture.quota_key()?)?
            .ok_or("old quota absent")?
            .version,
        1
    );
    fixture.refuses();
    Ok(())
}

#[test]
fn newer_global_quota_reference_refuses_current_allowance() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.later_global(false)?;
    fixture.refuses();
    Ok(())
}

#[test]
fn duplicate_current_quota_global_reference_refuses_allowance() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.later_global(true)?;
    fixture.refuses();
    Ok(())
}
