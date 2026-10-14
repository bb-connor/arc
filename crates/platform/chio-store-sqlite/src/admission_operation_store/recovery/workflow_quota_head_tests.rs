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
    /// The authenticated first workflow write, before any purpose allocation.
    fn unallocated() -> TestResult<Self> {
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
        let fixture = Self {
            connection,
            record,
            old_quota: Vec::new(),
        };
        fixture.append(
            &workflow_key(&fixture.record.scope, &fixture.record.workflow_id)?,
            &scope_key(&fixture.record.scope)?,
            "workflow",
            &fixture.record,
        )?;
        Ok(fixture)
    }

    fn new() -> TestResult<Self> {
        let mut fixture = Self::unallocated()?;
        let scope = scope_key(&fixture.record.scope)?;
        let mut quota = fixture.allocation(0)?;
        fixture.old_quota = encode(&quota)?;
        fixture.allocate(&quota)?;
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
        fixture.allocate(&quota)?;
        assert_eq!(fixture.read()?.commands[3].get(), 1);
        Ok(fixture)
    }

    fn quota_key(&self) -> TestResult<String> {
        Ok(quota_key(&self.record.scope, &self.record.workflow_id)?)
    }

    fn allocation(&self, baseline_revision: u64) -> TestResult<WorkflowQuota> {
        Ok(WorkflowQuota {
            schema: WorkflowQuotaSchema::V1,
            scope: self.record.scope.clone(),
            workflow_id: self.record.workflow_id.clone(),
            baseline_revision: SafeInteger::new(baseline_revision)?,
            baseline_commands: SafeInteger::ZERO,
            planning: SafeInteger::new(1)?,
            control: SafeInteger::ZERO,
            native: SafeInteger::ZERO,
            commands: [SafeInteger::ZERO; 6],
            native_archive: None,
            native_hold: None,
            native_terminal: None,
            native_release: None,
        })
    }

    fn allocate(&self, quota: &WorkflowQuota) -> TestResult {
        let scope = scope_key(&self.record.scope)?;
        self.append(&self.quota_key()?, &scope, "command", quota)
    }

    /// The next protected write of the workflow record.
    fn advance(&mut self) -> TestResult {
        self.record.revision = SafeInteger::new(self.record.revision.get() + 1)?;
        let key = workflow_key(&self.record.scope, &self.record.workflow_id)?;
        self.append(
            &key,
            &scope_key(&self.record.scope)?,
            "workflow",
            &self.record,
        )
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

const NATIVE_DEBT: &str = "unused original lacks its authentic zero native-purpose allocation";
const NOT_ONE_CONTROL: &str = "unused setup closure did not spend exactly one control purpose";

fn invariant_is<T>(result: Result<T, AdmissionOperationStoreError>, expected: &str) -> bool {
    matches!(
        result,
        Err(AdmissionOperationStoreError::Invariant(ref message)) if message == expected
    )
}

// The closing writer is replayed as its two protected appends; this does not
// claim a serving owner, setup selection or native capture.
#[test]
fn unused_setup_closure_spends_exactly_one_control_purpose() -> TestResult {
    let mut fixture = Fixture::unallocated()?;
    let mut quota = fixture.allocation(0)?;
    fixture.allocate(&quota)?;
    let before = source_reference(&fixture.connection, &fixture.quota_key()?)?;
    let proof = unused_setup_quota(&fixture.connection, &fixture.record)?;
    fixture.record.admission_closed = true;
    fixture.record.control = WorkflowControlV1::Cancelled;
    fixture.advance()?;
    quota.control = SafeInteger::new(1)?;
    fixture.allocate(&quota)?;
    proof.require_one_control_charge(&fixture.connection)?;
    let after = source_reference(&fixture.connection, before.record_key())?;
    assert_eq!(after.version(), before.version() + 1);
    assert_ne!(
        hex(after.digest().as_bytes()),
        hex(before.digest().as_bytes())
    );
    let current = fixture.read()?;
    assert_eq!(
        [
            current.planning.get(),
            current.control.get(),
            current.native.get()
        ],
        [1, 1, 0]
    );
    assert_eq!(current.baseline_revision.get(), 0);
    assert_eq!(current.units()?, after.version());
    Ok(())
}

#[test]
fn unused_setup_refuses_native_debt_and_legacy_or_absent_allocation() -> TestResult {
    let mut native = Fixture::unallocated()?;
    let mut quota = native.allocation(0)?;
    native.allocate(&quota)?;
    native.advance()?;
    quota.native = SafeInteger::new(1)?;
    native.allocate(&quota)?;
    // A quota first allocated over an existing workflow keeps a nonzero
    // authenticated baseline; absent fields there cannot prove no native use.
    let mut legacy = Fixture::unallocated()?;
    legacy.advance()?;
    legacy.allocate(&legacy.allocation(1)?)?;
    legacy.read()?;
    let absent = Fixture::unallocated()?;
    for (fixture, message) in [
        (&native, NATIVE_DEBT),
        (&legacy, NATIVE_DEBT),
        (
            &absent,
            "unused original lacks its authentic purpose allocation",
        ),
    ] {
        let before = fixture.connection.total_changes();
        assert!(
            invariant_is(
                unused_setup_quota(&fixture.connection, &fixture.record),
                message
            ),
            "unused setup accepted an allocation without its authentic zero native purpose"
        );
        assert_eq!(fixture.connection.total_changes(), before);
    }
    Ok(())
}

#[test]
fn unused_setup_closure_refuses_any_other_purpose_charge() -> TestResult {
    // Each case lists the (planning, control) allocation after every write.
    for writes in [&[][..], &[(2, 0)][..], &[(1, 1), (1, 2)][..]] {
        let mut fixture = Fixture::unallocated()?;
        let mut quota = fixture.allocation(0)?;
        fixture.allocate(&quota)?;
        let proof = unused_setup_quota(&fixture.connection, &fixture.record)?;
        fixture.record.admission_closed = true;
        fixture.record.control = WorkflowControlV1::Cancelled;
        for &(planning, control) in writes {
            fixture.advance()?;
            quota.planning = SafeInteger::new(planning)?;
            quota.control = SafeInteger::new(control)?;
            fixture.allocate(&quota)?;
        }
        assert!(
            invariant_is(
                proof.require_one_control_charge(&fixture.connection),
                NOT_ONE_CONTROL
            ),
            "unused setup closure accepted a charge other than exactly one Control purpose"
        );
    }
    Ok(())
}

/// A real body of the command kind that owns `slot`, against the fixture's
/// actual workflow identity. Only the kind matters to the slot gate.
fn slot_command_body(fixture: &Fixture, slot: usize) -> TestResult<RecoveryCommandBodyV1> {
    let workflow_id = fixture.record.workflow_id.clone();
    let expected_revision = fixture.record.revision;
    Ok(match slot {
        0 => RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("quota-head-slot-create")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: fixture.record.creation_seed.clone(),
        },
        1 => RecoveryCommandBodyV1::SelectOffer {
            workflow_id,
            expected_revision,
            offer_id: OfferId::new("offer:quota-head-slot")?,
        },
        2 => RecoveryCommandBodyV1::SubmitApproval {
            workflow_id,
            expected_revision,
            approval: fixture.record.creation_seed.clone(),
        },
        3 => RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id,
            expected_revision,
        },
        4 => RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id,
            expected_revision,
        },
        _ => RecoveryCommandBodyV1::ReportDecision {
            workflow_id,
            expected_revision,
            decision: RecoveryReportedDecision::Accepted,
        },
    })
}

/// Run the real `require_command_slot` gate inside one rolled-back read
/// transaction so its verdict never persists state.
fn slot_gate(
    fixture: &mut Fixture,
    body: &RecoveryCommandBodyV1,
) -> Result<(), AdmissionOperationStoreError> {
    let tx = fixture.connection.transaction().map_err(sqlite_error)?;
    let gated = require_command_slot(
        &tx,
        &fixture.record.scope,
        &fixture.record.workflow_id,
        body,
    );
    tx.rollback().map_err(sqlite_error)?;
    gated
}

/// Replaces the per-kind boundary obligations removed from the control-plane
/// quota fixtures: every non-Resume command kind must refuse its last slot at
/// the exact declared ceiling through the real authenticated gate, after
/// framing ceiling-1 authenticated counter units, while another kind keeps capacity.
/// This replays the same owning reader (`workflow_quota`, first-allocation
/// digest, global-head chain) that production charges through; the Resume
/// ceiling of 24 is exercised on genuinely charged mutations by the
/// control-plane saturation fixtures.
#[test]
fn require_command_slot_refuses_only_its_own_exhausted_kind() -> TestResult {
    for slot in [0_usize, 1, 2, 4, 5] {
        let ceiling = 8_u64;
        let mut fixture = Fixture::new()?;
        // Frame the target kind one authenticated unit per fixture write so
        // every intermediate head validates through the real reader. This
        // checks the fixed slot gate without claiming command admission.
        for charge in 1..ceiling {
            let mut quota = fixture.read()?;
            quota.commands[slot] = SafeInteger::new(charge)?;
            fixture.allocate(&quota)?;
            assert_eq!(fixture.read()?.commands[slot].get(), charge);
        }
        let body = slot_command_body(&fixture, slot)?;
        // At ceiling-1 the exact gate still admits the kind.
        let before = fixture.connection.total_changes();
        slot_gate(&mut fixture, &body)?;
        assert_eq!(fixture.connection.total_changes(), before);
        // One more authenticated fixture unit reaches the fixed per-kind ceiling.
        let mut quota = fixture.read()?;
        quota.commands[slot] = SafeInteger::new(ceiling)?;
        fixture.allocate(&quota)?;
        fixture.read()?;
        let before = fixture.connection.total_changes();
        assert!(
            invariant_is(
                slot_gate(&mut fixture, &body),
                "recovery command quota exhausted"
            ),
            "slot {slot} admitted a command at its exact ceiling {ceiling}"
        );
        assert_eq!(fixture.connection.total_changes(), before);
        // A different, non-target kind keeps its full independent capacity.
        let other = [0_usize, 1, 2, 4, 5]
            .into_iter()
            .find(|&candidate| candidate != slot)
            .ok_or("a non-target command kind is absent")?;
        let other_body = slot_command_body(&fixture, other)?;
        let before = fixture.connection.total_changes();
        slot_gate(&mut fixture, &other_body)?;
        assert_eq!(fixture.connection.total_changes(), before);
    }
    Ok(())
}
