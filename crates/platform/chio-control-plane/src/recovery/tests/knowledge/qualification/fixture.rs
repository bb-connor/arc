//! Fresh native authorities and independent provider/read counters per trial.
use super::*;
use crate::recovery::{RecoveryRuntimeError, RecoverySetupService};
use std::{future::Future, pin::Pin};

const ARTIFACT_BYTES: &[u8] = b"private-recovery-retained-research-checkpoint";

pub(super) struct CaseFixture {
    pub f: KnowledgeFixture,
    pub command: RecoveryCommandV1,
    pub workflow: String,
    pub case: String,
    handle: Option<ArtifactHandleV1>,
    sink: DurableSink,
    pub authority_contract: serde_json::Value,
    pub native_actions: AtomicUsize,
    observed_at_ms: u64,
    setup_process_charges: u32,
}

struct DurableSink {
    native: RecordingSink,
    path: std::path::PathBuf,
}
impl ArtifactReleaseSink for DurableSink {
    fn recipient(&self) -> &ArtifactRecipientV1 {
        self.native.recipient()
    }
    fn deliver(&self, intent: &ArtifactReleaseIntentV1, bytes: &[u8]) -> Result<(), KernelError> {
        // The existing sink independently checks native join-before-first-byte.
        self.native.deliver(intent, bytes)?;
        if bytes != ARTIFACT_BYTES {
            return Err(KernelError::Internal("qualification sink refused".into()));
        }
        let database = rusqlite::Connection::open(&self.path)
            .map_err(|_| KernelError::Internal("qualification sink refused".into()))?;
        database
            .execute(
                "INSERT INTO deliveries(release,content,size) VALUES (?1,?2,?3)",
                rusqlite::params![
                    intent.release.as_str(),
                    chio_core::sha256_hex(bytes),
                    i64::try_from(bytes.len())
                        .map_err(|_| KernelError::Internal("qualification sink refused".into()))?
                ],
            )
            .map_err(|_| KernelError::Internal("qualification sink refused".into()))?;
        Ok(())
    }
}

fn setup(f: &KnowledgeFixture, workflow: &WorkflowId) -> TestResult<RecoverySetupService> {
    Ok(RecoverySetupService::new(
        f.f.runtime.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.f.authority.mutation_fence(),
        Some(Arc::new(f.runtime.clone())),
        Keypair::from_seed(&[211; 32]),
        workflow.clone(),
    )?)
}

struct Initial {
    path: std::path::PathBuf,
    directory: Option<tempfile::TempDir>,
    workflow: WorkflowId,
    probe: SignedRecoverySetupProbeV1,
    artifact: Option<ArtifactVersionRefV1>,
    setup_process_charges: u32,
}

async fn initial(workflow: &str) -> TestResult<Initial> {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let id = Box::pin(f.f.ready()).await?;
    let artifact = if workflow == "artifact" {
        Some(publish_label(
            &f,
            "retained-research",
            ARTIFACT_BYTES,
            restricted_label(),
        )?)
    } else {
        None
    };
    let service = setup(&f, &id)?;
    let probe = service.probe(&f.f.control, &id).await?;
    drop(service);
    Ok(Initial {
        setup_process_charges: f.f.process.process("root")?.tree_calls,
        path: f.f.path.clone(),
        directory: f.f._directory.take(),
        workflow: id,
        probe,
        artifact,
    })
}

fn open(previous: &mut Initial) -> TestResult<KnowledgeFixture> {
    KnowledgeFixture::from(RecoveryFixture::open(
        previous.path.clone(),
        previous.directory.take(),
        false,
    )?)
}

pub(super) fn prepare_case<'a>(
    workflow: &'a str,
    case: &'a str,
) -> Pin<Box<dyn Future<Output = TestResult<CaseFixture>> + 'a>> {
    Box::pin(async move {
        if !matches!(workflow, "support" | "artifact")
            || !matches!(
                case,
                "authorized" | "lost_ack_restart" | "wrong_authority" | "conflicting_basis"
            )
        {
            return Err("unsupported qualification case".into());
        }
        let previous = Box::pin(initial(workflow)).await?;
        Box::pin(selected_writer(previous, workflow, case)).await
    })
}

async fn selected_writer(
    mut previous: Initial,
    workflow: &str,
    case: &str,
) -> TestResult<CaseFixture> {
    let f = open(&mut previous)?;
    let service = setup(&f, &previous.workflow)?;
    service.qualify(&f.f.control, &previous.probe).await?;
    drop(service);
    let id = if workflow == "support" {
        Box::pin(f.f.ready_named("trial-work", "trial-work")).await?
    } else {
        previous.workflow.clone()
    };
    let body = if workflow == "support" {
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: f.f.record(&id)?.revision,
        }
    } else {
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: id.clone(),
        }
    };
    let command = f.f.command("trial-owned-original", body)?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let handle = previous
        .artifact
        .as_ref()
        .map(|reference| f.runtime.handle(&f.f.control, reference, &recipient))
        .transpose()?;
    let database = rusqlite::Connection::open(f.f.path.join("deliveries.db"))?;
    database.execute("CREATE TABLE deliveries(sequence INTEGER PRIMARY KEY,release TEXT NOT NULL,content TEXT NOT NULL,size INTEGER NOT NULL)", [])?;
    drop(database);
    let deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    // Store UUIDs, issuance time and serving fence are isolated trial
    // identities. Match actual actor rights and policy, not those nonces.
    let authority_contract = serde_json::json!({
        "tenant":deployment.scope.tenant_id,"process":deployment.scope.process_id,
        "actors":deployment.actors,"coverage":deployment.coverage,
        "policy":deployment.policy_digest,"contract":deployment.contract_digest,
        "effect_cardinality":deployment.effect_cardinality,
        "artifact_clearance":f.profile.recipients.as_slice()[0].recipient.clearance,
        "artifact_label":restricted_label(),"artifact_sink":"agent-root",
        "classifier":f.profile.classifier_implementation,"classification":f.profile.classifier_configuration,
    });
    let sink = DurableSink {
        native: f.sink(),
        path: f.f.path.join("deliveries.db"),
    };
    let mut fixture = CaseFixture {
        f,
        command,
        workflow: workflow.into(),
        case: case.into(),
        handle,
        sink,
        authority_contract: authority_contract.clone(),
        native_actions: AtomicUsize::new(0),
        observed_at_ms: now_ms()?,
        setup_process_charges: previous.setup_process_charges,
    };
    match case {
        "lost_ack_restart" => {
            Box::pin(fixture.execute()).await?;
            // Discard the initiating result, close every writer and reopen
            // the same independently durable native/provider stores.
            previous.path = fixture.f.f.path.clone();
            previous.directory = fixture.f.f._directory.take();
            let handle = fixture.handle.clone();
            let command = fixture.command.clone();
            let control = fixture.f.f.control.clone();
            drop(fixture);
            let mut f = open(&mut previous)?;
            // An original release is bound to exact initiating read authority.
            // Preserve it across restart; a newly issued equivalent token is
            // intentionally not an exact acknowledgement-recovery identity.
            f.f.control = control;
            let service = setup(&f, &previous.workflow)?;
            service.qualify(&f.f.control, &previous.probe).await?;
            drop(service);
            let sink = DurableSink {
                native: f.sink(),
                path: f.f.path.join("deliveries.db"),
            };
            fixture = CaseFixture {
                f,
                command,
                workflow: workflow.into(),
                case: case.into(),
                handle,
                sink,
                authority_contract,
                native_actions: AtomicUsize::new(0),
                observed_at_ms: now_ms()?,
                setup_process_charges: previous.setup_process_charges,
            };
        }
        "wrong_authority" => {
            fixture
                .f
                .f
                .kernel
                .revoke_capability(&fixture.f.f.control.id)?;
        }
        "conflicting_basis" if workflow == "support" => {
            Box::pin(fixture.execute()).await?;
            let revision = fixture.f.f.record(&id)?.revision;
            fixture.command.command = RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id,
                expected_revision: SafeInteger::new(revision.get() + 1)?,
            };
            fixture.native_actions.store(0, Ordering::SeqCst);
        }
        "conflicting_basis" => {
            let mut current = fixture.f.profile.clone();
            current.generation = SafeInteger::new(2)?;
            let mut recipients = current.recipients.as_slice().to_vec();
            recipients[0].recipient.clearance = InformationLabel::bottom();
            current.recipients = NonEmptyBoundedList::new(recipients)?;
            fixture
                .f
                .f
                .authority
                .admission_operation_store()
                .configure_knowledge(&current)?;
        }
        _ => {}
    }
    Ok(fixture)
}

impl CaseFixture {
    pub fn execute(&self) -> Execution<'_> {
        self.execute_with(&self.f.f.control, &self.command)
    }
    pub fn execute_with<'a>(
        &'a self,
        capability: &'a CapabilityToken,
        command: &'a RecoveryCommandV1,
    ) -> Execution<'a> {
        self.native_actions.fetch_add(1, Ordering::SeqCst);
        if self.handle.is_none() {
            return self.f.f.runtime.execute_command(capability, command);
        }
        Box::pin(async move {
            let response = self
                .f
                .f
                .runtime
                .execute_command(capability, command)
                .await?;
            let handle = self
                .handle
                .as_ref()
                .ok_or(RecoveryRuntimeError::Unavailable)?;
            let prepared = self
                .f
                .runtime
                .prepare_read(capability, handle)
                .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
            self.f
                .runtime
                .release_into(
                    capability,
                    &RequestId::new("trial-owned-release")
                        .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
                    prepared,
                    &self.sink,
                )
                .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
            Ok(response)
        })
    }
    pub fn facts(&self) -> TestResult<serde_json::Value> {
        let database = rusqlite::Connection::open(self.f.f.path.join("admission.db"))?;
        let count = |db: &rusqlite::Connection, query: &str| -> TestResult<u64> {
            Ok(u64::try_from(
                db.query_row(query, [], |row| row.get::<_, i64>(0))?,
            )?)
        };
        let releases = count(&database, "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-release:*'")?;
        let artifacts = count(&database, "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-version:*'")?;
        let delivery = rusqlite::Connection::open(self.f.f.path.join("deliveries.db"))?;
        let deliveries = count(&delivery, "SELECT count(*) FROM deliveries")?;
        let distinct = count(&delivery, "SELECT count(DISTINCT release) FROM deliveries")?;
        let id = match &self.command.command {
            RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. }
            | RecoveryCommandBodyV1::InspectWorkflow { workflow_id } => workflow_id,
            _ => return Err("unsupported fixture command".into()),
        };
        let bytes: Vec<u8> = database.query_row("SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'workflow:*' AND json_extract(payload,'$.workflow_id')=?1", [id.as_str()], |row| row.get(0))?;
        let record: RecoveryWorkflowRecordV1 = serde_json::from_slice(&bytes)?;
        let unresolved = u32::from(matches!(
            record.effect,
            EffectObservationV1::AdmissionUnresolved { .. }
                | EffectObservationV1::InFlight { .. }
                | EffectObservationV1::AwaitingCallerReport { .. }
                | EffectObservationV1::Unknown { .. }
                | EffectObservationV1::Partial { .. }
        ));
        let approvals = count(&database, "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'workflow:*' AND json_type(payload,'$.approval')='object'")?;
        let expected_approvals = if self.workflow == "support" { 2 } else { 1 };
        let effects = if self.workflow == "support" {
            external_count(&self.f.f.path)?.saturating_sub(1) as u64
        } else {
            releases
        };
        let negative = matches!(self.case.as_str(), "wrong_authority" | "conflicting_basis");
        let preexisting_effects = u64::from(
            self.case == "lost_ack_restart"
                || self.workflow == "support" && self.case == "conflicting_basis",
        );
        let label = if self.workflow == "artifact" {
            let index: Vec<u8> = database.query_row("SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-version:*' LIMIT 1", [], |row| row.get(0))?;
            let publication: String = serde_json::from_slice(&index)?;
            let metadata: Vec<u8> = database.query_row(
                "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
                [publication],
                |row| row.get(0),
            )?;
            let value: serde_json::Value = serde_json::from_slice(&metadata)?;
            value["metadata"]["label"] == serde_json::to_value(restricted_label())?
        } else {
            let observed = self
                .f
                .f
                .authority
                .admission_operation_store()
                .observe_security_participant_flow(
                    &self.f.profile.native_authority,
                    &recovery_flow_key(&self.f.profile.producer_context),
                    &self.f.f.authority.mutation_fence(),
                    now_ms()?,
                )?;
            observed.snapshot().ok_or("flow")?.session_label == restricted_label()
        };
        let useful = self.native_actions.load(Ordering::SeqCst) > 0
            && matches!(record.effect, EffectObservationV1::Complete { .. })
            && effects == 1
            && !negative
            && (self.workflow == "support" || deliveries > 0 && distinct == 1);
        let process_charges_total = self.f.f.process.process("root")?.tree_calls;
        let charges = process_charges_total
            .checked_sub(self.setup_process_charges)
            .ok_or("process charge history regressed")?;
        Ok(serde_json::json!({
            "effects":effects,"charges":charges,
            "setup_process_charges":self.setup_process_charges,"process_charges_total":process_charges_total,
            "setup_effects":1,"provider_effects_total":external_count(&self.f.f.path)?,
            "artifact_releases":releases,"artifact_deliveries":deliveries,"artifacts":artifacts,
            "preexisting_effects":preexisting_effects,
            "useful_completion":useful,"unauthorized_effects":if negative { effects.saturating_sub(preexisting_effects) } else { 0 },
            "duplicate_effects":effects.saturating_sub(1),"source_label_retained":label,
            "unresolved":unresolved,"unresolved_age_ms":if unresolved > 0 { now_ms()?.saturating_sub(self.observed_at_ms) } else { 0 },
            "extra_approvals":approvals.saturating_sub(expected_approvals),"approval_records":approvals,
            "recovery_success":self.case == "lost_ack_restart" && useful,
            "native_actions":self.native_actions.load(Ordering::SeqCst),
            "fence":self.f.f.authority.mutation_fence(),
        }))
    }
}

type Execution<'a> = Pin<
    Box<
        dyn Future<Output = Result<crate::recovery::RecoveryCommandResultV1, RecoveryRuntimeError>>
            + Send
            + 'a,
    >,
>;
