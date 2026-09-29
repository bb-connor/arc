//! Owned process death at report commit and recovery, using the production planner.
use super::response_dry_run::{DryRunFixturePolicy, DryRunStateSource};
use super::*;
use crate::security::event_consumer::build_attested_finding_response_plan_publication;
use chio_kernel::IndexedSecurityEvidenceStore;
use chio_security_types::ResponsePlan;
use std::os::unix::net::UnixDatagram;
use std::process::{Child, Command, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct CutpointReceipts {
    inner: Arc<SqliteReceiptStore>,
    phase: String,
    socket: PathBuf,
}
impl CutpointReceipts {
    fn pause(&self, point: &str) {
        if self.phase == point {
            let socket = UnixDatagram::unbound().unwrap_or_else(|e| panic!("cutpoint socket: {e}"));
            socket
                .send_to(point.as_bytes(), &self.socket)
                .unwrap_or_else(|e| panic!("cutpoint barrier: {e}"));
            loop {
                std::thread::park();
            }
        }
    }
}
impl IndexedSecurityEvidenceStore for CutpointReceipts {
    fn ensure_indexed_security_evidence_ready(&self) -> Result<(), chio_kernel::ReceiptStoreError> {
        self.inner.ensure_indexed_security_evidence_ready()
    }
    fn load_indexed_security_evidence(
        &self,
        id: &OpaqueReceiptRef,
    ) -> Result<Option<chio_core::receipt::body::ChioReceipt>, chio_kernel::ReceiptStoreError> {
        let result = self.inner.load_indexed_security_evidence(id)?;
        if result.is_some() {
            self.pause("during-recovery");
        }
        Ok(result)
    }
    fn append_indexed_security_evidence(
        &self,
        id: &OpaqueReceiptRef,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<chio_core::receipt::body::ChioReceipt, chio_kernel::ReceiptStoreError> {
        self.pause("before-report");
        let result = self.inner.append_indexed_security_evidence(id, receipt)?;
        self.pause("after-report");
        Ok(result)
    }
}

fn from_field<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
    field: &str,
) -> TestResult<T> {
    Ok(serde_json::from_value(value[field].clone())?)
}

#[test]
#[ignore = "owned subprocess entry point"]
fn response_process_child() -> TestResult {
    let root = PathBuf::from(std::env::var("CHIO_RESPONSE_RECOVERY_ROOT")?);
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("case.json"))?)?;
    let paths = RealAdapterPaths::in_directory(&root);
    let plan: ResponsePlan = from_field(&value, "plan")?;
    let finding = AuthoritativeCorrelatedFindingEvidence::from_verified_signed_receipt(
        from_field(&value, "finding_id")?,
        from_field(&value, "finding")?,
    )?;
    let state = Arc::new(SqliteSecurityStateStore::open(&paths.responses)?);
    let row = state
        .load_attested_finding_response_outbox(&AttestedFindingResponseOutboxKey {
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
        })?
        .ok_or("response outbox missing on restart")?;
    // A crashed attempt retains its durable backoff. Advance the trusted test
    // clock to the persisted retry time instead of sleeping or bypassing it.
    let now: u64 = from_field(&value, "clock")?;
    let clock = Arc::new(FixedClock(now.max(row.next_attempt_at_unix_ms)));
    let operator = Keypair::from_seed(&[0x81; 32]);
    let executor = Keypair::from_seed(&[0x82; 32]);
    let submission = Keypair::from_seed(&[0x84; 32]);
    let threshold = Keypair::from_seed(&[0x85; 32]);
    let runtime = build_real_adapter_runtime(
        &paths,
        &operator,
        &executor,
        &submission,
        &threshold,
        &from_field(&value, "threshold")?,
        &finding,
        &plan,
        clock.clone(),
        false,
    );
    let artifacts = AttestedFindingAdmissionArtifacts::new(
        from_field(&value, "artifact_ref")?,
        from_field(&value, "capability")?,
        from_field(&value, "intent")?,
        from_field(&value, "proof")?,
        from_field(&value, "attestation")?,
        from_field(&value, "proposal")?,
        from_field(&value, "tokens")?,
    );
    let receipts = Arc::new(CutpointReceipts {
        inner: Arc::new(SqliteReceiptStore::open(&paths.receipts)?),
        phase: std::env::var("CHIO_RESPONSE_RECOVERY_PHASE")?,
        socket: root.join("cutpoint.sock"),
    });
    let simulator = Arc::new(crate::security::ProductionResponseSimulator::new(
        Arc::new(DryRunStateSource(state.clone())),
        receipts,
        Arc::new(Ed25519Backend::new(executor)),
        Digest32::new([0x91; 32]),
    )?);
    let coordinator = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
        runtime.executor.identity(),
        clock.clone(),
        crate::security::ActiveResponseExecutionProfile::DryRun(simulator),
    ));
    coordinator.bind_kernel(runtime.kernel.clone())?;
    let planner = recovery_planner(
        state,
        &[finding],
        Arc::new(DryRunFixturePolicy {
            artifacts,
            authority: submission.public_key(),
        }),
        coordinator,
        clock,
    );
    let report = planner.resume_incomplete_pass(16)?;
    assert_eq!(report.retryable_failures, 0, "{report:?}");
    assert_eq!(report.terminal_failures, 0, "{report:?}");
    assert_eq!(runtime.effects.executions(), 0);
    Ok(())
}

fn spawn(root: &Path, phase: &str) -> TestResult<OwnedChild> {
    let module = module_path!()
        .split_once("::")
        .ok_or("test module lacks crate prefix")?
        .1;
    let child_test = format!("{module}::response_process_child");
    Ok(OwnedChild(
        Command::new(std::env::current_exe()?)
            .args(["--exact", &child_test, "--ignored", "--nocapture"])
            .env("CHIO_RESPONSE_RECOVERY_ROOT", root)
            .env("CHIO_RESPONSE_RECOVERY_PHASE", phase)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    ))
}

#[test]
fn response_simulation_process_death_preserves_exact_report_and_terminal_outbox() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    for phase in ["before-report", "after-report"] {
        let fixture =
            real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::DryRun, true);
        let root = fixture._directory.path();
        let store = SqliteSecurityStateStore::open(&fixture.paths.responses)?;
        publish_recovery_batch(&store, std::slice::from_ref(&fixture.finding));
        store.publish_attested_finding_response_plan(
            &build_attested_finding_response_plan_publication(&fixture.plan)?,
        )?;
        let AttestedFindingAdmissionArtifactPayload::Kernel(payload) = &fixture.artifacts.payload
        else {
            return Err("real authority artifacts required".into());
        };
        let value = serde_json::json!({
            "plan": fixture.plan.response_plan(), "finding_id": fixture.finding.evidence_id(),
            "finding": fixture.finding.body(), "clock": fixture.clock.0,
            "threshold": fixture.threshold_requirement,
            "artifact_ref": payload.artifact_ref, "capability": payload.operator_capability,
            "intent": payload.governed_intent, "proof": payload.submission_proof,
            "attestation": payload.authority_attestation, "proposal": payload.threshold_proposal,
            "tokens": payload.approval_tokens,
        });
        std::fs::write(root.join("case.json"), serde_json::to_vec(&value)?)?;
        let barrier = UnixDatagram::bind(root.join("cutpoint.sock"))?;
        barrier.set_read_timeout(Some(std::time::Duration::from_secs(20)))?;
        let phases = if phase == "after-report" {
            vec![phase, "during-recovery"]
        } else {
            vec![phase]
        };
        let mut committed_id = None;
        for point in phases {
            let mut child = spawn(root, point)?;
            let mut message = [0; 64];
            let count = barrier.recv(&mut message)?;
            assert_eq!(&message[..count], point.as_bytes());
            child.0.kill()?;
            assert_eq!(child.0.wait()?.signal(), Some(9));
            let service = super::response_dry_run::dry_run_service(&fixture, None);
            let report = service.load(fixture.plan.response_plan())?;
            if point == "before-report" {
                assert!(report.is_none());
            } else {
                let id = report.ok_or("durably committed report missing")?.1.id;
                if let Some(expected) = &committed_id {
                    assert_eq!(&id, expected);
                }
                committed_id = Some(id);
            }
        }
        let mut recovery = spawn(root, "complete")?;
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = recovery.0.try_wait()? {
                break status;
            }
            if started.elapsed() > std::time::Duration::from_secs(20) {
                return Err("recovery process timed out".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.success(), "recovery failed: {status}");
        let row = store
            .load_attested_finding_response_outbox(&AttestedFindingResponseOutboxKey {
                tenant_id: fixture.plan.response_plan().tenant_id.clone(),
                action_id: fixture.plan.response_plan().action_id.clone(),
            })?
            .ok_or("recovered outbox missing")?;
        assert_eq!(
            row.completion_state,
            AttestedFindingResponseCompletionState::Simulated
        );
        assert!(row.execution_dispatch_id.is_none());
        assert!(row.prepared_dispatch_binding.is_none());
        assert_eq!(
            store
                .attested_finding_response_outbox_health()?
                .terminal_simulated,
            1
        );
        let report = super::response_dry_run::dry_run_service(&fixture, None)
            .load(fixture.plan.response_plan())?
            .ok_or("recovered report missing")?;
        if let Some(expected) = committed_id {
            assert_eq!(report.1.id, expected);
        }
        super::response_dry_run::assert_dry_run_untouched(&fixture);
    }
    Ok(())
}
