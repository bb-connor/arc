use super::*;
use chio_core::PublicKey;
use chio_security_types::ports::{LineageFenceMaintenanceRequest, ScheduledWork};
use chio_security_types::ResponsePlan;
pub(super) struct DryRunStateSource(pub(super) Arc<SqliteSecurityStateStore>);
impl chio_security_types::response_simulation::ResponseSimulationSnapshotSource
    for DryRunStateSource
{
    fn capture(
        &self,
        plan: &ResponsePlan,
    ) -> PortResult<chio_security_types::response_simulation::ResponseSimulationSnapshot> {
        self.0.capture_response_simulation(plan)
    }
}

struct DryRunReceiptFailure {
    inner: Arc<SqliteReceiptStore>,
    after_commit: bool,
}
impl chio_kernel::IndexedSecurityEvidenceStore for DryRunReceiptFailure {
    fn ensure_indexed_security_evidence_ready(&self) -> Result<(), chio_kernel::ReceiptStoreError> {
        Ok(())
    }
    fn load_indexed_security_evidence(
        &self,
        id: &OpaqueReceiptRef,
    ) -> Result<Option<chio_core::receipt::body::ChioReceipt>, chio_kernel::ReceiptStoreError> {
        self.inner.load_indexed_security_evidence(id)
    }
    fn append_indexed_security_evidence(
        &self,
        id: &OpaqueReceiptRef,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<chio_core::receipt::body::ChioReceipt, chio_kernel::ReceiptStoreError> {
        if self.after_commit {
            self.inner.append_indexed_security_evidence(id, receipt)?;
        }
        Err(chio_kernel::ReceiptStoreError::Unsupported(
            "injected simulation append failure".to_owned(),
        ))
    }
}

pub(super) fn dry_run_service(
    fixture: &RealAdapterFixture,
    failure: Option<bool>,
) -> Arc<crate::security::ProductionResponseSimulator> {
    let state = Arc::new(
        SqliteSecurityStateStore::open(&fixture.paths.responses)
            .unwrap_or_else(|e| panic!("simulation state: {e}")),
    );
    let store = Arc::new(
        SqliteReceiptStore::open(&fixture.paths.receipts)
            .unwrap_or_else(|e| panic!("simulation receipts: {e}")),
    );
    let receipts: Arc<dyn chio_kernel::IndexedSecurityEvidenceStore> = match failure {
        Some(after_commit) => Arc::new(DryRunReceiptFailure {
            inner: store,
            after_commit,
        }),
        None => store,
    };
    Arc::new(
        crate::security::ProductionResponseSimulator::new(
            Arc::new(DryRunStateSource(state)),
            receipts,
            Arc::new(Ed25519Backend::new(fixture.executor_signer.clone())),
            Digest32::new([0x91; 32]),
        )
        .unwrap_or_else(|e| panic!("simulation service: {e}")),
    )
}

pub(super) fn assert_dry_run_untouched(fixture: &RealAdapterFixture) {
    assert_eq!(fixture.runtime.effects.executions(), 0);
    assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), [0; 5]);
    assert_eq!(
        real_adapter_budget_and_replay_snapshot(&fixture.paths),
        [0; 9]
    );
    for table in [
        "security_response_dispatches",
        "security_session_throttle_effects",
    ] {
        assert_eq!(
            real_adapter_table_count(&fixture.paths.responses, table),
            0,
            "{table}"
        );
    }
}

#[test]
fn response_dry_run_real_automatic_and_governed_authorization_persist_and_restart_without_effects()
{
    for governed in [false, true] {
        let fixture = real_adapter_fixture_for_mode(
            chio_security_types::ResponseExecutionMode::DryRun,
            governed,
        );
        let request = fixture
            .artifacts
            .clone()
            .into_simulation_request(fixture.plan.response_plan().clone())
            .unwrap_or_else(|e| panic!("simulation request: {e}"));
        let service = dry_run_service(&fixture, None);
        let (report, receipt) = service
            .run(fixture.runtime.kernel.as_ref(), &request)
            .unwrap_or_else(|e| panic!("run simulation: {e}"));
        assert_eq!(report.approval_set_hash.is_some(), governed);
        assert_eq!(report.evaluation.apply.len(), 1);
        assert_eq!(report.evaluation.rollback.len(), 1);
        assert_dry_run_untouched(&fixture);
        drop(service);
        let restarted = dry_run_service(&fixture, None);
        let (retained, signed) = restarted
            .load(fixture.plan.response_plan())
            .unwrap_or_else(|e| panic!("recover report: {e}"))
            .unwrap_or_else(|| panic!("report missing"));
        assert_eq!(retained, report);
        assert_eq!(signed.id, receipt.id);
        let replay = restarted
            .run(fixture.runtime.kernel.as_ref(), &request)
            .unwrap_or_else(|e| panic!("replay simulation: {e}"));
        assert_eq!(replay.1.id, receipt.id);
        assert_dry_run_untouched(&fixture);
    }
}

#[test]
fn response_dry_run_receipt_failures_do_not_create_authority_or_effects() {
    for after_commit in [false, true] {
        let fixture =
            real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::DryRun, true);
        let request = fixture
            .artifacts
            .clone()
            .into_simulation_request(fixture.plan.response_plan().clone())
            .unwrap_or_else(|e| panic!("simulation request: {e}"));
        let service = dry_run_service(&fixture, Some(after_commit));
        let result = service.run(fixture.runtime.kernel.as_ref(), &request);
        if after_commit {
            assert!(result.is_ok(), "committed report readback: {result:?}");
        } else {
            assert_eq!(
                result
                    .err()
                    .unwrap_or_else(|| panic!("missing receipt accepted"))
                    .kind(),
                PortErrorKind::Unavailable
            );
        }
        assert_dry_run_untouched(&fixture);
    }
}

fn resign_dry_run_artifacts(
    fixture: &RealAdapterFixture,
    artifacts: &mut AttestedFindingAdmissionArtifacts,
) {
    let AttestedFindingAdmissionArtifactPayload::Kernel(payload) = &mut artifacts.payload else {
        panic!("native payload required");
    };
    let mut body = payload.authority_attestation.body.clone();
    body.artifact_payload_digest = chio_kernel::active_response_admission_artifact_payload_digest(
        &fixture.plan.response_plan().authorization_body(),
        &payload.operator_capability,
        &payload.governed_intent,
        &payload.submission_proof,
        &payload.threshold_proposal,
        &payload.approval_tokens,
    )
    .unwrap_or_else(|e| panic!("artifact digest: {e}"));
    payload.authority_attestation = ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        body,
        &Ed25519Backend::new(fixture.submission_authority.clone()),
    )
    .unwrap_or_else(|e| panic!("authority attestation: {e}"));
}

#[test]
fn response_dry_run_missing_and_expired_real_approvals_are_denied_without_reservation() {
    for expired in [false, true] {
        let fixture =
            real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::DryRun, true);
        let mut artifacts = fixture.artifacts.clone();
        let AttestedFindingAdmissionArtifactPayload::Kernel(payload) = &mut artifacts.payload
        else {
            panic!("native payload required");
        };
        if expired {
            let approver = Keypair::from_seed(&[0x86; 32]);
            let original = &payload.approval_tokens[0];
            let now = real_adapter_now_unix_seconds();
            payload.approval_tokens = vec![GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: original.id.clone(),
                    approver: original.approver.clone(),
                    subject: original.subject.clone(),
                    governed_intent_hash: original.governed_intent_hash.clone(),
                    threshold_proposal_hash: original.threshold_proposal_hash.clone(),
                    request_id: original.request_id.clone(),
                    issued_at: now - 2,
                    expires_at: now - 1,
                    decision: GovernedApprovalDecision::Approved,
                },
                &approver,
            )
            .unwrap_or_else(|e| panic!("expired token: {e}"))];
        } else {
            payload.approval_tokens.clear();
        }
        resign_dry_run_artifacts(&fixture, &mut artifacts);
        let request = artifacts
            .into_simulation_request(fixture.plan.response_plan().clone())
            .unwrap_or_else(|e| panic!("simulation request: {e}"));
        let error = fixture
            .runtime
            .kernel
            .verify_active_response_simulation(&request)
            .err()
            .unwrap_or_else(|| panic!("invalid approval accepted"));
        let chio_kernel::KernelError::GovernedTransactionDenied(reason) = error else {
            panic!("wrong approval refusal: {error:?}");
        };
        assert!(
            if expired {
                reason.contains("expired") || reason.contains("validity")
            } else {
                reason.contains("at least one governed approval token")
            },
            "{reason}"
        );
        assert_dry_run_untouched(&fixture);
    }
}

#[test]
fn response_dry_run_profile_cannot_prepare_live_dispatch() {
    let fixture = real_adapter_fixture();
    let coordinator = KernelAttestedFindingResponseCoordinator::new_unbound(
        fixture.runtime.executor.identity(),
        fixture.clock.clone(),
        crate::security::ActiveResponseExecutionProfile::DryRun(dry_run_service(&fixture, None)),
    );
    coordinator
        .bind_kernel(Arc::clone(&fixture.runtime.kernel))
        .unwrap_or_else(|e| panic!("bind kernel: {e}"));
    let error = coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone())
        .err()
        .unwrap_or_else(|| panic!("live admission in dry-run profile"));
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_dry_run_untouched(&fixture);
}

pub(super) struct DryRunFixturePolicy {
    pub(super) artifacts: AttestedFindingAdmissionArtifacts,
    pub(super) authority: PublicKey,
}
impl AttestedFindingResponsePolicyPlanner for DryRunFixturePolicy {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }
    fn trusted_artifact_authority(&self) -> PortResult<PublicKey> {
        Ok(self.authority.clone())
    }
    fn load_admission_artifacts(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: &AdmissionArtifactRef,
    ) -> PortResult<AttestedFindingAdmissionArtifacts> {
        Ok(self.artifacts.clone())
    }
}

#[test]
fn response_dry_run_scheduler_outbox_completes_without_live_work_and_recovers_report_cutpoint() {
    for committed_report in [false, true] {
        let fixture =
            real_adapter_fixture_for_mode(chio_security_types::ResponseExecutionMode::DryRun, true);
        let store = Arc::new(
            SqliteSecurityStateStore::open(&fixture.paths.responses)
                .unwrap_or_else(|e| panic!("outbox store: {e}")),
        );
        publish_recovery_batch(store.as_ref(), std::slice::from_ref(&fixture.finding));
        let publication =
            crate::security::event_consumer::build_attested_finding_response_plan_publication(
                &fixture.plan,
            )
            .unwrap_or_else(|e| panic!("plan publication: {e}"));
        store
            .publish_attested_finding_response_plan(&publication)
            .unwrap_or_else(|e| panic!("publish response plan: {e}"));
        let key = AttestedFindingResponseOutboxKey {
            tenant_id: fixture.plan.response_plan().tenant_id.clone(),
            action_id: fixture.plan.response_plan().action_id.clone(),
        };
        let service = dry_run_service(&fixture, None);
        if committed_report {
            let row = store
                .load_attested_finding_response_outbox(&key)
                .unwrap_or_else(|e| panic!("load outbox: {e}"))
                .unwrap_or_else(|| panic!("outbox missing"));
            store
                .transition_attested_finding_response_outbox(
                    &row,
                    AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                        artifact_digest: fixture
                            .artifacts
                            .canonical_digest(fixture.plan.response_plan())
                            .unwrap_or_else(|e| panic!("artifact digest: {e}")),
                    },
                )
                .unwrap_or_else(|e| panic!("bind artifacts: {e}"));
            let request = fixture
                .artifacts
                .clone()
                .into_simulation_request(fixture.plan.response_plan().clone())
                .unwrap_or_else(|e| panic!("simulation request: {e}"));
            service
                .run(fixture.runtime.kernel.as_ref(), &request)
                .unwrap_or_else(|e| panic!("persist report before outbox completion: {e}"));
        }
        // A new service instance models a process restart after the report
        // commits and before the planning outbox records completion.
        drop(service);
        let coordinator = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
            fixture.runtime.executor.identity(),
            fixture.clock.clone(),
            crate::security::ActiveResponseExecutionProfile::DryRun(dry_run_service(
                &fixture, None,
            )),
        ));
        coordinator
            .bind_kernel(Arc::clone(&fixture.runtime.kernel))
            .unwrap_or_else(|e| panic!("bind simulation coordinator: {e}"));
        let planner = recovery_planner(
            store.clone(),
            std::slice::from_ref(&fixture.finding),
            Arc::new(DryRunFixturePolicy {
                artifacts: fixture.artifacts.clone(),
                authority: fixture.submission_authority.public_key(),
            }),
            coordinator,
            fixture.clock.clone(),
        );
        planner
            .resume_incomplete_pass(16)
            .unwrap_or_else(|e| panic!("resume simulation outbox: {e}"));
        let row = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|e| panic!("load completed simulation: {e}"))
            .unwrap_or_else(|| panic!("outbox missing"));
        assert_eq!(
            row.completion_state,
            AttestedFindingResponseCompletionState::Simulated
        );
        assert!(row.is_complete());
        assert!(row.execution_dispatch_id.is_none());
        assert!(row.prepared_dispatch_binding.is_none());
        assert!(row.completion_outcome.is_none());
        assert!(row.completion_evidence_id.is_some());
        assert_eq!(
            store
                .attested_finding_response_outbox_health()
                .unwrap_or_else(|e| panic!("outbox health: {e}"))
                .terminal_simulated,
            1
        );
        assert!(store
            .scan_incomplete_attested_finding_responses(u64::MAX / 2, 16)
            .unwrap_or_else(|e| panic!("pending simulations: {e}"))
            .is_empty());
        assert_dry_run_untouched(&fixture);
    }
}

#[test]
fn response_dry_run_host_effect_gate_refuses_execution_and_fence_maintenance() {
    let effects = crate::security::response_simulation::SimulationOnlyEffects;
    assert_eq!(effects.ensure_effects_ready(), Ok(()));
    // No live backend is installed in this host profile. Its execute and
    // readback methods reject even correctly formed live requests.
    let fixture = real_adapter_fixture();
    let plan = fixture.plan.response_plan();
    let effect = &plan.effects.as_slice()[0];
    let request = EffectRequest {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: effect.effect_id.clone(),
        effect_kind: effect.kind,
        target: effect.target.clone(),
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record("dry-run-must-not-execute"),
        expected_version_hash: effect.observed_base_version_hash,
        scheduler_lease_owner_id: LeaseOwnerId::new("live-worker")
            .unwrap_or_else(|e| panic!("owner: {e}")),
        scheduler_fencing_token: 1,
        contribution_hash: effect.contribution_hash,
        canonical_contribution: effect.canonical_contribution.clone(),
    };
    let error = effects
        .execute(&request)
        .err()
        .unwrap_or_else(|| panic!("dry-run host executed an effect"));
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    let query = EffectResultQuery {
        tenant_id: request.tenant_id.clone(),
        action_id: request.action_id.clone(),
        plan_hash: request.plan_hash,
        effect_id: request.effect_id.clone(),
        effect_kind: request.effect_kind,
        target: request.target.clone(),
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key.clone(),
        expected_version_hash: request.expected_version_hash,
        contribution_hash: request.contribution_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
    };
    assert_eq!(
        effects
            .load_result(&query)
            .err()
            .unwrap_or_else(|| panic!("dry-run host read live effect results"))
            .kind(),
        PortErrorKind::InvalidData
    );
    let maintenance = LineageFenceMaintenanceRequest {
        plan: plan.clone(),
        effect_ids: vec![effect.effect_id.clone()],
        scheduler_work: ScheduledWork {
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
            lease_owner_id: request.scheduler_lease_owner_id,
            lease_expires_at_unix_ms: plan.expires_at_unix_ms,
            fencing_token: request.scheduler_fencing_token,
        },
        observed_at_unix_ms: plan.created_at_unix_ms,
        renewed_expires_at_unix_ms: plan.expires_at_unix_ms,
    };
    assert_eq!(
        effects
            .maintain_lineage_fences(&maintenance)
            .err()
            .unwrap_or_else(|| panic!("dry-run host renewed a live fence"))
            .kind(),
        PortErrorKind::Unavailable
    );
    assert_dry_run_untouched(&fixture);
}
