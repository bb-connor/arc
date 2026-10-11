use super::*;
use crate::security::event_consumer::AttestedFindingResponsePolicySelection;
use crate::security::{ProductionActiveDefenseHostError, ResponseWorkerTickError};
use chio_core::canonical_json_bytes;
use chio_core_types::SignedSecurityEvent;
use chio_kernel::AuthoritativeCorrelatedFindingEvidence;
use chio_security_types::ports::{
    AdmissionArtifactRef, AttestedFindingBatchBinding, AttestedFindingResponseCompletionOutcome,
    LineageId, ProducerTrustClass,
};
use chio_security_types::{
    ResponseExecutionBinding, ResponseExecutionMode, SecurityEventBody, SecurityEventBodyInput,
    SecurityEventKind, SecuritySeverity, SecuritySubject,
};

const OPEN_EVENT_ID: &str = "host-open-admission-event";
const CLOSED_EVENT_ID: &str = "host-closed-admission-event";
const RESPONSE_TTL_MS: u64 = 60_000;
const GOVERNED_INTENT_HASH: [u8; 32] = [6_u8; 32];
const POLICY_DECISION_HASH: [u8; 32] = [7_u8; 32];

struct ExecutingResponsePolicy {
    store: Arc<SqliteSecurityStateStore>,
    clock: Arc<FixedClock>,
    executor_subject: RecordId,
}

impl AttestedFindingResponsePolicyPlanner for ExecutingResponsePolicy {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
        Ok(Keypair::from_seed(&[95_u8; 32]).public_key())
    }

    fn select_response_policy(
        &self,
        finding: &AuthoritativeCorrelatedFindingEvidence,
        _: &AttestedFindingBatchBinding,
    ) -> PortResult<AttestedFindingResponsePolicySelection> {
        let tenant_id = finding.body().header.tenant_id.clone();
        let session_id = SessionId::new(format!(
            "host-response-{}",
            finding.body().finding_id.as_str()
        ))?;
        let target = session_containment_target(&tenant_id, &session_id)?;
        let observed_base_version_hash =
            session_overlay_version_hash(self.store.as_ref(), &target)?;
        let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())
            .map_err(|_| PortError::invalid_data())?;
        let contribution_hash =
            Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
        let now_unix_ms = self.clock.read_now_unix_ms()?;
        Ok(AttestedFindingResponsePolicySelection {
            execution: ResponseExecutionBinding::new(ResponseExecutionMode::Live),
            affected_ids: vec![RecordId::new(session_id.as_str())?],
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::SuspendSession,
                target: ResponseTarget::Session { session_id },
                canonical_contribution,
                contribution_hash,
                observed_base_version_hash,
            }],
            ttl_ms: RESPONSE_TTL_MS,
            created_at_unix_ms: now_unix_ms,
            operator_capability: OperatorCapabilityBinding {
                capability_id: RecordId::new("host-response-capability")?,
                capability_digest: Digest32::new([4_u8; 32]),
                expires_at_unix_ms: now_unix_ms.saturating_add(10 * RESPONSE_TTL_MS),
                executor_subject: self.executor_subject.clone(),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: RecordId::new("host-response-submitter")?,
            reason_hash: Digest32::new([5_u8; 32]),
            admission_artifact_ref: AdmissionArtifactRef::new("host-response-artifacts")?,
        })
    }

    fn load_admission_artifacts(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: &AdmissionArtifactRef,
    ) -> PortResult<AttestedFindingAdmissionArtifacts> {
        Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new(
            [74_u8; 32],
        )))
    }
}

/// Admits every plan and executes it through the durable production executor,
/// so a completed response applies a real overlay contribution.
type HostResponseExecutor = DurableActiveResponseExecutor<
    SqliteSecurityStateStore,
    ActiveResponseEffectPort,
    NativeSecurityReceiptSink,
    SqliteSiemOutbox,
>;

struct ExecutingResponseCoordinator {
    identity: ActiveResponseExecutorAuthorityIdentity,
    executor: HostResponseExecutor,
    executions: AtomicU64,
    last_execution_error: std::sync::Mutex<Option<String>>,
}

impl ExecutingResponseCoordinator {
    fn last_execution_error(&self) -> Option<String> {
        self.last_execution_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl AttestedFindingResponseCoordinator for ExecutingResponseCoordinator {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn recover_committed(
        &self,
        _: &chio_security_types::ResponsePlan,
        _: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
        Ok(None)
    }

    fn resume_dispatch_committed(
        &self,
        _: &chio_security_types::ResponsePlan,
        _: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingDispatchCommittedResume> {
        Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted)
    }

    fn reconstruct_pre_dispatch(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: AttestedFindingAdmissionArtifacts,
        _: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
        Err(PortError::integrity_failure())
    }

    fn terminate_never_committed(
        &self,
        _: &chio_security_types::ResponsePlan,
        _: &PreparedActiveResponseDispatchBinding,
        _: Option<&AttestedFindingAdmissionArtifacts>,
    ) -> PortResult<()> {
        Err(PortError::integrity_failure())
    }

    fn prepare_admission(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        _: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<PreparedAttestedFindingResponse> {
        let response_plan = plan.response_plan();
        let dispatch_id = chio_kernel::derive_active_response_dispatch_id(
            response_plan,
            &self.identity,
            &hex::encode(
                response_plan
                    .operator_capability
                    .capability_digest
                    .as_bytes(),
            ),
            &hex::encode(GOVERNED_INTENT_HASH),
            &hex::encode(POLICY_DECISION_HASH),
            response_plan.created_at_unix_ms,
            &chio_kernel::ActiveResponseExecutionApproval::Automatic,
        )
        .map_err(|_| PortError::integrity_failure())?;
        let artifact_fingerprint = Digest32::new([0x73; 32]);
        let dispatch_id = chio_kernel::bind_active_response_dispatch_id_to_artifact(
            &dispatch_id,
            &artifact_fingerprint,
        )
        .map_err(|_| PortError::integrity_failure())?;
        // Match execute_automatic_for_test's canonical descriptor before the
        // response outbox records preparation. This uses the real SQLite claim.
        let binding = PreparedActiveResponseDispatchBinding {
            schema_version:
                chio_security_types::ports::PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
            tenant_id: response_plan.tenant_id.clone(),
            action_id: response_plan.action_id.clone(),
            plan_hash: response_plan.plan_hash,
            dispatch_id,
            executor_authority_id: RecordId::new(self.identity.authority_id())?,
            executor_authority_generation: self.identity.generation(),
            authorized_at_unix_ms: response_plan.created_at_unix_ms,
            authorization_capability_hash: response_plan.operator_capability.capability_digest,
            governed_intent_hash: Digest32::new(GOVERNED_INTENT_HASH),
            policy_decision_hash: Digest32::new(POLICY_DECISION_HASH),
            admission_artifact_fingerprint: Some(artifact_fingerprint),
            approval: chio_security_types::ports::ResponseDispatchApproval::Automatic,
        };
        let claimed = chio_kernel::ActiveResponseExecutorAuthority::claim_automatic_preparation(
            &self.executor,
            response_plan,
            &binding,
        )
        .map_err(|_| PortError::integrity_failure())?;
        if claimed != binding {
            return Err(PortError::integrity_failure());
        }
        Ok(PreparedAttestedFindingResponse::synthetic_bound(claimed))
    }

    fn cancel_prepared(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: &PreparedAttestedFindingResponse,
    ) -> PortResult<()> {
        Ok(())
    }

    fn execute_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: PreparedAttestedFindingResponse,
    ) -> PortResult<AttestedFindingResponseCompletionProof> {
        let response_plan = plan.response_plan().clone();
        let authorized_at_unix_ms = response_plan.created_at_unix_ms;
        self.executor
            .execute_automatic_for_test(
                response_plan,
                Digest32::new(GOVERNED_INTENT_HASH),
                Digest32::new(POLICY_DECISION_HASH),
                authorized_at_unix_ms,
            )
            .map_err(|error| {
                *self
                    .last_execution_error
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.to_string());
                PortError::integrity_failure()
            })?;
        self.executions.fetch_add(1, Ordering::AcqRel);
        Ok(AttestedFindingResponseCompletionProof::synthetic(
            prepared.dispatch_id().clone(),
            AttestedFindingResponseCompletionOutcome::Activated,
            OpaqueReceiptRef::new("host-response-completion")?,
            Digest32::new([75_u8; 32]),
        ))
    }
}

fn executing_fixture() -> (HostFixture, Arc<ExecutingResponseCoordinator>) {
    let mut fixture = HostFixture::new();
    let executor_identity =
        ActiveResponseExecutorAuthorityIdentity::new(fixture.config.signer.public_key(), 1)
            .unwrap_or_else(|error| panic!("executor identity: {error}"));
    let executor_subject = RecordId::new(executor_identity.subject().to_hex())
        .unwrap_or_else(|error| panic!("executor subject: {error}"));
    let effects = Arc::new(
        ActiveResponseEffectPort::production(
            Arc::clone(&fixture.security_store),
            Arc::clone(&fixture.config.alert_outbox),
            Arc::clone(&fixture.config.blast_radius),
        )
        .unwrap_or_else(|error| panic!("response effects: {error}")),
    );
    let receipts = Arc::new(NativeSecurityReceiptSink::new(
        Arc::clone(&fixture.config.indexed_evidence_store),
        Arc::clone(&fixture.config.signer),
    ));
    let executor = DurableActiveResponseExecutor::new(
        executor_identity.clone(),
        LeaseOwnerId::new("host-response-executor")
            .unwrap_or_else(|error| panic!("executor lease owner: {error}")),
        Arc::clone(&fixture.security_store),
        effects,
        receipts,
        Arc::clone(&fixture.config.alert_outbox),
        fixture.clock.clone(),
        500,
    )
    .unwrap_or_else(|error| panic!("durable response executor: {error}"));
    let coordinator = Arc::new(ExecutingResponseCoordinator {
        identity: executor_identity,
        executor,
        executions: AtomicU64::new(0),
        last_execution_error: std::sync::Mutex::new(None),
    });
    fixture.config.response_coordinator = coordinator.clone();
    fixture.config.response_policy_planner = Arc::new(ExecutingResponsePolicy {
        store: Arc::clone(&fixture.security_store),
        clock: Arc::clone(&fixture.clock),
        executor_subject,
    });
    fixture.config.active_defense.policy_hashes.insert(
        RecordId::new("host-lifecycle-policy")
            .unwrap_or_else(|error| panic!("policy version: {error}")),
        Digest32::new([8_u8; 32]),
    );
    (fixture, coordinator)
}

fn signed_host_event(
    event_id: &str,
    session_id: &str,
    event_time_unix_ms: u64,
) -> UnverifiedSecurityEvent {
    let record = |value: &str| {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id {value}: {error}"))
    };
    let receipt = |value: &str| {
        OpaqueReceiptRef::new(value).unwrap_or_else(|error| panic!("receipt id {value}: {error}"))
    };
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
        event_time_unix_ms,
        ingest_time_unix_ms: event_time_unix_ms,
        tenant_id: TenantId::new("tenant-host-lifecycle")
            .unwrap_or_else(|error| panic!("tenant: {error}")),
        subject: SecuritySubject {
            subject_id: record("host-lifecycle-subject"),
            agent_id: record("host-lifecycle-agent"),
            session_id: SessionId::new(session_id)
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record("host-lifecycle-capability"),
            lineage_seed: LineageId::new("host-lifecycle-lineage")
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: receipt("host-lifecycle-source-receipt"),
        event_kind: SecurityEventKind::CredentialAccess,
        severity: SecuritySeverity::High,
        evidence_references: vec![receipt("host-lifecycle-evidence")],
        producer_id: ProducerId::new("host-lifecycle-producer")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        producer_key_id: record("host-lifecycle-producer-key"),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record("host-lifecycle-policy"),
    })
    .unwrap_or_else(|error| panic!("event body: {error}"));
    let canonical_body =
        canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical body: {error}"));
    let signed = SignedSecurityEvent::sign_with_backend(
        body.clone(),
        &Ed25519Backend::new(Keypair::from_seed(&[91_u8; 32])),
    )
    .unwrap_or_else(|error| panic!("sign event: {error}"));
    let source_evidence = canonical_json_bytes(&signed)
        .unwrap_or_else(|error| panic!("canonical signed event: {error}"));
    UnverifiedSecurityEvent {
        tenant_id: body.tenant_id,
        event_id: body.event_id,
        producer_id: body.producer_id,
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical_body.clone())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: Digest32::new(*chio_core::sha256(&canonical_body).as_bytes()),
        source_evidence: CanonicalBody::new(source_evidence)
            .unwrap_or_else(|error| panic!("source evidence: {error}")),
    }
}

fn pending_event_ids(fixture: &HostFixture) -> Vec<String> {
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open ingress inspection connection: {error}"));
    let mut statement = connection
        .prepare(
            "SELECT event_id FROM security_correlation_ingress WHERE acknowledged = 0 ORDER BY sequence",
        )
        .unwrap_or_else(|error| panic!("prepare pending ingress query: {error}"));
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap_or_else(|error| panic!("query pending ingress: {error}"));
    rows.map(|row| row.unwrap_or_else(|error| panic!("pending ingress row: {error}")))
        .collect()
}

fn response_rows(fixture: &HostFixture) -> Vec<(String, String, String, Option<String>)> {
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open outbox inspection connection: {error}"));
    let mut statement = connection
        .prepare(
            "SELECT planning_state, admission_state, completion_state, last_error_code FROM security_attested_finding_response_outbox ORDER BY batch_id, ordinal",
        )
        .unwrap_or_else(|error| panic!("prepare outbox query: {error}"));
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("query outbox: {error}"));
    rows.map(|row| row.unwrap_or_else(|error| panic!("outbox row: {error}")))
        .collect()
}

fn overlay_contributions(fixture: &HostFixture) -> u64 {
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open overlay inspection connection: {error}"));
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM security_effect_contributions",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("count overlay contributions: {error}"));
    u64::try_from(count).unwrap_or_else(|error| panic!("overlay contribution count: {error}"))
}

async fn wait_for_ticks(host: &ProductionActiveDefenseHost, ticks: u64) {
    let target = host.worker_health().ticks_attempted.saturating_add(ticks);
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while host.worker_health().ticks_attempted < target {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("worker did not keep ticking"));
}

#[tokio::test]
async fn closed_admission_ticks_start_no_new_response_work_but_still_expire_overlays() {
    let (fixture, coordinator) = executing_fixture();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    host.consume(&signed_host_event(
        OPEN_EVENT_ID,
        "host-open-admission-session",
        50_000,
    ))
    .unwrap_or_else(|error| panic!("accept open-admission event: {error}"));
    fixture.clock.set(51_500);
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while overlay_contributions(&fixture) != 1 || !pending_event_ids(&fixture).is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "published admission did not execute the first response: pending={:?} responses={:?} execution_error={:?}",
            pending_event_ids(&fixture),
            response_rows(&fixture),
            coordinator.last_execution_error()
        )
    });
    assert_eq!(coordinator.executions.load(Ordering::Acquire), 1);
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while host.ensure_ready().is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("host did not return to readiness after the first response"));

    host.consume(&signed_host_event(
        CLOSED_EVENT_ID,
        "host-closed-admission-session",
        51_500,
    ))
    .unwrap_or_else(|error| panic!("accept event before admission closes: {error}"));
    let shutdown = host.shutdown().await;
    assert!(
        matches!(
            shutdown,
            Err(ProductionActiveDefenseHostError::ActiveOverlayContributions { .. })
        ),
        "the first response overlay must keep the worker live after admission closes: {shutdown:?}"
    );
    assert_eq!(
        pending_event_ids(&fixture),
        vec![CLOSED_EVENT_ID.to_string()]
    );

    fixture.clock.set(53_000);
    wait_for_ticks(&host, 20).await;
    let contributions_after_close = overlay_contributions(&fixture);
    let executions_after_close = coordinator.executions.load(Ordering::Acquire);
    let pending_after_close = pending_event_ids(&fixture);

    fixture.clock.set(200_000);
    let expired_after_close = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while fixture.has_active_overlay_contributions() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown after overlays expired: {error}"));

    assert_eq!(
        executions_after_close, 1,
        "a pending event was planned and executed after admission closed: contributions={contributions_after_close} pending={pending_after_close:?}"
    );
    assert_eq!(contributions_after_close, 1);
    assert_eq!(pending_after_close, vec![CLOSED_EVENT_ID.to_string()]);
    assert!(
        expired_after_close,
        "expiry and rollback stopped after admission closed"
    );
}

#[tokio::test]
async fn resume_is_refused_once_runtime_admission_is_closed() {
    let (fixture, coordinator) = executing_fixture();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    host.consume(&signed_host_event(
        CLOSED_EVENT_ID,
        "host-closed-admission-session",
        50_000,
    ))
    .unwrap_or_else(|error| panic!("accept event before admission closes: {error}"));
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));
    fixture.clock.set(51_500);

    let resumed = host.resume_incomplete_active_responses();

    assert!(
        matches!(
            resumed,
            Err(ProductionActiveDefenseHostError::Worker(
                ResponseWorkerTickError::RuntimeAdmissionClosed
            ))
        ),
        "resume ran after runtime admission closed: {resumed:?} executions={} contributions={}",
        coordinator.executions.load(Ordering::Acquire),
        overlay_contributions(&fixture)
    );
    assert_eq!(coordinator.executions.load(Ordering::Acquire), 0);
    assert_eq!(overlay_contributions(&fixture), 0);
    assert_eq!(
        pending_event_ids(&fixture),
        vec![CLOSED_EVENT_ID.to_string()]
    );
}
