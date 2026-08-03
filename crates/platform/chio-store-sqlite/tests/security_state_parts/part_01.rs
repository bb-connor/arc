use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::sha256;
use chio_core::{
    crypto::{Ed25519Backend, Keypair},
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    },
    SignedSecurityEvent,
};
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, predict_containment_overlay_apply,
    predict_containment_overlay_remove, AdvisorySecurityEvent, CanonicalBody,
    ContainmentOverlayCommand, ContainmentOverlayStore, CorrelationCasRequest,
    CorrelationEventAdmissionRequest, CorrelationEventIndexRequest, CorrelationIngressStore,
    CorrelationPartial, CorrelationPartitionKey, CreateOutcome, Digest32, EffectId,
    EffectOperation, EffectRequest, EffectResult, EgressFenceCommit, EgressFenceRequest, ErrorCode,
    EventId, EventPartitionScan, FlowJoinRequest, FlowStateKey, FlowStateStore,
    IsolationEpochEvidenceVerifierPort, IsolationEpochId, IsolationEpochTransition, LineageId,
    OpaqueReceiptRef, OverlayApplyRequest, OverlayContribution, OverlayContributions,
    OverlayRemoveRequest, OverlaySnapshot, PortError, PortErrorKind, PortResult, ProducerId,
    ProducerTrustClass, RecordId, ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey,
    ResponsePlanRecord, ResponseSchedulerStore, ResponseStore, RuleId, SchedulerClaimRequest,
    SchedulerHealthAckRequest, SchedulerRetryRequest, SchedulerWorkKey, SecurityEventStore,
    SessionId, TenantId, TenantScopedId, UnverifiedSecurityEvent, VerifiedIsolationEvidence,
    VerifiedSecurityEvent,
};
use chio_security_types::ports::{
    ActionId, LineageFenceRelease, LineageFenceRequest, LineageFenceStore,
};
use chio_security_types::{
    Compartment, InformationLabel, PrincipalId, ResponseEffectKind, ResponseTarget,
    SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity,
    SecuritySubject,
};
use chio_store_sqlite::{
    security_state::SecurityStateClock, SqliteEncryptedBlobStore, SqliteReceiptStore,
    SqliteSecurityStateStore, TenantId as BlobTenantId, TenantKey,
};
use tempfile::tempdir;

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn encrypted_ref(path: &std::path::Path, tenant_id: &str, payload: &[u8]) -> RecordId {
    let store = SqliteEncryptedBlobStore::open(path)
        .unwrap_or_else(|error| panic!("open encrypted store: {error}"));
    let handle = store
        .write_encrypted_blob(
            &BlobTenantId::new(tenant_id),
            &TenantKey::from_bytes([7_u8; 32]),
            payload,
        )
        .unwrap_or_else(|error| panic!("write encrypted blob: {error}"));
    record(handle.blob_id())
}

struct TestIsolationEpochVerifier;

impl IsolationEpochEvidenceVerifierPort for TestIsolationEpochVerifier {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<VerifiedIsolationEvidence> {
        if transition.verification_evidence_hash != Digest32::new([1_u8; 32]) {
            return Err(PortError::invalid_data());
        }
        Ok(VerifiedIsolationEvidence {
            verifier_id: record("test-isolation-verifier"),
            receipt_ref: OpaqueReceiptRef::new("test-isolation-receipt")
                .map_err(PortError::from)?,
        })
    }
}

fn key(session: &str) -> FlowStateKey {
    FlowStateKey {
        tenant_id: tenant("tenant-a"),
        principal_id: PrincipalId::new("principal-a")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new("lineage-a")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new(session).unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("epoch-a")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
    }
}

fn compartment_label(value: &str) -> InformationLabel {
    InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([
            Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}"))
        ]),
    )
    .unwrap_or_else(|error| panic!("label: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    let hash = sha256(bytes);
    let mut value = [0_u8; 32];
    value.copy_from_slice(hash.as_ref());
    Digest32::new(value)
}

fn authenticated_correlation_event(
    event_id: &str,
) -> (UnverifiedSecurityEvent, VerifiedSecurityEvent) {
    authenticated_correlation_event_at(event_id, 10, 11)
}

fn authenticated_correlation_event_at(
    event_id: &str,
    event_time_unix_ms: u64,
    received_at_unix_ms: u64,
) -> (UnverifiedSecurityEvent, VerifiedSecurityEvent) {
    let tenant_id = tenant("tenant-correlation-ingress");
    let event_id = EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}"));
    let producer_id = ProducerId::new("detector-correlation-ingress")
        .unwrap_or_else(|error| panic!("producer id: {error}"));
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: event_id.clone(),
        event_time_unix_ms,
        ingest_time_unix_ms: received_at_unix_ms,
        tenant_id: tenant_id.clone(),
        subject: SecuritySubject {
            subject_id: record("subject-correlation-ingress"),
            agent_id: record("agent-correlation-ingress"),
            session_id: SessionId::new("session-correlation-ingress")
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record("capability-correlation-ingress"),
            lineage_seed: LineageId::new("lineage-correlation-ingress")
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-correlation-ingress")
            .unwrap_or_else(|error| panic!("source receipt id: {error}")),
        event_kind: SecurityEventKind::TripwireObservation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("evidence-correlation-ingress")
            .unwrap_or_else(|error| panic!("evidence id: {error}"))],
        producer_id: producer_id.clone(),
        producer_key_id: record("detector-correlation-ingress-key"),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record("policy-correlation-ingress"),
    })
    .unwrap_or_else(|error| panic!("security event body: {error}"));
    let canonical_body =
        canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical event body: {error}"));
    let signed =
        SignedSecurityEvent::sign_with_backend(body, &Ed25519Backend::new(Keypair::generate()))
            .unwrap_or_else(|error| panic!("sign correlation event: {error}"));
    let source_evidence = canonical_json_bytes(&signed)
        .unwrap_or_else(|error| panic!("canonical source evidence: {error}"));
    let mut evidence_preimage = b"chio.verified-security-event-evidence.v1\0".to_vec();
    evidence_preimage.extend_from_slice(&source_evidence);
    let canonical_body = CanonicalBody::new(canonical_body)
        .unwrap_or_else(|error| panic!("canonical event body: {error}"));
    let body_hash = digest(canonical_body.as_bytes());
    let source_evidence = CanonicalBody::new(source_evidence)
        .unwrap_or_else(|error| panic!("canonical source evidence: {error}"));
    let evidence_hash = digest(&evidence_preimage);
    let unverified = UnverifiedSecurityEvent {
        tenant_id: tenant_id.clone(),
        event_id: event_id.clone(),
        producer_id: producer_id.clone(),
        event_time_unix_ms,
        received_at_unix_ms,
        canonical_body: canonical_body.clone(),
        body_hash,
        source_evidence,
    };
    let verified = VerifiedSecurityEvent {
        tenant_id,
        event_id,
        producer_id,
        trust_class: ProducerTrustClass::InternalDetector,
        event_time_unix_ms,
        received_at_unix_ms,
        canonical_body,
        body_hash,
        evidence_hash,
    };
    (unverified, verified)
}

fn require_error<T>(result: PortResult<T>) -> PortError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn current_unix_ms() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock: {error}"));
    u64::try_from(duration.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

struct FixedSecurityStateClock {
    now_unix_ms: AtomicU64,
}

impl FixedSecurityStateClock {
    fn new(now_unix_ms: u64) -> Self {
        Self {
            now_unix_ms: AtomicU64::new(now_unix_ms),
        }
    }

    fn set(&self, now_unix_ms: u64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::Release);
    }
}

impl SecurityStateClock for FixedSecurityStateClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.now_unix_ms.load(Ordering::Acquire))
    }
}

fn overlay_apply_request(
    current: &OverlaySnapshot,
    session_id: &str,
    action_id: ActionId,
    effect_id: EffectId,
    posture_rank: u32,
    scheduler_fencing_token: u64,
    idempotency_suffix: &str,
) -> OverlayApplyRequest {
    let expires_at_unix_ms = current
        .active_contributions
        .as_slice()
        .iter()
        .find(|entry| entry.effect_id == effect_id)
        .and_then(|entry| entry.expires_at_unix_ms)
        .unwrap_or_else(|| current_unix_ms().saturating_add(120_000));
    overlay_apply_request_with_expiry(
        current,
        session_id,
        action_id,
        effect_id,
        posture_rank,
        scheduler_fencing_token,
        idempotency_suffix,
        expires_at_unix_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn overlay_apply_request_with_expiry(
    current: &OverlaySnapshot,
    session_id: &str,
    action_id: ActionId,
    effect_id: EffectId,
    posture_rank: u32,
    scheduler_fencing_token: u64,
    idempotency_suffix: &str,
    expires_at_unix_ms: u64,
) -> OverlayApplyRequest {
    let contribution_bytes = format!("{{\"posture_rank\":{posture_rank}}}").into_bytes();
    let contribution_hash = digest(&contribution_bytes);
    let request = EffectRequest {
        tenant_id: current.target.tenant_id.clone(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{idempotency_suffix}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new(session_id)
                .unwrap_or_else(|error| panic!("session id: {error}")),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{idempotency_suffix}").as_str()),
        expected_version_hash: containment_overlay_version_hash(current)
            .unwrap_or_else(|error| panic!("base version hash: {error}")),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "overlay-test-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .unwrap_or_else(|error| panic!("overlay contribution body: {error}")),
        contribution_hash,
    };
    let contribution = OverlayContribution {
        effect_id: effect_id.clone(),
        posture_rank,
        contribution_hash,
        expires_at_unix_ms: Some(expires_at_unix_ms),
    };
    let resulting_snapshot =
        predict_containment_overlay_apply(current, &contribution, scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("predict overlay apply: {error}"));
    OverlayApplyRequest {
        target: current.target.clone(),
        action_id,
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: containment_installed_version_hash(
                    &current.target,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed version hash: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn overlay_remove_request(
    apply: &OverlayApplyRequest,
    current: &OverlaySnapshot,
    session_id: &str,
    action_id: ActionId,
    scheduler_fencing_token: u64,
    idempotency_suffix: &str,
) -> OverlayRemoveRequest {
    let mut request = apply.command.request.clone();
    request.action_id = action_id.clone();
    request.target = ResponseTarget::Session {
        session_id: SessionId::new(session_id)
            .unwrap_or_else(|error| panic!("session id: {error}")),
    };
    request.operation = EffectOperation::Remove;
    request.idempotency_key =
        record(format!("response_effect_command:{idempotency_suffix}").as_str());
    request.expected_version_hash =
        containment_installed_version_hash(&current.target, &apply.contribution)
            .unwrap_or_else(|error| panic!("installed version hash: {error}"));
    request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_containment_overlay_remove(
        current,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("predict overlay remove: {error}"));
    OverlayRemoveRequest {
        target: current.target.clone(),
        action_id,
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: containment_overlay_version_hash(&resulting_snapshot)
                    .unwrap_or_else(|error| panic!("removed version hash: {error}")),
                applied: false,
            },
            resulting_snapshot,
        },
    }
}

fn overlay_target(session_id: &str) -> TenantScopedId {
    containment_session_target(
        &tenant("tenant-a"),
        &SessionId::new(session_id).unwrap_or_else(|error| panic!("session id: {error}")),
    )
    .unwrap_or_else(|error| panic!("containment target: {error}"))
}

fn empty_overlay(target: TenantScopedId) -> OverlaySnapshot {
    OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("empty overlay: {error}")),
        highest_fencing_token: 0,
    }
}

#[test]
fn migration_is_idempotent_and_preserves_existing_tables() {
    let directory =
        chio_test_support::private_fs::private_tempdir("receipt-security-state-migration")
            .unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let receipt_store = SqliteReceiptStore::open(&path)
        .unwrap_or_else(|error| panic!("open receipt store: {error}"));
    let keypair = Keypair::generate();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "security-migration-receipt".to_owned(),
            timestamp: 1,
            capability_id: "security-migration-capability".to_owned(),
            tool_server: "migration-server".to_owned(),
            tool_name: "migration-tool".to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .unwrap_or_else(|error| panic!("tool action: {error}")),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content".to_owned(),
            policy_hash: "policy".to_owned(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_owned()),
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap_or_else(|error| panic!("sign receipt: {error}"));
    receipt_store
        .append_chio_receipt_returning_seq(&receipt)
        .unwrap_or_else(|error| panic!("append receipt: {error}"));
    drop(receipt_store);

    drop(
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("first open: {error}")),
    );
    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("second open: {error}")),
    );

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("reopen database: {error}"));
    let receipt_id: String = connection
        .query_row(
            "SELECT receipt_id FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt.id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load existing receipt: {error}"));
    assert_eq!(receipt_id, receipt.id);
}

#[test]
fn response_effect_generation_migration_preserves_existing_intent() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("legacy-response-effect.db");
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open legacy database: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TABLE security_response_effects (
                effect_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                scheduler_fencing_token INTEGER NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                encrypted_rollback_ref TEXT,
                PRIMARY KEY (tenant_id, effect_id)
            );

            CREATE TABLE security_scheduler_leases (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                claim_id TEXT NOT NULL,
                claim_ordinal INTEGER NOT NULL,
                lease_owner_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                fencing_token INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, action_id)
            );

            INSERT INTO security_scheduler_leases (
                action_id, tenant_id, claim_id, claim_ordinal,
                lease_owner_id, lease_expires_at, fencing_token
            ) VALUES (
                'legacy-action', 'tenant-a', 'legacy-claim', 0,
                'legacy-worker', 4102444800000, 7
            );
            "#,
        )
        .unwrap_or_else(|error| panic!("create legacy response table: {error}"));
    connection
        .execute(
            r#"
            INSERT INTO security_response_effects (
                effect_id, tenant_id, action_id, scheduler_fencing_token,
                state, body, body_hash, encrypted_rollback_ref
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
            "#,
            rusqlite::params![
                "legacy-effect",
                "tenant-a",
                "legacy-action",
                7_i64,
                "apply_requested",
                b"{}".as_slice(),
                digest(b"{}").as_bytes().as_slice()
            ],
        )
        .unwrap_or_else(|error| panic!("insert legacy effect: {error}"));
    drop(connection);

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("migrate response store: {error}"));
    let loaded = store
        .load_effect(&ResponseEffectKey {
            tenant_id: tenant("tenant-a"),
            effect_id: EffectId::new("legacy-effect")
                .unwrap_or_else(|error| panic!("effect id: {error}")),
        })
        .unwrap_or_else(|error| panic!("load migrated effect: {error}"))
        .unwrap_or_else(|| panic!("migrated effect missing"));
    assert_eq!(loaded.generation, 0);
    assert_eq!(loaded.scheduler_lease_owner_id.as_str(), "legacy-worker");
    assert_eq!(loaded.scheduler_fencing_token, 7);
    assert_eq!(loaded.state, record("apply_requested"));
    let lease_body_hash_length = rusqlite::Connection::open(&path)
        .and_then(|connection| {
            connection.query_row(
                r#"
                SELECT length(lease_body_hash)
                FROM security_scheduler_leases
                WHERE tenant_id = 'tenant-a' AND action_id = 'legacy-action'
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
        })
        .unwrap_or_else(|error| panic!("load migrated lease body hash: {error}"));
    assert_eq!(lease_body_hash_length, 32);
}

#[test]
fn response_effect_owner_migration_rejects_unbound_existing_intent() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("unbound-response-effect.db");
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open legacy database: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TABLE security_response_effects (
                effect_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                scheduler_fencing_token INTEGER NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                encrypted_rollback_ref TEXT,
                PRIMARY KEY (tenant_id, effect_id)
            );
            "#,
        )
        .unwrap_or_else(|error| panic!("create legacy response table: {error}"));
    connection
        .execute(
            r#"
            INSERT INTO security_response_effects (
                effect_id, tenant_id, action_id, scheduler_fencing_token,
                state, body, body_hash, encrypted_rollback_ref
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
            "#,
            rusqlite::params![
                "unbound-effect",
                "tenant-a",
                "unbound-action",
                11_i64,
                "apply_requested",
                b"{}".as_slice(),
                digest(b"{}").as_bytes().as_slice()
            ],
        )
        .unwrap_or_else(|error| panic!("insert unbound effect: {error}"));
    drop(connection);

    let error = match SqliteSecurityStateStore::open(&path) {
        Ok(_) => panic!("unbound response effect migration unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn scheduler_retry_health_migration_preserves_age_conservatively() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("legacy-scheduler-retry.db");
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open legacy database: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TABLE security_scheduler_retries (
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                not_before INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, action_id)
            );
            INSERT INTO security_scheduler_retries (
                tenant_id, action_id, attempts, last_error, not_before
            ) VALUES ('tenant-a', 'legacy-action', 3, 'store.unavailable', 1234);
            "#,
        )
        .unwrap_or_else(|error| panic!("create legacy retry table: {error}"));
    drop(connection);

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("migrate scheduler retry store: {error}"));
    let loaded = store
        .load_retry(&SchedulerWorkKey {
            tenant_id: tenant("tenant-a"),
            action_id: ActionId::new("legacy-action")
                .unwrap_or_else(|error| panic!("action id: {error}")),
        })
        .unwrap_or_else(|error| panic!("load migrated retry: {error}"))
        .unwrap_or_else(|| panic!("migrated retry missing"));
    assert_eq!(loaded.attempts, 3);
    assert_eq!(loaded.last_error.as_str(), "store.unavailable");
    assert_eq!(loaded.first_failure_at_unix_ms, 0);
    assert_eq!(loaded.not_before_unix_ms, 1_234);
    assert!(loaded.health_event_id.is_none());
    assert!(!loaded.health_event_delivered);
}

#[test]
fn security_state_rejects_ephemeral_sqlite_paths() {
    for path in [
        "",
        ":memory:",
        "file:security-state?mode=memory&cache=shared",
        "FILE:security-state?mode=memory",
        "security-state?mode=memory",
        "security-state#fragment",
    ] {
        assert_eq!(
            require_error(SqliteSecurityStateStore::open(path)).kind(),
            PortErrorKind::InvalidData,
            "path must be rejected: {path:?}"
        );
    }
}

#[test]
fn concurrent_joins_retain_every_restriction_and_new_sessions_inherit() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("initialize store: {error}")),
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for (index, compartment) in ["phi", "secret"].into_iter().enumerate() {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = SqliteSecurityStateStore::open(path)
                .unwrap_or_else(|error| panic!("open store: {error}"));
            barrier.wait();
            store
                .join(&FlowJoinRequest {
                    key: key("session-a"),
                    principal_join: compartment_label(compartment),
                    lineage_join: compartment_label(compartment),
                    session_join: compartment_label(compartment),
                    transition_id: record(&format!("join-{index}")),
                })
                .unwrap_or_else(|error| panic!("join state: {error}"));
        }));
    }
    barrier.wait();
    for handle in handles {
        handle
            .join()
            .unwrap_or_else(|error| panic!("join worker: {error:?}"));
    }

    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("open final store: {error}"));
    let inherited = store
        .load(&key("session-b"))
        .unwrap_or_else(|error| panic!("load inherited state: {error}"))
        .unwrap_or_else(|| panic!("inherited state is missing"));
    for label in [
        &inherited.principal_label,
        &inherited.lineage_label,
        &inherited.session_label,
    ] {
        let compartments = label
            .compartments()
            .unwrap_or_else(|| panic!("label unexpectedly reached top"));
        assert!(compartments.iter().any(|value| value.as_str() == "phi"));
        assert!(compartments.iter().any(|value| value.as_str() == "secret"));
    }
}

#[test]
fn generation_change_invalidates_an_egress_fence() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let snapshot = store
        .join(&FlowJoinRequest {
            key: key("session-a"),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("join-initial"),
        })
        .unwrap_or_else(|error| panic!("initial join: {error}"));
    let fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: key("session-a"),
            request_id: chio_security_types::ports::RequestId::new("request-a")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([1; 32]),
            expected_context_generation: snapshot.context_generation,
            expires_at_unix_ms: i64::MAX as u64,
        })
        .unwrap_or_else(|error| panic!("acquire fence: {error}"));
    store
        .join(&FlowJoinRequest {
            key: key("session-b"),
            principal_join: compartment_label("pii"),
            lineage_join: InformationLabel::bottom(),
            session_join: compartment_label("pii"),
            transition_id: record("join-concurrent"),
        })
        .unwrap_or_else(|error| panic!("concurrent join: {error}"));
    let error = require_error(store.validate_egress_fence(&fence));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    let refreshed = store
        .load(&key("session-a"))
        .unwrap_or_else(|error| panic!("load first session: {error}"))
        .unwrap_or_else(|| panic!("first session state missing"));
    assert!(refreshed
        .session_label
        .compartments()
        .is_some_and(|values| values.iter().any(|value| value.as_str() == "pii")));
}

#[test]
fn egress_fence_binds_the_canonical_request_hash() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let snapshot = store
        .join(&FlowJoinRequest {
            key: key("session-a"),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("join-request-hash"),
        })
        .unwrap_or_else(|error| panic!("join state: {error}"));
    let request = EgressFenceRequest {
        key: key("session-a"),
        request_id: chio_security_types::ports::RequestId::new("request-hash-bound")
            .unwrap_or_else(|error| panic!("request id: {error}")),
        request_hash: Digest32::new([5; 32]),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: current_unix_ms() + 60_000,
    };
    let fence = store
        .acquire_egress_fence(&request)
        .unwrap_or_else(|error| panic!("acquire fence: {error}"));
    assert_eq!(
        store
            .acquire_egress_fence(&request)
            .unwrap_or_else(|error| panic!("retry fence: {error}")),
        fence
    );

    let mut mutated_request = request;
    mutated_request.request_hash = Digest32::new([6; 32]);
    assert_eq!(
        require_error(store.acquire_egress_fence(&mutated_request)).kind(),
        PortErrorKind::Conflict
    );
    let mut mutated_fence = fence;
    mutated_fence.request_hash = Digest32::new([6; 32]);
    assert_eq!(
        require_error(store.validate_egress_fence(&mutated_fence)).kind(),
        PortErrorKind::Conflict
    );
}

#[test]
fn lineage_change_invalidates_every_principal_context() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let first_key = key("session-a");
    let first = store
        .join(&FlowJoinRequest {
            key: first_key.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("first-principal"),
        })
        .unwrap_or_else(|error| panic!("join first principal: {error}"));
    let fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: first_key.clone(),
            request_id: chio_security_types::ports::RequestId::new("shared-lineage-fence")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([2; 32]),
            expected_context_generation: first.context_generation,
            expires_at_unix_ms: i64::MAX as u64,
        })
        .unwrap_or_else(|error| panic!("acquire fence: {error}"));
    let second_key = FlowStateKey {
        principal_id: PrincipalId::new("principal-b")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        session_id: SessionId::new("session-b")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("epoch-b")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        ..first_key.clone()
    };
    store
        .join(&FlowJoinRequest {
            key: second_key,
            principal_join: InformationLabel::bottom(),
            lineage_join: compartment_label("shared-secret"),
            session_join: InformationLabel::bottom(),
            transition_id: record("second-principal"),
        })
        .unwrap_or_else(|error| panic!("join second principal: {error}"));
    let error = require_error(store.validate_egress_fence(&fence));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    let inherited = store
        .load(&first_key)
        .unwrap_or_else(|error| panic!("load first principal: {error}"))
        .unwrap_or_else(|| panic!("first principal state missing"));
    assert!(inherited
        .session_label
        .compartments()
        .is_some_and(|values| values.contains(
            &Compartment::new("shared-secret")
                .unwrap_or_else(|error| panic!("compartment: {error}"))
        )));
}

#[test]
fn no_op_shared_label_joins_preserve_sibling_context_integrity() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));

    let shared_lineage_first = key("shared-lineage-session-a");
    let first_snapshot = store
        .join(&FlowJoinRequest {
            key: shared_lineage_first.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("shared-lineage-first"),
        })
        .unwrap_or_else(|error| panic!("join first shared-lineage context: {error}"));
    let shared_lineage_second = FlowStateKey {
        principal_id: PrincipalId::new("principal-b")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        session_id: SessionId::new("shared-lineage-session-b")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("epoch-b")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        ..shared_lineage_first.clone()
    };
    store
        .join(&FlowJoinRequest {
            key: shared_lineage_second,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("shared-lineage-second"),
        })
        .unwrap_or_else(|error| panic!("join second shared-lineage context: {error}"));
    assert_eq!(
        store
            .load(&shared_lineage_first)
            .unwrap_or_else(|error| panic!("load first shared-lineage context: {error}"))
            .unwrap_or_else(|| panic!("first shared-lineage context missing"))
            .context_generation,
        first_snapshot.context_generation
    );

    let first_lineage = key("multi-lineage-session-a");
    let first_lineage_snapshot = store
        .join(&FlowJoinRequest {
            key: first_lineage.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("multi-lineage-first"),
        })
        .unwrap_or_else(|error| panic!("join first lineage: {error}"));
    let second_lineage = FlowStateKey {
        lineage_id: LineageId::new("lineage-b")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new("multi-lineage-session-b")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        ..first_lineage.clone()
    };
    store
        .join(&FlowJoinRequest {
            key: second_lineage,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("multi-lineage-second"),
        })
        .unwrap_or_else(|error| panic!("join second lineage: {error}"));
    assert_eq!(
        store
            .load(&first_lineage)
            .unwrap_or_else(|error| panic!("load first lineage: {error}"))
            .unwrap_or_else(|| panic!("first lineage context missing"))
            .context_generation,
        first_lineage_snapshot.context_generation
    );
}

#[test]
fn new_lineage_inherits_existing_epoch_and_cannot_bootstrap_a_new_epoch() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let original = key("lineage-a-session");
    store
        .join(&FlowJoinRequest {
            key: original.clone(),
            principal_join: compartment_label("principal-history"),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("lineage-a-bootstrap"),
        })
        .unwrap_or_else(|error| panic!("bootstrap principal epoch: {error}"));

    let same_epoch_new_lineage = FlowStateKey {
        lineage_id: LineageId::new("lineage-b")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new("lineage-b-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        ..original.clone()
    };
    let inherited = store
        .join(&FlowJoinRequest {
            key: same_epoch_new_lineage,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("lineage-b-same-epoch"),
        })
        .unwrap_or_else(|error| panic!("join same epoch on new lineage: {error}"));
    assert!(inherited
        .session_label
        .compartments()
        .is_some_and(|values| values.contains(
            &Compartment::new("principal-history")
                .unwrap_or_else(|error| panic!("compartment: {error}"))
        )));

    let arbitrary_epoch = FlowStateKey {
        lineage_id: LineageId::new("lineage-c")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new("lineage-c-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("epoch-unverified")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        ..original
    };
    assert_eq!(
        require_error(store.join(&FlowJoinRequest {
            key: arbitrary_epoch,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("lineage-c-unverified-epoch"),
        }))
        .kind(),
        PortErrorKind::InvalidData
    );
}

#[test]
fn session_taint_is_shared_across_lineages_within_an_epoch() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let first = key("shared-session");
    store
        .join(&FlowJoinRequest {
            key: first.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: compartment_label("session-secret"),
            transition_id: record("shared-session-first-lineage"),
        })
        .unwrap_or_else(|error| panic!("join first lineage: {error}"));

    let second = FlowStateKey {
        lineage_id: LineageId::new("lineage-b")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        ..first.clone()
    };
    let inherited = store
        .join(&FlowJoinRequest {
            key: second.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("shared-session-second-lineage"),
        })
        .unwrap_or_else(|error| panic!("join second lineage: {error}"));
    let expected =
        Compartment::new("session-secret").unwrap_or_else(|error| panic!("compartment: {error}"));
    assert!(inherited
        .session_label
        .compartments()
        .is_some_and(|values| values.contains(&expected)));
    assert!(store
        .load(&first)
        .unwrap_or_else(|error| panic!("load first lineage: {error}"))
        .unwrap_or_else(|| panic!("first lineage state missing"))
        .session_label
        .compartments()
        .is_some_and(|values| values.contains(&expected)));
    assert!(store
        .load(&second)
        .unwrap_or_else(|error| panic!("load second lineage: {error}"))
        .unwrap_or_else(|| panic!("second lineage state missing"))
        .session_label
        .compartments()
        .is_some_and(|values| values.contains(&expected)));
}

#[test]
fn session_change_invalidates_same_session_fences_across_lineages() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let first = key("shared-fenced-session");
    store
        .join(&FlowJoinRequest {
            key: first.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("shared-fence-first-lineage"),
        })
        .unwrap_or_else(|error| panic!("join first lineage: {error}"));
    let second = FlowStateKey {
        lineage_id: LineageId::new("lineage-b")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        ..first.clone()
    };
    let second_snapshot = store
        .join(&FlowJoinRequest {
            key: second.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("shared-fence-second-lineage"),
        })
        .unwrap_or_else(|error| panic!("join second lineage: {error}"));
    let sibling_fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: second.clone(),
            request_id: chio_security_types::ports::RequestId::new("shared-session-fence")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([8; 32]),
            expected_context_generation: second_snapshot.context_generation,
            expires_at_unix_ms: i64::MAX as u64,
        })
        .unwrap_or_else(|error| panic!("acquire sibling fence: {error}"));

    store
        .join(&FlowJoinRequest {
            key: first,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: compartment_label("late-session-secret"),
            transition_id: record("shared-session-taint-advance"),
        })
        .unwrap_or_else(|error| panic!("advance shared session: {error}"));

    assert_eq!(
        require_error(store.validate_egress_fence(&sibling_fence)).kind(),
        PortErrorKind::Conflict
    );
    assert!(store
        .load(&second)
        .unwrap_or_else(|error| panic!("load sibling lineage: {error}"))
        .unwrap_or_else(|| panic!("sibling lineage state missing"))
        .session_label
        .compartments()
        .is_some_and(|values| values.contains(
            &Compartment::new("late-session-secret")
                .unwrap_or_else(|error| panic!("compartment: {error}"))
        )));
}

#[test]
fn missing_flow_context_generation_fails_closed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    store
        .join(&FlowJoinRequest {
            key: key("session-a"),
            principal_join: compartment_label("restricted"),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("flow-before-corruption"),
        })
        .unwrap_or_else(|error| panic!("join flow: {error}"));
    rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.execute(
                "DELETE FROM security_flow_contexts WHERE tenant_id = 'tenant-a' AND principal_id = 'principal-a'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt context generation: {error}"));
    let error = require_error(store.load(&key("session-a")));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn missing_flow_epoch_or_session_row_fails_closed() {
    for missing_table in ["security_isolation_epochs", "security_session_flow_state"] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("state.db");
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open store: {error}"));
        store
            .join(&FlowJoinRequest {
                key: key("session-a"),
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: compartment_label("session-only"),
                transition_id: record("flow-before-row-loss"),
            })
            .unwrap_or_else(|error| panic!("join flow: {error}"));
        let statement = format!("DELETE FROM {missing_table}");
        rusqlite::Connection::open(path)
            .and_then(|connection| {
                connection.execute(&statement, [])?;
                Ok(())
            })
            .unwrap_or_else(|error| panic!("delete flow row: {error}"));
        let error = require_error(store.load(&key("session-a")));
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}

#[test]
fn egress_fence_rejects_corrupt_flow_state() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let snapshot = store
        .join(&FlowJoinRequest {
            key: key("session-a"),
            principal_join: compartment_label("restricted"),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("join-before-fence-corruption"),
        })
        .unwrap_or_else(|error| panic!("join flow: {error}"));
    let fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: key("session-a"),
            request_id: chio_security_types::ports::RequestId::new("corrupt-flow-fence")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([3; 32]),
            expected_context_generation: snapshot.context_generation,
            expires_at_unix_ms: current_unix_ms() + 60_000,
        })
        .unwrap_or_else(|error| panic!("acquire fence: {error}"));
    rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_principal_flow_state SET label_hash = zeroblob(32) WHERE principal_id = 'principal-a'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt principal label hash: {error}"));
    let validation_error = require_error(store.validate_egress_fence(&fence));
    assert_eq!(validation_error.kind(), PortErrorKind::IntegrityFailure);
    let commit_error = require_error(store.commit_egress_fence(&EgressFenceCommit {
        fence,
        dispatch_commitment_id: record("corrupt-flow-dispatch"),
        committed_at_unix_ms: current_unix_ms(),
    }));
    assert_eq!(commit_error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn egress_dispatch_commitment_is_idempotent_and_immutable() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let snapshot = store
        .join(&FlowJoinRequest {
            key: key("session-a"),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("join-for-commit"),
        })
        .unwrap_or_else(|error| panic!("join state: {error}"));
    let fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: key("session-a"),
            request_id: chio_security_types::ports::RequestId::new("request-commit")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([4; 32]),
            expected_context_generation: snapshot.context_generation,
            expires_at_unix_ms: current_unix_ms() + 60_000,
        })
        .unwrap_or_else(|error| panic!("acquire fence: {error}"));
    let invalid_time = fence.expires_at_unix_ms + 1;
    let invalid_time_error = require_error(store.commit_egress_fence(&EgressFenceCommit {
        fence: fence.clone(),
        dispatch_commitment_id: record("invalid-time-commitment"),
        committed_at_unix_ms: invalid_time,
    }));
    assert_eq!(invalid_time_error.kind(), PortErrorKind::InvalidData);
    let commitment = EgressFenceCommit {
        fence,
        dispatch_commitment_id: record("dispatch-commitment"),
        committed_at_unix_ms: current_unix_ms(),
    };
    let first = store
        .commit_egress_fence(&commitment)
        .unwrap_or_else(|error| panic!("commit fence: {error}"));
    store
        .join(&FlowJoinRequest {
            key: key("session-b"),
            principal_join: compartment_label("post-commit-taint"),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("post-commit-flow-change"),
        })
        .unwrap_or_else(|error| panic!("join post-commit flow: {error}"));
    let retry = store
        .commit_egress_fence(&commitment)
        .unwrap_or_else(|error| panic!("retry fence commit: {error}"));
    assert_eq!(first, retry);
    let error = require_error(store.commit_egress_fence(&EgressFenceCommit {
        dispatch_commitment_id: record("different-commitment"),
        ..commitment
    }));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}

#[test]
fn lineage_fences_are_durable_and_orphans_recover_with_higher_fencing_tokens() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let now = current_unix_ms();
    let action_id =
        ActionId::new("contained-action").unwrap_or_else(|error| panic!("action id: {error}"));
    let action = TenantScopedId {
        tenant_id: tenant("tenant-a"),
        id: record("contained-action"),
    };

    let fence_request = LineageFenceRequest {
        tenant_id: tenant("tenant-a"),
        action_id: action_id.clone(),
        expected_commit_index: 41,
        expected_affected_set_hash: digest(b"affected set"),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "lineage-state-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token: 17,
        expires_at_unix_ms: now + 60_000,
    };
    let first = LineageFenceStore::acquire(&store, &fence_request)
        .unwrap_or_else(|error| panic!("acquire lineage fence: {error}"));
    let retry = LineageFenceStore::acquire(&store, &fence_request)
        .unwrap_or_else(|error| panic!("retry lineage fence: {error}"));
    assert_eq!(first, retry);
    rusqlite::Connection::open(&path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_lineage_fences SET expires_at = 0 WHERE action_id = 'contained-action'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("expire lineage fence: {error}"));
    assert!(LineageFenceStore::query(&store, &action)
        .unwrap_or_else(|error| panic!("query expired lineage fence: {error}"))
        .is_none());
    let expired_release_error = require_error(LineageFenceStore::release(
        &store,
        &LineageFenceRelease {
            tenant_id: tenant("tenant-a"),
            action_id: action_id.clone(),
            fencing_token: first.fencing_token,
            scheduler_lease_owner_id: first.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: first.scheduler_fencing_token,
        },
    ));
    assert_eq!(expired_release_error.kind(), PortErrorKind::Conflict);
    let recovered = LineageFenceStore::acquire(
        &store,
        &LineageFenceRequest {
            expires_at_unix_ms: now + 120_000,
            ..fence_request.clone()
        },
    )
    .unwrap_or_else(|error| panic!("recover lineage fence: {error}"));
    assert!(recovered.fencing_token > first.fencing_token);
    drop(store);
    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    assert_eq!(
        LineageFenceStore::query(&store, &action)
            .unwrap_or_else(|error| panic!("query recovered lineage fence: {error}")),
        Some(recovered.clone())
    );
    let stale_error = require_error(LineageFenceStore::release(
        &store,
        &LineageFenceRelease {
            tenant_id: tenant("tenant-a"),
            action_id: action_id.clone(),
            fencing_token: first.fencing_token,
            scheduler_lease_owner_id: first.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: first.scheduler_fencing_token,
        },
    ));
    assert_eq!(stale_error.kind(), PortErrorKind::Conflict);
    LineageFenceStore::release(
        &store,
        &LineageFenceRelease {
            tenant_id: tenant("tenant-a"),
            action_id,
            fencing_token: recovered.fencing_token,
            scheduler_lease_owner_id: recovered.scheduler_lease_owner_id,
            scheduler_fencing_token: recovered.scheduler_fencing_token,
        },
    )
    .unwrap_or_else(|error| panic!("release lineage fence: {error}"));
    assert!(LineageFenceStore::query(&store, &action)
        .unwrap_or_else(|error| panic!("query released lineage fence: {error}"))
        .is_none());
    let reacquire_error = require_error(LineageFenceStore::acquire(
        &store,
        &LineageFenceRequest {
            expires_at_unix_ms: now + 180_000,
            ..fence_request
        },
    ));
    assert_eq!(reacquire_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn isolation_epoch_must_be_verified_and_preserves_lineage_taint() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    store
        .join(&FlowJoinRequest {
            key: key("session-a"),
            principal_join: compartment_label("principal-secret"),
            lineage_join: compartment_label("lineage-secret"),
            session_join: compartment_label("session-secret"),
            transition_id: record("join-tainted"),
        })
        .unwrap_or_else(|error| panic!("taint state: {error}"));
    let next_key = FlowStateKey {
        session_id: SessionId::new("session-b")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("epoch-b")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        ..key("session-a")
    };
    let error = require_error(store.join(&FlowJoinRequest {
        key: next_key,
        principal_join: InformationLabel::bottom(),
        lineage_join: InformationLabel::bottom(),
        session_join: InformationLabel::bottom(),
        transition_id: record("unverified-epoch"),
    }));
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    let transition = IsolationEpochTransition {
        tenant_id: tenant("tenant-a"),
        principal_id: PrincipalId::new("principal-a")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new("lineage-a")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        previous_isolation_epoch_id: IsolationEpochId::new("epoch-a")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        new_isolation_epoch_id: IsolationEpochId::new("epoch-b")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        new_session_id: SessionId::new("session-b")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        verification_evidence_hash: Digest32::new([1_u8; 32]),
        transition_id: record("verified-epoch"),
        effective_at_unix_ms: 2,
    };
    let verifier_error = require_error(store.open_isolation_epoch(&transition));
    assert_eq!(verifier_error.kind(), PortErrorKind::InvalidData);
    drop(store);
    let store = SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
        path,
        Arc::new(TestIsolationEpochVerifier),
    )
    .unwrap_or_else(|error| panic!("open verified store: {error}"));
    let isolated = store
        .open_isolation_epoch(&transition)
        .unwrap_or_else(|error| panic!("open verified epoch: {error}"));
    assert!(isolated.principal_label.is_bottom());
    assert!(isolated
        .lineage_label
        .compartments()
        .is_some_and(|values| values
            .iter()
            .any(|value| value.as_str() == "lineage-secret")));
    assert!(isolated
        .session_label
        .compartments()
        .is_some_and(|values| values
            .iter()
            .any(|value| value.as_str() == "lineage-secret")));
}

#[test]
fn corrupt_canonical_hash_fails_closed_on_read() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("canonical body: {error}"));
    let partition = CorrelationPartitionKey {
        tenant_id: tenant("tenant-a"),
        rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
        partition_hash: digest(b"partition"),
    };
    store
        .compare_and_swap_correlation(&CorrelationCasRequest {
            scan: EventPartitionScan {
                tenant_id: partition.tenant_id.clone(),
                rule_id: partition.rule_id.clone(),
                partition_hash: partition.partition_hash,
                after_event_time_unix_ms: None,
                after_event_id: None,
                through_event_time_unix_ms: 5,
                max_results: 10,
            },
            observed_partition_generation: 0,
            partial: CorrelationPartial {
                key: partition.clone(),
                generation: 0,
                watermark_unix_ms: 5,
                expires_at_unix_ms: 10,
                canonical_body: body,
                body_hash: digest(b"{}"),
            },
            expected_generation: None,
            transition_id: record("correlation-create"),
        })
        .unwrap_or_else(|error| panic!("create correlation: {error}"));
    drop(store);
    let oversized = rusqlite::Connection::open(&path).and_then(|connection| {
        connection.execute(
            "UPDATE security_correlation_partials SET body = zeroblob(1048577)",
            [],
        )
    });
    assert!(oversized.is_err());
    rusqlite::Connection::open(&path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_correlation_partials SET body_hash = zeroblob(32)",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt body hash: {error}"));
    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    let error = require_error(store.load_correlation(&partition));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn scheduler_retry_health_outbox_survives_restart_and_ack_is_idempotent() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("scheduler-health.db");
    let now = current_unix_ms();
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let action_id = ActionId::new("scheduler-health-action")
        .unwrap_or_else(|error| panic!("action id: {error}"));
    let plan = ResponsePlanRecord {
        tenant_id: tenant("tenant-a"),
        action_id: action_id.clone(),
        generation: 0,
        state: record("active"),
        canonical_body: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: digest(b"{}"),
        due_at_unix_ms: Some(now.saturating_sub(1)),
    };
    store
        .create(&plan)
        .unwrap_or_else(|error| panic!("create plan: {error}"));
    let claimed = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: plan.tenant_id.clone(),
            claim_id: record("scheduler-health-claim"),
            lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("health-worker")
                .unwrap_or_else(|error| panic!("owner id: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(60_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim scheduler work: {error}"));
    let work = claimed
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("scheduler claim missing"));
    let event_id = record("scheduler-health-event");
    let retry = store
        .record_retry(&SchedulerRetryRequest {
            work,
            expected_attempts: 0,
            error_code: ErrorCode::new("store.unavailable")
                .unwrap_or_else(|error| panic!("error code: {error}")),
            first_failure_at_unix_ms: now,
            now_unix_ms: now,
            not_before_unix_ms: now.saturating_add(1_000),
            health_event_id: Some(event_id.clone()),
            transition_id: record("scheduler-health-retry-transition"),
        })
        .unwrap_or_else(|error| panic!("record retry: {error}"));
    assert_eq!(retry.first_failure_at_unix_ms, now);
    assert_eq!(retry.health_event_id.as_ref(), Some(&event_id));
    assert!(!retry.health_event_delivered);
    let ack = SchedulerHealthAckRequest {
        key: SchedulerWorkKey {
            tenant_id: plan.tenant_id,
            action_id,
        },
        event_id,
        transition_id: record("scheduler-health-ack-transition"),
    };
    let delivered = store
        .acknowledge_health_event(&ack)
        .unwrap_or_else(|error| panic!("ack health event: {error}"));
    assert!(delivered.health_event_delivered);
    drop(store);

    let reopened = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    let loaded = reopened
        .load_retry(&ack.key)
        .unwrap_or_else(|error| panic!("load retry after restart: {error}"))
        .unwrap_or_else(|| panic!("retry missing after restart"));
    assert_eq!(loaded, delivered);
    assert_eq!(
        reopened
            .acknowledge_health_event(&ack)
            .unwrap_or_else(|error| panic!("repeat health ack: {error}")),
        delivered
    );
}

#[test]
fn scheduler_takeover_fences_stale_overlay_mutations() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let now = current_unix_ms();
    let clock = Arc::new(FixedSecurityStateClock::new(now));
    let store_clock: Arc<dyn SecurityStateClock> = clock.clone();
    let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, store_clock)
        .unwrap_or_else(|error| panic!("open store: {error}"));
    let plan = ResponsePlanRecord {
        tenant_id: tenant("tenant-a"),
        action_id: chio_security_types::ports::ActionId::new("action-a")
            .unwrap_or_else(|error| panic!("action id: {error}")),
        generation: 0,
        state: record("active"),
        canonical_body: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: digest(b"{}"),
        due_at_unix_ms: Some(now.saturating_sub(1)),
    };
    assert_eq!(
        store
            .create(&plan)
            .unwrap_or_else(|error| panic!("create plan: {error}")),
        CreateOutcome::Created
    );
    let first_request = SchedulerClaimRequest {
        tenant_id: tenant("tenant-a"),
        claim_id: record("scheduler-first-claim"),
        lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("worker-a")
            .unwrap_or_else(|error| panic!("owner id: {error}")),
        now_unix_ms: now,
        lease_expires_at_unix_ms: now + 60_000,
        max_claims: 1,
    };
    let first = store
        .claim_due(&first_request)
        .unwrap_or_else(|error| panic!("first claim: {error}"));
    assert_eq!(
        store
            .claim_due(&first_request)
            .unwrap_or_else(|error| panic!("repeat first claim: {error}")),
        first
    );
    let claim_reuse_error = require_error(store.claim_due(&SchedulerClaimRequest {
        max_claims: 2,
        ..first_request.clone()
    }));
    assert_eq!(claim_reuse_error.kind(), PortErrorKind::Conflict);
    let live_competitor = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant("tenant-a"),
            claim_id: record("scheduler-live-competitor"),
            lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("worker-b")
                .unwrap_or_else(|error| panic!("owner id: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now + 60_000,
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("live competing claim: {error}"));
    assert!(live_competitor.is_empty());
    let effect = ResponseEffectRecord {
        tenant_id: tenant("tenant-a"),
        effect_id: EffectId::new("persisted-effect")
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        action_id: plan.action_id.clone(),
        generation: 0,
        scheduler_lease_owner_id: first[0].lease_owner_id.clone(),
        scheduler_fencing_token: first[0].fencing_token,
        state: record("applied"),
        canonical_body: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: digest(b"{}"),
        encrypted_rollback_ref: Some(encrypted_ref(&path, "tenant-a", b"rollback material")),
    };
    let invalid_effect_error = require_error(
        store.persist_effect(&ResponseEffectRecord {
            effect_id: EffectId::new("invalid-reference-effect")
                .unwrap_or_else(|error| panic!("effect id: {error}")),
            encrypted_rollback_ref: Some(record("missing-rollback-blob")),
            ..effect.clone()
        }),
    );
    assert_eq!(invalid_effect_error.kind(), PortErrorKind::InvalidData);
    assert_eq!(
        store
            .persist_effect(&effect)
            .unwrap_or_else(|error| panic!("persist effect: {error}")),
        CreateOutcome::Created
    );
    let takeover_now = first[0].lease_expires_at_unix_ms.saturating_add(1);
    clock.set(takeover_now);
    let expired_claim_error = require_error(store.claim_due(&first_request));
    assert_eq!(expired_claim_error.kind(), PortErrorKind::Conflict);
    let second = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant("tenant-a"),
            claim_id: record("scheduler-takeover"),
            lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("worker-b")
                .unwrap_or_else(|error| panic!("owner id: {error}")),
            now_unix_ms: takeover_now,
            lease_expires_at_unix_ms: takeover_now.saturating_add(60_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("takeover claim: {error}"));
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert!(second[0].fencing_token > first[0].fencing_token);
    let displaced_claim_error = require_error(store.claim_due(&first_request));
    assert_eq!(displaced_claim_error.kind(), PortErrorKind::Conflict);
    let stale_effect_error = require_error(store.persist_effect(&effect));
    assert_eq!(stale_effect_error.kind(), PortErrorKind::Conflict);

    let overlay_session = "session-a";
    let target = overlay_target(overlay_session);
    let empty = empty_overlay(target.clone());
    let apply = overlay_apply_request(
        &empty,
        overlay_session,
        plan.action_id.clone(),
        EffectId::new("effect-a").unwrap_or_else(|error| panic!("effect id: {error}")),
        2,
        second[0].fencing_token,
        "stale-fence-apply",
    );
    let applied = store
        .apply_contribution(&apply)
        .unwrap_or_else(|error| panic!("apply overlay: {error}"));
    let stale_remove = overlay_remove_request(
        &apply,
        &applied,
        overlay_session,
        plan.action_id,
        first[0].fencing_token,
        "stale-fence-remove",
    );
    let error = require_error(store.remove_contribution(&stale_remove));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}

#[test]
fn injected_clock_controls_scheduler_lease_and_overlay_mutations() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let clock = Arc::new(FixedSecurityStateClock::new(50_000));
    let store_clock: Arc<dyn SecurityStateClock> = clock.clone();
    let store = SqliteSecurityStateStore::open_with_trusted_clock(
        directory.path().join("trusted-clock-state.db"),
        store_clock,
    )
    .unwrap_or_else(|error| panic!("open trusted-clock store: {error}"));
    let action_id =
        ActionId::new("trusted-clock-action").unwrap_or_else(|error| panic!("action id: {error}"));
    store
        .create(&ResponsePlanRecord {
            tenant_id: tenant("tenant-a"),
            action_id: action_id.clone(),
            generation: 0,
            state: record("active"),
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            due_at_unix_ms: Some(49_999),
        })
        .unwrap_or_else(|error| panic!("create trusted-clock plan: {error}"));
    let lease_owner_id = chio_security_types::ports::LeaseOwnerId::new("trusted-clock-worker")
        .unwrap_or_else(|error| panic!("lease owner: {error}"));
    let claimed = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant("tenant-a"),
            claim_id: record("trusted-clock-claim"),
            lease_owner_id: lease_owner_id.clone(),
            now_unix_ms: 50_000,
            lease_expires_at_unix_ms: 60_000,
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim trusted-clock plan: {error}"));
    assert_eq!(claimed.len(), 1);
    let fencing_token = claimed[0].fencing_token;
    store
        .validate_lease_identity(
            &tenant("tenant-a"),
            &action_id,
            &lease_owner_id,
            fencing_token,
        )
        .unwrap_or_else(|error| panic!("validate trusted-clock lease: {error}"));

    let overlay_session = "trusted-clock-session";
    let empty = empty_overlay(overlay_target(overlay_session));
    let first_apply = overlay_apply_request_with_expiry(
        &empty,
        overlay_session,
        action_id.clone(),
        EffectId::new("trusted-clock-effect-a")
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        3,
        fencing_token,
        "trusted-clock-apply-a",
        55_000,
    );
    let applied = store
        .apply_contribution(&first_apply)
        .unwrap_or_else(|error| panic!("apply trusted-clock overlay: {error}"));
    assert_eq!(applied.effective_posture_rank, 3);

    clock.set(54_000);
    let first_remove = overlay_remove_request(
        &first_apply,
        &applied,
        overlay_session,
        action_id.clone(),
        fencing_token,
        "trusted-clock-remove-a",
    );
    let removed = store
        .remove_contribution(&first_remove)
        .unwrap_or_else(|error| panic!("remove trusted-clock overlay: {error}"));
    assert!(removed.active_contributions.is_empty());

    let second_apply = overlay_apply_request_with_expiry(
        &removed,
        overlay_session,
        action_id.clone(),
        EffectId::new("trusted-clock-effect-b")
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        2,
        fencing_token,
        "trusted-clock-apply-b",
        65_000,
    );
    let second_applied = store
        .apply_contribution(&second_apply)
        .unwrap_or_else(|error| panic!("apply second trusted-clock overlay: {error}"));

    clock.set(60_000);
    let expired_lease = require_error(store.validate_lease_identity(
        &tenant("tenant-a"),
        &action_id,
        &lease_owner_id,
        fencing_token,
    ));
    assert_eq!(expired_lease.kind(), PortErrorKind::Conflict);
    let blocked_remove = overlay_remove_request(
        &second_apply,
        &second_applied,
        overlay_session,
        action_id,
        fencing_token,
        "trusted-clock-remove-b",
    );
    let error = require_error(store.remove_contribution(&blocked_remove));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}
