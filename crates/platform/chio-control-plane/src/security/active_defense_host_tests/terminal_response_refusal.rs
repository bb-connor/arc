use super::*;
use crate::security::event_consumer::AttestedFindingResponsePolicySelection;
use crate::security::{ProductionActiveDefenseHostError, ResponseWorkerTickError};
use chio_core::canonical_json_bytes;
use chio_core_types::SignedSecurityEvent;
use chio_kernel::AuthoritativeCorrelatedFindingEvidence;
use chio_security_types::ports::{
    derive_attested_finding_action_id, derive_attested_finding_batch_id,
    derive_attested_finding_reservation_id, AttestedFindingBatchBinding,
    AttestedFindingBatchBindings, AttestedFindingBatchBody, AttestedFindingBatchPublication,
    AttestedFindingBatchStore, AttestedFindingResponseOutboxKey,
    AttestedFindingResponseOutboxRecord, AttestedFindingResponseOutboxStore,
    AttestedFindingResponsePlanningState, ErrorCode, LineageId, ProducerTrustClass,
    ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
};
use chio_security_types::{
    SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity, SecuritySubject,
};

const REFUSED_EVENT_ID: &str = "host-refused-response-event";
const LATER_EVENT_ID: &str = "host-later-healthy-event";
const POLICY_REFUSAL_CODE: &str = "active_response.policy_refused";
const INDEPENDENT_EVIDENCE_ID: &str = "host-independent-response-evidence";
const SETTLE_TIMEOUT: Duration = Duration::from_secs(5);

struct RefusingResponsePolicy;

impl AttestedFindingResponsePolicyPlanner for RefusingResponsePolicy {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn select_response_policy(
        &self,
        _: &AuthoritativeCorrelatedFindingEvidence,
        _: &AttestedFindingBatchBinding,
    ) -> PortResult<AttestedFindingResponsePolicySelection> {
        Err(PortError::new(
            PortErrorKind::InvalidData,
            ErrorCode::new(POLICY_REFUSAL_CODE)
                .unwrap_or_else(|error| panic!("policy refusal code: {error}")),
        ))
    }
}

fn refusal_fixture(attest_findings: bool) -> HostFixture {
    let mut fixture = HostFixture::new();
    fixture.config.response_policy_planner = Arc::new(RefusingResponsePolicy);
    if attest_findings {
        fixture.config.active_defense.policy_hashes.insert(
            RecordId::new("host-lifecycle-policy")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            Digest32::new([8_u8; 32]),
        );
    }
    fixture
}

fn signed_host_event(
    event_id: &str,
    event_kind: SecurityEventKind,
    session_id: &str,
) -> UnverifiedSecurityEvent {
    let record = |value: &str| {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id {value}: {error}"))
    };
    let receipt = |value: &str| {
        OpaqueReceiptRef::new(value).unwrap_or_else(|error| panic!("receipt id {value}: {error}"))
    };
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
        event_time_unix_ms: 50_000,
        ingest_time_unix_ms: 50_000,
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
        event_kind,
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

fn publish_independent_response_work(
    store: &SqliteSecurityStateStore,
) -> AttestedFindingResponseOutboxKey {
    let tenant_id =
        TenantId::new("tenant-host-lifecycle").unwrap_or_else(|error| panic!("tenant: {error}"));
    let evidence_id = OpaqueReceiptRef::new(INDEPENDENT_EVIDENCE_ID)
        .unwrap_or_else(|error| panic!("independent evidence id: {error}"));
    let finding_id = RecordId::new("host-independent-response-finding")
        .unwrap_or_else(|error| panic!("independent finding id: {error}"));
    let finding_hash = Digest32::new([9_u8; 32]);
    let batch_id = derive_attested_finding_batch_id(std::slice::from_ref(&evidence_id))
        .unwrap_or_else(|error| panic!("independent batch id: {error}"));
    let action_id = derive_attested_finding_action_id(
        &batch_id,
        0,
        &tenant_id,
        &evidence_id,
        &finding_id,
        &finding_hash,
    )
    .unwrap_or_else(|error| panic!("independent action id: {error}"));
    let reservation_id =
        derive_attested_finding_reservation_id(&batch_id, &action_id, &evidence_id)
            .unwrap_or_else(|error| panic!("independent reservation id: {error}"));
    let body = AttestedFindingBatchBody {
        schema_version: ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
        batch_id,
        tenant_id: tenant_id.clone(),
        bindings: AttestedFindingBatchBindings::new(vec![AttestedFindingBatchBinding {
            tenant_id: tenant_id.clone(),
            evidence_id,
            finding_id,
            finding_hash,
            action_id: action_id.clone(),
            reservation_id,
        }])
        .unwrap_or_else(|_| panic!("independent batch bindings")),
    };
    let canonical =
        canonical_json_bytes(&body).unwrap_or_else(|error| panic!("independent batch: {error}"));
    let publication = AttestedFindingBatchPublication {
        body,
        body_hash: Digest32::new(*chio_core::sha256(&canonical).as_bytes()),
        canonical_body: CanonicalBody::new(canonical)
            .unwrap_or_else(|error| panic!("independent canonical batch: {error}")),
    };
    AttestedFindingBatchStore::publish_attested_finding_batch(store, &publication)
        .unwrap_or_else(|error| panic!("publish independent response work: {error}"));
    AttestedFindingResponseOutboxKey {
        tenant_id,
        action_id,
    }
}

fn independent_response_work(
    fixture: &HostFixture,
    key: &AttestedFindingResponseOutboxKey,
) -> AttestedFindingResponseOutboxRecord {
    AttestedFindingResponseOutboxStore::load_attested_finding_response_outbox(
        fixture.security_store.as_ref(),
        key,
    )
    .unwrap_or_else(|error| panic!("load independent response work: {error}"))
    .unwrap_or_else(|| panic!("independent response work is missing"))
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

fn ingress_response_rows(fixture: &HostFixture) -> Vec<(String, String, Option<String>)> {
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open outbox inspection connection: {error}"));
    let mut statement = connection
        .prepare(
            "SELECT planning_state, admission_state, last_error_code FROM security_attested_finding_response_outbox WHERE evidence_id != ?1 ORDER BY batch_id, ordinal",
        )
        .unwrap_or_else(|error| panic!("prepare outbox query: {error}"));
    let rows = statement
        .query_map([INDEPENDENT_EVIDENCE_ID], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap_or_else(|error| panic!("query outbox: {error}"));
    rows.map(|row| row.unwrap_or_else(|error| panic!("outbox row: {error}")))
        .collect()
}

fn durable_policy_refusal() -> Vec<(String, String, Option<String>)> {
    vec![(
        "failed".to_string(),
        "rejected".to_string(),
        Some(POLICY_REFUSAL_CODE.to_string()),
    )]
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

async fn settles(mut settled: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(SETTLE_TIMEOUT, async {
        while !settled() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn terminal_policy_refusal_is_acknowledged_without_stalling_later_ingress_or_outbox_recovery()
{
    let fixture = refusal_fixture(true);
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    host.consume(&signed_host_event(
        REFUSED_EVENT_ID,
        SecurityEventKind::CredentialAccess,
        "host-refused-session",
    ))
    .unwrap_or_else(|error| panic!("accept refused event into ingress: {error}"));
    host.consume(&signed_host_event(
        LATER_EVENT_ID,
        SecurityEventKind::TripwireObservation,
        "host-later-session",
    ))
    .unwrap_or_else(|error| panic!("accept later event into ingress: {error}"));
    assert_eq!(
        pending_event_ids(&fixture),
        vec![REFUSED_EVENT_ID.to_string(), LATER_EVENT_ID.to_string()]
    );
    assert!(ingress_response_rows(&fixture).is_empty());

    fixture.clock.set(51_500);
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while ingress_response_rows(&fixture) != durable_policy_refusal() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "refused event did not reach a durable terminal policy refusal: {:?}",
            ingress_response_rows(&fixture)
        )
    });

    let independent = publish_independent_response_work(&fixture.security_store);
    wait_for_ticks(&host, 10).await;
    let acknowledged = settles(|| pending_event_ids(&fixture).is_empty()).await;
    let independent_recovered = settles(|| {
        let record = independent_response_work(&fixture, &independent);
        record.attempts > 0
            && record.planning_state != AttestedFindingResponsePlanningState::Pending
    })
    .await;
    let ready = settles(|| host.ensure_ready().is_ok()).await;
    let pending = pending_event_ids(&fixture);
    let refusal = ingress_response_rows(&fixture);
    let independent_record = independent_response_work(&fixture, &independent);
    let health = host.worker_health();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));

    assert!(
        acknowledged,
        "durable terminal policy refusal left ingress unacknowledged: pending={pending:?} lifecycle={:?} last_error={:?}",
        health.lifecycle, health.last_error
    );
    assert_eq!(refusal, durable_policy_refusal());
    assert!(
        independent_recovered,
        "outbox recovery made no progress behind the refused event: attempts={} planning={:?} lifecycle={:?} last_error={:?}",
        independent_record.attempts,
        independent_record.planning_state,
        health.lifecycle,
        health.last_error
    );
    assert!(
        ready,
        "worker did not return to readiness: lifecycle={:?} last_error={:?}",
        health.lifecycle, health.last_error
    );
}

#[tokio::test]
async fn unacknowledgeable_ingress_event_does_not_stop_outbox_recovery() {
    let fixture = refusal_fixture(false);
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    host.consume(&signed_host_event(
        REFUSED_EVENT_ID,
        SecurityEventKind::CredentialAccess,
        "host-refused-session",
    ))
    .unwrap_or_else(|error| panic!("accept unattestable event into ingress: {error}"));

    fixture.clock.set(51_500);
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while host.worker_health().lifecycle != ResponseWorkerLifecycle::Degraded {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("attestation failure did not degrade the worker"));
    assert_eq!(
        pending_event_ids(&fixture),
        vec![REFUSED_EVENT_ID.to_string()]
    );
    assert!(ingress_response_rows(&fixture).is_empty());

    let independent = publish_independent_response_work(&fixture.security_store);
    wait_for_ticks(&host, 10).await;
    let independent_recovered = settles(|| {
        let record = independent_response_work(&fixture, &independent);
        record.attempts > 0
            && record.planning_state != AttestedFindingResponsePlanningState::Pending
    })
    .await;
    let pending = pending_event_ids(&fixture);
    let independent_record = independent_response_work(&fixture, &independent);
    let health = host.worker_health();
    let readiness = host.ensure_ready();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));

    assert_eq!(pending, vec![REFUSED_EVENT_ID.to_string()]);
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Degraded);
    assert!(
        matches!(
            readiness,
            Err(ProductionActiveDefenseHostError::Worker(
                ResponseWorkerTickError::RuntimeAdmissionClosed
            ))
        ),
        "unacknowledgeable ingress must keep runtime admission closed: {readiness:?}"
    );
    assert!(
        independent_recovered,
        "outbox recovery made no progress behind the unacknowledgeable event: attempts={} planning={:?} last_error={:?}",
        independent_record.attempts,
        independent_record.planning_state,
        health.last_error
    );
}
