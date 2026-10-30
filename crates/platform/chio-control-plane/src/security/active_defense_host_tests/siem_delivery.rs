use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

use super::*;
use crate::security::ProductionActiveDefenseHostError;

const DELIVERY_TICKS: u64 = 20;
const EXHAUSTING_MAX_ATTEMPTS: u32 = 2;
const MAX_EXHAUSTION_PASSES: usize = 8;

#[derive(Default)]
struct RecordingAlertBackend {
    alerts: Mutex<Vec<Alert>>,
}

impl RecordingAlertBackend {
    fn alerts(&self) -> Vec<Alert> {
        self.alerts
            .lock()
            .unwrap_or_else(|_| panic!("recorded alert mutex poisoned"))
            .clone()
    }
}

impl AlertBackend for RecordingAlertBackend {
    fn name(&self) -> &str {
        "active-defense-host-recording"
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.alerts
                .lock()
                .map_err(|_| ExportError::HttpError("recording lock unavailable".to_owned()))?
                .push(alert.clone());
            Ok(())
        })
    }
}

#[derive(Default)]
struct UnavailableAlertBackend {
    attempts: AtomicUsize,
}

impl UnavailableAlertBackend {
    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl AlertBackend for UnavailableAlertBackend {
    fn name(&self) -> &str {
        "active-defense-host-unavailable"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(ExportError::HttpError("simulated SIEM outage".to_owned()))
        })
    }
}

#[derive(Debug)]
struct OutboxRow {
    idempotency_key: String,
    status: String,
    attempts: i64,
    next_attempt_at_unix_ms: i64,
}

fn outbox_rows(path: &std::path::Path) -> Vec<OutboxRow> {
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("open alert outbox inspection connection: {error}"));
    let mut statement = connection
        .prepare(
            "SELECT idempotency_key, status, attempts, next_attempt_at_unix_ms
             FROM chio_security_alert_outbox ORDER BY idempotency_key",
        )
        .unwrap_or_else(|error| panic!("prepare alert outbox inspection: {error}"));
    let rows = statement
        .query_map([], |row| {
            Ok(OutboxRow {
                idempotency_key: row.get(0)?,
                status: row.get(1)?,
                attempts: row.get(2)?,
                next_attempt_at_unix_ms: row.get(3)?,
            })
        })
        .unwrap_or_else(|error| panic!("query alert outbox: {error}"));
    rows.collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("decode alert outbox rows: {error}"))
}

fn wall_clock_unix_ms() -> u64 {
    chio_test_support::clock::unix_millis()
}

fn install_alert_outbox(
    fixture: &mut HostFixture,
    path: &std::path::Path,
    backend: Arc<dyn AlertBackend>,
    max_attempts: u32,
) -> Arc<SecurityAlertOutbox> {
    let outbox = Arc::new(
        SqliteSecurityAlertOutboxStore::open(path)
            .and_then(|store| {
                SecurityAlertOutbox::new(
                    Arc::new(store),
                    vec![backend],
                    AlertOutboxConfig {
                        base_retry_ms: 10,
                        max_retry_ms: 100,
                        max_attempts,
                    },
                )
            })
            .unwrap_or_else(|error| panic!("host test alert outbox: {error}")),
    );
    fixture.config.alert_outbox = Arc::clone(&outbox);
    fixture.config.scheduler_health = outbox.clone();
    outbox
}

fn apply_escalation_plan(fixture: &HostFixture, created_at_unix_ms: u64) {
    let tenant_id =
        TenantId::new("tenant-host-lifecycle").unwrap_or_else(|error| panic!("tenant: {error}"));
    let executor_identity = ActiveResponseExecutorAuthorityIdentity::new(
        fixture
            .config
            .signer
            .public_key()
            .unwrap_or_else(|error| panic!("signer key: {error}")),
        1,
    )
    .unwrap_or_else(|error| panic!("executor identity: {error}"));
    let canonical_contribution = CanonicalBody::new(b"{\"channel\":\"security\"}".to_vec())
        .unwrap_or_else(|error| panic!("escalation contribution: {error}"));
    let contribution_hash =
        Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
    let plan = build_response_plan(ResponsePlanInput {
        execution: chio_security_types::ResponseExecutionBinding::new(
            chio_security_types::ResponseExecutionMode::Live,
        ),
        action_id: ActionId::new("host-siem-escalation-action")
            .unwrap_or_else(|error| panic!("action id: {error}")),
        trigger_finding_id: RecordId::new("host-siem-escalation-finding")
            .unwrap_or_else(|error| panic!("finding id: {error}")),
        trigger_finding_hash: Digest32::new([12_u8; 32]),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("host-siem-escalation-receipt")
            .unwrap_or_else(|error| panic!("finding receipt: {error}")),
        tenant_id: tenant_id.clone(),
        policy_version: RecordId::new("host-lifecycle-policy")
            .unwrap_or_else(|error| panic!("policy version: {error}")),
        policy_hash: Digest32::new([13_u8; 32]),
        affected_ids: vec![RecordId::new(tenant_id.as_str())
            .unwrap_or_else(|error| panic!("affected tenant: {error}"))],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::EscalateAlert,
            target: ResponseTarget::Tenant { tenant_id },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: Digest32::new([14_u8; 32]),
        }],
        ttl_ms: 600_000,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: RecordId::new("host-siem-escalation-capability")
                .unwrap_or_else(|error| panic!("capability id: {error}")),
            capability_digest: Digest32::new([15_u8; 32]),
            expires_at_unix_ms: created_at_unix_ms.saturating_add(1_200_000),
            executor_subject: RecordId::new(executor_identity.subject().to_hex())
                .unwrap_or_else(|error| panic!("executor subject: {error}")),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: RecordId::new("host-siem-escalation-submitter")
            .unwrap_or_else(|error| panic!("submitter: {error}")),
        reason_hash: Digest32::new([16_u8; 32]),
    })
    .unwrap_or_else(|error| panic!("build escalation response plan: {error}"));
    let effects = Arc::new(
        ActiveResponseEffectPort::production_with_clock(
            Arc::clone(&fixture.security_store),
            Arc::clone(&fixture.config.alert_outbox),
            Arc::clone(&fixture.config.blast_radius),
            fixture.clock.clone(),
        )
        .unwrap_or_else(|error| panic!("construct escalation response effects: {error}")),
    );
    let receipts = Arc::new(NativeSecurityReceiptSink::new(
        Arc::clone(&fixture.config.indexed_evidence_store),
        Arc::clone(&fixture.config.signer),
    ));
    let executor = DurableActiveResponseExecutor::new(
        executor_identity,
        LeaseOwnerId::new("host-lifecycle-executor")
            .unwrap_or_else(|error| panic!("executor lease owner: {error}")),
        Arc::clone(&fixture.security_store),
        effects,
        receipts,
        Arc::clone(&fixture.config.alert_outbox),
        fixture.clock.clone(),
        500,
    )
    .unwrap_or_else(|error| panic!("construct durable escalation executor: {error}"));
    executor
        .execute_automatic_for_test(
            plan,
            Digest32::new([17_u8; 32]),
            Digest32::new([18_u8; 32]),
            created_at_unix_ms,
        )
        .unwrap_or_else(|error| panic!("apply escalation response: {error}"));
}

/// Pages one escalation alert through the production effect port and returns
/// its durable outbox row, pending with no delivery attempt.
fn page_escalation_alert(fixture: &HostFixture, alert_path: &std::path::Path) -> OutboxRow {
    let created_at_unix_ms = wall_clock_unix_ms();
    fixture.clock.set(created_at_unix_ms);
    apply_escalation_plan(fixture, created_at_unix_ms);
    let mut paged = outbox_rows(alert_path);
    assert_eq!(
        paged.len(),
        1,
        "the escalation effect must page one alert: {paged:?}"
    );
    let row = paged.remove(0);
    assert_eq!(
        (row.status.as_str(), row.attempts),
        ("pending", 0),
        "the paged alert must be durably pending before the host starts: {row:?}"
    );
    row
}

#[tokio::test]
async fn production_host_delivers_a_paged_escalation_alert_to_the_siem_backend() {
    let mut fixture = HostFixture::new();
    let alert_directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("alert tempdir: {error}"));
    let alert_path = alert_directory.path().join("recorded-alerts.sqlite");
    let backend = Arc::new(RecordingAlertBackend::default());
    install_alert_outbox(
        &mut fixture,
        &alert_path,
        Arc::clone(&backend) as Arc<dyn AlertBackend>,
        3,
    );
    let paged = page_escalation_alert(&fixture, &alert_path);
    let due_at_unix_ms = u64::try_from(paged.next_attempt_at_unix_ms)
        .unwrap_or_else(|error| panic!("alert due time: {error}"));
    fixture.clock.set(due_at_unix_ms.saturating_add(1));

    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    let observed = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        loop {
            let health = host.worker_health();
            if health.ticks_completed >= DELIVERY_TICKS {
                break health;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let delivered = backend.alerts();
    let remaining = outbox_rows(&alert_path);
    let readiness = host.ensure_ready();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));

    let health =
        observed.unwrap_or_else(|_| panic!("host worker did not complete {DELIVERY_TICKS} ticks"));
    assert!(
        readiness.is_ok(),
        "a delivered alert must leave the host ready: {readiness:?}"
    );
    let delivery = health
        .security_alert_delivery
        .clone()
        .unwrap_or_else(|| panic!("the host worker must report alert delivery: {health:?}"));
    assert!(
        delivery.delivered >= 1 && delivery.passes >= 1,
        "delivery health must count the delivered alert: {delivery:?}"
    );
    assert_eq!(
        (delivery.pending, delivery.parked, delivery.last_error),
        (0, 0, None)
    );
    assert_eq!(
        health.lifecycle,
        ResponseWorkerLifecycle::Ready,
        "the host worker must stay healthy while the alert is due: {health:?}"
    );
    assert!(
        delivered
            .iter()
            .any(|alert| alert.dedup_key == paged.idempotency_key),
        "production host completed {} worker ticks but its SIEM backend received {} alerts; \
         outbox rows after the ticks: {remaining:?}",
        health.ticks_completed,
        delivered.len()
    );
}

#[tokio::test]
async fn production_host_readiness_reports_an_alert_that_exhausted_siem_delivery() {
    let mut fixture = HostFixture::new();
    let alert_directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("alert tempdir: {error}"));
    let alert_path = alert_directory.path().join("unavailable-alerts.sqlite");
    let backend = Arc::new(UnavailableAlertBackend::default());
    let outbox = install_alert_outbox(
        &mut fixture,
        &alert_path,
        Arc::clone(&backend) as Arc<dyn AlertBackend>,
        EXHAUSTING_MAX_ATTEMPTS,
    );
    page_escalation_alert(&fixture, &alert_path);

    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    host.ensure_ready().unwrap_or_else(|error| {
        panic!("precondition: the host must be ready before the alert exhausts: {error}")
    });

    // The host may also be delivering. Each pass advances the trusted clock to
    // the row's next attempt, so whichever caller runs it records the attempt.
    let mut reports = Vec::new();
    for _ in 0..MAX_EXHAUSTION_PASSES {
        let row = outbox_rows(&alert_path).remove(0);
        if row.status == "parked" {
            break;
        }
        let due_at_unix_ms = u64::try_from(row.next_attempt_at_unix_ms)
            .unwrap_or_else(|error| panic!("alert due time: {error}"))
            .saturating_add(1);
        fixture.clock.set(due_at_unix_ms);
        reports.push(
            outbox
                .deliver_due(due_at_unix_ms, 1)
                .await
                .unwrap_or_else(|error| panic!("drive delivery to exhaustion: {error:?}")),
        );
    }
    let exhausted = outbox_rows(&alert_path);
    assert_eq!(
        exhausted
            .iter()
            .map(|row| (row.status.as_str(), row.attempts))
            .collect::<Vec<_>>(),
        vec![("parked", i64::from(EXHAUSTING_MAX_ATTEMPTS))],
        "precondition: the paged alert must be parked after max_attempts; reports {reports:?}"
    );
    assert_eq!(
        backend.attempts(),
        usize::try_from(EXHAUSTING_MAX_ATTEMPTS)
            .unwrap_or_else(|error| panic!("attempt count: {error}")),
        "precondition: every attempt must have reached the SIEM backend"
    );

    let reported = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        loop {
            let health = host.worker_health();
            if health
                .security_alert_delivery
                .as_ref()
                .is_some_and(|delivery| delivery.parked == 1)
            {
                break health;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let readiness = host.ensure_ready();
    let health = host.worker_health();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));

    let reported = reported
        .unwrap_or_else(|_| panic!("worker health never reported the parked alert: {health:?}"));
    assert_eq!(
        reported.lifecycle,
        ResponseWorkerLifecycle::Ready,
        "an exhausted alert must not degrade the response worker"
    );
    let Err(error) = readiness else {
        panic!(
            "production host readiness stayed Ok after its paged security alert exhausted \
             SIEM delivery; outbox rows: {exhausted:?}, backend attempts: {}, worker health: \
             {health:?}",
            backend.attempts()
        );
    };
    assert!(
        matches!(
            error,
            ProductionActiveDefenseHostError::ExhaustedSecurityAlerts { exhausted: 1 }
        ),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "security alerts that exhausted SIEM delivery: 1"
    );
}

/// SIEM backend whose dispatch never completes.
#[derive(Default)]
struct HangingAlertBackend {
    entered: AtomicBool,
}

impl AlertBackend for HangingAlertBackend {
    fn name(&self) -> &str {
        "active-defense-host-hanging"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
            Ok(())
        })
    }
}

#[tokio::test]
async fn containment_expiry_continues_while_siem_delivery_hangs() {
    let mut fixture = HostFixture::new();
    let alert_directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("alert tempdir: {error}"));
    let alert_path = alert_directory.path().join("hanging-alerts.sqlite");
    let backend = Arc::new(HangingAlertBackend::default());
    install_alert_outbox(
        &mut fixture,
        &alert_path,
        Arc::clone(&backend) as Arc<dyn AlertBackend>,
        3,
    );
    let expires_at_unix_ms = fixture.install_ttl_containment_plan();
    let paged_at_unix_ms = fixture
        .clock
        .read_now_unix_ms()
        .unwrap_or_else(|error| panic!("read fixture clock: {error}"));
    apply_escalation_plan(&fixture, paged_at_unix_ms);
    let paged = outbox_rows(&alert_path);
    assert!(
        paged
            .iter()
            .any(|row| row.status == "pending" && row.attempts == 0),
        "precondition: a due alert must be waiting for delivery: {paged:?}"
    );

    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    let hanging = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !backend.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let ticks_before_expiry = host.worker_health().ticks_completed;
    fixture.clock.set(expires_at_unix_ms.saturating_add(1));
    // A tick may lift the overlay before it completes, so also wait for a
    // completed tick after the clock moved.
    let lifted = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while fixture.has_active_overlay_contributions()
            || host.worker_health().ticks_completed <= ticks_before_expiry
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let health = host.worker_health();
    let shutdown = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, host.shutdown()).await;

    assert!(hanging.is_ok(), "delivery never reached the SIEM backend");
    assert!(
        lifted.is_ok(),
        "a hanging SIEM delivery stranded the expired containment overlay: {health:?}"
    );
    assert!(
        health.ticks_completed > ticks_before_expiry,
        "response ticks stopped while SIEM delivery hung: {health:?}"
    );
    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
    assert_eq!(
        health
            .security_alert_delivery
            .as_ref()
            .map(|delivery| delivery.passes),
        Some(0),
        "the hanging pass must still be in flight: {health:?}"
    );
    match shutdown {
        Ok(result) => result.unwrap_or_else(|error| panic!("shutdown host: {error}")),
        Err(_) => panic!("host shutdown waited on the hanging SIEM delivery"),
    }
    let record = fixture
        .security_store
        .load_plan(&ResponsePlanKey {
            tenant_id: TenantId::new("tenant-host-lifecycle")
                .unwrap_or_else(|error| panic!("tenant: {error}")),
            action_id: ActionId::new("host-lifecycle-ttl-action")
                .unwrap_or_else(|error| panic!("action: {error}")),
        })
        .unwrap_or_else(|error| panic!("load lifted response: {error}"))
        .unwrap_or_else(|| panic!("lifted response missing"));
    assert_eq!(
        decode_response_record(&record)
            .unwrap_or_else(|error| panic!("decode lifted response: {error}"))
            .state,
        ResponseState::Lifted
    );
}

mod outages;
