use super::*;

use chio_security_types::ports::{PortError, PortResult};

const DUE_AT_UNIX_MS: u64 = 1_000;
const FIRST_RETRY_AT_UNIX_MS: u64 = 1_010;
const SECOND_RETRY_AT_UNIX_MS: u64 = 1_030;
const PARKED_AT_UNIX_MS: u64 = i64::MAX as u64;
const PAGERDUTY: &str = "pagerduty";
const OPSGENIE: &str = "opsgenie";

type AcceptPolicy = fn(usize, &str) -> bool;

fn accept_every_dispatch(_: usize, _: &str) -> bool {
    true
}

fn reject_every_dispatch(_: usize, _: &str) -> bool {
    false
}

fn reject_only_the_first_dispatch(index: usize, _: &str) -> bool {
    index > 0
}

fn reject_only_the_first_row(_: usize, dedup_key: &str) -> bool {
    dedup_key != "siem-alert-001"
}

struct ScriptedBackend {
    name: &'static str,
    accept: AcceptPolicy,
    dispatches: Mutex<Vec<(String, bool)>>,
}

impl ScriptedBackend {
    fn new(name: &'static str, accept: AcceptPolicy) -> Arc<Self> {
        Arc::new(Self {
            name,
            accept,
            dispatches: Mutex::new(Vec::new()),
        })
    }

    fn dispatches(&self) -> Vec<(String, bool)> {
        self.dispatches
            .lock()
            .unwrap_or_else(|_| panic!("dispatch log poisoned"))
            .clone()
    }

    fn accepted(&self) -> Vec<String> {
        self.dispatches()
            .into_iter()
            .filter_map(|(key, accepted)| accepted.then_some(key))
            .collect()
    }

    fn received(&self, dedup_key: &str) -> usize {
        self.dispatches()
            .iter()
            .filter(|(key, _)| key == dedup_key)
            .count()
    }
}

impl AlertBackend for ScriptedBackend {
    fn name(&self) -> &str {
        self.name
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        Box::pin(async move {
            let accepted = {
                let mut dispatches = self
                    .dispatches
                    .lock()
                    .map_err(|_| ExportError::HttpError("dispatch log unavailable".to_owned()))?;
                let accepted = (self.accept)(dispatches.len(), &alert.dedup_key);
                dispatches.push((alert.dedup_key.clone(), accepted));
                accepted
            };
            if accepted {
                Ok(())
            } else {
                Err(ExportError::HttpError(format!(
                    "{} rejected the page with 401",
                    self.name
                )))
            }
        })
    }
}

struct Fixture {
    _tempdir: TempDir,
    path: std::path::PathBuf,
    outbox: SqliteSiemOutbox,
}

fn open_outbox(path: &std::path::Path, backends: &[&Arc<ScriptedBackend>]) -> SqliteSiemOutbox {
    let outbox = SqliteSiemOutbox::open(
        path,
        backends
            .iter()
            .map(|backend| Arc::clone(backend) as Arc<dyn AlertBackend>)
            .collect(),
        AlertOutboxConfig {
            base_retry_ms: 10,
            max_retry_ms: 100,
            max_attempts: 3,
        },
    )
    .unwrap_or_else(|error| panic!("outbox: {error}"));
    outbox
        .ensure_alerts_ready()
        .unwrap_or_else(|error| panic!("outbox readiness: {error}"));
    outbox
}

impl Fixture {
    fn open(backends: &[&Arc<ScriptedBackend>]) -> Self {
        let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = tempdir.path().join("alerts.sqlite");
        let outbox = open_outbox(&path, backends);
        Self {
            _tempdir: tempdir,
            path,
            outbox,
        }
    }

    fn backend_outcomes(
        &self,
        alert: &SecurityAlert,
    ) -> Option<BTreeMap<String, AlertDeliveryStatus>> {
        self.outbox
            .load_backend_deliveries(&AlertDeliveryQuery {
                alert: alert.clone(),
            })
            .unwrap_or_else(|error| panic!("load backend deliveries: {error}"))
    }

    fn database(&self) -> Connection {
        Connection::open(&self.path).unwrap_or_else(|error| panic!("open database: {error}"))
    }

    fn page_due(&self, count: u8) -> Vec<SecurityAlert> {
        (1..=count)
            .map(|index| {
                let alert = due_alert(index);
                assert_eq!(
                    SecurityAlertPort::page(&self.outbox, &alert)
                        .unwrap_or_else(|error| panic!("enqueue: {error}")),
                    AlertDeliveryStatus::Pending {
                        attempts: 0,
                        next_attempt_at_unix_ms: DUE_AT_UNIX_MS,
                    },
                    "precondition: {} must be durably pending and due",
                    alert.idempotency_key.as_str()
                );
                alert
            })
            .collect()
    }

    fn status(&self, alert: &SecurityAlert) -> Option<AlertDeliveryStatus> {
        SecurityAlertPort::load_delivery(
            &self.outbox,
            &AlertDeliveryQuery {
                alert: alert.clone(),
            },
        )
        .unwrap_or_else(|error| panic!("load delivery: {error}"))
    }

    fn statuses(&self, alerts: &[SecurityAlert]) -> Vec<Option<AlertDeliveryStatus>> {
        alerts.iter().map(|alert| self.status(alert)).collect()
    }

    async fn deliver(&self, now_unix_ms: u64, limit: usize) -> PortResult<AlertDispatchReport> {
        self.outbox.deliver_due(now_unix_ms, limit).await
    }
}

fn due_alert(index: u8) -> SecurityAlert {
    let mut alert = security_alert();
    alert.event_id = record(&format!("siem-event-{index:03}"));
    alert.idempotency_key = record(&format!("siem-alert-{index:03}"));
    alert.finding_id_hash = digest(index.saturating_add(100));
    alert
}

fn keys(alerts: &[SecurityAlert]) -> Vec<String> {
    alerts
        .iter()
        .map(|alert| alert.idempotency_key.as_str().to_owned())
        .collect()
}

#[track_caller]
fn report(result: PortResult<AlertDispatchReport>, context: &str) -> AlertDispatchReport {
    result.unwrap_or_else(|error: PortError| panic!("{context}: {error:?}"))
}

fn dispatch_report(
    [attempted, delivered, failed, parked, backend_dispatches, backend_failures]: [usize; 6],
) -> AlertDispatchReport {
    AlertDispatchReport {
        attempted,
        delivered,
        failed,
        parked,
        backend_dispatches,
        backend_failures,
    }
}

fn delivered(attempts: u32, delivered_at_unix_ms: u64) -> AlertDeliveryStatus {
    AlertDeliveryStatus::Delivered {
        attempts,
        delivered_at_unix_ms,
    }
}

fn pending(attempts: u32, next_attempt_at_unix_ms: u64) -> AlertDeliveryStatus {
    AlertDeliveryStatus::Pending {
        attempts,
        next_attempt_at_unix_ms,
    }
}

fn outcomes(
    entries: [(&str, AlertDeliveryStatus); 2],
) -> Option<BTreeMap<String, AlertDeliveryStatus>> {
    Some(
        entries
            .into_iter()
            .map(|(backend, status)| (backend.to_owned(), status))
            .collect(),
    )
}

#[tokio::test]
async fn healthy_backend_receives_every_due_row_in_one_call_while_another_backend_fails() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(3);

    let result = fixture.deliver(DUE_AT_UNIX_MS, 10).await;

    assert_eq!(
        opsgenie.received("siem-alert-001"),
        1,
        "precondition: delivery must reach the failing backend; deliver_due returned {result:?}"
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(AlertDeliveryStatus::Pending {
            attempts: 1,
            next_attempt_at_unix_ms: FIRST_RETRY_AT_UNIX_MS,
        }),
        "precondition: the first row's failed attempt must be durably rescheduled"
    );
    assert_eq!(
        pagerduty.accepted(),
        keys(&alerts),
        "one deliver_due call with limit 10 must page every due row on the healthy backend \
         while {OPSGENIE} fails; deliver_due returned {result:?}, {OPSGENIE} saw {:?}, \
         rows are now {:?}",
        opsgenie.dispatches(),
        fixture.statuses(&alerts)
    );
    assert_eq!(
        report(result, "partial delivery"),
        dispatch_report([3, 0, 3, 0, 6, 3])
    );
    for alert in &alerts {
        assert_eq!(
            fixture.status(alert),
            Some(pending(1, FIRST_RETRY_AT_UNIX_MS)),
            "a row {OPSGENIE} has not confirmed must not be reported delivered"
        );
        assert_eq!(
            fixture.backend_outcomes(alert),
            outcomes([
                (PAGERDUTY, delivered(1, DUE_AT_UNIX_MS)),
                (OPSGENIE, pending(1, FIRST_RETRY_AT_UNIX_MS)),
            ])
        );
    }
}

#[tokio::test]
async fn retry_pages_only_the_backend_that_has_not_confirmed_the_row() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_only_the_first_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(1);
    let key = alerts[0].idempotency_key.as_str();

    let first = fixture.deliver(DUE_AT_UNIX_MS, 1).await;
    assert_eq!(
        (pagerduty.accepted(), opsgenie.dispatches()),
        (vec![key.to_owned()], vec![(key.to_owned(), false)]),
        "precondition: the first attempt must reach both backends; deliver_due returned {first:?}"
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(AlertDeliveryStatus::Pending {
            attempts: 1,
            next_attempt_at_unix_ms: FIRST_RETRY_AT_UNIX_MS,
        }),
        "precondition: the row must stay pending for the backend that failed"
    );

    let second = report(
        fixture.deliver(FIRST_RETRY_AT_UNIX_MS, 1).await,
        "retry delivery",
    );
    assert_eq!(second, dispatch_report([1, 1, 0, 0, 1, 0]));
    assert_eq!(
        opsgenie.dispatches(),
        vec![(key.to_owned(), false), (key.to_owned(), true)],
        "precondition: the retry must reach the backend that failed"
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(AlertDeliveryStatus::Delivered {
            attempts: 2,
            delivered_at_unix_ms: FIRST_RETRY_AT_UNIX_MS,
        })
    );
    assert_eq!(
        pagerduty.received(key),
        1,
        "{PAGERDUTY} confirmed {key} on the first attempt and must not be paged again when the \
         row is retried for {OPSGENIE}; it saw {:?}",
        pagerduty.dispatches()
    );
    assert_eq!(
        report(first, "first delivery"),
        dispatch_report([1, 0, 1, 0, 2, 1])
    );
    assert_eq!(
        fixture.backend_outcomes(&alerts[0]),
        outcomes([
            (PAGERDUTY, delivered(1, DUE_AT_UNIX_MS)),
            (OPSGENIE, delivered(2, FIRST_RETRY_AT_UNIX_MS)),
        ])
    );
}

#[tokio::test]
async fn a_row_rejected_by_a_backend_does_not_stop_the_rest_of_the_batch() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, reject_only_the_first_row);
    let fixture = Fixture::open(&[&pagerduty]);
    let alerts = fixture.page_due(3);

    let result = fixture.deliver(DUE_AT_UNIX_MS, 10).await;

    assert_eq!(
        pagerduty.dispatches().first(),
        Some(&("siem-alert-001".to_owned(), false)),
        "precondition: the backend must reject the first row; deliver_due returned {result:?}"
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(AlertDeliveryStatus::Pending {
            attempts: 1,
            next_attempt_at_unix_ms: FIRST_RETRY_AT_UNIX_MS,
        }),
        "precondition: the rejected row must be durably rescheduled"
    );
    assert_eq!(
        fixture.statuses(&alerts[1..]),
        vec![
            Some(AlertDeliveryStatus::Delivered {
                attempts: 1,
                delivered_at_unix_ms: DUE_AT_UNIX_MS,
            });
            2
        ],
        "rows after the rejected row must still be delivered by the same bounded call; \
         deliver_due returned {result:?}, the backend saw {:?}",
        pagerduty.dispatches()
    );
    assert_eq!(
        report(result, "batch delivery"),
        dispatch_report([3, 2, 1, 0, 3, 1])
    );
}

#[tokio::test]
async fn every_healthy_backend_receives_each_row_once() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, accept_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(3);

    let first = report(
        fixture.deliver(DUE_AT_UNIX_MS, 10).await,
        "healthy delivery",
    );
    assert_eq!(first, dispatch_report([3, 3, 0, 0, 6, 0]));
    assert_eq!(pagerduty.accepted(), keys(&alerts));
    assert_eq!(opsgenie.accepted(), keys(&alerts));
    assert_eq!(
        fixture.statuses(&alerts),
        vec![
            Some(AlertDeliveryStatus::Delivered {
                attempts: 1,
                delivered_at_unix_ms: DUE_AT_UNIX_MS,
            });
            3
        ]
    );
    for alert in &alerts {
        assert_eq!(
            fixture.backend_outcomes(alert),
            outcomes([
                (PAGERDUTY, delivered(1, DUE_AT_UNIX_MS)),
                (OPSGENIE, delivered(1, DUE_AT_UNIX_MS)),
            ])
        );
    }

    let later = report(
        fixture.deliver(DUE_AT_UNIX_MS + 60_000, 10).await,
        "nothing due",
    );
    assert_eq!(later, AlertDispatchReport::default());
    assert_eq!(pagerduty.dispatches().len(), 3);
    assert_eq!(opsgenie.dispatches().len(), 3);
}

#[tokio::test]
async fn when_every_backend_fails_backoff_and_parking_are_unchanged() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, reject_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(1);
    let expected = [
        (DUE_AT_UNIX_MS, 1, FIRST_RETRY_AT_UNIX_MS),
        (FIRST_RETRY_AT_UNIX_MS, 2, SECOND_RETRY_AT_UNIX_MS),
        (SECOND_RETRY_AT_UNIX_MS, 3, PARKED_AT_UNIX_MS),
    ];
    for (now_unix_ms, attempts, next_attempt_at_unix_ms) in expected {
        let early = report(
            fixture.deliver(now_unix_ms - 1, 10).await,
            "row not yet due",
        );
        assert_eq!(early, AlertDispatchReport::default());

        assert_eq!(
            report(fixture.deliver(now_unix_ms, 10).await, "failed delivery"),
            AlertDispatchReport {
                attempted: 1,
                delivered: 0,
                failed: 1,
                parked: usize::from(next_attempt_at_unix_ms == PARKED_AT_UNIX_MS),
                backend_dispatches: 2,
                backend_failures: 2,
            },
            "a row no backend accepted must not be reported delivered"
        );
        assert_eq!(
            fixture.status(&alerts[0]),
            Some(AlertDeliveryStatus::Pending {
                attempts,
                next_attempt_at_unix_ms,
            })
        );
        let dispatched = usize::try_from(attempts).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(pagerduty.dispatches().len(), dispatched);
        assert_eq!(opsgenie.dispatches().len(), dispatched);
    }

    let parked = report(
        fixture.deliver(PARKED_AT_UNIX_MS, 10).await,
        "parked row is not due",
    );
    assert_eq!(parked, AlertDispatchReport::default());
    assert_eq!(pagerduty.dispatches().len(), 3);
    assert_eq!(opsgenie.dispatches().len(), 3);
    assert_eq!(
        fixture.backend_outcomes(&alerts[0]),
        outcomes([
            (PAGERDUTY, pending(3, PARKED_AT_UNIX_MS)),
            (OPSGENIE, pending(3, PARKED_AT_UNIX_MS)),
        ])
    );
}

#[tokio::test]
async fn a_call_handles_at_most_limit_rows_and_one_dispatch_per_unconfirmed_backend() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(3);

    assert_eq!(
        report(fixture.deliver(DUE_AT_UNIX_MS, 2).await, "bounded delivery"),
        dispatch_report([2, 0, 2, 0, 4, 2])
    );
    assert_eq!(pagerduty.accepted(), keys(&alerts[..2]));
    assert_eq!(opsgenie.dispatches().len(), 2);
    assert_eq!(
        fixture.status(&alerts[2]),
        Some(pending(0, DUE_AT_UNIX_MS)),
        "a row beyond the limit must stay untouched and due"
    );
    assert_eq!(fixture.backend_outcomes(&alerts[2]), Some(BTreeMap::new()));

    assert_eq!(
        report(fixture.deliver(DUE_AT_UNIX_MS, 2).await, "remaining row"),
        dispatch_report([1, 0, 1, 0, 2, 1])
    );
    assert_eq!(pagerduty.accepted(), keys(&alerts));

    assert_eq!(
        report(
            fixture.deliver(FIRST_RETRY_AT_UNIX_MS, 10).await,
            "retry delivery"
        ),
        dispatch_report([3, 0, 3, 0, 3, 3]),
        "a retry must dispatch only to the backend that has not confirmed each row"
    );
    assert_eq!(pagerduty.dispatches().len(), 3);
    assert_eq!(opsgenie.dispatches().len(), 6);
}

#[tokio::test]
async fn exhaustion_parks_the_row_with_each_backend_outcome_visible() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(1);
    let attempts = [
        (DUE_AT_UNIX_MS, dispatch_report([1, 0, 1, 0, 2, 1])),
        (FIRST_RETRY_AT_UNIX_MS, dispatch_report([1, 0, 1, 0, 1, 1])),
        (SECOND_RETRY_AT_UNIX_MS, dispatch_report([1, 0, 1, 1, 1, 1])),
    ];
    for (now_unix_ms, expected) in attempts {
        assert_eq!(
            report(fixture.deliver(now_unix_ms, 10).await, "failing delivery"),
            expected
        );
    }

    assert_eq!(
        fixture.status(&alerts[0]),
        Some(pending(3, PARKED_AT_UNIX_MS))
    );
    assert_eq!(
        fixture.backend_outcomes(&alerts[0]),
        outcomes([
            (PAGERDUTY, delivered(1, DUE_AT_UNIX_MS)),
            (OPSGENIE, pending(3, PARKED_AT_UNIX_MS)),
        ])
    );
    assert_eq!(
        report(
            fixture.deliver(PARKED_AT_UNIX_MS, 10).await,
            "parked row is not due"
        ),
        AlertDispatchReport::default()
    );
    assert_eq!(pagerduty.dispatches().len(), 1);
    assert_eq!(opsgenie.dispatches().len(), 3);
}

#[tokio::test]
async fn readiness_requires_the_backend_outcome_table_and_reopening_restores_it() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty]);
    let alerts = fixture.page_due(1);
    fixture
        .database()
        .execute_batch("DROP TABLE chio_security_alert_outbox_backend")
        .unwrap_or_else(|error| panic!("drop backend outcome table: {error}"));

    let error = rejection(
        fixture.outbox.ensure_alerts_ready(),
        "readiness must fail closed without the backend outcome table",
    );
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    let error = rejection(
        fixture.deliver(DUE_AT_UNIX_MS, 10).await,
        "delivery must fail closed without the backend outcome table",
    );
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert_eq!(pagerduty.dispatches().len(), 0);

    let reopened = open_outbox(&fixture.path, &[&pagerduty]);
    assert_eq!(
        report(reopened.deliver_due(DUE_AT_UNIX_MS, 10).await, "reopened"),
        dispatch_report([1, 1, 0, 0, 1, 0])
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(delivered(1, DUE_AT_UNIX_MS))
    );
}

#[tokio::test]
async fn a_backend_outcome_bound_to_another_command_fails_closed() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_every_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(1);
    assert_eq!(
        report(
            fixture.deliver(DUE_AT_UNIX_MS, 10).await,
            "partial delivery"
        ),
        dispatch_report([1, 0, 1, 0, 2, 1])
    );
    let changed = fixture
        .database()
        .execute(
            "UPDATE chio_security_alert_outbox_backend SET command_hash = ?1
             WHERE backend_name = ?2",
            rusqlite::params![[7_u8; 32].as_slice(), PAGERDUTY],
        )
        .unwrap_or_else(|error| panic!("rebind backend outcome: {error}"));
    assert_eq!(changed, 1);

    let error = rejection(
        fixture.deliver(FIRST_RETRY_AT_UNIX_MS, 10).await,
        "a rebound backend outcome must not count as a confirmation",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    let error = rejection(
        fixture.outbox.load_backend_deliveries(&AlertDeliveryQuery {
            alert: alerts[0].clone(),
        }),
        "a rebound backend outcome must not be reported",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(
        (pagerduty.dispatches().len(), opsgenie.dispatches().len()),
        (1, 1)
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(pending(1, FIRST_RETRY_AT_UNIX_MS))
    );
}

const FOREIGN_BACKEND_COLUMNS: &str = "idempotency_key TEXT NOT NULL,
    backend_name TEXT NOT NULL,
    command_hash BLOB NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    delivered_at_unix_ms INTEGER";

type SchemaEntry = (String, String, String, Option<String>);

fn schema_snapshot(connection: &Connection) -> Vec<SchemaEntry> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap_or_else(|error| panic!("prepare schema snapshot: {error}"));
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("query schema snapshot: {error}"))
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap_or_else(|error| panic!("read schema snapshot: {error}"))
}

fn backend_table_shape(connection: &Connection) -> (Vec<String>, Vec<String>, i64) {
    let names = |sql: &str| -> Vec<String> {
        let mut statement = connection
            .prepare(sql)
            .unwrap_or_else(|error| panic!("prepare table info: {error}"));
        statement
            .query_map([], |row| row.get(0))
            .unwrap_or_else(|error| panic!("query table info: {error}"))
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap_or_else(|error| panic!("read table info: {error}"))
    };
    let columns = names(
        "SELECT name FROM pragma_table_info('chio_security_alert_outbox_backend') ORDER BY cid",
    );
    let primary_key = names(
        "SELECT name FROM pragma_table_info('chio_security_alert_outbox_backend')
         WHERE pk > 0 ORDER BY pk",
    );
    let foreign_keys = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('chio_security_alert_outbox_backend')",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read foreign keys: {error}"));
    (columns, primary_key, foreign_keys)
}

fn backend_columns() -> Vec<String> {
    [
        "idempotency_key",
        "backend_name",
        "command_hash",
        "status",
        "attempts",
        "delivered_at_unix_ms",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn open_refuses_a_foreign_backend_outcome_table_before_any_schema_change() {
    let key = vec!["idempotency_key".to_owned(), "backend_name".to_owned()];
    let foreign_tables = [
        (
            "no composite key and no foreign key",
            format!("CREATE TABLE chio_security_alert_outbox_backend ({FOREIGN_BACKEND_COLUMNS})"),
            Vec::new(),
            0,
        ),
        (
            "composite key without the foreign key",
            format!(
                "CREATE TABLE chio_security_alert_outbox_backend ({FOREIGN_BACKEND_COLUMNS},
                 PRIMARY KEY (idempotency_key, backend_name))"
            ),
            key.clone(),
            0,
        ),
        (
            "composite key and foreign key without the value checks",
            format!(
                "CREATE TABLE chio_security_alert_outbox_backend ({FOREIGN_BACKEND_COLUMNS},
                 PRIMARY KEY (idempotency_key, backend_name),
                 FOREIGN KEY (idempotency_key)
                    REFERENCES chio_security_alert_outbox(idempotency_key))"
            ),
            key,
            1,
        ),
        (
            "upper-case name with no composite key",
            format!("CREATE TABLE CHIO_SECURITY_ALERT_OUTBOX_BACKEND ({FOREIGN_BACKEND_COLUMNS})"),
            Vec::new(),
            0,
        ),
    ];
    for (label, create_sql, primary_key, foreign_keys) in foreign_tables {
        let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = tempdir.path().join("alerts.sqlite");
        let database =
            Connection::open(&path).unwrap_or_else(|error| panic!("open database: {error}"));
        database
            .execute_batch(&create_sql)
            .unwrap_or_else(|error| panic!("create {label} table: {error}"));
        assert_eq!(
            backend_table_shape(&database),
            (backend_columns(), primary_key, foreign_keys),
            "precondition: the {label} table must exist with the declared columns"
        );
        let before = schema_snapshot(&database);
        drop(database);

        let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
        let opened = SqliteSiemOutbox::open(
            &path,
            vec![pagerduty as Arc<dyn AlertBackend>],
            AlertOutboxConfig {
                base_retry_ms: 10,
                max_retry_ms: 100,
                max_attempts: 3,
            },
        );
        let error = match opened {
            Ok(outbox) => panic!(
                "open accepted a foreign backend outcome table with {label}; readiness then \
                 returned {:?}",
                outbox.ensure_alerts_ready()
            ),
            Err(error) => error,
        };
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{label}");

        let database =
            Connection::open(&path).unwrap_or_else(|error| panic!("reopen database: {error}"));
        assert_eq!(
            schema_snapshot(&database),
            before,
            "a refused open must not change the schema ({label})"
        );
        let journal_mode: String = database
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("journal mode: {error}"));
        assert_eq!(journal_mode, "delete", "{label}");
    }
}

#[tokio::test]
async fn duplicate_backend_records_never_confirm_a_row() {
    let duplicates = [
        (
            "pending then delivered",
            [("pending", None), ("delivered", Some(1_000_i64))],
        ),
        (
            "delivered twice",
            [
                ("delivered", Some(1_000_i64)),
                ("delivered", Some(1_000_i64)),
            ],
        ),
        (
            "delivered then pending",
            [("delivered", Some(1_000_i64)), ("pending", None)],
        ),
    ];
    for (label, records) in duplicates {
        let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
        let fixture = Fixture::open(&[&pagerduty]);
        let alerts = fixture.page_due(1);
        let key = alerts[0].idempotency_key.as_str();
        let database = fixture.database();
        database
            .execute_batch(&format!(
                "DROP TABLE chio_security_alert_outbox_backend;
                 CREATE TABLE chio_security_alert_outbox_backend ({FOREIGN_BACKEND_COLUMNS});"
            ))
            .unwrap_or_else(|error| panic!("replace backend outcome table: {error}"));
        for (status, delivered_at) in records {
            database
                .execute(
                    "INSERT INTO chio_security_alert_outbox_backend
                     SELECT idempotency_key, ?1, command_hash, ?2, 1, ?3
                     FROM chio_security_alert_outbox WHERE idempotency_key = ?4",
                    rusqlite::params![PAGERDUTY, status, delivered_at, key],
                )
                .unwrap_or_else(|error| panic!("insert {status} record: {error}"));
        }
        let stored: Vec<String> = {
            let mut statement = database
                .prepare(
                    "SELECT backend.status
                     FROM chio_security_alert_outbox_backend AS backend
                     JOIN chio_security_alert_outbox AS alert
                       ON alert.idempotency_key = backend.idempotency_key
                      AND alert.command_hash = backend.command_hash
                     WHERE backend.idempotency_key = ?1 AND backend.backend_name = ?2
                     ORDER BY backend.rowid",
                )
                .unwrap_or_else(|error| panic!("prepare duplicate scan: {error}"));
            statement
                .query_map(rusqlite::params![key, PAGERDUTY], |row| row.get(0))
                .unwrap_or_else(|error| panic!("scan duplicates: {error}"))
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap_or_else(|error| panic!("read duplicates: {error}"))
        };
        assert_eq!(
            stored,
            records.map(|(status, _)| status.to_owned()).to_vec(),
            "precondition: both {PAGERDUTY} records ({label}) must bind the exact paged command"
        );
        assert_eq!(
            fixture.status(&alerts[0]),
            Some(pending(0, DUE_AT_UNIX_MS)),
            "precondition: the row must be pending and due ({label})"
        );

        let result = fixture.deliver(DUE_AT_UNIX_MS, 10).await;
        assert_eq!(
            fixture.status(&alerts[0]),
            Some(pending(0, DUE_AT_UNIX_MS)),
            "duplicate {PAGERDUTY} records ({label}) must never confirm the row; deliver_due \
             returned {result:?} after {} dispatches",
            pagerduty.dispatches().len()
        );
        assert_eq!(pagerduty.dispatches().len(), 0, "{label}");
        let error = rejection(result, "duplicate backend records must fail closed");
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{label}");
        let error = rejection(
            fixture.outbox.load_backend_deliveries(&AlertDeliveryQuery {
                alert: alerts[0].clone(),
            }),
            "duplicate backend records must not be reported as one outcome",
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{label}");
        let error = rejection(
            fixture.outbox.ensure_alerts_ready(),
            "readiness must refuse the replaced backend outcome table",
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{label}");
    }
}

#[tokio::test]
async fn reopening_accepts_the_exact_backend_outcome_table_with_its_records() {
    let pagerduty = ScriptedBackend::new(PAGERDUTY, accept_every_dispatch);
    let opsgenie = ScriptedBackend::new(OPSGENIE, reject_only_the_first_dispatch);
    let fixture = Fixture::open(&[&pagerduty, &opsgenie]);
    let alerts = fixture.page_due(1);
    assert_eq!(
        report(
            fixture.deliver(DUE_AT_UNIX_MS, 10).await,
            "partial delivery"
        ),
        dispatch_report([1, 0, 1, 0, 2, 1])
    );
    let database = fixture.database();
    assert_eq!(
        backend_table_shape(&database),
        (
            backend_columns(),
            vec!["idempotency_key".to_owned(), "backend_name".to_owned()],
            1
        ),
        "precondition: the declared table must hold its composite key and foreign key"
    );
    let before = schema_snapshot(&database);

    let reopened = open_outbox(&fixture.path, &[&pagerduty, &opsgenie]);
    assert_eq!(
        schema_snapshot(&database),
        before,
        "reopening must keep the declared schema unchanged"
    );
    assert_eq!(
        report(
            reopened.deliver_due(FIRST_RETRY_AT_UNIX_MS, 10).await,
            "retry after reopen"
        ),
        dispatch_report([1, 1, 0, 0, 1, 0])
    );
    assert_eq!(
        (pagerduty.dispatches().len(), opsgenie.dispatches().len()),
        (1, 2)
    );
    assert_eq!(
        fixture.status(&alerts[0]),
        Some(delivered(2, FIRST_RETRY_AT_UNIX_MS))
    );
}
