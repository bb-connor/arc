use chio_security_types::ports::TenantId;
use chio_test_support::clock::ClockScope;
use chio_test_support::prelude::*;
use rusqlite::Connection;
use tempfile::TempDir;

use super::*;
use crate::store_connection::test_support::{
    panic_before_commit, recovered, recovery_events_during, user_version, write_probe_user_version,
};

const DUE_AT_UNIX_MS: u64 = 1_000;
const RETRY_AT_UNIX_MS: u64 = 1_010;
const PAGERDUTY: &str = "pagerduty";
const OPSGENIE: &str = "opsgenie";
const CONFIRMED: AlertBackendOutcome = AlertBackendOutcome::Confirmed;
const REFUSED: AlertBackendOutcome = AlertBackendOutcome::Refused;
const UNCONSTRAINED_BACKEND_TABLE: &str = "CREATE TABLE chio_security_alert_outbox_backend (
    idempotency_key TEXT NOT NULL,
    backend_name TEXT NOT NULL,
    command_hash BLOB NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    delivered_at_unix_ms INTEGER
)";

struct Fixture {
    directory: TempDir,
    store: SqliteSecurityAlertOutboxStore,
    _clock: ClockScope,
}

impl Fixture {
    fn open() -> Self {
        let clock = chio_test_support::clock::scope_unix_secs(1_700_000_000);
        let directory = chio_test_support::private_tempdir().test_unwrap();
        let store = SqliteSecurityAlertOutboxStore::open(directory.path().join("alerts.sqlite"))
            .test_unwrap();
        Self {
            directory,
            store,
            _clock: clock,
        }
    }

    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("alerts.sqlite")
    }

    fn database(&self) -> Connection {
        Connection::open(self.path()).test_unwrap()
    }

    fn reopen(&self) -> PortResult<SqliteSecurityAlertOutboxStore> {
        SqliteSecurityAlertOutboxStore::open(self.path())
    }

    fn due_row(&self, alert: &SecurityAlert) -> DueSecurityAlert {
        let due = self.store.load_due(DUE_AT_UNIX_MS, 10).test_unwrap();
        due.into_iter()
            .find(|row| row.alert == *alert)
            .test_expect("the alert is due")
    }
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).test_unwrap()
}

fn name(value: &str) -> BackendName {
    BackendName::new(value).test_unwrap()
}

fn alert(index: u8) -> SecurityAlert {
    SecurityAlert {
        tenant_id: TenantId::new("tenant-alert-outbox").test_unwrap(),
        event_id: record(&format!("alert-event-{index:03}")),
        idempotency_key: record(&format!("alert-key-{index:03}")),
        occurred_at_unix_ms: DUE_AT_UNIX_MS,
        alert_type: record("response_rollback_partial"),
        finding_id_hash: Digest32::new([index; 32]),
        action_id_hash: Some(Digest32::new([2; 32])),
        evidence_hash: Digest32::new([3; 32]),
    }
}

fn pending(attempts: u32, next_attempt_at_unix_ms: u64) -> AlertDeliveryStatus {
    AlertDeliveryStatus::Pending {
        attempts,
        next_attempt_at_unix_ms,
    }
}

fn delivered(attempts: u32, delivered_at_unix_ms: u64) -> AlertDeliveryStatus {
    AlertDeliveryStatus::Delivered {
        attempts,
        delivered_at_unix_ms,
    }
}

fn kind<T>(result: PortResult<T>) -> PortErrorKind {
    result.test_unwrap_err().kind()
}

#[track_caller]
fn integrity<T>(result: PortResult<T>) {
    assert_eq!(kind(result), PortErrorKind::IntegrityFailure);
}

fn schema_snapshot(connection: &Connection) -> Vec<(String, String, String, Option<String>)> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .test_unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .test_unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .test_unwrap()
}

#[test]
fn admit_is_idempotent_and_refuses_a_different_command_under_the_same_key() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    assert_eq!(
        store.admit(&first).test_unwrap(),
        pending(0, DUE_AT_UNIX_MS)
    );
    assert_eq!(
        store.admit(&first).test_unwrap(),
        pending(0, DUE_AT_UNIX_MS)
    );
    assert_eq!(
        store.load_status(&first).test_unwrap(),
        Some(pending(0, DUE_AT_UNIX_MS))
    );

    let mut changed = first.clone();
    changed.evidence_hash = Digest32::new([9; 32]);
    assert_eq!(kind(store.admit(&changed)), PortErrorKind::Conflict);
    assert_eq!(kind(store.load_status(&changed)), PortErrorKind::Conflict);
    assert_eq!(store.load_status(&alert(2)).test_unwrap(), None);
}

#[test]
fn load_command_returns_the_exact_stored_alert() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    assert_eq!(
        store.load_command(&first.idempotency_key).test_unwrap(),
        Some((first, pending(0, DUE_AT_UNIX_MS)))
    );
    assert_eq!(
        store.load_command(&record("alert-key-404")).test_unwrap(),
        None
    );
}

#[test]
fn delivery_completes_only_after_every_backend_confirms() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let row = fixture.due_row(&first);
    assert_eq!(row.attempts, 0);

    store
        .record_backend_outcome(&row, &name(PAGERDUTY), CONFIRMED, DUE_AT_UNIX_MS)
        .test_unwrap();
    store
        .record_backend_outcome(&row, &name(OPSGENIE), REFUSED, DUE_AT_UNIX_MS)
        .test_unwrap();
    assert_eq!(
        store.confirmed_backends(&row).test_unwrap(),
        BTreeSet::from([name(PAGERDUTY)])
    );
    integrity(store.record_delivery(&row, &[name(PAGERDUTY), name(OPSGENIE)], DUE_AT_UNIX_MS));
    integrity(store.record_backend_outcome(&row, &name(PAGERDUTY), CONFIRMED, DUE_AT_UNIX_MS));

    store.record_failure(&row, RETRY_AT_UNIX_MS).test_unwrap();
    assert_eq!(
        store.load_status(&first).test_unwrap(),
        Some(pending(1, RETRY_AT_UNIX_MS))
    );
    integrity(store.record_failure(&row, RETRY_AT_UNIX_MS));
    assert!(store.load_due(DUE_AT_UNIX_MS, 10).test_unwrap().is_empty());

    let retry = store
        .load_due(RETRY_AT_UNIX_MS, 10)
        .test_unwrap()
        .pop()
        .test_expect("the alert is due again");
    assert_eq!(retry.attempts, 1);
    store
        .record_backend_outcome(&retry, &name(OPSGENIE), CONFIRMED, RETRY_AT_UNIX_MS)
        .test_unwrap();
    store
        .record_delivery(&retry, &[name(PAGERDUTY), name(OPSGENIE)], RETRY_AT_UNIX_MS)
        .test_unwrap();
    assert_eq!(
        store.load_status(&first).test_unwrap(),
        Some(delivered(2, RETRY_AT_UNIX_MS))
    );
    assert_eq!(
        store.load_backend_deliveries(&first).test_unwrap(),
        Some(BTreeMap::from([
            (name(OPSGENIE), delivered(2, RETRY_AT_UNIX_MS)),
            (name(PAGERDUTY), delivered(1, DUE_AT_UNIX_MS)),
        ]))
    );
}

#[test]
fn a_parked_row_is_counted_and_never_due_again() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    for index in 1..=3 {
        store.admit(&alert(index)).test_unwrap();
    }
    let due = store.load_due(DUE_AT_UNIX_MS, 10).test_unwrap();
    assert_eq!(due.len(), 3);
    store
        .record_backend_outcome(&due[0], &name(OPSGENIE), REFUSED, DUE_AT_UNIX_MS)
        .test_unwrap();
    assert_eq!(
        kind(store.record_parked(&due[0], 2)),
        PortErrorKind::InvalidData
    );
    store.record_parked(&due[0], 1).test_unwrap();
    store
        .record_failure(&due[1], RETRY_AT_UNIX_MS)
        .test_unwrap();

    assert_eq!(
        store.load_status(&due[0].alert).test_unwrap(),
        Some(AlertDeliveryStatus::Parked { attempts: 1 })
    );
    assert_eq!(
        store.load_backend_deliveries(&due[0].alert).test_unwrap(),
        Some(BTreeMap::from([(
            name(OPSGENIE),
            AlertDeliveryStatus::Parked { attempts: 1 }
        )]))
    );
    assert_eq!(
        store.backlog().test_unwrap(),
        SecurityAlertOutboxBacklog {
            pending: 2,
            parked: 1,
        }
    );
    assert_eq!(
        store
            .load_due(u64::try_from(i64::MAX).test_unwrap(), 10)
            .test_unwrap()
            .into_iter()
            .map(|row| row.alert)
            .collect::<Vec<_>>(),
        vec![due[2].alert.clone(), due[1].alert.clone()]
    );
    assert_eq!(store.load_due(RETRY_AT_UNIX_MS, 1).test_unwrap().len(), 1);
    integrity(store.record_parked(&due[0], 1));
    let unsent = store.load_due(DUE_AT_UNIX_MS, 1).test_unwrap();
    store.record_parked(&unsent[0], 0).test_unwrap();
    assert_eq!(
        store.load_status(&unsent[0].alert).test_unwrap(),
        Some(AlertDeliveryStatus::Parked { attempts: 0 })
    );
}

#[test]
fn writes_from_a_stale_due_row_refuse() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let stale = fixture.due_row(&first);
    store.record_failure(&stale, DUE_AT_UNIX_MS).test_unwrap();

    integrity(store.record_failure(&stale, RETRY_AT_UNIX_MS));
    integrity(store.record_backend_outcome(&stale, &name(PAGERDUTY), CONFIRMED, DUE_AT_UNIX_MS));
    integrity(store.record_delivery(&stale, &[], DUE_AT_UNIX_MS));
    integrity(store.record_parked(&stale, 1));
    assert_eq!(
        store.load_status(&first).test_unwrap(),
        Some(pending(1, DUE_AT_UNIX_MS))
    );
}

#[test]
fn times_beyond_the_stored_range_refuse_as_invalid_data() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let mut late = alert(1);
    late.occurred_at_unix_ms = u64::MAX;
    assert_eq!(kind(store.admit(&late)), PortErrorKind::InvalidData);
    assert_eq!(
        kind(store.load_due(u64::MAX, 1)),
        PortErrorKind::InvalidData
    );
}

#[test]
fn a_tampered_command_fails_every_read_path_as_an_integrity_failure() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let changed = fixture
        .database()
        .execute(
            "UPDATE chio_security_alert_outbox SET command_json = CAST('{}' AS BLOB)",
            [],
        )
        .test_unwrap();
    assert_eq!(changed, 1);

    integrity(store.load_due(DUE_AT_UNIX_MS, 10));
    integrity(store.load_command(&first.idempotency_key));
    assert_eq!(kind(store.load_status(&first)), PortErrorKind::Conflict);
}

#[test]
fn a_tampered_row_status_fails_every_read_path_as_an_integrity_failure() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let row = fixture.due_row(&first);
    store
        .record_backend_outcome(&row, &name(PAGERDUTY), REFUSED, DUE_AT_UNIX_MS)
        .test_unwrap();
    let database = fixture.database();
    database
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_unwrap();
    database
        .execute(
            "UPDATE chio_security_alert_outbox SET status = 'retired'",
            [],
        )
        .test_unwrap();
    database
        .execute(
            "UPDATE chio_security_alert_outbox_backend SET status = 'retired'",
            [],
        )
        .test_unwrap();

    integrity(store.load_status(&first));
    integrity(store.load_command(&first.idempotency_key));
    integrity(store.load_backend_deliveries(&first));
    integrity(store.confirmed_backends(&row));
}

#[test]
fn a_stored_backend_name_that_is_not_a_backend_name_fails_every_read_path() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let row = fixture.due_row(&first);
    store
        .record_backend_outcome(&row, &name(PAGERDUTY), CONFIRMED, DUE_AT_UNIX_MS)
        .test_unwrap();
    let changed = fixture
        .database()
        .execute(
            "UPDATE chio_security_alert_outbox_backend SET backend_name = ' pagerduty'",
            [],
        )
        .test_unwrap();
    assert_eq!(changed, 1);

    integrity(store.load_backend_deliveries(&first));
    integrity(store.confirmed_backends(&row));
}

#[test]
fn sqlite_corruption_maps_to_an_integrity_failure() {
    let corrupt = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
        None,
    );
    let busy =
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None);
    assert_eq!(
        sqlite_fault(corrupt).kind(),
        PortErrorKind::IntegrityFailure
    );
    assert_eq!(sqlite_fault(busy).kind(), PortErrorKind::Unavailable);
}

#[test]
fn a_dropped_backend_outcome_table_fails_readiness_and_reopen() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    store.admit(&alert(1)).test_unwrap();
    store.ensure_ready().test_unwrap();
    fixture
        .database()
        .execute_batch("DROP TABLE chio_security_alert_outbox_backend")
        .test_unwrap();

    integrity(store.ensure_ready());
    integrity(fixture.reopen());
}

#[test]
fn a_backend_outcome_bound_to_another_command_fails_closed() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let row = fixture.due_row(&first);
    store
        .record_backend_outcome(&row, &name(PAGERDUTY), CONFIRMED, DUE_AT_UNIX_MS)
        .test_unwrap();
    let changed = fixture
        .database()
        .execute(
            "UPDATE chio_security_alert_outbox_backend SET command_hash = ?1
             WHERE backend_name = ?2",
            rusqlite::params![[7_u8; 32].as_slice(), PAGERDUTY],
        )
        .test_unwrap();
    assert_eq!(changed, 1);

    integrity(store.confirmed_backends(&row));
    integrity(store.load_backend_deliveries(&first));
    integrity(store.record_delivery(&row, &[name(PAGERDUTY)], DUE_AT_UNIX_MS));
    assert_eq!(
        store.load_status(&first).test_unwrap(),
        Some(pending(0, DUE_AT_UNIX_MS))
    );
}

#[test]
fn duplicate_backend_records_never_confirm_a_row() {
    let duplicates = [
        [("pending", None), ("delivered", Some(1_000_i64))],
        [
            ("delivered", Some(1_000_i64)),
            ("delivered", Some(1_000_i64)),
        ],
        [("delivered", Some(1_000_i64)), ("pending", None)],
    ];
    for records in duplicates {
        let fixture = Fixture::open();
        let store = &fixture.store;
        let first = alert(1);
        store.admit(&first).test_unwrap();
        let row = fixture.due_row(&first);
        let database = fixture.database();
        database
            .execute_batch(&format!(
                "DROP TABLE chio_security_alert_outbox_backend; {UNCONSTRAINED_BACKEND_TABLE};"
            ))
            .test_unwrap();
        for (status, delivered_at) in records {
            database
                .execute(
                    "INSERT INTO chio_security_alert_outbox_backend
                     SELECT idempotency_key, ?1, command_hash, ?2, 1, ?3
                     FROM chio_security_alert_outbox WHERE idempotency_key = ?4",
                    rusqlite::params![
                        PAGERDUTY,
                        status,
                        delivered_at,
                        first.idempotency_key.as_str()
                    ],
                )
                .test_unwrap();
        }

        integrity(store.confirmed_backends(&row));
        integrity(store.record_delivery(&row, &[name(PAGERDUTY)], DUE_AT_UNIX_MS));
        integrity(store.load_backend_deliveries(&first));
        integrity(store.ensure_ready());
        assert_eq!(
            store.load_status(&first).test_unwrap(),
            Some(pending(0, DUE_AT_UNIX_MS))
        );
    }
}

#[test]
fn open_refuses_a_foreign_database_before_any_schema_change() {
    let keyed = |constraints: &str| {
        format!(
            "{}, {constraints})",
            UNCONSTRAINED_BACKEND_TABLE.trim_end_matches(')')
        )
    };
    let foreign_tables = [
        UNCONSTRAINED_BACKEND_TABLE.to_owned(),
        keyed("PRIMARY KEY (idempotency_key, backend_name)"),
        keyed(
            "PRIMARY KEY (idempotency_key, backend_name), FOREIGN KEY (idempotency_key) \
             REFERENCES chio_security_alert_outbox(idempotency_key)",
        ),
        "CREATE TABLE CHIO_SECURITY_ALERT_OUTBOX_BACKEND (idempotency_key TEXT NOT NULL)"
            .to_owned(),
    ];
    for create_sql in foreign_tables {
        let clock = chio_test_support::clock::scope_unix_secs(1_700_000_000);
        let directory = chio_test_support::private_tempdir().test_unwrap();
        let path = directory.path().join("alerts.sqlite");
        let database = Connection::open(&path).test_unwrap();
        database.execute_batch(&create_sql).test_unwrap();
        let before = schema_snapshot(&database);
        drop(database);

        integrity(SqliteSecurityAlertOutboxStore::open(&path));

        let database = Connection::open(&path).test_unwrap();
        assert_eq!(schema_snapshot(&database), before);
        let journal_mode: String = database
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(journal_mode, "delete");
        drop(clock);
    }
}

#[test]
fn reopening_keeps_the_declared_schema_and_its_records() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    let row = fixture.due_row(&first);
    store
        .record_backend_outcome(&row, &name(PAGERDUTY), CONFIRMED, DUE_AT_UNIX_MS)
        .test_unwrap();
    let before = schema_snapshot(&fixture.database());

    let reopened = fixture.reopen().test_unwrap();
    reopened.ensure_ready().test_unwrap();
    assert_eq!(schema_snapshot(&fixture.database()), before);
    assert_eq!(
        reopened.confirmed_backends(&row).test_unwrap(),
        BTreeSet::from([name(PAGERDUTY)])
    );
}

#[test]
fn due_and_status_reads_search_an_index() {
    let fixture = Fixture::open();
    let database = fixture.database();
    let plan = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Vec<String> {
        let mut statement = database
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .test_unwrap();
        let steps = statement.query_map(params, |row| row.get(3)).test_unwrap();
        steps.collect::<rusqlite::Result<_>>().test_unwrap()
    };
    assert_eq!(
        plan(SELECT_DUE, &[&1_000_i64, &10_i64]),
        ["SEARCH chio_security_alert_outbox USING INDEX idx_chio_security_alert_outbox_due (status=? AND next_attempt_at_unix_ms<?)"]
    );
    assert_eq!(
        plan(SELECT_STATUS, &[&"alert-key-001"]),
        ["SEARCH chio_security_alert_outbox USING INDEX sqlite_autoindex_chio_security_alert_outbox_1 (idempotency_key=?)"]
    );
}

#[test]
fn in_memory_paths_refuse() {
    for path in [":memory:", "file:alerts?mode=memory", ""] {
        assert_eq!(
            kind(SqliteSecurityAlertOutboxStore::open(path)),
            PortErrorKind::InvalidData
        );
    }
}

#[test]
fn the_largest_alert_encodes_to_its_bound() {
    let id = "\"".repeat(256);
    let largest = SecurityAlert {
        tenant_id: TenantId::new(id.clone()).test_unwrap(),
        event_id: record(&id),
        idempotency_key: record(&id),
        occurred_at_unix_ms: u64::MAX,
        alert_type: record(&id),
        finding_id_hash: Digest32::new([u8::MAX; 32]),
        action_id_hash: Some(Digest32::new([u8::MAX; 32])),
        evidence_hash: Digest32::new([u8::MAX; 32]),
    };
    assert_eq!(
        canonical_json_bytes(&largest).test_unwrap().len(),
        SECURITY_ALERT_MAX_CANONICAL_BYTES
    );
    assert!(TenantId::new(format!("{id}x")).is_err());
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_outbox_serves() {
    let fixture = Fixture::open();
    let store = &fixture.store;
    let first = alert(1);
    store.admit(&first).test_unwrap();
    panic_before_commit(&store.connection, |transaction| {
        write_probe_user_version(transaction);
        transaction
            .execute("UPDATE chio_security_alert_outbox SET attempts = 77", [])
            .test_unwrap();
    });

    let (status, events) = recovery_events_during(|| store.load_status(&first));
    assert_eq!(status.test_unwrap(), Some(pending(0, DUE_AT_UNIX_MS)));
    assert_eq!(events, [recovered("security_alert_outbox")]);
    assert_eq!(user_version(&fixture.database()), 0);
}
