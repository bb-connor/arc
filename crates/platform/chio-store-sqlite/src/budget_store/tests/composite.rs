#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};

use super::*;
use crate::serving_owner::SqliteAuthorityStore;

fn admission(operation_id: &str, capability_id: &str) -> BudgetAdmissionBinding {
    BudgetAdmissionBinding {
        operation_id: operation_id.to_string(),
        revocation_set: CanonicalRevocationSet::canonicalize(vec![capability_id.to_string()])
            .expect("canonical revocation set"),
        authorization_artifact_digests: vec!["a".repeat(64)],
        last_observed_revocation: None,
        supplemental_verifier_id: None,
        supplemental_verifier_config_digest: None,
        supplemental_authorization_artifact_digest: None,
        supplemental_authorization_expires_at: None,
    }
}

fn quotas(capability_id: &str, maximum: u32) -> Vec<BudgetInvocationQuota> {
    let mut quotas = vec![
        BudgetInvocationQuota {
            key: BudgetQuotaKey::grant(capability_id, 0),
            max_invocations: maximum,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateCapabilityInvocation,
                owner_id: capability_id.to_string(),
                grant_index: None,
            },
            max_invocations: maximum,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateFamilyInvocation,
                owner_id: "family-a".to_string(),
                grant_index: None,
            },
            max_invocations: maximum,
        },
    ];
    quotas.sort_by(|left, right| left.key.cmp(&right.key));
    quotas
}

fn authorize_request(id: &str, exposure: u64, maximum: u32) -> BudgetAuthorizeHoldRequest {
    let capability_id = "cap-composite";
    let operation_id = format!("operation-{id}");
    BudgetAuthorizeHoldRequest {
        capability_id: capability_id.to_string(),
        grant_index: 0,
        max_invocations: Some(maximum),
        invocation_quotas: quotas(capability_id, maximum),
        cumulative_approval: None,
        admission_binding: Some(admission(&operation_id, capability_id)),
        requested_exposure_units: exposure,
        max_cost_per_invocation: Some(exposure.max(1)),
        max_total_cost_units: Some(1_000),
        hold_id: Some(format!("hold-{id}")),
        event_id: Some(format!("event-{id}-authorize")),
        authority: None,
    }
}

fn cumulative_request(id: &str) -> BudgetAuthorizeHoldRequest {
    let operation_id = format!("operation-{id}");
    let mut request = authorize_request(id, 10, 2);
    request.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
        operation_id: operation_id.clone(),
        account_key: BudgetCumulativeApprovalAccountKey {
            authority_id: "approval-authority".to_string(),
            owner_id: "approval-owner".to_string(),
            approval_budget_id: "approval-budget".to_string(),
            approval_budget_epoch: 1,
            root_grant_hash: "root-grant".to_string(),
            delegation_root_id: None,
            root_binding_digest: None,
            currency: "USD".to_string(),
        },
        authority_threshold: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        effective_threshold: MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        requested_authorized: MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
    });
    request
}

fn capture_request(id: &str) -> BudgetCaptureInvocationRequest {
    BudgetCaptureInvocationRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        hold_id: format!("hold-{id}"),
        event_id: format!("event-{id}-capture-invocation"),
        trusted_time: None,
        authority: None,
    }
}

fn cancel_captured_request(id: &str) -> BudgetCancelCapturedBeforeDispatchRequest {
    BudgetCancelCapturedBeforeDispatchRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        hold_id: format!("hold-{id}"),
        event_id: format!("event-{id}-cancel-captured"),
        authority: None,
    }
}

fn reverse_request(id: &str, exposure: u64) -> BudgetReverseHoldRequest {
    BudgetReverseHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        reversed_exposure_units: exposure,
        hold_id: Some(format!("hold-{id}")),
        event_id: Some(format!("event-{id}-reverse")),
        expected_cumulative_approval_state: None,
        authority: None,
    }
}

trait AuthorityBoundRequest {
    fn set_authority(&mut self, authority: BudgetEventAuthority);
}

macro_rules! authority_bound_request {
    ($($request:ty),+ $(,)?) => {
        $(
            impl AuthorityBoundRequest for $request {
                fn set_authority(&mut self, authority: BudgetEventAuthority) {
                    self.authority = Some(authority);
                }
            }
        )+
    };
}

authority_bound_request!(
    BudgetAuthorizeHoldRequest,
    BudgetCaptureInvocationRequest,
    BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
    BudgetReconcileHoldRequest,
    BudgetCaptureHoldRequest,
    BudgetAuthorizeCumulativeApprovalRequest,
    BudgetCancelCapturedBeforeDispatchRequest,
);

fn current_authority(store: &SqliteBudgetStore) -> BudgetEventAuthority {
    let fence = store
        .serving_owner
        .as_ref()
        .expect("provisioned serving owner")
        .fence
        .clone();
    BudgetEventAuthority {
        authority_id: fence.store_uuid,
        lease_id: fence.lease_id,
        lease_epoch: fence.owner_epoch,
    }
}

fn owned<T: AuthorityBoundRequest>(store: &SqliteBudgetStore, mut request: T) -> T {
    request.set_authority(current_authority(store));
    request
}

fn secure_create_dir_all(path: &Path, context: &'static str) {
    fs::create_dir_all(path).expect(context);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("secure directory");
    }
}

fn reopen(path: &Path) -> SqliteBudgetStore {
    secure_create_dir_all(path, "create authority root");
    let database = path.join("authority.sqlite3");
    let lock_root = path.join("locks");
    secure_create_dir_all(&lock_root, "create lock root");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    crate::test_authority::open_serving(&database, &lock_root)
        .expect("open serving authority")
        .budget_store()
}

#[test]
fn denied_candidate_does_not_claim_the_operation_authorization_slot() {
    let path = unique_db_path("chio-composite-denied-candidate");
    let store = reopen(&path);
    let mut denied = authorize_request("candidate", 10, 2);
    denied.max_cost_per_invocation = Some(1);
    let denied_decision = store
        .authorize_budget_hold(owned(&store, denied.clone()))
        .expect("deny first candidate");
    assert!(matches!(
        denied_decision,
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    assert_eq!(
        store
            .authorize_budget_hold(owned(&store, denied.clone()))
            .expect("replay denied candidate"),
        denied_decision
    );

    let mut authorized = denied.clone();
    authorized.max_cost_per_invocation = Some(10);
    authorized.hold_id = Some("hold-candidate-fallback".to_string());
    authorized.event_id = Some("event-candidate-fallback-authorize".to_string());
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorized))
            .expect("authorize fallback candidate"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let mut conflicting = denied;
    conflicting.max_cost_per_invocation = Some(10);
    conflicting.hold_id = Some("hold-candidate-conflict".to_string());
    conflicting.event_id = Some("event-candidate-conflict-authorize".to_string());
    assert!(store
        .authorize_budget_hold(owned(&store, conflicting))
        .is_err());

    drop(store);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn budget_schema_refuses_stamp_six_without_mutation() {
    let (_directory, path) =
        super::schema_contract::populated_database().expect("create populated budget database");
    let connection = Connection::open(&path).expect("open budget database");
    crate::test_schema::write_version(&connection, "budget", 6).expect("stamp budget schema");
    drop(connection);
    super::schema_contract::assert_stale_without_mutation(&path, 6)
        .expect("refuse stamp six without mutation");
}

#[test]
fn composite_authorize_capture_and_settlement_survive_response_loss_and_restart() {
    for (id, monetary_capture) in [("reconcile", false), ("capture-spend", true)] {
        let path = unique_db_path(&format!("chio-composite-{id}"));
        let request = authorize_request(id, 10, 2);
        let store = reopen(&path);
        let authorized = store
            .authorize_budget_hold(owned(&store, request.clone()))
            .expect("authorize");
        assert!(matches!(
            authorized,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        drop(store);

        let store = reopen(&path);
        super::cleanup_custody::assert_replayed_authorization(
            authorized,
            store
                .authorize_budget_hold(owned(&store, request.clone()))
                .expect("replay authorization"),
        );
        let capture_request = capture_request(id);
        let captured = store
            .capture_invocation_reservations(owned(&store, capture_request.clone()))
            .expect("capture invocation");
        let captured_decision = match &captured {
            BudgetInvocationCaptureDecision::Captured(decision) => decision.clone(),
            other => panic!("unexpected capture decision: {other:?}"),
        };
        for quota in quotas("cap-composite", 2) {
            let usage = store
                .get_invocation_quota_usage(&quota.key)
                .expect("quota usage")
                .expect("quota row");
            assert_eq!(usage.reserved_invocations, 0);
            assert_eq!(usage.captured_invocations, 1);
        }
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-composite"), Some(0))
                .expect("events")
                .len(),
            2
        );
        drop(store);

        let store = reopen(&path);
        match store
            .capture_invocation_reservations(owned(&store, capture_request))
            .expect("replay capture")
        {
            BudgetInvocationCaptureDecision::AlreadyCaptured(decision) => {
                assert_eq!(decision, captured_decision)
            }
            other => panic!("unexpected replay decision: {other:?}"),
        }
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-composite"), Some(0))
                .expect("events after replay")
                .len(),
            2
        );
        let settled = if monetary_capture {
            store
                .capture_budget_hold(owned(
                    &store,
                    BudgetCaptureHoldRequest {
                        capability_id: "cap-composite".to_string(),
                        grant_index: 0,
                        exposed_cost_units: 10,
                        realized_spend_units: 7,
                        hold_id: Some(format!("hold-{id}")),
                        event_id: Some(format!("event-{id}-capture-spend")),
                        authority: None,
                    },
                ))
                .expect("capture spend")
        } else {
            store
                .reconcile_budget_hold(owned(
                    &store,
                    BudgetReconcileHoldRequest {
                        capability_id: "cap-composite".to_string(),
                        grant_index: 0,
                        exposed_cost_units: 10,
                        realized_spend_units: 7,
                        hold_id: Some(format!("hold-{id}")),
                        event_id: Some(format!("event-{id}-reconcile")),
                        authority: None,
                    },
                ))
                .expect("reconcile")
        };
        assert_eq!(settled.realized_spend_units, 7);
        drop(store);

        let store = reopen(&path);
        let usage = store
            .get_usage("cap-composite", 0)
            .expect("usage")
            .expect("usage row");
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 7);
        let _ = fs::remove_file(path);
    }
}

#[test]
fn composite_release_and_reverse_restore_durable_reservations() {
    let path = unique_db_path("chio-composite-release-reverse");
    let store = reopen(&path);
    store
        .authorize_budget_hold(owned(&store, authorize_request("release", 10, 2)))
        .expect("authorize release");
    let released = store
        .release_budget_hold(owned(
            &store,
            BudgetReleaseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                released_exposure_units: 4,
                hold_id: Some("hold-release".to_string()),
                event_id: Some("event-release-partial".to_string()),
                authority: None,
            },
        ))
        .expect("partial release");
    assert_eq!(released.exposure_units, 4);
    drop(store);

    let store = reopen(&path);
    store
        .authorize_budget_hold(owned(&store, authorize_request("reverse", 0, 2)))
        .expect("authorize reversal");
    let reversed = store
        .reverse_budget_hold(owned(&store, reverse_request("reverse", 0)))
        .expect("reverse");
    assert_eq!(reversed.invocation_state, BudgetInvocationState::Reversed);
    drop(store);

    let store = reopen(&path);
    assert_eq!(
        store
            .reverse_budget_hold(owned(&store, reverse_request("reverse", 0)))
            .expect("replay reverse"),
        reversed
    );
    let quota = store
        .get_invocation_quota_usage(&BudgetQuotaKey::grant("cap-composite", 0))
        .expect("quota")
        .expect("quota row");
    assert_eq!(quota.reserved_invocations, 1);
    let _ = fs::remove_file(path);
}

#[test]
fn every_quota_participant_exhausts_atomically_and_maximum_is_immutable() {
    let path = unique_db_path("chio-composite-quota-exhaustion");
    let store = reopen(&path);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorize_request("quota-one", 0, 1)))
            .expect("first authorization"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorize_request("quota-two", 0, 1)))
            .expect("denied authorization"),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    for quota in quotas("cap-composite", 1) {
        let usage = store
            .get_invocation_quota_usage(&quota.key)
            .expect("quota usage")
            .expect("quota row");
        assert_eq!(usage.reserved_invocations, 1);
        assert_eq!(usage.captured_invocations, 0);
    }
    let mut changed_max = authorize_request("quota-three", 0, 2);
    changed_max.max_invocations = Some(2);
    assert!(store
        .authorize_budget_hold(owned(&store, changed_max))
        .is_err());
    assert_eq!(store.max_mutation_event_seq().expect("event head"), 2);
    let _ = fs::remove_file(path);
}

#[test]
fn zero_limit_aggregate_quota_persists_and_replays_a_durable_denial() {
    let path = unique_db_path("chio-composite-zero-limit-denial");
    let request = authorize_request("zero-limit", 0, 0);
    let store = reopen(&path);
    let denied = store
        .authorize_budget_hold(owned(&store, request.clone()))
        .expect("zero-limit quota must produce a durable decision");
    assert!(matches!(denied, BudgetAuthorizeHoldDecision::Denied(_)));
    assert_eq!(
        store
            .authorize_budget_hold(owned(&store, request.clone()))
            .expect("zero-limit denial replay"),
        denied
    );
    {
        let connection = store.connection().expect("inspect zero-limit denial");
        let (event_quotas, live_quotas, holds): (i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM budget_event_quota_members
                     WHERE event_id = 'event-zero-limit-authorize'
                       AND max_invocations = 0),
                    (SELECT COUNT(*) FROM budget_invocation_quotas),
                    (SELECT COUNT(*) FROM budget_authorization_holds)
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("zero-limit projection counts");
        assert_eq!(event_quotas, 3);
        assert_eq!(live_quotas, 0);
        assert_eq!(holds, 0);
    }
    drop(store);

    let reopened = reopen(&path);
    assert_eq!(
        reopened
            .authorize_budget_hold(owned(&reopened, request))
            .expect("zero-limit denial replay after restart"),
        denied
    );
    drop(reopened);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn budget_schema_refuses_stamp_nine_without_mutation() {
    let (_directory, path) =
        super::schema_contract::populated_database().expect("create populated budget database");
    let connection = Connection::open(&path).expect("open budget database");
    crate::test_schema::write_version(&connection, "budget", 9).expect("stamp budget schema");
    drop(connection);
    super::schema_contract::assert_stale_without_mutation(&path, 9)
        .expect("refuse stamp nine without mutation");
}

const INSERT_PAYMENT_JOURNAL_ROW: &str = r#"
INSERT INTO payment_journal (
    operation_id, journal_version, request_namespace_digest, request_id,
    capability_id, grant_index, hold_id, rail, rail_mode,
    authorization_id, transaction_id, amount_units, authorized_amount_units,
    authorization_attempt, settle_action, settle_amount_units, release_authority_kind,
    release_authority_evidence_id, release_authority_evidence_digest,
    release_authority_operation_version, currency, state,
    created_at_unix_ms, updated_at_unix_ms
) VALUES (
    ?1, 2, ?2, ?3, 'cap-journal', 0, ?4, 'rail-test', 'reversible_hold',
    ?5, NULL, 10, 10, ?12, ?6, NULL, ?7, ?8, ?9, ?10, 'USD', ?11,
    1700000000000, 1700000000001
)
"#;

const INSERT_PAYMENT_RELEASE_EVIDENCE: &str = r#"
INSERT INTO payment_release_evidence (
    operation_id, evidence_id, evidence_kind, operation_version,
    canonical_bundle, bundle_digest, created_at_unix_ms
) VALUES (?1, ?2, 'pre_dispatch_no_effect', 7, X'0102', ?3, 1700000000001)
"#;

fn populated_payment_database() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("create budget directory");
    let database = directory.path().join("budget.sqlite3");
    let store = SqliteBudgetStore::open(&database).expect("open budget store");
    for id in [
        "journal-authorized",
        "journal-released",
        "journal-cancelled",
        "journal-duplicate",
    ] {
        assert!(matches!(
            store
                .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                    capability_id: "cap-journal".to_string(),
                    grant_index: 0,
                    max_invocations: Some(8),
                    requested_exposure_units: 10,
                    max_cost_per_invocation: Some(10),
                    max_total_cost_units: Some(1_000),
                    hold_id: Some(format!("hold-{id}")),
                    event_id: Some(format!("event-{id}-authorize")),
                    authority: None,
                    invocation_quotas: Vec::new(),
                    cumulative_approval: None,
                    admission_binding: None,
                })
                .expect("seed payment journal hold"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }
    let connection = store.connection().expect("open payment journal connection");
    connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-authorized",
                "a".repeat(64),
                "request-journal-authorized",
                "hold-journal-authorized",
                "authorization-journal-authorized",
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                "authorized",
                "started",
            ],
        )
        .expect("seed authorized journal row");
    connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-released",
                "b".repeat(64),
                "request-journal-released",
                "hold-journal-released",
                "authorization-journal-released",
                "release",
                "pre_dispatch_no_effect",
                "evidence-journal-released",
                "c".repeat(64),
                7_i64,
                "settling",
                "started",
            ],
        )
        .expect("seed releasing journal row");
    connection
        .execute(
            INSERT_PAYMENT_RELEASE_EVIDENCE,
            params![
                "operation-journal-released",
                "evidence-journal-released",
                "c".repeat(64),
            ],
        )
        .expect("seed release evidence row");
    drop(connection);
    drop(store);
    (directory, database)
}

fn assert_sqlite_constraint(error: rusqlite::Error, code: i32, message: &str) {
    match error {
        rusqlite::Error::SqliteFailure(error, detail) => {
            assert_eq!(error.extended_code, code);
            assert_eq!(detail.as_deref(), Some(message));
        }
        other => panic!("unexpected payment constraint error: {other:?}"),
    }
}

#[test]
fn budget_schema_refuses_stamp_ten_without_mutating_payment_facts() {
    let (_directory, database) = populated_payment_database();
    let connection = Connection::open(&database).expect("open budget database");
    crate::test_schema::write_version(&connection, "budget", 10).expect("stamp budget schema");
    drop(connection);
    super::schema_contract::assert_stale_without_mutation(&database, 10)
        .expect("refuse stamp ten without mutation");
}

#[test]
fn payment_journal_preserves_cancellation_constraints_and_evidence_across_restart() {
    let (_directory, database) = populated_payment_database();
    let store = SqliteBudgetStore::open(&database).expect("open budget store");
    let connection = store.connection().expect("inspect payment journal");
    connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-cancelled",
                "d".repeat(64),
                "request-journal-cancelled",
                "hold-journal-cancelled",
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                "closed",
                "not_started",
            ],
        )
        .expect("close a hold before payment authorization");
    let counts: (i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM payment_journal),
                    (SELECT COUNT(*) FROM payment_release_evidence),
                    (SELECT COUNT(*) FROM pragma_foreign_key_check)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("inspect payment and evidence counts");
    assert_eq!(counts, (3, 1, 0));
    let before = super::schema_contract::snapshot(&connection).expect("snapshot payment facts");

    for (sql, message) in [
        (
            "DELETE FROM payment_journal WHERE operation_id = 'operation-journal-cancelled'",
            "payment journal is append-preserving",
        ),
        (
            "UPDATE payment_journal SET amount_units = 11
             WHERE operation_id = 'operation-journal-authorized'",
            "payment journal identity is immutable",
        ),
        (
            "UPDATE payment_journal SET authorization_attempt = 'not_started'
             WHERE operation_id = 'operation-journal-authorized'",
            "payment authorization attempt is monotone",
        ),
        (
            "UPDATE payment_release_evidence SET canonical_bundle = X'0304'
             WHERE operation_id = 'operation-journal-released'",
            "payment release evidence is immutable",
        ),
        (
            "DELETE FROM payment_release_evidence
             WHERE operation_id = 'operation-journal-released'",
            "payment release evidence is immutable",
        ),
    ] {
        assert_sqlite_constraint(
            connection
                .execute(sql, [])
                .expect_err("refuse payment fact mutation"),
            rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER,
            message,
        );
    }

    assert_sqlite_constraint(
        connection
            .execute(
                INSERT_PAYMENT_JOURNAL_ROW,
                params![
                    "operation-journal-duplicate",
                    "d".repeat(64),
                    "request-journal-cancelled",
                    "hold-journal-duplicate",
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<i64>,
                    "closed",
                    "not_started",
                ],
            )
            .expect_err("refuse duplicate request identity"),
        rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
        "UNIQUE constraint failed: payment_journal.request_namespace_digest, payment_journal.request_id",
    );
    assert_sqlite_constraint(
        connection
            .execute(
                INSERT_PAYMENT_JOURNAL_ROW,
                params![
                    "operation-journal-missing-hold",
                    "e".repeat(64),
                    "request-journal-missing-hold",
                    "hold-journal-missing",
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    None::<i64>,
                    "closed",
                    "not_started",
                ],
            )
            .expect_err("refuse journal without a hold"),
        rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
        "FOREIGN KEY constraint failed",
    );

    for (operation, evidence, code, message) in [
        (
            "operation-journal-authorized",
            "evidence-journal-released",
            rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
            "UNIQUE constraint failed: payment_release_evidence.evidence_id",
        ),
        (
            "operation-journal-released",
            "evidence-journal-duplicate",
            rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY,
            "UNIQUE constraint failed: payment_release_evidence.operation_id",
        ),
        (
            "operation-journal-missing",
            "evidence-journal-missing",
            rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
            "FOREIGN KEY constraint failed",
        ),
    ] {
        assert_sqlite_constraint(
            connection
                .execute(
                    INSERT_PAYMENT_RELEASE_EVIDENCE,
                    params![operation, evidence, "c".repeat(64)],
                )
                .expect_err("refuse unbound or duplicate release evidence"),
            code,
            message,
        );
    }
    assert_eq!(
        super::schema_contract::snapshot(&connection).expect("snapshot retained payment facts"),
        before,
    );
    drop(connection);
    drop(store);

    let reopened = SqliteBudgetStore::open(&database).expect("reopen budget store");
    let connection = reopened
        .connection()
        .expect("inspect reopened payment journal");
    assert_eq!(
        super::schema_contract::snapshot(&connection).expect("snapshot reopened payment facts"),
        before,
    );
}

#[cfg(unix)]
#[test]
fn provision_refuses_populated_standalone_budget_state() {
    let path = unique_db_path("chio-composite-standalone-quota");
    secure_create_dir_all(&path, "create standalone authority root");
    let database = path.join("authority.sqlite3");
    {
        let standalone = SqliteBudgetStore::open(&database).expect("open standalone store");
        assert!(standalone
            .try_increment("cap-composite", 0, Some(2))
            .expect("record standalone usage"));
    }
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("secure standalone database mode");
    let lock_root = path.join("locks");
    secure_create_dir_all(&lock_root, "create lock root");

    let error = SqliteAuthorityStore::provision(&database, &lock_root)
        .expect_err("populated standalone safety state must not acquire an unproven baseline");
    assert!(
        error
            .to_string()
            .contains("baseline refuses nonempty safety table `budget_mutation_events`"),
        "unexpected provisioning error: {error}"
    );
    let _ = fs::remove_dir_all(path);
}

#[test]
fn captured_hold_redundantly_persists_authority_time() {
    let path = unique_db_path("chio-composite-capture-time");
    let store = reopen(&path);
    store
        .authorize_budget_hold(owned(&store, authorize_request("capture-time", 0, 2)))
        .expect("authorize");
    store
        .capture_invocation_reservations(owned(&store, capture_request("capture-time")))
        .expect("capture");
    {
        let connection = store.connection().expect("connection");
        let (hold_time, event_time): (Option<i64>, Option<i64>) = connection
            .query_row(
                r#"
                SELECT hold.trusted_capture_time, event.trusted_time
                FROM budget_authorization_holds AS hold
                JOIN budget_mutation_events AS event ON event.hold_id = hold.hold_id
                WHERE hold.hold_id = 'hold-capture-time'
                  AND event.kind = 'capture_invocation'
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("capture time projection");
        assert!(hold_time.is_some());
        assert_eq!(hold_time, event_time);
        assert!(connection
            .execute(
                "UPDATE budget_authorization_holds SET trusted_capture_time = trusted_capture_time + 1 WHERE hold_id = 'hold-capture-time'",
                [],
            )
            .is_err());
    }
    drop(store);
    drop(reopen(&path));
    let _ = fs::remove_dir_all(path);
}

#[test]
fn cumulative_approval_attach_is_exact_idempotent_and_survives_capture() {
    let path = unique_db_path("chio-composite-cumulative");
    let request = cumulative_request("cumulative");
    let binding = request
        .admission_binding
        .clone()
        .expect("admission binding");
    let store = reopen(&path);
    let pending = store
        .authorize_budget_hold(owned(&store, request.clone()))
        .expect("pending authorization");
    let pending_usage = match pending {
        BudgetAuthorizeHoldDecision::ApprovalRequired(decision) => decision.cumulative_approval,
        other => panic!("unexpected pending decision: {other:?}"),
    };
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-cumulative")
            .expect("pending operation lookup")
            .expect("pending operation"),
        pending_usage
    );
    drop(store);

    let approval = BudgetAuthorizeCumulativeApprovalRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        operation_id: "operation-cumulative".to_string(),
        hold_id: "hold-cumulative".to_string(),
        admission_binding: binding,
        approval_set_digest: "b".repeat(64),
        event_id: "event-cumulative-approval".to_string(),
        authority: None,
    };
    let store = reopen(&path);
    let attached = store
        .authorize_cumulative_approval(owned(&store, approval.clone()))
        .expect("attach approval");
    assert!(matches!(
        attached,
        BudgetCumulativeApprovalAuthorizationDecision::Authorized(_)
    ));
    let approved_usage = match &attached {
        BudgetCumulativeApprovalAuthorizationDecision::Authorized(decision) => decision
            .cumulative_approval
            .clone()
            .expect("approved cumulative projection"),
        other => panic!("unexpected approval decision: {other:?}"),
    };
    assert!(matches!(
        store
            .authorize_cumulative_approval(owned(&store, approval.clone()))
            .expect("replay approval"),
        BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(_)
    ));
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-cumulative")
            .expect("approved operation lookup"),
        Some(approved_usage)
    );
    let mut forged = approval.clone();
    forged.capability_id = "other-capability".to_string();
    assert!(store
        .authorize_cumulative_approval(owned(&store, forged))
        .is_err());
    drop(store);

    let store = reopen(&path);
    let capture = store
        .capture_invocation_reservations(owned(&store, capture_request("cumulative")))
        .expect("capture approved invocation");
    let captured_usage = match capture {
        BudgetInvocationCaptureDecision::Captured(decision) => decision
            .cumulative_approval
            .expect("captured cumulative projection"),
        other => panic!("unexpected capture decision: {other:?}"),
    };
    drop(store);
    let store = reopen(&path);
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-cumulative")
            .expect("restarted operation lookup"),
        Some(captured_usage)
    );
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("missing-operation")
            .expect("missing operation lookup"),
        None
    );
    let account = store
        .get_cumulative_approval_account_usage(
            &request
                .cumulative_approval
                .as_ref()
                .expect("cumulative request")
                .account_key,
        )
        .expect("account usage")
        .expect("account row");
    assert_eq!(account.reserved_authorized.units, 0);
    assert_eq!(account.captured_authorized.units, 10);
    let cancellation_request = cancel_captured_request("cumulative");
    let cancelled = store
        .cancel_captured_before_dispatch(owned(&store, cancellation_request.clone()))
        .expect("cancel captured cumulative invocation");
    let cancelled_usage = match cancelled {
        BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(decision) => decision
            .cumulative_approval
            .expect("cancelled cumulative projection"),
        other => panic!("unexpected cancellation decision: {other:?}"),
    };
    assert_eq!(
        cancelled_usage.state,
        BudgetCumulativeApprovalState::ReversedBeforeDispatch
    );
    assert!(matches!(
        store
            .cancel_captured_before_dispatch(owned(&store, cancellation_request))
            .expect("replay captured cumulative cancellation"),
        BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(_)
    ));
    drop(store);
    let store = reopen(&path);
    let account = store
        .get_cumulative_approval_account_usage(
            &request
                .cumulative_approval
                .as_ref()
                .expect("cumulative request")
                .account_key,
        )
        .expect("cancelled account usage")
        .expect("cancelled account row");
    assert_eq!(account.reserved_authorized.units, 0);
    assert_eq!(account.captured_authorized.units, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn below_threshold_cumulative_operation_captures_without_attachment() {
    let path = unique_db_path("chio-composite-cumulative-below-threshold");
    let mut request = cumulative_request("below-threshold");
    request
        .cumulative_approval
        .as_mut()
        .expect("cumulative request")
        .effective_threshold
        .units = 100;
    let store = reopen(&path);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, request))
            .expect("authorize below threshold"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(matches!(
        store
            .capture_invocation_reservations(owned(&store, capture_request("below-threshold")))
            .expect("capture below threshold"),
        BudgetInvocationCaptureDecision::Captured(_)
    ));
    drop(store);

    let store = reopen(&path);
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-below-threshold")
            .expect("operation lookup")
            .expect("operation projection")
            .state,
        BudgetCumulativeApprovalState::Captured
    );
    let _ = fs::remove_dir_all(path);
}

#[test]
fn cumulative_approval_state_flip_cannot_skip_attachment() {
    let path = unique_db_path("chio-composite-cumulative-state-flip");
    let store = reopen(&path);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, cumulative_request("state-flip")))
            .expect("create pending cumulative operation"),
        BudgetAuthorizeHoldDecision::ApprovalRequired(_)
    ));
    store
        .connection()
        .expect("connection")
        .execute_batch(
            r#"
            UPDATE budget_event_cumulative_approval
            SET state_after = 'authorized'
            WHERE operation_id = 'operation-state-flip';
            UPDATE budget_cumulative_approval_operations
            SET state = 'authorized'
            WHERE operation_id = 'operation-state-flip';
            "#,
        )
        .expect("forge coordinated cumulative state");

    let error = store
        .capture_invocation_reservations(owned(&store, capture_request("state-flip")))
        .expect_err("capture must require the missing approval attachment");
    assert!(
        error.to_string().contains("invalid reservation history"),
        "unexpected error: {error}"
    );
    drop(store);

    let database = path.join("authority.sqlite3");
    let error = match crate::test_authority::open_serving(&database, path.join("locks")) {
        Ok(_) => panic!("serving must reject a cumulative approval state flip"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("cumulative approval state machine"),
        "unexpected error: {error}"
    );
    let _ = fs::remove_dir_all(path);
}

#[test]
fn serving_rejects_structured_hold_event_frontier_corruption() {
    for (id, corruption) in [
        (
            "invocation",
            "UPDATE budget_authorization_holds SET invocation_state = 'captured'",
        ),
        (
            "disposition",
            "UPDATE budget_authorization_holds SET disposition = 'released'",
        ),
    ] {
        let path = unique_db_path(&format!("chio-composite-hold-frontier-{id}"));
        let store = reopen(&path);
        store
            .authorize_budget_hold(owned(&store, authorize_request(id, 10, 2)))
            .expect("create structured hold");
        drop(store);

        let database = path.join("authority.sqlite3");
        Connection::open(&database)
            .expect("open raw database")
            .execute(corruption, [])
            .expect("corrupt structured hold frontier");
        let error = match crate::test_authority::open_serving(&database, path.join("locks")) {
            Ok(_) => panic!("serving must reject structured {id} frontier corruption"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("durable event frontier"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn serving_rejects_cumulative_operation_corruption_hidden_by_account_totals() {
    for (id, corruption) in [
        (
            "request",
            r#"
            UPDATE budget_cumulative_approval_operations
            SET requested_authorized_units = requested_authorized_units + 1;
            UPDATE budget_cumulative_approval_accounts
            SET reserved_authorized_units = reserved_authorized_units + 1;
            "#,
        ),
        (
            "frontier",
            r#"
            UPDATE budget_cumulative_approval_operations
            SET state = 'authorized', account_version = account_version + 1;
            UPDATE budget_cumulative_approval_accounts
            SET version = version + 1;
            "#,
        ),
    ] {
        let path = unique_db_path(&format!("chio-composite-cumulative-corrupt-{id}"));
        let store = reopen(&path);
        store
            .authorize_budget_hold(owned(&store, cumulative_request(id)))
            .expect("create pending cumulative operation");
        drop(store);

        let database = path.join("authority.sqlite3");
        Connection::open(&database)
            .expect("open raw database")
            .execute_batch(corruption)
            .expect("corrupt cumulative projection");
        let error = match crate::test_authority::open_serving(&database, path.join("locks")) {
            Ok(_) => panic!("serving must reject cumulative {id} corruption"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("cumulative approval operation"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn approval_vs_reversal_and_last_unit_admission_are_serialized() {
    let path = unique_db_path("chio-composite-cas-races");
    let store = reopen(&path);
    let request = cumulative_request("race");
    let binding = request.admission_binding.clone().expect("binding");
    store
        .authorize_budget_hold(owned(&store, request))
        .expect("pending authorization");
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(2));
    let approval_store = store.clone();
    let approval_barrier = barrier.clone();
    let approval = std::thread::spawn(move || {
        approval_barrier.wait();
        approval_store.authorize_cumulative_approval(owned(
            &approval_store,
            BudgetAuthorizeCumulativeApprovalRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                operation_id: "operation-race".to_string(),
                hold_id: "hold-race".to_string(),
                admission_binding: binding,
                approval_set_digest: "c".repeat(64),
                event_id: "event-race-approval".to_string(),
                authority: None,
            },
        ))
    });
    let reverse_store = store.clone();
    let reverse = std::thread::spawn(move || {
        barrier.wait();
        let mut request = reverse_request("race", 10);
        request.expected_cumulative_approval_state =
            Some(BudgetCumulativeApprovalState::PendingApproval);
        reverse_store.reverse_budget_hold(owned(&reverse_store, request))
    });
    let winners = usize::from(approval.join().expect("approval thread").is_ok())
        + usize::from(reverse.join().expect("reverse thread").is_ok());
    assert_eq!(winners, 1);
    drop(store);

    let _ = fs::remove_file(&path);

    let last_path = unique_db_path("chio-composite-last-unit-race");
    let last_unit = Arc::new(reopen(&last_path));
    last_unit
        .authorize_budget_hold(owned(&last_unit, authorize_request("last-seed", 0, 2)))
        .expect("seed reservation");
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["last-one", "last-two"]
        .into_iter()
        .map(|id| {
            let store = last_unit.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.authorize_budget_hold(owned(&store, authorize_request(id, 0, 2)))
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|thread| thread.join().expect("admission thread").expect("decision"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)))
            .count(),
        1
    );
    let _ = fs::remove_file(last_path);
}

fn supplemental_admission(
    operation_id: &str,
    capability_id: &str,
    expires_at: u64,
) -> BudgetAdmissionBinding {
    let mut binding = admission(operation_id, capability_id);
    binding.last_observed_revocation = Some(RevocationCommitMetadata {
        authority: BudgetEventAuthority {
            authority_id: "revocation-authority".to_string(),
            lease_id: "revocation-lease".to_string(),
            lease_epoch: 1,
        },
        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
        commit_index: 1,
    });
    binding.supplemental_verifier_id = Some("supplemental-verifier".to_string());
    binding.supplemental_verifier_config_digest = Some("b".repeat(64));
    binding.supplemental_authorization_artifact_digest = Some("a".repeat(64));
    binding.supplemental_authorization_expires_at = Some(expires_at);
    binding
}

fn supplemental_request(id: &str, expires_at: u64) -> BudgetAuthorizeHoldRequest {
    let capability_id = "cap-composite";
    let mut request = authorize_request(id, 10, 2);
    request.admission_binding = Some(supplemental_admission(
        &format!("operation-{id}"),
        capability_id,
        expires_at,
    ));
    request.invocation_quotas.push(BudgetInvocationQuota {
        key: BudgetQuotaKey {
            profile: BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
            owner_id: capability_id.to_string(),
            grant_index: None,
        },
        max_invocations: 2,
    });
    request
        .invocation_quotas
        .sort_by(|left, right| left.key.cmp(&right.key));
    request
}

#[test]
fn millisecond_shaped_supplemental_expiry_is_rejected() {
    let path = unique_db_path("chio-composite-supplemental-expiry-unit");
    let store = reopen(&path);

    let request = supplemental_request("ms-expiry", 1_767_225_600_000);
    let error = store
        .authorize_budget_hold(owned(&store, request))
        .expect_err("a millisecond expiry cannot be compared against a seconds clock");
    assert!(
        error.to_string().contains("not expressed in seconds"),
        "unexpected error: {error}"
    );

    // The same binding with a seconds-shaped expiry clears the unit gate and is
    // carried on to the remaining admission checks.
    let request = supplemental_request("seconds-expiry", 1_767_225_600);
    let error = store
        .authorize_budget_hold(owned(&store, request))
        .expect_err("this fixture carries no live revocation head");
    assert!(
        !error.to_string().contains("not expressed in seconds"),
        "a seconds expiry must not be rejected as a unit error: {error}"
    );

    let _ = fs::remove_dir_all(path);
}

#[path = "composite/injected_clock.rs"]
mod injected_clock;
