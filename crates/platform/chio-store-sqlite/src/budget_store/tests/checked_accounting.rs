use super::*;
use chio_kernel::InMemoryBudgetStore;
use chio_test_support::prelude::*;
use std::sync::{Arc, Barrier};

fn open_store(path: &Path, composite: bool) -> SqliteBudgetStore {
    if !composite {
        return SqliteBudgetStore::open(path).test_expect("store");
    }
    let locks = path.with_extension("locks");
    fs::create_dir_all(&locks).test_expect("lock directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent = path.parent().test_expect("fixture parent directory");
        for directory in [parent, locks.as_path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .test_expect("private fixture directory");
        }
    }
    crate::serving_owner::SqliteAuthorityStore::provision(path, &locks)
        .test_expect("provision owner");
    crate::serving_owner::SqliteAuthorityStore::open_serving(path, &locks)
        .test_expect("serving owner")
        .budget_store()
}

fn authority(store: &SqliteBudgetStore) -> Option<BudgetEventAuthority> {
    store
        .serving_owner
        .as_ref()
        .map(|owner| BudgetEventAuthority {
            authority_id: owner.fence.store_uuid.clone(),
            lease_id: owner.fence.lease_id.clone(),
            lease_epoch: owner.fence.owner_epoch,
        })
}

fn release_from(
    store: &SqliteBudgetStore,
    amount: u64,
    event: &str,
) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
    let mut request = release(amount, event);
    request.authority = authority(store);
    store.release_budget_hold(request)
}

// Reopening recomputes these proof caches from the unchanged authoritative journal.
// Immediate rollback assertions below compare every table, including these caches.
fn authoritative_state(state: DurableState) -> DurableState {
    state
        .into_iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "budget_ack_head_watermark"
                    | "budget_snapshot_coverage"
                    | "budget_origin_ack_heads"
            )
        })
        .collect()
}

fn request(exposure: u64, composite: bool) -> BudgetAuthorizeHoldRequest {
    let mut request = BudgetAuthorizeHoldRequest {
        capability_id: "checked".into(),
        grant_index: 0,
        max_invocations: composite.then_some(10),
        invocation_quotas: if composite {
            vec![BudgetInvocationQuota {
                key: BudgetQuotaKey::grant("checked", 0),
                max_invocations: 10,
            }]
        } else {
            vec![]
        },
        cumulative_approval: None,
        admission_binding: composite.then(|| BudgetAdmissionBinding {
            operation_id: "operation".into(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec!["checked".into()])
                .test_expect("revocation set"),
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: exposure,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some("hold".into()),
        event_id: Some("authorize".into()),
        authority: None,
    };
    if composite {
        request.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
            operation_id: "operation".into(),
            account_key: BudgetCumulativeApprovalAccountKey {
                authority_id: "approval-authority".into(),
                owner_id: "approval-owner".into(),
                approval_budget_id: "approval-budget".into(),
                approval_budget_epoch: 1,
                root_grant_hash: "root-grant".into(),
                delegation_root_id: None,
                root_binding_digest: None,
                currency: "USD".into(),
            },
            authority_threshold: MonetaryAmount {
                units: 100,
                currency: "USD".into(),
            },
            effective_threshold: MonetaryAmount {
                units: 100,
                currency: "USD".into(),
            },
            requested_authorized: MonetaryAmount {
                units: 10,
                currency: "USD".into(),
            },
        });
    }
    request
}

fn release(amount: u64, event: &str) -> BudgetReleaseHoldRequest {
    BudgetReleaseHoldRequest {
        capability_id: "checked".into(),
        grant_index: 0,
        released_exposure_units: amount,
        hold_id: Some("hold".into()),
        event_id: Some(event.into()),
        authority: None,
    }
}

fn capture(
    store: &dyn BudgetStore,
    authority: Option<BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "checked".into(),
            grant_index: 0,
            hold_id: "hold".into(),
            event_id: "capture".into(),
            trusted_time: None,
            authority,
        })
        .map(|_| ())
}

fn settle(
    store: &dyn BudgetStore,
    exposed: u64,
    realized: u64,
    authority: Option<BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "checked".into(),
            grant_index: 0,
            exposed_cost_units: exposed,
            realized_spend_units: realized,
            hold_id: Some("hold".into()),
            event_id: Some("settle".into()),
            authority,
        })
        .map(|_| ())
}

type DurableState = Vec<(String, Vec<Vec<rusqlite::types::Value>>)>;

fn durable_state(store: &SqliteBudgetStore) -> DurableState {
    let connection = store.connection().test_expect("connection");
    let mut tables = connection.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND (name LIKE 'budget_%' OR name = 'capability_grant_budgets') ORDER BY name").test_expect("tables");
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))
        .test_expect("names")
        .collect::<Result<Vec<_>, _>>()
        .test_expect("table names");
    names
        .into_iter()
        .map(|name| {
            let mut query = connection
                .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                .test_expect("snapshot query");
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .test_expect("snapshot rows")
                .collect::<Result<Vec<_>, _>>()
                .test_expect("snapshot");
            (name, rows)
        })
        .collect()
}

#[test]
fn refused_sql_writes_roll_back_every_budget_participant_and_reopen() {
    for composite in [false, true] {
        for (operation, table) in [
            ("release", "capability_grant_budgets"),
            ("release", "budget_authorization_holds"),
            ("reverse", "capability_grant_budgets"),
            ("reverse", "budget_authorization_holds"),
            ("settle", "capability_grant_budgets"),
            ("settle", "budget_authorization_holds"),
            ("capture", "budget_authorization_holds"),
            ("capture", "budget_invocation_quotas"),
            ("reverse", "budget_invocation_quotas"),
            ("capture", "budget_cumulative_approval_accounts"),
            ("reverse", "budget_cumulative_approval_accounts"),
        ] {
            if !composite
                && matches!(
                    table,
                    "budget_invocation_quotas" | "budget_cumulative_approval_accounts"
                )
            {
                continue;
            }
            let directory = tempfile::tempdir().test_expect("directory");
            let path = directory.path().join("budget.sqlite3");
            let store = open_store(&path, composite);
            let mut initial = request(10, composite);
            initial.authority = authority(&store);
            let decision = store
                .authorize_budget_hold(initial)
                .test_expect("authorize");
            assert!(matches!(
                decision,
                BudgetAuthorizeHoldDecision::Authorized(_)
            ));
            if operation == "settle" {
                capture(&store, authority(&store)).test_expect("capture before settlement");
            }
            let before = durable_state(&store);
            store.connection().test_expect("connection").execute_batch(&format!(
                "CREATE TEMP TRIGGER refuse_accounting BEFORE UPDATE ON {table} BEGIN SELECT RAISE(IGNORE); END;"
            )).test_expect("install write refusal");
            let result = match operation {
                "release" => release_from(&store, 4, "release").map(|_| ()),
                "reverse" => store
                    .reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: "checked".into(),
                        grant_index: 0,
                        reversed_exposure_units: 10,
                        hold_id: Some("hold".into()),
                        event_id: Some("reverse".into()),
                        authority: authority(&store),
                        expected_cumulative_approval_state: None,
                    })
                    .map(|_| ()),
                "capture" => capture(&store, authority(&store)),
                "settle" => settle(&store, 10, 7, authority(&store)),
                _ => unreachable!(),
            };
            let error = result.test_expect_err("refused write must fail");
            assert!(
                matches!(error, BudgetStoreError::Invariant(_)),
                "{operation}/{table}: {error}"
            );
            assert_eq!(durable_state(&store), before, "{operation}/{table}");
            drop(store);
            let reopened = open_store(&path, composite);
            assert_eq!(
                authoritative_state(durable_state(&reopened)),
                authoritative_state(before),
                "reopened {operation}/{table}"
            );
        }
    }
}

#[test]
fn concurrent_partial_releases_cannot_spend_the_same_exposure() {
    for composite in [false, true] {
        let directory = tempfile::tempdir().test_expect("directory");
        let path = directory.path().join("budget.sqlite3");
        let store = open_store(&path, composite);
        let mut initial = request(10, composite);
        initial.authority = authority(&store);
        store
            .authorize_budget_hold(initial)
            .test_expect("authorize");
        let other = if composite {
            store.clone()
        } else {
            SqliteBudgetStore::open(&path).test_expect("independent competing connection")
        };
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                release_from(&store, 6, "first")
            });
            let second = scope.spawn(|| {
                barrier.wait();
                release_from(&other, 6, "second")
            });
            [
                first.join().test_expect("first writer"),
                second.join().test_expect("second writer"),
            ]
        });
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(BudgetStoreError::Invariant(_))))
                .count(),
            1
        );
        drop(other);
        drop(store);
        let reopened = open_store(&path, composite);
        let usage = reopened
            .get_usage("checked", 0)
            .test_expect("usage")
            .test_expect("row");
        assert_eq!(
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend
            ),
            (1, 4, 0)
        );
        capture(&reopened, authority(&reopened)).test_expect("capture remainder");
        settle(&reopened, 4, 3, authority(&reopened)).test_expect("settle remainder");
        let usage = reopened
            .get_usage("checked", 0)
            .test_expect("usage")
            .test_expect("row");
        assert_eq!(
            (usage.total_cost_exposed, usage.total_cost_realized_spend),
            (0, 3)
        );
        let events = reopened
            .list_mutation_events(10, Some("checked"), Some(0))
            .test_expect("events");
        assert_eq!(events.len(), 4);
        assert_eq!(
            events
                .last()
                .test_expect("settlement event")
                .realized_spend_units,
            3
        );
    }
}

#[test]
fn memory_preserves_unsigned_ceiling_and_refuses_overflow_atomically() {
    let store = InMemoryBudgetStore::new();
    store
        .authorize_budget_hold(request(u64::MAX, false))
        .test_expect("full width exposure");
    store
        .release_budget_hold(release(1, "release"))
        .test_expect("partial release");
    capture(&store, None).test_expect("capture");
    settle(&store, u64::MAX - 1, u64::MAX - 2, None).test_expect("full width settlement");
    let before = store.get_usage("checked", 0).test_expect("usage");
    let events = store
        .list_mutation_events(10, Some("checked"), Some(0))
        .test_expect("events");
    let mut next = request(3, false);
    next.hold_id = Some("overflow-hold".into());
    next.event_id = Some("overflow-event".into());
    assert!(matches!(
        store.authorize_budget_hold(next),
        Err(BudgetStoreError::Overflow(_))
    ));
    assert_eq!(
        store
            .get_usage("checked", 0)
            .test_expect("usage after refusal"),
        before
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("checked"), Some(0))
            .test_expect("events after refusal"),
        events
    );
    assert_eq!(
        store
            .get_budget_hold("overflow-hold")
            .test_expect("absent hold"),
        None
    );
}

#[test]
fn sqlite_range_refusal_leaves_no_hold_usage_or_sequence() {
    let directory = tempfile::tempdir().test_expect("directory");
    let store =
        SqliteBudgetStore::open(directory.path().join("budget.sqlite3")).test_expect("store");
    let before = durable_state(&store);
    for composite in [false, true] {
        assert!(matches!(
            store.authorize_budget_hold(request(u64::MAX, composite)),
            Err(BudgetStoreError::Overflow(_))
        ));
        assert_eq!(durable_state(&store), before);
    }
}

#[test]
fn sql_hold_predicate_refuses_underflow_and_wrong_remainder_without_rust_precheck() {
    let directory = tempfile::tempdir().test_expect("directory");
    let store = open_store(&directory.path().join("budget.sqlite3"), false);
    store
        .authorize_budget_hold(request(10, false))
        .test_expect("authorize");
    let before = durable_state(&store);
    for (consumed, remaining) in [(11, 0), (4, 5)] {
        let mut connection = store.connection().test_expect("connection");
        let transaction = store
            .begin_write(&mut connection)
            .test_expect("transaction");
        // Call the SQL writer directly, bypassing the release API's amount checks.
        let error = store
            .update_hold(
                &transaction,
                "hold",
                consumed,
                remaining,
                HoldDisposition::Released,
                None,
            )
            .test_expect_err("SQL predicate refuses write");
        assert!(
            matches!(&error, BudgetStoreError::Invariant(reason)
            if reason == "budget hold compare-and-set failed"),
            "{error}"
        );
        transaction.rollback().test_expect("rollback");
    }
    assert_eq!(durable_state(&store), before);
}
