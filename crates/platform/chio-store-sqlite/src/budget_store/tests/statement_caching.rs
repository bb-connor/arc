use super::*;
use std::cell::RefCell;

thread_local! {
    static SQL: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn capture_sql(event: rusqlite::trace::TraceEvent<'_>) {
    if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
        SQL.with_borrow_mut(|statements| statements.push(sql.to_owned()));
    }
}

#[test]
fn hold_mutations_validate_one_snapshot_and_preserve_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for action in ["reverse", "release", "settle"] {
        let directory = tempfile::tempdir()?;
        let store = SqliteBudgetStore::open(directory.path().join("budget.db"))?;
        let owner = authority("owner", "lease", 1);
        assert!(matches!(
            store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap".into(),
                grant_index: 0,
                max_invocations: Some(2),
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: None,
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(200),
                hold_id: Some("hold".into()),
                event_id: Some("authorize".into()),
                authority: Some(owner.clone()),
            })?,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        if action == "settle" {
            store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap".into(),
                grant_index: 0,
                hold_id: "hold".into(),
                event_id: "capture".into(),
                trusted_time: None,
                authority: Some(owner.clone()),
            })?;
        }
        store.connection()?.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(capture_sql),
        );
        SQL.with_borrow_mut(Vec::clear);
        let mutate = || match action {
            "reverse" => store.reverse_charge_cost_with_ids_and_authority(
                "cap",
                0,
                100,
                Some("hold"),
                Some("finish"),
                Some(&owner),
            ),
            "release" => store.reduce_charge_cost_with_ids_and_authority(
                "cap",
                0,
                100,
                Some("hold"),
                Some("finish"),
                Some(&owner),
            ),
            _ => store.settle_charge_cost_with_ids_and_authority(
                "cap",
                0,
                100,
                40,
                Some("hold"),
                Some("finish"),
                Some(&owner),
            ),
        };
        mutate()?;
        let loads = SQL.with_borrow(|statements| {
            statements
                .iter()
                .filter(|sql| {
                    sql.contains("FROM budget_authorization_holds")
                        && sql.contains("invocation_count_debited")
                        && sql.trim_start().starts_with("SELECT")
                })
                .count()
        });
        assert_eq!(
            loads, 1,
            "{action} must reuse the hold validated inside its write transaction"
        );
        let usage = store.get_usage("cap", 0)?.ok_or("usage missing")?;
        assert_eq!(
            usage.invocation_count,
            if action == "reverse" { 0 } else { 1 }
        );
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(
            usage.total_cost_realized_spend,
            if action == "settle" { 40 } else { 0 }
        );
        mutate()?;
        assert_eq!(
            store.get_usage("cap", 0)?.ok_or("replayed usage missing")?,
            usage
        );
        store
            .connection()?
            .trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
    }
    Ok(())
}

#[test]
fn cached_budget_reads_rebind_parameters_and_observe_external_commits(
) -> Result<(), Box<dyn std::error::Error>> {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.db");
    let store = SqliteBudgetStore::open(&path)?;
    let writer = SqliteBudgetStore::open(&path)?;
    assert!(writer.try_increment("cap-a", 0, Some(3))?);
    assert!(writer.try_increment("cap-b", 0, Some(3))?);
    let compilations = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&compilations);
    store
        .connection()?
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Read {
                    table_name: "capability_grant_budgets",
                    column_name: "total_cost_exposed"
                }
            ) {
                observed.fetch_add(1, Ordering::Relaxed);
            }
            Authorization::Allow
        }))?;
    assert_eq!(
        store
            .get_usage("cap-a", 0)?
            .ok_or("cap-a missing")?
            .invocation_count,
        1
    );
    assert_eq!(
        store
            .get_usage("cap-b", 0)?
            .ok_or("cap-b missing")?
            .capability_id,
        "cap-b"
    );
    assert!(store.get_usage("absent", 0)?.is_none());
    assert!(writer.try_increment("cap-a", 0, Some(3))?);
    assert_eq!(
        store
            .get_usage("cap-a", 0)?
            .ok_or("updated cap-a missing")?
            .invocation_count,
        2
    );
    assert_eq!(
        compilations.load(Ordering::Relaxed),
        1,
        "one prepared read must serve all bindings without caching results"
    );
    Ok(())
}
