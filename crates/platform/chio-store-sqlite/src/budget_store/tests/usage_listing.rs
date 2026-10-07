use super::store::{LIST_ALL_USAGES_SQL, LIST_CAPABILITY_USAGES_SQL};
use super::*;

#[path = "support.rs"]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    dead_code,
    reason = "Shared fixtures fail on violated setup invariants; this module uses only the usage-anchor helpers."
)]
mod support;
use support::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn query_plan(
    connection: &rusqlite::Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Vec<String>, rusqlite::Error> {
    connection
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?
        .query_map(parameters, |row| row.get::<_, String>(3))?
        .collect()
}

#[test]
fn a_capability_usage_listing_searches_the_primary_key() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteBudgetStore::open(directory.path().join("budget.db"))?;
    let connection = store.connection()?;

    let capability = query_plan(&connection, LIST_CAPABILITY_USAGES_SQL, ["cap-a"])?;
    assert!(
        capability.iter().any(|detail| {
            detail.starts_with("SEARCH capability_grant_budgets USING")
                && detail.contains("(capability_id=?)")
        }),
        "{capability:?}"
    );
    assert!(
        !capability
            .iter()
            .any(|detail| detail.starts_with("SCAN capability_grant_budgets")),
        "{capability:?}"
    );

    let all = query_plan(&connection, LIST_ALL_USAGES_SQL, [])?;
    assert!(!all.is_empty(), "{all:?}");
    Ok(())
}

#[test]
fn a_capability_usage_listing_returns_that_capability_in_listing_order() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteBudgetStore::open(directory.path().join("budget.db"))?;
    install_usage_anchors(
        &store,
        &[
            usage_record("cap-a", 0, 1, 10, 1, 0, 0),
            usage_record("cap-a", 1, 1, 30, 2, 0, 0),
            usage_record("cap-a", 2, 1, 30, 3, 0, 0),
            usage_record("cap-b", 0, 1, 20, 4, 0, 0),
        ],
    );

    let expected = store
        .list_all_usages()?
        .into_iter()
        .filter(|record| record.capability_id == "cap-a")
        .collect::<Vec<_>>();
    let listed = store.list_all_usages_for_capability("cap-a")?;
    assert_eq!(listed, expected);
    assert_eq!(
        listed
            .iter()
            .map(|record| (record.grant_index, record.updated_at))
            .collect::<Vec<_>>(),
        [(1, 30), (2, 30), (0, 10)]
    );
    assert!(store.list_all_usages_for_capability("cap-c")?.is_empty());
    Ok(())
}
