use super::*;

#[test]
fn capability_usage_listing_searches_the_primary_key() {
    let (_path_dir, path) = temp_sqlite_path("chio-budget-usage-plan");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let connection = store.connection().unwrap();
    let mut plan = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {LIST_CAPABILITY_USAGES_SQL}"))
        .unwrap();
    let details = plan
        .query_map(params!["cap-plan"], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    drop(plan);
    drop(connection);

    assert!(
        details.iter().all(|detail| !detail.starts_with("SCAN")),
        "{details:?}"
    );
    assert!(
        details.iter().any(|detail| detail.starts_with("SEARCH")
            && detail.contains("sqlite_autoindex_capability_grant_budgets_1")),
        "{details:?}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn budget_usage_query_rejects_negative_persisted_counter() {
    let (_path_dir, path) = temp_sqlite_path("chio-budget-negative-usage");
    let store = SqliteBudgetStore::open(&path).unwrap();
    install_usage_anchor(&store, &usage_record("cap-negative", 0, 1, 10, 1, 0, 0));
    {
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                    UPDATE capability_grant_budgets
                    SET invocation_count = -1
                    WHERE capability_id = 'cap-negative' AND grant_index = 0
                    "#,
                [],
            )
            .unwrap();
    }

    let error = store
        .list_all_usages()
        .expect_err("negative persisted budget counters must fail closed");
    assert!(
        error
            .to_string()
            .contains("budget field `invocation_count` was negative"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}
