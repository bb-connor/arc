#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chio_data_guards::{SqlDialect, SqlGuardConfig, SqlOperation, SqlQueryGuard};
use libfuzzer_sys::fuzz_target;

const MAX_QUERY_CHARS: usize = 2048;

#[derive(Arbitrary, Debug)]
struct SqlInput {
    raw_query: String,
    mode: u8,
    dialect: u8,
    table: u8,
    column: u8,
    value: u16,
}

fn trim(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

fn dialect(selector: u8) -> SqlDialect {
    match selector % 7 {
        0 => SqlDialect::Generic,
        1 => SqlDialect::Postgres,
        2 => SqlDialect::MySql,
        3 => SqlDialect::Sqlite,
        4 => SqlDialect::MsSql,
        5 => SqlDialect::Snowflake,
        _ => SqlDialect::BigQuery,
    }
}

fn pool(selector: u8, values: &[&str]) -> String {
    values[usize::from(selector) % values.len()].to_string()
}

struct GeneratedSql {
    query: String,
    operation: Option<SqlOperation>,
    table: String,
    has_where: bool,
    fail_closed: bool,
}

fn generated_query(input: &SqlInput) -> GeneratedSql {
    let table = pool(
        input.table,
        &["users", "orders", "audit_log", "tenant_events"],
    );
    let column = pool(input.column, &["id", "tenant_id", "email", "created_at"]);
    let value = input.value;

    match input.mode % 6 {
        0 => GeneratedSql {
            query: format!("SELECT {column} FROM {table} WHERE id = {value}"),
            operation: Some(SqlOperation::Select),
            table,
            has_where: true,
            fail_closed: false,
        },
        1 => GeneratedSql {
            query: format!("SELECT * FROM {table}"),
            operation: Some(SqlOperation::Select),
            table,
            has_where: false,
            fail_closed: false,
        },
        2 => GeneratedSql {
            query: format!("UPDATE {table} SET {column} = {value} WHERE id = {value}"),
            operation: Some(SqlOperation::Update),
            table,
            has_where: true,
            fail_closed: false,
        },
        3 => GeneratedSql {
            query: format!("DELETE FROM {table} WHERE id = {value}"),
            operation: Some(SqlOperation::Delete),
            table,
            has_where: true,
            fail_closed: false,
        },
        4 => GeneratedSql {
            query: format!("INSERT INTO {table} ({column}) VALUES ({value})"),
            operation: Some(SqlOperation::Insert),
            table,
            has_where: false,
            fail_closed: false,
        },
        _ => GeneratedSql {
            query: format!("SELECT {column} FROM {table}; DROP TABLE {table};"),
            operation: Some(SqlOperation::Ddl),
            table,
            has_where: false,
            fail_closed: true,
        },
    }
}

fn exercise_raw(query: &str) {
    let raw = trim(query, MAX_QUERY_CHARS);
    for dialect in [
        SqlDialect::Generic,
        SqlDialect::Postgres,
        SqlDialect::MySql,
        SqlDialect::Sqlite,
        SqlDialect::MsSql,
        SqlDialect::Snowflake,
        SqlDialect::BigQuery,
    ] {
        exercise(&raw, dialect);
    }
}

fn exercise(query: &str, dialect: SqlDialect) -> Option<chio_data_guards::sql_parser::SqlAnalysis> {
    let result = chio_data_guards::sql_parser::parse(query, dialect);
    let Ok(analysis) = result else {
        return None;
    };

    assert!(!analysis.operation.as_str().is_empty());

    let mut tables = analysis.tables.clone();
    tables.sort();
    tables.dedup();
    assert_eq!(tables.len(), analysis.tables.len());

    Some(analysis)
}

fn exercise_generated(input: SqlInput) {
    let dialect = dialect(input.dialect);
    exercise_raw(&input.raw_query);

    let generated = generated_query(&input);
    let parsed = exercise(&generated.query, dialect);

    if generated.fail_closed {
        let fail_closed_guard = SqlQueryGuard::new(SqlGuardConfig {
            dialect: SqlDialect::Generic,
            operation_allowlist: vec![SqlOperation::Select],
            table_allowlist: vec![generated.table.clone()],
            ..Default::default()
        });
        assert!(
            fail_closed_guard.analyze(&generated.query).is_err(),
            "multi-statement or DDL SQL must fail closed: {}",
            generated.query
        );
        return;
    }

    let analysis = match parsed {
        Some(analysis) => analysis,
        None => panic!("generated SQL should parse: {}", generated.query),
    };
    if let Some(expected) = generated.operation {
        assert_eq!(analysis.operation, expected);
    }
    assert!(
        analysis
            .tables
            .iter()
            .any(|table| table.eq_ignore_ascii_case(&generated.table)),
        "generated SQL should reference expected table: {}",
        generated.query
    );
    assert_eq!(analysis.has_where, generated.has_where);

    let guard = SqlQueryGuard::new(SqlGuardConfig {
        dialect: SqlDialect::Generic,
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".to_string()],
        ..Default::default()
    });
    assert!(guard.analyze("SELECT id FROM orders WHERE id = 1").is_ok());
    assert!(guard.analyze("DROP TABLE orders").is_err());
    assert!(guard.analyze("SELECT * FROM users").is_err());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        exercise_raw(raw);
    }

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = SqlInput::arbitrary(&mut unstructured) {
        exercise_generated(input);
    }
});
