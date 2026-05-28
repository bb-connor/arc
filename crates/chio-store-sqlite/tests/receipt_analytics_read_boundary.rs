//! Receipt analytics read-boundary enforcement for `SqliteReceiptStore`.
//!
//! Analytics and operator report surfaces require explicit admin read
//! authority. Tenant-scoped contexts must not reach these aggregations until
//! tenant-filtered reporting is implemented.

use chio_kernel::receipt_query::ReceiptReadContext;
use chio_kernel::ReceiptAnalyticsQuery;
use chio_store_sqlite::SqliteReceiptStore;

trait TestResultOk<T, E> {
    fn test_expect(self, context: &'static str) -> T;
}

impl<T, E> TestResultOk<T, E> for Result<T, E> {
    fn test_expect(self, context: &'static str) -> T {
        match self {
            Ok(value) => value,
            Err(_) => panic!("{context}"),
        }
    }
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-{prefix}-{nonce}.sqlite3"))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

#[test]
fn receipt_analytics_without_read_context_fails_closed() {
    let path = unique_db_path("analytics-missing-context");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    let err = store
        .query_receipt_analytics(&ReceiptAnalyticsQuery::default())
        .expect_err("analytics without read context must fail closed");

    assert!(
        err.to_string()
            .contains("requires an explicit receipt read context"),
        "unexpected error: {err}"
    );

    cleanup(&path);
}

#[test]
fn receipt_analytics_rejects_tenant_scoped_read_context() {
    let path = unique_db_path("analytics-tenant-scoped");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    let err = store
        .query_receipt_analytics(&ReceiptAnalyticsQuery {
            read_context: Some(ReceiptReadContext::authenticated_tenant("tenant-a")),
            ..ReceiptAnalyticsQuery::default()
        })
        .expect_err("tenant-scoped context must not authorize analytics aggregation");

    assert!(
        err.to_string()
            .contains("requires admin receipt read authority"),
        "unexpected error: {err}"
    );

    cleanup(&path);
}
