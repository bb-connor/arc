use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_kernel::{AuthoritySnapshot, BudgetStore, RevocationRecord};
use arc_store_sqlite::{SqliteBudgetStore, SqliteCapabilityAuthority, SqliteRevocationStore};

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn cleanup_sqlite_files(path: &std::path::Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

#[test]
fn sqlite_capability_authority_rotates_and_applies_newer_snapshot() {
    let primary_path = unique_db_path("arc-authority-primary");
    let replica_path = unique_db_path("arc-authority-replica");
    let primary = SqliteCapabilityAuthority::open(&primary_path).expect("open primary authority");
    let replica = SqliteCapabilityAuthority::open(&replica_path).expect("open replica authority");

    let rotated = replica.rotate().expect("rotate replica authority");
    let snapshot = replica.snapshot().expect("snapshot replica authority");
    let replaced = primary
        .apply_snapshot(&snapshot)
        .expect("apply newer replica snapshot");
    let status = primary.status().expect("read primary status");

    assert!(replaced);
    assert_eq!(status.generation, rotated.generation);
    assert_eq!(status.public_key.to_hex(), snapshot.public_key_hex);
    assert!(status
        .trusted_public_keys
        .iter()
        .any(|key| key.to_hex() == snapshot.public_key_hex));

    cleanup_sqlite_files(&primary_path);
    cleanup_sqlite_files(&replica_path);
}

#[test]
fn sqlite_capability_authority_rejects_snapshot_with_mismatched_public_key() {
    let path = unique_db_path("arc-authority-invalid-snapshot");
    let authority = SqliteCapabilityAuthority::open(&path).expect("open authority");
    let mut snapshot: AuthoritySnapshot = authority.snapshot().expect("snapshot authority");
    snapshot.public_key_hex = "deadbeef".to_string();

    let error = authority
        .apply_snapshot(&snapshot)
        .expect_err("mismatched public key should fail closed");
    assert!(error.to_string().contains("public key does not match seed"));

    cleanup_sqlite_files(&path);
}

#[test]
fn sqlite_budget_and_revocation_paths_cover_limits_and_ordering() {
    let budget_path = unique_db_path("arc-budget-store");
    let revocation_path = unique_db_path("arc-revocation-store");
    let mut budget_store = SqliteBudgetStore::open(&budget_path).expect("open budget store");
    let mut revocation_store =
        SqliteRevocationStore::open(&revocation_path).expect("open revocation store");

    assert!(budget_store
        .try_charge_cost("cap-1", 0, Some(2), 5, Some(10), Some(10))
        .expect("charge within limits"));
    assert!(!budget_store
        .try_charge_cost("cap-1", 0, Some(2), 6, Some(5), Some(10))
        .expect("per-invocation cap should fail closed"));

    let charged = budget_store
        .get_usage("cap-1", 0)
        .expect("load charged usage")
        .expect("charged usage exists");
    assert_eq!(charged.invocation_count, 1);
    assert_eq!(charged.total_cost_charged, 5);

    budget_store
        .reduce_charge_cost("cap-1", 0, 3)
        .expect("reduce charged budget");
    let reduced = budget_store
        .get_usage("cap-1", 0)
        .expect("reload reduced usage")
        .expect("reduced usage exists");
    assert_eq!(reduced.total_cost_charged, 2);
    assert_eq!(
        budget_store
            .list_usages_after(10, Some(0))
            .expect("list replicated budgets")
            .len(),
        1
    );

    revocation_store
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-1".to_string(),
            revoked_at: 100,
        })
        .expect("insert first revocation");
    revocation_store
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-2".to_string(),
            revoked_at: 100,
        })
        .expect("insert second revocation");
    revocation_store
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-3".to_string(),
            revoked_at: 101,
        })
        .expect("insert third revocation");

    let after = revocation_store
        .list_revocations_after(10, Some(100), Some("cap-1"))
        .expect("list revocations after cursor");
    let capability_ids = after
        .iter()
        .map(|record| record.capability_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(capability_ids, vec!["cap-2", "cap-3"]);

    cleanup_sqlite_files(&budget_path);
    cleanup_sqlite_files(&revocation_path);
}
