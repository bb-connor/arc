use chio_core::Keypair;
use chio_test_support::prelude::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn logical_store_digest_is_stable_and_order_sensitive() {
    let authority = Keypair::from_seed(&[8; 32]).public_key();
    let first = LogicalRecord {
        key: "a".to_string(),
        payload: serde_json::json!({"value": 1}),
    };
    let second = LogicalRecord {
        key: "b".to_string(),
        payload: serde_json::json!({"value": 2}),
    };
    let ordered = logical_store_digest(&authority, &[first, second], &[])
        .test_expect("ordered logical digest");
    assert_eq!(
        hex::encode(ordered.as_bytes()),
        "5431410a5bdb6124b7350fd34b9b0bddedd7d52b5d1646b3b37a01e10404f9a6"
    );
    let reversed = logical_store_digest(
        &authority,
        &[
            LogicalRecord {
                key: "b".to_string(),
                payload: serde_json::json!({"value": 2}),
            },
            LogicalRecord {
                key: "a".to_string(),
                payload: serde_json::json!({"value": 1}),
            },
        ],
        &[],
    )
    .test_expect("reversed logical digest");
    assert_ne!(ordered, reversed);
}

#[test]
fn empty_or_zero_digest_bundle_is_rejected_before_output_creation() {
    let directory = tempfile::tempdir().test_expect("authority store directory");
    let database = directory.path().join("authority.db");
    let manifest = directory.path().join("authority.manifest.json");
    let bundle = AuthorityStoreBundle {
        schema: AUTHORITY_STORE_BUNDLE_SCHEMA.to_string(),
        deployment_digest: Digest32::new([0; 32]),
        authority_identity: Keypair::from_seed(&[9; 32]).public_key(),
        policies: Vec::new(),
        artifacts: Vec::new(),
    };
    assert!(build_authority_store(&bundle, &database, &manifest).is_err());
    assert!(!database.exists());
    assert!(!manifest.exists());
}

#[test]
fn canonical_digest_matches_canonical_sha256() {
    let value = serde_json::json!({"input": "same"});
    let digest = canonical_digest(&value).test_expect("canonical digest");
    let raw: [u8; 32] =
        Sha256::digest(canonical_json_bytes(&value).test_expect("canonical JSON")).into();
    assert_eq!(digest, Digest32::new(raw));
}

#[cfg(unix)]
#[test]
fn sqlite_snapshot_round_trips_canonical_metadata_and_rows() {
    let directory = tempfile::tempdir().test_expect("authority store directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .test_expect("private authority store directory");
    let database = directory.path().join("authority.db");
    let file = create_private_new_file(&database).test_expect("create private database");
    let guard = CreatedFileGuard::new(&database, &file).test_expect("database identity guard");
    drop(file);

    let manifest = AuthorityStoreManifest {
        schema: AUTHORITY_STORE_MANIFEST_SCHEMA.to_string(),
        deployment_digest: Digest32::new([1; 32]),
        store_digest: Digest32::new([2; 32]),
        authority_identity: Keypair::from_seed(&[3; 32]).public_key(),
        policy_count: 1,
        artifact_count: 1,
    };
    let policy_payload = canonical_json_bytes(&serde_json::json!({"kind": "policy"}))
        .test_expect("canonical policy payload");
    let artifact_payload = canonical_json_bytes(&serde_json::json!({"kind": "artifact"}))
        .test_expect("canonical artifact payload");
    let mut connection = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .test_expect("open private database");
    initialize_database(
        &mut connection,
        &manifest,
        &[("a".repeat(64), policy_payload)],
        &[("b".repeat(64), artifact_payload)],
    )
    .test_expect("initialize authority database");
    connection.close().test_expect("close authority database");
    guard
        .validate_exact()
        .test_expect("unchanged database path");
    sync_private_file(&database).test_expect("sync authority database");

    let connection = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .test_expect("reopen authority database");
    assert_eq!(
        load_manifest(&connection).test_expect("load authority manifest"),
        manifest
    );
    assert_eq!(
        load_logical_records(&connection, "policies")
            .test_expect("load policy rows")
            .len(),
        1
    );
    assert_eq!(
        load_logical_records(&connection, "artifacts")
            .test_expect("load artifact rows")
            .len(),
        1
    );
    validate_database_schema(&connection).test_expect("exact authority schema");
    drop(connection);
    let connection = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .test_expect("reopen writable authority database");
    connection
        .execute(
            "INSERT INTO metadata (key, value) VALUES ('unexpected', X'31')",
            [],
        )
        .test_expect("add unexpected metadata");
    assert!(load_manifest(&connection).is_err());
    connection
        .execute("DELETE FROM metadata WHERE key = 'unexpected'", [])
        .test_expect("remove unexpected metadata");
    connection
        .execute_batch("CREATE TABLE unexpected (value INTEGER NOT NULL) STRICT;")
        .test_expect("add unexpected schema object");
    assert!(validate_database_schema(&connection).is_err());
}

#[cfg(unix)]
#[test]
fn decisions_use_the_verified_startup_image_not_later_database_writes() {
    let directory = tempfile::tempdir().test_expect("authority store directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .test_expect("private authority store directory");
    let database = directory.path().join("authority.db");
    let deployment_digest = Digest32::new([0x41; 32]);
    let authority = Keypair::from_seed(&[0x42; 32]).public_key();
    let store_digest = build_empty_store_for_process_test(&database, deployment_digest, &authority)
        .test_expect("build empty authority store");
    let store = AuthorityStore::open(
        &database,
        rustix::process::geteuid().as_raw(),
        deployment_digest,
        store_digest,
        &authority,
    )
    .test_expect("open verified authority store");

    let connection = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .test_expect("open external writer");
    let injected_key = "a".repeat(64);
    connection
        .execute(
            "INSERT INTO policies (lookup_key, payload) VALUES (?1, ?2)",
            params![&injected_key, br#"{}"#],
        )
        .test_expect("inject post-startup row");
    drop(connection);

    assert!(matches!(
        store.policy_record(&injected_key),
        Err(AuthorityError::NotPreAdmitted)
    ));
    assert!(store.health().is_err());
}

#[cfg(unix)]
#[test]
fn cleanup_guard_never_removes_a_replacement_inode() {
    let directory = tempfile::tempdir().test_expect("guard directory");
    let path = directory.path().join("guarded");
    let displaced = directory.path().join("displaced");
    let original = create_private_new_file(&path).test_expect("create guarded file");
    let guard = CreatedFileGuard::new(&path, &original).test_expect("create identity guard");
    drop(original);
    std::fs::rename(&path, &displaced).test_expect("displace guarded file");
    create_private_new_file(&path).test_expect("create replacement file");

    assert!(guard.validate_exact().is_err());
    drop(guard);
    assert!(path.exists());
    assert!(displaced.exists());
}
