use chio_test_support::prelude::*;

use std::io::{BufReader, Cursor};

use chio_core_types::{Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    load_key_log_policy, load_witness_seed_backend, read_bounded_json_line,
    KEY_LOG_POLICY_DOCUMENT_SCHEMA, MAX_CANONICAL_RECORD_BYTES,
};

mod support;

use support::{private_tempdir, trusted_temp_path, write_private_file};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

#[test]
fn policy_file_loader_is_strict_and_binds_all_configured_roots() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "policy.json");
    let bootstrap = backend(1);
    let operator = backend(2);
    let witness_a = backend(3);
    let witness_b = backend(4);
    let witness_c = backend(5);
    let artifact_time = backend(6);
    let auditor_a = backend(7);
    let auditor_b = backend(8);
    let document = serde_json::json!({
        "schema": KEY_LOG_POLICY_DOCUMENT_SCHEMA,
        "log_id": "log.service.test",
        "authority_id": "authority.service.test",
        "bootstrap_public_key": bootstrap.public_key().to_hex(),
        "operator_public_key": operator.public_key().to_hex(),
        "witness_roster_id": "roster.service.v1",
        "witness_public_keys": {
            "witness.a": witness_a.public_key().to_hex(),
            "witness.b": witness_b.public_key().to_hex(),
            "witness.c": witness_c.public_key().to_hex()
        },
        "recovery_policy_id": "recovery.service.v1",
        "recovery_public_keys": {},
        "recovery_threshold": 0,
        "artifact_time_public_keys": {
            "timestamp.service.v1": artifact_time.public_key().to_hex()
        },
        "auditor_public_keys": {
            "audit.a": auditor_a.public_key().to_hex(),
            "audit.b": auditor_b.public_key().to_hex()
        },
        "max_checkpoint_future_skew_millis": 100
    });
    write_private_file(&path, serde_json::to_vec(&document).test_unwrap()).test_unwrap();

    let policy = load_key_log_policy(&path).test_unwrap();
    assert_eq!(policy.log_id().as_str(), "log.service.test");
    assert_eq!(policy.authority_id().as_str(), "authority.service.test");
    assert_eq!(policy.witness_threshold().test_unwrap(), 2);
    assert_eq!(policy.auditor_public_keys().len(), 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).test_unwrap();
        assert!(load_key_log_policy(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).test_unwrap();

        let hardlink = trusted_temp_path(&directory, "policy-hardlink.json");
        std::fs::hard_link(&path, &hardlink).test_unwrap();
        assert!(load_key_log_policy(&path).is_err());
        std::fs::remove_file(&hardlink).test_unwrap();

        let symlink_path = trusted_temp_path(&directory, "policy-symlink.json");
        symlink(&path, &symlink_path).test_unwrap();
        assert!(load_key_log_policy(&symlink_path).is_err());

        let substituted_parent = trusted_temp_path(&directory, "substituted-parent");
        symlink(directory.path(), &substituted_parent).test_unwrap();
        assert!(load_key_log_policy(substituted_parent.join("policy.json")).is_err());
    }

    let mut incomplete_auditors = document.clone();
    incomplete_auditors["auditor_public_keys"]
        .as_object_mut()
        .test_unwrap()
        .remove("audit.b");
    write_private_file(
        &path,
        serde_json::to_vec(&incomplete_auditors).test_unwrap(),
    )
    .test_unwrap();
    assert!(load_key_log_policy(&path).is_err());

    let mut unknown_field = document;
    unknown_field["unexpected"] = serde_json::Value::Bool(true);
    write_private_file(&path, serde_json::to_vec(&unknown_field).test_unwrap()).test_unwrap();
    assert!(load_key_log_policy(&path).is_err());
}

#[test]
fn bounded_json_line_rejects_requests_over_one_megabyte() {
    let mut oversized = vec![b' '; MAX_CANONICAL_RECORD_BYTES + 1];
    oversized.push(b'\n');
    let mut reader = BufReader::new(Cursor::new(oversized));
    assert!(read_bounded_json_line::<_, serde_json::Value>(&mut reader).is_err());

    let mut reader = BufReader::new(Cursor::new(b"{\"ok\":true}\n"));
    assert_eq!(
        read_bounded_json_line::<_, serde_json::Value>(&mut reader).test_unwrap(),
        Some(serde_json::json!({"ok": true}))
    );
}

#[cfg(unix)]
#[test]
fn witness_seed_loader_rejects_links_and_permissive_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = private_tempdir().test_unwrap();
    let seed_path = trusted_temp_path(&directory, "witness.seed");
    write_private_file(&seed_path, [9_u8; 32]).test_unwrap();
    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).test_unwrap();
    let loaded = load_witness_seed_backend(&seed_path).test_unwrap();
    assert_eq!(loaded.public_key(), backend(9).public_key());

    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o640)).test_unwrap();
    assert!(load_witness_seed_backend(&seed_path).is_err());
    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).test_unwrap();

    let symlink_path = trusted_temp_path(&directory, "witness-link.seed");
    symlink(&seed_path, &symlink_path).test_unwrap();
    assert!(load_witness_seed_backend(&symlink_path).is_err());

    let hardlink_path = trusted_temp_path(&directory, "witness-hardlink.seed");
    std::fs::hard_link(&seed_path, &hardlink_path).test_unwrap();
    assert!(load_witness_seed_backend(&seed_path).is_err());
}
