use chio_core::Keypair;
use chio_test_support::prelude::*;

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use super::*;

fn deployment() -> ActiveDefenseDeploymentConfig {
    let authority = Keypair::from_seed(&[1; 32]).public_key();
    let client = Keypair::from_seed(&[2; 32]).public_key();
    let receipt = Keypair::from_seed(&[3; 32]).public_key();
    let authority_process = PeerIdentity {
        process_id: 100,
        user_id: 200,
        group_id: 300,
    };
    let broker_process = PeerIdentity {
        process_id: 101,
        user_id: 201,
        group_id: 301,
    };
    let mut deployment = ActiveDefenseDeploymentConfig {
        schema: ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA.to_string(),
        deployment_digest: Digest32::new([0; 32]),
        response_authority: AuthorityRuntimeConfig {
            schema: AUTHORITY_RUNTIME_CONFIG_SCHEMA.to_string(),
            protocol: ACTIVE_RESPONSE_AUTHORITY_PROTOCOL.to_string(),
            socket_path: PathBuf::from("/run/chio/response-authority.sock"),
            store_path: PathBuf::from("/var/lib/chio/response-authority.db"),
            trusted_service_uid: authority_process.user_id,
            service_identity: authority_process,
            expected_client_peer: broker_process,
            trusted_client: client.clone(),
            authority_identity: authority,
            deployment_digest: Digest32::new([0; 32]),
            store_digest: Digest32::new([4; 32]),
            timeout_ms: 1_000,
            maximum_clock_skew_seconds: 5,
            maximum_replay_entries: 1_024,
            worker_count: 4,
            queue_capacity: 16,
        },
        secret_broker: SecretBrokerDeploymentBinding {
            service_identity: broker_process,
            active_response_client_identity: client,
            receipt_signing_identity: receipt,
            normal_socket_path: PathBuf::from("/run/chio/secret-broker.sock"),
            audit_socket_path: PathBuf::from("/run/chio/secret-broker-audit.sock"),
            database_paths: vec![PathBuf::from("/var/lib/chio/secret-broker.db")],
            stage: ActiveDefenseDeploymentStage::Shadow,
        },
    };
    let digest = deployment
        .compute_deployment_digest()
        .test_expect("deployment digest");
    deployment.deployment_digest = digest;
    deployment.response_authority.deployment_digest = digest;
    deployment
}

#[test]
fn combined_deployment_binds_processes_paths_keys_and_store() {
    let deployment = deployment();
    deployment.validate().test_expect("valid deployment");

    let mut changed = deployment.clone();
    changed.response_authority.store_digest = Digest32::new([9; 32]);
    assert!(changed.validate().is_err());

    let mut aliased = deployment.clone();
    aliased.secret_broker.database_paths[0] = aliased.response_authority.store_path.clone();
    assert!(aliased.validate().is_err());

    let mut shared_key = deployment;
    shared_key.secret_broker.receipt_signing_identity =
        shared_key.response_authority.authority_identity.clone();
    assert!(shared_key.validate().is_err());
}

#[test]
fn runtime_config_rejects_same_process_role_aliasing() {
    let mut config = deployment().response_authority;
    config.expected_client_peer = config.service_identity;
    assert!(config.validate().is_err());
}

#[test]
fn deployment_digest_can_be_planned_before_digest_fields_are_populated() {
    let complete = deployment();
    let expected = complete.deployment_digest;
    let mut planned = complete;
    planned.deployment_digest = Digest32::new([0; 32]);
    planned.response_authority.deployment_digest = Digest32::new([0; 32]);
    assert_eq!(
        planned
            .compute_deployment_digest()
            .test_expect("planned deployment digest"),
        expected
    );
    assert!(planned.validate().is_err());
}

#[test]
fn deployment_digest_has_an_exact_golden_vector() {
    assert_eq!(
        hex::encode(deployment().deployment_digest.as_bytes()),
        "6d6ec839be20fd9377b4d8c3412e6543c653faba73735ebf883f800c8605bf70"
    );
}

#[test]
fn deployment_rejects_oversized_broker_socket_paths() {
    let mut changed = deployment();
    changed.secret_broker.normal_socket_path =
        PathBuf::from(format!("/{}", "x".repeat(MAX_UNIX_SOCKET_PATH_BYTES)));
    changed.deployment_digest = Digest32::new([0; 32]);
    changed.response_authority.deployment_digest = Digest32::new([0; 32]);
    assert!(changed.compute_deployment_digest().is_err());
}

#[test]
fn deployment_rejects_non_normalized_privileged_paths() {
    let mut changed = deployment();
    changed.secret_broker.database_paths[0] =
        PathBuf::from("/var/lib/chio/../chio/secret-broker.db");
    changed.deployment_digest = Digest32::new([0; 32]);
    changed.response_authority.deployment_digest = Digest32::new([0; 32]);
    assert!(changed.compute_deployment_digest().is_err());
}

#[cfg(unix)]
#[test]
fn daemon_loader_rejects_a_standalone_runtime_projection() {
    let directory = tempfile::tempdir().test_expect("deployment config directory");
    let path = directory.path().join("authority-runtime.json");
    let runtime = deployment().response_authority;
    let bytes = chio_core::canonical_json_bytes(&runtime).test_expect("canonical runtime subset");
    write_private_config(&path, &bytes);

    let error = load_runtime_config(&path)
        .test_expect_err("daemon must require the complete combined deployment");
    assert!(matches!(error, AuthorityError::InvalidConfig(_)));
}

#[cfg(unix)]
#[test]
fn daemon_loader_revalidates_the_combined_deployment_digest() {
    let directory = tempfile::tempdir().test_expect("deployment config directory");
    let path = directory.path().join("deployment.json");
    let mut combined = deployment();
    combined.response_authority.trusted_service_uid = rustix::process::geteuid().as_raw();
    combined.response_authority.service_identity.user_id =
        combined.response_authority.trusted_service_uid;
    combined.deployment_digest = Digest32::new([0; 32]);
    combined.response_authority.deployment_digest = Digest32::new([0; 32]);
    let digest = combined
        .compute_deployment_digest()
        .test_expect("combined deployment digest");
    combined.deployment_digest = digest;
    combined.response_authority.deployment_digest = digest;
    combined.secret_broker.normal_socket_path = combined.response_authority.socket_path.clone();
    let bytes =
        chio_core::canonical_json_bytes(&combined).test_expect("canonical tampered deployment");
    write_private_config(&path, &bytes);

    let error = load_runtime_config(&path)
        .test_expect_err("daemon must revalidate the complete deployment");
    assert!(matches!(error, AuthorityError::InvalidConfig(_)));
}

#[cfg(unix)]
fn write_private_config(path: &std::path::Path, bytes: &[u8]) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).test_expect("create private config");
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .test_expect("write private config");
}
