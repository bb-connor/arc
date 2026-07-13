#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::Keypair;
use chio_secret_broker::daemon::daemon_admin_intent_digest;
use chio_secret_broker::daemon_runtime::{
    BrokerDaemonAdminConfig, BrokerDaemonConfig, BrokerDaemonDatabaseConfig,
    ProviderPlacementConfig, BROKER_DAEMON_CONFIG_SCHEMA,
};
use chio_secret_broker::service::IpcOperation;

fn config(directory: &std::path::Path) -> BrokerDaemonConfig {
    let capability_issuer = Keypair::from_seed(&[91; 32]);
    let authority = Keypair::from_seed(&[92; 32]);
    let broker = Keypair::from_seed(&[93; 32]);
    let approver = Keypair::from_seed(&[94; 32]);
    BrokerDaemonConfig {
        schema: BROKER_DAEMON_CONFIG_SCHEMA.to_string(),
        tenant_scope: "tenant-production".to_string(),
        ipc_socket_path: directory.join("broker.sock"),
        authority_socket_path: directory.join("authority.sock"),
        trusted_capability_issuer: capability_issuer.public_key(),
        trusted_authority: authority.public_key(),
        broker_identity: broker.public_key(),
        broker_audience: "broker-service-production".to_string(),
        parent_audience: "parent-service-production".to_string(),
        provider_adapter_id: "generic-bearer".to_string(),
        provider_adapter_version: 1,
        provider_placement: ProviderPlacementConfig::BearerAuthorization,
        expected_key_owner_uid: 501,
        authority_timeout_ms: 1_000,
        maximum_clock_skew_seconds: 30,
        maximum_liveness_snapshot_age_seconds: 30,
        maximum_revocation_snapshot_age_seconds: 30,
        databases: BrokerDaemonDatabaseConfig {
            secret_database_path: directory.join("secrets.sqlite3"),
            attempt_database_path: directory.join("attempts.sqlite3"),
            admin_replay_database_path: directory.join("admin.sqlite3"),
            receipt_database_path: directory.join("receipts.sqlite3"),
        },
        admin: BrokerDaemonAdminConfig {
            trusted_approvers: vec![approver.public_key()],
            subject: Keypair::from_seed(&[95; 32]).public_key(),
            threshold: 1,
            maximum_token_lifetime_seconds: 60,
        },
    }
}

#[test]
fn daemon_runtime_config_is_closed_and_rejects_partial_authority_or_storage() {
    let directory = tempfile::tempdir().expect("tempdir");
    let valid = config(directory.path());
    valid.validate().expect("valid runtime config");

    let mut partial = valid.clone();
    partial.authority_timeout_ms = 0;
    assert!(partial.validate().is_err());

    let mut aliased_storage = valid;
    aliased_storage.databases.receipt_database_path =
        aliased_storage.databases.attempt_database_path.clone();
    assert!(aliased_storage.validate().is_err());
}

#[test]
fn daemon_governed_intent_changes_with_operation_tenant_and_payload() {
    let payload = br#"{"credential":"opaque-reference","version":1}"#;
    let baseline =
        daemon_admin_intent_digest(IpcOperation::Provision, "tenant-production", payload)
            .expect("baseline");
    assert_ne!(
        baseline,
        daemon_admin_intent_digest(IpcOperation::Rotate, "tenant-production", payload)
            .expect("operation")
    );
    assert_ne!(
        baseline,
        daemon_admin_intent_digest(IpcOperation::Provision, "tenant-other", payload)
            .expect("tenant")
    );
    assert_ne!(
        baseline,
        daemon_admin_intent_digest(
            IpcOperation::Provision,
            "tenant-production",
            br#"{"credential":"different-reference","version":1}"#,
        )
        .expect("payload")
    );
}
