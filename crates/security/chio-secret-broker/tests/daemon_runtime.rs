#![cfg(unix)]

mod support;

use chio_core_types::canonical_json_bytes;
use chio_core_types::Keypair;
use chio_secret_broker::daemon::daemon_admin_intent_digest;
use chio_secret_broker::daemon_runtime::{
    BrokerDaemonAdminConfig, BrokerDaemonConfig, BrokerDaemonDatabaseConfig,
    BrokerDaemonPrivilegedAuditConfig, ProviderPlacementConfig, BROKER_DAEMON_CONFIG_SCHEMA,
};
use chio_secret_broker::service::IpcOperation;
use chio_test_support::prelude::*;

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn current_gid() -> u32 {
    rustix::process::getegid().as_raw()
}

fn config(directory: &std::path::Path) -> BrokerDaemonConfig {
    let directory = std::fs::canonicalize(directory).test_expect("canonical runtime directory");
    let capability_issuer = Keypair::from_seed(&[91; 32]);
    let authority = Keypair::from_seed(&[92; 32]);
    let broker = Keypair::from_seed(&[93; 32]);
    let approver = Keypair::from_seed(&[94; 32]);
    let audit_runner = Keypair::from_seed(&[96; 32]);
    BrokerDaemonConfig {
        schema: BROKER_DAEMON_CONFIG_SCHEMA.to_string(),
        deployment_id: "deployment-production".to_string(),
        broker_instance_id: "broker-production-1".to_string(),
        tenant_scope: "tenant-production".to_string(),
        audit_runner_id: "enterprise-runner-1".to_string(),
        trusted_audit_runner: audit_runner.public_key(),
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
        trusted_service_uid: current_uid(),
        authorized_client_uid: current_uid(),
        ipc_read_timeout_ms: 1_000,
        ipc_write_timeout_ms: 1_000,
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
        enterprise_migration: support::enforced_broker_migration(
            &directory,
            "deployment-production",
            "generic-https",
        ),
        admin: BrokerDaemonAdminConfig {
            trusted_approvers: vec![approver.public_key()],
            subject: Keypair::from_seed(&[95; 32]).public_key(),
            threshold: 1,
            maximum_token_lifetime_seconds: 60,
        },
        privileged_audit: BrokerDaemonPrivilegedAuditConfig {
            socket_path: directory.join("privileged-audit").join("audit.sock"),
            authorized_runner_uid: current_uid(),
            authorized_runner_gid: current_gid(),
            read_timeout_ms: 1_000,
            write_timeout_ms: 1_000,
            authorization_lifetime_seconds: 30,
        },
    }
}

#[test]
fn daemon_runtime_config_is_closed_and_rejects_partial_authority_or_storage() {
    let directory = support::private_tempdir();
    let valid = config(directory.path());
    valid.validate().test_expect("valid runtime config");

    let mut legacy = valid.clone();
    legacy.schema = "chio.secret-brokerd.runtime-config.v1".to_string();
    legacy
        .validate()
        .test_expect_err("deadline-less v1 runtime config must be rejected");
    let mut pre_governed_audit = valid.clone();
    pre_governed_audit.schema = "chio.secret-brokerd.runtime-config.v2".to_string();
    pre_governed_audit
        .validate()
        .test_expect_err("runner-unbound v2 runtime config must be rejected");
    let mut in_process_only_audit = valid.clone();
    in_process_only_audit.schema = "chio.secret-brokerd.runtime-config.v3".to_string();
    in_process_only_audit
        .validate()
        .test_expect_err("socket-less v3 runtime config must be rejected");
    let mut unanchored_migration = valid.clone();
    unanchored_migration.schema = "chio.secret-brokerd.runtime-config.v4".to_string();
    unanchored_migration
        .validate()
        .test_expect_err("migration-unbound v4 runtime config must be rejected");

    let mut missing_binding = valid.clone();
    missing_binding.enterprise_migration.minimum_heads.clear();
    missing_binding
        .validate()
        .test_expect_err("both broker migration bindings are required");

    let mut wrong_deployment = valid.clone();
    wrong_deployment.enterprise_migration.deployment_id =
        chio_security_types::ports::RecordId::new("wrong-deployment")
            .test_expect("wrong deployment id");
    wrong_deployment
        .validate()
        .test_expect_err("migration deployment must match daemon deployment");

    let mut wrong_provider = valid.clone();
    wrong_provider.enterprise_migration.credential_provider =
        chio_security_types::ports::RecordId::new("wrong-provider")
            .test_expect("wrong provider id");
    wrong_provider
        .validate()
        .test_expect_err("migration heads must match the configured provider");

    let mut wrong_control = valid.clone();
    wrong_control.enterprise_migration.minimum_heads[0]
        .key
        .control = chio_security_types::EnterpriseMigrationControl::BrokerQuotaEnforcement;
    wrong_control
        .validate()
        .test_expect_err("migration heads must bind both exact controls");

    let mut fallback_stage = valid.clone();
    fallback_stage.enterprise_migration.credential_custody_stage =
        chio_security_types::EnterpriseMigrationStage::Shadow;
    fallback_stage
        .validate()
        .test_expect_err("production custody migration cannot permit fallback");

    let mut wrong_stage = valid.clone();
    wrong_stage.enterprise_migration.quota_enforcement_stage =
        chio_security_types::EnterpriseMigrationStage::LegacyRemoved;
    wrong_stage
        .validate()
        .test_expect_err("migration head generation must equal the configured stage");

    let mut reused_runner = valid.clone();
    reused_runner.trusted_audit_runner = reused_runner.broker_identity.clone();
    reused_runner
        .validate()
        .test_expect_err("audit runner must use an independent key");

    let mut partial = valid.clone();
    partial.authority_timeout_ms = 0;
    assert!(partial.validate().is_err());

    let mut unbounded_ipc = valid.clone();
    unbounded_ipc.ipc_read_timeout_ms = 0;
    assert!(unbounded_ipc.validate().is_err());

    let mut aliased_audit_socket = valid.clone();
    aliased_audit_socket.privileged_audit.socket_path =
        aliased_audit_socket.ipc_socket_path.clone();
    assert!(aliased_audit_socket.validate().is_err());

    let mut shared_audit_parent = valid.clone();
    shared_audit_parent.privileged_audit.socket_path = shared_audit_parent
        .ipc_socket_path
        .with_file_name("audit.sock");
    assert!(shared_audit_parent.validate().is_err());

    let mut unbounded_audit = valid.clone();
    unbounded_audit.privileged_audit.read_timeout_ms = 0;
    assert!(unbounded_audit.validate().is_err());

    let mut stale_audit_authorization = valid.clone();
    stale_audit_authorization
        .privileged_audit
        .authorization_lifetime_seconds = 301;
    assert!(stale_audit_authorization.validate().is_err());

    let mut aliased_storage = valid;
    aliased_storage.databases.receipt_database_path =
        aliased_storage.databases.attempt_database_path.clone();
    assert!(aliased_storage.validate().is_err());

    let mut aliased_migration = config(directory.path());
    aliased_migration.enterprise_migration.state_database_path =
        aliased_migration.databases.receipt_database_path.clone();
    assert!(aliased_migration.validate().is_err());
}

#[cfg(unix)]
#[test]
fn daemon_runtime_config_rejects_a_self_declared_service_uid() {
    let directory = support::private_tempdir();
    let mut untrusted = config(directory.path());
    untrusted.trusted_service_uid = current_uid().wrapping_add(1);

    let error = untrusted
        .validate()
        .test_expect_err("configured service UID must be anchored to the effective UID");
    assert!(error
        .to_string()
        .contains("effective service UID does not match"));
}

#[test]
fn daemon_config_file_owner_is_bound_to_the_effective_service_uid() {
    use std::os::unix::fs::PermissionsExt;

    let directory = support::private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonical runtime directory");
    let valid = config(&trusted_directory);
    let config_path = trusted_directory.join("brokerd.json");
    std::fs::write(
        &config_path,
        canonical_json_bytes(&valid).test_expect("canonical daemon config"),
    )
    .test_expect("write daemon config");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .test_expect("private daemon config");
    BrokerDaemonConfig::load(&config_path).test_expect("load service-owned daemon config");

    let mut forged = valid;
    forged.trusted_service_uid = current_uid().wrapping_add(1);
    std::fs::write(
        &config_path,
        canonical_json_bytes(&forged).test_expect("canonical forged config"),
    )
    .test_expect("write forged daemon config");
    assert!(BrokerDaemonConfig::load(&config_path).is_err());
}

#[test]
fn daemon_governed_intent_changes_with_operation_tenant_and_payload() {
    let payload = br#"{"credential":"opaque-reference","version":1}"#;
    let baseline =
        daemon_admin_intent_digest(IpcOperation::Provision, "tenant-production", payload)
            .test_expect("baseline");
    assert_ne!(
        baseline,
        daemon_admin_intent_digest(IpcOperation::Rotate, "tenant-production", payload)
            .test_expect("operation")
    );
    assert_ne!(
        baseline,
        daemon_admin_intent_digest(IpcOperation::Provision, "tenant-other", payload)
            .test_expect("tenant")
    );
    assert_ne!(
        baseline,
        daemon_admin_intent_digest(
            IpcOperation::Provision,
            "tenant-production",
            br#"{"credential":"different-reference","version":1}"#,
        )
        .test_expect("payload")
    );
}

#[cfg(target_os = "linux")]
mod startup {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::thread;

    use chio_core_types::Ed25519Backend;
    use chio_secret_broker::authority_ipc::{
        AuthorityOperation, AuthorityResult, AuthorityRpcServer, BrokerAuthorityHandler,
    };
    use chio_secret_broker::budget::{ExecutionAuthorityCapabilities, ExecutionAuthorityProfile};
    use chio_secret_broker::daemon_runtime::BrokerDaemonRuntime;
    use chio_secret_broker::{BrokerError, Result};
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};

    use super::*;

    struct CapabilitiesOnlyAuthority;

    impl BrokerAuthorityHandler for CapabilitiesOnlyAuthority {
        fn handle(&self, operation: &AuthorityOperation) -> Result<AuthorityResult> {
            match operation {
                AuthorityOperation::Capabilities => Ok(AuthorityResult::Capabilities(
                    ExecutionAuthorityCapabilities {
                        profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                        atomic_multi_key_holds: true,
                        combined_capture_and_revocation: true,
                        query_by_id: true,
                        shared_revocation_write_domain: true,
                    },
                )),
                _ => Err(BrokerError::AuthorizationDenied(
                    "unexpected startup-test authority operation".to_string(),
                )),
            }
        }
    }

    fn sealed_read_only_seed(name: &str, seed: &[u8; 32]) -> File {
        let descriptor = memfd_create(name, MemfdFlags::ALLOW_SEALING).test_expect("memfd");
        let mut writable = File::from(descriptor);
        writable.write_all(seed).test_expect("write seed");
        writable.seek(SeekFrom::Start(0)).test_expect("seek seed");
        fcntl_add_seals(
            &writable,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
        )
        .test_expect("seal seed");
        File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).test_expect("read-only seed")
    }

    #[test]
    fn broker_startup_rejects_missing_or_wrong_migration_head_before_socket_publication() {
        let directory = support::private_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .test_expect("private runtime directory");
        let daemon_config = config(directory.path());
        let broker_socket = daemon_config.ipc_socket_path.clone();
        let audit_socket = daemon_config.privileged_audit.socket_path.clone();

        let mut wrong_head = daemon_config.clone();
        wrong_head.enterprise_migration.minimum_heads[0].transition_digest =
            chio_security_types::ports::Digest32::new([0xee; 32]);
        assert!(BrokerDaemonRuntime::build(
            wrong_head,
            sealed_read_only_seed("wrong-head-master", &[81; 32]),
            sealed_read_only_seed("wrong-head-signing", &[93; 32]),
        )
        .is_err());
        assert!(!broker_socket.exists());
        assert!(!audit_socket.exists());

        let mut missing_binding = daemon_config;
        let missing_path = directory.path().join("missing-migration.sqlite3");
        File::create(&missing_path).test_expect("create missing-binding ledger");
        std::fs::set_permissions(&missing_path, std::fs::Permissions::from_mode(0o600))
            .test_expect("harden missing-binding ledger");
        missing_binding.enterprise_migration.state_database_path = missing_path;
        assert!(BrokerDaemonRuntime::build(
            missing_binding,
            sealed_read_only_seed("missing-binding-master", &[81; 32]),
            sealed_read_only_seed("missing-binding-signing", &[93; 32]),
        )
        .is_err());
        assert!(!broker_socket.exists());
        assert!(!audit_socket.exists());
    }

    #[test]
    fn broker_first_startup_stays_unpublished_until_authority_is_ready_then_retries() {
        let directory = support::private_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .test_expect("private runtime directory");
        let mut daemon_config = config(directory.path());
        daemon_config.authority_timeout_ms = 100;
        let broker_socket = daemon_config.ipc_socket_path.clone();
        let audit_socket = daemon_config.privileged_audit.socket_path.clone();

        let unavailable = BrokerDaemonRuntime::build(
            daemon_config.clone(),
            sealed_read_only_seed("cold-master-1", &[81; 32]),
            sealed_read_only_seed("cold-signing-1", &[93; 32]),
        );
        let error = match unavailable {
            Ok(_) => panic!("broker IPC bound without an authority"),
            Err(error) => error,
        };
        assert!(matches!(error, BrokerError::AuthorityUnavailable(_)));
        assert!(!broker_socket.exists());
        assert!(!audit_socket.exists());

        let authority = AuthorityRpcServer::bind(
            &daemon_config.authority_socket_path,
            Keypair::from_seed(&[93; 32]).public_key(),
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[92; 32]))),
            Arc::new(CapabilitiesOnlyAuthority),
            30,
        )
        .test_expect("bind authority");
        let authority_worker =
            thread::spawn(move || authority.serve_one().test_expect("serve broker handshake"));

        let runtime = BrokerDaemonRuntime::build(
            daemon_config,
            sealed_read_only_seed("cold-master-2", &[81; 32]),
            sealed_read_only_seed("cold-signing-2", &[93; 32]),
        )
        .test_expect("retry broker startup");
        authority_worker.join().test_expect("authority worker");
        assert!(broker_socket.exists());
        let audit_metadata = std::fs::symlink_metadata(&audit_socket)
            .test_expect("privileged audit socket metadata");
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        assert!(audit_metadata.file_type().is_socket());
        assert_eq!(audit_metadata.uid(), current_uid());
        assert_eq!(audit_metadata.gid(), current_gid());
        assert_eq!(audit_metadata.permissions().mode() & 0o777, 0o660);
        drop(runtime);
        assert!(!audit_socket.exists());
    }
}
