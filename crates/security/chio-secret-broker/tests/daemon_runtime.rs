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
use chio_secret_broker::BrokerError;
use chio_test_support::prelude::*;

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn current_gid() -> u32 {
    rustix::process::getegid().as_raw()
}

const MIGRATION_CONTROLS: &str =
    "daemon enterprise migration anchors must contain the exact sorted broker controls";
const MIGRATION_MISBOUND: &str =
    "daemon enterprise migration anchor is misbound to its provider or control";
const IPC_DEADLINES: &str = "broker IPC deadlines must be between 1 and 30000 milliseconds";
const AUDIT_DEADLINES: &str = "privileged audit deadlines must be between 1 and 30000 milliseconds";
#[cfg(target_os = "linux")]
const MIGRATION_LEDGER_INTEGRITY: &str =
    "broker storage failed: daemon enterprise migration state database failed: \
     enterprise migration state schema or transition ledger failed integrity validation";
const DISTINCT_DATABASES: &str = "daemon database paths must be distinct";

fn assert_invalid_request<T: std::fmt::Debug>(
    result: chio_secret_broker::Result<T>,
    message: &str,
) {
    let error = result.test_expect_err("the runtime config must be refused");
    assert!(
        matches!(error, BrokerError::InvalidRequest(_)),
        "unexpected variant: {error:?}"
    );
    assert_eq!(error.diagnostic_code(), "invalid_request");
    assert_eq!(
        error.to_string(),
        format!("broker request is invalid: {message}")
    );
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
        local_adapter: None,
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

    let mut foreign_schema = valid.clone();
    foreign_schema.schema = "chio.secret-brokerd.runtime-config.unknown".to_string();
    assert_invalid_request(foreign_schema.validate(), "daemon config schema is invalid");

    let mut missing_binding = valid.clone();
    missing_binding.enterprise_migration.heads.clear();
    assert_invalid_request(missing_binding.validate(), MIGRATION_CONTROLS);

    let mut wrong_deployment = valid.clone();
    wrong_deployment.enterprise_migration.deployment_id =
        chio_security_types::ports::RecordId::new("wrong-deployment")
            .test_expect("wrong deployment id");
    assert_invalid_request(
        wrong_deployment.validate(),
        "daemon enterprise migration deployment does not match the broker deployment",
    );

    let mut wrong_provider = valid.clone();
    wrong_provider.enterprise_migration.credential_provider =
        chio_security_types::ports::RecordId::new("wrong-provider")
            .test_expect("wrong provider id");
    assert_invalid_request(wrong_provider.validate(), MIGRATION_MISBOUND);

    let mut wrong_control = valid.clone();
    wrong_control.enterprise_migration.heads[0].key.control =
        chio_security_types::EnterpriseMigrationControl::BrokerQuotaEnforcement;
    assert_invalid_request(wrong_control.validate(), MIGRATION_CONTROLS);

    for (field, value) in [
        ("credentialCustodyStage", serde_json::json!("shadow")),
        ("quotaEnforcementStage", serde_json::json!("legacy_removed")),
        ("minimumHeads", serde_json::json!([])),
    ] {
        let mut encoded = serde_json::to_value(&valid).test_expect("encode runtime config");
        encoded["enterpriseMigration"]
            .as_object_mut()
            .test_expect("enterprise migration object")
            .insert(field.to_string(), value);
        let error = serde_json::from_value::<BrokerDaemonConfig>(encoded)
            .test_expect_err("a staged migration field must be refused structurally");
        assert_eq!(
            error.to_string(),
            format!(
                "unknown field `{field}`, expected one of `stateDatabasePath`, `deploymentId`, \
                 `credentialProvider`, `trustedTransitionSigners`, `heads`"
            )
        );
    }

    let mut reused_runner = valid.clone();
    reused_runner.trusted_audit_runner = reused_runner.broker_identity.clone();
    assert_invalid_request(
        reused_runner.validate(),
        "daemon audit runner key must be independent of broker and operator keys",
    );

    let mut partial = valid.clone();
    partial.authority_timeout_ms = 0;
    assert_invalid_request(
        partial.validate(),
        "daemon provider or authority limits are invalid",
    );

    let mut unbounded_ipc = valid.clone();
    unbounded_ipc.ipc_read_timeout_ms = 0;
    assert_invalid_request(unbounded_ipc.validate(), IPC_DEADLINES);

    let mut aliased_audit_socket = valid.clone();
    aliased_audit_socket.privileged_audit.socket_path =
        aliased_audit_socket.ipc_socket_path.clone();
    assert_invalid_request(
        aliased_audit_socket.validate(),
        "broker, authority, and privileged audit sockets must be distinct",
    );

    let mut shared_audit_parent = valid.clone();
    shared_audit_parent.privileged_audit.socket_path = shared_audit_parent
        .ipc_socket_path
        .with_file_name("audit.sock");
    assert_invalid_request(
        shared_audit_parent.validate(),
        "privileged audit socket must use a dedicated parent directory",
    );

    let mut unbounded_audit = valid.clone();
    unbounded_audit.privileged_audit.read_timeout_ms = 0;
    assert_invalid_request(unbounded_audit.validate(), AUDIT_DEADLINES);

    let mut stale_audit_authorization = valid.clone();
    stale_audit_authorization
        .privileged_audit
        .authorization_lifetime_seconds = 301;
    assert_invalid_request(
        stale_audit_authorization.validate(),
        "privileged audit identity or authorization lifetime is invalid",
    );

    let mut aliased_storage = valid;
    aliased_storage.databases.receipt_database_path =
        aliased_storage.databases.attempt_database_path.clone();
    assert_invalid_request(aliased_storage.validate(), DISTINCT_DATABASES);

    let mut aliased_migration = config(directory.path());
    aliased_migration.enterprise_migration.state_database_path =
        aliased_migration.databases.receipt_database_path.clone();
    assert_invalid_request(aliased_migration.validate(), DISTINCT_DATABASES);
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
    assert!(matches!(error, BrokerError::Custody(_)), "{error:?}");
    assert_eq!(error.diagnostic_code(), "custody");
    assert_eq!(
        error.to_string(),
        "broker custody failed: effective service UID does not match the trusted daemon configuration"
    );
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
    let error = BrokerDaemonConfig::load(&config_path)
        .test_expect_err("a config owned by another UID than it declares must be refused");
    assert!(matches!(error, BrokerError::Custody(_)), "{error:?}");
    assert_eq!(error.diagnostic_code(), "custody");
    assert_eq!(
        error.to_string(),
        "broker custody failed: daemon config owner does not match the trusted service UID"
    );
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
    use chio_secret_broker::Result;
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
        wrong_head.enterprise_migration.heads[0].transition_digest =
            chio_security_types::ports::Digest32::new([0xee; 32]);
        let error = match BrokerDaemonRuntime::build(
            wrong_head,
            sealed_read_only_seed("wrong-head-master", &[81; 32]),
            sealed_read_only_seed("wrong-head-signing", &[93; 32]),
        ) {
            Ok(_) => panic!("wrong-head startup must be refused"),
            Err(error) => error,
        };
        assert!(matches!(error, BrokerError::Storage(_)), "{error:?}");
        assert_eq!(error.diagnostic_code(), "storage");
        assert_eq!(error.to_string(), MIGRATION_LEDGER_INTEGRITY);
        assert!(!broker_socket.exists());
        assert!(!audit_socket.exists());

        let mut missing_binding = daemon_config;
        let missing_path = directory.path().join("missing-migration.sqlite3");
        File::create(&missing_path).test_expect("create missing-binding ledger");
        std::fs::set_permissions(&missing_path, std::fs::Permissions::from_mode(0o600))
            .test_expect("harden missing-binding ledger");
        missing_binding.enterprise_migration.state_database_path = missing_path;
        let error = match BrokerDaemonRuntime::build(
            missing_binding,
            sealed_read_only_seed("missing-binding-master", &[81; 32]),
            sealed_read_only_seed("missing-binding-signing", &[93; 32]),
        ) {
            Ok(_) => panic!("missing-binding startup must be refused"),
            Err(error) => error,
        };
        assert!(matches!(error, BrokerError::Storage(_)), "{error:?}");
        assert_eq!(error.diagnostic_code(), "storage");
        assert_eq!(error.to_string(), MIGRATION_LEDGER_INTEGRITY);
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
