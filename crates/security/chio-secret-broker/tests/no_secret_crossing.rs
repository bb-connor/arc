use std::process::Command;

#[cfg(target_os = "linux")]
mod support;

use chio_core_types::{Ed25519Backend, Keypair};
use chio_secret_broker::budget::ExecutionQuota;
use chio_secret_broker::protocol::{
    BrokerDestination, BrokerExecuteResponse, BrokerExecutionEvidence, BROKER_EVIDENCE_SCHEMA,
};
use chio_secret_broker::receipt::{
    receipt_digest, sign_execution_receipt, BrokerExecutionOutcome, BrokerReceiptBody,
    BROKER_RECEIPT_SCHEMA,
};
use chio_test_support::prelude::*;

#[test]
fn public_response_and_daemon_diagnostics_do_not_contain_seeded_credential() {
    let canary = "credential-canary-7f890f957c";
    let evidence = BrokerExecutionEvidence {
        schema: BROKER_EVIDENCE_SCHEMA.to_string(),
        attempt_id: "attempt".to_string(),
        invocation_id: "invocation".to_string(),
        hold_id: "hold".to_string(),
        request_digest: "a".repeat(64),
        capability_digest: "b".repeat(64),
        revocation_set_digest: "c".repeat(64),
        budget_commit_index: 1,
        revocation_commit_index: 2,
        authority_commit_index: 3,
        leader_epoch: 4,
        upstream_status: 200,
        response_body_sha256: "d".repeat(64),
    };
    let signer = Keypair::from_seed(&[77; 32]);
    let signer_backend = Ed25519Backend::new(signer);
    let receipt = sign_execution_receipt(
        BrokerReceiptBody {
            schema: BROKER_RECEIPT_SCHEMA.to_string(),
            receipt_id: "broker-receipt-attempt".to_string(),
            issued_at_unix_seconds: 1,
            evidence: evidence.clone(),
            operation_id: "operation".to_string(),
            authorize_event_id: "authorize".to_string(),
            capture_event_id: "capture".to_string(),
            parent_capability_id: "parent-capability".to_string(),
            broker_capability_id: "broker-capability".to_string(),
            subject: Keypair::from_seed(&[78; 32]).public_key(),
            credential_reference_hash: "e".repeat(64),
            credential_version: 1,
            normalized_destination: BrokerDestination::parse(
                "https://example.com/v1",
                "POST",
                false,
            )
            .test_expect("destination"),
            request_body_sha256: "f".repeat(64),
            caller_headers_sha256: "1".repeat(64),
            caller_options_sha256: "2".repeat(64),
            quotas: vec![ExecutionQuota {
                key_id: "broker-quota".to_string(),
                maximum_executions: 1,
            }],
            broker_quota_key_id: "broker-quota".to_string(),
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            request_body_bytes: 9,
            response_body_bytes: 9,
            source_receipt_ids: vec!["source-receipt".to_string()],
            outcome: BrokerExecutionOutcome::Completed,
        },
        &signer_backend,
    )
    .test_expect("receipt");
    let response = BrokerExecuteResponse {
        status: 200,
        headers: Vec::new(),
        body: b"sanitized".to_vec(),
        evidence,
        receipt_reference: format!(
            "broker-receipt-sha256-{}",
            receipt_digest(&receipt).test_expect("receipt digest")
        ),
        receipt,
    };
    let encoded = serde_json::to_vec(&response).test_expect("response");
    assert!(!encoded
        .windows(canary.len())
        .any(|window| window == canary.as_bytes()));

    let output = Command::new(env!("CARGO_BIN_EXE_chio-secret-brokerd"))
        .env("CHIO_TEST_CANARY", canary)
        .output()
        .test_expect("daemon");
    assert!(!output
        .stdout
        .windows(canary.len())
        .any(|window| window == canary.as_bytes()));
    assert!(!output
        .stderr
        .windows(canary.len())
        .any(|window| window == canary.as_bytes()));
    assert!(!output.status.success());
    let diagnostics = String::from_utf8(output.stderr).test_expect("UTF-8 diagnostics");
    assert!(diagnostics.contains("failed closed: invalid_configuration"));
    assert!(!diagnostics.contains("requires runtime-supplied"));
}

#[cfg(target_os = "linux")]
mod linux_process {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair};
    use chio_secret_broker::authority_ipc::{
        AuthorityOperation, AuthorityResult, AuthorityRpcServer, BrokerAuthorityHandler,
    };
    use chio_secret_broker::budget::{ExecutionAuthorityCapabilities, ExecutionAuthorityProfile};
    use chio_secret_broker::daemon::{
        daemon_admin_intent_digest, encode_credential_mutation_payload,
    };
    use chio_secret_broker::daemon_runtime::{
        BrokerDaemonAdminConfig, BrokerDaemonConfig, BrokerDaemonDatabaseConfig,
        BrokerDaemonPrivilegedAuditConfig, ProviderPlacementConfig, BROKER_DAEMON_CONFIG_SCHEMA,
    };
    use chio_secret_broker::protocol::CredentialRef;
    use chio_secret_broker::provision::GovernedAdminAuthorizationEnvelope;
    use chio_secret_broker::service::{
        canonical_ipc_request_bytes, read_bounded_frame, write_bounded_frame,
        AuthenticatedIpcRequest, IpcOperation, IpcResponse,
    };
    use chio_secret_broker::{BrokerError, Result};
    use chio_test_support::prelude::*;
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use rustix::io::{fcntl_setfd, FdFlags};

    struct Authority;

    impl BrokerAuthorityHandler for Authority {
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
                    "unexpected process-test authority operation".to_string(),
                )),
            }
        }
    }

    fn sealed_seed(name: &str, seed: &[u8; 32]) -> File {
        let descriptor = memfd_create(name, MemfdFlags::ALLOW_SEALING).test_expect("memfd");
        let mut file = File::from(descriptor);
        file.write_all(seed).test_expect("write seed");
        file.seek(SeekFrom::Start(0)).test_expect("seek seed");
        fcntl_add_seals(
            &file,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
        )
        .test_expect("seal seed");
        fcntl_setfd(&file, FdFlags::empty()).test_expect("inherit seed");
        file
    }

    #[test]
    fn brokerd_process_governed_provisioning_keeps_seeded_secret_inside_broker() {
        let directory = tempfile::tempdir().test_expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .test_expect("private directory");
        let canary = b"brokerd-linux-process-canary-4f9071";
        let master_seed = sealed_seed("broker-master", &[101; 32]);
        let signing_seed = [102; 32];
        let signing_key = Keypair::from_seed(&signing_seed);
        let signing_seed = sealed_seed("broker-signing", &signing_seed);
        let expected_owner_uid = master_seed.metadata().test_expect("master metadata").uid();
        let authority_signer = Keypair::from_seed(&[103; 32]);
        let capability_issuer = Keypair::from_seed(&[104; 32]);
        let approver = Keypair::from_seed(&[105; 32]);
        let admin_subject = Keypair::from_seed(&[106; 32]).public_key();
        let authority_socket = directory.path().join("authority.sock");
        let broker_socket = directory.path().join("broker.sock");
        let audit_socket = directory.path().join("privileged-audit").join("audit.sock");
        let authority_server = AuthorityRpcServer::bind(
            &authority_socket,
            signing_key.public_key(),
            Arc::new(Ed25519Backend::new(authority_signer.clone())),
            Arc::new(Authority),
            30,
        )
        .test_expect("authority server");
        let authority_thread = thread::spawn(move || {
            authority_server
                .serve_one()
                .test_expect("authority handshake")
        });
        let config = BrokerDaemonConfig {
            schema: BROKER_DAEMON_CONFIG_SCHEMA.to_string(),
            deployment_id: "deployment-production".to_string(),
            broker_instance_id: "broker-production-1".to_string(),
            tenant_scope: "tenant-production".to_string(),
            audit_runner_id: "enterprise-runner-1".to_string(),
            trusted_audit_runner: Keypair::from_seed(&[97; 32]).public_key(),
            ipc_socket_path: broker_socket.clone(),
            authority_socket_path: authority_socket,
            trusted_capability_issuer: capability_issuer.public_key(),
            trusted_authority: authority_signer.public_key(),
            broker_identity: signing_key.public_key(),
            broker_audience: "broker-service-production".to_string(),
            parent_audience: "parent-service-production".to_string(),
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            provider_placement: ProviderPlacementConfig::BearerAuthorization,
            trusted_service_uid: expected_owner_uid,
            authorized_client_uid: expected_owner_uid,
            ipc_read_timeout_ms: 1_000,
            ipc_write_timeout_ms: 1_000,
            authority_timeout_ms: 1_000,
            maximum_clock_skew_seconds: 30,
            maximum_liveness_snapshot_age_seconds: 30,
            maximum_revocation_snapshot_age_seconds: 30,
            databases: BrokerDaemonDatabaseConfig {
                secret_database_path: directory.path().join("secrets.sqlite3"),
                attempt_database_path: directory.path().join("attempts.sqlite3"),
                admin_replay_database_path: directory.path().join("admin.sqlite3"),
                receipt_database_path: directory.path().join("receipts.sqlite3"),
            },
            enterprise_migration: super::support::enforced_broker_migration(
                directory.path(),
                "deployment-production",
                "generic-https",
            ),
            admin: BrokerDaemonAdminConfig {
                trusted_approvers: vec![approver.public_key()],
                subject: admin_subject.clone(),
                threshold: 1,
                maximum_token_lifetime_seconds: 60,
            },
            privileged_audit: BrokerDaemonPrivilegedAuditConfig {
                socket_path: audit_socket.clone(),
                authorized_runner_uid: expected_owner_uid,
                authorized_runner_gid: rustix::process::getegid().as_raw(),
                read_timeout_ms: 1_000,
                write_timeout_ms: 1_000,
                authorization_lifetime_seconds: 30,
            },
        };
        let config_path = directory.path().join("broker-config.json");
        std::fs::write(
            &config_path,
            canonical_json_bytes(&config).test_expect("config"),
        )
        .test_expect("write config");
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .test_expect("config permissions");
        let mut child = Command::new(env!("CARGO_BIN_EXE_chio-secret-brokerd"))
            .arg("--config")
            .arg(&config_path)
            .arg("--master-key-fd")
            .arg(master_seed.as_raw_fd().to_string())
            .arg("--signing-key-fd")
            .arg(signing_seed.as_raw_fd().to_string())
            .env(
                "CHIO_TEST_CANARY",
                String::from_utf8_lossy(canary).into_owned(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .test_expect("spawn brokerd");
        fcntl_setfd(&master_seed, FdFlags::CLOEXEC).test_expect("restore master cloexec");
        fcntl_setfd(&signing_seed, FdFlags::CLOEXEC).test_expect("restore signing cloexec");
        authority_thread.join().test_expect("authority thread");
        for _ in 0..200 {
            if broker_socket.exists() && audit_socket.exists() {
                break;
            }
            if child.try_wait().test_expect("child status").is_some() {
                panic!("brokerd exited before binding IPC");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(broker_socket.exists());
        assert!(audit_socket.exists());

        let ordinary_tool_frame = canonical_json_bytes(&serde_json::json!({
            "authorization": [1],
            "operation": "status",
            "payload": [1],
            "tenantScope": "tenant-production"
        }))
        .test_expect("ordinary tool frame");
        let mut wrong_endpoint = std::os::unix::net::UnixStream::connect(&audit_socket)
            .test_expect("connect privileged audit socket");
        write_bounded_frame(&mut wrong_endpoint, &ordinary_tool_frame)
            .test_expect("write ordinary operation to audit socket");
        assert!(read_bounded_frame(&mut wrong_endpoint).is_err());
        assert!(child
            .try_wait()
            .test_expect("brokerd status after rejected audit frame")
            .is_none());

        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-process-production".to_string(),
            version: 1,
        };
        let payload =
            encode_credential_mutation_payload(IpcOperation::Provision, &credential, canary)
                .test_expect("payload");
        let intent =
            daemon_admin_intent_digest(IpcOperation::Provision, "tenant-production", &payload)
                .test_expect("intent");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("clock")
            .as_secs();
        let approval = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "process-approval-production".to_string(),
                approver: approver.public_key(),
                subject: admin_subject,
                governed_intent_hash: intent,
                threshold_proposal_hash: Some("dd".repeat(32)),
                request_id: "process-admin-request-production".to_string(),
                issued_at: now.saturating_sub(1),
                expires_at: now + 30,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )
        .test_expect("approval");
        let authorization = GovernedAdminAuthorizationEnvelope::new(vec![approval])
            .test_expect("envelope")
            .canonical_bytes()
            .test_expect("authorization");
        let frame = canonical_ipc_request_bytes(&AuthenticatedIpcRequest {
            operation: IpcOperation::Provision,
            tenant_scope: "tenant-production".to_string(),
            authorization: authorization.into(),
            payload: payload.into(),
        })
        .test_expect("request frame");
        let mut stream =
            std::os::unix::net::UnixStream::connect(&broker_socket).test_expect("connect brokerd");
        write_bounded_frame(&mut stream, &frame).test_expect("write request");
        let response_frame = read_bounded_frame(&mut stream).test_expect("read response");
        let response: IpcResponse =
            serde_json::from_slice(&response_frame).test_expect("response envelope");
        assert!(response.accepted);
        assert!(!response_frame
            .windows(canary.len())
            .any(|window| window == canary));

        child.kill().test_expect("terminate brokerd");
        let output = child.wait_with_output().test_expect("brokerd output");
        assert!(!output
            .stdout
            .windows(canary.len())
            .any(|window| window == canary));
        assert!(!output
            .stderr
            .windows(canary.len())
            .any(|window| window == canary));
        for entry in std::fs::read_dir(directory.path()).test_expect("database directory") {
            let entry = entry.test_expect("directory entry");
            if entry.file_type().test_expect("entry type").is_file() {
                let bytes = std::fs::read(entry.path()).test_expect("read persisted file");
                assert!(!bytes.windows(canary.len()).any(|window| window == canary));
            }
        }
    }
}
