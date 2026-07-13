#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use chio_secret_broker::protocol::{
    BrokerExecuteResponse, BrokerExecutionEvidence, BROKER_EVIDENCE_SCHEMA,
};

#[test]
fn public_response_and_daemon_diagnostics_do_not_contain_seeded_credential() {
    let canary = "credential-canary-7f890f957c";
    let response = BrokerExecuteResponse {
        status: 200,
        headers: Vec::new(),
        body: b"sanitized".to_vec(),
        evidence: BrokerExecutionEvidence {
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
        },
        receipt_reference: "receipt-reference".to_string(),
    };
    let encoded = serde_json::to_vec(&response).expect("response");
    assert!(!encoded
        .windows(canary.len())
        .any(|window| window == canary.as_bytes()));

    let output = Command::new(env!("CARGO_BIN_EXE_chio-secret-brokerd"))
        .env("CHIO_TEST_CANARY", canary)
        .output()
        .expect("daemon");
    assert!(!output
        .stdout
        .windows(canary.len())
        .any(|window| window == canary.as_bytes()));
    assert!(!output
        .stderr
        .windows(canary.len())
        .any(|window| window == canary.as_bytes()));
    assert!(!output.status.success());
    let diagnostics = String::from_utf8(output.stderr).expect("UTF-8 diagnostics");
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
    use chio_core_types::{canonical_json_bytes, Keypair};
    use chio_secret_broker::authority_ipc::{
        AuthorityOperation, AuthorityResult, AuthorityRpcServer, BrokerAuthorityHandler,
    };
    use chio_secret_broker::budget::{ExecutionAuthorityCapabilities, ExecutionAuthorityProfile};
    use chio_secret_broker::daemon::{daemon_admin_intent_digest, CREDENTIAL_MUTATION_SCHEMA};
    use chio_secret_broker::daemon_runtime::{
        BrokerDaemonAdminConfig, BrokerDaemonConfig, BrokerDaemonDatabaseConfig,
        ProviderPlacementConfig, BROKER_DAEMON_CONFIG_SCHEMA,
    };
    use chio_secret_broker::protocol::CredentialRef;
    use chio_secret_broker::provision::GovernedAdminAuthorizationEnvelope;
    use chio_secret_broker::service::{
        read_bounded_frame, write_bounded_frame, IpcOperation, IpcResponse,
    };
    use chio_secret_broker::{BrokerError, Result};
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use rustix::io::{fcntl_setfd, FdFlags};
    use serde::Serialize;

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

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MutationPayload<'a> {
        schema: &'static str,
        mutation: &'static str,
        credential: &'a CredentialRef,
        secret: &'a [u8],
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RequestWire<'a> {
        operation: IpcOperation,
        tenant_scope: &'a str,
        authorization: &'a [u8],
        payload: &'a [u8],
    }

    fn sealed_seed(name: &str, seed: &[u8; 32]) -> File {
        let descriptor = memfd_create(name, MemfdFlags::ALLOW_SEALING).expect("memfd");
        let mut file = File::from(descriptor);
        file.write_all(seed).expect("write seed");
        file.seek(SeekFrom::Start(0)).expect("seek seed");
        fcntl_add_seals(
            &file,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
        )
        .expect("seal seed");
        fcntl_setfd(&file, FdFlags::empty()).expect("inherit seed");
        file
    }

    #[test]
    fn brokerd_process_governed_provisioning_keeps_seeded_secret_inside_broker() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let canary = b"brokerd-linux-process-canary-4f9071";
        let master_seed = sealed_seed("broker-master", &[101; 32]);
        let signing_seed = [102; 32];
        let signing_key = Keypair::from_seed(&signing_seed);
        let signing_seed = sealed_seed("broker-signing", &signing_seed);
        let expected_owner_uid = master_seed.metadata().expect("master metadata").uid();
        let authority_signer = Keypair::from_seed(&[103; 32]);
        let capability_issuer = Keypair::from_seed(&[104; 32]);
        let approver = Keypair::from_seed(&[105; 32]);
        let admin_subject = Keypair::from_seed(&[106; 32]).public_key();
        let authority_socket = directory.path().join("authority.sock");
        let broker_socket = directory.path().join("broker.sock");
        let authority_server = AuthorityRpcServer::bind(
            &authority_socket,
            signing_key.public_key(),
            authority_signer.clone(),
            Arc::new(Authority),
            30,
        )
        .expect("authority server");
        let authority_thread =
            thread::spawn(move || authority_server.serve_one().expect("authority handshake"));
        let config = BrokerDaemonConfig {
            schema: BROKER_DAEMON_CONFIG_SCHEMA.to_string(),
            tenant_scope: "tenant-production".to_string(),
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
            expected_key_owner_uid,
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
            admin: BrokerDaemonAdminConfig {
                trusted_approvers: vec![approver.public_key()],
                subject: admin_subject.clone(),
                threshold: 1,
                maximum_token_lifetime_seconds: 60,
            },
        };
        let config_path = directory.path().join("broker-config.json");
        std::fs::write(&config_path, canonical_json_bytes(&config).expect("config"))
            .expect("write config");
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .expect("config permissions");
        let mut child = Command::new(env!("CARGO_BIN_EXE_chio-secret-brokerd"))
            .arg("--config")
            .arg(&config_path)
            .arg("--master-key-fd")
            .arg(master_seed.as_raw_fd().to_string())
            .arg("--signing-key-fd")
            .arg(signing_seed.as_raw_fd().to_string())
            .env("CHIO_TEST_CANARY", String::from_utf8_lossy(canary).as_ref())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn brokerd");
        fcntl_setfd(&master_seed, FdFlags::CLOEXEC).expect("restore master cloexec");
        fcntl_setfd(&signing_seed, FdFlags::CLOEXEC).expect("restore signing cloexec");
        authority_thread.join().expect("authority thread");
        for _ in 0..200 {
            if broker_socket.exists() {
                break;
            }
            if child.try_wait().expect("child status").is_some() {
                panic!("brokerd exited before binding IPC");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(broker_socket.exists());

        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-process-production".to_string(),
            version: 1,
        };
        let payload = canonical_json_bytes(&MutationPayload {
            schema: CREDENTIAL_MUTATION_SCHEMA,
            mutation: "provision",
            credential: &credential,
            secret: canary,
        })
        .expect("payload");
        let intent =
            daemon_admin_intent_digest(IpcOperation::Provision, "tenant-production", &payload)
                .expect("intent");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
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
        .expect("approval");
        let authorization = GovernedAdminAuthorizationEnvelope::new(vec![approval])
            .expect("envelope")
            .canonical_bytes()
            .expect("authorization");
        let frame = canonical_json_bytes(&RequestWire {
            operation: IpcOperation::Provision,
            tenant_scope: "tenant-production",
            authorization: &authorization,
            payload: &payload,
        })
        .expect("request frame");
        let mut stream =
            std::os::unix::net::UnixStream::connect(&broker_socket).expect("connect brokerd");
        write_bounded_frame(&mut stream, &frame).expect("write request");
        let response_frame = read_bounded_frame(&mut stream).expect("read response");
        let response: IpcResponse =
            serde_json::from_slice(&response_frame).expect("response envelope");
        assert!(response.accepted);
        assert!(!response_frame
            .windows(canary.len())
            .any(|window| window == canary));

        child.kill().expect("terminate brokerd");
        let output = child.wait_with_output().expect("brokerd output");
        assert!(!output
            .stdout
            .windows(canary.len())
            .any(|window| window == canary));
        assert!(!output
            .stderr
            .windows(canary.len())
            .any(|window| window == canary));
        for entry in std::fs::read_dir(directory.path()).expect("database directory") {
            let entry = entry.expect("directory entry");
            if entry.file_type().expect("entry type").is_file() {
                let bytes = std::fs::read(entry.path()).expect("read persisted file");
                assert!(!bytes.windows(canary.len()).any(|window| window == canary));
            }
        }
    }
}
