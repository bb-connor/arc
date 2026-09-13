use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair, PublicKey};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationScopeKind,
    EnterpriseMigrationStage, EnterpriseMigrationStateStore, EnterpriseMigrationTransitionBody,
};
use chio_store_sqlite::{
    sign_enterprise_migration_transition, SqliteEnterpriseMigrationOpenPolicy,
    SqliteEnterpriseMigrationStateStore,
};
use chio_test_support::prelude::*;
use rand_core::{OsRng, RngCore};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
use rustix::io::{fcntl_getfd, FdFlags};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_ipc::{
    AuthorityOperation, AuthorityResult, AuthorityRpcServer, BrokerAuthorityHandler,
};
use crate::budget::{
    canonicalize_quotas, CombinedCaptureCommit, ExecutionAuthorityCapabilities,
    ExecutionAuthorityProfile, ExecutionHoldState, ExecutionQuota,
};
use crate::capability::{capability_digest, issue_capability};
use crate::daemon::{daemon_admin_intent_digest, encode_credential_mutation_payload};
use crate::daemon_runtime::{
    harden_broker_process_custody, secure_inherited_key_file, BrokerDaemonAdminConfig,
    BrokerDaemonConfig, BrokerDaemonDatabaseConfig, BrokerDaemonMigrationConfig,
    BrokerDaemonPrivilegedAuditConfig, BrokerDaemonRuntime, ProviderPlacementConfig,
    BROKER_DAEMON_CONFIG_SCHEMA,
};
use crate::generic_https::{
    DestinationResolver, GenericHttpsExecutor, NetworkPolicy, RustlsPinnedHttpsTransport,
};
use crate::inherited_fd::adopt_inherited_key_file;
use crate::ipc_client::{
    BrokerIpcClient, BrokerIpcClientConfig, BrokerIpcExecutionOutcome, BrokerPeerIdentity,
};
use crate::migration::production_broker_migration_posture_digest;
use crate::proof::{
    body_digest, caller_header_digest, caller_option_digest, issue_request_proof, proof_digest,
};
use crate::protocol::{
    AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerExecuteRequest,
    BrokerExecuteResponse, BrokerRequest, CallerOptions, CredentialRef, ProofBinding, ProofMode,
    RedirectPolicy, RequestConstraints, BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    MAX_WIRE_BYTES,
};
use crate::provision::GovernedAdminAuthorizationEnvelope;
use crate::receipt::{
    credential_reference_hash, receipt_digest, verify_execution_receipt, BrokerExecutionOutcome,
    BrokerReceiptSink, SqliteBrokerReceiptSink,
};
use crate::registration::{broker_execute_request_registration_digest, prepared_dispatch_id};
use crate::revocation::{BrokerRevocationSnapshot, LiveParentCapability};
use crate::service::{
    broker_request_digest, canonical_ipc_request_bytes, read_bounded_frame, write_bounded_frame,
    AuthenticatedIpcRequest, IpcOperation, IpcResponse, TrustedExecutionContext,
};
use crate::store::{derive_attempt_ids_for_operation, AttemptRegistration};
use crate::{BrokerError, Result};

const ROLE_ENV: &str = "CHIO_BOUNDARY_ROLE";
const CONFIG_ENV: &str = "CHIO_BOUNDARY_CONFIG";
const CERT_ENV: &str = "CHIO_BOUNDARY_CERT";
const KEY_ENV: &str = "CHIO_BOUNDARY_KEY";
const MASTER_FD_ENV: &str = "CHIO_BOUNDARY_MASTER_FD";
const SIGNING_FD_ENV: &str = "CHIO_BOUNDARY_SIGNING_FD";
const REQUEST_ENV: &str = "CHIO_BOUNDARY_REQUEST_HEX";
const CANARY_LENGTH_ENV: &str = "CHIO_BOUNDARY_CANARY_LENGTH";
const CANARY_DIGEST_ENV: &str = "CHIO_BOUNDARY_CANARY_SHA256";
const BROKER_PID_ENV: &str = "CHIO_BOUNDARY_BROKER_PID";
const RECEIPT_SIGNER_ENV: &str = "CHIO_BOUNDARY_RECEIPT_SIGNER_HEX";
const FALLBACK_MARKER_ENV: &str = "CHIO_BOUNDARY_FALLBACK_MARKER";

const BROKER_HELPER: &str = "process_boundary_tests::broker_daemon_helper_process";
const TOOL_HELPER: &str = "process_boundary_tests::calling_tool_helper_process";
const UPSTREAM_HELPER: &str = "process_boundary_tests::fake_upstream_helper_process";
const TOOL_REPORT_PREFIX: &str = "CHIO_BOUNDARY_TOOL_REPORT ";
const UPSTREAM_REPORT_PREFIX: &str = "CHIO_BOUNDARY_UPSTREAM_REPORT ";
const TOOL_LOG_MARKER: &str = "CHIO_BOUNDARY_TOOL_LOG fixed_event=execute_complete";
const TOOL_PANIC_MARKER: &str = "CHIO_BOUNDARY_TOOL_PANIC_FIXED";
const FALLBACK_MARKER: &str = "CHIO_BOUNDARY_BROKER_UNAVAILABLE_NO_FALLBACK";

const TENANT_SCOPE: &str = "tenant-process-boundary";
const BROKER_AUDIENCE: &str = "broker-process-boundary";
const PARENT_AUDIENCE: &str = "parent-process-boundary";
const DEPLOYMENT_ID: &str = "deployment-process-boundary";
const BROKER_INSTANCE_ID: &str = "broker-process-boundary-1";
const CREDENTIAL_PROVIDER: &str = "generic-https";
const CREDENTIAL_ID: &str = "credential-process-boundary";
const PROVIDER_ADAPTER_ID: &str = "generic-bearer";
const OPERATION_ID: &str = "kernel-operation-process-boundary";
const AUTHORITY_DOMAIN: &str = "authority-domain-process-boundary";
const BROKER_QUOTA_KEY: &str = "broker-quota-process-boundary";
const PARENT_QUOTA_KEY: &str = "parent-quota-process-boundary";
const UPSTREAM_HOST: &str = "boundary-upstream.test";
const UPSTREAM_PATH_AND_QUERY: &str = "/boundary?mode=process-boundary";
const UPSTREAM_REQUEST_BODY: &[u8] = b"{\"boundary\":true}";
const MAX_SCANNED_FILE_BYTES: u64 = 16 * 1_048_576;
const TOOL_SCANNED_SURFACES: [&str; 19] = [
    "argv",
    "environment",
    "proc_self_cmdline",
    "proc_self_environ",
    "ipc_request",
    "ipc_response",
    "execute_response",
    "receipt",
    "temp_readable_files",
    "self_fd_targets_and_files",
    "broker_cmdline",
    "broker_environ_access_denied",
    "broker_fd_access_denied",
    "broker_mem_access_denied",
    "ptrace_capability_absent",
    "tool_stdout",
    "tool_stderr",
    "structured_log",
    "panic_output",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ToolBoundaryReport {
    schema: String,
    request_frame_hex: String,
    response_frame_hex: String,
    execute_response_hex: String,
    receipt_hex: String,
    scanned_surfaces: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpstreamBoundaryReport {
    schema: String,
    method: String,
    path_and_query: String,
    http_version: String,
    host: String,
    header_names: Vec<String>,
    body_hex: String,
    body_sha256: String,
    credential_matches: usize,
    authorization_header_count: usize,
    authorization_exact_bearer_canary: bool,
    content_length_header_count: usize,
    transfer_encoding_header_count: usize,
    connection_count: usize,
    request_sha256: String,
}

#[derive(Clone)]
struct CanaryProbe {
    length: usize,
    sha256: [u8; 32],
}

impl CanaryProbe {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len(),
            sha256: Sha256::digest(bytes).into(),
        }
    }

    fn from_environment() -> Self {
        let length = required_environment(CANARY_LENGTH_ENV)
            .parse::<usize>()
            .test_expect("canary length");
        let digest = hex::decode(required_environment(CANARY_DIGEST_ENV))
            .test_expect("canary digest encoding");
        let sha256: [u8; 32] = digest
            .try_into()
            .map_err(|_| "canary digest length")
            .test_expect("canary digest length");
        assert!(length >= 32);
        Self { length, sha256 }
    }

    fn matching_offsets(&self, bytes: &[u8]) -> Vec<usize> {
        if self.length == 0 || bytes.len() < self.length {
            return Vec::new();
        }
        bytes
            .windows(self.length)
            .enumerate()
            .filter_map(|(offset, candidate)| {
                let digest: [u8; 32] = Sha256::digest(candidate).into();
                (digest == self.sha256).then_some(offset)
            })
            .collect()
    }

    fn assert_absent(&self, bytes: &[u8], surface: &str) {
        assert!(
            self.matching_offsets(bytes).is_empty(),
            "credential canary crossed {surface}"
        );
    }
}

fn required_environment(name: &str) -> String {
    std::env::var(name).test_expect("required process-boundary environment")
}

fn install_fixed_panic_hook(marker: &'static str) {
    std::panic::set_hook(Box::new(move |_| eprintln!("{marker}")));
}

mod fixture;
mod orchestration;
mod roles;

#[test]
fn broker_daemon_helper_process() {
    if std::env::var(ROLE_ENV).as_deref() != Ok("broker") {
        return;
    }
    install_fixed_panic_hook("CHIO_BOUNDARY_BROKER_PANIC_FIXED");
    roles::run_broker_helper().test_expect("broker helper failed");
}

#[test]
fn calling_tool_helper_process() {
    match std::env::var(ROLE_ENV).as_deref() {
        Ok("tool") => {
            install_fixed_panic_hook(TOOL_PANIC_MARKER);
            roles::run_calling_tool_helper();
            std::panic::panic_any(());
        }
        Ok("tool_unavailable") => {
            install_fixed_panic_hook("CHIO_BOUNDARY_UNAVAILABLE_TOOL_PANIC_FIXED");
            roles::run_unavailable_tool_helper();
        }
        _ => {}
    }
}

#[test]
fn fake_upstream_helper_process() {
    if std::env::var(ROLE_ENV).as_deref() != Ok("upstream") {
        return;
    }
    install_fixed_panic_hook("CHIO_BOUNDARY_UPSTREAM_PANIC_FIXED");
    roles::run_fake_upstream_helper();
}

#[test]
fn tool_process_never_receives_broker_credential_and_cannot_fallback_after_broker_death() {
    orchestration::run_boundary_test();
}
