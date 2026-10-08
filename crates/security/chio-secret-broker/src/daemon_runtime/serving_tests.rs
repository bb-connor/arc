//! The daemon keeps serving after faults its endpoints contain to one
//! request, stops on a fault in its own state, and honors a stop request
//! within its serving wait.

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use chio_core_types::Keypair;
use chio_store_sqlite::BlobStoreError;
use chio_test_support::prelude::*;

use super::*;
use crate::service::{
    canonical_ipc_request_bytes, read_bounded_frame, write_bounded_frame, AuthenticatedIpcRequest,
    BrokerIpcHandler, IpcOperation, IpcResponse,
};
use crate::{BrokerFaultDisposition, CredentialStoreError};

/// Answers each attempt registration with the next scripted result.
struct ScriptedHandler {
    results: Mutex<VecDeque<Result<()>>>,
}

impl ScriptedHandler {
    fn next(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        let next = self
            .results
            .lock()
            .map_err(|_| BrokerError::Invariant("script lock poisoned".into()))?
            .pop_front()
            .ok_or_else(|| BrokerError::Invariant("script exhausted".into()))?;
        next.map(|()| IpcResponse {
            operation: request.operation,
            accepted: true,
            response: b"registered".to_vec(),
            error_code: None,
        })
    }
}

fn unsupported() -> Result<IpcResponse> {
    Err(BrokerError::AuthorizationDenied(
        "operation is not scripted".into(),
    ))
}

impl BrokerIpcHandler for ScriptedHandler {
    fn register_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.next(request)
    }
    fn prepare_dispatch(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn release_attempt(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn issue(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn revoke(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn status(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn execute(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn provision(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn rotate(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn disable(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
    fn delete(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        unsupported()
    }
}

/// An audit handler for a daemon whose audit socket stays idle.
struct IdleAuditHandler;

impl BrokerPrivilegedAuditHandler for IdleAuditHandler {
    fn now_unix_seconds(&self) -> Result<u64> {
        Ok(100)
    }

    fn compare(
        &self,
        _request: &BrokerExecuteRequest,
        _reference: BrokerAuditReferenceRequest,
        _runner_authorization: &SignedBrokerAuditRunnerAuthorization,
        _admin_authorization: &AdminAuthorization,
    ) -> Result<CompletedBrokerAuditComparison> {
        Err(BrokerError::Invariant(
            "no audit session is expected".into(),
        ))
    }
}

struct Daemon {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    endpoint: UnixBrokerEndpoint,
    audit: BrokerPrivilegedAuditEndpoint,
}

fn daemon(results: Vec<Result<()>>) -> Daemon {
    let directory = crate::private_tempdir().test_expect("daemon directory");
    let root = std::fs::canonicalize(directory.path()).test_expect("canonical directory");
    let ipc = root.join("ipc");
    std::fs::create_dir(&ipc).test_expect("IPC directory");
    std::fs::set_permissions(&ipc, std::fs::Permissions::from_mode(0o700))
        .test_expect("private IPC directory");
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let socket = ipc.join("broker.sock");
    let endpoint = UnixBrokerEndpoint::bind(
        &socket,
        Arc::new(ScriptedHandler {
            results: Mutex::new(results.into()),
        }),
        uid,
        uid,
    )
    .test_expect("broker endpoint");
    let audit = BrokerPrivilegedAuditEndpoint::bind(
        BrokerPrivilegedAuditEndpointConfig {
            socket_path: root.join("audit").join("audit.sock"),
            trusted_service_uid: uid,
            authorized_runner_uid: uid,
            authorized_runner_gid: gid,
            read_timeout_ms: 1_000,
            write_timeout_ms: 1_000,
            authorization_lifetime_seconds: 60,
            deployment_id: "test-deployment".to_string(),
            broker_instance_id: "test-broker-instance".to_string(),
            tenant_scope: "tenant-a".to_string(),
            runner_id: "test-enterprise-runner".to_string(),
        },
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[7; 32]))),
        Arc::new(IdleAuditHandler),
    )
    .test_expect("audit endpoint");
    Daemon {
        _directory: directory,
        socket,
        endpoint,
        audit,
    }
}

/// Send one attempt registration and return the decoded response, or `None`
/// when the daemon closed the connection without one.
fn register(socket: &Path) -> Option<IpcResponse> {
    let mut stream = UnixStream::connect(socket).test_expect("connect broker");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .test_expect("client read bound");
    let request = AuthenticatedIpcRequest {
        operation: IpcOperation::RegisterAttempt,
        tenant_scope: "tenant-a".to_string(),
        authorization: vec![1].into(),
        payload: vec![2].into(),
    };
    let frame = canonical_ipc_request_bytes(&request).test_expect("canonical request");
    write_bounded_frame(&mut stream, &frame).test_expect("send request");
    let response = read_bounded_frame(&mut stream).ok()?;
    Some(serde_json::from_slice(&response).test_expect("decode response"))
}

fn is_denied(response: &IpcResponse, code: &str) -> bool {
    !response.accepted && response.error_code.as_deref() == Some(code)
}

#[test]
fn contained_request_faults_do_not_stop_the_daemon_and_a_stop_request_ends_it_promptly() {
    let missing_credential = BrokerError::CredentialUnavailable(CredentialStoreError::for_test(
        BlobStoreError::NotFound,
    ));
    let fixture = daemon(vec![
        Err(missing_credential),
        Err(BrokerError::AuthorityUnavailable(
            "authority offline".into(),
        )),
        Err(BrokerError::Conflict("attempt already registered".into())),
        Ok(()),
    ]);
    let shutdown = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let served = scope
            .spawn(|| serve_endpoints_until_stopped(&fixture.endpoint, &fixture.audit, &shutdown));
        let responses = (0..4)
            .map(|_| register(&fixture.socket).test_expect("the daemon answers every request"))
            .collect::<Vec<_>>();
        assert!(
            is_denied(&responses[0], "authorization_denied"),
            "{responses:?}"
        );
        assert!(
            is_denied(&responses[1], "authority_unavailable"),
            "{responses:?}"
        );
        assert!(is_denied(&responses[2], "conflict"), "{responses:?}");
        assert!(responses[3].accepted, "{responses:?}");

        let requested = Instant::now();
        shutdown.store(true, Ordering::Release);
        let result = served.join().test_expect("daemon thread");
        assert!(result.is_ok(), "{result:?}");
        let elapsed = requested.elapsed();
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    });
}

#[test]
fn a_fault_in_the_brokers_own_state_stops_the_daemon_without_a_stop_request() {
    let corrupt_credential = BrokerError::CredentialStorage(CredentialStoreError::for_test(
        BlobStoreError::InvalidReference,
    ));
    for (fault, expected) in [
        (
            BrokerError::Storage("attempt store failed".into()),
            "storage",
        ),
        (corrupt_credential, "storage"),
        (
            BrokerError::Invariant("attempt journal broken".into()),
            "invariant",
        ),
    ] {
        let fixture = daemon(vec![Err(fault)]);
        let shutdown = AtomicBool::new(false);
        let (finished, watchdog) = mpsc::channel::<()>();
        std::thread::scope(|scope| {
            // Bound the test: a daemon that keeps serving is stopped, and then
            // reports a clean exit instead of the expected failure.
            let stop = &shutdown;
            scope.spawn(move || {
                if watchdog.recv_timeout(Duration::from_secs(10)).is_err() {
                    stop.store(true, Ordering::Release);
                }
            });
            let served = scope.spawn(|| {
                serve_endpoints_until_stopped(&fixture.endpoint, &fixture.audit, &shutdown)
            });
            assert!(register(&fixture.socket).is_none());
            let result = served.join().test_expect("daemon thread");
            let _ = finished.send(());
            let error = result.test_expect_err("a fatal fault ends the daemon");
            assert_eq!(error.diagnostic_code(), expected, "{error:?}");
            assert_eq!(error.disposition(), BrokerFaultDisposition::Fatal);
        });
    }
}
