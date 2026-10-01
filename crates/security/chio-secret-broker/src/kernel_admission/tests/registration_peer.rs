//! Real authenticated Unix transport and a reopened durable broker attempt DB.
//! Provider execution and liveness authority are outside this registration test.
use super::*;
use crate::ipc_client::{BrokerIpcClientConfig, BrokerPeerIdentity};
use crate::registration::{
    verify_register_attempt_authorization, AuthenticatedAttemptRequest,
    RegisterAttemptAcknowledgement, RegisterAttemptAction, SignedRegisterAttemptAuthorization,
};
use crate::service::{
    decode_canonical_ipc_request, read_bounded_frame, write_bounded_frame, IpcOperation,
    IpcResponse,
};
use crate::store::{AttemptRegistration, AttemptStore};
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

pub(super) struct RegistrationPeer {
    pub(super) config: BrokerIpcClientConfig,
    pub(super) misbind_ack: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<std::result::Result<Vec<AttemptRegistration>, String>>>,
}

impl RegistrationPeer {
    pub(super) fn new(directory: &std::path::Path, authority_key: PublicKey) -> TestResult<Self> {
        let socket_path = directory.join("broker.sock");
        let database = directory.join("broker-attempts.db");
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let misbind_ack = Arc::new(AtomicBool::new(false));
        let misbinding = misbind_ack.clone();
        let worker = std::thread::spawn(move || {
            let serve = || -> TestResult<Vec<AttemptRegistration>> {
                let mut registrations = Vec::new();
                while !stopping.load(Ordering::SeqCst) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(stream) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let wire = decode_canonical_ipc_request(&read_bounded_frame(&mut stream)?)?;
                    assert_eq!(wire.operation, IpcOperation::RegisterAttempt);
                    assert_eq!(wire.tenant_scope, "broker-kernel-test");
                    let attempt: AuthenticatedAttemptRequest =
                        serde_json::from_slice(wire.payload.as_slice())?;
                    let authorization: SignedRegisterAttemptAuthorization =
                        serde_json::from_slice(wire.authorization.as_slice())?;
                    let now = crate::daemon::SystemDaemonClock.now_unix_seconds()?;
                    verify_register_attempt_authorization(
                        &authorization,
                        &attempt.registration,
                        RegisterAttemptAction::Register,
                        &wire.tenant_scope,
                        &authority_key,
                        now,
                        2,
                    )?;
                    assert_eq!(
                        attempt.registration.request_canonical_digest,
                        crate::registration::broker_execute_request_registration_digest(
                            &attempt.request
                        )?
                    );
                    let store = crate::sqlite::SqliteAttemptStore::open(&database)?;
                    let outcome = store.register_intent(&attempt.registration, now)?;
                    let mut acknowledgement =
                        RegisterAttemptAcknowledgement::from_outcome(outcome, now)?;
                    drop(store);
                    let reopened = crate::sqlite::SqliteAttemptStore::open(&database)?;
                    assert_eq!(
                        reopened
                            .load_attempt(&attempt.registration.ids.attempt_id)?
                            .ok_or("lost registration")?
                            .registration,
                        attempt.registration
                    );
                    drop(reopened);
                    if misbinding.load(Ordering::SeqCst) {
                        acknowledgement.operation_id.push_str("-substituted");
                    }
                    let response = IpcResponse {
                        operation: IpcOperation::RegisterAttempt,
                        accepted: true,
                        response: canonical_json_bytes(&acknowledgement)?,
                        error_code: None,
                    };
                    write_bounded_frame(&mut stream, &canonical_json_bytes(&response)?)?;
                    registrations.push(attempt.registration);
                }
                Ok(registrations)
            };
            serve().map_err(|error| error.to_string())
        });
        Ok(Self {
            config: BrokerIpcClientConfig {
                socket_path,
                tenant_scope: "broker-kernel-test".into(),
                timeout_ms: 2000,
                expected_peer: BrokerPeerIdentity {
                    process_id: std::process::id(),
                    user_id: rustix::process::geteuid().as_raw(),
                    group_id: rustix::process::getegid().as_raw(),
                },
                trusted_receipt_signer: Keypair::from_seed(&[35; 32]).public_key(),
            },
            misbind_ack,
            stop,
            worker: Some(worker),
        })
    }

    pub(super) fn finish(&mut self) -> TestResult<Vec<AttemptRegistration>> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .ok_or("registration peer already stopped")?
            .join()
            .map_err(|_| "registration peer panicked")?
            .map_err(Into::into)
    }
}

impl Drop for RegistrationPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
