use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chio_control_plane::security::{
    ActiveResponseAuthorityProtocolServer, ActiveResponseAuthorityProtocolServerConfig,
};
use chio_core::{Ed25519Backend, Keypair, SigningBackend};
use chio_secure_ipc::{
    InheritedSecretFile, SecureIpcError, SecureUnixListener, SecureUnixListenerConfig,
};
use zeroize::Zeroizing;

use crate::{
    AuthorityError, AuthorityRuntimeConfig, AuthorityStore, PreAdmittedAuthorityHandler, Result,
};

pub struct AuthorityDaemonRuntime {
    config: AuthorityRuntimeConfig,
    listener: Arc<SecureUnixListener>,
    server: Arc<ActiveResponseAuthorityProtocolServer>,
}

impl AuthorityDaemonRuntime {
    pub fn build(config: AuthorityRuntimeConfig, signing_key: InheritedSecretFile) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(AuthorityError::Runtime(
                "active-response authority runtime requires Linux".to_string(),
            ));
        }
        config.validate_for_current_process()?;
        signing_key
            .validate_private_regular_file(config.trusted_service_uid, "authority signing key")
            .map_err(|error| AuthorityError::Custody(error.to_string()))?;
        let keypair = read_keypair(signing_key.into_file())?;
        if keypair.public_key() != config.authority_identity {
            return Err(AuthorityError::Custody(
                "signing key does not match the configured authority identity".to_string(),
            ));
        }
        let store = Arc::new(AuthorityStore::open(
            &config.store_path,
            config.trusted_service_uid,
            config.deployment_digest,
            config.store_digest,
            &config.authority_identity,
        )?);
        let handler = Arc::new(PreAdmittedAuthorityHandler::new(store));
        let signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(keypair));
        let server = Arc::new(
            ActiveResponseAuthorityProtocolServer::new(
                ActiveResponseAuthorityProtocolServerConfig {
                    expected_client_peer: config.expected_client_peer,
                    trusted_client: config.trusted_client.clone(),
                    deployment_digest: config.deployment_digest,
                    store_digest: config.store_digest,
                    timeout_ms: config.timeout_ms,
                    maximum_clock_skew_seconds: config.maximum_clock_skew_seconds,
                    maximum_replay_entries: config.maximum_replay_entries,
                },
                signer,
                handler,
            )
            .map_err(AuthorityError::InvalidConfig)?,
        );
        let listener = Arc::new(
            SecureUnixListener::bind(SecureUnixListenerConfig {
                socket_path: config.socket_path.clone(),
                trusted_service_uid: config.trusted_service_uid,
                expected_peer: config.expected_client_peer,
            })
            .map_err(|error| AuthorityError::Custody(error.to_string()))?,
        );
        Ok(Self {
            config,
            listener,
            server,
        })
    }

    pub fn serve(self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.serve_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(AuthorityError::Runtime(
                "active-response authority runtime requires Linux".to_string(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn serve_linux(self) -> Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        install_signal_waiter(Arc::clone(&stop))?;
        self.listener
            .set_nonblocking(true)
            .map_err(|error| AuthorityError::Runtime(error.to_string()))?;
        let (sender, receiver) = mpsc::sync_channel(self.config.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let fatal = Arc::new(Mutex::new(None::<String>));
        let workers = spawn_workers(
            self.config.worker_count,
            Arc::clone(&receiver),
            Arc::clone(&self.server),
            Arc::clone(&stop),
            Arc::clone(&fatal),
        )?;
        let accept_result = self.accept_until_stopped(&sender, &stop, &fatal);
        drop(sender);
        let mut worker_panicked = false;
        for worker in workers {
            worker_panicked |= worker.join().is_err();
        }
        if worker_panicked {
            return Err(AuthorityError::Runtime(
                "one or more authority workers panicked".to_string(),
            ));
        }
        accept_result?;
        let fatal = fatal
            .lock()
            .map_err(|_| AuthorityError::Invariant("fatal-state mutex was poisoned".to_string()))?;
        if let Some(message) = fatal.as_ref() {
            return Err(AuthorityError::Runtime(message.clone()));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn accept_until_stopped(
        &self,
        sender: &SyncSender<std::os::unix::net::UnixStream>,
        stop: &Arc<AtomicBool>,
        fatal: &Arc<Mutex<Option<String>>>,
    ) -> Result<()> {
        while !stop.load(Ordering::Acquire) {
            match self.listener.try_accept_authenticated() {
                Ok(Some(stream)) => match sender.try_send(stream) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_stream)) => {}
                    Err(TrySendError::Disconnected(_stream)) => {
                        return Err(AuthorityError::Runtime(
                            "all authority workers stopped".to_string(),
                        ))
                    }
                },
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(SecureIpcError::UnauthorizedPeer) => {}
                Err(error) => {
                    set_fatal(fatal, stop, format!("authenticated accept failed: {error}"));
                }
            }
        }
        Ok(())
    }
}

fn read_keypair(mut file: File) -> Result<Keypair> {
    let metadata = file.metadata().map_err(|error| {
        AuthorityError::Custody(format!("authority signing key metadata failed: {error}"))
    })?;
    if metadata.len() != 32 {
        return Err(AuthorityError::Custody(
            "authority signing key must contain exactly 32 bytes".to_string(),
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        AuthorityError::Custody(format!("authority signing key rewind failed: {error}"))
    })?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    file.read_exact(seed.as_mut()).map_err(|error| {
        AuthorityError::Custody(format!("authority signing key read failed: {error}"))
    })?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|error| {
        AuthorityError::Custody(format!(
            "authority signing key length check failed: {error}"
        ))
    })? != 0
    {
        return Err(AuthorityError::Custody(
            "authority signing key must contain exactly 32 bytes".to_string(),
        ));
    }
    Ok(Keypair::from_seed(&seed))
}

#[cfg(target_os = "linux")]
fn install_signal_waiter(stop: Arc<AtomicBool>) -> Result<()> {
    use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow, Signal};

    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .map_err(|error| AuthorityError::Runtime(format!("signal mask failed: {error}")))?;
    thread::Builder::new()
        .name("authority-signal".to_string())
        .spawn(move || {
            let _signal = signals.wait();
            stop.store(true, Ordering::Release);
        })
        .map_err(|error| AuthorityError::Runtime(format!("signal thread failed: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_workers(
    count: usize,
    receiver: Arc<Mutex<Receiver<std::os::unix::net::UnixStream>>>,
    server: Arc<ActiveResponseAuthorityProtocolServer>,
    stop: Arc<AtomicBool>,
    fatal: Arc<Mutex<Option<String>>>,
) -> Result<Vec<thread::JoinHandle<()>>> {
    let mut workers = Vec::with_capacity(count);
    for index in 0..count {
        let receiver = Arc::clone(&receiver);
        let server = Arc::clone(&server);
        let stop = Arc::clone(&stop);
        let fatal = Arc::clone(&fatal);
        let worker = thread::Builder::new()
            .name(format!("authority-worker-{index}"))
            .spawn(move || worker_loop(&receiver, &server, &stop, &fatal))
            .map_err(|error| AuthorityError::Runtime(format!("worker spawn failed: {error}")))?;
        workers.push(worker);
    }
    Ok(workers)
}

#[cfg(target_os = "linux")]
fn worker_loop(
    receiver: &Mutex<Receiver<std::os::unix::net::UnixStream>>,
    server: &ActiveResponseAuthorityProtocolServer,
    stop: &Arc<AtomicBool>,
    fatal: &Arc<Mutex<Option<String>>>,
) {
    loop {
        if fatal.lock().is_ok_and(|state| state.is_some()) {
            return;
        }
        let received = match receiver.lock() {
            Ok(receiver) => receiver.recv_timeout(Duration::from_millis(50)),
            Err(_) => {
                set_fatal(
                    fatal,
                    stop,
                    "authority queue mutex was poisoned".to_string(),
                );
                return;
            }
        };
        match received {
            Ok(stream) => {
                if let Err(error) = server.serve_one(stream) {
                    set_fatal(fatal, stop, format!("protocol server failed: {error}"));
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) if stop.load(Ordering::Acquire) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn set_fatal(fatal: &Mutex<Option<String>>, stop: &AtomicBool, message: String) {
    if let Ok(mut state) = fatal.lock() {
        if state.is_none() {
            *state = Some(message);
        }
    }
    stop.store(true, Ordering::Release);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use chio_control_plane::security::{
        AttestedFindingResponsePolicyPlanner, ProductionActiveResponseAuthorityClient,
        ProductionActiveResponseAuthorityFileConfig, ACTIVE_RESPONSE_AUTHORITY_SCHEMA,
    };
    use chio_core::canonical_json_bytes;
    use chio_secure_ipc::{harden_process_custody, PeerIdentity};
    use chio_security_types::ports::Digest32;
    use chio_test_support::prelude::*;
    use rustix::io::{fcntl_setfd, FdFlags};

    use super::*;
    use crate::store::{build_empty_store_for_process_test, empty_store_digest_for_process_test};
    use crate::{
        ActiveDefenseDeploymentConfig, ActiveDefenseDeploymentStage, SecretBrokerDeploymentBinding,
        ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA, AUTHORITY_RUNTIME_CONFIG_SCHEMA,
    };

    const PROCESS_ROLE_ENV: &str = "CHIO_RESPONSE_AUTHORITY_TEST_ROLE";
    const PROCESS_CONFIG_ENV: &str = "CHIO_RESPONSE_AUTHORITY_TEST_CONFIG";
    const PROCESS_SIGNING_FD_ENV: &str = "CHIO_RESPONSE_AUTHORITY_TEST_SIGNING_FD";
    const PROCESS_SOCKET_ENV: &str = "CHIO_RESPONSE_AUTHORITY_TEST_SOCKET";
    const PROCESS_HELPER_TEST: &str = "runtime::tests::active_response_authority_helper_process";
    const UNAUTHORIZED_HELPER_TEST: &str =
        "runtime::tests::unauthorized_authority_client_helper_process";

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _kill_result = self.0.kill();
            let _wait_result = self.0.wait();
        }
    }

    #[test]
    fn signing_key_reader_requires_exact_file_length_and_ignores_inherited_offset() {
        let mut valid = tempfile::tempfile().test_expect("valid signing key file");
        valid
            .write_all(&[7; 32])
            .test_expect("write valid signing key");
        valid
            .seek(SeekFrom::End(0))
            .test_expect("move inherited key offset");
        assert_eq!(
            read_keypair(valid)
                .test_expect("read exact signing key")
                .public_key(),
            Keypair::from_seed(&[7; 32]).public_key()
        );

        let mut oversized = tempfile::tempfile().test_expect("oversized signing key file");
        oversized
            .write_all(&[8; 33])
            .test_expect("write oversized signing key");
        oversized
            .seek(SeekFrom::Start(1))
            .test_expect("move oversized key offset");
        assert!(read_keypair(oversized).is_err());
    }

    #[test]
    #[ignore = "helper process launched by the process-boundary test"]
    fn active_response_authority_helper_process() {
        if std::env::var(PROCESS_ROLE_ENV).as_deref() != Ok("authority") {
            return;
        }
        let config_path = PathBuf::from(
            std::env::var(PROCESS_CONFIG_ENV).test_expect("authority helper config path"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !config_path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        harden_process_custody().test_expect("harden authority helper process");
        let config =
            crate::load_runtime_config(&config_path).test_expect("load authority helper config");
        let descriptor = std::env::var(PROCESS_SIGNING_FD_ENV)
            .test_expect("authority helper signing descriptor")
            .parse::<u32>()
            .test_expect("parse authority helper signing descriptor");
        // SAFETY: the parent transferred this descriptor exclusively for the
        // helper launch and does not use the child process's descriptor table.
        #[allow(unsafe_code)]
        let signing_key = unsafe { InheritedSecretFile::adopt(descriptor, "test signing key") }
            .test_expect("adopt authority helper signing key");
        AuthorityDaemonRuntime::build(config, signing_key)
            .test_expect("build authority helper runtime")
            .serve()
            .test_expect("serve authority helper runtime");
    }

    #[test]
    #[ignore = "helper process launched by the process-boundary test"]
    fn unauthorized_authority_client_helper_process() {
        if std::env::var(PROCESS_ROLE_ENV).as_deref() != Ok("unauthorized-client") {
            return;
        }
        let socket_path = PathBuf::from(
            std::env::var(PROCESS_SOCKET_ENV).test_expect("unauthorized client socket path"),
        );
        let _stream = UnixStream::connect(socket_path)
            .test_expect("unauthorized client reaches authority socket");
    }

    #[test]
    fn daemon_health_crosses_an_authenticated_process_boundary() {
        let directory = tempfile::tempdir().test_expect("authority process directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .test_expect("private authority process directory");
        let authority = Keypair::from_seed(&[0x62; 32]);
        let client = Keypair::from_seed(&[0x63; 32]);
        let receipt_signer = Keypair::from_seed(&[0x64; 32]);
        let store_path = directory.path().join("authority.sqlite3");
        let store_digest = empty_store_digest_for_process_test(&authority.public_key())
            .test_expect("compute empty process-boundary store digest");

        let key_path = directory.path().join("authority.seed");
        let mut key_options = OpenOptions::new();
        key_options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600);
        let mut signing_key = key_options
            .open(&key_path)
            .test_expect("create authority process signing key");
        signing_key
            .write_all(&[0x62; 32])
            .and_then(|()| signing_key.sync_all())
            .test_expect("write authority process signing key");
        signing_key
            .seek(SeekFrom::Start(0))
            .test_expect("rewind authority process signing key");
        fcntl_setfd(&signing_key, FdFlags::empty())
            .test_expect("make authority signing key inheritable");
        let raw_descriptor = signing_key.as_raw_fd();

        let config_path = directory.path().join("authority.json");
        let socket_path = directory.path().join("authority.sock");
        let mut command = Command::new(std::env::current_exe().test_expect("current test binary"));
        command
            .arg(PROCESS_HELPER_TEST)
            .arg("--exact")
            .arg("--ignored")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(PROCESS_ROLE_ENV, "authority")
            .env(PROCESS_CONFIG_ENV, &config_path)
            .env(PROCESS_SIGNING_FD_ENV, raw_descriptor.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child_result = command.spawn();
        fcntl_setfd(&signing_key, FdFlags::CLOEXEC)
            .test_expect("restore signing key close-on-exec");
        let child = child_result.test_expect("spawn authority helper process");
        let service_identity = PeerIdentity {
            process_id: child.id(),
            user_id: rustix::process::geteuid().as_raw(),
            group_id: rustix::process::getegid().as_raw(),
        };
        let client_identity = PeerIdentity {
            process_id: std::process::id(),
            user_id: rustix::process::geteuid().as_raw(),
            group_id: rustix::process::getegid().as_raw(),
        };
        let mut child = ChildGuard(child);
        let mut deployment = ActiveDefenseDeploymentConfig {
            schema: ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA.to_string(),
            deployment_digest: Digest32::new([0; 32]),
            response_authority: AuthorityRuntimeConfig {
                schema: AUTHORITY_RUNTIME_CONFIG_SCHEMA.to_string(),
                protocol: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
                socket_path: socket_path.clone(),
                store_path: store_path.clone(),
                trusted_service_uid: service_identity.user_id,
                service_identity,
                expected_client_peer: client_identity,
                trusted_client: client.public_key(),
                authority_identity: authority.public_key(),
                deployment_digest: Digest32::new([0; 32]),
                store_digest,
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 5,
                maximum_replay_entries: 128,
                worker_count: 2,
                queue_capacity: 4,
            },
            secret_broker: SecretBrokerDeploymentBinding {
                service_identity: client_identity,
                active_response_client_identity: client.public_key(),
                receipt_signing_identity: receipt_signer.public_key(),
                normal_socket_path: directory.path().join("broker.sock"),
                audit_socket_path: directory.path().join("broker-audit.sock"),
                database_paths: vec![directory.path().join("broker.sqlite3")],
                stage: ActiveDefenseDeploymentStage::Shadow,
            },
        };
        let deployment_digest = deployment
            .compute_deployment_digest()
            .test_expect("compute combined deployment digest");
        deployment.deployment_digest = deployment_digest;
        deployment.response_authority.deployment_digest = deployment_digest;
        deployment
            .validate()
            .test_expect("validate combined authority deployment");
        build_empty_store_for_process_test(&store_path, deployment_digest, &authority.public_key())
            .test_expect("build deployment-bound process authority store");
        let config_bytes =
            canonical_json_bytes(&deployment).test_expect("canonical authority deployment");
        let staging_path = directory.path().join("authority.json.staging");
        let mut config_options = OpenOptions::new();
        config_options.write(true).create_new(true).mode(0o600);
        let mut config_file = config_options
            .open(&staging_path)
            .test_expect("create authority config staging file");
        config_file
            .write_all(&config_bytes)
            .and_then(|()| config_file.sync_all())
            .test_expect("write authority config staging file");
        std::fs::rename(&staging_path, &config_path).test_expect("publish authority config");

        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket_path.exists() && Instant::now() < deadline {
            assert!(
                child
                    .0
                    .try_wait()
                    .test_expect("poll authority helper")
                    .is_none(),
                "authority helper exited before publishing its socket"
            );
            thread::sleep(Duration::from_millis(2));
        }
        assert!(socket_path.exists(), "authority socket was not published");
        let unauthorized_status =
            Command::new(std::env::current_exe().test_expect("unauthorized client test binary"))
                .arg(UNAUTHORIZED_HELPER_TEST)
                .arg("--exact")
                .arg("--ignored")
                .arg("--test-threads=1")
                .env(PROCESS_ROLE_ENV, "unauthorized-client")
                .env(PROCESS_SOCKET_ENV, &socket_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .test_expect("run unauthorized authority client");
        assert!(unauthorized_status.success());

        let client_signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(client.clone()));
        let protocol_client = ProductionActiveResponseAuthorityClient::new(
            ProductionActiveResponseAuthorityFileConfig {
                socket_path,
                expected_peer: service_identity,
                trusted_authority: authority.public_key(),
                deployment_digest,
                store_digest,
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 5,
            },
            client_signer,
        )
        .test_expect("build process-boundary authority client");
        protocol_client
            .ensure_ready()
            .test_expect("authenticated authority health response");
    }
}
