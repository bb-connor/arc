#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use chio_core_types::SigningBackend;
#[cfg(unix)]
use chio_keyring::bind_private_unix_listener;
use chio_keyring::{
    load_audit_service_config, load_key_log_policy, load_witness_seed_backend,
    read_single_canonical_frame, write_canonical_frame, AuditServiceOperation,
    AuditServiceReadinessBody, AuditServiceReadinessProof, AuditServiceRequest,
    AuditServiceResponse, AuditServiceResult, CheckpointStage, KeyLogAuditMonitor, KeyLogPin,
    KeyLogPolicy, KeyringError, SqliteKeyLogStore, SqlitePinnedKeyLogVerifier, SystemTrustedClock,
    TrustedClock, UnixKeyLogWitnessClient, WitnessId, WitnessServiceView,
    KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA, KEY_LOG_AUDIT_IPC_RESPONSE_SCHEMA,
    KEY_LOG_AUDIT_READINESS_SCHEMA,
};

#[derive(Clone, Debug, Default)]
struct AuditHealth {
    last_successful_poll_at: u64,
    pin: Option<KeyLogPin>,
    operator_head: Option<KeyLogPin>,
    witness_views: std::collections::BTreeMap<WitnessId, WitnessServiceView>,
    witness_proofs:
        std::collections::BTreeMap<WitnessId, chio_keyring::WitnessServiceReadinessProof>,
    conflict_count: usize,
    fatal_error: Option<String>,
}

const MAX_AUDIT_SYNC_PAGES: usize = 4_096;

struct PollLoopConfig {
    monitor: Arc<KeyLogAuditMonitor>,
    operator: Arc<SqliteKeyLogStore>,
    policy: KeyLogPolicy,
    witnesses: Vec<UnixKeyLogWitnessClient>,
    health: Arc<Mutex<AuditHealth>>,
    force_poll: Arc<AtomicBool>,
    poll_interval_millis: u64,
    clock: Arc<SystemTrustedClock>,
}

#[cfg(unix)]
struct AuditConnectionContext<'a> {
    health: &'a Mutex<AuditHealth>,
    force_poll: &'a AtomicBool,
    monitor_id: &'a str,
    readiness_backend: &'a dyn chio_core_types::SigningBackend,
    configuration_binding: chio_core_types::Hash,
    storage_identity: chio_core_types::Hash,
    started_at: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-keylog-audit detected a fatal verification failure: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn run() -> chio_keyring::Result<()> {
    let config_path = parse_config_argument().map_err(KeyringError::Canonical)?;
    let config = load_audit_service_config(&config_path)?;
    let policy = load_key_log_policy(&config.policy_path)?;
    let readiness_backend = load_witness_seed_backend(&config.seed_file_path)?;
    let expected_auditor_key = policy
        .auditor_public_key(&config.monitor_id)
        .ok_or(KeyringError::InvalidSignature)?;
    if readiness_backend.public_key() != expected_auditor_key.clone() {
        return Err(KeyringError::InvalidSignature);
    }
    let configured_witnesses = config
        .witness_sockets
        .keys()
        .map(|value| WitnessId::new(value.clone()))
        .collect::<chio_keyring::Result<std::collections::BTreeSet<_>>>()?;
    if configured_witnesses
        != policy
            .witness_public_keys()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    {
        return Err(KeyringError::StateInvariant(
            "audit witness endpoints do not match configured trust roots",
        ));
    }
    let configuration_binding = policy.configuration_binding()?;
    let operator = Arc::new(SqliteKeyLogStore::open_observer(
        &config.operator_database_path,
        policy.clone(),
    )?);
    let clock = Arc::new(SystemTrustedClock);
    let verifier = if config.provision {
        SqlitePinnedKeyLogVerifier::provision(&config.database_path, policy.clone(), clock.clone())?
    } else {
        SqlitePinnedKeyLogVerifier::open(&config.database_path, policy.clone(), clock.clone())?
    };
    let storage_identity = verifier.storage_identity();
    if storage_identity == operator.storage_identity() {
        return Err(KeyringError::StateInvariant(
            "audit monitor and operator must not share durable storage",
        ));
    }
    let monitor = Arc::new(KeyLogAuditMonitor::new(verifier));
    let started_at = clock.now()?;
    let witnesses = config
        .witness_sockets
        .iter()
        .map(|(identifier, endpoint)| {
            let witness_id = WitnessId::new(identifier.clone())?;
            let public_key = policy
                .witness_public_key(&witness_id)
                .ok_or(KeyringError::InvalidSignature)?
                .clone();
            UnixKeyLogWitnessClient::new(
                endpoint.clone(),
                witness_id,
                public_key,
                configuration_binding,
            )
        })
        .collect::<chio_keyring::Result<Vec<_>>>()?;
    let health = Arc::new(Mutex::new(AuditHealth::default()));
    let force_poll = Arc::new(AtomicBool::new(true));
    let _poll_thread = spawn_poll_loop(PollLoopConfig {
        monitor: Arc::clone(&monitor),
        operator: Arc::clone(&operator),
        policy: policy.clone(),
        witnesses,
        health: Arc::clone(&health),
        force_poll: Arc::clone(&force_poll),
        poll_interval_millis: config.poll_interval_millis,
        clock,
    });

    let listener = bind_private_unix_listener(&config.socket_path)?;
    listener.set_nonblocking(true)?;
    let _socket_guard = SocketPathGuard(config.socket_path);
    loop {
        if let Some(error) = health_lock(&health)?.fatal_error.clone() {
            return Err(KeyringError::Storage(error));
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let result = (|| {
                    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                    handle_connection(
                        &mut stream,
                        AuditConnectionContext {
                            health: &health,
                            force_poll: &force_poll,
                            monitor_id: &config.monitor_id,
                            readiness_backend: &readiness_backend,
                            configuration_binding,
                            storage_identity,
                            started_at,
                        },
                    )
                })();
                if let Err(error) = result {
                    eprintln!("chio-keylog-audit rejected IPC request: {error}");
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::ConnectionAborted
                ) => {}
            Err(error) => return Err(KeyringError::Io(error)),
        }
    }
}

#[cfg(not(unix))]
fn run() -> chio_keyring::Result<()> {
    Err(KeyringError::StateInvariant(
        "chio-keylog-audit requires Unix domain sockets",
    ))
}

fn spawn_poll_loop(config: PollLoopConfig) -> thread::JoinHandle<()> {
    let PollLoopConfig {
        monitor,
        operator,
        policy,
        witnesses,
        health,
        force_poll,
        poll_interval_millis,
        clock,
    } = config;
    thread::spawn(move || loop {
        let previous_health = match health_lock(&health) {
            Ok(guard) => guard.clone(),
            Err(error) => {
                if let Ok(mut guard) = health.lock() {
                    guard.fatal_error = Some(error.to_string());
                }
                return;
            }
        };
        match poll_once(
            &monitor,
            &operator,
            &policy,
            &witnesses,
            previous_health.clone(),
            clock.as_ref(),
        ) {
            Ok(updated) => match health_lock(&health) {
                Ok(mut guard) => *guard = updated,
                Err(_) => return,
            },
            Err(KeyringError::InvalidWitnessActivation) => match health_lock(&health) {
                Ok(mut guard) => {
                    *guard = previous_health;
                    guard.last_successful_poll_at = 0;
                }
                Err(_) => return,
            },
            Err(error) => {
                if let Ok(mut guard) = health_lock(&health) {
                    guard.fatal_error = Some(error.to_string());
                }
                return;
            }
        }
        let sleep_slices = poll_interval_millis.div_ceil(10);
        for _ in 0..sleep_slices {
            if force_poll.swap(false, Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    })
}

fn poll_once(
    monitor: &KeyLogAuditMonitor,
    operator: &SqliteKeyLogStore,
    policy: &KeyLogPolicy,
    witnesses: &[UnixKeyLogWitnessClient],
    previous_health: AuditHealth,
    clock: &dyn TrustedClock,
) -> chio_keyring::Result<AuditHealth> {
    let retained_health = previous_health.clone();
    let mut current_operator_pin = None;
    let mut observed_operator_head = None;
    let mut pending_operator_head = false;
    for _ in 0..MAX_AUDIT_SYNC_PAGES {
        let before = monitor.pin()?;
        let synchronization = operator.synchronization_response(before.as_ref())?;
        let target = operator.head_pin()?.ok_or(KeyringError::StateInvariant(
            "operator key log is uninitialized",
        ))?;
        let pending_tail = operator.head_stage()? == Some(CheckpointStage::Pending)
            && synchronization_is_pending_tail(&synchronization, &target, policy)?;
        let operator_pin = match monitor.poll(&synchronization) {
            Ok(pin) => pin,
            Err(KeyringError::InvalidWitnessActivation) if pending_tail => {
                let retained_pin = before.ok_or(KeyringError::StateInvariant(
                    "audit monitor cannot accept a pending genesis head",
                ))?;
                current_operator_pin = Some(retained_pin);
                observed_operator_head = Some(target);
                pending_operator_head = true;
                break;
            }
            Err(error) => return Err(error),
        };
        if operator_pin == target {
            current_operator_pin = Some(target.clone());
            observed_operator_head = Some(target);
            break;
        }
        if before.as_ref() == Some(&operator_pin) {
            let awaiting_activation_commit = before.as_ref().is_some_and(|pin| {
                pin.checkpoint_sequence == target.checkpoint_sequence
                    && pin.tree_size == target.tree_size
                    && pin.checkpoint_hash == target.checkpoint_hash
                    && pin.root_hash == target.root_hash
                    && pin.signing_epoch.checked_add(1) == Some(target.signing_epoch)
            });
            if pending_tail || awaiting_activation_commit {
                return Ok(retained_health);
            }
            return Err(KeyringError::StateInvariant(
                "audit synchronization made no progress",
            ));
        }
    }
    let current_operator_pin = current_operator_pin.ok_or(KeyringError::StateInvariant(
        "audit synchronization exceeded its page limit",
    ))?;
    let observed_operator_head = observed_operator_head.ok_or(KeyringError::StateInvariant(
        "audit synchronization did not observe the operator head",
    ))?;

    let now = clock.now()?;
    let mut witness_views = previous_health.witness_views;
    let mut witness_proofs = previous_health.witness_proofs;
    let mut available = Vec::new();
    let mut gossip = Vec::new();
    for client in witnesses {
        let state = match client.state() {
            Ok(state) => state,
            Err(KeyringError::Io(_)) => continue,
            Err(error) => return Err(error),
        };
        let readiness = state.proof.body.clone();
        if readiness.conflict_count != 0 || state.conflict_count != 0 {
            return Err(KeyringError::EquivocationDetected);
        }
        witness_views.insert(
            readiness.witness_id.clone(),
            WitnessServiceView {
                pin: state.pin,
                process_id: readiness.process_id,
                storage_identity: readiness.storage_identity,
                conflict_count: state.conflict_count,
            },
        );
        witness_proofs.insert(readiness.witness_id.clone(), state.proof.clone());
        gossip.extend(state.gossip);
        available.push(client);
    }
    if available.len() < policy.witness_threshold()? {
        return Err(KeyringError::InvalidWitnessActivation);
    }
    for observation in &gossip {
        monitor.import_gossip(observation)?;
    }
    for client in &available {
        for observation in &gossip {
            match client.import_gossip(observation) {
                Ok(()) => {}
                Err(KeyringError::Io(_)) => return Err(KeyringError::InvalidWitnessActivation),
                Err(error) => return Err(error),
            }
        }
    }
    if pending_operator_head {
        let consistent = witness_views
            .values()
            .filter(|view| {
                view.conflict_count == 0
                    && matches!(
                        view.pin.as_ref(),
                        Some(pin)
                            if pin == &current_operator_pin || pin == &observed_operator_head
                    )
            })
            .count();
        if consistent < policy.witness_threshold()? {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        let conflicts = monitor.conflicts()?;
        if !conflicts.is_empty() {
            return Err(KeyringError::EquivocationDetected);
        }
        return Ok(AuditHealth {
            last_successful_poll_at: now,
            pin: Some(current_operator_pin),
            operator_head: Some(observed_operator_head),
            witness_views,
            witness_proofs,
            conflict_count: conflicts.len(),
            fatal_error: None,
        });
    }
    let agreeing = witness_views
        .values()
        .filter(|view| view.pin.as_ref() == Some(&current_operator_pin) && view.conflict_count == 0)
        .count();
    if agreeing < policy.witness_threshold()? {
        let awaiting_activation_commit = witness_views
            .values()
            .filter(|view| {
                view.conflict_count == 0
                    && view.pin.as_ref().is_some_and(|pin| {
                        pin.checkpoint_sequence == current_operator_pin.checkpoint_sequence
                            && pin.tree_size == current_operator_pin.tree_size
                            && pin.checkpoint_hash == current_operator_pin.checkpoint_hash
                            && pin.root_hash == current_operator_pin.root_hash
                            && pin.signing_epoch.checked_add(1)
                                == Some(current_operator_pin.signing_epoch)
                    })
            })
            .count();
        if awaiting_activation_commit >= policy.witness_threshold()? {
            return Ok(retained_health);
        }
        return Err(KeyringError::InvalidWitnessActivation);
    }
    let conflicts = monitor.conflicts()?;
    if !conflicts.is_empty() {
        return Err(KeyringError::EquivocationDetected);
    }
    Ok(AuditHealth {
        last_successful_poll_at: now,
        pin: Some(current_operator_pin),
        operator_head: Some(observed_operator_head),
        witness_views,
        witness_proofs,
        conflict_count: conflicts.len(),
        fatal_error: None,
    })
}

fn synchronization_is_pending_tail(
    synchronization: &chio_keyring::KeyLogSyncResponse,
    operator_head: &KeyLogPin,
    policy: &KeyLogPolicy,
) -> chio_keyring::Result<bool> {
    let Some((pending, preceding)) = synchronization.checkpoints.split_last() else {
        return Ok(false);
    };
    if pending.checkpoint_hash()? != operator_head.checkpoint_hash {
        return Ok(false);
    }
    pending.verify_operator(policy.operator_public_key())?;
    pending.verify_witness_signatures(policy.witness_public_keys())?;
    if pending.witness_signatures.len() >= policy.witness_threshold()? {
        return Err(KeyringError::StateInvariant(
            "pending operator head already has a witness quorum",
        ));
    }
    for checkpoint in preceding {
        checkpoint.verify_witnesses(policy.witness_public_keys())?;
    }
    Ok(true)
}

#[cfg(unix)]
fn handle_connection(
    stream: &mut UnixStream,
    context: AuditConnectionContext<'_>,
) -> chio_keyring::Result<()> {
    let AuditConnectionContext {
        health,
        force_poll,
        monitor_id,
        readiness_backend,
        configuration_binding,
        storage_identity,
        started_at,
    } = context;
    let request: AuditServiceRequest = read_single_canonical_frame(stream)?;
    if request.schema != KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA {
        return Err(KeyringError::UnsupportedSchema(request.schema));
    }
    let result = match request.operation {
        AuditServiceOperation::Readiness { nonce } => {
            let current = health_lock(health)?.clone();
            if let Some(reason) = current.fatal_error {
                AuditServiceResult::Failure { reason }
            } else if current.last_successful_poll_at == 0
                || current.pin.is_none()
                || current.operator_head.is_none()
                || current.witness_views.len() != 3
                || current.witness_proofs.len() != 3
            {
                AuditServiceResult::Unready {
                    reason: "audit monitor has not completed a full autonomous poll".to_string(),
                }
            } else {
                AuditServiceResult::Readiness {
                    proof: Box::new(AuditServiceReadinessProof::sign(
                        AuditServiceReadinessBody {
                            schema: KEY_LOG_AUDIT_READINESS_SCHEMA.to_string(),
                            monitor_id: monitor_id.to_string(),
                            configuration_binding,
                            nonce,
                            process_id: std::process::id(),
                            storage_identity,
                            started_at,
                            last_successful_poll_at: current.last_successful_poll_at,
                            pin: current.pin,
                            operator_head: current.operator_head.ok_or(
                                KeyringError::StateInvariant(
                                    "audit monitor readiness is missing the operator head",
                                ),
                            )?,
                            witness_views: current.witness_views,
                            witness_proofs: current.witness_proofs,
                            conflict_count: current.conflict_count,
                        },
                        readiness_backend,
                    )?),
                }
            }
        }
        AuditServiceOperation::PollNow => {
            force_poll.store(true, Ordering::SeqCst);
            AuditServiceResult::PollAccepted
        }
    };
    write_canonical_frame(
        stream,
        &AuditServiceResponse {
            schema: KEY_LOG_AUDIT_IPC_RESPONSE_SCHEMA.to_string(),
            result,
        },
    )
}

fn health_lock(health: &Mutex<AuditHealth>) -> chio_keyring::Result<MutexGuard<'_, AuditHealth>> {
    health.lock().map_err(|_| KeyringError::Synchronization)
}

fn parse_config_argument() -> Result<PathBuf, String> {
    let mut values = std::env::args().skip(1);
    if values.next().as_deref() != Some("--config") {
        return Err("expected --config PATH".to_string());
    }
    let path = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing value for --config".to_string())?;
    if values.next().is_some() {
        return Err("unexpected extra audit service argument".to_string());
    }
    Ok(PathBuf::from(path))
}

struct SocketPathGuard(PathBuf);

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
