#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use chio_keyring::bind_private_unix_listener;
use chio_keyring::{
    load_key_log_policy, load_witness_seed_backend, load_witness_service_config,
    read_single_canonical_frame, write_canonical_frame, KeyringError, SqliteKeyLogWitness,
    SystemTrustedClock, TrustedClock, WitnessId, WitnessServiceOperation,
    WitnessServiceReadinessBody, WitnessServiceReadinessProof, WitnessServiceRequest,
    WitnessServiceResponse, WitnessServiceResult, WitnessServiceState,
    KEY_LOG_WITNESS_IPC_REQUEST_SCHEMA, KEY_LOG_WITNESS_IPC_RESPONSE_SCHEMA,
    KEY_LOG_WITNESS_READINESS_SCHEMA,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-keylog-witness failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn run() -> chio_keyring::Result<()> {
    let config_path = parse_config_argument().map_err(KeyringError::Canonical)?;
    let config = load_witness_service_config(&config_path)?;
    let policy = load_key_log_policy(&config.policy_path)?;
    let configuration_binding = policy.configuration_binding()?;
    let witness_id = WitnessId::new(config.witness_id)?;
    let backend = load_witness_seed_backend(&config.seed_file_path)?;
    let readiness_backend = backend.clone();
    let clock = Arc::new(SystemTrustedClock);
    let started_at = clock.now()?;
    let witness = if config.provision {
        SqliteKeyLogWitness::provision(
            &config.database_path,
            policy,
            witness_id,
            Box::new(backend),
            clock,
        )?
    } else {
        SqliteKeyLogWitness::open(
            &config.database_path,
            policy,
            witness_id,
            Box::new(backend),
            clock,
        )?
    };
    let storage_identity = witness.storage_identity();
    let listener = bind_private_unix_listener(&config.socket_path)?;
    let _socket_guard = SocketPathGuard(config.socket_path);

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let result = (|| {
                    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                    handle_connection(
                        &mut stream,
                        &witness,
                        &readiness_backend,
                        configuration_binding,
                        storage_identity,
                        started_at,
                    )
                })();
                if let Err(error) = result {
                    eprintln!("chio-keylog-witness rejected IPC request: {error}");
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted
                ) => {}
            Err(error) => return Err(KeyringError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn run() -> chio_keyring::Result<()> {
    Err(KeyringError::StateInvariant(
        "chio-keylog-witness requires Unix domain sockets",
    ))
}

#[cfg(unix)]
fn handle_connection(
    stream: &mut UnixStream,
    witness: &SqliteKeyLogWitness,
    readiness_backend: &dyn chio_core_types::SigningBackend,
    configuration_binding: chio_core_types::Hash,
    storage_identity: chio_core_types::Hash,
    started_at: u64,
) -> chio_keyring::Result<()> {
    let request: WitnessServiceRequest = read_single_canonical_frame(stream)?;
    if request.schema != KEY_LOG_WITNESS_IPC_REQUEST_SCHEMA {
        return Err(KeyringError::UnsupportedSchema(request.schema));
    }
    let result = match request.operation {
        WitnessServiceOperation::Readiness { nonce } => {
            let proof = WitnessServiceReadinessProof::sign(
                WitnessServiceReadinessBody {
                    schema: KEY_LOG_WITNESS_READINESS_SCHEMA.to_string(),
                    witness_id: witness.witness_id().clone(),
                    configuration_binding,
                    nonce,
                    process_id: std::process::id(),
                    storage_identity,
                    started_at,
                    pin: witness.pin()?,
                    conflict_count: witness.conflicts()?.len(),
                    gossip_observation_count: witness.service_gossip_observations()?.len(),
                },
                readiness_backend,
            )?;
            WitnessServiceResult::Readiness { proof }
        }
        WitnessServiceOperation::Pin => WitnessServiceResult::Pin {
            pin: witness.pin()?,
        },
        WitnessServiceOperation::SignCandidate {
            candidate,
            synchronization,
        } => match witness.sign_candidate(&candidate, &synchronization) {
            Ok(signature) => {
                let pin = witness.pin()?.ok_or(KeyringError::StateInvariant(
                    "witness signed without durably advancing its pin",
                ))?;
                WitnessServiceResult::Signed { signature, pin }
            }
            Err(error) => WitnessServiceResult::Failure {
                reason: error.to_string(),
            },
        },
        WitnessServiceOperation::State { nonce, after } => {
            let observations = witness.service_gossip_observations()?;
            let pin = witness.pin()?;
            let conflict_count = witness.conflicts()?.len();
            let proof = WitnessServiceReadinessProof::sign(
                WitnessServiceReadinessBody {
                    schema: KEY_LOG_WITNESS_READINESS_SCHEMA.to_string(),
                    witness_id: witness.witness_id().clone(),
                    configuration_binding,
                    nonce,
                    process_id: std::process::id(),
                    storage_identity,
                    started_at,
                    pin: pin.clone(),
                    conflict_count,
                    gossip_observation_count: observations.len(),
                },
                readiness_backend,
            )?;
            let (gossip, next_cursor) = chio_keyring::gossip_page(&observations, after.as_ref());
            WitnessServiceResult::State {
                state: WitnessServiceState {
                    proof,
                    witness_id: witness.witness_id().clone(),
                    pin,
                    gossip,
                    gossip_observation_count: observations.len(),
                    next_cursor,
                    conflict_count,
                },
            }
        }
        WitnessServiceOperation::ImportGossip { gossip } => match witness.import_gossip(&gossip) {
            Ok(()) => WitnessServiceResult::Imported,
            Err(error) => WitnessServiceResult::Failure {
                reason: error.to_string(),
            },
        },
    };
    write_canonical_frame(
        stream,
        &WitnessServiceResponse {
            schema: KEY_LOG_WITNESS_IPC_RESPONSE_SCHEMA.to_string(),
            result,
        },
    )
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
        return Err("unexpected extra witness service argument".to_string());
    }
    Ok(PathBuf::from(path))
}

struct SocketPathGuard(PathBuf);

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
