use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use chio_core::Keypair;

use crate::CliError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum Reader {
    Call,
    Outcomes,
    Run,
}

impl Reader {
    fn verify(self, artifact: &Path, key: &Path) -> Result<(), CliError> {
        match self {
            Self::Call => super::call_evidence::verify_file(
                artifact, key, "runtime", artifact, artifact, None, None,
            ),
            Self::Outcomes => super::call_evidence::verify_outcomes(artifact, key, "runtime", &[]),
            Self::Run => super::run_evidence::verify_file(artifact, key, "runtime", &[]),
        }
    }
}

pub(super) fn fifo_refusal(
    reader: impl FnOnce(&Path, &Path) -> Result<(), CliError> + Send + 'static,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let artifact = directory.path().join("artifact.fifo");
    let key_path = directory.path().join("trusted.pub");
    let key = Keypair::generate();
    std::fs::write(&key_path, key.public_key().to_hex())?;
    assert_eq!(
        crate::load_trusted_kernel_pubkey(&key_path)?.to_hex(),
        key.public_key().to_hex()
    );
    assert!(std::process::Command::new("mkfifo")
        .arg(&artifact)
        .status()?
        .success());
    let (send, receive) = mpsc::channel();
    let input = artifact.clone();
    let worker = std::thread::spawn(move || {
        let outcome = match reader(&input, &key_path) {
            Err(CliError::Io(error)) => Err((error.kind(), error.to_string())),
            Err(other) => Err((ErrorKind::InvalidData, other.to_string())),
            Ok(()) => Ok(()),
        };
        let _ = send.send(outcome);
    });
    let first = receive.recv_timeout(Duration::from_secs(5));
    let mut unblock = if first.is_err() {
        Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&artifact)?,
        )
    } else {
        None
    };
    if let Some(writer) = unblock.as_mut() {
        writer.write_all(b"{}")?;
    }
    drop(unblock);
    let timely = first.is_ok();
    let outcome = match first {
        Ok(outcome) => outcome,
        Err(_) => receive.recv_timeout(Duration::from_secs(5))?,
    };
    worker.join().map_err(|_| "artifact reader panicked")?;
    assert!(timely, "artifact reader blocked opening a FIFO");
    assert_eq!(
        outcome,
        Err((ErrorKind::Other, "input must be a regular file".to_owned()))
    );
    Ok(())
}

#[test]
fn call_artifact_fifo_is_refused_without_blocking() -> TestResult {
    fifo_refusal(|artifact, key| Reader::Call.verify(artifact, key))
}

#[test]
fn outcomes_artifact_fifo_is_refused_without_blocking() -> TestResult {
    fifo_refusal(|artifact, key| Reader::Outcomes.verify(artifact, key))
}

#[test]
fn run_artifact_fifo_is_refused_without_blocking() -> TestResult {
    fifo_refusal(|artifact, key| Reader::Run.verify(artifact, key))
}

#[test]
fn state_artifact_fifo_is_refused_without_blocking() -> TestResult {
    fifo_refusal(|artifact, _| super::state::read_json::<serde_json::Value>(artifact).map(|_| ()))
}

#[test]
fn state_artifact_regular_control_and_bound() -> TestResult {
    let directory = tempfile::tempdir()?;
    let artifact = directory.path().join("state.json");
    std::fs::write(&artifact, b"{\"value\":42}")?;
    let value: serde_json::Value = super::state::read_json(&artifact)?;
    assert_eq!(value, serde_json::json!({"value": 42}));
    let bound = super::state::MAX_CONFIG_BYTES as usize;
    std::fs::File::create(&artifact)?.set_len(bound as u64 + 1)?;
    let result = super::state::read_json::<serde_json::Value>(&artifact);
    let Err(CliError::Io(failure)) = result else {
        return Err("expected bounded input I/O refusal".into());
    };
    assert_eq!(failure.kind(), ErrorKind::Other);
    assert!(matches!(
        failure.get_ref().and_then(|source| source.downcast_ref::<chio_core::canonical::UntrustedJsonError>()),
        Some(chio_core::canonical::UntrustedJsonError::TooLarge { bytes, bound: actual })
            if *bytes == bound + 1 && *actual == bound
    ));
    Ok(())
}
