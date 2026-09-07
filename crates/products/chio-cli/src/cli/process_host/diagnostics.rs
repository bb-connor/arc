//! Bounded local diagnostics. Reading status never opens a kernel or reconciles admission.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use chio_control_plane::{prepare_private_directory, PreparedPrivateDirectory};
use serde::{Deserialize, Serialize};

use super::state::{error, identifier, Record, MAX_CONFIG_BYTES, SCHEMA};
use crate::CliError;

pub(super) const STATUS_FILE: &str = "run-status.json";
pub(super) const RUN_SCHEMA: &str = "chio.process.run-status.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunStatus {
    pub schema: String,
    pub run_id: String,
    pub observed_at_ms: u64,
    pub plan_binding: String,
    pub max_parallel: usize,
    pub workers: Vec<WorkerStatus>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerStatus {
    pub process: String,
    pub state: String,
    pub attempts: u32,
    pub max_attempts: u32,
    #[serde(default)]
    pub suspensions: u32,
    #[serde(default)]
    pub max_suspensions: u32,
    pub outcome: Option<String>,
    pub waiting_on: Vec<String>,
}

struct Observer {
    directory: PreparedPrivateDirectory,
    record: Record,
    // If the lock was free, hold it only during this bounded read. Otherwise
    // retain the same file handle while reading the runner's atomic snapshot.
    _lock: File,
    host_lock_held: bool,
}

impl Observer {
    fn open(path: &Path) -> Result<Self, CliError> {
        let metadata = path.symlink_metadata()?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(error(
                "state directory must already exist and be private (0700)",
            ));
        }
        let directory = prepare_private_directory(path)?;
        let lock = open_private(&directory, Path::new("host.lock"))?;
        let host_lock_held = match lock.try_lock() {
            Ok(()) => false,
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Error(failure)) => return Err(error(failure)),
        };
        let record: Record = serde_json::from_slice(&read_private(
            &directory,
            Path::new("host.json"),
            MAX_CONFIG_BYTES,
        )?)
        .map_err(error)?;
        if record.config.schema != SCHEMA {
            return Err(error("unsupported process host configuration"));
        }
        directory.validate_path_identity()?;
        Ok(Self {
            directory,
            record,
            _lock: lock,
            host_lock_held,
        })
    }

    fn run_status(&self) -> Result<Option<RunStatus>, CliError> {
        let path = Path::new(STATUS_FILE);
        match self.directory.path().join(path).symlink_metadata() {
            Ok(_) => {
                let snapshot: RunStatus =
                    serde_json::from_slice(&read_private(&self.directory, path, MAX_CONFIG_BYTES)?)
                        .map_err(error)?;
                if snapshot.schema != RUN_SCHEMA || snapshot.workers.len() > 128 {
                    return Err(error("unsupported or oversized run status snapshot"));
                }
                Ok(Some(snapshot))
            }
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(failure) => Err(error(failure)),
        }
    }
}

fn open_private(directory: &PreparedPrivateDirectory, name: &Path) -> Result<File, CliError> {
    directory.validate_path_identity()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.path().join(name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != std::fs::metadata(directory.path())?.uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(error(
            "diagnostics require private regular files owned by the state owner",
        ));
    }
    directory.validate_path_identity()?;
    Ok(file)
}

fn read_private(
    directory: &PreparedPrivateDirectory,
    name: &Path,
    maximum: u64,
) -> Result<Vec<u8>, CliError> {
    let file = open_private(directory, name)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(error("diagnostic file exceeds its size limit"));
    }
    directory.validate_path_identity()?;
    Ok(bytes)
}

pub(super) fn status(path: &Path) -> Result<(), CliError> {
    let observer = Observer::open(path)?;
    let snapshot = observer.run_status()?;
    observer.directory.validate_path_identity()?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "chio.process.status.v1",
            "abi": {
                "serving": chio_process::PROCESS_ABI,
                "host": observer.record.abi,
                "written_by": observer.record.written_by,
            },
            "host_lock_held": observer.host_lock_held,
            "run": snapshot,
        })
    );
    Ok(())
}

pub(super) fn logs(path: &Path, process: &str, attempt: u32) -> Result<(), CliError> {
    identifier(process)?;
    if !(1..=16).contains(&attempt) {
        return Err(error("log attempt must be between 1 and 16"));
    }
    let observer = Observer::open(path)?;
    let log_path = observer.directory.path().join("run-logs");
    let metadata = log_path.symlink_metadata()?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(error("run logs must be an existing private directory"));
    }
    let logs = prepare_private_directory(&log_path)?;
    let mut output = serde_json::Map::new();
    for stream in ["stdout", "stderr"] {
        let name = format!("{process}-{attempt}.{stream}");
        let bytes = read_private(&logs, Path::new(&name), 65_536)?;
        let text = String::from_utf8(bytes).map_err(error)?;
        output.insert(stream.to_owned(), serde_json::Value::String(text));
    }
    observer.directory.validate_path_identity()?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "chio.process.logs.v1", "process": process, "attempt": attempt,
            "logs": output,
        })
    );
    Ok(())
}
