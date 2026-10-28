//! Move or restore a complete host state directory.
//!
//! `export` retires the authority where it is and writes `relocation.json`,
//! a manifest of every file that must travel with the directory. The operator
//! copies the directory with ordinary tools. `import` verifies the copy
//! against the manifest, re-anchors the authority at its new location and
//! removes the manifest. Both commands require the host to be stopped.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chio_control_plane::DurableAdmissionRuntime;
use chio_store_sqlite::{RelocationImportPhase, RelocationSeal};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::state::{error, read_json, write_secret, Lease};
use crate::CliError;

const MANIFEST: &str = "relocation.json";
const SCHEMA: &str = "chio.process.relocation.v1";
/// Application databases beside the authority that are checkpointed before export.
const CHECKPOINTED: [&str; 4] = ["receipts.db", "process.db", "mailboxes.db", "runner.db"];
/// Files that never travel: the host lock, live sockets, journals emptied by
/// checkpointing and the manifest itself.
const EXCLUDED: [&str; 2] = ["host.lock", MANIFEST];
const EXCLUDED_DIRECTORIES: [&str; 1] = ["run-sockets"];
const SQLITE_SIDECARS: [&str; 2] = ["-wal", "-shm"];

#[derive(Clone, Copy)]
enum SidecarPolicy {
    Checkpointable,
    Sealed,
    CommittedImport,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    written_by: Option<String>,
    seal: RelocationSeal,
    files: BTreeMap<String, String>,
}

pub(super) fn export(state: &Path) -> Result<(), CliError> {
    let lease = Lease::acquire(state, false)?;
    let directory = lease.directory.path().to_path_buf();
    let record = super::state::read_current_record(&directory.join("host.json"))?;
    super::state::require_abi(&record.abi, "host state")?;
    // Reject unreadable files and symlinks before retiring a usable authority.
    // Retirement itself is resumable if a later write or the host fails.
    digests(&directory, SidecarPolicy::Checkpointable)?;
    let runner = directory.join("runner.db");
    if runner.try_exists()? {
        let db = Connection::open_with_flags(
            &runner,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(error)?;
        let table: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_containers')", [], |row| row.get(0)).map_err(error)?;
        if table {
            let pending: bool = db
                .query_row("SELECT EXISTS(SELECT 1 FROM run_containers)", [], |row| {
                    row.get(0)
                })
                .map_err(error)?;
            if pending {
                return Err(error("container ownership is unresolved; resume the same run plan on its original Docker engine before export"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            db.pragma_update(None, "synchronous", "FULL")
                .map_err(error)?;
            super::runner::cleanup_socket_for_export(&db)?;
        }
    }
    for name in CHECKPOINTED {
        let path = directory.join(name);
        if path.try_exists()? {
            checkpoint(&path)?;
        }
    }
    let seal = DurableAdmissionRuntime::export_relocation(&directory.join("authority.db"))?;
    let files = digests(&directory, SidecarPolicy::Sealed)?;
    let manifest = Manifest {
        schema: SCHEMA.to_owned(),
        abi: record.abi,
        written_by: Some(super::state::code_identity()),
        seal: seal.clone(),
        files,
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(error)?;
    let path = directory.join(MANIFEST);
    if path.try_exists()? {
        std::fs::remove_file(&path)?;
    }
    write_secret(&lease.directory, Path::new(MANIFEST).as_os_str(), &bytes)?;
    println!(
        "{}",
        serde_json::json!({"exported": true, "store_uuid": seal.store_uuid,
            "export_id": seal.export_id, "files": manifest.files.len()})
    );
    Ok(())
}

pub(super) fn import(state: &Path) -> Result<(), CliError> {
    let lease = Lease::acquire(state, false)?;
    let directory = lease.directory.path().to_path_buf();
    let manifest: Manifest = read_json(&directory.join(MANIFEST))?;
    if manifest.schema != SCHEMA
        || manifest.seal.format != chio_store_sqlite::RELOCATION_SEAL_FORMAT
    {
        return Err(error("unsupported relocation manifest"));
    }
    super::state::require_abi(&manifest.abi, "the exported host state")?;
    let record = super::state::read_current_record(&directory.join("host.json"))?;
    super::state::require_abi(&record.abi, "host state")?;
    if record.abi != manifest.abi {
        return Err(error("host ABI differs from its relocation manifest"));
    }
    // Import replaces the copied lock artifacts before its database commit.
    // They are not an authority for the new location, and an interrupted
    // replacement must be retryable. The database still has to match its
    // exported bytes until commit; application files must match on every try.
    let verify_files = |phase: RelocationImportPhase| -> Result<(), CliError> {
        let all = phase == RelocationImportPhase::Exported;
        let policy = match phase {
            RelocationImportPhase::Exported => SidecarPolicy::Sealed,
            RelocationImportPhase::Committed => SidecarPolicy::CommittedImport,
        };
        let actual = digests(&directory, policy)?;
        let authoritative = |name: &&String| !name.starts_with("authority.db.locks/");
        if actual
            .keys()
            .filter(authoritative)
            .ne(manifest.files.keys().filter(authoritative))
        {
            return Err(error("relocated file set differs from its manifest"));
        }
        for (name, expected) in &manifest.files {
            if name.starts_with("authority.db.locks/") || (!all && name == "authority.db") {
                continue;
            }
            match actual.get(name) {
                Some(digest) if digest == expected => {}
                Some(_) => {
                    return Err(error(format!(
                        "relocated file changed since export: {name}"
                    )))
                }
                None => return Err(error(format!("relocated file is missing: {name}"))),
            }
        }
        Ok(())
    };
    let imported = DurableAdmissionRuntime::import_relocation_checked_with_phase(
        &directory.join("authority.db"),
        &manifest.seal,
        verify_files,
    )?;
    lease.directory.validate_path_identity()?;
    std::fs::remove_file(directory.join(MANIFEST))?;
    File::open(&directory)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"imported": true, "store_uuid": imported.seal.store_uuid,
            "export_id": imported.seal.export_id, "import_id": imported.import_id})
    );
    Ok(())
}

/// Fold an application database's write-ahead log into its main file so the
/// copied file is complete on its own. The host lock guarantees no writer.
fn checkpoint(path: &Path) -> Result<(), CliError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(error)?;
    let busy: i64 = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(error)?;
    if busy != 0 {
        return Err(error("relocation checkpoint is busy"));
    }
    Ok(())
}

mod walk;
use walk::digests;

#[cfg(test)]
fn digest(path: &Path) -> Result<String, CliError> {
    let file = crate::input::open_regular(path)?;
    let expected = file.metadata()?.len();
    digest_file(file, expected)
}

fn digest_file(file: File, expected: u64) -> Result<String, CliError> {
    let limit = expected.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "relocation file length overflow",
        )
    })?;
    let mut file = file.take(limit);
    let mut observed = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed += count as u64;
        hasher.update(&buffer[..count]);
    }
    if observed != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "relocation file length changed while hashing",
        )
        .into());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
#[path = "relocation_reader_tests.rs"]
mod reader_tests;
