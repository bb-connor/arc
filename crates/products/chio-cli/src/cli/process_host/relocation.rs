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
use std::path::{Path, PathBuf};

use chio_control_plane::DurableAdmissionRuntime;
use chio_store_sqlite::RelocationSeal;
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
const EXCLUDED_SUFFIXES: [&str; 3] = ["-wal", "-shm", ".tmp"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    #[serde(default = "super::state::first_abi")]
    abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    written_by: Option<String>,
    seal: RelocationSeal,
    files: BTreeMap<String, String>,
}

pub(super) fn export(state: &Path) -> Result<(), CliError> {
    let lease = Lease::acquire(state, false)?;
    let directory = lease.directory.path().to_path_buf();
    for name in CHECKPOINTED {
        let path = directory.join(name);
        if path.try_exists()? {
            checkpoint(&path)?;
        }
    }
    let seal = DurableAdmissionRuntime::export_relocation(&directory.join("authority.db"))?;
    let files = digests(&directory)?;
    let manifest = Manifest {
        schema: SCHEMA.to_owned(),
        abi: chio_process::PROCESS_ABI.to_owned(),
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
    let actual = digests(&directory)?;
    for (name, expected) in &manifest.files {
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
    let imported = DurableAdmissionRuntime::import_relocation(&directory.join("authority.db"))?;
    if imported.seal != manifest.seal {
        return Err(error(
            "the authority seal does not match the relocation manifest",
        ));
    }
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
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(error)?;
    Ok(())
}

/// SHA-256 of every regular file that travels with the directory, keyed by
/// its slash-separated relative path.
fn digests(directory: &Path) -> Result<BTreeMap<String, String>, CliError> {
    let mut files = BTreeMap::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if current == directory && EXCLUDED_DIRECTORIES.contains(&name.as_str()) {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                if file_type.is_symlink() {
                    return Err(error(format!(
                        "host state must not contain symlinks: {}",
                        relative(directory, &path)?
                    )));
                }
                continue;
            }
            if (current == directory && EXCLUDED.contains(&name.as_str()))
                || EXCLUDED_SUFFIXES
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
            {
                continue;
            }
            files.insert(relative(directory, &path)?, digest(&path)?);
        }
    }
    Ok(files)
}

fn relative(directory: &Path, path: &Path) -> Result<String, CliError> {
    let relative: PathBuf = path
        .strip_prefix(directory)
        .map_err(|_| error("relocated file escaped the state directory"))?
        .to_path_buf();
    relative
        .to_str()
        .map(|text| text.replace(std::path::MAIN_SEPARATOR, "/"))
        .ok_or_else(|| error("relocated file name is not valid UTF-8"))
}

fn digest(path: &Path) -> Result<String, CliError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
