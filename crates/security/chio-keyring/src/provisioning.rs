//! First-start provisioning that remembers the store it created.

use std::path::{Path, PathBuf};

use chio_core_types::Hash;

use crate::{KeyringError, Result};

const RECORD_SUFFIX: &str = ".provisioned";
const MAX_RECORD_BYTES: u64 = 128;

/// Open a service store, provisioning it only on its first start.
///
/// `build(true)` provisions a new store and `build(false)` opens the existing
/// one. The first provisioning records the store's identity in
/// `<file>.provisioned` beside it. A later start that finds the record but no
/// store, or a store whose identity differs from the record, fails closed: an
/// empty replacement would discard the decisions, pin and conflict history a
/// witness or auditor must keep. A store provisioned before records existed
/// adopts one when it is opened.
pub fn open_or_provision_once<T>(
    database_path: &Path,
    provision_allowed: bool,
    build: impl FnOnce(bool) -> Result<T>,
    identity: impl Fn(&T) -> Hash,
) -> Result<T> {
    let record_path = provisioning_record_path(database_path)?;
    let recorded = read_record(&record_path)?;
    if !database_path.try_exists()? {
        if recorded.is_some() {
            return Err(KeyringError::StateInvariant(
                "provisioned key-log store is missing; refusing to provision an empty replacement",
            ));
        }
        if !provision_allowed {
            return build(false);
        }
        let store = build(true)?;
        write_record(database_path, &record_path, identity(&store))?;
        return Ok(store);
    }
    let store = build(false)?;
    match recorded {
        Some(recorded) if recorded != identity(&store) => Err(KeyringError::StateInvariant(
            "key-log store identity differs from its provisioning record",
        )),
        Some(_) => Ok(store),
        None => {
            write_record(database_path, &record_path, identity(&store))?;
            Ok(store)
        }
    }
}

fn provisioning_record_path(database_path: &Path) -> Result<PathBuf> {
    let mut file_name = database_path
        .file_name()
        .ok_or(KeyringError::StateInvariant(
            "key-log database path has no file name",
        ))?
        .to_os_string();
    file_name.push(RECORD_SUFFIX);
    Ok(database_path.with_file_name(file_name))
}

fn read_record(record_path: &Path) -> Result<Option<Hash>> {
    use std::io::Read;

    let file = match open_record_no_follow(record_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(KeyringError::Io(error)),
    };
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES).read_to_string(&mut text)?;
    Hash::from_hex(text.trim())
        .map(Some)
        .map_err(|_| KeyringError::StateInvariant("key-log provisioning record is malformed"))
}

#[cfg(unix)]
fn open_record_no_follow(record_path: &Path) -> std::io::Result<std::fs::File> {
    rustix::fs::open(
        record_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn open_record_no_follow(record_path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(record_path)
}

#[cfg(unix)]
fn write_record(database_path: &Path, record_path: &Path, identity: Hash) -> Result<()> {
    use std::io::Write;

    let parent = crate::open_trusted_sqlite_parent(database_path)?;
    let file_name = record_path.file_name().ok_or(KeyringError::StateInvariant(
        "key-log provisioning record path has no file name",
    ))?;
    let descriptor = rustix::fs::openat(
        &parent,
        file_name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| KeyringError::Io(error.into()))?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(format!("{}\n", identity.to_hex()).as_bytes())?;
    file.sync_all()?;
    parent.sync_all().map_err(KeyringError::Io)
}

#[cfg(not(unix))]
fn write_record(_database_path: &Path, record_path: &Path, identity: Hash) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(record_path)?;
    file.write_all(format!("{}\n", identity.to_hex()).as_bytes())?;
    file.sync_all().map_err(KeyringError::Io)
}
