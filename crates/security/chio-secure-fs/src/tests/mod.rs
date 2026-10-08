use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::{effective_uid, refusal, Owner, OwnerPolicy, Refusal};

mod directory;
mod file;
mod publish;

type TestResult = Result<(), Box<dyn Error>>;

/// The durable-admission directory rule: owned by the effective user and not
/// writable by group or others.
const DIRECTORY: OwnerPolicy = OwnerPolicy {
    owner: Owner::EffectiveUser,
    forbidden_mode: 0o022,
    require_single_link: false,
    reject_acl: false,
};

/// An owner-only directory rule.
const OWNER_ONLY_DIRECTORY: OwnerPolicy = OwnerPolicy {
    owner: Owner::EffectiveUser,
    forbidden_mode: 0o077,
    require_single_link: false,
    reject_acl: false,
};

/// An owner-only, singly linked secret file.
const SECRET: OwnerPolicy = OwnerPolicy {
    owner: Owner::EffectiveUser,
    forbidden_mode: 0o077,
    require_single_link: true,
    reject_acl: false,
};

fn private_root() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn foreign_uid() -> u32 {
    effective_uid().wrapping_add(1)
}

fn mode_of(path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(fs::symlink_metadata(path)?.mode() & 0o7777)
}

fn write_private(path: &Path, contents: &[u8]) -> TestResult {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// The custody rule that refused `result`; fails the test when the operation
/// succeeded or failed for an operating-system reason.
fn refusal_of<T>(result: io::Result<T>) -> Result<Refusal, Box<dyn Error>> {
    match result {
        Ok(_) => Err("operation was not refused".into()),
        Err(error) => refusal(&error)
            .ok_or_else(|| format!("expected a custody refusal, got: {error}").into()),
    }
}

/// The operating-system error kind of a failed `result`.
fn os_error_kind<T>(result: io::Result<T>) -> Result<io::ErrorKind, Box<dyn Error>> {
    match result {
        Ok(_) => Err("operation was not refused".into()),
        Err(error) if refusal(&error).is_some() => {
            Err(format!("expected an operating-system error, got: {error}").into())
        }
        Err(error) => Ok(error.kind()),
    }
}

/// The operating-system error code of a failed `result`.
fn os_error_code<T>(result: io::Result<T>) -> Result<i32, Box<dyn Error>> {
    match result {
        Ok(_) => Err("operation was not refused".into()),
        Err(error) => error
            .raw_os_error()
            .ok_or_else(|| format!("expected an operating-system error, got: {error}").into()),
    }
}

/// `ELOOP`: a no-follow open met a symlink.
fn symlink_loop() -> i32 {
    rustix::io::Errno::LOOP.raw_os_error()
}

/// `ENOTDIR`: a no-follow directory open met a symlink on Linux.
fn not_a_directory() -> i32 {
    rustix::io::Errno::NOTDIR.raw_os_error()
}

fn name(value: &str) -> &OsStr {
    OsStr::new(value)
}

fn append(path: &Path, contents: &[u8]) -> TestResult {
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(contents)?;
    Ok(())
}
