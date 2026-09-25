//! Retain v2 authoring and first-run resolution under the existing host lease.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chio_core_types::crypto::canonical_json_bytes;
use serde::{Deserialize, Serialize};

use super::super::state::{error, read_json, write_secret, Host, MAX_CONFIG_BYTES};
use super::plan::Plan;
use crate::CliError;

const RECORD: &str = "run-plan.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    version: u32,
    source: PathBuf,
    authored: Plan,
    resolved: Plan,
}

pub(super) fn load(host: &Host, source: &Path) -> Result<Plan, CliError> {
    let authored: Plan = read_json(source)?;
    let directory = &host.lease.directory;
    directory.validate_path_identity()?;
    let record = directory.path().join(RECORD);
    if record.symlink_metadata().is_ok() {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&record)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(error("retained run plan must be a private regular file"));
        }
        let mut bytes = Vec::new();
        file.take(2 * MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > 2 * MAX_CONFIG_BYTES {
            return Err(error("retained run plan exceeds two MiB"));
        }
        let saved: Resolution = serde_json::from_slice(&bytes).map_err(error)?;
        if saved.version != 1
            || saved.source != source.canonicalize()?
            || canonical_json_bytes(&saved.authored).map_err(error)?
                != canonical_json_bytes(&authored).map_err(error)?
        {
            return Err(error("run plan or location changed; restore the original configuration and use explicit host relocation when moving state"));
        }
        directory.validate_path_identity()?;
        return Ok(saved.resolved);
    }
    if authored.schema == "chio.process.run.v1" {
        return Ok(authored);
    }
    if authored.schema != "chio.process.run.v2" {
        return Err(error(
            "run plan requires chio.process.run.v1 or chio.process.run.v2",
        ));
    }
    // Never retrofit portable resolution onto an already bound v1 journal.
    if directory.path().join("runner.db").try_exists()? {
        return Err(error(
            "existing run journal has no portable source binding; restore its original v1 plan",
        ));
    }
    let source = source.canonicalize()?;
    let parent = source
        .parent()
        .ok_or_else(|| error("run plan has no parent"))?;
    let mut resolved = authored.clone();
    resolved.schema = "chio.process.run.v1".to_owned();
    for worker in &mut resolved.workers {
        if worker.container.is_none() {
            resolve(parent, &mut worker.cwd, &mut worker.command)?;
        }
    }
    for template in &mut resolved.templates {
        if template.container.is_none() {
            resolve(parent, &mut template.cwd, &mut template.command)?;
        }
    }
    resolved.validate(host)?;
    let saved = Resolution {
        version: 1,
        source,
        authored,
        resolved: resolved.clone(),
    };
    let bytes = canonical_json_bytes(&saved).map_err(error)?;
    if bytes.len() as u64 > 2 * MAX_CONFIG_BYTES {
        return Err(error("resolved run plan exceeds two MiB"));
    }
    write_secret(directory, std::ffi::OsStr::new(RECORD), &bytes)?;
    Ok(resolved)
}

fn resolve(parent: &Path, cwd: &mut PathBuf, command: &mut [String]) -> Result<(), CliError> {
    *cwd = super::super::paths::directory(parent, cwd)?;
    let executable = command
        .first_mut()
        .ok_or_else(|| error("worker command is empty"))?;
    *executable = super::super::paths::executable(cwd, executable)?
        .to_str()
        .ok_or_else(|| error("worker executable path must be UTF-8"))?
        .to_owned();
    Ok(())
}
