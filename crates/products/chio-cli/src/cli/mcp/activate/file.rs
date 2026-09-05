//! Serialize Chio writers and replace a complete private config after a recheck.
//! Editors must be closed: their writers may not honor the directory lock.

use super::*;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;

pub(super) struct ConfigFile {
    path: PathBuf,
    directory: File,
    metadata: Metadata,
    bytes: Vec<u8>,
}

impl ConfigFile {
    pub(super) fn open(path: &Path) -> Result<Self, CliError> {
        let name = path
            .file_name()
            .ok_or_else(|| invalid("client config requires a file name"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&parent)?;
        if directory.metadata()?.permissions().mode() & 0o022 != 0 {
            return Err(invalid(
                "client config directory must not be writable by group or others",
            ));
        }
        directory.try_lock().map_err(|_| {
            invalid(
                "another configuration update holds this directory; try again after it finishes",
            )
        })?;
        let path = parent.join(name);
        let (metadata, bytes) = read_file(&path)?;
        Ok(Self {
            path,
            directory,
            metadata,
            bytes,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn replace(&self, bytes: &[u8]) -> Result<(), CliError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("client config has no parent"))?;
        let temporary = parent.join(format!(".chio-mcp-{}.tmp", uuid::Uuid::new_v4()));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        let result = (|| {
            output.write_all(bytes)?;
            output.sync_all()?;
            let current_parent = std::fs::metadata(parent)?;
            if !same_file(&current_parent, &self.directory.metadata()?) {
                return Err(invalid("client config directory changed during the update"));
            }
            let (metadata, current) = read_file(&self.path)?;
            if !same_file(&metadata, &self.metadata)
                || current != self.bytes
                || metadata.mode() != self.metadata.mode()
                || metadata.uid() != self.metadata.uid()
                || metadata.gid() != self.metadata.gid()
            {
                return Err(invalid(
                    "client configuration changed during the update; no replacement was made",
                ));
            }
            std::fs::rename(&temporary, &self.path)?;
            self.directory.sync_all().map_err(|_| invalid("configuration was replaced but directory synchronization failed; inspect the config before restarting the client"))?;
            Ok(())
        })();
        // A failed validation leaves the installed configuration intact. A
        // completed rename already removed this unique temporary pathname.
        let _ = std::fs::remove_file(&temporary);
        result
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn read_file(path: &Path) -> Result<(Metadata, Vec<u8>), CliError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid(
            "client config must be a regular file with one link and no group or other write access",
        ));
    }
    let mut bytes = Vec::new();
    file.take(super::super::adopt::MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > super::super::adopt::MAX_CONFIG_BYTES {
        return Err(invalid("MCP config exceeds the 1 MiB limit"));
    }
    Ok((metadata, bytes))
}
