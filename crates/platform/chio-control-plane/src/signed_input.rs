//! Bounded original-byte readers for operator files carrying authenticated data.

use std::io::Read;
use std::path::Path;

use chio_core::canonical::UntrustedJsonText;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::CliError;

pub(crate) const MAX_SIGNED_FILE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn read_bounded(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(crate::integer::count(MAX_SIGNED_FILE_BYTES + 1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    Ok(UntrustedJsonText::from_wire(bytes, MAX_SIGNED_FILE_BYTES)?.decode_signed()?)
}

/// Space kept free below the read cap so redemptions of live records, which
/// only add small fields to existing entries, can still be persisted after
/// issuance has been refused.
pub(crate) const ISSUANCE_RESERVE_BYTES: usize = 1024 * 1024;

/// Writes `value` as compact JSON, refusing any file the bounded reader could
/// not load back. The destination is untouched when the write is refused.
pub(crate) fn write_bounded_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    write_bounded_json_with_limit(path, value, MAX_SIGNED_FILE_BYTES)
}

/// Collects serializer output and refuses to grow past `limit` bytes, so an
/// oversized value never materializes beyond the cap.
struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl std::io::Write for LimitedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::other("registry size limit exceeded"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn write_bounded_json_with_limit<T: Serialize>(
    path: &Path,
    value: &T,
    limit: usize,
) -> Result<(), CliError> {
    let mut buffer = LimitedBuffer {
        bytes: Vec::new(),
        limit,
        overflowed: false,
    };
    if let Err(error) = serde_json::to_writer(&mut buffer, value) {
        if buffer.overflowed {
            return Err(CliError::policy_constraint_error(format!(
                "registry file would exceed the {limit} byte limit; the existing file was left unchanged"
            )));
        }
        return Err(error.into());
    }
    replace_file(path, &buffer.bytes)
}

/// Replaces `path` through a freshly created, randomly named sibling that is
/// opened exclusively with owner-only permissions (never more permissive than
/// the file it replaces), synced, and renamed into place. A failure removes
/// only the temporary file this call created and leaves the prior file intact.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_io_error("registry path has no file name"))?
        .to_string_lossy();
    let temporary = directory.join(format!(
        ".{file_name}.{}.tmp",
        chio_core::Keypair::generate().public_key().to_hex()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mode = match std::fs::metadata(path) {
            Ok(existing) => existing.mode() & 0o600,
            Err(_) => 0o600,
        };
        options.mode(mode);
    }
    let mut file = options.open(&temporary)?;
    let written = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(directory)?.sync_all()
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(CliError::Io(error));
    }
    Ok(())
}

pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    decode(&read_bounded(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_input_keeps_full_width_integers_and_rejects_nested_aliases() {
        let value: serde_json::Value =
            decode(br#"{"amount":18446744073709551615,"nested":{"limit":1}}"#)
                .unwrap_or_else(|error| panic!("valid signed input: {error}"));
        assert_eq!(value["amount"].as_u64(), Some(u64::MAX));
        for bytes in [
            br#"{"nested":{"limit":0,"limit":1}}"#.as_slice(),
            br#"{"nested":{"limit":1.0000000000000001}}"#.as_slice(),
        ] {
            assert!(matches!(
                decode::<serde_json::Value>(bytes),
                Err(CliError::SignedJson(
                    chio_core::canonical::UntrustedJsonError::SignedInput(_)
                ))
            ));
        }
    }
}
