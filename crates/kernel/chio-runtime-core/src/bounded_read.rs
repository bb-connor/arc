use std::fs::File;
use std::io::Read;
use std::path::Path;

use chio_core_types::canonical::UntrustedJsonError;

use crate::ChioRuntimeError;

/// Reads the regular file at `path`, refusing it with `UntrustedJsonError::TooLarge`
/// once it holds more than `limit` bytes. At most `limit + 1` bytes are ever
/// buffered, so a file that grows after the length check is still refused.
/// A final-component symlink or any non-regular file (FIFO, socket, device,
/// directory) is refused with `runtime_untrusted_file_not_regular` without
/// blocking on it.
pub(crate) fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, ChioRuntimeError> {
    let file = open_unfollowed(path)?;
    let metadata = file.metadata().map_err(ChioRuntimeError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(not_regular(path));
    }
    let bound = u64::try_from(limit).unwrap_or(u64::MAX);
    if metadata.len() > bound {
        return Err(too_large(
            usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            limit,
        ));
    }
    let mut bytes = Vec::new();
    file.take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(ChioRuntimeError::Io)?;
    if bytes.len() > limit {
        return Err(too_large(bytes.len(), limit));
    }
    Ok(bytes)
}

/// Opens without following a final-component symlink and without waiting for
/// a FIFO writer; the caller still fstats the handle before reading.
#[cfg(unix)]
fn open_unfollowed(path: &Path) -> Result<File, ChioRuntimeError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                not_regular(path)
            } else {
                ChioRuntimeError::Io(error)
            }
        })
}

#[cfg(not(unix))]
fn open_unfollowed(path: &Path) -> Result<File, ChioRuntimeError> {
    let unfollowed = std::fs::symlink_metadata(path).map_err(ChioRuntimeError::Io)?;
    if !unfollowed.file_type().is_file() {
        return Err(not_regular(path));
    }
    File::open(path).map_err(ChioRuntimeError::Io)
}

fn not_regular(path: &Path) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_untrusted_file_not_regular",
        detail: format!("{} is not a regular file", path.display()),
    }
}

fn too_large(bytes: usize, bound: usize) -> ChioRuntimeError {
    ChioRuntimeError::UntrustedInput(UntrustedJsonError::TooLarge { bytes, bound })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn reads_a_file_at_the_limit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("at-limit.json");
        std::fs::write(&path, b"{\"a\":1}")?;
        assert_eq!(read_bounded_file(&path, 7)?, b"{\"a\":1}");
        Ok(())
    }

    #[test]
    fn refuses_a_file_one_byte_over_the_limit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("over-limit.json");
        std::fs::write(&path, b"{\"ab\":1}")?;
        match read_bounded_file(&path, 7) {
            Err(ChioRuntimeError::UntrustedInput(UntrustedJsonError::TooLarge {
                bytes: 8,
                bound: 7,
            })) => Ok(()),
            other => panic!("expected TooLarge {{ bytes: 8, bound: 7 }}, got {other:?}"),
        }
    }

    #[test]
    fn refuses_a_directory() -> TestResult {
        let directory = tempfile::tempdir()?;
        match read_bounded_file(directory.path(), 7) {
            Err(ChioRuntimeError::Rejected { code, .. }) => {
                assert_eq!(code, "runtime_untrusted_file_not_regular");
                Ok(())
            }
            other => panic!("expected runtime_untrusted_file_not_regular, got {other:?}"),
        }
    }
}
