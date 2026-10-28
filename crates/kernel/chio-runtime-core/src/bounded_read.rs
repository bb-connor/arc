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

#[cfg(windows)]
fn open_unfollowed(path: &Path) -> Result<File, ChioRuntimeError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(0)
        .open(path)
        .map_err(ChioRuntimeError::Io)?;
    let metadata = file.metadata().map_err(ChioRuntimeError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.file_type().is_file()
    {
        return Err(not_regular(path));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_unfollowed(_path: &Path) -> Result<File, ChioRuntimeError> {
    Err(ChioRuntimeError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-follow file opening is unavailable on this platform",
    )))
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

    #[cfg(windows)]
    #[test]
    fn windows_open_refuses_reparse_points_and_accepts_regular_files() -> TestResult {
        let directory = tempfile::tempdir()?;
        let regular = directory.path().join("regular.json");
        let link = directory.path().join("link.json");
        std::fs::write(&regular, b"{}")?;
        std::os::windows::fs::symlink_file(&regular, &link)?;
        assert_eq!(read_bounded_file(&regular, 2)?, b"{}");
        match open_unfollowed(&link) {
            Err(ChioRuntimeError::Rejected { code, detail }) => {
                assert_eq!(code, "runtime_untrusted_file_not_regular");
                assert_eq!(detail, format!("{} is not a regular file", link.display()));
            }
            other => panic!("expected reparse-point refusal, got {other:?}"),
        }
        std::fs::remove_file(&regular)?;
        match read_bounded_file(&link, 2) {
            Err(ChioRuntimeError::Rejected { code, detail }) => {
                assert_eq!(code, "runtime_untrusted_file_not_regular");
                assert_eq!(detail, format!("{} is not a regular file", link.display()));
            }
            other => panic!("expected dangling reparse-point refusal, got {other:?}"),
        }
        Ok(())
    }

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
