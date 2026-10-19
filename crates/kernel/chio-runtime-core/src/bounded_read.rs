use std::fs::File;
use std::io::Read;
use std::path::Path;

use chio_core_types::canonical::UntrustedJsonError;

use crate::ChioRuntimeError;

/// Reads the file at `path`, refusing it with `UntrustedJsonError::TooLarge`
/// once it holds more than `limit` bytes. At most `limit + 1` bytes are ever
/// buffered, so a file that grows after the length check is still refused.
pub(crate) fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, ChioRuntimeError> {
    let file = File::open(path).map_err(ChioRuntimeError::Io)?;
    let len = file.metadata().map_err(ChioRuntimeError::Io)?.len();
    let bound = u64::try_from(limit).unwrap_or(u64::MAX);
    if len > bound {
        return Err(too_large(usize::try_from(len).unwrap_or(usize::MAX), limit));
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
}
