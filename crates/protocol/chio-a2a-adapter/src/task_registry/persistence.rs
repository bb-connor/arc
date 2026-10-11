//! Publish only complete registry snapshots within the reader's byte ceiling.

use std::io::{self, BufWriter, Write};
use std::path::Path;

use super::{A2aPersistedTaskRegistry, AdapterError, MAX_A2A_JSON_BYTES};

pub(super) fn save(path: &Path, registry: &A2aPersistedTaskRegistry) -> Result<(), AdapterError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut output = LimitedWriter {
            inner: BufWriter::new(staged.as_file_mut()),
            remaining: MAX_A2A_JSON_BYTES,
        };
        serde_json::to_writer_pretty(&mut output, registry).map_err(|error| {
            AdapterError::Lifecycle(format!(
                "failed to encode bounded A2A task registry {}: {error}",
                path.display()
            ))
        })?;
        output.flush()?;
    }
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .map_err(|error| AdapterError::Io(error.error))?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "A2A task registry exceeds 16 MiB",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.remaining = self.remaining.checked_sub(written).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "registry writer exceeded its byte budget",
            )
        })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
