//! Bounded custody for guard input files.
use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

pub(crate) fn read_file(path: &Path, bound: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guard input must be a regular file",
        ));
    }
    let limit = u64::try_from(bound).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if metadata.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guard input exceeds byte limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guard input exceeds byte limit",
        ));
    }
    Ok(bytes)
}

pub(crate) const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn external<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> crate::oci::Result<T> {
    Ok(
        chio_core_types::canonical::UntrustedJsonText::from_wire(bytes, MAX_JSON_BYTES)?
            .decode_external()?,
    )
}
