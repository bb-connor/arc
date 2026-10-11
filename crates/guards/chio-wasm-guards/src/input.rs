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

pub(crate) const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, chio_core::canonical::UntrustedJsonError> {
    chio_core::canonical::UntrustedJsonText::from_wire(bytes, MAX_DOCUMENT_BYTES)?.decode_signed()
}

/// A local YAML parser cause whose public diagnostics do not contain input.
pub struct ManifestYamlError(serde_yml::Error);

impl From<serde_yml::Error> for ManifestYamlError {
    fn from(error: serde_yml::Error) -> Self {
        Self(error)
    }
}
impl std::fmt::Debug for ManifestYamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManifestYamlError")
    }
}
impl std::fmt::Display for ManifestYamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("guard manifest YAML rejected")
    }
}
impl std::error::Error for ManifestYamlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
