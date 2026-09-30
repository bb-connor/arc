//! Bounded fixture files and strict original JSON for recorder and replay.
pub use chio_provider_adapter_core::input::{json, text, typed, MAX_DOCUMENT_BYTES, MAX_RECORDS};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub fn read_fixture(path: &Path) -> io::Result<String> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{open, Mode, OFlags};
        File::from(open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?)
    };
    #[cfg(not(unix))]
    let file = {
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::other("fixture symlink denied"));
        }
        File::open(path)?
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("fixture must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(io::Error::other(
            chio_core::canonical::UntrustedJsonError::TooLarge {
                bytes: bytes.len(),
                bound: MAX_DOCUMENT_BYTES,
            },
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.utf8_error()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn fixture_reader_accepts_bounded_regular_files_and_rejects_oversize() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"{}\n").unwrap();
        assert_eq!(read_fixture(file.path()).unwrap(), "{}\n");
        file.as_file()
            .set_len((MAX_DOCUMENT_BYTES + 1) as u64)
            .unwrap();
        let error = read_fixture(file.path()).unwrap_err();
        assert!(error
            .get_ref()
            .unwrap()
            .downcast_ref::<chio_core::canonical::UntrustedJsonError>()
            .is_some());
    }
    #[cfg(unix)]
    #[test]
    fn fixture_reader_rejects_symlinks_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"{}").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_fixture(&link).is_err());
        assert!(read_fixture(dir.path()).is_err());
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(read_fixture(&fifo).is_err());
    }
}
