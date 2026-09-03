use std::fs::File;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};

use crate::{BrokerError, Result};

/// Atomically duplicate an exclusively transferred inherited descriptor with
/// close-on-exec set, then retire the original descriptor number.
///
/// # Safety
///
/// The caller must own the live descriptor exclusively under an OS process
/// launch transfer. No Rust value or other code may access or close the
/// original descriptor after this call begins.
#[allow(unsafe_code)]
pub unsafe fn adopt_inherited_key_file(fd: u32, label: &str) -> Result<File> {
    #[cfg(unix)]
    {
        let raw_fd = validate_inherited_descriptor_number(fd, label)?;
        // SAFETY: raw fcntl accepts an integer descriptor and reports EBADF for
        // a closed number without first requiring a Rust descriptor borrow.
        let duplicated = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor duplication failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returns a new live descriptor
        // uniquely owned by this function with CLOEXEC set atomically.
        let descriptor = unsafe { OwnedFd::from_raw_fd(duplicated) };
        // SAFETY: daemon launch transfers exclusive ownership of each inherited
        // descriptor. Successful duplication established that the original was
        // live, and the transfer contract requires retiring it exactly once.
        if unsafe { libc::close(raw_fd) } != 0 {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor retirement failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        let _validated_descriptor = validate_inherited_descriptor_number(fd, label)?;
        Err(BrokerError::Custody(
            "inherited key descriptors require Unix descriptor custody".to_string(),
        ))
    }
}

fn validate_inherited_descriptor_number(fd: u32, label: &str) -> Result<i32> {
    if !(3..=65_535).contains(&fd) {
        return Err(BrokerError::Custody(format!(
            "{label} inherited descriptor number is invalid"
        )));
    }
    i32::try_from(fd).map_err(|_| {
        BrokerError::Custody(format!("{label} inherited descriptor number is invalid"))
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, IntoRawFd};

    use chio_test_support::prelude::*;
    use rustix::io::{fcntl_getfd, FdFlags};

    use super::*;

    fn descriptor_is_closed(raw_fd: i32) -> bool {
        // SAFETY: F_GETFD accepts an integer descriptor and reports EBADF when
        // the number does not designate an open descriptor.
        #[allow(unsafe_code)]
        let result = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    }

    #[test]
    fn inherited_descriptor_number_validation_is_safe_and_bounded() {
        assert!(validate_inherited_descriptor_number(2, "test key").is_err());
        assert!(validate_inherited_descriptor_number(65_536, "test key").is_err());
        assert_eq!(
            validate_inherited_descriptor_number(3, "test key")
                .test_expect("minimum inherited descriptor"),
            3
        );
    }

    #[test]
    fn inherited_transfer_retires_only_the_original_descriptor() {
        let mut source = tempfile::tempfile().test_expect("create ownership-transfer fixture");
        source
            .write_all(b"broker-key")
            .test_expect("write ownership-transfer fixture");
        source
            .seek(SeekFrom::Start(0))
            .test_expect("rewind ownership-transfer fixture");
        let mut independent_alias = source
            .try_clone()
            .test_expect("duplicate ownership-transfer fixture");
        let raw_fd = source.into_raw_fd();

        // SAFETY: into_raw_fd transfers the only Rust ownership of raw_fd to
        // this test. No code accesses or closes it before adoption.
        #[allow(unsafe_code)]
        let mut adopted = unsafe {
            adopt_inherited_key_file(
                u32::try_from(raw_fd).test_expect("fixture descriptor is nonnegative"),
                "test key",
            )
        }
        .test_expect("adopt inherited descriptor");

        assert_ne!(adopted.as_raw_fd(), raw_fd);
        assert!(descriptor_is_closed(raw_fd));
        assert!(fcntl_getfd(&adopted)
            .test_expect("adopted descriptor flags")
            .contains(FdFlags::CLOEXEC));
        let mut bytes = Vec::new();
        adopted
            .read_to_end(&mut bytes)
            .test_expect("read adopted descriptor");
        assert_eq!(bytes, b"broker-key");
        drop(adopted);

        independent_alias
            .seek(SeekFrom::Start(0))
            .test_expect("rewind independent alias");
        bytes.clear();
        independent_alias
            .read_to_end(&mut bytes)
            .test_expect("read independent alias");
        assert_eq!(bytes, b"broker-key");
    }

    #[test]
    fn inherited_adoption_requires_an_unsafe_function_contract() {
        let adoption: unsafe fn(u32, &str) -> Result<File> = adopt_inherited_key_file;
        let _ = adoption;
    }
}
