use std::{io, os::raw::c_int};

pub(super) fn acl_entry_returned(result: c_int, error: io::Error) -> io::Result<bool> {
    // Darwin yields an entry with 0 and ends the list with -1/EINVAL.
    // errno may be stale after a successful call, so inspect it only on -1.
    if result == 0 {
        return Ok(true);
    }
    if result == -1 && error.raw_os_error() == Some(rustix::io::Errno::INVAL.raw_os_error()) {
        return Ok(false);
    }
    Err(if result == -1 {
        error
    } else {
        io::Error::other("unexpected Darwin ACL entry result")
    })
}

#[cfg(target_vendor = "apple")]
pub(super) fn trusted_file_has_extended_acl(file: &std::fs::File) -> super::Result<bool> {
    use std::os::fd::AsRawFd;

    type Acl = *mut std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut *mut std::ffi::c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut std::ffi::c_void, tag_type: *mut c_int) -> c_int;
        fn acl_free(value: *mut std::ffi::c_void) -> c_int;
    }

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    // SAFETY: `file` owns a valid descriptor and ACL_TYPE_EXTENDED is the
    // platform-defined ACL type. The returned allocation is released below.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // Darwin reports ENOENT when a valid descriptor has no extended ACL
        // object. Descriptor metadata was already read successfully, so this
        // means that no additional ACL authority exists rather than that the
        // file disappeared.
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(super::KeyringError::Io(error));
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is a live ACL object and `entry` points to writable storage.
    let mut entry_result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let mut acl_error = None;
    let mut grants_additional_authority = false;
    loop {
        match acl_entry_returned(entry_result, io::Error::last_os_error()) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                acl_error = Some(error);
                break;
            }
        }
        let mut tag_type = 0;
        // SAFETY: `entry` was returned by `acl_get_entry` for the live ACL.
        if unsafe { acl_get_tag_type(entry, &mut tag_type) } != 0 {
            acl_error = Some(io::Error::last_os_error());
            break;
        }
        // A deny-only entry cannot add authority. Any allow or unknown tag is
        // rejected conservatively without trying to reproduce Darwin's ACL
        // precedence rules.
        if super::apple_acl_tag_grants_additional_authority(tag_type) {
            grants_additional_authority = true;
            break;
        }
        // SAFETY: `acl` remains live and `entry` points to writable storage.
        entry_result = unsafe { acl_get_entry(acl, ACL_NEXT_ENTRY, &mut entry) };
    }
    // SAFETY: `acl` was allocated by `acl_get_fd_np` and is freed exactly once.
    let free_result = unsafe { acl_free(acl) };
    if let Some(error) = acl_error {
        return Err(super::KeyringError::Io(error));
    }
    if free_result != 0 {
        return Err(super::KeyringError::Io(io::Error::last_os_error()));
    }
    Ok(grants_additional_authority)
}

#[cfg(all(test, target_vendor = "apple"))]
mod native_tests;

#[cfg(test)]
mod tests {
    use super::acl_entry_returned;
    use std::io;

    #[test]
    fn acl_return_code_zero_yields_an_entry_even_with_stale_errno() -> io::Result<()> {
        let stale_error = io::Error::from_raw_os_error(rustix::io::Errno::INVAL.raw_os_error());
        assert!(acl_entry_returned(0, stale_error)?);
        Ok(())
    }

    #[test]
    fn acl_return_code_einval_terminates_an_empty_or_exhausted_acl() -> io::Result<()> {
        let error = io::Error::from_raw_os_error(rustix::io::Errno::INVAL.raw_os_error());
        assert!(!acl_entry_returned(-1, error)?);
        Ok(())
    }

    #[test]
    fn acl_return_code_real_errors_fail_closed() {
        let errno = rustix::io::Errno::IO.raw_os_error();
        let result = acl_entry_returned(-1, io::Error::from_raw_os_error(errno));
        assert_eq!(
            result.err().and_then(|error| error.raw_os_error()),
            Some(errno)
        );
    }

    #[test]
    fn acl_return_code_linux_success_is_rejected() {
        let stale_error = io::Error::from_raw_os_error(rustix::io::Errno::INVAL.raw_os_error());
        assert!(matches!(
            acl_entry_returned(1, stale_error),
            Err(error) if error.kind() == io::ErrorKind::Other
                && error.raw_os_error().is_none()
                && error.to_string() == "unexpected Darwin ACL entry result"
        ));
    }

    #[test]
    fn acl_return_code_unexpected_status_fails_closed() {
        let stale_error = io::Error::from_raw_os_error(rustix::io::Errno::INVAL.raw_os_error());
        assert!(matches!(
            acl_entry_returned(2, stale_error),
            Err(error) if error.kind() == io::ErrorKind::Other
                && error.raw_os_error().is_none()
                && error.to_string() == "unexpected Darwin ACL entry result"
        ));
    }
}
