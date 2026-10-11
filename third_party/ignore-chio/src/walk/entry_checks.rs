use super::*;

pub(super) fn check_symlink_loop(
    ig_parent: &Ignore,
    child_path: &Path,
    child_depth: usize,
) -> Result<(), Error> {
    let hchild = Handle::from_path(child_path).map_err(|err| {
        Error::from(err).with_path(child_path).with_depth(child_depth)
    })?;
    for ig in ig_parent.parents().take_while(|ig| !ig.is_absolute_parent()) {
        let h = Handle::from_path(ig.path()).map_err(|err| {
            Error::from(err).with_path(child_path).with_depth(child_depth)
        })?;
        if hchild == h {
            return Err(Error::Loop {
                ancestor: ig.path().to_path_buf(),
                child: child_path.to_path_buf(),
            }
            .with_depth(child_depth));
        }
    }
    Ok(())
}

// Before calling this function, make sure that you ensure that is really
// necessary as the arguments imply a file stat.
pub(super) fn skip_filesize(
    max_filesize: u64,
    path: &Path,
    ent: &Option<Metadata>,
) -> bool {
    let filesize = match *ent {
        Some(ref md) => Some(md.len()),
        None => None,
    };

    if let Some(fs) = filesize {
        if fs > max_filesize {
            log::debug!("ignoring {}: {} bytes", path.display(), fs);
            true
        } else {
            false
        }
    } else {
        false
    }
}

pub(super) fn should_skip_entry(ig: &Ignore, dent: &DirEntry) -> bool {
    let m = ig.matched_dir_entry(dent);
    if m.is_ignore() {
        log::debug!("ignoring {}: {:?}", dent.path().display(), m);
        true
    } else if m.is_whitelist() {
        log::debug!("whitelisting {}: {:?}", dent.path().display(), m);
        false
    } else {
        false
    }
}

/// Returns a handle to stdout for filtering search.
///
/// A handle is returned if and only if stdout is being redirected to a file.
/// The handle returned corresponds to that file.
///
/// This can be used to ensure that we do not attempt to search a file that we
/// may also be writing to.
pub(super) fn stdout_handle() -> Option<Handle> {
    let h = match Handle::stdout() {
        Err(_) => return None,
        Ok(h) => h,
    };
    let md = match h.as_file().metadata() {
        Err(_) => return None,
        Ok(md) => md,
    };
    if !md.is_file() {
        return None;
    }
    Some(h)
}

/// Returns true if and only if the given directory entry is believed to be
/// equivalent to the given handle. If there was a problem querying the path
/// for information to determine equality, then that error is returned.
pub(super) fn path_equals(dent: &DirEntry, handle: &Handle) -> Result<bool, Error> {
    #[cfg(unix)]
    fn never_equal(dent: &DirEntry, handle: &Handle) -> bool {
        dent.ino() != Some(handle.ino())
    }

    #[cfg(not(unix))]
    fn never_equal(_: &DirEntry, _: &Handle) -> bool {
        false
    }

    // If we know for sure that these two things aren't equal, then avoid
    // the costly extra stat call to determine equality.
    if dent.is_stdin() || never_equal(dent, handle) {
        return Ok(false);
    }
    Handle::from_path(dent.path()).map(|h| &h == handle).map_err(|err| {
        Error::Io(err).with_depth(dent.depth()).with_path(dent.path())
    })
}

/// Returns true if the given walkdir entry corresponds to a directory.
///
/// This is normally just `dent.file_type().is_dir()`, but when we aren't
/// following symlinks, the root directory entry may be a symlink to a
/// directory that we *do* follow---by virtue of it being specified by the user
/// explicitly. In that case, we need to follow the symlink and query whether
/// it's a directory or not. But we only do this for root entries to avoid an
/// additional stat check in most cases.
pub(super) fn walkdir_is_dir(dent: &walkdir::DirEntry) -> bool {
    if dent.file_type().is_dir() {
        return true;
    }
    if !dent.file_type().is_symlink() || dent.depth() > 0 {
        return false;
    }
    dent.path().metadata().ok().map_or(false, |md| md.file_type().is_dir())
}

/// Returns true if and only if the given path is on the same device as the
/// given root device.
pub(super) fn is_same_file_system(root_device: u64, path: &Path) -> Result<bool, Error> {
    let dent_device =
        device_num(path).map_err(|err| Error::Io(err).with_path(path))?;
    Ok(root_device == dent_device)
}

#[cfg(unix)]
pub(super) fn device_num<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;

    path.as_ref().metadata().map(|md| md.dev())
}

#[cfg(windows)]
pub(super) fn device_num<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    use winapi_util::{Handle, file};

    let h = Handle::from_path_any(path)?;
    file::information(h).map(|info| info.volume_serial_number())
}

#[cfg(not(any(unix, windows)))]
pub(super) fn device_num<P: AsRef<Path>>(_: P) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "walkdir: same_file_system option not supported on this platform",
    ))
}
