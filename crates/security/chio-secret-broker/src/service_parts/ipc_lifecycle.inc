#[cfg(unix)]
struct ProvisionalBrokerSocketCleanup {
    path: PathBuf,
    identity: BrokerSocketIdentity,
    armed: bool,
}

#[cfg(unix)]
impl ProvisionalBrokerSocketCleanup {
    fn new(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            BrokerError::Storage(format!("provisional IPC socket metadata failed: {error}"))
        })?;
        if !metadata.file_type().is_socket() {
            return Err(BrokerError::Custody(
                "provisional IPC path is not the socket just bound".to_string(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: BrokerSocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            armed: true,
        })
    }

    fn identity(&self) -> BrokerSocketIdentity {
        self.identity
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for ProvisionalBrokerSocketCleanup {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if !self.armed {
            return;
        }
        let is_exact_socket = std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.identity.device
                && metadata.ino() == self.identity.inode
        });
        if is_exact_socket {
            let _remove_result = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
impl Drop for UnixBrokerEndpoint {
    fn drop(&mut self) {
        if validate_broker_socket_identity(&self.socket_path, self.trusted_service_uid)
            .is_ok_and(|identity| identity == self.socket_identity)
        {
            let _remove_result = std::fs::remove_file(&self.socket_path);
        }
    }
}

#[cfg(unix)]
fn validate_broker_socket_identity(
    path: &Path,
    trusted_service_uid: u32,
) -> Result<BrokerSocketIdentity> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| BrokerError::Storage(format!("IPC metadata failed: {error}")))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != trusted_service_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Custody(
            "broker IPC socket ownership or permissions do not match the trusted service UID"
                .to_string(),
        ));
    }
    Ok(BrokerSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn acquire_broker_socket_lifecycle_lock(path: &Path, trusted_service_uid: u32) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lifecycle.lock");
    let lock_path = PathBuf::from(lock_path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let flags = i32::try_from(flags.bits())
        .map_err(|_| BrokerError::Storage("IPC lifecycle lock flags are invalid".to_string()))?;
    options.custom_flags(flags);
    let lock = options.open(&lock_path).map_err(|error| {
        BrokerError::Storage(format!("IPC lifecycle lock open failed: {error}"))
    })?;
    let path_metadata = std::fs::symlink_metadata(&lock_path).map_err(|error| {
        BrokerError::Storage(format!("IPC lifecycle lock metadata failed: {error}"))
    })?;
    let descriptor_metadata = lock.metadata().map_err(|error| {
        BrokerError::Storage(format!("IPC lifecycle lock descriptor failed: {error}"))
    })?;
    if !path_metadata.file_type().is_file()
        || !descriptor_metadata.file_type().is_file()
        || path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
        || descriptor_metadata.uid() != trusted_service_uid
        || descriptor_metadata.nlink() != 1
        || descriptor_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Custody(
            "IPC lifecycle lock identity or permissions are invalid".to_string(),
        ));
    }
    rustix::fs::flock(
        &lock,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| {
        BrokerError::AuthorityUnavailable(format!(
            "broker IPC socket is owned by another daemon: {error}"
        ))
    })?;
    let retained_metadata = std::fs::symlink_metadata(&lock_path).map_err(|error| {
        BrokerError::Storage(format!("IPC lifecycle lock revalidation failed: {error}"))
    })?;
    if retained_metadata.dev() != descriptor_metadata.dev()
        || retained_metadata.ino() != descriptor_metadata.ino()
        || !retained_metadata.file_type().is_file()
        || retained_metadata.uid() != trusted_service_uid
        || retained_metadata.nlink() != 1
        || retained_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Custody(
            "IPC lifecycle lock changed during acquisition".to_string(),
        ));
    }
    Ok(lock)
}
