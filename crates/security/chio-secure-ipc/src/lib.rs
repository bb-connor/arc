#![deny(unsafe_code)]

//! Shared custody primitives for Linux Unix-domain IPC services.
//!
//! The listener retains an exclusive lifecycle lock, authenticates kernel
//! peer credentials before returning a stream, detects pathname replacement,
//! and removes only the exact socket inode it created.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use serde::{Deserialize, Serialize};

pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 100;
pub const MAX_INHERITED_DESCRIPTOR: u32 = 65_535;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1_048_576;

#[derive(Debug, thiserror::Error)]
pub enum SecureIpcError {
    #[error("secure IPC configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("secure IPC custody failed: {0}")]
    Custody(String),
    #[error("secure IPC peer is not authorized")]
    UnauthorizedPeer,
    #[error("secure IPC operation failed: {0}")]
    Io(String),
    #[error("secure IPC frame is invalid: {0}")]
    InvalidFrame(String),
}

pub type Result<T> = std::result::Result<T, SecureIpcError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerIdentity {
    pub process_id: u32,
    pub user_id: u32,
    pub group_id: u32,
}

impl PeerIdentity {
    pub fn validate(self) -> Result<Self> {
        if self.process_id == 0 {
            return Err(SecureIpcError::InvalidConfig(
                "peer process ID must be nonzero".to_string(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureUnixListenerConfig {
    pub socket_path: PathBuf,
    pub trusted_service_uid: u32,
    pub expected_peer: PeerIdentity,
}

impl SecureUnixListenerConfig {
    fn validate(&self) -> Result<()> {
        validate_unix_socket_path(&self.socket_path)?;
        self.expected_peer.validate()?;
        if self.expected_peer.process_id == std::process::id() {
            return Err(SecureIpcError::InvalidConfig(
                "service and client must be separate processes".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
pub struct SecureUnixListener {
    listener: UnixListener,
    config: SecureUnixListenerConfig,
    socket_identity: SocketIdentity,
    _lifecycle_lock: File,
}

#[cfg(unix)]
impl SecureUnixListener {
    pub fn bind(config: SecureUnixListenerConfig) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(SecureIpcError::Custody(
                "kernel-authenticated peer credentials require Linux".to_string(),
            ));
        }
        config.validate()?;
        validate_private_parent(&config.socket_path, config.trusted_service_uid)?;
        let lifecycle_lock =
            acquire_lifecycle_lock(&config.socket_path, config.trusted_service_uid)?;
        if config.socket_path.exists() {
            return Err(SecureIpcError::Custody(
                "socket path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(&config.socket_path)
            .map_err(|error| SecureIpcError::Io(format!("socket bind failed: {error}")))?;
        let mut provisional = ProvisionalSocketCleanup::new(&config.socket_path)?;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| SecureIpcError::Io(format!("socket chmod failed: {error}")))?;
        let socket_identity =
            validate_socket_identity(&config.socket_path, config.trusted_service_uid)?;
        if socket_identity != provisional.identity {
            return Err(SecureIpcError::Custody(
                "socket identity changed during bind".to_string(),
            ));
        }
        let endpoint = Self {
            listener,
            config,
            socket_identity,
            _lifecycle_lock: lifecycle_lock,
        };
        provisional.armed = false;
        Ok(endpoint)
    }

    pub fn accept_authenticated(&self) -> Result<UnixStream> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|error| SecureIpcError::Io(format!("socket accept failed: {error}")))?;
        self.authenticate(&stream)?;
        Ok(stream)
    }

    pub fn try_accept_authenticated(&self) -> Result<Option<UnixStream>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(SecureIpcError::Io(format!("socket accept failed: {error}"))),
        };
        self.authenticate(&stream)?;
        Ok(Some(stream))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|error| SecureIpcError::Io(format!("listener mode failed: {error}")))
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    fn authenticate(&self, stream: &UnixStream) -> Result<()> {
        let observed = peer_identity(stream)?;
        if observed != self.config.expected_peer {
            return Err(SecureIpcError::UnauthorizedPeer);
        }
        let current =
            validate_socket_identity(&self.config.socket_path, self.config.trusted_service_uid)?;
        if current != self.socket_identity {
            return Err(SecureIpcError::Custody(
                "socket path identity changed after bind".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for SecureUnixListener {
    fn drop(&mut self) {
        if validate_socket_identity(&self.config.socket_path, self.config.trusted_service_uid)
            .is_ok_and(|identity| identity == self.socket_identity)
        {
            let _remove_result = std::fs::remove_file(&self.config.socket_path);
        }
    }
}

#[cfg(unix)]
struct ProvisionalSocketCleanup {
    path: PathBuf,
    identity: SocketIdentity,
    armed: bool,
}

#[cfg(unix)]
impl ProvisionalSocketCleanup {
    fn new(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| SecureIpcError::Io(format!("socket metadata failed: {error}")))?;
        if !metadata.file_type().is_socket() {
            return Err(SecureIpcError::Custody(
                "bound path is not a socket".to_string(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            armed: true,
        })
    }
}

#[cfg(unix)]
impl Drop for ProvisionalSocketCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let exact = std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.identity.device
                && metadata.ino() == self.identity.inode
        });
        if exact {
            let _remove_result = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|error| SecureIpcError::Io(format!("peer credentials failed: {error}")))?;
    let process_id = u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| {
        SecureIpcError::Custody("kernel returned an invalid peer process ID".to_string())
    })?;
    PeerIdentity {
        process_id,
        user_id: credentials.uid.as_raw(),
        group_id: credentials.gid.as_raw(),
    }
    .validate()
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn peer_identity(_stream: &UnixStream) -> Result<PeerIdentity> {
    Err(SecureIpcError::Custody(
        "kernel-authenticated peer credentials require Linux".to_string(),
    ))
}

#[cfg(unix)]
fn validate_socket_identity(path: &Path, trusted_service_uid: u32) -> Result<SocketIdentity> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| SecureIpcError::Io(format!("socket metadata failed: {error}")))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != trusted_service_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SecureIpcError::Custody(
            "socket ownership, link count, or permissions are invalid".to_string(),
        ));
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn validate_private_parent(path: &Path, trusted_service_uid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        SecureIpcError::InvalidConfig("socket path has no parent directory".to_string())
    })?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| SecureIpcError::Io(format!("socket parent metadata failed: {error}")))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != trusted_service_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SecureIpcError::Custody(
            "socket parent must be a private directory owned by the service UID".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_lifecycle_lock(path: &Path, trusted_service_uid: u32) -> Result<File> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lifecycle.lock");
    let lock_path = PathBuf::from(lock_path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let flags = i32::try_from(flags.bits())
        .map_err(|_| SecureIpcError::Io("lifecycle lock flags are invalid".to_string()))?;
    options.custom_flags(flags);
    let lock = options
        .open(&lock_path)
        .map_err(|error| SecureIpcError::Io(format!("lifecycle lock open failed: {error}")))?;
    validate_lock_identity(&lock_path, &lock, trusted_service_uid)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| SecureIpcError::Custody(format!("lifecycle lock is held: {error}")))?;
    validate_lock_identity(&lock_path, &lock, trusted_service_uid)?;
    Ok(lock)
}

#[cfg(unix)]
fn validate_lock_identity(path: &Path, lock: &File, trusted_service_uid: u32) -> Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| SecureIpcError::Io(format!("lifecycle lock metadata failed: {error}")))?;
    let fd_metadata = lock.metadata().map_err(|error| {
        SecureIpcError::Io(format!("lifecycle lock descriptor failed: {error}"))
    })?;
    if !path_metadata.file_type().is_file()
        || !fd_metadata.file_type().is_file()
        || path_metadata.dev() != fd_metadata.dev()
        || path_metadata.ino() != fd_metadata.ino()
        || fd_metadata.uid() != trusted_service_uid
        || fd_metadata.nlink() != 1
        || fd_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SecureIpcError::Custody(
            "lifecycle lock identity or permissions are invalid".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_unix_socket_path(path: &Path) -> Result<()> {
    let encoded = path.as_os_str().as_encoded_bytes();
    let normalized = path.components().all(|component| {
        matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    });
    if !path.is_absolute()
        || path.file_name().is_none()
        || encoded.is_empty()
        || encoded.contains(&0)
        || !normalized
        || encoded.len() > MAX_UNIX_SOCKET_PATH_BYTES
    {
        return Err(SecureIpcError::InvalidConfig(
            "socket path must be absolute, normalized, named, and within the Unix limit"
                .to_string(),
        ));
    }
    Ok(())
}

pub struct InheritedSecretFile {
    file: File,
}

impl InheritedSecretFile {
    /// Adopt an exclusively transferred inherited descriptor.
    ///
    /// The descriptor is duplicated with close-on-exec set atomically, and the
    /// original descriptor number is retired exactly once.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own the live descriptor under a process
    /// launch transfer. No Rust value or other code may access or close the
    /// original descriptor after this call begins.
    #[allow(unsafe_code)]
    pub unsafe fn adopt(fd: u32, label: &str) -> Result<Self> {
        #[cfg(unix)]
        {
            let raw_fd = validate_inherited_descriptor_number(fd, label)?;
            // SAFETY: raw fcntl reports EBADF without creating a Rust borrow.
            let duplicated = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicated < 0 {
                return Err(SecureIpcError::Custody(format!(
                    "{label} descriptor duplication failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned here.
            let descriptor = unsafe { OwnedFd::from_raw_fd(duplicated) };
            // SAFETY: launch transferred exclusive ownership of raw_fd.
            if unsafe { libc::close(raw_fd) } != 0 {
                return Err(SecureIpcError::Custody(format!(
                    "{label} descriptor retirement failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self {
                file: File::from(descriptor),
            })
        }
        #[cfg(not(unix))]
        {
            let _validated = validate_inherited_descriptor_number(fd, label)?;
            Err(SecureIpcError::Custody(
                "inherited descriptors require Unix".to_string(),
            ))
        }
    }

    pub fn validate_private_regular_file(&self, expected_uid: u32, label: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = self.file.metadata().map_err(|error| {
                SecureIpcError::Io(format!("{label} descriptor metadata failed: {error}"))
            })?;
            if !metadata.file_type().is_file()
                || metadata.uid() != expected_uid
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(SecureIpcError::Custody(format!(
                    "{label} descriptor custody is invalid"
                )));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (expected_uid, label);
            Err(SecureIpcError::Custody(
                "inherited descriptors require Unix".to_string(),
            ))
        }
    }

    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }
}

fn validate_inherited_descriptor_number(fd: u32, label: &str) -> Result<i32> {
    if !(3..=MAX_INHERITED_DESCRIPTOR).contains(&fd) {
        return Err(SecureIpcError::InvalidConfig(format!(
            "{label} descriptor number is invalid"
        )));
    }
    i32::try_from(fd)
        .map_err(|_| SecureIpcError::InvalidConfig(format!("{label} descriptor number is invalid")))
}

#[cfg(target_os = "linux")]
pub fn harden_process_custody() -> Result<()> {
    use rustix::process::{dumpable_behavior, set_dumpable_behavior, DumpableBehavior};

    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|error| SecureIpcError::Custody(format!("dump protection failed: {error}")))?;
    if dumpable_behavior().map_err(|error| {
        SecureIpcError::Custody(format!("dump protection check failed: {error}"))
    })? != DumpableBehavior::NotDumpable
    {
        return Err(SecureIpcError::Custody(
            "dump protection was not retained".to_string(),
        ));
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS mutates only the calling process attribute.
    #[allow(unsafe_code)]
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(SecureIpcError::Custody(format!(
            "no-new-privileges setup failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn harden_process_custody() -> Result<()> {
    Err(SecureIpcError::Custody(
        "process custody hardening requires Linux".to_string(),
    ))
}

pub fn read_bounded_frame(reader: &mut impl Read, maximum_bytes: usize) -> Result<Vec<u8>> {
    if maximum_bytes == 0 || maximum_bytes > u32::MAX as usize {
        return Err(SecureIpcError::InvalidConfig(
            "frame limit is invalid".to_string(),
        ));
    }
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| SecureIpcError::InvalidFrame(format!("prefix read failed: {error}")))?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| SecureIpcError::InvalidFrame("length overflow".to_string()))?;
    if length == 0 || length > maximum_bytes {
        return Err(SecureIpcError::InvalidFrame(
            "frame is empty or oversized".to_string(),
        ));
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .map_err(|error| SecureIpcError::InvalidFrame(format!("body read failed: {error}")))?;
    Ok(frame)
}

pub fn write_bounded_frame(
    writer: &mut impl Write,
    frame: &[u8],
    maximum_bytes: usize,
) -> Result<()> {
    if frame.is_empty() || frame.len() > maximum_bytes {
        return Err(SecureIpcError::InvalidFrame(
            "frame is empty or oversized".to_string(),
        ));
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| SecureIpcError::InvalidFrame("length overflow".to_string()))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(|error| SecureIpcError::Io(format!("frame write failed: {error}")))
}

#[cfg(test)]
mod tests;
