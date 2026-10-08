//! One custody implementation for privileged Unix-domain service sockets.
//!
//! A bound socket is owned by the service user and sits in a directory the
//! service controls, and a lifecycle lock beside it serializes instances. The
//! socket's mode and group are set before it listens, so no connection is ever
//! queued under a looser mode. Every accepted peer is checked against the
//! kernel's record of the connecting process before a stream is returned, and
//! the socket path must still name the bound socket. Dropping the listener
//! removes only the socket it created.

use std::fs::{File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{validate_unix_socket_path, PeerIdentity};

const LISTEN_BACKLOG: i32 = 128;
const OWNER_SOCKET_MODE: u32 = 0o600;
const GROUP_SOCKET_MODE: u32 = 0o660;
const GROUP_DIRECTORY_MODE: u32 = 0o710;

/// Who the socket file itself lets connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAccess {
    /// Mode 0600, in a directory with no group or other access.
    Owner,
    /// Mode 0660 with group `gid`, in a mode 0710 directory of that group, so
    /// members can reach the socket but cannot list or change the directory.
    Group { gid: u32 },
}

/// The kernel-reported identity every accepted peer must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Exactly this process, user and group.
    Process(PeerIdentity),
    /// Any process running as this user.
    User { uid: u32 },
    /// Any process running as this user with this primary group.
    UserAndGroup { uid: u32, gid: u32 },
}

impl PeerPolicy {
    fn admits(self, observed: PeerIdentity) -> bool {
        match self {
            Self::Process(expected) => observed == expected,
            Self::User { uid } => observed.user_id == uid,
            Self::UserAndGroup { uid, gid } => observed.user_id == uid && observed.group_id == gid,
        }
    }

    fn validate(self) -> Result<(), ListenerError> {
        if let Self::Process(expected) = self {
            if expected.process_id == 0 {
                return Err(ListenerError::InvalidPeerPolicy(
                    "peer process ID must be nonzero",
                ));
            }
            if expected.process_id == std::process::id() {
                return Err(ListenerError::InvalidPeerPolicy(
                    "service and client must be separate processes",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketCustody {
    pub socket_path: PathBuf,
    pub trusted_service_uid: u32,
    pub access: SocketAccess,
    pub peer: PeerPolicy,
}

impl SocketCustody {
    const fn socket_mode(&self) -> u32 {
        match self.access {
            SocketAccess::Owner => OWNER_SOCKET_MODE,
            SocketAccess::Group { .. } => GROUP_SOCKET_MODE,
        }
    }

    const fn socket_group(&self) -> Option<u32> {
        match self.access {
            SocketAccess::Owner => None,
            SocketAccess::Group { gid } => Some(gid),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("socket path must be absolute, normalized, named, and within the Unix limit")]
    InvalidPath,
    #[error("peer policy is invalid: {0}")]
    InvalidPeerPolicy(&'static str),
    #[error("kernel-authenticated peer credentials require Linux")]
    Unsupported,
    #[error("socket directory is not controlled by the service user with the required mode")]
    DirectoryCustody,
    #[error("socket lifecycle lock is held by another instance: {0}")]
    LockHeld(#[source] std::io::Error),
    #[error("socket lifecycle lock identity or permissions are invalid")]
    LockCustody,
    #[error("socket path already exists")]
    PathOccupied,
    #[error("socket ownership, group, link count, or permissions are invalid")]
    SocketCustody,
    #[error("socket path no longer names the bound socket")]
    SocketReplaced,
    #[error(
        "peer process {} running as {}:{} is not authorized",
        .observed.process_id,
        .observed.user_id,
        .observed.group_id
    )]
    UnauthorizedPeer { observed: PeerIdentity },
    #[error("socket {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

fn io_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> ListenerError {
    move |source| ListenerError::Io { operation, source }
}

fn errno_error(operation: &'static str) -> impl FnOnce(rustix::io::Errno) -> ListenerError {
    move |errno| ListenerError::Io {
        operation,
        source: errno.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

/// A listening service socket held under [`SocketCustody`].
pub struct CustodialUnixListener {
    listener: UnixListener,
    custody: SocketCustody,
    socket_identity: SocketIdentity,
    _lifecycle_lock: File,
}

impl CustodialUnixListener {
    pub fn bind(custody: SocketCustody) -> Result<Self, ListenerError> {
        if !cfg!(target_os = "linux") {
            return Err(ListenerError::Unsupported);
        }
        validate_unix_socket_path(&custody.socket_path).map_err(|_| ListenerError::InvalidPath)?;
        custody.peer.validate()?;
        validate_socket_directory(&custody)?;
        let lifecycle_lock =
            acquire_lifecycle_lock(&custody.socket_path, custody.trusted_service_uid)?;
        match std::fs::symlink_metadata(&custody.socket_path) {
            Ok(_) => return Err(ListenerError::PathOccupied),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("path metadata")(error)),
        }
        let socket = unbound_stream_socket().map_err(errno_error("creation"))?;
        let address = rustix::net::SocketAddrUnix::new(&custody.socket_path)
            .map_err(errno_error("address"))?;
        rustix::net::bind(&socket, &address).map_err(errno_error("bind"))?;
        let mut provisional = ProvisionalSocketCleanup::new(&custody.socket_path)?;
        apply_socket_custody(&custody)?;
        let socket_identity = validate_socket_identity(&custody)?;
        if socket_identity != provisional.identity {
            return Err(ListenerError::SocketReplaced);
        }
        rustix::net::listen(&socket, LISTEN_BACKLOG).map_err(errno_error("listen"))?;
        let listener = UnixListener::from(socket);
        provisional.armed = false;
        Ok(Self {
            listener,
            custody,
            socket_identity,
            _lifecycle_lock: lifecycle_lock,
        })
    }

    /// Wait for one connection and authenticate its peer.
    pub fn accept_authenticated(&self) -> Result<UnixStream, ListenerError> {
        let (stream, _) = self.listener.accept().map_err(io_error("accept"))?;
        self.authenticate(stream)
    }

    /// Accept one pending connection from a nonblocking listener, or `None`
    /// when none is pending.
    pub fn try_accept_authenticated(&self) -> Result<Option<UnixStream>, ListenerError> {
        match self.listener.accept() {
            Ok((stream, _)) => self.authenticate(stream).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(io_error("accept")(error)),
        }
    }

    /// Wait up to `timeout` for a connection, then accept and authenticate it.
    /// `None` means no connection arrived, or one was withdrawn or interrupted
    /// before it could be accepted. The listener is left nonblocking so a
    /// withdrawn connection never blocks the caller past `timeout`.
    pub fn accept_authenticated_within(
        &self,
        timeout: Duration,
    ) -> Result<Option<UnixStream>, ListenerError> {
        self.set_nonblocking(true)?;
        if !wait_readable(&self.listener, timeout).map_err(io_error("readiness wait"))? {
            return Ok(None);
        }
        match self.listener.accept() {
            Ok((stream, _)) => self.authenticate(stream).map(Some),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(io_error("accept")(error)),
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ListenerError> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(io_error("listener mode change"))
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.custody.socket_path
    }

    fn authenticate(&self, stream: UnixStream) -> Result<UnixStream, ListenerError> {
        let observed = peer_credentials(&stream)?;
        if !self.custody.peer.admits(observed) {
            return Err(ListenerError::UnauthorizedPeer { observed });
        }
        if validate_socket_identity(&self.custody)? != self.socket_identity {
            return Err(ListenerError::SocketReplaced);
        }
        Ok(stream)
    }
}

impl Drop for CustodialUnixListener {
    fn drop(&mut self) {
        if validate_socket_identity(&self.custody)
            .is_ok_and(|identity| identity == self.socket_identity)
        {
            let _remove_result = std::fs::remove_file(&self.custody.socket_path);
        }
    }
}

/// A close-on-exec Unix stream socket, not yet bound.
#[cfg(not(target_vendor = "apple"))]
fn unbound_stream_socket() -> rustix::io::Result<std::os::fd::OwnedFd> {
    rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
}

/// Apple kernels have no `SOCK_CLOEXEC`; close-on-exec is set before the
/// descriptor is shared with anything.
#[cfg(target_vendor = "apple")]
fn unbound_stream_socket() -> rustix::io::Result<std::os::fd::OwnedFd> {
    let socket = rustix::net::socket(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        None,
    )?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
    Ok(socket)
}

/// Wait until `descriptor` is readable, has hung up or has failed, or until
/// `timeout` passes. For a listener, readable means a connection is pending.
/// `false` means nothing happened, or the wait was interrupted; the caller
/// rechecks its own state and waits again.
pub fn wait_readable(descriptor: impl AsFd, timeout: Duration) -> std::io::Result<bool> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};

    let timeout = Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    let mut descriptors = [PollFd::new(&descriptor, PollFlags::IN)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) | Err(rustix::io::Errno::INTR) => Ok(false),
        Ok(_) => Ok(descriptors
            .first()
            .is_some_and(|descriptor| !descriptor.revents().is_empty())),
        Err(errno) => Err(errno.into()),
    }
}

/// The kernel's record of the process at the other end of `stream`, taken
/// when it connected.
#[cfg(target_os = "linux")]
fn peer_credentials(stream: &UnixStream) -> Result<PeerIdentity, ListenerError> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)
        .map_err(errno_error("peer credential lookup"))?;
    let process_id =
        u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| ListenerError::Io {
            operation: "peer credential lookup",
            source: std::io::Error::other("kernel returned a negative peer process ID"),
        })?;
    Ok(PeerIdentity {
        process_id,
        user_id: credentials.uid.as_raw(),
        group_id: credentials.gid.as_raw(),
    })
}

#[cfg(not(target_os = "linux"))]
fn peer_credentials(_stream: &UnixStream) -> Result<PeerIdentity, ListenerError> {
    Err(ListenerError::Unsupported)
}

struct ProvisionalSocketCleanup {
    path: PathBuf,
    identity: SocketIdentity,
    armed: bool,
}

impl ProvisionalSocketCleanup {
    fn new(path: &Path) -> Result<Self, ListenerError> {
        let metadata = std::fs::symlink_metadata(path).map_err(io_error("metadata"))?;
        if !metadata.file_type().is_socket() {
            return Err(ListenerError::SocketReplaced);
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

/// Set the bound socket's group and mode. The socket is not listening yet, so
/// a connection attempt before this point is refused.
fn apply_socket_custody(custody: &SocketCustody) -> Result<(), ListenerError> {
    if let Some(gid) = custody.socket_group() {
        rustix::fs::chown(
            &custody.socket_path,
            None,
            Some(rustix::process::Gid::from_raw(gid)),
        )
        .map_err(errno_error("group change"))?;
    }
    std::fs::set_permissions(
        &custody.socket_path,
        std::fs::Permissions::from_mode(custody.socket_mode()),
    )
    .map_err(io_error("mode change"))
}

fn validate_socket_identity(custody: &SocketCustody) -> Result<SocketIdentity, ListenerError> {
    let metadata = std::fs::symlink_metadata(&custody.socket_path).map_err(io_error("metadata"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != custody.trusted_service_uid
        || custody
            .socket_group()
            .is_some_and(|gid| metadata.gid() != gid)
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != custody.socket_mode()
    {
        return Err(ListenerError::SocketCustody);
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// The socket's directory must be a real directory owned by the service user,
/// reached through no symlink, with no access beyond the socket's own grant.
fn validate_socket_directory(custody: &SocketCustody) -> Result<(), ListenerError> {
    let parent = custody
        .socket_path
        .parent()
        .ok_or(ListenerError::InvalidPath)?;
    let metadata = std::fs::symlink_metadata(parent).map_err(io_error("directory metadata"))?;
    let mode = metadata.permissions().mode();
    let mode_allowed = match custody.access {
        SocketAccess::Owner => mode & 0o077 == 0,
        SocketAccess::Group { gid } => {
            metadata.gid() == gid && mode & 0o777 == GROUP_DIRECTORY_MODE
        }
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != custody.trusted_service_uid
        || !mode_allowed
    {
        return Err(ListenerError::DirectoryCustody);
    }
    if std::fs::canonicalize(parent).map_err(io_error("directory resolution"))? != parent {
        return Err(ListenerError::DirectoryCustody);
    }
    Ok(())
}

fn acquire_lifecycle_lock(path: &Path, trusted_service_uid: u32) -> Result<File, ListenerError> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lifecycle.lock");
    let lock_path = PathBuf::from(lock_path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let flags = i32::try_from(flags.bits()).map_err(|_| ListenerError::LockCustody)?;
    options.custom_flags(flags);
    let lock = options
        .open(&lock_path)
        .map_err(io_error("lifecycle lock open"))?;
    validate_lock_identity(&lock_path, &lock, trusted_service_uid)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|errno| ListenerError::LockHeld(errno.into()))?;
    validate_lock_identity(&lock_path, &lock, trusted_service_uid)?;
    Ok(lock)
}

fn validate_lock_identity(
    path: &Path,
    lock: &File,
    trusted_service_uid: u32,
) -> Result<(), ListenerError> {
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(io_error("lifecycle lock metadata"))?;
    let fd_metadata = lock
        .metadata()
        .map_err(io_error("lifecycle lock descriptor metadata"))?;
    if !path_metadata.file_type().is_file()
        || !fd_metadata.file_type().is_file()
        || path_metadata.dev() != fd_metadata.dev()
        || path_metadata.ino() != fd_metadata.ino()
        || fd_metadata.uid() != trusted_service_uid
        || fd_metadata.nlink() != 1
        || fd_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ListenerError::LockCustody);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "listener_tests.rs"]
mod tests;
