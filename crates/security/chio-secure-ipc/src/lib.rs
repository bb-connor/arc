#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
#![deny(unsafe_code)]

//! Shared custody primitives for Linux Unix-domain IPC services.
//!
//! [`listener`] binds service sockets under one custody contract and
//! authenticates every peer before returning a stream; [`frame`] is the one
//! length-prefixed framing every service uses.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

pub mod credentials;
pub mod frame;
#[cfg(unix)]
pub mod listener;

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

/// A private service socket that admits exactly one peer process.
#[cfg(unix)]
pub struct SecureUnixListener {
    inner: listener::CustodialUnixListener,
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
        let inner = listener::CustodialUnixListener::bind(listener::SocketCustody {
            socket_path: config.socket_path,
            trusted_service_uid: config.trusted_service_uid,
            access: listener::SocketAccess::Owner,
            peer: listener::PeerPolicy::Process(config.expected_peer),
        })?;
        Ok(Self { inner })
    }

    pub fn accept_authenticated(&self) -> Result<UnixStream> {
        Ok(self.inner.accept_authenticated()?)
    }

    pub fn try_accept_authenticated(&self) -> Result<Option<UnixStream>> {
        Ok(self.inner.try_accept_authenticated()?)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        Ok(self.inner.set_nonblocking(nonblocking)?)
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.inner.socket_path()
    }
}

#[cfg(unix)]
impl From<listener::ListenerError> for SecureIpcError {
    fn from(error: listener::ListenerError) -> Self {
        use listener::ListenerError;
        match error {
            ListenerError::UnauthorizedPeer { .. } => Self::UnauthorizedPeer,
            ListenerError::InvalidPath | ListenerError::InvalidPeerPolicy(_) => {
                Self::InvalidConfig(error.to_string())
            }
            ListenerError::Io { .. } => Self::Io(error.to_string()),
            ListenerError::Unsupported
            | ListenerError::DirectoryCustody
            | ListenerError::LockHeld(_)
            | ListenerError::LockCustody
            | ListenerError::PathOccupied
            | ListenerError::SocketCustody
            | ListenerError::SocketReplaced => Self::Custody(error.to_string()),
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
                || (metadata.nlink() != 1
                    && !(metadata.nlink() == 0
                        && credentials::is_sealed_credential(&self.file).map_err(|error| {
                            SecureIpcError::Io(format!("{label} descriptor seals failed: {error}"))
                        })?))
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

impl From<frame::FrameError> for SecureIpcError {
    fn from(error: frame::FrameError) -> Self {
        use frame::FrameError;
        match error {
            FrameError::InvalidLimit { .. } => {
                Self::InvalidConfig("frame limit is invalid".to_string())
            }
            FrameError::Empty | FrameError::Oversized { .. } => {
                Self::InvalidFrame("frame is empty or oversized".to_string())
            }
            FrameError::Prefix(error) => Self::InvalidFrame(format!("prefix read failed: {error}")),
            FrameError::Body(error) => Self::InvalidFrame(format!("body read failed: {error}")),
            FrameError::Write(error) => Self::Io(format!("frame write failed: {error}")),
        }
    }
}

pub fn read_bounded_frame(reader: &mut impl Read, maximum_bytes: usize) -> Result<Vec<u8>> {
    Ok(frame::read_frame(reader, maximum_bytes)?)
}

pub fn write_bounded_frame(
    writer: &mut impl Write,
    frame: &[u8],
    maximum_bytes: usize,
) -> Result<()> {
    Ok(frame::write_frame(writer, frame, maximum_bytes)?)
}

#[cfg(test)]
mod tests;
