//! Private service sockets and the generation records that let a later
//! instance remove a socket this service created.

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::Path;

use chio_core_types::Hash;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};

use crate::{KeyringError, Result};

const SOCKET_GENERATION_DOMAIN: &[u8] = b"chio.key-log.service-socket-generation.v1\0";
/// A generation record is the lowercase hex digest and one newline.
const GENERATION_RECORD_BYTES: usize = 65;

/// A bound service socket, the lifecycle lock that keeps another instance
/// from unlinking it, and the generation of the socket recorded in that lock.
///
/// Only `accept` and `set_nonblocking` reach the listener, so no supported
/// holder can keep the socket listening after it releases the lock. Dropping
/// the listener removes the socket name only while the name still holds this
/// generation, then closes the listener and releases the lock.
///
/// The listener cannot be cloned or turned into a raw descriptor:
///
/// ```compile_fail
/// fn escape(listener: &chio_keyring::PrivateUnixListener) {
///     let _ = listener.try_clone();
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::AsRawFd as _;
///
/// fn escape(listener: &chio_keyring::PrivateUnixListener) {
///     let _ = listener.as_raw_fd();
/// }
/// ```
pub struct PrivateUnixListener {
    listener: UnixListener,
    parent: std::fs::File,
    socket_name: OsString,
    generation: Hash,
    lifecycle_lock: std::fs::File,
}

impl PrivateUnixListener {
    pub fn accept(&self) -> std::io::Result<(UnixStream, SocketAddr)> {
        self.listener.accept()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    #[cfg(test)]
    pub(super) fn descriptors_close_on_exec(&self) -> std::io::Result<[bool; 3]> {
        use std::os::fd::AsFd as _;

        let close_on_exec = |descriptor: std::os::fd::BorrowedFd<'_>| {
            rustix::io::fcntl_getfd(descriptor)
                .map(|flags| flags.contains(rustix::io::FdFlags::CLOEXEC))
                .map_err(std::io::Error::from)
        };
        Ok([
            close_on_exec(self.listener.as_fd())?,
            close_on_exec(self.parent.as_fd())?,
            close_on_exec(self.lifecycle_lock.as_fd())?,
        ])
    }
}

impl Drop for PrivateUnixListener {
    fn drop(&mut self) {
        let _ = remove_socket_of_generation(
            &self.parent,
            &self.socket_name,
            &self.lifecycle_lock,
            self.generation,
        );
    }
}

/// Bind a service socket in a directory only the service user can enter, so
/// no other user can connect, even before the socket's own mode is set, or
/// replace the socket. The directory is opened through the keyring's trusted
/// directory chain, so no other user can swap it or any ancestor, and its
/// descriptor is held for the lock, stale-socket and bind steps. bind(2) has
/// no descriptor-relative form, so after binding the path must still resolve
/// to the held directory and name a socket owned by the service user in it.
///
/// A lifecycle lock beside the socket serializes instances. It also holds the
/// generation of the socket the lock holder bound: the socket's identity,
/// owner, mode and change time, bound to the held directory, the lock and the
/// socket name. An existing socket is removed only when it is not listening
/// and the lock records exactly its generation, so a socket another holder
/// bound, or one this service bound but crashed before recording, is never
/// removed. Such a socket refuses startup. To recover, stop every service that
/// may hold the socket, then remove the socket name and its `.lock` record;
/// keep the databases, provisioning records and seeds.
pub fn bind_private_unix_listener(path: &Path) -> Result<PrivateUnixListener> {
    bind_private_unix_listener_with(path, ListenerHooks::default())
}

/// Steps the constructor runs between its own, for tests that change the
/// filesystem at an exact point.
#[derive(Default)]
pub(super) struct ListenerHooks<'a> {
    pub(super) before_stale_unlink: Option<Box<dyn FnOnce() -> std::io::Result<()> + 'a>>,
    pub(super) before_bind: Option<Box<dyn FnOnce() -> std::io::Result<()> + 'a>>,
    pub(super) before_publication: Option<Box<dyn FnOnce() -> std::io::Result<()> + 'a>>,
}

fn run_hook(hook: Option<Box<dyn FnOnce() -> std::io::Result<()> + '_>>) -> std::io::Result<()> {
    hook.map_or(Ok(()), |hook| hook())
}

pub(super) fn bind_private_unix_listener_with(
    path: &Path,
    hooks: ListenerHooks<'_>,
) -> Result<PrivateUnixListener> {
    if !path.is_absolute() {
        return Err(KeyringError::StateInvariant(
            "service socket path must be absolute",
        ));
    }
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(KeyringError::StateInvariant(
            "service socket path has no parent directory",
        ))?;
    let socket_name = path.file_name().ok_or(KeyringError::StateInvariant(
        "service socket path has no file name",
    ))?;
    let parent = open_private_socket_directory(parent_path)?;
    let lifecycle_lock = lock_socket_lifecycle(&parent, socket_name)?;
    match rustix::fs::statat(&parent, socket_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(existing) => {
            if FileType::from_raw_mode(existing.st_mode) != FileType::Socket {
                return Err(KeyringError::StateInvariant(
                    "service socket path is occupied by a non-socket",
                ));
            }
            let refusal = match connect_unix_without_waiting(path) {
                Ok(_) => None,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
                Err(error)
                    if error.raw_os_error()
                        == Some(rustix::io::Errno::CONNREFUSED.raw_os_error()) =>
                {
                    Some(error)
                }
                Err(error) => return Err(KeyringError::Io(error)),
            };
            let Some(refusal) = refusal else {
                return Err(KeyringError::StateInvariant(
                    "service socket already has a live listener",
                ));
            };
            // A refused connection does not prove the socket stale: BSD kernels
            // also refuse a live listener whose queue is full. Only the
            // generation this lock recorded authorizes removal.
            let generation = socket_generation(&parent, &lifecycle_lock, socket_name, &existing)?;
            if recorded_generation(&lifecycle_lock)? != Some(generation) {
                return Err(KeyringError::Io(refusal));
            }
            run_hook(hooks.before_stale_unlink)?;
            let current = rustix::fs::statat(&parent, socket_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)?;
            if socket_generation(&parent, &lifecycle_lock, socket_name, &current)? != generation {
                return Err(KeyringError::StateInvariant(
                    "service socket changed during its stale check",
                ));
            }
            rustix::fs::unlinkat(&parent, socket_name, AtFlags::empty())
                .map_err(std::io::Error::from)?;
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(KeyringError::Io(error.into())),
    }
    run_hook(hooks.before_bind)?;
    let listener = UnixListener::bind(path)?;
    validate_bound_socket(&parent, parent_path, socket_name)?;
    rustix::fs::chmodat(
        &parent,
        socket_name,
        Mode::RUSR | Mode::WUSR,
        AtFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    let bound = rustix::fs::statat(&parent, socket_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(bound.st_mode) != FileType::Socket
        || bound.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(bound.st_mode) != Mode::RUSR | Mode::WUSR
    {
        return Err(KeyringError::StateInvariant(
            "service socket path does not name the bound socket",
        ));
    }
    let generation = socket_generation(&parent, &lifecycle_lock, socket_name, &bound)?;
    let listener = PrivateUnixListener {
        listener,
        parent,
        socket_name: socket_name.to_os_string(),
        generation,
        lifecycle_lock,
    };
    run_hook(hooks.before_publication)?;
    publish_generation(&listener.lifecycle_lock, &listener.parent, generation)?;
    Ok(listener)
}

/// Open and exclusively lock `<socket>.lock` beside the socket. The lock must
/// be a private regular file with one link and no extended ACL, and its name
/// must still resolve to the locked file once the lock is held.
fn lock_socket_lifecycle(parent: &std::fs::File, socket_name: &OsStr) -> Result<std::fs::File> {
    let mut lock_name = socket_name.to_os_string();
    lock_name.push(".lock");
    let lock = std::fs::File::from(
        rustix::fs::openat(
            parent,
            lock_name.as_os_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(std::io::Error::from)?,
    );
    let metadata = lock.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(KeyringError::StateInvariant(
            "service socket lock must be a regular file",
        ));
    }
    crate::validate_trusted_file_security(&lock, &metadata).map_err(|error| match error {
        KeyringError::StateInvariant(_) => KeyringError::StateInvariant(
            "service socket lock must have trusted ownership, a private mode, no extended ACL and one hard link",
        ),
        other => other,
    })?;
    match rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            return Err(KeyringError::StateInvariant(
                "another service instance holds this socket",
            ));
        }
        Err(error) => return Err(KeyringError::Io(error.into())),
    }
    let named = rustix::fs::statat(parent, lock_name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    let held = rustix::fs::fstat(&lock).map_err(std::io::Error::from)?;
    if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino) {
        return Err(KeyringError::StateInvariant(
            "service socket lock changed while it was locked",
        ));
    }
    Ok(lock)
}

/// The digest of a socket generation: the held directory and lock identities,
/// the socket name, the service user, and the socket's identity, owner, mode
/// and change time. Each field is fixed width, so no two tuples encode alike.
pub(super) fn socket_generation(
    parent: &std::fs::File,
    lifecycle_lock: &std::fs::File,
    socket_name: &OsStr,
    socket: &rustix::fs::Stat,
) -> Result<Hash> {
    let parent_stat = rustix::fs::fstat(parent).map_err(std::io::Error::from)?;
    let lock_stat = rustix::fs::fstat(lifecycle_lock).map_err(std::io::Error::from)?;
    let name = socket_name.as_bytes();
    let name_length = u64::try_from(name.len()).map_err(|_| KeyringError::NumericRange)?;
    let fields = [
        i128::from(parent_stat.st_dev),
        i128::from(parent_stat.st_ino),
        i128::from(lock_stat.st_dev),
        i128::from(lock_stat.st_ino),
        i128::from(rustix::process::geteuid().as_raw()),
        i128::from(socket.st_dev),
        i128::from(socket.st_ino),
        i128::from(socket.st_uid),
        i128::from(socket.st_mode),
        i128::from(socket.st_ctime),
        i128::from(socket.st_ctime_nsec),
    ];
    let mut bytes = Vec::with_capacity(SOCKET_GENERATION_DOMAIN.len() + 8 + name.len() + 16 * 11);
    bytes.extend_from_slice(SOCKET_GENERATION_DOMAIN);
    bytes.extend_from_slice(&name_length.to_be_bytes());
    bytes.extend_from_slice(name);
    for field in fields {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
    Ok(chio_core_types::sha256(&bytes))
}

fn malformed_generation_record() -> KeyringError {
    KeyringError::StateInvariant("service socket generation record is malformed")
}

/// The generation the held lock records, or `None` when it records nothing.
/// At most one byte past a full record is read, and only the exact canonical
/// lowercase digest and newline is accepted.
fn recorded_generation(lifecycle_lock: &std::fs::File) -> Result<Option<Hash>> {
    let mut bytes = Vec::with_capacity(GENERATION_RECORD_BYTES + 1);
    let limit =
        u64::try_from(GENERATION_RECORD_BYTES + 1).map_err(|_| KeyringError::NumericRange)?;
    let mut reader = lifecycle_lock;
    std::io::Seek::rewind(&mut reader)?;
    reader.take(limit).read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != GENERATION_RECORD_BYTES {
        return Err(malformed_generation_record());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| malformed_generation_record())?;
    let generation = text
        .strip_suffix('\n')
        .ok_or_else(malformed_generation_record)
        .and_then(|hex| Hash::from_hex(hex).map_err(|_| malformed_generation_record()))?;
    if encode_generation_record(generation).as_bytes() != bytes.as_slice() {
        return Err(malformed_generation_record());
    }
    Ok(Some(generation))
}

fn encode_generation_record(generation: Hash) -> String {
    format!("{}\n", generation.to_hex())
}

/// Write the generation into the held lock in place and sync it and the
/// directory that holds the socket and lock names.
pub(super) fn publish_generation(
    lifecycle_lock: &std::fs::File,
    parent: &std::fs::File,
    generation: Hash,
) -> Result<()> {
    let record = encode_generation_record(generation);
    lifecycle_lock.write_all_at(record.as_bytes(), 0)?;
    lifecycle_lock.set_len(u64::try_from(record.len()).map_err(|_| KeyringError::NumericRange)?)?;
    lifecycle_lock.sync_all()?;
    parent.sync_all().map_err(KeyringError::Io)
}

/// Remove the socket name only while it still holds `generation`. A missing
/// name, or one rebound, replaced or turned into a symlink, is left alone.
fn remove_socket_of_generation(
    parent: &std::fs::File,
    socket_name: &OsStr,
    lifecycle_lock: &std::fs::File,
    generation: Hash,
) -> Result<()> {
    let current = match rustix::fs::statat(parent, socket_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(current) => current,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(KeyringError::Io(error.into())),
    };
    if socket_generation(parent, lifecycle_lock, socket_name, &current)? != generation {
        return Ok(());
    }
    rustix::fs::unlinkat(parent, socket_name, AtFlags::empty())
        .map_err(|error| KeyringError::Io(error.into()))
}

/// Connect once without waiting for room in the listen queue. Linux reports
/// a live listener's full queue as `EAGAIN`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn connect_unix_without_waiting(path: &Path) -> std::io::Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    rustix::net::connect(&socket, &SocketAddrUnix::new(path)?)?;
    Ok(UnixStream::from(socket))
}

/// BSD-derived kernels refuse a connection to a full listen queue instead of
/// waiting, so a blocking connect returns at once. They report that refusal as
/// `ECONNREFUSED`, the same as a socket with no listener.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn connect_unix_without_waiting(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path)
}

/// Open a socket directory through the keyring's trusted directory chain,
/// which refuses symlinked components, foreign owners, untrusted write bits
/// and extended ACL grants on every component. The directory itself must also
/// be owned by the service user with no group or other access, because
/// connecting needs only search permission on it.
pub(super) fn open_private_socket_directory(parent_path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;

    let directory =
        crate::open_trusted_unix_directory_chain(parent_path).map_err(|error| match error {
            KeyringError::StateInvariant(_) => KeyringError::StateInvariant(
                "service socket directory path must consist of directories owned by the service or root that grant no untrusted write access or extended ACL",
            ),
            other => other,
        })?;
    let metadata = directory.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(KeyringError::StateInvariant(
            "service socket directory must be private to the service user",
        ));
    }
    Ok(directory)
}

/// Require the socket path to still resolve to the held directory and the
/// bound name in it to be a socket owned by the service user.
fn validate_bound_socket(
    parent: &std::fs::File,
    parent_path: &Path,
    socket_name: &OsStr,
) -> Result<()> {
    let current = open_private_socket_directory(parent_path)?;
    if !crate::unix_metadata_identity_matches(&parent.metadata()?, &current.metadata()?) {
        return Err(KeyringError::StateInvariant(
            "service socket directory changed while the socket was bound",
        ));
    }
    let bound = rustix::fs::statat(parent, socket_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(bound.st_mode) != FileType::Socket
        || bound.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(KeyringError::StateInvariant(
            "service socket path does not name the bound socket",
        ));
    }
    Ok(())
}
