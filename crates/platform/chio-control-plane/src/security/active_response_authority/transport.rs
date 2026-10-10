use chio_security_types::clock::{AuthorityDeadline, Clock, MonotonicInstant};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use chio_secure_ipc::PeerIdentity;
use chio_security_types::ports::{PortError, PortResult};

#[cfg(all(test, target_os = "linux"))]
mod clock_tests;

#[cfg(target_os = "linux")]
pub(super) fn connect_unix_stream_before(
    path: &Path,
    deadline: MonotonicInstant,
    clock: &dyn Clock,
) -> PortResult<UnixStream> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    use rustix::io::Errno;
    use rustix::net::{
        connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };

    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| PortError::unavailable())?;
    let address = SocketAddrUnix::new(path).map_err(|_| PortError::invalid_data())?;
    loop {
        match connect(&socket, &address) {
            Ok(()) => break,
            Err(error) if error == Errno::ISCONN => break,
            Err(error) if error == Errno::AGAIN || error == Errno::WOULDBLOCK => {
                let remaining = deadline
                    .duration_since(clock.monotonic()?)
                    .ok()
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(PortError::unavailable)?;
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(error) if error == Errno::INPROGRESS || error == Errno::ALREADY => loop {
                let remaining = deadline
                    .duration_since(clock.monotonic()?)
                    .ok()
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(PortError::unavailable)?;
                let timeout =
                    Timespec::try_from(remaining).map_err(|_| PortError::invalid_data())?;
                let mut ready = [PollFd::new(
                    &socket,
                    PollFlags::OUT | PollFlags::ERR | PollFlags::HUP,
                )];
                match poll(&mut ready, Some(&timeout)) {
                    Ok(0) => return Err(PortError::unavailable()),
                    Ok(_) => {
                        if ready[0].revents().contains(PollFlags::NVAL) {
                            return Err(PortError::integrity_failure());
                        }
                        match rustix::net::sockopt::socket_error(&socket) {
                            Ok(Ok(())) => return finish_connected_stream(socket),
                            Ok(Err(_)) | Err(_) => return Err(PortError::unavailable()),
                        }
                    }
                    Err(Errno::INTR) => continue,
                    Err(_) => return Err(PortError::unavailable()),
                }
            },
            Err(_) => return Err(PortError::unavailable()),
        }
    }
    finish_connected_stream(socket)
}

#[cfg(target_os = "linux")]
fn finish_connected_stream(socket: std::os::fd::OwnedFd) -> PortResult<UnixStream> {
    let stream = UnixStream::from(socket);
    stream
        .set_nonblocking(false)
        .map_err(|_| PortError::unavailable())?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
pub(super) fn validate_connected_peer(
    stream: &UnixStream,
    expected_peer: &PeerIdentity,
) -> PortResult<()> {
    let credentials =
        rustix::net::sockopt::socket_peercred(stream).map_err(|_| PortError::unavailable())?;
    let process_id =
        u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| PortError::integrity_failure())?;
    let observed = PeerIdentity {
        process_id,
        user_id: credentials.uid.as_raw(),
        group_id: credentials.gid.as_raw(),
    };
    if &observed != expected_peer {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) struct AbsoluteDeadlineUnixStream {
    stream: UnixStream,
    deadline: AuthorityDeadline,
    clock: Arc<dyn Clock>,
}

#[cfg(target_os = "linux")]
impl AbsoluteDeadlineUnixStream {
    pub(super) fn new(
        stream: UnixStream,
        timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> PortResult<Self> {
        let timeout_ms =
            u64::try_from(timeout.as_millis()).map_err(|_| PortError::invalid_data())?;
        let deadline = AuthorityDeadline::for_timeout_ms(clock.read()?, timeout_ms)?;
        Self::with_deadline(stream, deadline, clock)
    }
    pub(super) fn with_deadline(
        stream: UnixStream,
        deadline: AuthorityDeadline,
        clock: Arc<dyn Clock>,
    ) -> PortResult<Self> {
        let mut value = Self {
            stream,
            deadline,
            clock,
        };
        value.remaining().map_err(|_| PortError::unavailable())?;
        Ok(value)
    }
    fn remaining(&mut self) -> io::Result<Duration> {
        self.clock
            .read()
            .and_then(|now| self.deadline.remaining(now))
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
    }
}

#[cfg(target_os = "linux")]
impl Read for AbsoluteDeadlineUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

#[cfg(target_os = "linux")]
impl Write for AbsoluteDeadlineUnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.flush()
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
pub(super) fn validate_socket_metadata(
    path: &Path,
    trusted_uid: u32,
) -> PortResult<SocketIdentity> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PortError::unavailable())?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != trusted_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(PortError::integrity_failure());
    }
    let parent = path.parent().ok_or_else(PortError::invalid_data)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| PortError::unavailable())?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != trusted_uid
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(PortError::integrity_failure());
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(test)]
pub(super) fn now_unix_seconds() -> PortResult<u64> {
    Ok(chio_security_types::clock::SystemClock
        .unix_millis()?
        .as_secs())
}
