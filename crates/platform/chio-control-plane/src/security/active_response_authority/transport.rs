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
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use chio_secret_broker::ipc_client::BrokerPeerIdentity;
use chio_security_types::ports::{PortError, PortResult};

#[cfg(target_os = "linux")]
pub(super) fn connect_unix_stream_before(path: &Path, deadline: Instant) -> PortResult<UnixStream> {
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
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error)
            if error == Errno::INPROGRESS
                || error == Errno::AGAIN
                || error == Errno::WOULDBLOCK =>
        {
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
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
                            Ok(Ok(())) => break,
                            Ok(Err(_)) | Err(_) => return Err(PortError::unavailable()),
                        }
                    }
                    Err(Errno::INTR) => continue,
                    Err(_) => return Err(PortError::unavailable()),
                }
            }
        }
        Err(_) => return Err(PortError::unavailable()),
    }
    let stream = UnixStream::from(socket);
    stream
        .set_nonblocking(false)
        .map_err(|_| PortError::unavailable())?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
pub(super) fn validate_connected_peer(
    stream: &UnixStream,
    expected_peer: &BrokerPeerIdentity,
) -> PortResult<()> {
    let credentials =
        rustix::net::sockopt::socket_peercred(stream).map_err(|_| PortError::unavailable())?;
    let process_id =
        u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| PortError::integrity_failure())?;
    let observed = BrokerPeerIdentity {
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
    deadline: Instant,
}

#[cfg(target_os = "linux")]
impl AbsoluteDeadlineUnixStream {
    pub(super) fn new(stream: UnixStream, timeout: Duration) -> PortResult<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(PortError::invalid_data)?;
        Self::with_deadline(stream, deadline)
    }

    pub(super) fn with_deadline(stream: UnixStream, deadline: Instant) -> PortResult<Self> {
        Self::remaining(deadline).map_err(|_| PortError::unavailable())?;
        Ok(Self { stream, deadline })
    }

    fn remaining(deadline: Instant) -> io::Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "IPC deadline elapsed"))
    }
}

#[cfg(target_os = "linux")]
impl Read for AbsoluteDeadlineUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(Self::remaining(self.deadline)?))?;
        self.stream.read(buffer)
    }
}

#[cfg(target_os = "linux")]
impl Write for AbsoluteDeadlineUnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(Self::remaining(self.deadline)?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(Self::remaining(self.deadline)?))?;
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

pub(super) fn now_unix_seconds() -> PortResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PortError::unavailable())
        .and_then(|now| {
            if now == 0 {
                Err(PortError::unavailable())
            } else {
                Ok(now)
            }
        })
}

#[cfg(target_os = "linux")]
pub(super) fn now_unix_millis() -> PortResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PortError::unavailable())?;
    let now = u64::try_from(elapsed.as_millis()).map_err(|_| PortError::unavailable())?;
    if now == 0 {
        Err(PortError::unavailable())
    } else {
        Ok(now)
    }
}
