//! Absolute deadlines and finite private channel buffers. Nothing is forwarded.
use super::*;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::io::{Read, Write};
use std::os::{fd::OwnedFd, unix::net::UnixStream};
use std::time::{Duration, Instant};

pub(super) fn socket(file: std::fs::File) -> UnixStream {
    UnixStream::from(OwnedFd::from(file))
}
fn remaining(deadline: Instant) -> Result<Duration, KernelError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| refused("channel deadline"))
}
fn wait(stream: &UnixStream, flags: PollFlags, deadline: Instant) -> Result<(), KernelError> {
    loop {
        let timeout = Timespec::try_from(remaining(deadline)?).map_err(refused)?;
        let mut ready = [PollFd::new(stream, flags | PollFlags::ERR | PollFlags::HUP)];
        match poll(&mut ready, Some(&timeout)) {
            Ok(0) => return Err(refused("channel deadline")),
            Ok(_) if ready[0].revents().contains(PollFlags::NVAL) => {
                return Err(refused("channel descriptor"));
            }
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(refused(error)),
        }
    }
}
pub(super) fn read(
    mut stream: UnixStream,
    limit: usize,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, KernelError> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 1024]);
    stream.set_nonblocking(true).map_err(refused)?;
    loop {
        remaining(deadline)?;
        let n = match stream.read(&mut *buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(&stream, PollFlags::IN, deadline)?;
                continue;
            }
            Err(e) => return Err(refused(e)),
        };
        if n == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(n) > limit {
            return Err(refused("channel bound"));
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
}
pub(super) fn write(
    mut stream: UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), KernelError> {
    stream.set_nonblocking(true).map_err(refused)?;
    while !bytes.is_empty() {
        remaining(deadline)?;
        let n = match stream.write(bytes) {
            Ok(0) => return Err(refused("input closed")),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(&stream, PollFlags::OUT, deadline)?;
                continue;
            }
            Err(e) => return Err(refused(e)),
        };
        bytes = &bytes[n..];
    }
    stream.shutdown(std::net::Shutdown::Write).map_err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn private_channels_preserve_only_bounded_bytes_and_close_input() -> TestResult {
        let (sender, receiver) = UnixStream::pair()?;
        let deadline = Instant::now() + Duration::from_secs(1);
        write(sender, b"true", deadline)?;
        assert_eq!(read(receiver, 8, deadline)?.as_slice(), b"true");
        Ok(())
    }
    #[test]
    fn private_channel_overflow_returns_no_content_or_diagnostic_body() -> TestResult {
        let (sender, receiver) = UnixStream::pair()?;
        let deadline = Instant::now() + Duration::from_secs(1);
        write(sender, b"PRIVATE-RETURN-CANARY", deadline)?;
        let error = read(receiver, 8, deadline)
            .err()
            .ok_or("overflow allowed")?;
        assert!(!error.to_string().contains("PRIVATE-RETURN-CANARY"));
        Ok(())
    }
    #[test]
    fn private_channels_use_absolute_deadline_without_chunk_renewal() -> TestResult {
        let (_sender, receiver) = UnixStream::pair()?;
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        assert!(read(receiver, 8, deadline).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }
}
