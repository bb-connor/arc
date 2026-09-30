//! Nonblocking private pipes with a single deadline across the entire exchange.
use super::*;
use rustix::event::{poll, PollFd, PollFlags, Timespec};

pub(super) fn nonblocking(fd: &impl AsFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| unavailable())?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| unavailable())
}

fn ready(fd: &impl AsFd, events: PollFlags, deadline: Instant) -> Result<()> {
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(unavailable)?;
        let timeout = Timespec {
            tv_sec: i64::try_from(left.as_secs()).map_err(|_| unavailable())?,
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        let mut descriptors = [PollFd::new(fd, events)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(1)
                if descriptors
                    .first()
                    .is_some_and(|fd| fd.revents().contains(events)) =>
            {
                return Ok(())
            }
            Err(rustix::io::Errno::INTR) => continue,
            _ => return Err(unavailable()),
        }
    }
}

impl RepositoryChild {
    pub(super) fn write_frame(&mut self, bytes: &[u8], deadline: Instant) -> Result<()> {
        let prefix = u32::try_from(bytes.len())
            .map_err(|_| denied())?
            .to_be_bytes();
        for mut remaining in [prefix.as_slice(), bytes] {
            while !remaining.is_empty() {
                ready(&self.input, PollFlags::OUT, deadline)?;
                match self.input.write(remaining) {
                    Ok(0) => return Err(unavailable()),
                    Ok(count) => remaining = remaining.get(count..).ok_or_else(unavailable)?,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => return Err(unavailable()),
                }
            }
        }
        Ok(())
    }
    fn read_exact(&mut self, mut remaining: &mut [u8], deadline: Instant) -> Result<()> {
        while !remaining.is_empty() {
            ready(&self.output, PollFlags::IN, deadline)?;
            match self.output.read(remaining) {
                Ok(0) => return Err(unavailable()),
                Ok(count) => remaining = remaining.get_mut(count..).ok_or_else(unavailable)?,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => return Err(unavailable()),
            }
        }
        Ok(())
    }
    pub(super) fn read_frame(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        let mut prefix = [0; 4];
        self.read_exact(&mut prefix, deadline)?;
        let size = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| unavailable())?;
        if !(1..=524_288).contains(&size) {
            return Err(unavailable());
        }
        let mut body = vec![0; size];
        self.read_exact(&mut body, deadline)?;
        Ok(body)
    }
}
