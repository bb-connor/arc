//! Private invocation lifetime for the independent zero-effect process.
use super::*;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::os::unix::process::CommandExt;

const OBSERVATION_FD_ENV: &str = "CHIO_BOUNDARY_OBSERVATION_FD";
pub(super) const DONE: u8 = 1;

struct ObservationFd(i32);

impl ObservationFd {
    fn new(raw: i32) -> io::Result<Self> {
        if !(3..=65_535).contains(&raw) {
            return Err(io::Error::other(
                "observation descriptor is outside its transfer range",
            ));
        }
        Ok(Self(raw))
    }
}

pub(super) struct ObservationOwner {
    stream: UnixStream,
}

impl ObservationOwner {
    pub(super) fn spawn(
        mut command: Command,
        listener: TcpListener,
    ) -> io::Result<(Self, ManagedChild)> {
        let (stream, inherited) = private_pair()?;
        let descriptor = ObservationFd::new(inherited.as_raw_fd())?;
        command.env(OBSERVATION_FD_ENV, descriptor.0.to_string());
        let raw = descriptor.0;
        let transfer = move || {
            // SAFETY: only the child changes FD_CLOEXEC for the uniquely
            // transferred live endpoint. fcntl is async-signal-safe.
            #[allow(unsafe_code)]
            let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            #[allow(unsafe_code)]
            if unsafe { libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: pre_exec only runs the above descriptor operations; both
        // endpoints remain owned and live until the spawn transfer completes.
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(transfer);
        }
        let child = spawn_with_stdin(
            command,
            OwnedFd::from(listener),
            "owned zero-effect observer",
        );
        assert!(fcntl_getfd(&stream)?.contains(FdFlags::CLOEXEC));
        assert!(fcntl_getfd(&inherited)?.contains(FdFlags::CLOEXEC));
        drop(inherited);
        Ok((Self { stream }, child))
    }

    pub(super) fn complete_after_verified_reap(mut self) -> io::Result<()> {
        self.stream.write_all(&[DONE])
    }
}

pub(super) fn private_pair() -> io::Result<(UnixStream, UnixStream)> {
    let pair = UnixStream::pair()?;
    for stream in [&pair.0, &pair.1] {
        if !fcntl_getfd(stream)?.contains(FdFlags::CLOEXEC) {
            return Err(io::Error::other("observation lifetime must remain private"));
        }
    }
    Ok(pair)
}

pub(super) fn cancelled(cancel: &UnixStream, timeout: Option<&Timespec>) -> io::Result<bool> {
    let mut descriptors = [PollFd::new(cancel, PollFlags::IN)];
    loop {
        match poll(&mut descriptors, timeout) {
            Err(rustix::io::Errno::INTR) => continue,
            result => {
                result?;
            }
        }
        return Ok(descriptors[0]
            .revents()
            .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL));
    }
}

/// Adopt only the private endpoint exclusively transferred by the observer spawn.
///
/// # Safety
/// The helper launch must transfer this descriptor exclusively. No other Rust
/// value or concurrent code may access, replace or close that inherited slot.
#[allow(unsafe_code)]
pub(super) unsafe fn adopt_inherited_observation() -> io::Result<UnixStream> {
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::FromRawFd;

    let raw = required_environment(OBSERVATION_FD_ENV)
        .parse::<i32>()
        .map_err(|_| io::Error::other("observation descriptor encoding is invalid"))?;
    let raw = ObservationFd::new(raw)?.0;
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes only this stat and accepts a checked integer slot.
    if unsafe { libc::fstat(raw, metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized the complete stat value.
    if unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::other("observation descriptor is not a socket"));
    }
    let mut address = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut address_bytes = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .map_err(|_| io::Error::other("observation address bound is invalid"))?;
    // SAFETY: address points to address_bytes bytes of writable storage.
    if unsafe { libc::getsockname(raw, address.as_mut_ptr().cast(), &mut address_bytes) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getsockname initialized this zeroed address; family is present.
    if i32::from(unsafe { address.assume_init() }.ss_family) != libc::AF_UNIX {
        return Err(io::Error::other(
            "observation descriptor is not a Unix socket",
        ));
    }
    let mut socket_type = 0_i32;
    let mut type_bytes = libc::socklen_t::try_from(size_of::<i32>())
        .map_err(|_| io::Error::other("observation socket bound is invalid"))?;
    // SAFETY: socket_type and type_bytes designate writable integer storage.
    if unsafe {
        libc::getsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut socket_type).cast(),
            &mut type_bytes,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if socket_type != libc::SOCK_STREAM {
        return Err(io::Error::other("observation descriptor is not a stream"));
    }
    // SAFETY: fcntl observes and marks the live exclusive slot close-on-exec.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: launch transfer grants exclusive ownership; the checks establish
    // a live Unix stream and this value retires the inherited ownership once.
    Ok(unsafe { UnixStream::from_raw_fd(raw) })
}
