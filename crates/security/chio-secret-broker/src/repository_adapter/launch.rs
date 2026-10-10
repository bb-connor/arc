//! Execute only the captured launcher bytes. The pathname is never reopened
//! after hashing, including for shebang scripts whose interpreter reads argv[0].
use super::{denied, unavailable, Result};
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::Command,
};

pub(super) fn capture(bytes: &[u8]) -> Result<File> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    let fd = memfd_create(
        "chio-repository-launcher",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|_| unavailable())?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|_| unavailable())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| unavailable())?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR)
        .map_err(|_| denied())?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .map_err(|_| unavailable())?;
    Ok(file)
}

pub(super) fn command(file: &File) -> Result<Command> {
    let fd = file.as_raw_fd();
    let parent = libc::pid_t::try_from(std::process::id()).map_err(|_| unavailable())?;
    let mut command = Command::new(format!("/proc/self/fd/{fd}"));
    // SAFETY: spawn borrows this command while the caller retains the sealed
    // descriptor. Only the forked child clears CLOEXEC on that descriptor. The
    // callback uses allocation-free Linux syscalls, with no locks or Rust I/O.
    // Parent-death protection also covers adapter SIGKILL; the post-prctl check
    // closes the race where the adapter dies before that protection is installed.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || child_setup(fd, parent));
    }
    Ok(command)
}

fn child_setup(fd: std::os::fd::RawFd, parent: libc::pid_t) -> std::io::Result<()> {
    // SAFETY: the spawning caller retains this sealed descriptor until exec.
    #[allow(unsafe_code)]
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: scalar-only prctl installs a valid Linux signal in the child.
    #[allow(unsafe_code)]
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: getppid has no pointer or descriptor preconditions.
    #[allow(unsafe_code)]
    if unsafe { libc::getppid() } != parent {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}
