use super::{
    io, AsRawFd, BootstrapFault, CageEnforcementFailureCode, CageInitPlan, FdPurpose, File, RawFd,
    PLAN_FD, STATUS_FD, TEMP_FD_START,
};

pub(super) fn remap_descriptors(
    control: File,
    plan_memfd: File,
    resources: Vec<File>,
    plan: &CageInitPlan,
) -> Result<(), BootstrapFault> {
    let mut mappings = Vec::with_capacity(resources.len() + 2);
    mappings.push((control.as_raw_fd(), STATUS_FD, true));
    mappings.push((plan_memfd.as_raw_fd(), PLAN_FD, true));
    for (entry, file) in plan.fd_table.iter().zip(&resources) {
        mappings.push((
            file.as_raw_fd(),
            checked_slot_fd(entry.slot)?,
            entry.close_on_exec,
        ));
    }
    let mut temporary = Vec::with_capacity(mappings.len());
    for (source, target, close_on_exec) in mappings {
        // SAFETY: source is live and F_DUPFD_CLOEXEC returns a new descriptor
        // at or above the collision-free temporary range.
        let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, TEMP_FD_START) };
        if duplicate < 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "descriptor_duplicate",
            ));
        }
        temporary.push((duplicate, target, close_on_exec));
    }
    drop(resources);
    drop(plan_memfd);
    drop(control);
    for (source, target, close_on_exec) in &temporary {
        let flags = if *close_on_exec { libc::O_CLOEXEC } else { 0 };
        // SAFETY: both descriptor numbers are valid, distinct, and the flags
        // value is the only one accepted by dup3.
        if unsafe { libc::dup3(*source, *target, flags) } < 0 {
            close_raw_descriptors(&temporary);
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "descriptor_remap",
            ));
        }
    }
    close_raw_descriptors(&temporary);
    remap_target_stdio(plan)?;
    close_unnamed_descriptors(plan)?;
    Ok(())
}

fn remap_target_stdio(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    for (purpose, target) in [
        (FdPurpose::TargetStdin, 0),
        (FdPurpose::TargetStdout, 1),
        (FdPurpose::TargetStderr, 2),
    ] {
        let source = plan
            .fd_table
            .iter()
            .find(|entry| entry.purpose == purpose)
            .map(|entry| checked_slot_fd(entry.slot))
            .transpose()?
            .ok_or_else(|| {
                BootstrapFault::new(
                    CageEnforcementFailureCode::DescriptorCountMismatch,
                    "target_stdio_remap",
                )
            })?;
        // SAFETY: the fixed source slot was populated from an authenticated
        // descriptor and the target is one of the standard descriptors.
        if unsafe { libc::dup3(source, target, 0) } < 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "target_stdio_remap",
            ));
        }
    }
    Ok(())
}

fn close_raw_descriptors(descriptors: &[(RawFd, RawFd, bool)]) {
    for (source, _, _) in descriptors {
        // SAFETY: each temporary descriptor is uniquely owned by this vector.
        unsafe { libc::close(*source) };
    }
}

fn close_range(first: u32, last: u32) -> Result<(), BootstrapFault> {
    if first > last {
        return Ok(());
    }
    // SAFETY: close_range receives only integer bounds and zero flags.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) };
    if result != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "close_range",
        ));
    }
    Ok(())
}

pub(super) fn checked_slot_fd(slot: u32) -> Result<RawFd, BootstrapFault> {
    RawFd::try_from(slot).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "descriptor_slot_range",
        )
    })
}

pub(super) fn peer_credentials(fd: RawFd) -> Result<libc::ucred, BootstrapFault> {
    // SAFETY: ucred is a plain C output structure that getsockopt initializes.
    let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "peer_credentials",
            )
        })?;
    // SAFETY: the descriptor is a live Unix socket and both output pointers
    // remain valid for the call.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut length,
        )
    } != 0
        || usize::try_from(length) != Ok(std::mem::size_of::<libc::ucred>())
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "peer_credentials",
        ));
    }
    Ok(credentials)
}

pub(super) fn write_packet(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: bytes is a live input buffer and the status descriptor is a
    // connected sequenced-packet socket.
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if usize::try_from(written) == Ok(bytes.len()) {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("partial status packet"))
    }
}

pub(super) fn is_status_socket(fd: RawFd) -> bool {
    let mut socket_type = 0_i32;
    let mut length = match libc::socklen_t::try_from(std::mem::size_of::<i32>()) {
        Ok(length) => length,
        Err(_) => return false,
    };
    // SAFETY: socket_type and length are live outputs. Invalid or closed
    // descriptors simply return an error and are not treated as status paths.
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut socket_type).cast(),
            &mut length,
        ) == 0
            && socket_type == libc::SOCK_SEQPACKET
    }
}

fn close_unnamed_descriptors(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    let mut retained = vec![0_u32, 1, 2, plan.plan_fd_slot, plan.status_fd_slot];
    retained.extend(plan.fd_table.iter().map(|entry| entry.slot));
    retained.sort_unstable();
    retained.dedup();
    let mut first = 0_u32;
    for slot in retained {
        if first < slot {
            close_range(first, slot - 1)?;
        }
        first = slot.saturating_add(1);
    }
    close_range(first, u32::MAX)
}
