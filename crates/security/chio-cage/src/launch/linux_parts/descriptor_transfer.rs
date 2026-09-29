use super::*;

#[allow(
    clippy::useless_conversion,
    reason = "libc uses usize fields on glibc and u32 fields on musl; retain checked conversions for both targets."
)]
pub(super) fn send_descriptors(
    socket: RawFd,
    descriptors: &[RawFd],
) -> Result<(), CageLaunchError> {
    if descriptors.is_empty() || descriptors.len() > MAX_TRANSFER_FDS {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_send_count",
        ));
    }
    let count = u32::try_from(descriptors.len()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_send_count",
        )
    })?;
    let mut payload = count.to_le_bytes();
    let mut io_vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let descriptor_bytes = descriptors
        .len()
        .checked_mul(std::mem::size_of::<RawFd>())
        .ok_or_else(|| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "descriptor_send_size",
            )
        })?;
    // SAFETY: CMSG_SPACE computes the required ancillary buffer size.
    let control_size = usize::try_from(unsafe {
        libc::CMSG_SPACE(u32::try_from(descriptor_bytes).map_err(|_| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "descriptor_send_size",
            )
        })?)
    })
    .map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_send_size",
        )
    })?;
    let control_entries = control_size.div_ceil(std::mem::size_of::<libc::cmsghdr>());
    let mut control = Vec::<std::mem::MaybeUninit<libc::cmsghdr>>::with_capacity(control_entries);
    control.resize_with(control_entries, std::mem::MaybeUninit::zeroed);
    // SAFETY: msghdr is a plain C input structure whose zero value denotes no
    // peer address or optional flags.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // msg_controllen is size_t on glibc and socklen_t on musl.
    message.msg_controllen = control_size.try_into().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_send_size",
        )
    })?;
    // SAFETY: message owns a correctly sized control buffer.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "descriptor_send_header",
        ));
    }
    // SAFETY: header points inside control and CMSG_DATA has descriptor_bytes
    // writable bytes after the header.
    let header_fields = unsafe { &mut *header };
    header_fields.cmsg_level = libc::SOL_SOCKET;
    header_fields.cmsg_type = libc::SCM_RIGHTS;
    // SAFETY: descriptor_bytes is bounded by MAX_TRANSFER_FDS and fits c_uint.
    header_fields.cmsg_len = unsafe {
        libc::CMSG_LEN(descriptor_bytes.try_into().map_err(|_| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "descriptor_send_size",
            )
        })?)
    }
    .try_into()
    .map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_send_size",
        )
    })?;
    // SAFETY: header points into the allocated aligned control buffer.
    let data = unsafe { libc::CMSG_DATA(header) };
    // SAFETY: the descriptor array and control buffer are disjoint and both
    // contain descriptor_bytes readable/writable bytes for this synchronous copy.
    unsafe {
        std::ptr::copy_nonoverlapping(descriptors.as_ptr().cast::<u8>(), data, descriptor_bytes);
    }
    // SAFETY: all message buffers and descriptor values remain live for the
    // single atomic sequenced-packet send.
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if usize::try_from(sent) != Ok(payload.len()) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "descriptor_send",
        ));
    }
    Ok(())
}

#[allow(
    clippy::useless_conversion,
    reason = "libc uses usize fields on glibc and u32 fields on musl; retain checked conversions for both targets."
)]
pub(super) fn receive_descriptors(socket: RawFd) -> Result<(File, Vec<OwnedFd>), BootstrapFault> {
    let mut payload = [0_u8; 4];
    let mut io_vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let descriptor_bytes = MAX_TRANSFER_FDS * std::mem::size_of::<RawFd>();
    // SAFETY: CMSG_SPACE computes the maximum ancillary buffer size.
    let control_size = usize::try_from(unsafe {
        libc::CMSG_SPACE(u32::try_from(descriptor_bytes).map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "descriptor_receive_size",
            )
        })?)
    })
    .map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_receive_size",
        )
    })?;
    let control_entries = control_size.div_ceil(std::mem::size_of::<libc::cmsghdr>());
    let mut control = Vec::<std::mem::MaybeUninit<libc::cmsghdr>>::with_capacity(control_entries);
    control.resize_with(control_entries, std::mem::MaybeUninit::zeroed);
    // SAFETY: msghdr is a plain C output structure initialized to no address.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // msg_controllen is size_t on glibc and socklen_t on musl.
    message.msg_controllen = control_size.try_into().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_receive_size",
        )
    })?;
    // SAFETY: all output buffers are writable for the duration of recvmsg.
    let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "descriptor_receive",
        ));
    }
    let mut owned = Vec::new();
    let mut control_headers = 0_usize;
    let mut control_valid = true;
    // SAFETY: message contains the ancillary bytes initialized by recvmsg.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        // SAFETY: header is within the received ancillary buffer.
        let header_fields = unsafe { &*header };
        let valid = header_fields.cmsg_level == libc::SOL_SOCKET
            && header_fields.cmsg_type == libc::SCM_RIGHTS;
        if !valid {
            control_valid = false;
            // SAFETY: CMSG_NXTHDR advances within the same received message.
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
            continue;
        }
        control_headers = control_headers.saturating_add(1);
        // SAFETY: cmsg_len was validated by the kernel to lie in the buffer.
        // cmsg_len is size_t on glibc and socklen_t on musl.
        let length = usize::try_from(header_fields.cmsg_len).map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "descriptor_control_length",
            )
        })?;
        // SAFETY: zero data bytes cannot overflow the CMSG header size calculation.
        let header_length = usize::try_from(unsafe { libc::CMSG_LEN(0) }).map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "descriptor_control_length",
            )
        })?;
        if length < header_length
            || !(length - header_length).is_multiple_of(std::mem::size_of::<RawFd>())
        {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "descriptor_control_length",
            ));
        }
        let count = (length - header_length) / std::mem::size_of::<RawFd>();
        // SAFETY: CMSG_DATA points to count initialized RawFd values.
        let data = unsafe { libc::CMSG_DATA(header) }.cast::<RawFd>();
        // SAFETY: the kernel initialized count aligned RawFd entries in this
        // control buffer; it stays live and immutable until all descriptors are owned.
        let values = unsafe { std::slice::from_raw_parts(data, count) };
        for raw in values {
            if *raw < 0 {
                control_valid = false;
                continue;
            }
            // SAFETY: SCM_RIGHTS returned a new uniquely owned descriptor.
            owned.push(unsafe { OwnedFd::from_raw_fd(*raw) });
        }
        // SAFETY: CMSG_NXTHDR advances within the same received message.
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if usize::try_from(received) != Ok(payload.len())
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || control_headers != 1
        || !control_valid
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "descriptor_receive",
        ));
    }
    let expected = usize::try_from(u32::from_le_bytes(payload)).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_receive_count",
        )
    })?;
    if expected == 0 || expected > MAX_TRANSFER_FDS || owned.len() != expected {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_receive_count",
        ));
    }
    let plan = owned.remove(0);
    Ok((File::from(plan), owned))
}
