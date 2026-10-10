#[cfg(target_os = "linux")]
use super::REQUIRED_MEMFD_SEALS;
use super::{
    io, peer_credentials, AsRawFd, BTreeSet, BootstrapFault, CageEnforcementFailureCode,
    CageInitPlan, FdPurpose, File, FileExt, FileIdentity, LaunchEnvelope, MetadataExt,
    NativeSyscallProfile, NetworkMode, RawFd, SeccompDefaultAction, CAGE_COMPILER_VERSION,
    CAGE_INIT_PLAN_SCHEMA, LAUNCH_ENVELOPE_SCHEMA, MAX_ARTIFACT_BYTES, MAX_TRANSFER_FDS, PLAN_FD,
    STATUS_FD, TARGET_FD,
};

#[allow(
    clippy::as_conversions,
    reason = "The fixed PLAN_FD, STATUS_FD and TARGET_FD constants are positive and fit u32."
)]
pub(super) fn validate_envelope(
    envelope: &LaunchEnvelope,
    peer: libc::ucred,
) -> Result<(), BootstrapFault> {
    if envelope.schema != LAUNCH_ENVELOPE_SCHEMA
        || envelope.parent_process_id == 0
        || peer.pid <= 0
        || u32::try_from(peer.pid).ok() != Some(envelope.parent_process_id)
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "parent_binding",
        ));
    }
    // SAFETY: getppid takes no pointers and returns the kernel-recorded parent.
    let parent = unsafe { libc::getppid() };
    if parent <= 0 || u32::try_from(parent).ok() != Some(envelope.parent_process_id) {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "parent_process",
        ));
    }
    validate_digest(&envelope.trace_session_digest)?;
    validate_digest(&envelope.plan_digest)?;
    validate_digest(&envelope.fd_table_digest)?;
    validate_digest(&envelope.helper_binding_digest)?;
    validate_digest(&envelope.target_binding_digest)?;
    if envelope.plan.schema != CAGE_INIT_PLAN_SCHEMA
        || envelope.plan.compiler_version != CAGE_COMPILER_VERSION
        || envelope.plan.plan_fd_slot != PLAN_FD as u32
        || envelope.plan.status_fd_slot != STATUS_FD as u32
        || envelope.plan.target_fd_slot != TARGET_FD as u32
        || envelope.plan.resource_limits.nofile_soft > u64::from(envelope.plan.target_fd_slot)
        || envelope.plan.resource_limits.nofile_hard < envelope.plan.resource_limits.nofile_soft
        || envelope.plan.resource_limits.nofile_hard > u64::from(envelope.plan.target_fd_slot)
        || envelope.plan.seccomp.default_action() != SeccompDefaultAction::KillProcess
        || !envelope.plan.landlock.default_filesystem_deny
        || envelope.plan.landlock.network_mode != NetworkMode::Blocked
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_shape",
        ));
    }
    let plan_bytes = chio_cage_plan::canonical_json_bytes(&envelope.plan)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_digest"))?;
    if chio_cage_plan::sha256_hex(&plan_bytes) != envelope.plan_digest {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_digest",
        ));
    }
    let table_bytes =
        chio_cage_plan::canonical_json_bytes(&envelope.plan.fd_table).map_err(|_| {
            BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "fd_table_digest")
        })?;
    if chio_cage_plan::sha256_hex(&table_bytes) != envelope.fd_table_digest {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "fd_table_digest",
        ));
    }
    crate::validate_target_argv(&envelope.plan.target_argv)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "target_argv"))?;
    envelope.plan.execution_identity.validate().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityInvalid,
            "execution_identity",
        )
    })?;
    validate_fd_table_shape(&envelope.plan)
}

pub fn validate_fd_table_shape(plan: &CageInitPlan) -> Result<(), BootstrapFault> {
    if plan.fd_table.is_empty() || plan.fd_table.len() + 1 > MAX_TRANSFER_FDS {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "fd_table_count",
        ));
    }
    let mut slots = BTreeSet::new();
    let mut helper = 0_u8;
    let mut target = 0_u8;
    let mut workdir = 0_u8;
    let mut target_stdin = 0_u8;
    let mut target_stdout = 0_u8;
    let mut target_stderr = 0_u8;
    let mut broker = 0_u8;
    for (position, entry) in plan.fd_table.iter().enumerate() {
        if RawFd::try_from(entry.slot).is_err()
            || !slots.insert(entry.slot)
            || position
                .checked_sub(1)
                .and_then(|index| plan.fd_table.get(index))
                .is_some_and(|previous| previous.slot >= entry.slot)
            || entry.slot <= plan.status_fd_slot
            || entry.purpose != FdPurpose::TargetExecutable
                && u64::from(entry.slot) >= plan.resource_limits.nofile_hard
        {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "fd_table_slots",
            ));
        }
        match entry.purpose {
            FdPurpose::CageInitHelper => {
                helper = helper.saturating_add(1);
                if entry.slot != plan.helper_fd_slot || !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "helper_slot",
                    ));
                }
            }
            FdPurpose::TargetExecutable => {
                target = target.saturating_add(1);
                if entry.slot != plan.target_fd_slot || !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "target_slot",
                    ));
                }
            }
            FdPurpose::WorkingDirectory => {
                workdir = workdir.saturating_add(1);
                if entry.slot != plan.working_directory_fd_slot || !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "workdir_slot",
                    ));
                }
            }
            FdPurpose::TargetStdin => validate_stdio_entry(
                entry,
                &mut target_stdin,
                crate::TARGET_STDIN_FD_SLOT,
                "target_stdin_slot",
            )?,
            FdPurpose::TargetStdout => validate_stdio_entry(
                entry,
                &mut target_stdout,
                crate::TARGET_STDOUT_FD_SLOT,
                "target_stdout_slot",
            )?,
            FdPurpose::TargetStderr => validate_stdio_entry(
                entry,
                &mut target_stderr,
                crate::TARGET_STDERR_FD_SLOT,
                "target_stderr_slot",
            )?,
            FdPurpose::BrokerIpc => {
                broker = broker.saturating_add(1);
                if entry.slot != crate::BROKER_IPC_FD_SLOT
                    || entry.close_on_exec
                    || entry.broker_peer_identity.is_none()
                    || entry.identity.kind() != crate::ResourceKind::UnixSocket
                    || entry.path.is_some()
                    || entry.binding_digest.as_deref()
                        != plan.broker_authentication_digest.as_deref()
                {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "broker_slot",
                    ));
                }
            }
            FdPurpose::RuntimeFile { .. }
            | FdPurpose::ReadGrant { .. }
            | FdPurpose::WriteGrant { .. } => {
                if !entry.close_on_exec {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::InvalidPlan,
                        "resource_close_on_exec",
                    ));
                }
            }
        }
    }
    if helper != 1
        || target != 1
        || workdir != 1
        || target_stdin != 1
        || target_stdout != 1
        || target_stderr != 1
        || broker > 1
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "fd_table_roles",
        ));
    }
    let brokered = plan.seccomp.profile() == NativeSyscallProfile::BrokeredNativeV1;
    if brokered != (broker == 1) || brokered != plan.broker_authentication_digest.is_some() {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "broker_profile",
        ));
    }
    if let Some(authentication_digest) = plan.broker_authentication_digest.as_deref() {
        validate_digest(authentication_digest)?;
    }
    Ok(())
}

fn validate_stdio_entry(
    entry: &crate::FdTableEntry,
    count: &mut u8,
    expected_slot: u32,
    stage: &'static str,
) -> Result<(), BootstrapFault> {
    *count = (*count).saturating_add(1);
    if entry.slot != expected_slot
        || !entry.close_on_exec
        || entry.identity.kind() != crate::ResourceKind::UnixSocket
        || entry.path.is_some()
        || entry.binding_digest.is_some()
        || entry.broker_peer_identity.is_some()
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            stage,
        ));
    }
    Ok(())
}

pub fn verify_descriptor_table(
    envelope: &LaunchEnvelope,
    files: &[File],
) -> Result<(), BootstrapFault> {
    if files.len() != envelope.plan.fd_table.len() {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "received_descriptor_count",
        ));
    }
    let mut live_target_binding = None;
    for (entry, file) in envelope.plan.fd_table.iter().zip(files) {
        let observed_identity = verify_received_descriptor_identity(entry, file)?;
        if matches!(
            entry.purpose,
            FdPurpose::CageInitHelper | FdPurpose::TargetExecutable
        ) || matches!(entry.purpose, FdPurpose::RuntimeFile { .. })
            && entry.identity.mode() & 0o111 != 0
        {
            verify_unprivileged_executable(file)?;
        }
        match entry.purpose {
            FdPurpose::CageInitHelper
            | FdPurpose::TargetExecutable
            | FdPurpose::RuntimeFile { .. } => {
                let expected = entry.binding_digest.as_ref().ok_or_else(|| {
                    BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "artifact_binding",
                    )
                })?;
                let observed_binding_digest = hash_file(file)?;
                if observed_binding_digest != *expected {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "artifact_binding",
                    ));
                }
                if matches!(entry.purpose, FdPurpose::TargetExecutable) {
                    live_target_binding = Some((observed_identity, observed_binding_digest));
                }
            }
            FdPurpose::WorkingDirectory
            | FdPurpose::TargetStdin
            | FdPurpose::TargetStdout
            | FdPurpose::TargetStderr
            | FdPurpose::ReadGrant { .. }
            | FdPurpose::WriteGrant { .. } => {}
            FdPurpose::BrokerIpc => {
                let expected = entry.broker_peer_identity.ok_or_else(|| {
                    BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "broker_peer",
                    )
                })?;
                let actual = peer_credentials(file.as_raw_fd())?;
                if u32::try_from(actual.pid).ok() != Some(expected.pid)
                    || actual.uid != expected.uid
                    || actual.gid != expected.gid
                {
                    return Err(BootstrapFault::new(
                        CageEnforcementFailureCode::DescriptorIdentityMismatch,
                        "broker_peer",
                    ));
                }
            }
        }
    }
    let helper = helper_entry(&envelope.plan)?;
    let target = target_entry(&envelope.plan)?;
    if helper.binding_digest.as_deref() != Some(&envelope.helper_binding_digest)
        || target.binding_digest.as_deref() != Some(&envelope.target_binding_digest)
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "runtime_bindings",
        ));
    }
    let (observed_identity, observed_binding_digest) = live_target_binding.ok_or_else(|| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "target_descriptor",
        )
    })?;
    crate::validate_cage_target_fd_binding(
        &envelope.plan,
        &observed_binding_digest,
        observed_identity,
    )
    .map_err(|_| {
        BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "target_fd_binding")
    })?;
    Ok(())
}

pub fn verify_received_descriptor_identity(
    entry: &crate::FdTableEntry,
    file: &File,
) -> Result<crate::FileIdentity, BootstrapFault> {
    let identity = chio_cage_plan::linux::descriptor_identity(file, None).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "descriptor_identity",
        )
    })?;
    if identity != entry.identity {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "descriptor_identity",
        ));
    }
    Ok(identity)
}

pub(super) fn verify_helper_self(
    envelope: &LaunchEnvelope,
    files: &[File],
) -> Result<(), BootstrapFault> {
    let helper_position = envelope
        .plan
        .fd_table
        .iter()
        .position(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "helper_descriptor",
            )
        })?;
    let expected_file = files.get(helper_position).ok_or_else(|| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "helper_descriptor",
        )
    })?;
    let live = File::open("/proc/self/exe").map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_self",
        )
    })?;
    let expected_identity = chio_cage_plan::linux::descriptor_identity(expected_file, None)
        .map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::HelperIdentityMismatch,
                "helper_self_identity",
            )
        })?;
    let live_identity = chio_cage_plan::linux::descriptor_identity(&live, None).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_self_identity",
        )
    })?;
    let live_binding_digest = hash_file(&live)?;
    if !helper_identity_and_binding_match(
        expected_identity,
        live_identity,
        &envelope.helper_binding_digest,
        &live_binding_digest,
    ) {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_self_binding",
        ));
    }
    Ok(())
}

fn helper_entry(plan: &CageInitPlan) -> Result<&crate::FdTableEntry, BootstrapFault> {
    plan.fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "helper_entry",
            )
        })
}

pub(super) fn target_entry(plan: &CageInitPlan) -> Result<&crate::FdTableEntry, BootstrapFault> {
    plan.fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::TargetExecutable))
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorCountMismatch,
                "target_entry",
            )
        })
}

fn verify_unprivileged_executable(file: &File) -> Result<(), BootstrapFault> {
    let metadata = file.metadata().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::PrivilegedExecutable,
            "executable_metadata",
        )
    })?;
    if metadata.mode() & 0o6000 != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::PrivilegedExecutable,
            "executable_mode",
        ));
    }
    let name = c"security.capability";
    // SAFETY: fgetxattr receives a live descriptor and valid attribute name;
    // null output with size zero queries only the attribute length.
    let capability_size =
        unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if capability_size > 0
        || capability_size < 0
            && !matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA) | Some(libc::ENOTSUP)
            )
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::PrivilegedExecutable,
            "executable_capability",
        ));
    }
    Ok(())
}

pub(super) fn verify_single_threaded() -> Result<(), BootstrapFault> {
    let mut count = 0_usize;
    for entry in std::fs::read_dir("/proc/self/task").map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::NonSingleThreadedHelper,
            "task_directory",
        )
    })? {
        entry.map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::NonSingleThreadedHelper,
                "task_directory",
            )
        })?;
        count = count.saturating_add(1);
    }
    if count != 1 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::NonSingleThreadedHelper,
            "task_count",
        ));
    }
    Ok(())
}

pub(super) fn verify_memfd_seals(fd: RawFd) -> Result<(), BootstrapFault> {
    // SAFETY: F_GET_SEALS reads integer metadata from the live memfd.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 || seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlanSeals,
            "plan_memfd_seals",
        ));
    }
    Ok(())
}

#[allow(
    clippy::indexing_slicing,
    reason = "offset starts at zero, the loop checks it against the allocated size, and each FileExt read is bounded by the remaining slice."
)]
pub fn read_bounded_file(file: &File, max_bytes: usize) -> Result<Vec<u8>, BootstrapFault> {
    let size = usize::try_from(
        file.metadata()
            .map_err(|_| {
                BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_metadata")
            })?
            .len(),
    )
    .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_size"))?;
    if size == 0 || size > max_bytes {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_size",
        ));
    }
    let mut bytes = vec![0_u8; size];
    let mut offset = 0_usize;
    while offset < size {
        let read = file
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset).map_err(|_| {
                    BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_offset")
                })?,
            )
            .map_err(|_| {
                BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_read")
            })?;
        if read == 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "plan_short_read",
            ));
        }
        offset += read;
    }
    Ok(bytes)
}

pub fn hash_file(file: &File) -> Result<String, BootstrapFault> {
    let before = file.metadata().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "artifact_metadata",
        )
    })?;
    let size = before.len();
    if size > MAX_ARTIFACT_BYTES {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "artifact_size",
        ));
    }
    let capacity = usize::try_from(size).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "artifact_size",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < size {
        let read = file.read_at(&mut buffer, offset).map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "artifact_read",
            )
        })?;
        if read == 0 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "artifact_short_read",
            ));
        }
        bytes.extend_from_slice(buffer.get(..read).ok_or(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "artifact_read_count",
        ))?);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| {
                BootstrapFault::new(
                    CageEnforcementFailureCode::DescriptorIdentityMismatch,
                    "artifact_read_count",
                )
            })?)
            .ok_or(BootstrapFault::new(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "artifact_read_offset",
            ))?;
    }
    let after = file.metadata().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "artifact_metadata",
        )
    })?;
    if after.len() != size
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "artifact_changed",
        ));
    }
    Ok(chio_cage_plan::sha256_hex(&bytes))
}

pub fn validate_digest(value: &str) -> Result<(), BootstrapFault> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "digest",
        ));
    }
    Ok(())
}

pub fn helper_identity_and_binding_match(
    expected_identity: FileIdentity,
    live_identity: FileIdentity,
    expected_binding_digest: &str,
    live_binding_digest: &str,
) -> bool {
    expected_identity == live_identity && expected_binding_digest == live_binding_digest
}

pub fn seccomp_profile_is_fail_closed(plan: &crate::SeccompProfilePlan) -> bool {
    plan.validate().is_ok()
}
