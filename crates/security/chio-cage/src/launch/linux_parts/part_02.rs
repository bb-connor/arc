fn syscall_number(architecture: SandboxArchitecture, name: &str) -> Option<u32> {
    match architecture {
        SandboxArchitecture::X86_64 => Some(match name {
            "read" => 0,
            "write" => 1,
            "close" => 3,
            "fstat" => 5,
            "poll" => 7,
            "lseek" => 8,
            "mmap" => 9,
            "mprotect" => 10,
            "munmap" => 11,
            "brk" => 12,
            "rt_sigaction" => 13,
            "rt_sigprocmask" => 14,
            "rt_sigreturn" => 15,
            "ioctl" => 16,
            "pread64" => 17,
            "access" => 21,
            "readv" => 19,
            "writev" => 20,
            "sched_yield" => 24,
            "mremap" => 25,
            "madvise" => 28,
            "nanosleep" => 35,
            "setitimer" => 38,
            "getpid" => 39,
            "sendto" => 44,
            "recvfrom" => 45,
            "sendmsg" => 46,
            "recvmsg" => 47,
            "exit" => 60,
            "getdents64" => 217,
            "getcwd" => 79,
            "sigaltstack" => 131,
            "arch_prctl" => 158,
            "gettid" => 186,
            "futex" => 202,
            "set_tid_address" => 218,
            "restart_syscall" => 219,
            "clock_gettime" => 228,
            "exit_group" => 231,
            "epoll_ctl" => 233,
            "tgkill" => 234,
            "openat" => 257,
            "newfstatat" => 262,
            "readlinkat" => 267,
            "ppoll" => 271,
            "set_robust_list" => 273,
            "epoll_pwait" => 281,
            "eventfd2" => 290,
            "epoll_create1" => 291,
            "pipe2" => 293,
            "prlimit64" => 302,
            "execveat" => 322,
            "getrandom" => 318,
            "statx" => 332,
            "rseq" => 334,
            "openat2" => 437,
            "faccessat2" => 439,
            _ => return None,
        }),
        SandboxArchitecture::Aarch64 => Some(match name {
            "getcwd" => 17,
            "eventfd2" => 19,
            "epoll_create1" => 20,
            "epoll_ctl" => 21,
            "epoll_pwait" => 22,
            "ioctl" => 29,
            "openat" => 56,
            "close" => 57,
            "pipe2" => 59,
            "getdents64" => 61,
            "lseek" => 62,
            "read" => 63,
            "write" => 64,
            "readv" => 65,
            "writev" => 66,
            "pread64" => 67,
            "ppoll" => 73,
            "readlinkat" => 78,
            "newfstatat" => 79,
            "fstat" => 80,
            "exit" => 93,
            "exit_group" => 94,
            "set_tid_address" => 96,
            "futex" => 98,
            "set_robust_list" => 99,
            "nanosleep" => 101,
            "setitimer" => 103,
            "clock_gettime" => 113,
            "sched_yield" => 124,
            "restart_syscall" => 128,
            "tgkill" => 131,
            "sigaltstack" => 132,
            "rt_sigaction" => 134,
            "rt_sigprocmask" => 135,
            "rt_sigreturn" => 139,
            "getpid" => 172,
            "gettid" => 178,
            "sendto" => 206,
            "recvfrom" => 207,
            "sendmsg" => 211,
            "recvmsg" => 212,
            "brk" => 214,
            "munmap" => 215,
            "mremap" => 216,
            "mmap" => 222,
            "mprotect" => 226,
            "madvise" => 233,
            "prlimit64" => 261,
            "getrandom" => 278,
            "execveat" => 281,
            "statx" => 291,
            "rseq" => 293,
            "openat2" => 437,
            "faccessat2" => 439,
            _ => return None,
        }),
    }
}

struct ExecVectors {
    _argv_storage: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    _environment_storage: Vec<CString>,
    environment: Vec<*const libc::c_char>,
}

fn build_exec_vectors(plan: &CageInitPlan) -> Result<ExecVectors, BootstrapFault> {
    crate::validate_target_argv(&plan.target_argv)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "argv"))?;
    let argv_storage = plan
        .target_argv
        .iter()
        .map(|argument| {
            CString::new(argument.as_str())
                .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "argv"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv = argv_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let mut environment_storage = Vec::with_capacity(plan.environment.len());
    let mut total = 0_usize;
    for (name, value) in &plan.environment {
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_'
                    || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
            })
            || crate::is_credential_or_injection_name(name)
            || value.len() > 16 * 1024
            || value.chars().any(char::is_control)
        {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "environment",
            ));
        }
        total = total
            .checked_add(name.len() + value.len() + 2)
            .ok_or_else(|| {
                BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "environment")
            })?;
        if total > 64 * 1024 {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::InvalidPlan,
                "environment",
            ));
        }
        environment_storage.push(CString::new(format!("{name}={value}")).map_err(|_| {
            BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "environment")
        })?);
    }
    let mut environment = environment_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment.push(std::ptr::null());
    Ok(ExecVectors {
        _argv_storage: argv_storage,
        argv,
        _environment_storage: environment_storage,
        environment,
    })
}

fn validate_prepared(
    prepared: &EnforcementPrepared,
    compiled: &CompiledCage,
    process_id: u32,
    trace_session_digest: &str,
    filter_digest: &str,
) -> Result<(), CageLaunchError> {
    prepared.validate().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_validate",
        )
    })?;
    crate::validate_cage_execution_identity_binding(compiled.plan(), prepared).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "prepared_execution_identity_binding",
        )
    })?;
    if prepared.process_id != process_id
        || prepared.manifest_digest != compiled.plan().manifest_digest
        || prepared.profile_digest != compiled.profile_digest()
        || prepared.plan_digest != compiled.plan_digest()
        || prepared.fd_table_digest != compiled.profile().fd_table_digest
        || prepared.helper_binding_digest != compiled.profile().helper_binding_digest
        || prepared.target_binding_digest != compiled.profile().target_binding_digest
        || prepared.target_identity != compiled.runtime().target().resource().identity()
        || prepared.nono_version != PINNED_NONO_VERSION
        || prepared.nono_patch_version != NONO_PATCH_VERSION
        || prepared.landlock_abi < MINIMUM_LANDLOCK_ABI
        || prepared.landlock_filesystem_status != ObservedRulesetStatus::FullyEnforced
        || prepared.landlock_network_status != ObservedRulesetStatus::FullyEnforced
        || prepared.seccompiler_version != PINNED_SECCOMPILER_VERSION
        || prepared.seccomp_status != SeccompEnforcementStatus::FullyEnforced
        || prepared.seccomp_architecture != compiled.plan().seccomp.architecture
        || prepared.seccomp_filter_digest != filter_digest
        || prepared.trace_session_digest != trace_session_digest
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_binding",
        ));
    }
    Ok(())
}

fn wait_for_initial_trace_stop(
    child: &mut Child,
    status_fd: RawFd,
    deadline: Instant,
) -> Result<(), CageLaunchError> {
    let pid = i32::try_from(child.id()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "process_id",
        )
    })?;
    while Instant::now() < deadline {
        match read_status(status_fd)? {
            StatusRead::Pending => {}
            StatusRead::Eof => {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::TraceHandshakeFailed,
                    "trace_status_eof",
                ));
            }
            StatusRead::Record(record) => match *record {
                StatusRecord::Failure { failure, .. } => {
                    return Err(CageLaunchError::bootstrap_failed(
                        failure.code,
                        "helper_failure",
                    ));
                }
                StatusRecord::Prepared { .. } => {
                    return Err(CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::TraceHandshakeFailed,
                        "prepared_before_trace",
                    ));
                }
            },
        }
        let mut status = 0;
        // SAFETY: status is a valid output pointer and pid names the owned child.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited < 0 {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::TraceHandshakeFailed,
                "trace_wait",
            ));
        }
        if waited > 0 {
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                return Ok(());
            }
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::TraceHandshakeFailed,
                "trace_stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Err(CageLaunchError::bootstrap_failed(
        CageEnforcementFailureCode::Timeout,
        "trace_timeout",
    ))
}

fn ptrace_set_options(process_id: u32) -> Result<(), CageLaunchError> {
    let pid = i32::try_from(process_id).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "process_id",
        )
    })?;
    // SAFETY: the child is stopped under PTRACE_TRACEME and the options value
    // contains only TRACEEXEC and EXITKILL.
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, PTRACE_OPTIONS) } != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "trace_options",
        ));
    }
    Ok(())
}

fn ptrace_continue(process_id: u32) -> Result<(), CageLaunchError> {
    let pid = i32::try_from(process_id).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "process_id",
        )
    })?;
    // SAFETY: the child is stopped under ptrace and signal zero resumes it
    // without injecting an application-visible signal.
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "trace_continue",
        ));
    }
    Ok(())
}

fn ptrace_detach(process_id: u32) -> Result<(), CageLaunchError> {
    let pid = i32::try_from(process_id).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "process_id",
        )
    })?;
    // SAFETY: the child is stopped at PTRACE_EVENT_EXEC and signal zero
    // resumes it without exposing the trace stop to the target.
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) } != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "trace_detach",
        ));
    }
    Ok(())
}

fn verify_live_process_image(
    process_id: u32,
    expected_identity: FileIdentity,
    expected_digest: &str,
    code: CageEnforcementFailureCode,
    stage: &'static str,
) -> Result<(), CageLaunchError> {
    let path = format!("/proc/{process_id}/exe");
    let file = File::open(path).map_err(|_| CageLaunchError::bootstrap_failed(code, stage))?;
    let identity = crate::linux::descriptor_identity(&file, None)
        .map_err(|_| CageLaunchError::bootstrap_failed(code, stage))?;
    let digest = hash_file(&file).map_err(|_| CageLaunchError::bootstrap_failed(code, stage))?;
    if identity != expected_identity || digest != expected_digest {
        return Err(CageLaunchError::bootstrap_failed(code, stage));
    }
    Ok(())
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

fn verify_single_threaded() -> Result<(), BootstrapFault> {
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

fn socket_pair() -> Result<(OwnedFd, OwnedFd), CageLaunchError> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to two writable integers and the requested
    // socket type is a local close-on-exec sequenced packet channel.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    } != 0
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "control_socket",
        ));
    }
    // SAFETY: socketpair returned two distinct newly owned descriptors.
    let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: ownership of the second descriptor is independent of the first.
    let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    Ok((first, second))
}

fn receive_helper_pidfd(
    socket: RawFd,
    deadline: Instant,
) -> Result<OwnedFd, CageLaunchError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::Timeout,
                "pidfd_receive_timeout",
            ));
        }
        let timeout_ms = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut descriptor = libc::pollfd {
            fd: socket,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the duration
        // of the finite wait.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::StatusProtocolViolation,
                    "pidfd_receive_poll",
                ));
            }
            let (pidfd, extras) = receive_descriptors(socket).map_err(|fault| {
                CageLaunchError::bootstrap_failed(fault.code, "pidfd_receive")
            })?;
            if !extras.is_empty() {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::DescriptorCountMismatch,
                    "pidfd_receive_count",
                ));
            }
            return Ok(OwnedFd::from(pidfd));
        }
        if result == 0 {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::Timeout,
                "pidfd_receive_timeout",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "pidfd_receive_poll",
            ));
        }
    }
}

fn validate_helper_pidfd(pidfd: &OwnedFd, process_id: u32) -> Result<(), CageLaunchError> {
    let fdinfo = std::fs::read_to_string(format!(
        "/proc/self/fdinfo/{}",
        pidfd.as_raw_fd()
    ))
    .map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "pidfd_identity",
        )
    })?;
    let observed_pid = fdinfo.lines().find_map(|line| {
        line.strip_prefix("Pid:")
            .and_then(|value| value.trim().parse::<i64>().ok())
    });
    if observed_pid != Some(i64::from(process_id)) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "pidfd_identity",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod stdio_tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn identity(kind: &str, inode: u64) -> FileIdentity {
        serde_json::from_value(serde_json::json!({
            "device": 1,
            "inode": inode,
            "mount_id": 1,
            "mode": if kind == "directory" { 0o040700 } else { 0o100700 },
            "uid": 1000,
            "gid": 1000,
            "kind": kind
        }))
        .test_expect("valid identity")
    }

    fn entry(slot: u32, purpose: FdPurpose, kind: &str, inode: u64) -> crate::FdTableEntry {
        let stdio = matches!(
            purpose,
            FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr
        );
        crate::FdTableEntry {
            slot,
            purpose,
            identity: identity(kind, inode),
            path: (!stdio).then(|| format!("/test/{slot}")),
            binding_digest: None,
            broker_peer_identity: None,
            close_on_exec: true,
        }
    }

    fn plan() -> CageInitPlan {
        CageInitPlan {
            schema: CAGE_INIT_PLAN_SCHEMA.to_string(),
            compiler_version: CAGE_COMPILER_VERSION.to_string(),
            manifest_digest: "1".repeat(64),
            profile_digest: "2".repeat(64),
            plan_fd_slot: PLAN_FD as u32,
            status_fd_slot: STATUS_FD as u32,
            helper_fd_slot: crate::HELPER_FD_SLOT,
            target_fd_slot: TARGET_FD as u32,
            working_directory_fd_slot: crate::WORKING_DIRECTORY_FD_SLOT,
            target_argv: vec!["/test/target".to_string(), "--stdio".to_string()],
            fd_table: vec![
                entry(
                    crate::HELPER_FD_SLOT,
                    FdPurpose::CageInitHelper,
                    "regular_file",
                    1,
                ),
                entry(
                    crate::WORKING_DIRECTORY_FD_SLOT,
                    FdPurpose::WorkingDirectory,
                    "directory",
                    2,
                ),
                entry(
                    crate::TARGET_STDIN_FD_SLOT,
                    FdPurpose::TargetStdin,
                    "unix_socket",
                    3,
                ),
                entry(
                    crate::TARGET_STDOUT_FD_SLOT,
                    FdPurpose::TargetStdout,
                    "unix_socket",
                    4,
                ),
                entry(
                    crate::TARGET_STDERR_FD_SLOT,
                    FdPurpose::TargetStderr,
                    "unix_socket",
                    5,
                ),
                entry(
                    TARGET_FD as u32,
                    FdPurpose::TargetExecutable,
                    "regular_file",
                    6,
                ),
            ],
            landlock: crate::LandlockPolicyPlan {
                default_filesystem_deny: true,
                network_mode: NetworkMode::Blocked,
                forbidden_resources: Vec::new(),
                grants: Vec::new(),
            },
            seccomp: crate::SeccompProfilePlan {
                architecture: SandboxArchitecture::X86_64,
                profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
                default_action: SeccompDefaultAction::KillProcess,
                allowed_syscalls: vec!["read".into(), "write".into(), "exit".into()],
                argument_constraints: std::collections::BTreeMap::new(),
            },
            resource_limits: crate::ResourceLimitPlan {
                nofile_soft: crate::CHILD_NOFILE_LIMIT,
                nofile_hard: crate::CHILD_NOFILE_LIMIT,
            },
            execution_identity: crate::ExecutionIdentity::new(10001, 10001, Vec::new())
                .test_unwrap(),
            environment: std::collections::BTreeMap::new(),
            broker_authentication_digest: None,
        }
    }

    #[test]
    fn exact_target_argv_is_used_and_mutation_is_rejected() {
        let mut plan = plan();
        let vectors = build_exec_vectors(&plan).test_expect("valid argv");
        assert_eq!(
            vectors
                ._argv_storage
                .iter()
                .map(|argument| argument.to_str().test_expect("utf8"))
                .collect::<Vec<_>>(),
            vec!["/test/target", "--stdio"]
        );

        plan.target_argv[1].push('\0');
        assert!(build_exec_vectors(&plan).is_err());
    }

    #[test]
    fn swapped_extra_and_missing_stdio_roles_fail_plan_validation() {
        let mut swapped = plan();
        let stdin = swapped
            .fd_table
            .iter()
            .position(|entry| entry.purpose == FdPurpose::TargetStdin)
            .test_expect("stdin");
        let stdout = swapped
            .fd_table
            .iter()
            .position(|entry| entry.purpose == FdPurpose::TargetStdout)
            .test_expect("stdout");
        swapped.fd_table[stdin].purpose = FdPurpose::TargetStdout;
        swapped.fd_table[stdout].purpose = FdPurpose::TargetStdin;
        assert!(validate_fd_table_shape(&swapped).is_err());

        let mut extra = plan();
        extra
            .fd_table
            .push(entry(11, FdPurpose::TargetStdin, "unix_socket", 7));
        extra.fd_table.sort_by_key(|entry| entry.slot);
        assert!(validate_fd_table_shape(&extra).is_err());

        let mut missing = plan();
        missing
            .fd_table
            .retain(|entry| entry.purpose != FdPurpose::TargetStderr);
        assert!(validate_fd_table_shape(&missing).is_err());
    }

    #[test]
    fn swapped_live_stdio_descriptors_fail_identity_verification() {
        let stdio = crate::CompiledTargetStdio::create().test_expect("stdio channels");
        let entries = stdio.entries().test_expect("stdio entries");
        let stdin_entry = entries
            .iter()
            .find(|entry| entry.purpose == FdPurpose::TargetStdin)
            .test_expect("stdin entry");
        let stdout = stdio
            .child_file(&FdPurpose::TargetStdout)
            .test_expect("stdout descriptor");
        assert!(verify_received_descriptor_identity(stdin_entry, stdout).is_err());
    }
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred, BootstrapFault> {
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
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "peer_credentials",
        ));
    }
    Ok(credentials)
}

fn set_nonblocking(fd: RawFd) -> Result<(), CageLaunchError> {
    // SAFETY: F_GETFL does not use a third argument and fd is live.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_nonblocking",
        ));
    }
    // SAFETY: the existing flags plus O_NONBLOCK are valid for F_SETFL.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_nonblocking",
        ));
    }
    Ok(())
}

fn plan_memfd(bytes: &[u8]) -> Result<File, CageLaunchError> {
    let name = c"chio-cage-plan";
    // SAFETY: name is NUL terminated and the flags request a close-on-exec,
    // sealable anonymous file.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "plan_memfd",
        ));
    }
    let raw_fd = i32::try_from(raw).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "plan_memfd",
        )
    })?;
    // SAFETY: a successful memfd_create returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(raw_fd) };
    file.write_all(bytes).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlanSeals,
            "plan_memfd_write",
        )
    })?;
    Ok(file)
}

fn sealed_memfd(bytes: &[u8]) -> Result<File, CageLaunchError> {
    let file = plan_memfd(bytes)?;
    // SAFETY: the descriptor is a sealable memfd and the seal mask is valid.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_MEMFD_SEALS) } != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlanSeals,
            "plan_memfd_seal",
        ));
    }
    Ok(file)
}

#[cfg(feature = "enforcement-mutants")]
fn unsealed_memfd(bytes: &[u8]) -> Result<File, CageLaunchError> {
    plan_memfd(bytes)
}

fn verify_memfd_seals(fd: RawFd) -> Result<(), BootstrapFault> {
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

fn memfd_seal_mask(fd: RawFd) -> Result<u32, CageLaunchError> {
    // SAFETY: F_GET_SEALS reads integer metadata from the live memfd.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlanSeals,
            "plan_memfd_seals",
        ));
    }
    u32::try_from(seals).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlanSeals,
            "plan_memfd_seals",
        )
    })
}

fn send_descriptors(socket: RawFd, descriptors: &[RawFd]) -> Result<(), CageLaunchError> {
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
    let control_size = unsafe { libc::CMSG_SPACE(descriptor_bytes as libc::c_uint) } as usize;
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
    message.msg_controllen = control_size as _;
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
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes as libc::c_uint)
            .try_into()
            .map_err(|_| {
                CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::DescriptorCountMismatch,
                    "descriptor_send_size",
                )
            })?;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header),
            descriptor_bytes,
        );
    }
    // SAFETY: all message buffers and descriptor values remain live for the
    // single atomic sequenced-packet send.
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent != payload.len() as isize {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "descriptor_send",
        ));
    }
    Ok(())
}

fn receive_descriptors(socket: RawFd) -> Result<(File, Vec<OwnedFd>), BootstrapFault> {
    let mut payload = [0_u8; 4];
    let mut io_vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let descriptor_bytes = MAX_TRANSFER_FDS * std::mem::size_of::<RawFd>();
    // SAFETY: CMSG_SPACE computes the maximum ancillary buffer size.
    let control_size = unsafe { libc::CMSG_SPACE(descriptor_bytes as libc::c_uint) } as usize;
    let control_entries = control_size.div_ceil(std::mem::size_of::<libc::cmsghdr>());
    let mut control = Vec::<std::mem::MaybeUninit<libc::cmsghdr>>::with_capacity(control_entries);
    control.resize_with(control_entries, std::mem::MaybeUninit::zeroed);
    // SAFETY: msghdr is a plain C output structure initialized to no address.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // msg_controllen is size_t on glibc and socklen_t on musl.
    message.msg_controllen = control_size as _;
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
        let valid = unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS
        };
        if !valid {
            control_valid = false;
            // SAFETY: CMSG_NXTHDR advances within the same received message.
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
            continue;
        }
        control_headers = control_headers.saturating_add(1);
        // SAFETY: cmsg_len was validated by the kernel to lie in the buffer.
        // cmsg_len is size_t on glibc and socklen_t on musl.
        let length = unsafe { (*header).cmsg_len } as usize;
        let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
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
        let values =
            unsafe { std::slice::from_raw_parts(libc::CMSG_DATA(header).cast::<RawFd>(), count) };
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
    if received != payload.len() as isize
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || control_headers != 1
        || !control_valid
    {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "descriptor_receive",
        ));
    }
    let expected = u32::from_le_bytes(payload) as usize;
    if expected == 0 || expected > MAX_TRANSFER_FDS || owned.len() != expected {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "descriptor_receive_count",
        ));
    }
    let plan = owned.remove(0);
    Ok((File::from(plan), owned))
}

fn read_status(fd: RawFd) -> Result<StatusRead, CageLaunchError> {
    let mut buffer = vec![0_u8; MAX_STATUS_BYTES];
    let mut io_vector = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: msghdr is a plain output structure initialized without ancillary
    // storage because status records never carry descriptors.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    // SAFETY: buffer is writable and MSG_DONTWAIT preserves the deadline loop.
    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    if received < 0 {
        if matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        ) {
            return Ok(StatusRead::Pending);
        }
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_read",
        ));
    }
    if received == 0 {
        if message.msg_flags & libc::MSG_EOR != 0 {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "status_empty_packet",
            ));
        }
        return Ok(StatusRead::Eof);
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_truncated",
        ));
    }
    let length = usize::try_from(received).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_length",
        )
    })?;
    let record = serde_json::from_slice::<StatusRecord>(&buffer[..length]).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_decode",
        )
    })?;
    let canonical = chio_core::canonical_json_bytes(&record).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_canonical",
        )
    })?;
    if canonical != buffer[..length] {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_noncanonical",
        ));
    }
    Ok(StatusRead::Record(Box::new(record)))
}

fn write_packet(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: bytes is a live input buffer and the status descriptor is a
    // connected sequenced-packet socket.
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if written == bytes.len() as isize {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("partial status packet"))
    }
}

fn write_failure_record(fault: &BootstrapFault, fallback_fd: RawFd) {
    let record = StatusRecord::Failure {
        schema: STATUS_RECORD_SCHEMA.to_string(),
        failure: CageEnforcementFailure {
            code: fault.code,
            stage: fault.stage.to_string(),
        },
    };
    if let Ok(bytes) = chio_core::canonical_json_bytes(&record) {
        if is_status_socket(fallback_fd) {
            let _ = write_packet(fallback_fd, &bytes);
        } else if is_status_socket(STATUS_FD) {
            let _ = write_packet(STATUS_FD, &bytes);
        }
    }
}

fn is_status_socket(fd: RawFd) -> bool {
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
            (&mut socket_type as *mut i32).cast(),
            &mut length,
        ) == 0
            && socket_type == libc::SOCK_SEQPACKET
    }
}

fn read_bounded_file(file: &File, max_bytes: usize) -> Result<Vec<u8>, BootstrapFault> {
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
            .read_at(&mut bytes[offset..], offset as u64)
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

fn hash_file(file: &File) -> Result<String, BootstrapFault> {
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
        bytes.extend_from_slice(&buffer[..read]);
        offset = offset.saturating_add(read as u64);
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
    Ok(chio_core::sha256_hex(&bytes))
}

fn random_digest() -> Result<String, CageLaunchError> {
    let mut bytes = [0_u8; 32];
    // SAFETY: bytes is writable for its full length and flags zero requests a
    // blocking kernel random read.
    let read = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if read != bytes.len() as isize {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "trace_random",
        ));
    }
    Ok(chio_core::sha256_hex(&bytes))
}

fn unix_time_ms() -> Result<u64, CageLaunchError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "system_time",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "system_time",
        )
    })
}

fn validate_digest(value: &str) -> Result<(), BootstrapFault> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(inode: u64) -> FileIdentity {
        FileIdentity {
            device: 1,
            inode,
            mount_id: 2,
            mode: 0o100500,
            uid: 1000,
            gid: 1000,
            kind: crate::ResourceKind::RegularFile,
        }
    }

    #[test]
    fn required_enforcement_comparison_is_exact() {
        let exact = crate::RequiredEnforcement {
            landlock_full: true,
            seccomp_default_deny: true,
            ptrace_exec_observation: true,
        };
        assert!(exact_required_enforcement(&exact));

        for inexact in [
            crate::RequiredEnforcement {
                landlock_full: false,
                ..exact.clone()
            },
            crate::RequiredEnforcement {
                seccomp_default_deny: false,
                ..exact.clone()
            },
            crate::RequiredEnforcement {
                ptrace_exec_observation: false,
                ..exact.clone()
            },
        ] {
            assert!(!exact_required_enforcement(&inexact));
        }
    }

    #[test]
    fn helper_identity_control_rejects_same_bytes_different_identity() {
        let expected = identity(51);
        let substituted = identity(52);
        let binding_digest = "a".repeat(64);

        assert!(!helper_identity_and_binding_match(
            expected,
            substituted,
            &binding_digest,
            &binding_digest,
        ));
        assert!(helper_identity_and_binding_match(
            expected,
            expected,
            &binding_digest,
            &binding_digest,
        ));
    }

    #[test]
    fn seccomp_control_rejects_forbidden_socket_before_default_deny() {
        let mut plan = crate::SeccompProfilePlan {
            architecture: SandboxArchitecture::X86_64,
            profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            default_action: SeccompDefaultAction::KillProcess,
            allowed_syscalls: vec!["socket".to_string()],
            argument_constraints: BTreeMap::new(),
        };

        assert!(!seccomp_profile_is_fail_closed(&plan));
        plan.allowed_syscalls = vec!["read".to_string()];
        assert!(seccomp_profile_is_fail_closed(&plan));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn constrained_exec_filter_fails_closed() {
        let mut argument_constraints = BTreeMap::new();
        argument_constraints.insert(
            "execveat".to_string(),
            vec![
                SyscallArgumentConstraint {
                    argument_index: 0,
                    comparison: SeccompArgumentComparison::Equal,
                    value: TARGET_FD as u64,
                },
                SyscallArgumentConstraint {
                    argument_index: 4,
                    comparison: SeccompArgumentComparison::Equal,
                    value: AT_EMPTY_PATH as u64,
                },
            ],
        );
        let mut plan = crate::SeccompProfilePlan {
            architecture: SandboxArchitecture::current().test_expect("supported test architecture"),
            profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            default_action: SeccompDefaultAction::KillProcess,
            allowed_syscalls: vec!["execveat".to_string()],
            argument_constraints,
        };
        let constrained = compile_seccomp_filter(&plan).test_expect("valid constrained filter");
        assert!(!constrained.is_empty());
        let constrained_digest = filter_digest(&constrained).test_expect("filter digest");

        plan.argument_constraints
            .get_mut("execveat")
            .test_expect("execveat constraint")[0]
            .value = (TARGET_FD - 1) as u64;
        let mutated = compile_seccomp_filter(&plan).test_expect("valid mutated filter");
        assert_ne!(
            constrained_digest,
            filter_digest(&mutated).test_expect("mutated filter digest")
        );
    }

    #[test]
    fn architecture_syscall_tables_cover_reviewed_profiles() {
        for architecture in [SandboxArchitecture::X86_64, SandboxArchitecture::Aarch64] {
            for syscall in [
                "read",
                "write",
                "close",
                "execveat",
                "exit_group",
                "openat",
                "openat2",
                "rt_sigreturn",
            ] {
                assert!(syscall_number(architecture, syscall).is_some());
            }
        }
        assert!(syscall_number(SandboxArchitecture::Aarch64, "arch_prctl").is_none());
        assert!(syscall_number(SandboxArchitecture::Aarch64, "poll").is_none());
    }
}
