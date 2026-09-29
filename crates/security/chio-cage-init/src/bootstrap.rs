#[cfg(feature = "enforcement-mutants")]
use super::ENFORCEMENT_MUTATION_ENV;
use super::{
    apply_execution_identity, apply_landlock, apply_resource_limits, arm_parent_death,
    build_exec_vectors, checked_slot_fd, compile_seccomp_filter, filter_digest, install_seccomp,
    peer_credentials, read_bounded_file, receive_descriptors, remap_descriptors,
    reset_signal_state, send_descriptors, target_entry, unix_time_ms, validate_envelope,
    verify_descriptor_table, verify_helper_self, verify_memfd_seals, verify_single_threaded,
    write_failure_record, write_packet, AsRawFd, BootstrapFault, CageEnforcementFailure,
    CageEnforcementFailureCode, EnforcementPrepared, File, FromRawFd, LandlockEnforcement,
    LaunchEnvelope, ObservedRulesetStatus, OwnedFd, RawFd, SeccompEnforcementStatus, StatusRecord,
    CONTROL_FD, CONTROL_FD_ENV, ENFORCEMENT_PREPARED_SCHEMA, MAX_ENVELOPE_BYTES,
    MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION, PINNED_NONO_VERSION, PINNED_SECCOMPILER_VERSION,
    STATUS_FD, STATUS_RECORD_SCHEMA, TARGET_FD, TEMP_FD_START,
};

pub fn run_cage_init() -> Result<(), BootstrapFault> {
    let control_fd = std::env::var(CONTROL_FD_ENV)
        .ok()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd == CONTROL_FD)
        .ok_or_else(|| {
            BootstrapFault::new(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "control_descriptor",
            )
        })?;
    // SAFETY: the inherited control descriptor is live and F_DUPFD_CLOEXEC
    // creates an early-error status path that cannot survive target exec.
    let failure_fd = unsafe { libc::fcntl(control_fd, libc::F_DUPFD_CLOEXEC, TEMP_FD_START) };
    if failure_fd < 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "control_duplicate",
        ));
    }
    // SAFETY: the helper contract gives sole ownership of the inherited
    // control descriptor to this entrypoint.
    let control = unsafe { File::from_raw_fd(control_fd) };
    let result = send_self_pidfd(control.as_raw_fd()).and_then(|()| child_main(control));
    match result {
        Ok(()) => Ok(()),
        Err(fault) => {
            write_failure_record(&fault, failure_fd);
            // SAFETY: failure_fd is uniquely owned by this entrypoint when it
            // remains open. EBADF after descriptor closure is harmless.
            unsafe { libc::close(failure_fd) };
            Err(BootstrapFault::new(fault.code, fault.stage))
        }
    }
}

fn send_self_pidfd(control_fd: RawFd) -> Result<(), BootstrapFault> {
    // SAFETY: getpid takes no pointers and returns the live helper identity.
    let process_id = unsafe { libc::getpid() };
    if process_id <= 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "pidfd_self_open",
        ));
    }
    // SAFETY: the helper opens a pidfd for itself while it is unquestionably
    // live, so the descriptor cannot bind a recycled numeric PID.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0) };
    if raw < 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::UnsupportedKernel,
            "pidfd_self_open",
        ));
    }
    let raw_fd = match i32::try_from(raw) {
        Ok(raw_fd) => raw_fd,
        Err(_) => std::process::abort(),
    };
    // SAFETY: a successful pidfd_open returned one new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    send_descriptors(control_fd, &[pidfd.as_raw_fd()]).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_transfer",
        )
    })
}

fn child_main(control: File) -> Result<(), BootstrapFault> {
    verify_single_threaded()?;
    let peer = peer_credentials(control.as_raw_fd())?;
    let (plan_memfd, descriptor_fds) = receive_descriptors(control.as_raw_fd())?;
    verify_memfd_seals(plan_memfd.as_raw_fd())?;
    let envelope_bytes = read_bounded_file(&plan_memfd, MAX_ENVELOPE_BYTES)?;
    let envelope: LaunchEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_decode"))?;
    let canonical = chio_cage_plan::canonical_json_bytes(&envelope).map_err(|_| {
        BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_canonical")
    })?;
    if canonical != envelope_bytes {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_noncanonical",
        ));
    }
    validate_envelope(&envelope, peer)?;
    let descriptor_files = descriptor_fds
        .into_iter()
        .map(File::from)
        .collect::<Vec<_>>();
    verify_descriptor_table(&envelope, &descriptor_files)?;
    verify_helper_self(&envelope, &descriptor_files)?;

    // SAFETY: PTRACE_TRACEME takes no pointers and establishes the documented
    // parent-child trace relationship before confinement.
    if unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "trace_me",
        ));
    }
    // SAFETY: raising SIGSTOP in this single-threaded helper creates the trace
    // handshake stop required before any confinement state is changed.
    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "trace_stop",
        ));
    }

    remap_descriptors(control, plan_memfd, descriptor_files, &envelope.plan)?;
    if enforcement_mutation_is("malformed_status") {
        write_packet(STATUS_FD, b"{").map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "malformed_status_mutation",
            )
        })?;
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "malformed_status_mutation",
        ));
    }
    reset_signal_state()?;
    apply_resource_limits(&envelope.plan)?;
    // SAFETY: the working-directory slot is an authenticated retained
    // directory descriptor.
    if unsafe { libc::fchdir(checked_slot_fd(envelope.plan.working_directory_fd_slot)?) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "working_directory",
        ));
    }
    if enforcement_mutation_is("skip_execution_identity") {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_skipped",
        ));
    }
    let applied_execution_identity = apply_execution_identity(&envelope.plan.execution_identity)?;
    if applied_execution_identity != envelope.plan.execution_identity {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_verify",
        ));
    }
    arm_parent_death(envelope.parent_process_id)?;
    // SAFETY: PR_SET_NO_NEW_PRIVS with argument one is irreversible for this
    // process and is required by both Landlock and seccomp.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::SeccompUnavailable,
            "no_new_privs",
        ));
    }
    let landlock = if enforcement_mutation_is("disable_landlock") {
        LandlockEnforcement {
            abi: MINIMUM_LANDLOCK_ABI,
            filesystem: ObservedRulesetStatus::NotEnforced,
            network: ObservedRulesetStatus::NotEnforced,
        }
    } else if enforcement_mutation_is("partial_landlock") {
        LandlockEnforcement {
            abi: MINIMUM_LANDLOCK_ABI,
            filesystem: ObservedRulesetStatus::PartiallyEnforced,
            network: ObservedRulesetStatus::PartiallyEnforced,
        }
    } else {
        apply_landlock(&envelope.plan)?
    };
    let filter = match compile_seccomp_filter(&envelope.plan.seccomp) {
        Ok(filter) => filter,
        Err(_) => {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::SeccompArchitectureMismatch,
                "seccomp_compile",
            ));
        }
    };
    let filter_digest = match filter_digest(&filter) {
        Ok(digest) => digest,
        Err(_) => {
            return Err(BootstrapFault::new(
                CageEnforcementFailureCode::SeccompInstallFailed,
                "seccomp_digest",
            ));
        }
    };
    let prepared = EnforcementPrepared {
        schema: ENFORCEMENT_PREPARED_SCHEMA.to_string(),
        process_id: std::process::id(),
        manifest_digest: envelope.plan.manifest_digest.clone(),
        profile_digest: envelope.plan.profile_digest.clone(),
        plan_digest: envelope.plan_digest.clone(),
        fd_table_digest: envelope.fd_table_digest.clone(),
        helper_binding_digest: envelope.helper_binding_digest.clone(),
        target_binding_digest: envelope.target_binding_digest.clone(),
        target_identity: target_entry(&envelope.plan)?.identity,
        applied_execution_identity,
        nono_version: PINNED_NONO_VERSION.to_string(),
        nono_patch_version: NONO_PATCH_VERSION.to_string(),
        landlock_abi: landlock.abi,
        landlock_filesystem_status: landlock.filesystem,
        landlock_network_status: landlock.network,
        seccompiler_version: PINNED_SECCOMPILER_VERSION.to_string(),
        seccomp_status: if enforcement_mutation_is("disable_seccomp") {
            SeccompEnforcementStatus::NotEnforced
        } else {
            SeccompEnforcementStatus::FullyEnforced
        },
        seccomp_architecture: envelope.plan.seccomp.architecture(),
        seccomp_filter_digest: filter_digest,
        trace_session_digest: if enforcement_mutation_is("trace_binding_mismatch") {
            "0".repeat(64)
        } else {
            envelope.trace_session_digest.clone()
        },
        prepared_at_unix_ms: unix_time_ms().map_err(|_| {
            BootstrapFault::new(
                CageEnforcementFailureCode::PreparedRecordInvalid,
                "prepared_time",
            )
        })?,
    };
    prepared.validate().map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_validate",
        )
    })?;
    let prepared_bytes = chio_cage_plan::canonical_json_bytes(&StatusRecord::Prepared {
        schema: STATUS_RECORD_SCHEMA.to_string(),
        evidence: Box::new(prepared),
    })
    .map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_encode",
        )
    })?;
    let exec_failure_bytes = chio_cage_plan::canonical_json_bytes(&StatusRecord::Failure {
        schema: STATUS_RECORD_SCHEMA.to_string(),
        failure: CageEnforcementFailure {
            code: CageEnforcementFailureCode::ChildExitedBeforeExec,
            stage: "execveat".to_string(),
        },
    })
    .map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "exec_failure_encode",
        )
    })?;
    let exec_vectors = build_exec_vectors(&envelope.plan)?;
    if !enforcement_mutation_is("disable_seccomp") {
        install_seccomp(&filter)?;
    }
    write_packet(STATUS_FD, &prepared_bytes).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_write",
        )
    })?;
    if enforcement_mutation_is("exit_before_exec") {
        // SAFETY: this caught mutant intentionally terminates after prepared
        // evidence but before exec so the parent must deny the launch.
        unsafe { libc::_exit(71) }
    }

    let empty = c"";
    // SAFETY: the target slot is an authenticated executable descriptor, all
    // pointer arrays are NUL terminated and remain live across the syscall,
    // and AT_EMPTY_PATH selects the already-open target.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            TARGET_FD,
            empty.as_ptr(),
            exec_vectors.argv.as_ptr(),
            exec_vectors.environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    let _ = write_packet(STATUS_FD, &exec_failure_bytes);
    // SAFETY: exec failed after confinement. _exit terminates without invoking
    // destructors that could require syscalls outside the installed filter.
    unsafe { libc::_exit(70) }
}

fn enforcement_mutation_is(expected: &str) -> bool {
    #[cfg(feature = "enforcement-mutants")]
    {
        std::env::var(ENFORCEMENT_MUTATION_ENV).is_ok_and(|value| value == expected)
    }
    #[cfg(not(feature = "enforcement-mutants"))]
    {
        let _ = expected;
        false
    }
}
