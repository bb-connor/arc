#[cfg(test)]
use chio_cage_init::helper_identity_and_binding_match;
#[cfg(test)]
use chio_cage_init::seccomp_profile_is_fail_closed;
#[cfg(test)]
use chio_cage_init::syscall_number;
#[cfg(test)]
use chio_cage_init::verify_received_descriptor_identity;
use chio_cage_init::{receive_descriptors, send_descriptors};
#[cfg(test)]
use chio_cage_plan::SandboxArchitecture;
#[cfg(test)]
use std::collections::BTreeMap;

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{
    enforced_child, process_exit_evidence, reserve_child_custody, transfer_child_custody,
    CageLaunchError, CageLaunchOptions, CageLaunchPreparationEvidence, ChildCustodyPermit,
    EnforcedChild, EnforcedStdio,
};
use crate::{
    CageEnforcementFailureCode, CageError, CageInitPlan, CageReceiptBindings,
    CageTargetFdBindingMutation, CageTargetFdBindingProductionValidation, CompiledCage,
    EnforcementPrepared, ExecTransitionObserved, FdPurpose, FileIdentity, FullyEnforcedEvidence,
    NetworkMode, ObservedRulesetStatus, ProcessExitEvidence, RequiredEnforcement,
    SeccompDefaultAction, SeccompEnforcementStatus, CAGE_COMPILER_VERSION, CAGE_INIT_PLAN_SCHEMA,
    EXEC_TRANSITION_OBSERVED_SCHEMA, MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION, PINNED_NONO_VERSION,
    PINNED_SECCOMPILER_VERSION,
};
const PTRACE_EVENT_EXEC: i32 = 4;
#[allow(
    clippy::as_conversions,
    reason = "The nonnegative Linux ptrace option bits fit c_ulong on both supported architectures; From is not const."
)]
const PTRACE_OPTIONS: libc::c_ulong =
    (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as libc::c_ulong;

struct CompiledPlanValidation<'a> {
    plan: &'a CageInitPlan,
    profile_digest: &'a str,
    manifest_digest: &'a str,
    plan_digest: &'a str,
    target: &'a File,
}

impl<'a> CompiledPlanValidation<'a> {
    fn from_compiled(compiled: &'a CompiledCage) -> Self {
        Self {
            plan: compiled.plan(),
            profile_digest: compiled.profile_digest(),
            manifest_digest: compiled.admitted().manifest_digest(),
            plan_digest: compiled.plan_digest(),
            target: compiled.runtime().target().resource().file(),
        }
    }
}

pub(super) struct PreparedLaunchContract {
    compiled: CompiledCage,
    envelope: LaunchEnvelope,
    plan_memfd: File,
    evidence: CageLaunchPreparationEvidence,
    #[cfg(feature = "enforcement-mutants")]
    preparation_mutation: Option<super::EnforcementMutation>,
}

impl PreparedLaunchContract {
    pub(super) fn receipt_bindings(&self) -> CageReceiptBindings {
        CageReceiptBindings::from_compiled(&self.compiled)
    }

    pub(super) const fn evidence(&self) -> &CageLaunchPreparationEvidence {
        &self.evidence
    }
}

struct ChildCleanup {
    child: Option<Child>,
    pidfd: Option<Arc<OwnedFd>>,
    custody_permit: Option<ChildCustodyPermit>,
}

impl ChildCleanup {
    fn new(child: Child, custody_permit: ChildCustodyPermit) -> Self {
        Self {
            child: Some(child),
            pidfd: None,
            custody_permit: Some(custody_permit),
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, CageLaunchError> {
        self.child.as_mut().ok_or_else(|| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "child_handle",
            )
        })
    }

    fn set_pidfd(&mut self, pidfd: Arc<OwnedFd>) {
        if self.pidfd.replace(pidfd).is_some() {
            std::process::abort();
        }
    }

    fn disarm(mut self) -> Result<(Child, Arc<OwnedFd>, ChildCustodyPermit), CageLaunchError> {
        let Some(child) = self.child.take() else {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "child_handle",
            ));
        };
        let Some(pidfd) = self.pidfd.take() else {
            self.child = Some(child);
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "child_pidfd",
            ));
        };
        let Some(custody_permit) = self.custody_permit.take() else {
            self.child = Some(child);
            self.pidfd = Some(pidfd);
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "child_custody_permit",
            ));
        };
        Ok((child, pidfd, custody_permit))
    }
}

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let Some(custody_permit) = self.custody_permit.take() else {
                std::process::abort();
            };
            transfer_child_custody(child, self.pidfd.take(), custody_permit);
        }
    }
}

enum StatusRead {
    Pending,
    Eof,
    Record(Box<StatusRecord>),
}

pub(super) fn prepare_launch(
    mut compiled: CompiledCage,
    options: CageLaunchOptions,
) -> Result<PreparedLaunchContract, CageLaunchError> {
    let target_stdio = crate::CompiledTargetStdio::create().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "target_stdio_create",
        )
    })?;
    compiled.bind_target_stdio(target_stdio).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "target_stdio_bind",
        )
    })?;
    let receipt_bindings = CageReceiptBindings::from_compiled(&compiled);
    prepare_bound(compiled, options)
        .map_err(|error| error.with_receipt_bindings_if_missing(receipt_bindings))
}

fn prepare_bound(
    compiled: CompiledCage,
    options: CageLaunchOptions,
) -> Result<PreparedLaunchContract, CageLaunchError> {
    #[cfg(not(feature = "enforcement-mutants"))]
    let _ = options;
    compiled.verify_retained_bindings().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "retained_bindings",
        )
    })?;
    validate_compiled_plan(CompiledPlanValidation::from_compiled(&compiled))?;
    let exact_requirements_match =
        exact_required_enforcement(&compiled.profile().required_enforcement);
    if !exact_requirements_match {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "required_enforcement",
        ));
    }
    verify_bootstrap_fd_capacity(compiled.plan().fd_table.len())?;

    let trace_session_digest = random_digest()?;
    let envelope = LaunchEnvelope {
        schema: LAUNCH_ENVELOPE_SCHEMA.to_string(),
        parent_process_id: std::process::id(),
        trace_session_digest,
        plan_digest: compiled.plan_digest().to_string(),
        fd_table_digest: compiled.profile().fd_table_digest.clone(),
        helper_binding_digest: compiled.profile().helper_binding_digest.clone(),
        target_binding_digest: compiled.profile().target_binding_digest.clone(),
        plan: compiled.plan().clone(),
    };
    #[cfg(feature = "enforcement-mutants")]
    let envelope = {
        let mut envelope = envelope;
        if matches!(
            options.enforcement_mutation(),
            Some(super::EnforcementMutation::CorruptPlanDigest)
        ) {
            envelope.plan_digest = "0".repeat(64);
        }
        envelope
    };
    let envelope_bytes = chio_core::canonical_json_bytes(&envelope).map_err(|_| {
        CageLaunchError::bootstrap_failed(CageEnforcementFailureCode::InvalidPlan, "plan_encoding")
    })?;
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_size",
        ));
    }
    #[cfg(feature = "enforcement-mutants")]
    let plan_memfd = if matches!(
        options.enforcement_mutation(),
        Some(super::EnforcementMutation::UnsealedPlan)
    ) {
        unsealed_memfd(&envelope_bytes)?
    } else {
        sealed_memfd(&envelope_bytes)?
    };
    #[cfg(not(feature = "enforcement-mutants"))]
    let plan_memfd = sealed_memfd(&envelope_bytes)?;

    let seal_mask =
        validate_prepared_launch_contract(&compiled, &envelope, &envelope_bytes, &plan_memfd)?;
    let evidence = CageLaunchPreparationEvidence {
        manifest_digest: envelope.plan.manifest_digest.clone(),
        profile_digest: envelope.plan.profile_digest.clone(),
        plan_digest: envelope.plan_digest.clone(),
        fd_table_digest: envelope.fd_table_digest.clone(),
        helper_binding_digest: envelope.helper_binding_digest.clone(),
        target_binding_digest: envelope.target_binding_digest.clone(),
        seal_mask,
        exact_requirements_match,
        target_launch_count: 0,
    };
    Ok(PreparedLaunchContract {
        compiled,
        envelope,
        plan_memfd,
        evidence,
        #[cfg(feature = "enforcement-mutants")]
        preparation_mutation: options.enforcement_mutation(),
    })
}

pub(super) fn launch_prepared(
    prepared: PreparedLaunchContract,
    options: CageLaunchOptions,
) -> Result<EnforcedChild, CageLaunchError> {
    let receipt_bindings = CageReceiptBindings::from_compiled(&prepared.compiled);
    launch_bound(prepared, options)
        .map_err(|error| error.with_receipt_bindings_if_missing(receipt_bindings))
}

fn launch_bound(
    prepared: PreparedLaunchContract,
    options: CageLaunchOptions,
) -> Result<EnforcedChild, CageLaunchError> {
    let PreparedLaunchContract {
        mut compiled,
        envelope,
        plan_memfd,
        evidence,
        #[cfg(feature = "enforcement-mutants")]
        preparation_mutation,
    } = prepared;
    #[cfg(feature = "enforcement-mutants")]
    if preparation_mutation != options.enforcement_mutation() {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "prepared_contract_options",
        ));
    }
    let envelope_bytes = chio_core::canonical_json_bytes(&envelope).map_err(|_| {
        CageLaunchError::bootstrap_failed(CageEnforcementFailureCode::InvalidPlan, "plan_encoding")
    })?;
    let observed_seal_mask =
        validate_prepared_launch_contract(&compiled, &envelope, &envelope_bytes, &plan_memfd)?;
    if observed_seal_mask != evidence.seal_mask()
        || evidence.target_launch_count() != 0
        || !evidence.exact_requirements_match()
        || evidence.manifest_digest() != envelope.plan.manifest_digest.as_str()
        || evidence.profile_digest() != envelope.plan.profile_digest.as_str()
        || evidence.plan_digest() != envelope.plan_digest.as_str()
        || evidence.fd_table_digest() != envelope.fd_table_digest.as_str()
        || evidence.helper_binding_digest() != envelope.helper_binding_digest.as_str()
        || evidence.target_binding_digest() != envelope.target_binding_digest.as_str()
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "prepared_contract",
        ));
    }
    let trace_session_digest = envelope.trace_session_digest;
    let (parent_control, child_control) = socket_pair()?;
    set_nonblocking(parent_control.as_raw_fd())?;
    let deadline = Instant::now()
        .checked_add(options.timeout())
        .ok_or_else(|| {
            CageLaunchError::bootstrap_failed(CageEnforcementFailureCode::Timeout, "deadline")
        })?;

    let helper_exec_fd =
        duplicate_helper_exec_fd(compiled.runtime().helper().resource().file().as_raw_fd())?;
    let helper_exec_path = format!("/proc/self/fd/{}", helper_exec_fd.as_raw_fd());
    let child_stdio = Stdio::from(File::from(child_control));
    let mut command = Command::new(helper_exec_path);
    command
        .env_clear()
        .env(CONTROL_FD_ENV, CONTROL_FD.to_string())
        .stdin(child_stdio);
    #[cfg(feature = "enforcement-mutants")]
    if let Some(mutation) = options.enforcement_mutation() {
        command.env(ENFORCEMENT_MUTATION_ENV, mutation.as_env_value());
    }
    let custody_permit = reserve_child_custody()?;
    let child = command.spawn().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_spawn",
        )
    })?;
    let mut cleanup = ChildCleanup::new(child, custody_permit);
    // A reusable Command retains its configured Stdio. Drop the parent-held
    // child endpoint so target exec can produce authenticated status EOF.
    drop(command);
    drop(helper_exec_fd);
    let process_id = cleanup.child_mut()?.id();
    let pidfd = match receive_helper_pidfd(parent_control.as_raw_fd(), deadline) {
        Ok(pidfd) => Arc::new(pidfd),
        Err(error) => {
            drop(parent_control);
            return Err(error);
        }
    };
    if let Err(error) = validate_helper_pidfd(&pidfd, process_id) {
        drop(parent_control);
        return Err(error);
    }
    cleanup.set_pidfd(Arc::clone(&pidfd));

    verify_live_process_image(
        process_id,
        compiled.runtime().helper().resource().identity(),
        compiled.runtime().helper().binding_digest(),
        CageEnforcementFailureCode::HelperIdentityMismatch,
        "helper_live_identity",
    )?;
    validate_helper_pidfd(&pidfd, process_id)?;

    let mut descriptors = Vec::with_capacity(compiled.plan().fd_table.len() + 1);
    descriptors.push(plan_memfd.as_raw_fd());
    descriptors.extend(transfer_descriptors(&compiled)?);
    #[cfg(feature = "enforcement-mutants")]
    if matches!(
        options.enforcement_mutation(),
        Some(super::EnforcementMutation::DropDescriptor)
    ) {
        descriptors.pop();
    }
    send_descriptors(parent_control.as_raw_fd(), &descriptors)?;

    wait_for_initial_trace_stop(cleanup.child_mut()?, parent_control.as_raw_fd(), deadline)?;
    ptrace_set_options(process_id)?;
    ptrace_continue(process_id)?;

    let expected_filter = compile_seccomp_filter(&compiled.plan().seccomp)?;
    let expected_filter_digest = filter_digest(&expected_filter)?;
    let mut prepared: Option<EnforcementPrepared> = None;
    let mut exec_transition: Option<ExecTransitionObserved> = None;
    let mut eof = false;

    while Instant::now() < deadline {
        if !eof {
            loop {
                match read_status(parent_control.as_raw_fd())? {
                    StatusRead::Pending => break,
                    StatusRead::Eof => {
                        eof = true;
                        break;
                    }
                    StatusRead::Record(record) => match *record {
                        StatusRecord::Prepared { schema, evidence } => {
                            if schema != STATUS_RECORD_SCHEMA || prepared.is_some() {
                                return Err(CageLaunchError::bootstrap_failed(
                                    CageEnforcementFailureCode::StatusProtocolViolation,
                                    "prepared_shape",
                                ));
                            }
                            validate_prepared(
                                &evidence,
                                &compiled,
                                process_id,
                                &trace_session_digest,
                                &expected_filter_digest,
                            )?;
                            prepared = Some(*evidence);
                        }
                        StatusRecord::Failure { schema, failure } => {
                            if schema != STATUS_RECORD_SCHEMA {
                                return Err(CageLaunchError::bootstrap_failed(
                                    CageEnforcementFailureCode::StatusProtocolViolation,
                                    "failure_shape",
                                ));
                            }
                            return Err(CageLaunchError::bootstrap_failed(
                                failure.code,
                                "helper_failure",
                            ));
                        }
                    },
                }
            }
        }

        let mut status = 0;
        // SAFETY: `status` is a live output pointer and the child is owned by
        // this parent. WNOHANG makes the deadline loop nonblocking.
        let waited = unsafe {
            libc::waitpid(
                i32::try_from(process_id).map_err(|_| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::TraceHandshakeFailed,
                        "process_id",
                    )
                })?,
                &mut status,
                libc::WNOHANG,
            )
        };
        if waited < 0 {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::TraceHandshakeFailed,
                "trace_wait",
            ));
        }
        if waited > 0 {
            if libc::WIFSTOPPED(status)
                && libc::WSTOPSIG(status) == libc::SIGTRAP
                && (status >> 16) == PTRACE_EVENT_EXEC
            {
                if exec_transition.is_some() {
                    return Err(CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::ExecEventMissing,
                        "duplicate_exec_event",
                    ));
                }
                verify_live_process_image(
                    process_id,
                    compiled.runtime().target().resource().identity(),
                    compiled.runtime().target().binding_digest(),
                    CageEnforcementFailureCode::ExecIdentityMismatch,
                    "target_live_identity",
                )?;
                exec_transition = Some(ExecTransitionObserved {
                    schema: EXEC_TRANSITION_OBSERVED_SCHEMA.to_string(),
                    process_id,
                    trace_session_digest: trace_session_digest.clone(),
                    target_binding_digest: compiled.profile().target_binding_digest.clone(),
                    target_identity: compiled.runtime().target().resource().identity(),
                    observed_at_unix_ms: unix_time_ms()?,
                });
            } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::ChildExitedBeforeExec,
                    "child_before_exec",
                ));
            } else if libc::WIFSTOPPED(status) {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::ExecEventMissing,
                    "unexpected_trace_stop",
                ));
            }
        }

        if prepared.is_some() && exec_transition.is_some() && eof {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    let prepared = prepared.ok_or_else(|| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_missing",
        )
    })?;
    let exec_transition = exec_transition.ok_or_else(|| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::ExecEventMissing,
            "exec_event_missing",
        )
    })?;
    if !eof {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "status_eof_missing",
        ));
    }
    let exec_time_precedes_prepared =
        exec_transition.observed_at_unix_ms < prepared.prepared_at_unix_ms;
    let evidence = FullyEnforcedEvidence::new(prepared, exec_transition, true).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            if exec_time_precedes_prepared {
                "exec_time_precedes_prepared"
            } else {
                "fully_enforced_evidence"
            },
        )
    })?;
    let (stdin, stdout, stderr) = compiled.take_parent_stdio().ok_or_else(|| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorCountMismatch,
            "target_stdio_release",
        )
    })?;
    let stdio = EnforcedStdio::new(stdin, stdout, stderr);
    ptrace_detach(process_id)?;
    let (child, pidfd, custody_permit) = cleanup.disarm()?;
    Ok(enforced_child(
        child,
        pidfd,
        custody_permit,
        evidence,
        stdio,
    ))
}

pub(super) fn exit_evidence(
    process_id: u32,
    status: ExitStatus,
) -> Result<ProcessExitEvidence, CageLaunchError> {
    process_exit_evidence(process_id, status.code(), status.signal(), unix_time_ms()?)
}

pub(super) enum PidfdReap {
    Running,
    Exited(ExitStatus),
    ReapedWithoutStatus,
}

pub(super) fn try_reap_pidfd(pidfd: &OwnedFd) -> Result<PidfdReap, CageLaunchError> {
    waitid_pidfd(pidfd, true)
}

pub(super) fn reap_pidfd(pidfd: &OwnedFd) -> Result<PidfdReap, CageLaunchError> {
    waitid_pidfd(pidfd, false)
}

#[cfg(test)]
pub(super) fn pidfd_is_reaped(pidfd: &OwnedFd) -> Result<bool, CageLaunchError> {
    let id = libc::id_t::try_from(pidfd.as_raw_fd()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_observe_id",
        )
    })?;
    loop {
        // SAFETY: siginfo_t is a plain kernel output structure. WNOWAIT
        // observes exact pidfd state without consuming a terminal status.
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: information is writable and id names the retained pidfd.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                id,
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(true);
        }
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_observe",
        ));
    }
}

fn waitid_pidfd(pidfd: &OwnedFd, nonblocking: bool) -> Result<PidfdReap, CageLaunchError> {
    let id = libc::id_t::try_from(pidfd.as_raw_fd()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_wait_id",
        )
    })?;
    loop {
        // SAFETY: siginfo_t is a plain kernel output structure. waitid receives
        // an owned pidfd and WEXITED consumes only that exact child's status.
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let options = libc::WEXITED | if nonblocking { libc::WNOHANG } else { 0 };
        // SAFETY: information is writable, id names the owned pidfd, and the
        // options request only terminal child state.
        let result = unsafe { libc::waitid(libc::P_PIDFD, id, &mut information, options) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(PidfdReap::ReapedWithoutStatus);
            }
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "pidfd_wait",
            ));
        }
        // SAFETY: waitid initialized the SIGCHLD view of siginfo_t. A zero PID
        // is Linux's WNOHANG indication that the exact child is still live.
        let observed_pid = unsafe { information.si_pid() };
        if observed_pid == 0 {
            if nonblocking {
                return Ok(PidfdReap::Running);
            }
            continue;
        }
        // SAFETY: si_status is initialized for the CLD_* codes returned by
        // waitid with WEXITED.
        let observed_status = unsafe { information.si_status() };
        let raw_status = match information.si_code {
            libc::CLD_EXITED if (0..=255).contains(&observed_status) => observed_status << 8,
            libc::CLD_KILLED if (1..=127).contains(&observed_status) => observed_status,
            libc::CLD_DUMPED if (1..=127).contains(&observed_status) => observed_status | 0x80,
            _ => {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::StatusProtocolViolation,
                    "pidfd_wait_status",
                ));
            }
        };
        return Ok(PidfdReap::Exited(ExitStatus::from_raw(raw_status)));
    }
}

pub(super) fn signal_pidfd(pidfd: &OwnedFd, signal: i32) -> Result<(), CageLaunchError> {
    if !matches!(signal, libc::SIGHUP | libc::SIGINT | libc::SIGTERM) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "termination_signal",
        ));
    }
    send_pidfd_signal(pidfd, signal, "pidfd_signal")
}

pub(super) fn kill_pidfd(pidfd: &OwnedFd) -> Result<(), CageLaunchError> {
    send_pidfd_signal(pidfd, libc::SIGKILL, "pidfd_kill")
}

fn send_pidfd_signal(
    pidfd: &OwnedFd,
    signal: i32,
    failure_stage: &'static str,
) -> Result<(), CageLaunchError> {
    // SAFETY: the pidfd is owned and the remaining arguments contain no
    // pointers. A zero flags value is required by the kernel ABI.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            failure_stage,
        ));
    }
    Ok(())
}

fn exact_required_enforcement(requirements: &RequiredEnforcement) -> bool {
    requirements
        == &RequiredEnforcement {
            landlock_full: true,
            seccomp_default_deny: true,
            ptrace_exec_observation: true,
        }
}

#[allow(
    clippy::as_conversions,
    reason = "Only fixed nonnegative descriptor and seal constants are converted here; their values fit u32."
)]
fn validate_prepared_launch_contract(
    compiled: &CompiledCage,
    envelope: &LaunchEnvelope,
    envelope_bytes: &[u8],
    plan_memfd: &File,
) -> Result<u32, CageLaunchError> {
    compiled.verify_retained_bindings().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "retained_bindings",
        )
    })?;
    compiled.plan().execution_identity.validate().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::ExecutionIdentityInvalid,
            "execution_identity",
        )
    })?;
    let execution_identity_digest = chio_core::sha256_hex(
        &chio_core::canonical_json_bytes(&compiled.plan().execution_identity).map_err(|_| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::ExecutionIdentityInvalid,
                "execution_identity_digest",
            )
        })?,
    );
    if compiled.plan().execution_identity != *compiled.runtime().execution_identity()
        || execution_identity_digest != compiled.profile().execution_identity_digest
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_binding",
        ));
    }
    validate_compiled_plan(CompiledPlanValidation::from_compiled(compiled))?;
    verify_bootstrap_fd_capacity(compiled.plan().fd_table.len())?;
    if !exact_required_enforcement(&compiled.profile().required_enforcement) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "required_enforcement",
        ));
    }
    if envelope.schema != LAUNCH_ENVELOPE_SCHEMA
        || envelope.parent_process_id != std::process::id()
        || &envelope.plan != compiled.plan()
        || envelope.plan_digest.as_str() != compiled.plan_digest()
        || envelope.fd_table_digest.as_str() != compiled.profile().fd_table_digest.as_str()
        || envelope.helper_binding_digest.as_str()
            != compiled.profile().helper_binding_digest.as_str()
        || envelope.target_binding_digest.as_str()
            != compiled.profile().target_binding_digest.as_str()
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "prepared_envelope_binding",
        ));
    }
    validate_digest(&envelope.trace_session_digest)
        .map_err(|fault| CageLaunchError::bootstrap_failed(fault.code, fault.stage))?;
    let canonical = chio_core::canonical_json_bytes(envelope).map_err(|_| {
        CageLaunchError::bootstrap_failed(CageEnforcementFailureCode::InvalidPlan, "plan_encoding")
    })?;
    if canonical != envelope_bytes || canonical.is_empty() || canonical.len() > MAX_ENVELOPE_BYTES {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_encoding",
        ));
    }
    let sealed_bytes = read_bounded_file(plan_memfd, MAX_ENVELOPE_BYTES)
        .map_err(|fault| CageLaunchError::bootstrap_failed(fault.code, fault.stage))?;
    if sealed_bytes != canonical {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "sealed_plan_binding",
        ));
    }
    let seals = memfd_seal_mask(plan_memfd.as_raw_fd())?;
    if seals != REQUIRED_MEMFD_SEALS as u32 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlanSeals,
            "plan_memfd_seals",
        ));
    }
    Ok(seals)
}

#[allow(
    clippy::as_conversions,
    reason = "Only fixed nonnegative descriptor and seal constants are converted here; their values fit u32."
)]
fn validate_compiled_plan(validation: CompiledPlanValidation<'_>) -> Result<(), CageLaunchError> {
    let plan = validation.plan;
    if plan.schema != CAGE_INIT_PLAN_SCHEMA
        || plan.compiler_version != CAGE_COMPILER_VERSION
        || plan.plan_fd_slot != PLAN_FD as u32
        || plan.status_fd_slot != STATUS_FD as u32
        || plan.target_fd_slot != TARGET_FD as u32
        || plan.resource_limits.nofile_soft > u64::from(plan.target_fd_slot)
        || plan.resource_limits.nofile_hard < plan.resource_limits.nofile_soft
        || plan.resource_limits.nofile_hard > u64::from(plan.target_fd_slot)
        || !plan.landlock.default_filesystem_deny
        || plan.landlock.network_mode != NetworkMode::Blocked
        || plan.seccomp.default_action() != SeccompDefaultAction::KillProcess
        || plan.profile_digest != validation.profile_digest
        || plan.manifest_digest != validation.manifest_digest
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "compiled_plan",
        ));
    }
    let plan_digest =
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(plan).map_err(|_| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::InvalidPlan,
                "plan_digest",
            )
        })?);
    if plan_digest != validation.plan_digest {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_digest",
        ));
    }
    crate::validate_target_argv(&plan.target_argv).map_err(|_| {
        CageLaunchError::bootstrap_failed(CageEnforcementFailureCode::InvalidPlan, "target_argv")
    })?;
    validate_fd_table_shape(plan)
        .map_err(|fault| CageLaunchError::bootstrap_failed(fault.code, fault.stage))?;
    let observed_identity =
        crate::linux::descriptor_identity(validation.target, None).map_err(|_| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::DescriptorIdentityMismatch,
                "target_fd_identity",
            )
        })?;
    let observed_binding_digest = hash_file(validation.target)
        .map_err(|fault| CageLaunchError::bootstrap_failed(fault.code, fault.stage))?;
    crate::validate_cage_target_fd_binding(plan, &observed_binding_digest, observed_identity)
        .map_err(|_| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::InvalidPlan,
                "target_fd_binding",
            )
        })?;
    Ok(())
}

fn verify_bootstrap_fd_capacity(fd_table_len: usize) -> Result<(), CageLaunchError> {
    // One early failure descriptor plus the control, plan, and complete FD
    // table remap must all fit above the fixed target slot.
    let bootstrap_descriptor_count = fd_table_len.checked_add(3).ok_or_else(|| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "bootstrap_nofile",
        )
    })?;
    let start = u64::try_from(TEMP_FD_START).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "bootstrap_nofile",
        )
    })?;
    let count = u64::try_from(bootstrap_descriptor_count).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "bootstrap_nofile",
        )
    })?;
    let required = start.checked_add(count).ok_or_else(|| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "bootstrap_nofile",
        )
    })?;
    // SAFETY: limit is a live output object and RLIMIT_NOFILE is a valid
    // process resource selector.
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    // SAFETY: limit remains a live writable output for the process query.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if result != 0 || limit.rlim_cur < required {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "bootstrap_nofile",
        ));
    }
    Ok(())
}

fn duplicate_helper_exec_fd(source: RawFd) -> Result<OwnedFd, CageLaunchError> {
    // The helper must be executed from the descriptor whose identity and
    // content were admitted. Spawning the retained pathname would reopen a
    // mutable directory entry and let a replacement image run before the
    // parent could perform its post-exec identity check.
    // SAFETY: source is a live retained helper descriptor and
    // F_DUPFD_CLOEXEC returns a new independently owned descriptor.
    let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, TEMP_FD_START) };
    if duplicate < 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::HelperIdentityMismatch,
            "helper_descriptor_duplicate",
        ));
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a fresh descriptor and this
    // is its only conversion into an owning Rust value.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn transfer_descriptors(compiled: &CompiledCage) -> Result<Vec<RawFd>, CageLaunchError> {
    compiled
        .plan()
        .fd_table
        .iter()
        .map(|entry| match entry.purpose {
            FdPurpose::CageInitHelper => {
                Ok(compiled.runtime().helper().resource().file().as_raw_fd())
            }
            FdPurpose::TargetExecutable => {
                Ok(compiled.runtime().target().resource().file().as_raw_fd())
            }
            FdPurpose::WorkingDirectory => Ok(compiled
                .runtime()
                .working_directory()
                .resource()
                .file()
                .as_raw_fd()),
            FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr => compiled
                .target_stdio()
                .and_then(|stdio| stdio.child_file(&entry.purpose))
                .map(std::os::fd::AsRawFd::as_raw_fd)
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "target_stdio_descriptor",
                    )
                }),
            FdPurpose::RuntimeFile { index } => compiled
                .runtime()
                .runtime_files()
                .get(usize::try_from(index).map_err(|_| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "descriptor_index",
                    )
                })?)
                .map(|artifact| artifact.resource().file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "runtime_descriptor",
                    )
                }),
            FdPurpose::ReadGrant { index } => compiled
                .admitted()
                .read_resources()
                .get(usize::try_from(index).map_err(|_| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "descriptor_index",
                    )
                })?)
                .map(|resource| resource.file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "read_descriptor",
                    )
                }),
            FdPurpose::WriteGrant { index } => compiled
                .admitted()
                .write_resources()
                .get(usize::try_from(index).map_err(|_| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "descriptor_index",
                    )
                })?)
                .map(|resource| resource.file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "write_descriptor",
                    )
                }),
            FdPurpose::BrokerIpc => compiled
                .broker_ipc()
                .map(|broker| broker.file().as_raw_fd())
                .ok_or_else(|| {
                    CageLaunchError::bootstrap_failed(
                        CageEnforcementFailureCode::DescriptorCountMismatch,
                        "broker_descriptor",
                    )
                }),
        })
        .collect()
}

#[allow(
    clippy::indexing_slicing,
    reason = "The mutation target index comes from position on this exact fd_table and the vector is not resized while applying the conformance mutation."
)]
pub(super) fn validate_cage_target_fd_binding_production_paths(
    template: &CageInitPlan,
    target: &File,
    mutation: CageTargetFdBindingMutation,
) -> Result<CageTargetFdBindingProductionValidation, CageError> {
    let stdio = crate::CompiledTargetStdio::create()?;
    let working_directory = File::open(".")
        .map_err(|_| CageError::InvalidTargetFdBinding("conformance_working_directory"))?;
    let mut plan = template.clone();
    let mut files = Vec::with_capacity(plan.fd_table.len());
    for entry in &mut plan.fd_table {
        let file = match &entry.purpose {
            FdPurpose::CageInitHelper | FdPurpose::TargetExecutable => target
                .try_clone()
                .map_err(|_| CageError::InvalidTargetFdBinding("conformance_target_clone"))?,
            FdPurpose::WorkingDirectory => working_directory.try_clone().map_err(|_| {
                CageError::InvalidTargetFdBinding("conformance_working_directory_clone")
            })?,
            FdPurpose::TargetStdin | FdPurpose::TargetStdout | FdPurpose::TargetStderr => stdio
                .child_file(&entry.purpose)
                .ok_or(CageError::InvalidTargetFdBinding("conformance_stdio"))?
                .try_clone()
                .map_err(|_| CageError::InvalidTargetFdBinding("conformance_stdio_clone"))?,
            FdPurpose::RuntimeFile { .. }
            | FdPurpose::ReadGrant { .. }
            | FdPurpose::WriteGrant { .. }
            | FdPurpose::BrokerIpc => {
                return Err(CageError::InvalidTargetFdBinding(
                    "conformance_descriptor_shape",
                ));
            }
        };
        entry.identity = crate::linux::descriptor_identity(&file, None)?;
        if matches!(
            entry.purpose,
            FdPurpose::CageInitHelper | FdPurpose::TargetExecutable
        ) {
            entry.binding_digest = Some(
                hash_file(&file)
                    .map_err(|_| CageError::InvalidTargetFdBinding("conformance_hash"))?,
            );
        }
        files.push(file);
    }

    let target_index = plan
        .fd_table
        .iter()
        .position(|entry| matches!(entry.purpose, FdPurpose::TargetExecutable))
        .ok_or(CageError::InvalidTargetFdBinding(
            "conformance_target_entry",
        ))?;
    match mutation {
        CageTargetFdBindingMutation::None => {}
        CageTargetFdBindingMutation::Slot => {
            plan.fd_table[target_index].slot = plan.fd_table[target_index].slot.saturating_sub(1);
        }
        CageTargetFdBindingMutation::BindingDigest => {
            let binding_digest = plan.fd_table[target_index].binding_digest.as_mut().ok_or(
                CageError::InvalidTargetFdBinding("conformance_target_binding"),
            )?;
            let replacement = if binding_digest.starts_with('0') {
                "1"
            } else {
                "0"
            };
            binding_digest.replace_range(..1, replacement);
        }
        CageTargetFdBindingMutation::Identity => {
            let identity = plan.fd_table[target_index].identity;
            plan.fd_table[target_index].identity = FileIdentity::new(
                identity.device(),
                identity.inode().wrapping_add(1),
                identity.mount_id(),
                identity.mode(),
                identity.uid(),
                identity.gid(),
                identity.kind(),
            );
        }
        CageTargetFdBindingMutation::ExecveatTarget => {
            let mut constraints = plan.seccomp.argument_constraints().clone();
            let constraint = constraints
                .get_mut(&crate::Syscall::Execveat)
                .and_then(|constraints| {
                    constraints
                        .iter_mut()
                        .flatten()
                        .find(|constraint| constraint.argument_index == 0)
                })
                .ok_or(CageError::InvalidTargetFdBinding(
                    "conformance_execveat_target",
                ))?;
            constraint.value ^= 1;
            plan.seccomp = crate::SeccompProfilePlan::new(
                plan.seccomp.architecture(),
                plan.seccomp.profile(),
                plan.seccomp.allowed_syscalls().to_vec(),
                constraints,
            )?;
        }
    }

    let plan_digest = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&plan)?);
    let fd_table_digest = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&plan.fd_table)?);
    let helper_binding_digest = plan
        .fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .and_then(|entry| entry.binding_digest.clone())
        .ok_or(CageError::InvalidTargetFdBinding(
            "conformance_helper_binding",
        ))?;
    let observed_target_binding_digest = hash_file(target)
        .map_err(|_| CageError::InvalidTargetFdBinding("conformance_target_hash"))?;
    let parent_accepted = validate_compiled_plan(CompiledPlanValidation {
        plan: &plan,
        profile_digest: plan.profile_digest.as_str(),
        manifest_digest: plan.manifest_digest.as_str(),
        plan_digest: &plan_digest,
        target,
    })
    .is_ok();
    let envelope = LaunchEnvelope {
        schema: LAUNCH_ENVELOPE_SCHEMA.to_string(),
        parent_process_id: std::process::id(),
        trace_session_digest: "0".repeat(64),
        plan_digest,
        fd_table_digest,
        helper_binding_digest,
        target_binding_digest: observed_target_binding_digest,
        plan,
    };
    let child_accepted = verify_descriptor_table(&envelope, &files).is_ok();
    Ok(CageTargetFdBindingProductionValidation {
        parent_accepted,
        child_accepted,
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
        || prepared.seccomp_architecture != compiled.plan().seccomp.architecture()
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

fn receive_helper_pidfd(socket: RawFd, deadline: Instant) -> Result<OwnedFd, CageLaunchError> {
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
            let (pidfd, extras) = receive_descriptors(socket)
                .map_err(|fault| CageLaunchError::bootstrap_failed(fault.code, "pidfd_receive"))?;
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
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
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

#[allow(
    clippy::indexing_slicing,
    reason = "The packet read count was converted from nonnegative ssize_t and is bounded by the supplied buffer."
)]
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

fn random_digest() -> Result<String, CageLaunchError> {
    let mut bytes = [0_u8; 32];
    // SAFETY: bytes is writable for its full length and flags zero requests a
    // blocking kernel random read.
    let read = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if usize::try_from(read) != Ok(bytes.len()) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::UnsupportedKernel,
            "trace_random",
        ));
    }
    Ok(chio_core::sha256_hex(&bytes))
}

use chio_cage_plan::{
    LaunchEnvelope, StatusRecord, CONTROL_FD, CONTROL_FD_ENV, LAUNCH_ENVELOPE_SCHEMA,
    MAX_ENVELOPE_BYTES, MAX_STATUS_BYTES, PLAN_FD, REQUIRED_MEMFD_SEALS, STATUS_FD,
    STATUS_RECORD_SCHEMA, TARGET_FD, TEMP_FD_START,
};

#[cfg(feature = "enforcement-mutants")]
use chio_cage_plan::ENFORCEMENT_MUTATION_ENV;

use chio_cage_init::{
    compile_seccomp_filter, filter_digest, hash_file, read_bounded_file, unix_time_ms,
    validate_digest, validate_fd_table_shape, verify_descriptor_table, BootstrapFault,
};

impl From<BootstrapFault> for CageLaunchError {
    fn from(fault: BootstrapFault) -> Self {
        Self::bootstrap_failed(fault.code, fault.stage)
    }
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
            seccomp: chio_cage_plan::SeccompProfilePlan::test_unchecked(
                SandboxArchitecture::X86_64,
                chio_manifest::NativeSyscallProfile::NativeMinimalV1,
                SeccompDefaultAction::KillProcess,
                vec![
                    crate::Syscall::Read,
                    crate::Syscall::Write,
                    crate::Syscall::Exit,
                ],
                std::collections::BTreeMap::new(),
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::{SeccompArgumentComparison, SyscallArgumentConstraint, AT_EMPTY_PATH};
    #[cfg(target_arch = "x86_64")]
    use chio_test_support::prelude::*;

    fn identity(inode: u64) -> FileIdentity {
        FileIdentity::new(
            1,
            inode,
            2,
            0o100500,
            1000,
            1000,
            crate::ResourceKind::RegularFile,
        )
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
        let mut plan = chio_cage_plan::SeccompProfilePlan::test_unchecked(
            SandboxArchitecture::X86_64,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            SeccompDefaultAction::KillProcess,
            vec![crate::Syscall::Socket],
            BTreeMap::new(),
        );

        assert!(!seccomp_profile_is_fail_closed(&plan));
        *plan.test_allowed_syscalls_mut() = vec![crate::Syscall::Read];
        assert!(seccomp_profile_is_fail_closed(&plan));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn constrained_exec_filter_fails_closed() {
        let mut argument_constraints = BTreeMap::new();
        argument_constraints.insert(
            crate::Syscall::Execveat,
            vec![vec![
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
            ]],
        );
        let mut plan = chio_cage_plan::SeccompProfilePlan::test_unchecked(
            SandboxArchitecture::current().test_expect("supported test architecture"),
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            SeccompDefaultAction::KillProcess,
            vec![crate::Syscall::Execveat],
            argument_constraints,
        );
        let constrained = compile_seccomp_filter(&plan).test_expect("valid constrained filter");
        assert!(!constrained.is_empty());
        let constrained_digest = filter_digest(&constrained).test_expect("filter digest");

        plan.test_argument_constraints_mut()
            .get_mut(&crate::Syscall::Execveat)
            .test_expect("execveat constraint")[0][0]
            .value = (TARGET_FD - 1) as u64;
        let mutated = compile_seccomp_filter(&plan).test_expect("valid mutated filter");
        assert_ne!(
            constrained_digest,
            filter_digest(&mutated).test_expect("mutated filter digest")
        );
    }

    #[test]
    fn seccomp_rejects_peer_process_authority_in_every_profile() {
        use chio_manifest::NativeSyscallProfile;
        use chio_test_support::plain::TestResultOk;
        for profile in [
            NativeSyscallProfile::NativeMinimalV1,
            NativeSyscallProfile::NativeStandardV1,
            NativeSyscallProfile::BrokeredNativeV1,
        ] {
            let plan =
                crate::build_seccomp_plan(SandboxArchitecture::X86_64, profile).test_unwrap();
            assert!(seccomp_profile_is_fail_closed(&plan));
            #[cfg(target_arch = "x86_64")]
            compile_seccomp_filter(&plan).test_expect("self-only profile compiles");

            let mut unconfined_limits = plan.clone();
            unconfined_limits
                .test_argument_constraints_mut()
                .remove(&crate::Syscall::Prlimit64);
            assert!(!seccomp_profile_is_fail_closed(&unconfined_limits));
            for signal in [
                crate::Syscall::Kill,
                crate::Syscall::Tkill,
                crate::Syscall::Tgkill,
                crate::Syscall::PidfdSendSignal,
            ] {
                let mut peer_signals = plan.clone();
                peer_signals.test_allowed_syscalls_mut().push(signal);
                assert!(!seccomp_profile_is_fail_closed(&peer_signals));
            }
            let mut peer_limits = plan;
            peer_limits
                .test_argument_constraints_mut()
                .get_mut(&crate::Syscall::Prlimit64)
                .test_unwrap()[0][0]
                .value = 1;
            assert!(!seccomp_profile_is_fail_closed(&peer_limits));
        }
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
                "sched_getaffinity",
                "readlinkat",
            ] {
                assert!(syscall_number(architecture, syscall).is_some());
            }
        }
        assert!(syscall_number(SandboxArchitecture::Aarch64, "arch_prctl").is_none());
        assert!(syscall_number(SandboxArchitecture::Aarch64, "poll").is_none());
        assert_eq!(
            syscall_number(SandboxArchitecture::X86_64, "readlink"),
            Some(89)
        );
        assert!(syscall_number(SandboxArchitecture::Aarch64, "readlink").is_none());
        for (name, number) in [("open", 2), ("stat", 4), ("lstat", 6)] {
            assert_eq!(
                syscall_number(SandboxArchitecture::X86_64, name),
                Some(number)
            );
            assert!(syscall_number(SandboxArchitecture::Aarch64, name).is_none());
        }
    }
}

#[cfg(test)]
#[path = "seccomp_validation_tests.rs"]
mod seccomp_validation_tests;
