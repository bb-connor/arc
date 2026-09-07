use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    enforced_child, process_exit_evidence, reserve_child_custody, transfer_child_custody,
    CageLaunchError, CageLaunchOptions, CageLaunchPreparationEvidence, ChildCustodyPermit,
    EnforcedChild, EnforcedStdio,
};
use crate::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageError, CageInitPlan,
    CageReceiptBindings, CageTargetFdBindingMutation, CageTargetFdBindingProductionValidation,
    CompiledCage, EnforcementPrepared, ExecTransitionObserved, ExecutionIdentity, FdPurpose,
    FileIdentity, FilesystemGrantAccess, FullyEnforcedEvidence, NetworkMode, ObservedRulesetStatus,
    ProcessExitEvidence, RequiredEnforcement, SandboxArchitecture, SeccompArgumentComparison,
    SeccompDefaultAction, SeccompEnforcementStatus, SyscallArgumentConstraint, CAGE_COMPILER_VERSION,
    CAGE_INIT_PLAN_SCHEMA, ENFORCEMENT_PREPARED_SCHEMA, EXEC_TRANSITION_OBSERVED_SCHEMA,
    MAX_SUPPLEMENTARY_GIDS, MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION, PINNED_NONO_VERSION,
    PINNED_SECCOMPILER_VERSION,
};

const LAUNCH_ENVELOPE_SCHEMA: &str = "chio.cage.launch-envelope.v1";
const STATUS_RECORD_SCHEMA: &str = "chio.cage.status-record.v1";
const CONTROL_FD_ENV: &str = "CHIO_CAGE_CONTROL_FD";
#[cfg(feature = "enforcement-mutants")]
const ENFORCEMENT_MUTATION_ENV: &str = "CHIO_CAGE_TEST_ENFORCEMENT_MUTATION";
const CONTROL_FD: RawFd = 0;
const PLAN_FD: RawFd = 3;
const STATUS_FD: RawFd = 4;
const TARGET_FD: RawFd = 255;
const TEMP_FD_START: RawFd = TARGET_FD + 1;
const MAX_TRANSFER_FDS: usize = 192;
const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATUS_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const REQUIRED_MEMFD_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_OPTIONS: libc::c_ulong =
    (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as libc::c_ulong;
const AT_EMPTY_PATH: libc::c_int = 0x1000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchEnvelope {
    schema: String,
    parent_process_id: u32,
    trace_session_digest: String,
    plan_digest: String,
    fd_table_digest: String,
    helper_binding_digest: String,
    target_binding_digest: String,
    plan: CageInitPlan,
}

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
    pub(super) const fn evidence(&self) -> &CageLaunchPreparationEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StatusRecord {
    Prepared {
        schema: String,
        evidence: Box<EnforcementPrepared>,
    },
    Failure {
        schema: String,
        failure: CageEnforcementFailure,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct FilterInstruction {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    value: u32,
}

impl FilterInstruction {
    const fn from_seccompiler(instruction: &seccompiler::sock_filter) -> Self {
        Self {
            code: instruction.code,
            jump_true: instruction.jt,
            jump_false: instruction.jf,
            value: instruction.k,
        }
    }
}

#[derive(Debug)]
struct BootstrapFault {
    code: CageEnforcementFailureCode,
    stage: &'static str,
}

impl BootstrapFault {
    const fn new(code: CageEnforcementFailureCode, stage: &'static str) -> Self {
        Self { code, stage }
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

    let seal_mask = validate_prepared_launch_contract(
        &compiled,
        &envelope,
        &envelope_bytes,
        &plan_memfd,
    )?;
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
    let observed_seal_mask = validate_prepared_launch_contract(
        &compiled,
        &envelope,
        &envelope_bytes,
        &plan_memfd,
    )?;
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
    let evidence = FullyEnforcedEvidence::new(prepared, exec_transition, true).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "fully_enforced_evidence",
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
    Ok(enforced_child(child, pidfd, custody_permit, evidence, stdio))
}

pub(super) fn run_cage_init() -> Result<(), CageLaunchError> {
    let control_fd = std::env::var(CONTROL_FD_ENV)
        .ok()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd == CONTROL_FD)
        .ok_or_else(|| {
            CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "control_descriptor",
            )
        })?;
    // SAFETY: the inherited control descriptor is live and F_DUPFD_CLOEXEC
    // creates an early-error status path that cannot survive target exec.
    let failure_fd = unsafe { libc::fcntl(control_fd, libc::F_DUPFD_CLOEXEC, TEMP_FD_START) };
    if failure_fd < 0 {
        return Err(CageLaunchError::bootstrap_failed(
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
            Err(CageLaunchError::bootstrap_failed(fault.code, fault.stage))
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

fn child_main(control: File) -> Result<(), BootstrapFault> {
    verify_single_threaded()?;
    let peer = peer_credentials(control.as_raw_fd())?;
    let (plan_memfd, descriptor_fds) = receive_descriptors(control.as_raw_fd())?;
    verify_memfd_seals(plan_memfd.as_raw_fd())?;
    let envelope_bytes = read_bounded_file(&plan_memfd, MAX_ENVELOPE_BYTES)?;
    let envelope: LaunchEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| BootstrapFault::new(CageEnforcementFailureCode::InvalidPlan, "plan_decode"))?;
    let canonical = chio_core::canonical_json_bytes(&envelope).map_err(|_| {
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
    if unsafe { libc::fchdir(envelope.plan.working_directory_fd_slot as RawFd) } != 0 {
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
    let applied_execution_identity =
        apply_execution_identity(&envelope.plan.execution_identity)?;
    if applied_execution_identity != envelope.plan.execution_identity {
        return Err(BootstrapFault::new(
            CageEnforcementFailureCode::ExecutionIdentityMismatch,
            "execution_identity_verify",
        ));
    }
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
        seccomp_architecture: envelope.plan.seccomp.architecture,
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
    let prepared_bytes = chio_core::canonical_json_bytes(&StatusRecord::Prepared {
        schema: STATUS_RECORD_SCHEMA.to_string(),
        evidence: Box::new(prepared),
    })
    .map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::PreparedRecordInvalid,
            "prepared_encode",
        )
    })?;
    let exec_failure_bytes = chio_core::canonical_json_bytes(&StatusRecord::Failure {
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
            AT_EMPTY_PATH,
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
        return std::env::var(ENFORCEMENT_MUTATION_ENV).is_ok_and(|value| value == expected);
    }
    #[cfg(not(feature = "enforcement-mutants"))]
    {
        let _ = expected;
        false
    }
}

fn exact_required_enforcement(requirements: &RequiredEnforcement) -> bool {
    requirements
        == &RequiredEnforcement {
            landlock_full: true,
            seccomp_default_deny: true,
            ptrace_exec_observation: true,
        }
}

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
        || plan.seccomp.default_action != SeccompDefaultAction::KillProcess
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
    let observed_identity = crate::linux::descriptor_identity(validation.target, None).map_err(|_| {
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
