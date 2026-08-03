#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{Arc, OnceLock};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use crate::receipt::CageReceiptBindings;
#[cfg(target_os = "linux")]
use crate::ProcessExitEvidence;
use crate::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord, CageError,
    CageInitPlan, CompiledCage, FullyEnforcedEvidence,
};

#[cfg(target_os = "linux")]
#[path = "launch/linux.rs"]
mod platform;

const DEFAULT_LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LAUNCH_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const TERMINATION_REAP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const REAPER_KILL_RETRY_PERIOD: Duration = Duration::from_millis(250);
#[cfg(target_os = "linux")]
const MAX_SUPERVISED_CHILDREN: usize = 64;

#[cfg(target_os = "linux")]
struct ChildSupervisor {
    owner_pid: u32,
    sender: std::sync::mpsc::SyncSender<ChildCustody>,
}

#[cfg(target_os = "linux")]
static CHILD_SUPERVISOR: OnceLock<Option<ChildSupervisor>> = OnceLock::new();
#[cfg(target_os = "linux")]
static SUPERVISED_CHILDREN: AtomicUsize = AtomicUsize::new(0);

/// Target-binding mutation exercised through both Linux production validators.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CageTargetFdBindingMutation {
    None,
    Slot,
    BindingDigest,
    Identity,
    ExecveatTarget,
}

/// Acceptance results from the parent and child production validation paths.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CageTargetFdBindingProductionValidation {
    parent_accepted: bool,
    child_accepted: bool,
}

impl CageTargetFdBindingProductionValidation {
    #[must_use]
    pub const fn parent_accepted(self) -> bool {
        self.parent_accepted
    }

    #[must_use]
    pub const fn child_accepted(self) -> bool {
        self.child_accepted
    }
}

/// Exercise the exact parent and child target-binding validators with a live FD.
#[doc(hidden)]
pub fn validate_cage_target_fd_binding_production_paths(
    plan: &CageInitPlan,
    target: &std::fs::File,
    mutation: CageTargetFdBindingMutation,
) -> Result<CageTargetFdBindingProductionValidation, CageError> {
    #[cfg(target_os = "linux")]
    {
        platform::validate_cage_target_fd_binding_production_paths(plan, target, mutation)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plan, target, mutation);
        Err(CageError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CageLaunchOptions {
    timeout: Duration,
    #[cfg(feature = "enforcement-mutants")]
    mutation: Option<EnforcementMutation>,
}

/// Secret-free observation of a descriptor-owned, sealed launch preparation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CageLaunchPreparationEvidence {
    manifest_digest: String,
    profile_digest: String,
    plan_digest: String,
    fd_table_digest: String,
    helper_binding_digest: String,
    target_binding_digest: String,
    seal_mask: u32,
    exact_requirements_match: bool,
    target_launch_count: u64,
}

impl CageLaunchPreparationEvidence {
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    #[must_use]
    pub fn fd_table_digest(&self) -> &str {
        &self.fd_table_digest
    }

    #[must_use]
    pub fn helper_binding_digest(&self) -> &str {
        &self.helper_binding_digest
    }

    #[must_use]
    pub fn target_binding_digest(&self) -> &str {
        &self.target_binding_digest
    }

    #[must_use]
    pub const fn seal_mask(&self) -> u32 {
        self.seal_mask
    }

    #[must_use]
    pub const fn exact_requirements_match(&self) -> bool {
        self.exact_requirements_match
    }

    #[must_use]
    pub const fn target_launch_count(&self) -> u64 {
        self.target_launch_count
    }
}

/// Opaque RAII owner for a validated and sealed launch contract.
///
/// Preparation binds target stdio, retains every executable and resource
/// descriptor, and owns the sealed plan artifact. Observation never starts a
/// helper or target process. Dropping this value closes all owned descriptors.
pub struct PreparedCageLaunch {
    #[cfg(target_os = "linux")]
    inner: platform::PreparedLaunchContract,
    #[cfg(not(target_os = "linux"))]
    unsupported: std::convert::Infallible,
}

impl std::fmt::Debug for PreparedCageLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedCageLaunch")
            .field("evidence", self.evidence())
            .finish_non_exhaustive()
    }
}

impl PreparedCageLaunch {
    #[must_use]
    pub fn evidence(&self) -> &CageLaunchPreparationEvidence {
        #[cfg(target_os = "linux")]
        {
            self.inner.evidence()
        }
        #[cfg(not(target_os = "linux"))]
        {
            match self.unsupported {}
        }
    }
}

impl CageLaunchOptions {
    pub fn new(timeout: Duration) -> Result<Self, CageLaunchError> {
        if timeout.is_zero() || timeout > MAX_LAUNCH_TIMEOUT {
            return Err(CageLaunchError::rejected(
                CageEnforcementFailureCode::Timeout,
                "launch_timeout",
            ));
        }
        Ok(Self {
            timeout,
            #[cfg(feature = "enforcement-mutants")]
            mutation: None,
        })
    }

    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Select a caught-mutant launch. This API exists only in debug test builds.
    #[cfg(feature = "enforcement-mutants")]
    #[doc(hidden)]
    #[must_use]
    pub const fn with_enforcement_mutation(mut self, mutation: EnforcementMutation) -> Self {
        self.mutation = Some(mutation);
        self
    }

    #[cfg(feature = "enforcement-mutants")]
    pub(crate) const fn enforcement_mutation(self) -> Option<EnforcementMutation> {
        self.mutation
    }
}

impl Default for CageLaunchOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_LAUNCH_TIMEOUT,
            #[cfg(feature = "enforcement-mutants")]
            mutation: None,
        }
    }
}

/// Test-only mutations proving each enforcement layer is mandatory.
#[cfg(feature = "enforcement-mutants")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementMutation {
    DisableLandlock,
    PartialLandlock,
    DisableSeccomp,
    UnsealedPlan,
    CorruptPlanDigest,
    DropDescriptor,
    SkipExecutionIdentity,
    MalformedStatus,
    TraceBindingMismatch,
    ExitBeforeExec,
}

#[cfg(feature = "enforcement-mutants")]
impl EnforcementMutation {
    pub(crate) const fn as_env_value(self) -> &'static str {
        match self {
            Self::DisableLandlock => "disable_landlock",
            Self::PartialLandlock => "partial_landlock",
            Self::DisableSeccomp => "disable_seccomp",
            Self::UnsealedPlan => "unsealed_plan",
            Self::CorruptPlanDigest => "corrupt_plan_digest",
            Self::DropDescriptor => "drop_descriptor",
            Self::SkipExecutionIdentity => "skip_execution_identity",
            Self::MalformedStatus => "malformed_status",
            Self::TraceBindingMismatch => "trace_binding_mismatch",
            Self::ExitBeforeExec => "exit_before_exec",
        }
    }
}

#[derive(Debug)]
pub struct EnforcedChild {
    #[cfg(target_os = "linux")]
    child: Option<std::process::Child>,
    #[cfg(target_os = "linux")]
    pidfd: Arc<std::os::fd::OwnedFd>,
    #[cfg(target_os = "linux")]
    custody_permit: Option<ChildCustodyPermit>,
    #[cfg(target_os = "linux")]
    owner_pid: u32,
    evidence: FullyEnforcedEvidence,
    stdio: Option<EnforcedStdio>,
}

/// Parent-side target stdio handles released only after verified target exec.
#[derive(Debug)]
pub struct EnforcedStdio {
    stdin: std::fs::File,
    stdout: std::fs::File,
    stderr: std::fs::File,
}

impl EnforcedStdio {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(stdin: std::fs::File, stdout: std::fs::File, stderr: std::fs::File) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (std::fs::File, std::fs::File, std::fs::File) {
        (self.stdin, self.stdout, self.stderr)
    }
}

impl EnforcedChild {
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.evidence.prepared.process_id
    }

    #[must_use]
    pub const fn evidence(&self) -> &FullyEnforcedEvidence {
        &self.evidence
    }

    /// Transfer the target stdio handles after fully enforced evidence exists.
    pub fn take_stdio(&mut self) -> Option<EnforcedStdio> {
        self.stdio.take()
    }

    /// Observe and reap a natural exit without blocking. A live child returns
    /// `None` without changing ownership. An observed exit is returned once;
    /// later calls return `None`, and dropping the handle performs no work.
    pub fn try_wait(&mut self) -> Result<Option<CageEnforcementRecord>, CageLaunchError> {
        #[cfg(target_os = "linux")]
        {
            self.require_process_owner("child_try_wait_owner")?;
            let receipt_bindings = CageReceiptBindings::from_prepared(&self.evidence.prepared);
            if self.child.is_none() {
                return Ok(None);
            }
            let status = match platform::try_reap_pidfd(&self.pidfd) {
                Ok(platform::PidfdReap::Running) => return Ok(None),
                Ok(platform::PidfdReap::Exited(status)) => status,
                Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                    let _ = self.child.take();
                    drop(self.custody_permit.take());
                    drop(self.stdio.take());
                    return Err(CageLaunchError::terminalization_failed(
                        &self.evidence,
                        CageEnforcementFailureCode::StatusProtocolViolation,
                        "child_try_wait_status_unavailable",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings));
                }
                Err(_) => {
                    return Err(CageLaunchError::terminalization_failed(
                        &self.evidence,
                        CageEnforcementFailureCode::StatusProtocolViolation,
                        "child_try_wait",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings));
                }
            };
            let _ = self.child.take();
            drop(self.custody_permit.take());
            drop(self.stdio.take());
            self.exited_record(status, receipt_bindings).map(Some)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageLaunchError::unsupported())
        }
    }

    /// Forward an allowed termination signal through the exact process handle.
    pub fn signal(&self, signal: TerminationSignal) -> Result<(), CageLaunchError> {
        #[cfg(target_os = "linux")]
        {
            self.require_process_owner("child_signal_owner")?;
            let bindings = CageReceiptBindings::from_prepared(&self.evidence.prepared);
            platform::signal_pidfd(&self.pidfd, signal.as_raw()).map_err(|error| {
                CageLaunchError::terminalization_failure(
                    &self.evidence,
                    error.operation_failure().clone(),
                )
                .with_receipt_bindings_if_missing(bindings)
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = signal;
            Err(CageLaunchError::unsupported())
        }
    }

    pub fn wait(self) -> Result<CageEnforcementRecord, CageLaunchError> {
        #[cfg(target_os = "linux")]
        {
            let mut this = self;
            let receipt_bindings = CageReceiptBindings::from_prepared(&this.evidence.prepared);
            this.require_process_owner("child_wait_owner")?;
            drop(this.stdio.take());
            let child = this.child.take().ok_or_else(|| {
                CageLaunchError::terminalization_failed(
                    &this.evidence,
                    CageEnforcementFailureCode::StatusProtocolViolation,
                    "child_handle",
                )
                .with_receipt_bindings_if_missing(receipt_bindings.clone())
            })?;
            let status = match platform::reap_pidfd(&this.pidfd) {
                Ok(platform::PidfdReap::Exited(status)) => status,
                Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                    return Err(CageLaunchError::terminalization_failed(
                        &this.evidence,
                        CageEnforcementFailureCode::StatusProtocolViolation,
                        "child_wait_status_unavailable",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings));
                }
                Ok(platform::PidfdReap::Running) | Err(_) => {
                    let _ = platform::kill_pidfd(&this.pidfd);
                    match wait_pidfd_bounded(&this.pidfd, TERMINATION_REAP_TIMEOUT) {
                        Ok(platform::PidfdReap::Exited(status)) => {
                            return this.exited_record(status, receipt_bindings);
                        }
                        Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                            return Err(CageLaunchError::terminalization_failed(
                                &this.evidence,
                                CageEnforcementFailureCode::StatusProtocolViolation,
                                "child_wait_status_unavailable",
                            )
                            .with_receipt_bindings_if_missing(receipt_bindings));
                        }
                        Ok(platform::PidfdReap::Running) => {
                            this.transfer_child_custody(child);
                            return Err(CageLaunchError::terminalization_failed(
                                &this.evidence,
                                CageEnforcementFailureCode::Timeout,
                                "child_wait_reap_timeout",
                            )
                            .with_receipt_bindings_if_missing(receipt_bindings));
                        }
                        Err(_) => {
                            this.transfer_child_custody(child);
                            return Err(CageLaunchError::terminalization_failed(
                                &this.evidence,
                                CageEnforcementFailureCode::StatusProtocolViolation,
                                "child_wait_reap",
                            )
                            .with_receipt_bindings_if_missing(receipt_bindings));
                        }
                    }
                }
            };
            this.exited_record(status, receipt_bindings)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageLaunchError::unsupported())
        }
    }

    /// Terminate the exact retained process and return signed-receipt-ready
    /// terminal evidence. The child receives SIGTERM first. If it does not
    /// exit during the bounded grace period, the retained pidfd delivers
    /// SIGKILL. Success requires reaping the child and recording the observed
    /// exit code or signal. Failure preserves the truthful fully-enforced
    /// record and never claims an unverified terminal exit.
    pub fn terminate(self) -> Result<CageEnforcementRecord, CageLaunchError> {
        #[cfg(target_os = "linux")]
        {
            let mut this = self;
            let receipt_bindings = CageReceiptBindings::from_prepared(&this.evidence.prepared);
            this.require_process_owner("child_terminate_owner")?;
            drop(this.stdio.take());
            let child = this.child.take().ok_or_else(|| {
                CageLaunchError::terminalization_failed(
                    &this.evidence,
                    CageEnforcementFailureCode::StatusProtocolViolation,
                    "termination_child_handle",
                )
                .with_receipt_bindings_if_missing(receipt_bindings.clone())
            })?;

            match platform::try_reap_pidfd(&this.pidfd) {
                Ok(platform::PidfdReap::Exited(status)) => {
                    return this.exited_record(status, receipt_bindings);
                }
                Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                    return Err(CageLaunchError::terminalization_failed(
                        &this.evidence,
                        CageEnforcementFailureCode::StatusProtocolViolation,
                        "termination_status_unavailable",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings));
                }
                Ok(platform::PidfdReap::Running) | Err(_) => {}
            }

            if platform::signal_pidfd(&this.pidfd, libc::SIGTERM).is_ok() {
                match wait_pidfd_bounded(&this.pidfd, TERMINATION_GRACE_PERIOD) {
                    Ok(platform::PidfdReap::Exited(status)) => {
                        return this.exited_record(status, receipt_bindings);
                    }
                    Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                        return Err(CageLaunchError::terminalization_failed(
                            &this.evidence,
                            CageEnforcementFailureCode::StatusProtocolViolation,
                            "termination_status_unavailable",
                        )
                        .with_receipt_bindings_if_missing(receipt_bindings));
                    }
                    Ok(platform::PidfdReap::Running) | Err(_) => {}
                }
            } else {
                match platform::try_reap_pidfd(&this.pidfd) {
                    Ok(platform::PidfdReap::Exited(status)) => {
                        return this.exited_record(status, receipt_bindings);
                    }
                    Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                        return Err(CageLaunchError::terminalization_failed(
                            &this.evidence,
                            CageEnforcementFailureCode::StatusProtocolViolation,
                            "termination_status_unavailable",
                        )
                        .with_receipt_bindings_if_missing(receipt_bindings));
                    }
                    Ok(platform::PidfdReap::Running) | Err(_) => {}
                }
            }

            if platform::kill_pidfd(&this.pidfd).is_err() {
                match platform::try_reap_pidfd(&this.pidfd) {
                    Ok(platform::PidfdReap::Exited(status)) => {
                        return this.exited_record(status, receipt_bindings);
                    }
                    Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                        return Err(CageLaunchError::terminalization_failed(
                            &this.evidence,
                            CageEnforcementFailureCode::StatusProtocolViolation,
                            "termination_status_unavailable",
                        )
                        .with_receipt_bindings_if_missing(receipt_bindings));
                    }
                    Ok(platform::PidfdReap::Running) | Err(_) => {
                        this.transfer_child_custody(child);
                        return Err(CageLaunchError::terminalization_failed(
                            &this.evidence,
                            CageEnforcementFailureCode::StatusProtocolViolation,
                            "termination_kill",
                        )
                        .with_receipt_bindings_if_missing(receipt_bindings));
                    }
                }
            }

            match wait_pidfd_bounded(&this.pidfd, TERMINATION_REAP_TIMEOUT) {
                Ok(platform::PidfdReap::Exited(status)) => {
                    this.exited_record(status, receipt_bindings)
                }
                Ok(platform::PidfdReap::ReapedWithoutStatus) => {
                    Err(CageLaunchError::terminalization_failed(
                        &this.evidence,
                        CageEnforcementFailureCode::StatusProtocolViolation,
                        "termination_status_unavailable",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings))
                }
                Ok(platform::PidfdReap::Running) => {
                    this.transfer_child_custody(child);
                    Err(CageLaunchError::terminalization_failed(
                        &this.evidence,
                        CageEnforcementFailureCode::Timeout,
                        "termination_reap_timeout",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings))
                }
                Err(_) => {
                    this.transfer_child_custody(child);
                    Err(CageLaunchError::terminalization_failed(
                        &this.evidence,
                        CageEnforcementFailureCode::StatusProtocolViolation,
                        "termination_reap",
                    )
                    .with_receipt_bindings_if_missing(receipt_bindings))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageLaunchError::unsupported())
        }
    }

    #[cfg(target_os = "linux")]
    fn exited_record(
        &self,
        status: std::process::ExitStatus,
        receipt_bindings: CageReceiptBindings,
    ) -> Result<CageEnforcementRecord, CageLaunchError> {
        let exit = platform::exit_evidence(self.process_id(), status).map_err(|error| {
            CageLaunchError::terminalization_failure(
                &self.evidence,
                error.operation_failure().clone(),
            )
            .with_receipt_bindings_if_missing(receipt_bindings.clone())
        })?;
        CageEnforcementRecord::exited(self.evidence.clone(), exit).map_err(|_| {
            CageLaunchError::terminalization_failed(
                &self.evidence,
                CageEnforcementFailureCode::StatusProtocolViolation,
                "exit_evidence",
            )
            .with_receipt_bindings_if_missing(receipt_bindings)
        })
    }

    #[cfg(target_os = "linux")]
    fn new(
        child: std::process::Child,
        pidfd: Arc<std::os::fd::OwnedFd>,
        custody_permit: ChildCustodyPermit,
        evidence: FullyEnforcedEvidence,
        stdio: EnforcedStdio,
    ) -> Self {
        let owner_pid = custody_permit.owner_pid;
        Self {
            child: Some(child),
            pidfd,
            custody_permit: Some(custody_permit),
            owner_pid,
            evidence,
            stdio: Some(stdio),
        }
    }

    #[cfg(target_os = "linux")]
    fn transfer_child_custody(&mut self, child: std::process::Child) {
        let Some(permit) = self.custody_permit.take() else {
            std::process::abort();
        };
        transfer_child_custody(child, Some(Arc::clone(&self.pidfd)), permit);
    }

    #[cfg(target_os = "linux")]
    fn require_process_owner(&self, stage: &'static str) -> Result<(), CageLaunchError> {
        if std::process::id() != self.owner_pid {
            return Err(CageLaunchError::terminalization_failed(
                &self.evidence,
                CageEnforcementFailureCode::StatusProtocolViolation,
                stage,
            )
            .with_receipt_bindings_if_missing(CageReceiptBindings::from_prepared(
                &self.evidence.prepared,
            )));
        }
        Ok(())
    }
}

/// Termination signals that may be forwarded to an enforced child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationSignal {
    Hangup,
    Interrupt,
    Terminate,
}

#[cfg(target_os = "linux")]
impl TerminationSignal {
    const fn as_raw(self) -> i32 {
        match self {
            Self::Hangup => libc::SIGHUP,
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for EnforcedChild {
    fn drop(&mut self) {
        if std::process::id() != self.owner_pid {
            return;
        }
        if let Some(child) = self.child.take() {
            if platform::signal_pidfd(&self.pidfd, libc::SIGTERM).is_ok()
                && matches!(
                    wait_pidfd_bounded(&self.pidfd, TERMINATION_GRACE_PERIOD),
                    Ok(platform::PidfdReap::Exited(_) | platform::PidfdReap::ReapedWithoutStatus)
                )
            {
                return;
            }
            if matches!(
                platform::try_reap_pidfd(&self.pidfd),
                Ok(platform::PidfdReap::Exited(_) | platform::PidfdReap::ReapedWithoutStatus)
            ) {
                return;
            }
            let _ = platform::kill_pidfd(&self.pidfd);
            if !matches!(
                wait_pidfd_bounded(&self.pidfd, TERMINATION_REAP_TIMEOUT),
                Ok(platform::PidfdReap::Exited(_) | platform::PidfdReap::ReapedWithoutStatus)
            ) {
                self.transfer_child_custody(child);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_pidfd_bounded(
    pidfd: &std::os::fd::OwnedFd,
    timeout: Duration,
) -> Result<platform::PidfdReap, CageLaunchError> {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::Timeout,
            "pidfd_wait_deadline",
        ));
    };
    loop {
        match platform::try_reap_pidfd(pidfd)? {
            platform::PidfdReap::Running => {}
            terminal => return Ok(terminal),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return platform::try_reap_pidfd(pidfd);
        }
        let timeout_ms = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut descriptor = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the duration
        // of the call, and timeout_ms is a finite nonnegative timeout.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::StatusProtocolViolation,
                    "pidfd_poll",
                ));
            }
            continue;
        }
        if result == 0 {
            return platform::try_reap_pidfd(pidfd);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "pidfd_poll",
            ));
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct ChildCustodyPermit {
    owner_pid: u32,
}

#[cfg(target_os = "linux")]
impl Drop for ChildCustodyPermit {
    fn drop(&mut self) {
        if std::process::id() != self.owner_pid {
            return;
        }
        let previous = SUPERVISED_CHILDREN.fetch_sub(1, Ordering::AcqRel);
        if previous == 0 {
            std::process::abort();
        }
    }
}

#[cfg(target_os = "linux")]
struct ChildCustody {
    child: std::process::Child,
    pidfd: Option<Arc<std::os::fd::OwnedFd>>,
    _permit: ChildCustodyPermit,
}

#[cfg(target_os = "linux")]
impl ChildCustody {
    fn new(
        child: std::process::Child,
        pidfd: Option<Arc<std::os::fd::OwnedFd>>,
        permit: ChildCustodyPermit,
    ) -> Self {
        Self {
            child,
            pidfd,
            _permit: permit,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn reserve_child_custody() -> Result<ChildCustodyPermit, CageLaunchError> {
    if child_supervisor_sender().is_none() {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "child_supervisor_start",
        ));
    }
    if SUPERVISED_CHILDREN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < MAX_SUPERVISED_CHILDREN).then_some(current + 1)
        })
        .is_err()
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "child_supervisor_capacity",
        ));
    }
    Ok(ChildCustodyPermit {
        owner_pid: std::process::id(),
    })
}

#[cfg(target_os = "linux")]
fn child_supervisor_sender() -> Option<&'static std::sync::mpsc::SyncSender<ChildCustody>> {
    let supervisor = CHILD_SUPERVISOR
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(MAX_SUPERVISED_CHILDREN);
            match std::thread::Builder::new()
                .name("chio-cage-child-supervisor".to_string())
                .spawn(move || supervise_child_custodies(receiver))
            {
                Ok(_handle) => Some(ChildSupervisor {
                    owner_pid: std::process::id(),
                    sender,
                }),
                Err(_) => None,
            }
        })
        .as_ref()?;
    (supervisor.owner_pid == std::process::id()).then_some(&supervisor.sender)
}

#[cfg(target_os = "linux")]
fn supervise_child_custodies(receiver: std::sync::mpsc::Receiver<ChildCustody>) {
    let mut custodies = Vec::with_capacity(MAX_SUPERVISED_CHILDREN);
    loop {
        let disconnected = if custodies.is_empty() {
            match receiver.recv() {
                Ok(custody) => {
                    push_child_custody(&mut custodies, custody);
                    false
                }
                Err(_) => return,
            }
        } else {
            match receiver.recv_timeout(REAPER_KILL_RETRY_PERIOD) {
                Ok(custody) => {
                    push_child_custody(&mut custodies, custody);
                    false
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
            }
        };

        while let Ok(custody) = receiver.try_recv() {
            push_child_custody(&mut custodies, custody);
        }

        let mut index = 0;
        while index < custodies.len() {
            let custody = &mut custodies[index];
            if child_custody_is_reaped(custody) {
                drop(custodies.swap_remove(index));
                continue;
            }
            signal_child_kill(custody);
            if child_custody_is_reaped(custody) {
                drop(custodies.swap_remove(index));
                continue;
            }
            index += 1;
        }

        if disconnected {
            if custodies.is_empty() {
                return;
            }
            std::thread::sleep(REAPER_KILL_RETRY_PERIOD);
        }
    }
}

#[cfg(target_os = "linux")]
fn push_child_custody(custodies: &mut Vec<ChildCustody>, custody: ChildCustody) {
    if custodies.len() >= MAX_SUPERVISED_CHILDREN {
        std::process::abort();
    }
    custodies.push(custody);
}

#[cfg(target_os = "linux")]
fn child_custody_is_reaped(custody: &mut ChildCustody) -> bool {
    if let Some(pidfd) = custody.pidfd.as_ref() {
        return matches!(
            platform::try_reap_pidfd(pidfd),
            Ok(platform::PidfdReap::Exited(_) | platform::PidfdReap::ReapedWithoutStatus)
        );
    }
    match custody.child.try_wait() {
        Ok(Some(_)) => true,
        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => true,
        Ok(None) | Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn signal_child_kill(custody: &mut ChildCustody) {
    if let Some(pidfd) = custody.pidfd.as_ref() {
        let _ = platform::kill_pidfd(pidfd);
    }
}

#[cfg(target_os = "linux")]
fn reap_child_custody_bounded_with<K>(
    custody: &mut ChildCustody,
    timeout: Duration,
    mut signal_kill: K,
) -> bool
where
    K: FnMut(&mut ChildCustody),
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return false;
    };
    loop {
        if child_custody_is_reaped(custody) {
            return true;
        }
        signal_kill(custody);
        if child_custody_is_reaped(custody) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(REAPER_KILL_RETRY_PERIOD));
    }
}

#[cfg(target_os = "linux")]
fn reap_child_custody_bounded(custody: &mut ChildCustody, timeout: Duration) -> bool {
    reap_child_custody_bounded_with(custody, timeout, signal_child_kill)
}

#[cfg(target_os = "linux")]
fn enqueue_child_custody(custody: ChildCustody) -> Result<(), ChildCustody> {
    let Some(sender) = child_supervisor_sender() else {
        return Err(custody);
    };
    sender.try_send(custody).map_err(|error| match error {
        std::sync::mpsc::TrySendError::Full(custody)
        | std::sync::mpsc::TrySendError::Disconnected(custody) => custody,
    })
}

#[cfg(target_os = "linux")]
fn transfer_child_custody_with<H>(custody: ChildCustody, handoff: H) -> bool
where
    H: FnOnce(ChildCustody) -> Result<(), ChildCustody>,
{
    match handoff(custody) {
        Ok(()) => true,
        Err(mut custody) => {
            while !reap_child_custody_bounded(&mut custody, TERMINATION_REAP_TIMEOUT) {
                // Custody cannot be dropped after a failed handoff. Keep the
                // current thread responsible until the exact child is reaped.
            }
            false
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn transfer_child_custody(
    child: std::process::Child,
    pidfd: Option<Arc<std::os::fd::OwnedFd>>,
    permit: ChildCustodyPermit,
) {
    if permit.owner_pid != std::process::id() {
        return;
    }
    let custody = ChildCustody::new(child, pidfd, permit);
    let _ = transfer_child_custody_with(custody, enqueue_child_custody);
}

#[derive(Debug, thiserror::Error)]
#[error("cage lifecycle operation failed at {operation_failure:?}")]
pub struct CageLaunchError {
    record: Box<CageEnforcementRecord>,
    receipt_bindings: Option<Box<CageReceiptBindings>>,
    operation_failure: CageEnforcementFailure,
}

impl CageLaunchError {
    /// Return the last truthful enforcement state. For an operation that fails
    /// after full enforcement, this is the prior `FullyEnforced` snapshot, not
    /// a new receipt record. Use `operation_failure` for the failed operation
    /// and do not persist this snapshot as another lifecycle transition.
    #[must_use]
    pub fn record(&self) -> &CageEnforcementRecord {
        &self.record
    }

    /// Return the exact failed lifecycle operation without changing the last
    /// truthful enforcement record.
    #[must_use]
    pub const fn operation_failure(&self) -> &CageEnforcementFailure {
        &self.operation_failure
    }

    /// Return authenticated compiled bindings for a truthful failure receipt.
    #[must_use]
    pub fn receipt_bindings(&self) -> Option<&CageReceiptBindings> {
        self.receipt_bindings.as_deref()
    }

    #[cfg(not(target_os = "linux"))]
    fn unsupported() -> Self {
        Self::failure(
            crate::CageEnforcementState::Unsupported,
            CageEnforcementFailureCode::UnsupportedKernel,
            "platform",
        )
    }

    fn rejected(code: CageEnforcementFailureCode, stage: &'static str) -> Self {
        Self::failure(crate::CageEnforcementState::Rejected, code, stage)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bootstrap_failed(code: CageEnforcementFailureCode, stage: &'static str) -> Self {
        Self::failure(crate::CageEnforcementState::BootstrapFailed, code, stage)
    }

    fn failure(
        state: crate::CageEnforcementState,
        code: CageEnforcementFailureCode,
        stage: &'static str,
    ) -> Self {
        let failure = CageEnforcementFailure {
            code,
            stage: stage.to_string(),
        };
        Self {
            record: Box::new(CageEnforcementRecord {
                schema: crate::CAGE_ENFORCEMENT_RECORD_SCHEMA.to_string(),
                state,
                fully_enforced: None,
                failure: Some(failure.clone()),
                exit: None,
            }),
            receipt_bindings: None,
            operation_failure: failure,
        }
    }

    #[cfg(target_os = "linux")]
    fn terminalization_failed(
        evidence: &FullyEnforcedEvidence,
        code: CageEnforcementFailureCode,
        stage: &'static str,
    ) -> Self {
        Self::terminalization_failure(
            evidence,
            CageEnforcementFailure {
                code,
                stage: stage.to_string(),
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn terminalization_failure(
        evidence: &FullyEnforcedEvidence,
        operation_failure: CageEnforcementFailure,
    ) -> Self {
        Self {
            record: Box::new(CageEnforcementRecord {
                schema: crate::CAGE_ENFORCEMENT_RECORD_SCHEMA.to_string(),
                state: crate::CageEnforcementState::FullyEnforced,
                fully_enforced: Some(evidence.clone()),
                failure: None,
                exit: None,
            }),
            receipt_bindings: None,
            operation_failure,
        }
    }

    pub(crate) fn with_receipt_bindings_if_missing(
        mut self,
        bindings: CageReceiptBindings,
    ) -> Self {
        if self.receipt_bindings.is_none() {
            self.receipt_bindings = Some(Box::new(bindings));
        }
        self
    }
}

/// Bind, validate, serialize, and seal a launch without spawning or executing.
pub fn prepare_launch(compiled: CompiledCage) -> Result<PreparedCageLaunch, CageLaunchError> {
    prepare_launch_with_options(compiled, CageLaunchOptions::default())
}

/// Bind, validate, serialize, and seal a launch under the supplied deadline
/// without spawning or executing. Callers may perform a final durable policy
/// revalidation before consuming the returned single-use preparation.
pub fn prepare_launch_with_options(
    compiled: CompiledCage,
    options: CageLaunchOptions,
) -> Result<PreparedCageLaunch, CageLaunchError> {
    let receipt_bindings = CageReceiptBindings::from_compiled(&compiled);
    #[cfg(target_os = "linux")]
    {
        platform::prepare_launch(compiled, options)
            .map(|inner| PreparedCageLaunch { inner })
            .map_err(|error| error.with_receipt_bindings_if_missing(receipt_bindings))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (compiled, options);
        Err(CageLaunchError::unsupported().with_receipt_bindings_if_missing(receipt_bindings))
    }
}

/// Consume an observed sealed preparation and begin the enforced launch.
pub fn launch_prepared(
    prepared: PreparedCageLaunch,
    options: CageLaunchOptions,
) -> Result<EnforcedChild, CageLaunchError> {
    #[cfg(target_os = "linux")]
    {
        platform::launch_prepared(prepared.inner, options)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (prepared, options);
        Err(CageLaunchError::unsupported())
    }
}

pub fn launch(
    compiled: CompiledCage,
    options: CageLaunchOptions,
) -> Result<EnforcedChild, CageLaunchError> {
    let receipt_bindings = CageReceiptBindings::from_compiled(&compiled);
    prepare_launch_with_options(compiled, options)
        .and_then(|prepared| launch_prepared(prepared, options))
        .map_err(|error| error.with_receipt_bindings_if_missing(receipt_bindings))
}

pub fn run_cage_init() -> Result<(), CageLaunchError> {
    #[cfg(target_os = "linux")]
    {
        platform::run_cage_init()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(CageLaunchError::unsupported())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn enforced_child(
    child: std::process::Child,
    pidfd: Arc<std::os::fd::OwnedFd>,
    custody_permit: ChildCustodyPermit,
    evidence: FullyEnforcedEvidence,
    stdio: EnforcedStdio,
) -> EnforcedChild {
    EnforcedChild::new(child, pidfd, custody_permit, evidence, stdio)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_exit_evidence(
    process_id: u32,
    exit_code: Option<i32>,
    signal: Option<i32>,
    exited_at_unix_ms: u64,
) -> Result<ProcessExitEvidence, CageLaunchError> {
    let evidence = ProcessExitEvidence {
        process_id,
        exit_code,
        signal,
        exited_at_unix_ms,
    };
    evidence.validate().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "exit_evidence",
        )
    })?;
    Ok(evidence)
}

#[cfg(all(test, target_os = "linux"))]
mod linux_child_custody_tests {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::{Child, Command, Stdio};

    use super::*;

    fn reap_test_child_after_stdin_close(child: &mut Child) {
        drop(child.stdin.take());
        let Some(deadline) = Instant::now().checked_add(TERMINATION_REAP_TIMEOUT) else {
            std::process::abort();
        };
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                Ok(None) | Err(_) => {}
            }
            if Instant::now() >= deadline {
                std::process::abort();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn live_child_custody() -> std::io::Result<ChildCustody> {
        let permit =
            reserve_child_custody().map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let process_id = child.id();
        // SAFETY: pidfd_open receives a live child PID and zero flags.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            reap_test_child_after_stdin_close(&mut child);
            return Err(error);
        }
        let raw_fd = match i32::try_from(raw) {
            Ok(raw_fd) => raw_fd,
            Err(_) => std::process::abort(),
        };
        // SAFETY: a successful pidfd_open returned one new owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(ChildCustody::new(child, Some(Arc::new(pidfd)), permit))
    }

    fn wait_until_reaped(pidfd: &std::os::fd::OwnedFd) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if platform::pidfd_is_reaped(pidfd)
                .map_err(|error| std::io::Error::other(error.to_string()))?
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "child pidfd was not reaped before the deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn child_reaper_start_failure_reaps_synchronously() -> std::io::Result<()> {
        let mut custody = live_child_custody()?;
        custody.pidfd = None;
        drop(custody.child.stdin.take());
        let transferred = transfer_child_custody_with(custody, |custody| Err(custody));

        assert!(!transferred);
        Ok(())
    }

    #[test]
    fn child_reaper_send_failure_reaps_synchronously() -> std::io::Result<()> {
        let custody = live_child_custody()?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let transferred = transfer_child_custody_with(custody, |custody| {
            sender.try_send(custody).map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(custody)
                | std::sync::mpsc::TrySendError::Disconnected(custody) => custody,
            })
        });

        assert!(!transferred);
        Ok(())
    }

    #[test]
    fn child_supervisor_retries_sigkill_until_reaped() -> std::io::Result<()> {
        let mut custody = live_child_custody()?;
        let mut kill_attempts = 0_u8;
        let reaped =
            reap_child_custody_bounded_with(&mut custody, TERMINATION_REAP_TIMEOUT, |custody| {
                kill_attempts = kill_attempts.saturating_add(1);
                if kill_attempts > 1 {
                    signal_child_kill(custody);
                }
            });

        assert!(reaped);
        assert!(kill_attempts >= 2);
        Ok(())
    }

    #[test]
    fn acknowledged_child_reaper_handoff_reaps() -> std::io::Result<()> {
        let custody = live_child_custody()?;
        let Some(pidfd) = custody.pidfd.as_ref().map(Arc::clone) else {
            return Err(std::io::Error::other("test custody has no pidfd"));
        };
        assert!(transfer_child_custody_with(custody, enqueue_child_custody));
        wait_until_reaped(&pidfd)
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_keeps_a_fail_closed_signal_surface() {
        fn signal_surface(
            child: &EnforcedChild,
            signal: TerminationSignal,
        ) -> Result<(), CageLaunchError> {
            child.signal(signal)
        }

        let _: fn(&EnforcedChild, TerminationSignal) -> Result<(), CageLaunchError> =
            signal_surface;
        let _: fn(&mut EnforcedChild) -> Result<Option<CageEnforcementRecord>, CageLaunchError> =
            EnforcedChild::try_wait;
        let unsupported = CageLaunchError::unsupported();
        assert_eq!(
            unsupported.record().state,
            crate::CageEnforcementState::Unsupported
        );
    }
}
