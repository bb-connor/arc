//! Closed private refusal metadata, independent of authority and error values.
//!
//! A native capture also reports one bounded profile: authority-clock values
//! the transaction already holds, and the monotonic and thread CPU time spent
//! in each visited stage. No profile value is read back by any check.
use std::cell::Cell;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_kernel::budget_store::BudgetStoreError;

#[derive(Clone, Copy)]
pub(crate) enum NativeCaptureStage {
    StoreCallback,
    Connection,
    TransactionBegin,
    Authority,
    PreflightHold,
    NativeEvidence,
    NativeBinding,
    NativePolicy,
    NativeOwner,
    BudgetSelection,
    BudgetReplay,
    BudgetCredentials,
    BudgetHold,
    BudgetIdentity,
    BudgetRevocation,
    BudgetMutation,
    AdmissionAdvance,
    CommitPolicy,
    CommitClock,
    CommitLeaseExpired,
    CommitCapabilityExpired,
    CommitRuntimeExpired,
    CommitNonceExpired,
    CommitApproval,
    CommitDpop,
    PolicyNotYetValid,
    PolicyExpired,
    DeclassificationNotYetValid,
    DeclassificationExpired,
    ObservationChanged,
    Commit,
    AnchorSync,
}

impl NativeCaptureStage {
    fn token(self) -> &'static str {
        match self {
            Self::StoreCallback => "store_callback",
            Self::Connection => "connection",
            Self::TransactionBegin => "transaction_begin",
            Self::Authority => "authority",
            Self::PreflightHold => "preflight_hold",
            Self::NativeEvidence => "native_evidence",
            Self::NativeBinding => "native_binding",
            Self::NativePolicy => "native_policy",
            Self::NativeOwner => "native_owner",
            Self::BudgetSelection => "budget_selection",
            Self::BudgetReplay => "budget_replay",
            Self::BudgetCredentials => "budget_credentials",
            Self::BudgetHold => "budget_hold",
            Self::BudgetIdentity => "budget_identity",
            Self::BudgetRevocation => "budget_revocation",
            Self::BudgetMutation => "budget_mutation",
            Self::AdmissionAdvance => "admission_advance",
            Self::CommitPolicy => "commit_policy",
            Self::CommitClock => "commit_clock",
            Self::CommitLeaseExpired => "commit_lease_expired",
            Self::CommitCapabilityExpired => "commit_capability_expired",
            Self::CommitRuntimeExpired => "commit_runtime_expired",
            Self::CommitNonceExpired => "commit_nonce_expired",
            Self::CommitApproval => "commit_approval",
            Self::CommitDpop => "commit_dpop",
            Self::PolicyNotYetValid => "policy_not_yet_valid",
            Self::PolicyExpired => "policy_expired",
            Self::DeclassificationNotYetValid => "declassification_not_yet_valid",
            Self::DeclassificationExpired => "declassification_expired",
            Self::ObservationChanged => "observation_changed",
            Self::Commit => "commit",
            Self::AnchorSync => "anchor_sync",
        }
    }
}

/// The time-check site whose failed check refused the capture.
#[derive(Clone, Copy)]
pub(crate) enum NativeCapturePhase {
    /// Policy at the transaction's first authority sample.
    CaptureEntry,
    /// Every deadline at the caller frame's frozen interval endpoint.
    CallerInterval,
    /// Every deadline at the sample taken before final state verification.
    CommitState,
    /// Every deadline at the last sample before the physical commit.
    CommitTime,
}

impl NativeCapturePhase {
    fn token(self) -> &'static str {
        match self {
            Self::CaptureEntry => "capture_entry",
            Self::CallerInterval => "caller_interval",
            Self::CommitState => "commit_state",
            Self::CommitTime => "commit_time",
        }
    }
}

/// Authority-clock values the capture already holds. The profile reports each
/// as milliseconds after policy preparation, in this declaration order.
#[derive(Clone, Copy)]
pub(crate) enum NativeCaptureTime {
    PolicyPrepared,
    PolicyValidUntil,
    RetainDecision,
    RetainEntry,
    CaptureDecision,
    CaptureEntry,
    CallerInterval,
    CommitState,
    CommitTime,
}

const TIMES: usize = 9;

impl NativeCaptureTime {
    const REPORTED: [Self; TIMES - 1] = [
        Self::PolicyValidUntil,
        Self::RetainDecision,
        Self::RetainEntry,
        Self::CaptureDecision,
        Self::CaptureEntry,
        Self::CallerInterval,
        Self::CommitState,
        Self::CommitTime,
    ];

    fn slot(self) -> usize {
        match self {
            Self::PolicyPrepared => 0,
            Self::PolicyValidUntil => 1,
            Self::RetainDecision => 2,
            Self::RetainEntry => 3,
            Self::CaptureDecision => 4,
            Self::CaptureEntry => 5,
            Self::CallerInterval => 6,
            Self::CommitState => 7,
            Self::CommitTime => 8,
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::PolicyPrepared => "prepared",
            Self::PolicyValidUntil => "valid_until",
            Self::RetainDecision => "retain_decision",
            Self::RetainEntry => "retain_entry",
            Self::CaptureDecision => "capture_decision",
            Self::CaptureEntry => "capture_entry",
            Self::CallerInterval => "caller_interval",
            Self::CommitState => "commit_state",
            Self::CommitTime => "commit_time",
        }
    }
}

/// Every stage visit comes from a distinct call site outside any loop, so one
/// capture visits fewer stages than this bound. Later visits are not recorded.
const MAX_STAGE_VISITS: usize = 64;

#[derive(Clone, Copy)]
struct Mark {
    wall: Instant,
    cpu: Duration,
}

impl Mark {
    fn now() -> Self {
        let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
        Self {
            wall: Instant::now(),
            cpu: Duration::from_secs(u64::try_from(cpu.tv_sec).unwrap_or(0)).saturating_add(
                Duration::from_nanos(u64::try_from(cpu.tv_nsec).unwrap_or(0)),
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct StageVisit {
    stage: NativeCaptureStage,
    wall: Duration,
    cpu: Duration,
}

fn micros(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy)]
enum Category {
    Fenced,
    OutcomeUnknown,
    Invariant,
    Unavailable,
    Operation,
    NotFound,
    Clock,
    Sqlite,
    Io,
    Overflow,
}

impl Category {
    fn token(self) -> &'static str {
        match self {
            Self::Fenced => "fenced",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::Invariant => "invariant",
            Self::Unavailable => "unavailable",
            Self::Operation => "operation",
            Self::NotFound => "not_found",
            Self::Clock => "clock",
            Self::Sqlite => "sqlite",
            Self::Io => "io",
            Self::Overflow => "overflow",
        }
    }

    fn budget(error: &BudgetStoreError) -> Self {
        match error {
            BudgetStoreError::Fenced { .. } => Self::Fenced,
            BudgetStoreError::OutcomeUnknown(_) => Self::OutcomeUnknown,
            BudgetStoreError::Invariant(_) => Self::Invariant,
            BudgetStoreError::Clock(_) => Self::Clock,
            BudgetStoreError::Sqlite(_) => Self::Sqlite,
            BudgetStoreError::Io(_) => Self::Io,
            BudgetStoreError::Overflow(_) => Self::Overflow,
        }
    }

    fn admission(error: &AdmissionOperationStoreError) -> Self {
        match error {
            AdmissionOperationStoreError::Fenced => Self::Fenced,
            AdmissionOperationStoreError::OutcomeUnknown(_) => Self::OutcomeUnknown,
            AdmissionOperationStoreError::Invariant(_) => Self::Invariant,
            AdmissionOperationStoreError::Unavailable(_) => Self::Unavailable,
            AdmissionOperationStoreError::Operation(_) => Self::Operation,
            AdmissionOperationStoreError::NotFound => Self::NotFound,
        }
    }
}

/// One physical capture's observation. It never contains an identifier or error text.
pub(crate) struct NativeCaptureDiagnostic {
    enabled: bool,
    stage: Cell<NativeCaptureStage>,
    category: Cell<Option<Category>>,
    phase: Cell<Option<NativeCapturePhase>>,
    times: [Cell<Option<u64>>; TIMES],
    mark: Cell<Option<Mark>>,
    visits: [Cell<Option<StageVisit>>; MAX_STAGE_VISITS],
    visited: Cell<usize>,
}

impl NativeCaptureDiagnostic {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            stage: Cell::new(NativeCaptureStage::StoreCallback),
            category: Cell::new(None),
            phase: Cell::new(None),
            times: std::array::from_fn(|_| Cell::new(None)),
            mark: Cell::new(enabled.then(Mark::now)),
            visits: std::array::from_fn(|_| Cell::new(None)),
            visited: Cell::new(0),
        }
    }

    pub(crate) fn at(&self, stage: NativeCaptureStage) {
        self.close_visit();
        self.stage.set(stage);
        self.category.set(None);
    }

    /// Name the time-check site of a refusal. Call only on its failed result.
    pub(crate) fn phase(&self, phase: NativeCapturePhase) {
        self.phase.set(Some(phase));
    }

    /// Retain a value the capture already sampled or loaded. Never sample here.
    pub(crate) fn observe(&self, time: NativeCaptureTime, unix_ms: u64) {
        if let Some(slot) = self.times.get(time.slot()) {
            slot.set(Some(unix_ms));
        }
    }

    pub(crate) fn admission_error(&self, error: &AdmissionOperationStoreError) {
        self.category.set(Some(Category::admission(error)));
    }

    pub(crate) fn budget_refused(&self, error: &BudgetStoreError) {
        self.emit(
            self.category
                .get()
                .unwrap_or_else(|| Category::budget(error)),
        );
    }

    pub(crate) fn store_fenced() {
        Self::new(false).emit_enabled(Category::Fenced);
    }

    /// Report the finished capture's profile, after any refusal marker.
    pub(crate) fn profile(&self, captured: bool) {
        if !self.enabled {
            return;
        }
        self.close_visit();
        tracing::warn!(target: "chio::native_capture_profile",
            native_capture_outcome = if captured { "captured" } else { "refused" },
            native_capture_timeline = self.timeline().as_str(),
            native_capture_stages = self.stage_visits().as_str(),
            "native capture profile");
    }

    fn close_visit(&self) {
        let Some(start) = self.mark.get() else {
            return;
        };
        let end = Mark::now();
        self.mark.set(Some(end));
        let visited = self.visited.get();
        if let Some(slot) = self.visits.get(visited) {
            slot.set(Some(StageVisit {
                stage: self.stage.get(),
                wall: end.wall.saturating_duration_since(start.wall),
                cpu: end.cpu.saturating_sub(start.cpu),
            }));
            self.visited.set(visited.saturating_add(1));
        }
    }

    fn time(&self, time: NativeCaptureTime) -> Option<u64> {
        self.times.get(time.slot()).and_then(Cell::get)
    }

    fn timeline(&self) -> String {
        let Some(prepared) = self.time(NativeCaptureTime::PolicyPrepared) else {
            return "none".to_owned();
        };
        let mut line = String::new();
        for time in NativeCaptureTime::REPORTED {
            if let Some(unix_ms) = self.time(time) {
                let elapsed = u32::try_from(unix_ms.saturating_sub(prepared)).unwrap_or(u32::MAX);
                let separator = if line.is_empty() { "" } else { "," };
                let _ = write!(line, "{separator}{}:{elapsed}", time.token());
            }
        }
        if line.is_empty() {
            line.push_str("none");
        }
        line
    }

    fn stage_visits(&self) -> String {
        let mut line = String::new();
        for visit in self.visits.iter().filter_map(Cell::get) {
            let separator = if line.is_empty() { "" } else { "," };
            let _ = write!(
                line,
                "{separator}{}:{}/{}",
                visit.stage.token(),
                micros(visit.wall),
                micros(visit.cpu)
            );
        }
        if line.is_empty() {
            line.push_str("none");
        }
        line
    }

    fn emit(&self, category: Category) {
        if self.enabled {
            self.emit_enabled(category);
        }
    }

    fn emit_enabled(&self, category: Category) {
        let stage = self.stage.get().token();
        match self.phase.get() {
            Some(phase) => tracing::warn!(target: "chio::native_capture",
                native_capture_stage = stage,
                native_capture_category = category.token(),
                native_capture_phase = phase.token(), "native capture refused"),
            None => tracing::warn!(target: "chio::native_capture",
                native_capture_stage = stage,
                native_capture_category = category.token(), "native capture refused"),
        }
    }
}
