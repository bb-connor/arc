//! Closed private refusal metadata, independent of authority and error values.
use std::cell::Cell;

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
}

impl NativeCaptureDiagnostic {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            stage: Cell::new(NativeCaptureStage::StoreCallback),
            category: Cell::new(None),
        }
    }

    pub(crate) fn at(&self, stage: NativeCaptureStage) {
        self.stage.set(stage);
        self.category.set(None);
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
        Self::new(true).emit(Category::Fenced);
    }

    fn emit(&self, category: Category) {
        if self.enabled {
            tracing::warn!(target: "chio::native_capture",
                native_capture_stage = self.stage.get().token(),
                native_capture_category = category.token(), "native capture refused");
        }
    }
}
