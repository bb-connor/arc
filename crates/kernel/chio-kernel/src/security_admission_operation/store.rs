//! The admission operation store port and its authority profiles.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOperationStoreProfile {
    EphemeralLocal,
    SingleNodeDurable,
    SharedLinearizable,
}

impl AdmissionOperationStoreProfile {
    pub fn supports_dispatch_workers(self, dispatch_worker_count: usize) -> bool {
        match self {
            Self::EphemeralLocal => false,
            Self::SingleNodeDurable => dispatch_worker_count == 1,
            Self::SharedLinearizable => dispatch_worker_count > 0,
        }
    }
}

pub trait AdmissionOperationStore: Send + Sync {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        AdmissionOperationStoreProfile::EphemeralLocal
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError>;

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError>;

    /// Return a bounded deterministic inventory for one caller request id.
    /// Exact caller-reservation replay uses this index before any new admission
    /// effect. More than one row is intentionally returned so the replay gate
    /// can reject an ambiguous or reused request id without choosing a row.
    fn load_by_request_id(
        &self,
        kind: AdmissionOperationKind,
        request_id: &str,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.load_by_request_id(kind, request_id, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "exact admission operation lookup by request id is unavailable".to_string(),
        ))
    }

    /// Resolve the one immutable admission operation that owns a budget hold.
    /// Concrete durable stores must enforce uniqueness for every non-null
    /// `budget_hold_id`; returning an arbitrary match is not permitted.
    fn load_by_budget_hold_id(
        &self,
        budget_hold_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.load_by_budget_hold_id(budget_hold_id);
        }
        Err(AdmissionOperationError::Unavailable(
            "exact admission operation lookup by budget hold is unavailable".to_string(),
        ))
    }

    /// Return a bounded, deterministic inventory of operations that still
    /// require recovery or reconciliation.
    fn list_unresolved(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_unresolved(kind, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "unresolved admission operation inventory is unavailable".to_string(),
        ))
    }

    /// Return one bounded activation-recovery batch with mutable operations
    /// first, incomplete caller handoffs second, and completed caller handoffs
    /// last. Outcome-unknown rows are excluded because their TerminalReceipt
    /// outboxes are recovered by the dedicated forward-only path.
    fn list_admission_recovery_candidates(
        &self,
        kind: AdmissionOperationKind,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_admission_recovery_candidates(kind, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "prioritized admission recovery inventory is unavailable".to_string(),
        ))
    }

    /// Traverse recovery candidates in stable operation-ID order. The cursor
    /// is exclusive and comes from the previous page; retained committed rows
    /// must not hide later recoverable operations.
    fn list_admission_recovery_candidates_page(
        &self,
        kind: AdmissionOperationKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_admission_recovery_candidates_page(
                kind,
                after_operation_id,
                limit,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "paged admission recovery inventory is unavailable".into(),
        ))
    }

    /// Return a bounded deterministic page of nonterminal caller-reservation
    /// operations that can require expiry terminalization. Expiry is deliberately
    /// not evaluated by the store: the only authoritative deadline is inside the
    /// signed handoff intent and must be verified by the kernel. The exclusive
    /// operation-id cursor lets repeated bounded calls cross arbitrarily large
    /// mixtures of unexpired, damaged, and terminalizable rows without starvation.
    fn list_caller_reservation_reap_candidates(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_caller_reservation_reap_candidates(after_operation_id, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "caller reservation reap inventory is unavailable".to_string(),
        ))
    }

    /// Atomically increment the operation lease epoch without changing saga
    /// state. Every later state transition must present the returned epoch.
    fn claim_recovery(
        &self,
        operation_id: &str,
        expected_version: u64,
        expected_coordinator_lease_epoch: u64,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.claim_recovery(
                operation_id,
                expected_version,
                expected_coordinator_lease_epoch,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "admission recovery claims are unavailable".to_string(),
        ))
    }

    /// Count operations that still require their original authority.
    ///
    /// An unknown post-dispatch outcome is terminal for admission mutation but
    /// remains unresolved for authority rotation and reconciliation.
    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError>;

    /// Count every nonterminal, non-compensated operation of one kind. This is
    /// the cold-restart authority-rotation gate when the prior coordinator
    /// identity is not available in process memory.
    fn count_unresolved(
        &self,
        kind: AdmissionOperationKind,
    ) -> Result<u64, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.count_unresolved(kind);
        }
        Err(AdmissionOperationError::Unavailable(
            "unresolved admission operation inventory is unavailable".to_string(),
        ))
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError>;

    /// Atomically persist one state transition and its exact forward-only
    /// journal action. Terminal receipt finalization uses this so a terminal
    /// operation can never become durable without a recoverable signed receipt.
    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.compare_and_swap_with_cleanup_action(request, action);
        }
        Err(AdmissionOperationError::Unavailable(
            "atomic admission transition with journal action is unavailable".to_string(),
        ))
    }

    /// Optional forwarding target for store decorators used by observability
    /// and fault-injection layers. Durable concrete stores should implement the
    /// cleanup methods directly. A decorator can forward the complete journal
    /// contract by returning its wrapped store here.
    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        None
    }

    fn create_cleanup_action(
        &self,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionCleanupActionCreateOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.create_cleanup_action(action);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.load_cleanup_actions(operation_id);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    /// Return compensation-pending or compensated operations with unfinished
    /// cleanup, oldest first.
    /// The caller supplies a hard bound so startup recovery never scans an
    /// unbounded journal in one pass.
    fn list_compensated_with_pending_cleanup(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_compensated_with_pending_cleanup(kind, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    /// Bounded compensation inventory with an exclusive operation-ID cursor.
    /// Busy or refused cleanup rows remain retained and cannot starve later IDs.
    fn list_compensated_with_pending_cleanup_page(
        &self,
        kind: Option<AdmissionOperationKind>,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_compensated_with_pending_cleanup_page(
                kind,
                after_operation_id,
                limit,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "paged admission cleanup inventory is unavailable".into(),
        ))
    }

    fn list_operations_with_pending_cleanup_action(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_operations_with_pending_cleanup_action(
                operation_kind,
                action_kind,
                limit,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "pending admission journal inventory is unavailable".to_string(),
        ))
    }

    /// Bounded pending-journal inventory with an exclusive operation-ID cursor.
    /// Rows whose recovery keeps failing stay in ID order and cannot starve
    /// later IDs.
    fn list_operations_with_pending_cleanup_action_page(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_operations_with_pending_cleanup_action_page(
                operation_kind,
                action_kind,
                after_operation_id,
                limit,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "paged pending admission journal inventory is unavailable".to_string(),
        ))
    }

    fn claim_cleanup_action(
        &self,
        action_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<AdmissionCleanupActionClaimOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.claim_cleanup_action(
                action_id,
                claim_token,
                now_unix_ms,
                claim_deadline_unix_ms,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn acknowledge_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.acknowledge_cleanup_action(action_id, expected_version, claim_token);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn abandon_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        last_error: String,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.abandon_cleanup_action(
                action_id,
                expected_version,
                claim_token,
                last_error,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }
}
