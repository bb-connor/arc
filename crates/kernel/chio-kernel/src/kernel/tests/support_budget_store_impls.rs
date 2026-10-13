/// Implements the listed `BudgetStore` methods by forwarding to `self.$field`.
macro_rules! delegate_budget_store_methods {
    ($field:ident; $($method:ident),+ $(,)?) => {
        $(delegate_budget_store_methods!(@method $field $method);)+
    };
    (@method $field:ident authorize_budget_hold) => {
        fn authorize_budget_hold(&self, request: crate::budget_store::BudgetAuthorizeHoldRequest) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, crate::budget_store::BudgetStoreError> {
            self.$field.authorize_budget_hold(request)
        }
    };
    (@method $field:ident capture_invocation_reservations) => {
        fn capture_invocation_reservations(&self, request: crate::budget_store::BudgetCaptureInvocationRequest) -> Result<crate::budget_store::BudgetInvocationCaptureDecision, crate::budget_store::BudgetStoreError> {
            self.$field.capture_invocation_reservations(request)
        }
    };
    (@method $field:ident authorize_cumulative_approval) => {
        fn authorize_cumulative_approval(&self, request: crate::budget_store::BudgetAuthorizeCumulativeApprovalRequest) -> Result<crate::budget_store::BudgetCumulativeApprovalAuthorizationDecision, crate::budget_store::BudgetStoreError> {
            self.$field.authorize_cumulative_approval(request)
        }
    };
    (@method $field:ident cancel_captured_before_dispatch) => {
        fn cancel_captured_before_dispatch(&self, request: crate::budget_store::BudgetCancelCapturedBeforeDispatchRequest) -> Result<crate::budget_store::BudgetCapturedBeforeDispatchCancellationDecision, crate::budget_store::BudgetStoreError> {
            self.$field.cancel_captured_before_dispatch(request)
        }
    };
    (@method $field:ident reverse_budget_hold) => {
        fn reverse_budget_hold(&self, request: crate::budget_store::BudgetReverseHoldRequest) -> Result<crate::budget_store::BudgetReverseHoldDecision, crate::budget_store::BudgetStoreError> {
            self.$field.reverse_budget_hold(request)
        }
    };
    (@method $field:ident release_budget_hold) => {
        fn release_budget_hold(&self, request: crate::budget_store::BudgetReleaseHoldRequest) -> Result<crate::budget_store::BudgetReleaseHoldDecision, crate::budget_store::BudgetStoreError> {
            self.$field.release_budget_hold(request)
        }
    };
    (@method $field:ident reconcile_budget_hold) => {
        fn reconcile_budget_hold(&self, request: crate::budget_store::BudgetReconcileHoldRequest) -> Result<crate::budget_store::BudgetReconcileHoldDecision, crate::budget_store::BudgetStoreError> {
            self.$field.reconcile_budget_hold(request)
        }
    };
    (@method $field:ident capture_budget_hold) => {
        fn capture_budget_hold(&self, request: crate::budget_store::BudgetCaptureHoldRequest) -> Result<crate::budget_store::BudgetCaptureHoldDecision, crate::budget_store::BudgetStoreError> {
            self.$field.capture_budget_hold(request)
        }
    };
    (@method $field:ident list_usages) => {
        fn list_usages(&self, limit: usize, capability_id: Option<&str>) -> Result<Vec<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError> {
            self.$field.list_usages(limit, capability_id)
        }
    };
    (@method $field:ident get_usage) => {
        fn get_usage(&self, capability_id: &str, grant_index: usize) -> Result<Option<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError> {
            self.$field.get_usage(capability_id, grant_index)
        }
    };
    (@method $field:ident get_invocation_quota_usage) => {
        fn get_invocation_quota_usage(&self, key: &crate::budget_store::BudgetQuotaKey) -> Result<Option<crate::budget_store::BudgetInvocationQuotaUsage>, crate::budget_store::BudgetStoreError> {
            self.$field.get_invocation_quota_usage(key)
        }
    };
    (@method $field:ident get_cumulative_approval_account_usage) => {
        fn get_cumulative_approval_account_usage(&self, key: &crate::budget_store::BudgetCumulativeApprovalAccountKey) -> Result<Option<crate::budget_store::BudgetCumulativeApprovalAccountUsage>, crate::budget_store::BudgetStoreError> {
            self.$field.get_cumulative_approval_account_usage(key)
        }
    };
    (@method $field:ident get_cumulative_approval_operation_usage) => {
        fn get_cumulative_approval_operation_usage(&self, operation_id: &str) -> Result<Option<crate::budget_store::BudgetCumulativeApprovalUsage>, crate::budget_store::BudgetStoreError> {
            self.$field.get_cumulative_approval_operation_usage(operation_id)
        }
    };
    (@method $field:ident list_mutation_events) => {
        fn list_mutation_events(&self, limit: usize, capability_id: Option<&str>, grant_index: Option<usize>) -> Result<Vec<crate::budget_store::BudgetMutationRecord>, crate::budget_store::BudgetStoreError> {
            self.$field.list_mutation_events(limit, capability_id, grant_index)
        }
    };
    (@method $field:ident reap_orphaned_holds) => {
        fn reap_orphaned_holds(&self, realized_by_hold: &std::collections::HashMap<String, u64>) -> Result<(usize, usize), crate::budget_store::BudgetStoreError> {
            self.$field.reap_orphaned_holds(realized_by_hold)
        }
    };
    (@method $field:ident count_open_holds) => {
        fn count_open_holds(&self) -> Result<usize, crate::budget_store::BudgetStoreError> {
            self.$field.count_open_holds()
        }
    };
    (@method $field:ident list_open_delegated_reserved_hold_ids) => {
        fn list_open_delegated_reserved_hold_ids(&self) -> Result<Option<Vec<String>>, crate::budget_store::BudgetStoreError> {
            self.$field.list_open_delegated_reserved_hold_ids()
        }
    };
    (@method $field:ident request_id_has_reserved_hold) => {
        fn request_id_has_reserved_hold(&self, request_id: &str) -> Result<Option<bool>, crate::budget_store::BudgetStoreError> {
            self.$field.request_id_has_reserved_hold(request_id)
        }
    };
    (@method $field:ident get_budget_hold) => {
        fn get_budget_hold(&self, hold_id: &str) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, crate::budget_store::BudgetStoreError> {
            self.$field.get_budget_hold(hold_id)
        }
    };
    (@method $field:ident mark_hold_reserved) => {
        fn mark_hold_reserved(&self, hold_id: &str, reserved_until_unix_secs: i64, currency: &str, payment_reference: Option<&str>, envelope: &crate::budget_store::ReservedHoldEnvelope) -> Result<(), crate::budget_store::BudgetStoreError> {
            self.$field.mark_hold_reserved(hold_id, reserved_until_unix_secs, currency, payment_reference, envelope)
        }
    };
    (@method $field:ident reap_expired_reserved_holds) => {
        fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, crate::budget_store::BudgetStoreError> {
            self.$field.reap_expired_reserved_holds(now_unix_secs)
        }
    };
}

/// Implements the listed `BudgetStore` methods for a stub that does not model them.
macro_rules! unsupported_budget_store_methods {
    ($reason:literal; $($method:ident),+ $(,)?) => {
        $(unsupported_budget_store_methods!(@method $reason $method);)+
    };
    (@method $reason:literal authorize_budget_hold) => {
        fn authorize_budget_hold(&self, _request: crate::budget_store::BudgetAuthorizeHoldRequest) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal capture_invocation_reservations) => {
        fn capture_invocation_reservations(&self, _request: crate::budget_store::BudgetCaptureInvocationRequest) -> Result<crate::budget_store::BudgetInvocationCaptureDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal authorize_cumulative_approval) => {
        fn authorize_cumulative_approval(&self, _request: crate::budget_store::BudgetAuthorizeCumulativeApprovalRequest) -> Result<crate::budget_store::BudgetCumulativeApprovalAuthorizationDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal cancel_captured_before_dispatch) => {
        fn cancel_captured_before_dispatch(&self, _request: crate::budget_store::BudgetCancelCapturedBeforeDispatchRequest) -> Result<crate::budget_store::BudgetCapturedBeforeDispatchCancellationDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal reverse_budget_hold) => {
        fn reverse_budget_hold(&self, _request: crate::budget_store::BudgetReverseHoldRequest) -> Result<crate::budget_store::BudgetReverseHoldDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal release_budget_hold) => {
        fn release_budget_hold(&self, _request: crate::budget_store::BudgetReleaseHoldRequest) -> Result<crate::budget_store::BudgetReleaseHoldDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal reconcile_budget_hold) => {
        fn reconcile_budget_hold(&self, _request: crate::budget_store::BudgetReconcileHoldRequest) -> Result<crate::budget_store::BudgetReconcileHoldDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal capture_budget_hold) => {
        fn capture_budget_hold(&self, _request: crate::budget_store::BudgetCaptureHoldRequest) -> Result<crate::budget_store::BudgetCaptureHoldDecision, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal list_usages) => {
        fn list_usages(&self, _limit: usize, _capability_id: Option<&str>) -> Result<Vec<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal get_usage) => {
        fn get_usage(&self, _capability_id: &str, _grant_index: usize) -> Result<Option<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal get_invocation_quota_usage) => {
        fn get_invocation_quota_usage(&self, _key: &crate::budget_store::BudgetQuotaKey) -> Result<Option<crate::budget_store::BudgetInvocationQuotaUsage>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal get_cumulative_approval_account_usage) => {
        fn get_cumulative_approval_account_usage(&self, _key: &crate::budget_store::BudgetCumulativeApprovalAccountKey) -> Result<Option<crate::budget_store::BudgetCumulativeApprovalAccountUsage>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal get_cumulative_approval_operation_usage) => {
        fn get_cumulative_approval_operation_usage(&self, _operation_id: &str) -> Result<Option<crate::budget_store::BudgetCumulativeApprovalUsage>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal list_mutation_events) => {
        fn list_mutation_events(&self, _limit: usize, _capability_id: Option<&str>, _grant_index: Option<usize>) -> Result<Vec<crate::budget_store::BudgetMutationRecord>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal reap_orphaned_holds) => {
        fn reap_orphaned_holds(&self, _realized_by_hold: &std::collections::HashMap<String, u64>) -> Result<(usize, usize), crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal count_open_holds) => {
        fn count_open_holds(&self) -> Result<usize, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal list_open_delegated_reserved_hold_ids) => {
        fn list_open_delegated_reserved_hold_ids(&self) -> Result<Option<Vec<String>>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal request_id_has_reserved_hold) => {
        fn request_id_has_reserved_hold(&self, _request_id: &str) -> Result<Option<bool>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal get_budget_hold) => {
        fn get_budget_hold(&self, _hold_id: &str) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal mark_hold_reserved) => {
        fn mark_hold_reserved(&self, _hold_id: &str, _reserved_until_unix_secs: i64, _currency: &str, _payment_reference: Option<&str>, _envelope: &crate::budget_store::ReservedHoldEnvelope) -> Result<(), crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
    (@method $reason:literal reap_expired_reserved_holds) => {
        fn reap_expired_reserved_holds(&self, _now_unix_secs: i64) -> Result<usize, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant($reason.to_string()))
        }
    };
}

pub(in crate::kernel::tests) use {delegate_budget_store_methods, unsupported_budget_store_methods};
