use super::*;

/// Parameters of `write_authorization_event_projection`.
pub(super) struct AuthorizationEventProjection<'a> {
    pub(super) event_id: &'a str,
    pub(super) admission: &'a BudgetAdmissionBinding,
    pub(super) outcome: BudgetAuthorizationOutcome,
    pub(super) quotas: &'a [BudgetInvocationQuota],
    pub(super) quota_before: &'a [QuotaState],
    pub(super) quota_after: &'a [QuotaState],
    pub(super) cumulative: Option<&'a BudgetCumulativeApprovalRequest>,
    pub(super) cumulative_state: Option<BudgetCumulativeApprovalState>,
    pub(super) cumulative_before: Option<&'a CumulativeAccount>,
    pub(super) cumulative_after: Option<&'a CumulativeAccount>,
    pub(super) invocation_quotas_explicit: bool,
    pub(super) requested_exposure_units: u64,
}

/// Parameters of `authorization_decision`.
pub(super) struct AuthorizationDecisionInput {
    pub(super) request: BudgetAuthorizeHoldRequest,
    pub(super) outcome: BudgetAuthorizationOutcome,
    pub(super) event_seq: u64,
    pub(super) recorded_at: i64,
    pub(super) usage: BudgetUsageRecord,
    pub(super) quotas: Vec<QuotaState>,
    pub(super) cumulative_state: Option<BudgetCumulativeApprovalState>,
    pub(super) cumulative_account: Option<CumulativeAccount>,
}
