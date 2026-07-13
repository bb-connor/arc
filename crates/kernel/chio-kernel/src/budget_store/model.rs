pub const MAX_INVOCATION_QUOTAS_PER_ADMISSION: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetQuotaProfile {
    GrantInvocation,
    AggregateCapabilityInvocation,
    AggregateFamilyInvocation,
    SupplementalBrokerCapabilityExecution,
}

impl BudgetQuotaProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GrantInvocation => "chio.grant-invocation.v1",
            Self::AggregateCapabilityInvocation => "chio.aggregate-capability-invocation.v1",
            Self::AggregateFamilyInvocation => "chio.aggregate-family-invocation.v1",
            Self::SupplementalBrokerCapabilityExecution => "chio.broker-capability-execution.v1",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "chio.grant-invocation.v1" => Some(Self::GrantInvocation),
            "chio.aggregate-capability-invocation.v1" => Some(Self::AggregateCapabilityInvocation),
            "chio.aggregate-family-invocation.v1" => Some(Self::AggregateFamilyInvocation),
            "chio.broker-capability-execution.v1" => {
                Some(Self::SupplementalBrokerCapabilityExecution)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BudgetQuotaKey {
    pub profile: BudgetQuotaProfile,
    pub owner_id: String,
    pub grant_index: Option<u32>,
}

impl BudgetQuotaKey {
    pub fn grant(capability_id: impl Into<String>, grant_index: u32) -> Self {
        Self {
            profile: BudgetQuotaProfile::GrantInvocation,
            owner_id: capability_id.into(),
            grant_index: Some(grant_index),
        }
    }

    fn validate(&self) -> Result<(), BudgetStoreError> {
        if self.owner_id.is_empty() {
            return Err(BudgetStoreError::Invariant(
                "budget quota owner_id must not be empty".to_string(),
            ));
        }
        let grant_profile = self.profile == BudgetQuotaProfile::GrantInvocation;
        if grant_profile != self.grant_index.is_some() {
            return Err(BudgetStoreError::Invariant(
                "only grant invocation quota keys may carry grant_index".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetInvocationQuota {
    pub key: BudgetQuotaKey,
    pub max_invocations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAdmissionBinding {
    pub operation_id: String,
    pub revocation_set: CanonicalRevocationSet,
    pub supplemental_verifier_id: Option<String>,
    pub supplemental_verifier_config_digest: Option<String>,
    pub supplemental_authorization_artifact_digest: Option<String>,
    pub supplemental_authorization_expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetInvocationQuotaUsage {
    pub quota: BudgetInvocationQuota,
    pub reserved_invocations: u32,
    pub captured_invocations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetInvocationQuotaMutation {
    pub quota: BudgetInvocationQuota,
    pub reserved_invocations_before: u32,
    pub captured_invocations_before: u32,
    pub reserved_invocations_after: u32,
    pub captured_invocations_after: u32,
}

impl BudgetInvocationQuotaUsage {
    pub fn invocation_count_after(&self) -> Result<u32, BudgetStoreError> {
        self.reserved_invocations
            .checked_add(self.captured_invocations)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "reserved_invocations + captured_invocations overflowed u32".to_string(),
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BudgetCumulativeApprovalAccountKey {
    pub authority_id: String,
    pub owner_id: String,
    pub approval_budget_id: String,
    pub approval_budget_epoch: u64,
    pub root_grant_hash: String,
    pub delegation_root_id: Option<String>,
    pub root_binding_digest: Option<String>,
    pub currency: String,
}

impl BudgetCumulativeApprovalAccountKey {
    fn validate(&self) -> Result<(), BudgetStoreError> {
        if self.authority_id.is_empty()
            || self.owner_id.is_empty()
            || self.approval_budget_id.is_empty()
            || self.root_grant_hash.is_empty()
            || self.currency.is_empty()
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval account key fields must not be empty".to_string(),
            ));
        }
        if self.delegation_root_id.is_some() != self.root_binding_digest.is_some()
            || self
                .delegation_root_id
                .as_ref()
                .is_some_and(String::is_empty)
            || self
                .root_binding_digest
                .as_ref()
                .is_some_and(String::is_empty)
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative family root identity and binding digest must be presented together"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCumulativeApprovalRequest {
    pub operation_id: String,
    pub account_key: BudgetCumulativeApprovalAccountKey,
    pub authority_threshold: MonetaryAmount,
    pub effective_threshold: MonetaryAmount,
    pub requested_authorized: MonetaryAmount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetCumulativeApprovalState {
    PendingApproval,
    Authorized,
    Captured,
    ReversedBeforeDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetInvocationState {
    Absent,
    Authorized,
    Captured,
    Reversed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMonetaryState {
    None,
    Exposed,
    Released,
    Reconciled,
    Captured,
    Reversed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAuthorizationOutcome {
    Authorized,
    ApprovalRequired,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCumulativeApprovalUsage {
    pub operation_id: String,
    pub account_key: BudgetCumulativeApprovalAccountKey,
    pub authority_threshold: MonetaryAmount,
    pub effective_threshold: MonetaryAmount,
    pub requested_authorized: MonetaryAmount,
    pub reserved_authorized_after: MonetaryAmount,
    pub captured_authorized_after: MonetaryAmount,
    pub state: BudgetCumulativeApprovalState,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCumulativeApprovalAccountUsage {
    pub account_key: BudgetCumulativeApprovalAccountKey,
    pub authority_threshold: MonetaryAmount,
    pub reserved_authorized: MonetaryAmount,
    pub captured_authorized: MonetaryAmount,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCumulativeApprovalMutation {
    pub operation_id: String,
    pub account_key: BudgetCumulativeApprovalAccountKey,
    pub state_before: Option<BudgetCumulativeApprovalState>,
    pub state_after: BudgetCumulativeApprovalState,
    pub reserved_authorized_before: MonetaryAmount,
    pub captured_authorized_before: MonetaryAmount,
    pub reserved_authorized_after: MonetaryAmount,
    pub captured_authorized_after: MonetaryAmount,
    pub version_before: u64,
    pub version_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetEventAuthority {
    pub authority_id: String,
    pub lease_id: String,
    pub lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetMutationRecord {
    pub event_id: String,
    pub hold_id: Option<String>,
    pub admission_binding: Option<BudgetAdmissionBinding>,
    pub capability_id: String,
    pub grant_index: u32,
    pub kind: BudgetMutationKind,
    pub allowed: Option<bool>,
    pub authorization_outcome: Option<BudgetAuthorizationOutcome>,
    pub invocation_state_before: BudgetInvocationState,
    pub invocation_state_after: BudgetInvocationState,
    pub monetary_state_before: BudgetMonetaryState,
    pub monetary_state_after: BudgetMonetaryState,
    pub recorded_at: i64,
    pub event_seq: u64,
    pub usage_seq: Option<u64>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub max_invocations: Option<u32>,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub invocation_count_after: u32,
    pub invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub invocation_quota_mutations: Vec<BudgetInvocationQuotaMutation>,
    pub cumulative_approval: Option<BudgetCumulativeApprovalUsage>,
    pub cumulative_approval_mutation: Option<BudgetCumulativeApprovalMutation>,
    pub cumulative_approval_set_digest: Option<String>,
    pub total_cost_exposed_after: u64,
    pub total_cost_realized_spend_after: u64,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetGuaranteeLevel {
    SingleNodeAtomic,
    HaLinearizable,
    PartitionEscrowed,
    AdvisoryPosthoc,
}

impl BudgetGuaranteeLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleNodeAtomic => "single_node_atomic",
            Self::HaLinearizable => "ha_linearizable",
            Self::PartitionEscrowed => "partition_escrowed",
            Self::AdvisoryPosthoc => "advisory_posthoc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAuthorityProfile {
    AuthoritativeHoldEvent,
}

impl BudgetAuthorityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthoritativeHoldEvent => "authoritative_hold_event",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMeteringProfile {
    MaxCostPreauthorizeThenReconcileActual,
}

impl BudgetMeteringProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxCostPreauthorizeThenReconcileActual => {
                "max_cost_preauthorize_then_reconcile_actual"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCommitMetadata {
    pub authority: Option<BudgetEventAuthority>,
    pub guarantee_level: BudgetGuaranteeLevel,
    pub budget_profile: BudgetAuthorityProfile,
    pub metering_profile: BudgetMeteringProfile,
    /// Commit index for the decision, including a durable denial. Legacy backends
    /// that cannot expose a denial event index return `None`.
    pub budget_commit_index: Option<u64>,
    pub event_id: Option<String>,
}

impl BudgetCommitMetadata {
    pub fn budget_term(&self) -> Option<String> {
        self.authority
            .as_ref()
            .map(|authority| format!("{}:{}", authority.authority_id, authority.lease_epoch))
    }
}

fn budget_commit_metadata<T: BudgetStore + ?Sized>(
    store: &T,
    authority: Option<BudgetEventAuthority>,
    budget_commit_index: Option<u64>,
    event_id: Option<String>,
) -> BudgetCommitMetadata {
    BudgetCommitMetadata {
        authority,
        guarantee_level: store.budget_guarantee_level(),
        budget_profile: store.budget_authority_profile(),
        metering_profile: store.budget_metering_profile(),
        budget_commit_index,
        event_id,
    }
}
