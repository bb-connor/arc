use chio_core::capability::aggregate_budget::{
    AggregateInvocationScope, VerifiedAggregateInvocationAuthority,
};
use serde::{Deserialize, Serialize};

use crate::supplemental_quota::{CanonicalRevocationSet, VerifiedSupplementalQuota};
use chio_log_redact::redacted;

#[derive(Debug, thiserror::Error)]
pub enum BudgetStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare budget store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("budget arithmetic overflow: {0}")]
    Overflow(String),

    #[error("budget state conflict: {0}")]
    Conflict(String),

    #[error("budget state invariant violated: {0}")]
    Invariant(String),
}

pub const MAX_INVOCATION_QUOTAS_PER_ADMISSION: usize = 8;
const MAX_BUDGET_QUOTA_OWNER_ID_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BudgetQuotaProfile {
    GrantInvocation,
    AggregateCapabilityInvocation,
    AggregateFamilyInvocation,
    SupplementalBrokerExecution,
}

impl BudgetQuotaProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GrantInvocation => "chio.grant-invocation.v1",
            Self::AggregateCapabilityInvocation => "chio.aggregate-capability-invocation.v1",
            Self::AggregateFamilyInvocation => "chio.aggregate-family-invocation.v1",
            Self::SupplementalBrokerExecution => "chio.broker-capability-execution.v1",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "chio.grant-invocation.v1" => Some(Self::GrantInvocation),
            "chio.aggregate-capability-invocation.v1" => Some(Self::AggregateCapabilityInvocation),
            "chio.aggregate-family-invocation.v1" => Some(Self::AggregateFamilyInvocation),
            "chio.broker-capability-execution.v1" => Some(Self::SupplementalBrokerExecution),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Read-only quota-key descriptor. Admission keys are derived inside the kernel.
///
/// ```compile_fail
/// use chio_kernel::budget_store::{BudgetQuotaKey, BudgetQuotaProfile};
/// let _ = BudgetQuotaKey {
///     profile: BudgetQuotaProfile::SupplementalBrokerExecution,
///     owner_id: "00".repeat(32),
///     grant_index: None,
/// };
/// ```
pub struct BudgetQuotaKey {
    profile: BudgetQuotaProfile,
    owner_id: String,
    grant_index: Option<u32>,
}

impl BudgetQuotaKey {
    pub fn grant(
        capability_id: impl Into<String>,
        grant_index: usize,
    ) -> Result<Self, BudgetStoreError> {
        let grant_index = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let key = Self {
            profile: BudgetQuotaProfile::GrantInvocation,
            owner_id: capability_id.into(),
            grant_index: Some(grant_index),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        if self.owner_id.is_empty()
            || self.owner_id.len() > MAX_BUDGET_QUOTA_OWNER_ID_BYTES
            || self.owner_id.bytes().any(|byte| byte == 0)
        {
            return Err(BudgetStoreError::Invariant(
                "budget quota owner_id is empty, oversized, or contains NUL".to_string(),
            ));
        }
        if matches!(
            self.profile,
            BudgetQuotaProfile::AggregateFamilyInvocation
                | BudgetQuotaProfile::SupplementalBrokerExecution
        ) && (self.owner_id.len() != 64
            || !self
                .owner_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
        {
            return Err(BudgetStoreError::Invariant(
                "derived invocation quota owner_id must be lowercase SHA-256 hex".to_string(),
            ));
        }
        match (self.profile, self.grant_index) {
            (BudgetQuotaProfile::GrantInvocation, Some(_))
            | (
                BudgetQuotaProfile::AggregateCapabilityInvocation
                | BudgetQuotaProfile::AggregateFamilyInvocation
                | BudgetQuotaProfile::SupplementalBrokerExecution,
                None,
            ) => Ok(()),
            (BudgetQuotaProfile::GrantInvocation, None) => Err(BudgetStoreError::Invariant(
                "grant invocation quota requires grant_index".to_string(),
            )),
            (_, Some(_)) => Err(BudgetStoreError::Invariant(
                "non-grant invocation quota must not carry grant_index".to_string(),
            )),
        }
    }

    pub(crate) fn from_verified_parts(
        profile: BudgetQuotaProfile,
        owner_id: String,
        grant_index: Option<u32>,
    ) -> Result<Self, BudgetStoreError> {
        let key = Self {
            profile,
            owner_id,
            grant_index,
        };
        key.validate()?;
        Ok(key)
    }

    /// Reconstruct a read-only descriptor from durable store columns.
    ///
    /// This validates the same structural invariants as kernel derivation. The
    /// descriptor is not admission authority: callers still cannot install it
    /// into [`BudgetAuthorizeHoldRequest`].
    pub fn from_persisted_parts(
        profile: BudgetQuotaProfile,
        owner_id: String,
        grant_index: Option<u32>,
    ) -> Result<Self, BudgetStoreError> {
        Self::from_verified_parts(profile, owner_id, grant_index)
    }

    pub fn profile(&self) -> BudgetQuotaProfile {
        self.profile
    }

    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    pub fn grant_index(&self) -> Option<u32> {
        self.grant_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Read-only quota descriptor. A descriptor alone is not admission authority.
///
/// ```compile_fail
/// use chio_kernel::budget_store::{BudgetInvocationQuota, BudgetQuotaKey};
/// let key = BudgetQuotaKey::grant("capability", 0)?;
/// let _ = BudgetInvocationQuota { key, max_invocations: 1 };
/// # Ok::<(), chio_kernel::BudgetStoreError>(())
/// ```
pub struct BudgetInvocationQuota {
    key: BudgetQuotaKey,
    max_invocations: u32,
}

impl BudgetInvocationQuota {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        self.key.validate()
    }

    pub fn key(&self) -> &BudgetQuotaKey {
        &self.key
    }

    pub fn max_invocations(&self) -> u32 {
        self.max_invocations
    }

    pub(crate) fn from_verified_parts(
        key: BudgetQuotaKey,
        max_invocations: u32,
    ) -> Result<Self, BudgetStoreError> {
        let quota = Self {
            key,
            max_invocations,
        };
        quota.validate()?;
        Ok(quota)
    }

    /// Reconstruct a read-only quota descriptor from validated durable state.
    pub fn from_persisted_parts(
        key: BudgetQuotaKey,
        max_invocations: u32,
    ) -> Result<Self, BudgetStoreError> {
        Self::from_verified_parts(key, max_invocations)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupplementalQuotaBinding {
    artifact_digest: String,
    verifier_id: String,
    request_binding_hash: String,
    negotiated_features_digest: String,
}

/// Read-only projection of invocation admission evidence derived by the kernel.
///
/// The projection exposes durable descriptors and binding evidence without
/// exposing a constructor or the private authority installation path.
#[derive(Debug, Clone, Copy)]
pub struct BudgetInvocationAdmissionEvidence<'a> {
    admission: &'a VerifiedInvocationAdmission,
}

impl<'a> BudgetInvocationAdmissionEvidence<'a> {
    pub fn quotas(self) -> &'a [BudgetInvocationQuota] {
        &self.admission.quotas
    }

    pub fn revocation_set(self) -> &'a CanonicalRevocationSet {
        &self.admission.revocation_set
    }

    pub fn aggregate_binding_digest(self) -> Option<&'a str> {
        self.admission.aggregate_binding_digest.as_deref()
    }

    pub fn aggregate_root_capability_id(self) -> Option<&'a str> {
        self.admission.aggregate_root_capability_id.as_deref()
    }

    pub fn supplemental_artifact_digest(self) -> Option<&'a str> {
        self.admission
            .supplemental_binding
            .as_ref()
            .map(|binding| binding.artifact_digest.as_str())
    }

    pub fn supplemental_verifier_id(self) -> Option<&'a str> {
        self.admission
            .supplemental_binding
            .as_ref()
            .map(|binding| binding.verifier_id.as_str())
    }

    pub fn supplemental_request_binding_hash(self) -> Option<&'a str> {
        self.admission
            .supplemental_binding
            .as_ref()
            .map(|binding| binding.request_binding_hash.as_str())
    }

    pub fn supplemental_negotiated_features_digest(self) -> Option<&'a str> {
        self.admission
            .supplemental_binding
            .as_ref()
            .map(|binding| binding.negotiated_features_digest.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedInvocationAdmission {
    quotas: Vec<BudgetInvocationQuota>,
    revocation_set: CanonicalRevocationSet,
    aggregate_root_capability_id: Option<String>,
    aggregate_binding_digest: Option<String>,
    supplemental_binding: Option<SupplementalQuotaBinding>,
}

impl VerifiedInvocationAdmission {
    pub(crate) fn grant_only(
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<Self, BudgetStoreError> {
        derive_verified_invocation_admission(
            capability_id,
            grant_index,
            max_invocations,
            None,
            None,
            &[],
        )
    }

    fn quotas(&self) -> &[BudgetInvocationQuota] {
        &self.quotas
    }

    fn revocation_set(&self) -> &CanonicalRevocationSet {
        &self.revocation_set
    }
}

pub(crate) fn derive_verified_invocation_admission(
    capability_id: &str,
    grant_index: usize,
    grant_max_invocations: Option<u32>,
    aggregate: Option<&VerifiedAggregateInvocationAuthority>,
    supplemental: Option<&VerifiedSupplementalQuota>,
    verified_ancestor_ids: &[String],
) -> Result<VerifiedInvocationAdmission, BudgetStoreError> {
    let mut quotas = vec![BudgetInvocationQuota {
        key: BudgetQuotaKey::grant(capability_id, grant_index)?,
        max_invocations: grant_max_invocations.unwrap_or(u32::MAX),
    }];
    let aggregate_root_capability_id = aggregate
        .and_then(VerifiedAggregateInvocationAuthority::family_root)
        .map(|root| root.root_capability_id().to_string());
    let aggregate_binding_digest = aggregate
        .and_then(VerifiedAggregateInvocationAuthority::root_binding_digest)
        .map(ToOwned::to_owned);
    if let Some(aggregate) = aggregate {
        let profile = match aggregate.scope() {
            AggregateInvocationScope::Capability => {
                BudgetQuotaProfile::AggregateCapabilityInvocation
            }
            AggregateInvocationScope::DelegationFamily => {
                BudgetQuotaProfile::AggregateFamilyInvocation
            }
        };
        quotas.push(BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile,
                owner_id: aggregate.owner().to_string(),
                grant_index: None,
            },
            max_invocations: aggregate.max_invocations(),
        });
    }
    let (supplemental_ids, supplemental_binding) = if let Some(supplemental) = supplemental {
        quotas.push(supplemental.quota().clone());
        (
            supplemental.supplemental_revocation_ids(),
            Some(SupplementalQuotaBinding {
                artifact_digest: supplemental.artifact_digest().to_string(),
                verifier_id: supplemental.verifier_id().to_string(),
                request_binding_hash: supplemental.request_binding_hash().to_string(),
                negotiated_features_digest: supplemental.negotiated_features_digest().to_string(),
            }),
        )
    } else {
        (&[][..], None)
    };
    quotas.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    validate_invocation_quotas(&quotas)?;
    validate_aggregate_family_receipt_evidence(
        &quotas,
        aggregate_root_capability_id.as_deref(),
        aggregate_binding_digest.as_deref(),
    )?;
    let revocation_set =
        CanonicalRevocationSet::new(capability_id, verified_ancestor_ids, supplemental_ids)
            .map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "failed to build canonical revocation set: {error}"
                ))
            })?;
    validate_aggregate_root_revocation_binding(
        aggregate_root_capability_id.as_deref(),
        &revocation_set,
    )?;
    Ok(VerifiedInvocationAdmission {
        quotas,
        revocation_set,
        aggregate_root_capability_id,
        aggregate_binding_digest,
        supplemental_binding,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetInvocationQuotaUsage {
    pub quota: BudgetInvocationQuota,
    pub reserved_invocations_after: u32,
    pub captured_invocations_after: u32,
}

impl BudgetInvocationQuotaUsage {
    pub fn invocation_count_after(&self) -> Result<u32, BudgetStoreError> {
        self.reserved_invocations_after
            .checked_add(self.captured_invocations_after)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "reserved invocations + captured invocations overflowed u32".to_string(),
                )
            })
    }

    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        self.quota.validate()?;
        let invocation_count = self.invocation_count_after()?;
        if invocation_count > self.quota.max_invocations() {
            return Err(BudgetStoreError::Invariant(
                "invocation quota usage exceeds its immutable maximum".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetInvocationReservationState {
    Absent,
    Authorized,
    Captured,
    Reversed,
    Denied,
}

impl BudgetInvocationReservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Authorized => "authorized",
            Self::Captured => "captured",
            Self::Reversed => "reversed",
            Self::Denied => "denied",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "absent" => Some(Self::Absent),
            "authorized" => Some(Self::Authorized),
            "captured" => Some(Self::Captured),
            "reversed" => Some(Self::Reversed),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMonetaryHoldState {
    None,
    Exposed,
    Released,
    Reconciled,
    Captured,
    Reversed,
}

impl BudgetMonetaryHoldState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Exposed => "exposed",
            Self::Released => "released",
            Self::Reconciled => "reconciled",
            Self::Captured => "captured",
            Self::Reversed => "reversed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "exposed" => Some(Self::Exposed),
            "released" => Some(Self::Released),
            "reconciled" => Some(Self::Reconciled),
            "captured" => Some(Self::Captured),
            "reversed" => Some(Self::Reversed),
            _ => None,
        }
    }
}

pub(crate) fn validate_invocation_quotas(
    quotas: &[BudgetInvocationQuota],
) -> Result<(), BudgetStoreError> {
    if quotas.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(format!(
            "budget authorization exceeds {MAX_INVOCATION_QUOTAS_PER_ADMISSION} invocation quotas"
        )));
    }
    let mut previous: Option<&BudgetQuotaKey> = None;
    for quota in quotas {
        quota.validate()?;
        if previous.is_some_and(|key| key >= &quota.key) {
            return Err(BudgetStoreError::Invariant(
                "budget invocation quotas must be strictly sorted without duplicate keys"
                    .to_string(),
            ));
        }
        previous = Some(&quota.key);
    }
    Ok(())
}

fn validate_aggregate_family_receipt_evidence(
    quotas: &[BudgetInvocationQuota],
    root_capability_id: Option<&str>,
    root_binding_digest: Option<&str>,
) -> Result<(), BudgetStoreError> {
    let has_family_quota = quotas
        .iter()
        .any(|quota| quota.key().profile() == BudgetQuotaProfile::AggregateFamilyInvocation);
    match (has_family_quota, root_capability_id, root_binding_digest) {
        (true, Some(root_capability_id), Some(root_binding_digest)) => {
            if root_capability_id.is_empty()
                || root_capability_id.len() > MAX_BUDGET_QUOTA_OWNER_ID_BYTES
                || root_capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(BudgetStoreError::Invariant(
                    "aggregate family receipt root capability ID is empty, oversized, or contains NUL"
                        .to_string(),
                ));
            }
            if root_binding_digest.len() != 64
                || !root_binding_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(BudgetStoreError::Invariant(
                    "aggregate family receipt root binding digest must be lowercase SHA-256 hex"
                        .to_string(),
                ));
            }
            Ok(())
        }
        (true, _, _) => Err(BudgetStoreError::Invariant(
            "aggregate family quota requires root capability ID and binding digest receipt evidence"
                .to_string(),
        )),
        (false, None, None) => Ok(()),
        (false, _, _) => Err(BudgetStoreError::Invariant(
            "aggregate family receipt evidence requires an aggregate family quota".to_string(),
        )),
    }
}

fn validate_aggregate_root_revocation_binding(
    root_capability_id: Option<&str>,
    revocation_set: &CanonicalRevocationSet,
) -> Result<(), BudgetStoreError> {
    if root_capability_id.is_some_and(|root_id| {
        revocation_set
            .ids()
            .binary_search_by(|candidate| candidate.as_bytes().cmp(root_id.as_bytes()))
            .is_err()
    }) {
        return Err(BudgetStoreError::Invariant(
            "canonical revocation set omits the authenticated aggregate root capability"
                .to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
    pub total_cost_exposed: u64,
    pub total_cost_realized_spend: u64,
}

impl BudgetUsageRecord {
    pub fn committed_cost_units(&self) -> Result<u64, BudgetStoreError> {
        checked_committed_cost_units(self.total_cost_exposed, self.total_cost_realized_spend)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMutationKind {
    IncrementInvocation,
    ReserveInvocations,
    CaptureInvocations,
    ReverseInvocations,
    AuthorizeExposure,
    CaptureExposure,
    ReverseExposure,
    ReleaseExposure,
    ReconcileSpend,
    ExpireHold,
}

impl BudgetMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncrementInvocation => "increment_invocation",
            Self::ReserveInvocations => "reserve_invocations",
            Self::CaptureInvocations => "capture_invocations",
            Self::ReverseInvocations => "reverse_invocations",
            Self::AuthorizeExposure => "authorize_exposure",
            Self::CaptureExposure => "capture_exposure",
            Self::ReverseExposure => "reverse_exposure",
            Self::ReleaseExposure => "release_exposure",
            Self::ReconcileSpend => "reconcile_spend",
            Self::ExpireHold => "expire_hold",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "increment_invocation" => Some(Self::IncrementInvocation),
            "reserve_invocations" => Some(Self::ReserveInvocations),
            "capture_invocations" => Some(Self::CaptureInvocations),
            "reverse_invocations" => Some(Self::ReverseInvocations),
            "authorize_exposure" => Some(Self::AuthorizeExposure),
            "capture_exposure" => Some(Self::CaptureExposure),
            "reverse_exposure" => Some(Self::ReverseExposure),
            "release_exposure" => Some(Self::ReleaseExposure),
            "reconcile_spend" => Some(Self::ReconcileSpend),
            "expire_hold" => Some(Self::ExpireHold),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEventAuthority {
    pub authority_id: String,
    pub lease_id: String,
    pub lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetAdmissionOperationBinding {
    operation_id: String,
    request_binding_hash: String,
}

impl<'de> Deserialize<'de> for BudgetAdmissionOperationBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct PersistedBinding {
            operation_id: String,
            request_binding_hash: String,
        }

        let persisted = PersistedBinding::deserialize(deserializer)?;
        Self::new(persisted.operation_id, persisted.request_binding_hash)
            .map_err(serde::de::Error::custom)
    }
}

impl BudgetAdmissionOperationBinding {
    pub fn new(
        operation_id: String,
        request_binding_hash: String,
    ) -> Result<Self, BudgetStoreError> {
        if operation_id.is_empty()
            || operation_id.len() > 512
            || operation_id.bytes().any(|byte| byte == 0)
        {
            return Err(BudgetStoreError::Invariant(
                "budget admission operation_id is empty, oversized, or contains NUL".to_string(),
            ));
        }
        if request_binding_hash.len() != 64
            || !request_binding_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(BudgetStoreError::Invariant(
                "budget admission request_binding_hash must be lowercase SHA-256 hex".to_string(),
            ));
        }
        Ok(Self {
            operation_id,
            request_binding_hash,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn request_binding_hash(&self) -> &str {
        &self.request_binding_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetMutationRecord {
    pub event_id: String,
    pub hold_id: Option<String>,
    pub admission_operation: Option<BudgetAdmissionOperationBinding>,
    pub capability_id: String,
    pub grant_index: u32,
    pub kind: BudgetMutationKind,
    pub allowed: Option<bool>,
    pub recorded_at: i64,
    pub event_seq: u64,
    pub usage_seq: Option<u64>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub max_invocations: Option<u32>,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub invocation_count_after: u32,
    pub invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    pub invocation_state: BudgetInvocationReservationState,
    pub monetary_state: BudgetMonetaryHoldState,
    pub revocation_set: Option<CanonicalRevocationSet>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStoreProfile {
    EphemeralLocal,
    SingleNodeDurable,
    SharedLinearizable,
}

impl BudgetStoreProfile {
    #[must_use]
    pub fn supports_dispatch_workers(self, dispatch_worker_count: usize) -> bool {
        match self {
            Self::EphemeralLocal => false,
            Self::SingleNodeDurable => dispatch_worker_count == 1,
            Self::SharedLinearizable => dispatch_worker_count > 0,
        }
    }
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

    /// Returns whether this guarantee and store topology can enforce one hard
    /// invocation ceiling. Partition escrow stays disabled until commit
    /// metadata carries signed allocation evidence whose sum is bounded by the
    /// capability maximum.
    #[must_use]
    pub fn supports_hard_invocation_limit(
        self,
        store_profile: BudgetStoreProfile,
        dispatch_worker_count: usize,
    ) -> bool {
        match self {
            Self::SingleNodeAtomic => {
                store_profile == BudgetStoreProfile::SingleNodeDurable && dispatch_worker_count == 1
            }
            Self::HaLinearizable => {
                store_profile == BudgetStoreProfile::SharedLinearizable && dispatch_worker_count > 0
            }
            Self::PartitionEscrowed | Self::AdvisoryPosthoc => false,
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

/// Assemble the commit metadata a hold decision carries, stamped with the
/// store's guarantee and metering profiles. Public so store implementations
/// that override the defaulted hold methods can produce identical metadata.
pub fn budget_commit_metadata<T: BudgetStore + ?Sized>(
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Budget authorization input. Composite authority can only be installed by the kernel.
///
/// ```compile_fail
/// use chio_kernel::budget_store::BudgetAuthorizeHoldRequest;
/// let _ = BudgetAuthorizeHoldRequest {
///     capability_id: "capability".to_string(),
///     grant_index: 0,
///     max_invocations: None,
///     requested_exposure_units: 0,
///     max_cost_per_invocation: None,
///     max_total_cost_units: None,
///     hold_id: None,
///     event_id: None,
///     authority: None,
///     admission_operation: None,
///     invocation_admission: None,
///     payment_journal: None,
/// };
/// ```
pub struct BudgetAuthorizeHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub max_invocations: Option<u32>,
    pub requested_exposure_units: u64,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
    pub admission_operation: Option<BudgetAdmissionOperationBinding>,
    invocation_admission: Option<VerifiedInvocationAdmission>,
    /// Optional payment-journal row committed in the SAME transaction as
    /// the hold write, so the money path's recoverable record is durable
    /// before the rail is touched. `None` for non-monetary calls and for
    /// stores without the journal.
    pub payment_journal: Option<crate::payment::PaymentJournalRecord>,
}

/// Read model of an open budget hold, for the orphaned-hold sweeper and the
/// operator CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenHoldSummary {
    pub hold_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    pub remaining_exposure_units: u64,
    pub created_at_unix_ms: u64,
}

/// Durable, operation-bound input for authorize-then-reverse recovery.
///
/// Recovery deliberately persists the complete verified quota projection, not
/// merely a hold identifier. If an authority commits authorization and the
/// caller loses that acknowledgement, a recovery worker can replay the exact
/// authorization, obtain the original authority assignment, and then issue the
/// exact idempotent reverse without reconstructing data from a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetAuthorizationCleanupSnapshot {
    capability_id: String,
    grant_index: u32,
    max_invocations: Option<u32>,
    requested_exposure_units: u64,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
    hold_id: String,
    authorize_event_id: String,
    reverse_event_id: String,
    capture_event_id: String,
    requested_authority: Option<BudgetEventAuthority>,
    operation_id: String,
    request_binding_hash: String,
    invocation_quotas: Vec<BudgetCleanupQuota>,
    revocation_ids: Vec<String>,
    revocation_digest: String,
    aggregate_root_capability_id: Option<String>,
    aggregate_binding_digest: Option<String>,
    supplemental_binding: Option<BudgetCleanupSupplementalBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetCleanupQuota {
    profile: String,
    owner_id: String,
    grant_index: Option<u32>,
    max_invocations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetCleanupSupplementalBinding {
    artifact_digest: String,
    verifier_id: String,
    request_binding_hash: String,
    negotiated_features_digest: String,
}

impl BudgetAuthorizationCleanupSnapshot {
    pub fn authorization_request(&self) -> Result<BudgetAuthorizeHoldRequest, BudgetStoreError> {
        let grant_index = usize::try_from(self.grant_index).map_err(|_| {
            BudgetStoreError::Invariant(
                "cleanup budget grant index cannot be represented as usize".to_string(),
            )
        })?;
        let mut quotas = Vec::with_capacity(self.invocation_quotas.len());
        for quota in &self.invocation_quotas {
            let profile = BudgetQuotaProfile::parse(&quota.profile).ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "cleanup budget quota has unknown profile `{}`",
                    quota.profile
                ))
            })?;
            let key = BudgetQuotaKey::from_persisted_parts(
                profile,
                quota.owner_id.clone(),
                quota.grant_index,
            )?;
            quotas.push(BudgetInvocationQuota::from_persisted_parts(
                key,
                quota.max_invocations,
            )?);
        }
        validate_invocation_quotas(&quotas)?;
        validate_aggregate_family_receipt_evidence(
            &quotas,
            self.aggregate_root_capability_id.as_deref(),
            self.aggregate_binding_digest.as_deref(),
        )?;
        let revocation_set = CanonicalRevocationSet::from_persisted_parts(
            self.revocation_ids.clone(),
            self.revocation_digest.clone(),
        )
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "cleanup budget revocation set is invalid: {error}"
            ))
        })?;
        validate_aggregate_root_revocation_binding(
            self.aggregate_root_capability_id.as_deref(),
            &revocation_set,
        )?;
        let supplemental_binding =
            self.supplemental_binding
                .as_ref()
                .map(|binding| SupplementalQuotaBinding {
                    artifact_digest: binding.artifact_digest.clone(),
                    verifier_id: binding.verifier_id.clone(),
                    request_binding_hash: binding.request_binding_hash.clone(),
                    negotiated_features_digest: binding.negotiated_features_digest.clone(),
                });
        let admission_operation = BudgetAdmissionOperationBinding::new(
            self.operation_id.clone(),
            self.request_binding_hash.clone(),
        )?;
        Ok(BudgetAuthorizeHoldRequest {
            capability_id: self.capability_id.clone(),
            grant_index,
            max_invocations: self.max_invocations,
            requested_exposure_units: self.requested_exposure_units,
            max_cost_per_invocation: self.max_cost_per_invocation,
            max_total_cost_units: self.max_total_cost_units,
            hold_id: Some(self.hold_id.clone()),
            event_id: Some(self.authorize_event_id.clone()),
            authority: self.requested_authority.clone(),
            admission_operation: Some(admission_operation),
            invocation_admission: Some(VerifiedInvocationAdmission {
                quotas,
                revocation_set,
                aggregate_root_capability_id: self.aggregate_root_capability_id.clone(),
                aggregate_binding_digest: self.aggregate_binding_digest.clone(),
                supplemental_binding,
            }),
            payment_journal: None,
        })
    }

    pub fn reverse_request(
        &self,
        authority: Option<BudgetEventAuthority>,
    ) -> Result<BudgetReverseHoldRequest, BudgetStoreError> {
        Ok(BudgetReverseHoldRequest {
            capability_id: self.capability_id.clone(),
            grant_index: usize::try_from(self.grant_index).map_err(|_| {
                BudgetStoreError::Invariant(
                    "cleanup budget grant index cannot be represented as usize".to_string(),
                )
            })?,
            reversed_exposure_units: self.requested_exposure_units,
            hold_id: Some(self.hold_id.clone()),
            event_id: Some(self.reverse_event_id.clone()),
            authority,
            admission_operation: Some(BudgetAdmissionOperationBinding::new(
                self.operation_id.clone(),
                self.request_binding_hash.clone(),
            )?),
        })
    }

    pub fn capture_request(
        &self,
        authority: Option<BudgetEventAuthority>,
    ) -> Result<BudgetCaptureInvocationRequest, BudgetStoreError> {
        Ok(BudgetCaptureInvocationRequest {
            capability_id: self.capability_id.clone(),
            grant_index: usize::try_from(self.grant_index).map_err(|_| {
                BudgetStoreError::Invariant(
                    "cleanup budget grant index cannot be represented as usize".to_string(),
                )
            })?,
            hold_id: Some(self.hold_id.clone()),
            event_id: Some(self.capture_event_id.clone()),
            authority,
            admission_operation: Some(BudgetAdmissionOperationBinding::new(
                self.operation_id.clone(),
                self.request_binding_hash.clone(),
            )?),
        })
    }

    pub fn revocation_set(&self) -> Result<CanonicalRevocationSet, BudgetStoreError> {
        CanonicalRevocationSet::from_persisted_parts(
            self.revocation_ids.clone(),
            self.revocation_digest.clone(),
        )
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "cleanup budget revocation set is invalid: {error}"
            ))
        })
    }

    pub fn requires_combined_capture(&self) -> bool {
        self.supplemental_binding.is_some()
    }

    pub fn authorization_artifact_digests(&self) -> Vec<String> {
        self.supplemental_binding
            .iter()
            .map(|binding| binding.artifact_digest.clone())
            .collect()
    }

    pub fn aggregate_root_capability_id(&self) -> Option<&str> {
        self.aggregate_root_capability_id.as_deref()
    }

    pub fn aggregate_root_binding_digest(&self) -> Option<&str> {
        self.aggregate_binding_digest.as_deref()
    }

    pub fn requested_authority(&self) -> Option<&BudgetEventAuthority> {
        self.requested_authority.as_ref()
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn hold_id(&self) -> &str {
        &self.hold_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn request_binding_hash(&self) -> &str {
        &self.request_binding_hash
    }

    pub fn capture_event_id(&self) -> &str {
        &self.capture_event_id
    }
}

impl BudgetAuthorizeHoldRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn legacy(
        capability_id: String,
        grant_index: usize,
        max_invocations: Option<u32>,
        requested_exposure_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<String>,
        event_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
    ) -> Self {
        Self {
            capability_id,
            grant_index,
            max_invocations,
            requested_exposure_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
            admission_operation: None,
            invocation_admission: None,
            payment_journal: None,
        }
    }

    pub fn invocation_quotas(&self) -> &[BudgetInvocationQuota] {
        self.invocation_admission
            .as_ref()
            .map_or(&[], VerifiedInvocationAdmission::quotas)
    }

    pub fn revocation_set(&self) -> Option<&CanonicalRevocationSet> {
        self.invocation_admission
            .as_ref()
            .map(VerifiedInvocationAdmission::revocation_set)
    }

    pub fn invocation_admission_evidence(&self) -> Option<BudgetInvocationAdmissionEvidence<'_>> {
        self.invocation_admission
            .as_ref()
            .map(|admission| BudgetInvocationAdmissionEvidence { admission })
    }

    pub(crate) fn install_verified_invocation_admission(
        &mut self,
        admission: VerifiedInvocationAdmission,
    ) -> Result<(), BudgetStoreError> {
        if self.invocation_admission.is_some() {
            return Err(BudgetStoreError::Invariant(
                "verified invocation admission is already installed".to_string(),
            ));
        }
        self.invocation_admission = Some(admission);
        Ok(())
    }

    pub(crate) fn cleanup_snapshot(
        &self,
        reverse_event_id: String,
        capture_event_id: String,
    ) -> Result<BudgetAuthorizationCleanupSnapshot, BudgetStoreError> {
        let hold_id = self.hold_id.clone().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "operation-owned cleanup requires a budget hold_id".to_string(),
            )
        })?;
        let authorize_event_id = self.event_id.clone().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "operation-owned cleanup requires an authorize event_id".to_string(),
            )
        })?;
        let operation = self.admission_operation.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "operation-owned cleanup requires an admission operation binding".to_string(),
            )
        })?;
        let admission = self.invocation_admission.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "operation-owned cleanup requires verified invocation admission".to_string(),
            )
        })?;
        let grant_index = u32::try_from(self.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let invocation_quotas = admission
            .quotas
            .iter()
            .map(|quota| BudgetCleanupQuota {
                profile: quota.key().profile().as_str().to_string(),
                owner_id: quota.key().owner_id().to_string(),
                grant_index: quota.key().grant_index(),
                max_invocations: quota.max_invocations(),
            })
            .collect();
        let supplemental_binding = admission.supplemental_binding.as_ref().map(|binding| {
            BudgetCleanupSupplementalBinding {
                artifact_digest: binding.artifact_digest.clone(),
                verifier_id: binding.verifier_id.clone(),
                request_binding_hash: binding.request_binding_hash.clone(),
                negotiated_features_digest: binding.negotiated_features_digest.clone(),
            }
        });
        Ok(BudgetAuthorizationCleanupSnapshot {
            capability_id: self.capability_id.clone(),
            grant_index,
            max_invocations: self.max_invocations,
            requested_exposure_units: self.requested_exposure_units,
            max_cost_per_invocation: self.max_cost_per_invocation,
            max_total_cost_units: self.max_total_cost_units,
            hold_id,
            authorize_event_id,
            reverse_event_id,
            capture_event_id,
            requested_authority: self.authority.clone(),
            operation_id: operation.operation_id().to_string(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            invocation_quotas,
            revocation_ids: admission.revocation_set.ids().to_vec(),
            revocation_digest: admission.revocation_set.digest().to_string(),
            aggregate_root_capability_id: admission.aggregate_root_capability_id.clone(),
            aggregate_binding_digest: admission.aggregate_binding_digest.clone(),
            supplemental_binding,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReleaseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub released_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
    pub admission_operation: Option<BudgetAdmissionOperationBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReverseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub reversed_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
    pub admission_operation: Option<BudgetAdmissionOperationBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReconcileHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub exposed_cost_units: u64,
    pub realized_spend_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
    pub admission_operation: Option<BudgetAdmissionOperationBinding>,
}

pub type BudgetCaptureHoldRequest = BudgetReconcileHoldRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCaptureInvocationRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
    pub admission_operation: Option<BudgetAdmissionOperationBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBudgetHold {
    pub hold_id: Option<String>,
    pub authorized_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    pub invocation_state: BudgetInvocationReservationState,
    pub monetary_state: BudgetMonetaryHoldState,
    pub revocation_set: Option<CanonicalRevocationSet>,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedBudgetHold {
    pub hold_id: Option<String>,
    pub attempted_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    pub invocation_state: BudgetInvocationReservationState,
    pub monetary_state: BudgetMonetaryHoldState,
    pub revocation_set: Option<CanonicalRevocationSet>,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetAuthorizeHoldDecision {
    Authorized(AuthorizedBudgetHold),
    Denied(DeniedBudgetHold),
}

impl BudgetAuthorizeHoldDecision {
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldMutationDecision {
    pub hold_id: Option<String>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    pub invocation_state: BudgetInvocationReservationState,
    pub monetary_state: BudgetMonetaryHoldState,
    pub revocation_set: Option<CanonicalRevocationSet>,
    pub metadata: BudgetCommitMetadata,
}

pub type BudgetReleaseHoldDecision = BudgetHoldMutationDecision;
pub type BudgetReverseHoldDecision = BudgetHoldMutationDecision;
pub type BudgetReconcileHoldDecision = BudgetHoldMutationDecision;
pub type BudgetCaptureHoldDecision = BudgetHoldMutationDecision;

/// Terminal state of an authorization hold, projected for callers that need to
/// inspect a hold by id without depending on a store's private disposition type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetHoldDispositionView {
    Open,
    Released,
    Reversed,
    Reconciled,
    Captured,
    Expired,
}

impl BudgetHoldDispositionView {
    #[must_use]
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Released => "released",
            Self::Reversed => "reversed",
            Self::Reconciled => "reconciled",
            Self::Captured => "captured",
            Self::Expired => "expired",
        }
    }
}

/// Grant-level financial envelope recorded on a reserved hold at reserve time so
/// reconcile-by-nonce can stamp the originating grant's total/remaining budget and
/// delegation lineage onto the authoritative receipt, rather than the
/// reservation's own exposure and a lost lineage. Persisted alongside
/// `reserved_until` by the reserve-for-caller path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReservedHoldEnvelope {
    /// Grant ceiling (`max_total_cost`) in currency minor units. `None` for a
    /// zero-exposure invocation reserve, which carries no monetary ceiling.
    pub budget_total: Option<u64>,
    /// Delegation depth of the reserving capability's chain.
    pub delegation_depth: u32,
    /// Root budget holder of the reserving capability's delegation chain.
    pub root_budget_holder: String,
}

/// Read-only projection of a single authorization hold, used by the
/// reconcile-by-nonce entry point to look up the exact reserved hold a signed
/// execution nonce names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldSnapshot {
    pub hold_id: String,
    pub capability_id: String,
    pub grant_index: usize,
    pub authorized_exposure_units: u64,
    pub remaining_exposure_units: u64,
    pub disposition: BudgetHoldDispositionView,
    /// Wall-clock unix seconds after which an unreconciled reserved hold is
    /// eligible for the TTL reaper. `None` for holds that were never marked
    /// reserved (they are reclaimed by the crash reaper, not the TTL reaper).
    pub reserved_until: Option<i64>,
    /// Currency the grant was authorized in, recorded when the reserve-for-caller
    /// path stamps the hold. `None` for holds that were never marked reserved.
    /// Reconcile-by-nonce validates the caller-supplied realized currency against
    /// this before settling or signing, so an unchecked currency is never stamped
    /// onto a signed authoritative receipt.
    pub reserved_currency: Option<String>,
    /// Rail transaction id that funded a prepaid MustPrepay reservation, recorded
    /// when the reserve-for-caller path stamps the hold. `None` for holds that
    /// carried no prepayment (an ordinary mediated reserve billed at reconcile
    /// time downstream). Reconcile-by-nonce stamps it as the authoritative
    /// receipt's `payment_reference` so operators can tie the reconciled spend to
    /// the transaction that paid for it, and it survives a fresh-kernel reconcile.
    pub reserved_payment_reference: Option<String>,
    /// Grant ceiling (`max_total_cost`) recorded when the reserve-for-caller path
    /// stamps a monetary hold, so reconcile-by-nonce reports the grant's total
    /// budget rather than the reservation's exposure. `None` for holds never
    /// marked reserved and for zero-exposure invocation reserves.
    pub reserved_budget_total: Option<u64>,
    /// Delegation depth of the reserving capability, recorded at reserve time so
    /// reconcile-by-nonce stamps the true lineage depth rather than zero. `None`
    /// for holds never marked reserved.
    pub reserved_delegation_depth: Option<u32>,
    /// Root budget holder of the reserving capability's delegation chain, recorded
    /// at reserve time so reconcile-by-nonce stamps the true lineage root rather
    /// than the nonce subject. `None` for holds never marked reserved.
    pub reserved_root_budget_holder: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}
