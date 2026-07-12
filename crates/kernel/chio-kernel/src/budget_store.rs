use chio_core::capability::aggregate_budget::{
    AggregateInvocationScope, VerifiedAggregateInvocationAuthority,
};

use crate::supplemental_quota::{CanonicalRevocationSet, VerifiedSupplementalQuota};

#[derive(Debug, thiserror::Error)]
pub enum BudgetStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare budget store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("budget arithmetic overflow: {0}")]
    Overflow(String),

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
    aggregate_binding_digest: Option<String>,
    supplemental_binding: Option<SupplementalQuotaBinding>,
}

impl VerifiedInvocationAdmission {
    fn grant_only(
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
    let revocation_set =
        CanonicalRevocationSet::new(capability_id, verified_ancestor_ids, supplemental_ids)
            .map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "failed to build canonical revocation set: {error}"
                ))
            })?;
    Ok(VerifiedInvocationAdmission {
        quotas,
        revocation_set,
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
            _ => None,
        }
    }
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
///     invocation_admission: None,
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
    invocation_admission: Option<VerifiedInvocationAdmission>,
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
            invocation_admission: None,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReleaseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub released_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReverseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub reversed_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
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
}

pub type BudgetCaptureHoldRequest = BudgetReconcileHoldRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCaptureInvocationRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
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

pub trait BudgetStore: Send + Sync {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    /// Atomically check monetary budget limits and record provisional exposure if within bounds.
    ///
    /// Checks:
    /// 1. `invocation_count < max_invocations` (if set)
    /// 2. `cost_units <= max_cost_per_invocation` (if set)
    /// 3. `(total_cost_exposed + total_cost_realized_spend + cost_units)
    ///    <= max_total_cost_units` (if set)
    ///
    /// On pass: increments `invocation_count` by 1 and `total_cost_exposed` by
    /// `cost_units`, allocates a new replication seq, returns `Ok(true)`.
    /// On any limit exceeded: rolls back, returns `Ok(false)`.
    ///
    // SAFETY: HA overrun bound = max_cost_per_invocation x node_count
    // In a split-brain scenario, each HA node may independently approve up to
    // one invocation at the full per-invocation cap before the LWW merge
    // propagates the updated total. The maximum possible overrun is therefore
    // bounded by max_cost_per_invocation multiplied by the number of active
    // nodes in the HA cluster.
    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let _ = authority;
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    /// Reverse a previously applied provisional exposure for a pre-execution denial path.
    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    /// Release a previously exposed monetary amount without changing invocation count.
    ///
    /// This is used when the kernel needs to release provisional exposure without
    /// realizing any spend in the budget store itself.
    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    /// Atomically release provisional exposure and record realized spend.
    ///
    /// This removes `exposed_cost_units` from `total_cost_exposed` and adds
    /// `realized_cost_units` to `total_cost_realized_spend` without changing
    /// invocation count. `realized_cost_units` must not exceed
    /// `exposed_cost_units`.
    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError>;

    fn list_mutation_events(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
        _grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget mutation events unavailable for this backend".to_string(),
        ))
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn budget_authority_profile(&self) -> BudgetAuthorityProfile {
        BudgetAuthorityProfile::AuthoritativeHoldEvent
    }

    fn budget_metering_profile(&self) -> BudgetMeteringProfile {
        BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            return Err(BudgetStoreError::Invariant(
                "composite budget holds are unavailable for this backend".to_string(),
            ));
        }
        let monetary_state = if request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let allowed = self.try_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        let committed_cost_units_after = usage
            .as_ref()
            .map(BudgetUsageRecord::committed_cost_units)
            .transpose()?
            .unwrap_or(0);
        let invocation_count_after = usage.as_ref().map_or(0, |usage| usage.invocation_count);
        let metadata = budget_commit_metadata(
            self,
            request.authority,
            allowed
                .then(|| usage.as_ref().map(|usage| usage.seq))
                .flatten(),
            request.event_id,
        );

        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    invocation_counts_after: Vec::new(),
                    invocation_state: BudgetInvocationReservationState::Absent,
                    monetary_state,
                    revocation_set: None,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
                invocation_counts_after: Vec::new(),
                invocation_state: BudgetInvocationReservationState::Denied,
                monetary_state: BudgetMonetaryHoldState::None,
                revocation_set: None,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Reversed,
            revocation_set: None,
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Released,
            revocation_set: None,
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Reconciled,
            revocation_set: None,
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn capture_budget_hold(
        &self,
        _request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "monetary hold capture unavailable for this backend".to_string(),
        ))
    }

    fn capture_invocation_reservations(
        &self,
        _request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "invocation reservation capture unavailable for this backend".to_string(),
        ))
    }
}

fn checked_committed_cost_units(
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> Result<u64, BudgetStoreError> {
    total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "total_cost_exposed + total_cost_realized_spend overflowed u64".to_string(),
            )
        })
}

mod in_memory;

#[cfg(test)]
mod property_tests;

pub use in_memory::InMemoryBudgetStore;

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(
        profile: BudgetQuotaProfile,
        owner_id: &str,
        grant_index: Option<u32>,
        max_invocations: u32,
    ) -> BudgetInvocationQuota {
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile,
                owner_id: owner_id.to_string(),
                grant_index,
            },
            max_invocations,
        }
    }

    fn composite_request(
        hold_id: &str,
        event_id: &str,
        quotas: Vec<BudgetInvocationQuota>,
    ) -> BudgetAuthorizeHoldRequest {
        let invocation_admission = VerifiedInvocationAdmission {
            quotas,
            revocation_set: CanonicalRevocationSet::new("cap-composite", &[], &[]).unwrap(),
            aggregate_binding_digest: None,
            supplemental_binding: Some(SupplementalQuotaBinding {
                artifact_digest: "11".repeat(32),
                verifier_id: "test-verifier".to_string(),
                request_binding_hash: "22".repeat(32),
                negotiated_features_digest: "33".repeat(32),
            }),
        };
        BudgetAuthorizeHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            max_invocations: None,
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(1_000),
            hold_id: Some(hold_id.to_string()),
            event_id: Some(event_id.to_string()),
            authority: None,
            invocation_admission: Some(invocation_admission),
        }
    }

    fn three_quotas(aggregate_max: u32) -> Vec<BudgetInvocationQuota> {
        vec![
            quota(
                BudgetQuotaProfile::GrantInvocation,
                "cap-composite",
                Some(0),
                2,
            ),
            quota(
                BudgetQuotaProfile::AggregateCapabilityInvocation,
                "cap-composite",
                None,
                aggregate_max,
            ),
            quota(
                BudgetQuotaProfile::SupplementalBrokerExecution,
                &"22".repeat(32),
                None,
                2,
            ),
        ]
    }

    #[test]
    fn authorization_request_exposes_verified_admission_evidence_read_only() {
        let mut request = composite_request("hold-evidence", "event-evidence", three_quotas(3));
        request
            .invocation_admission
            .as_mut()
            .unwrap()
            .aggregate_binding_digest = Some("44".repeat(32));

        let evidence = request
            .invocation_admission_evidence()
            .expect("verified admission evidence");
        assert_eq!(evidence.quotas(), request.invocation_quotas());
        assert_eq!(
            evidence.revocation_set().digest(),
            request.revocation_set().unwrap().digest()
        );
        assert_eq!(
            evidence.aggregate_binding_digest(),
            Some("44".repeat(32).as_str())
        );
        assert_eq!(
            evidence.supplemental_artifact_digest(),
            Some("11".repeat(32).as_str())
        );
        assert_eq!(evidence.supplemental_verifier_id(), Some("test-verifier"));
        assert_eq!(
            evidence.supplemental_request_binding_hash(),
            Some("22".repeat(32).as_str())
        );
        assert_eq!(
            evidence.supplemental_negotiated_features_digest(),
            Some("33".repeat(32).as_str())
        );
    }

    #[test]
    fn persisted_quota_descriptors_revalidate_the_structured_key() {
        let key = BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::GrantInvocation,
            "cap-persisted".to_string(),
            Some(7),
        )
        .unwrap();
        let quota = BudgetInvocationQuota::from_persisted_parts(key, 11).unwrap();
        assert_eq!(quota.key().profile(), BudgetQuotaProfile::GrantInvocation);
        assert_eq!(quota.key().owner_id(), "cap-persisted");
        assert_eq!(quota.key().grant_index(), Some(7));
        assert_eq!(quota.max_invocations(), 11);

        assert!(BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::AggregateFamilyInvocation,
            "not-a-digest".to_string(),
            None,
        )
        .is_err());
        assert!(BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "cap-persisted".to_string(),
            Some(7),
        )
        .is_err());
    }

    #[test]
    fn persisted_quota_usage_revalidates_counters_and_states() {
        let quota = BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant("cap-persisted", 0).unwrap(),
            2,
        )
        .unwrap();
        assert!(BudgetInvocationQuotaUsage {
            quota: quota.clone(),
            reserved_invocations_after: 1,
            captured_invocations_after: 1,
        }
        .validate()
        .is_ok());
        assert!(BudgetInvocationQuotaUsage {
            quota,
            reserved_invocations_after: 2,
            captured_invocations_after: 1,
        }
        .validate()
        .is_err());

        for state in [
            BudgetInvocationReservationState::Absent,
            BudgetInvocationReservationState::Authorized,
            BudgetInvocationReservationState::Captured,
            BudgetInvocationReservationState::Reversed,
            BudgetInvocationReservationState::Denied,
        ] {
            assert_eq!(
                BudgetInvocationReservationState::parse(state.as_str()),
                Some(state)
            );
        }
        assert_eq!(BudgetInvocationReservationState::parse("unknown"), None);

        for state in [
            BudgetMonetaryHoldState::None,
            BudgetMonetaryHoldState::Exposed,
            BudgetMonetaryHoldState::Released,
            BudgetMonetaryHoldState::Reconciled,
            BudgetMonetaryHoldState::Captured,
            BudgetMonetaryHoldState::Reversed,
        ] {
            assert_eq!(BudgetMonetaryHoldState::parse(state.as_str()), Some(state));
        }
        assert_eq!(BudgetMonetaryHoldState::parse("unknown"), None);
    }

    #[test]
    fn composite_hold_reserves_all_quotas_or_none() {
        let store = InMemoryBudgetStore::new();
        let first = store
            .authorize_budget_hold(composite_request(
                "hold-composite-1",
                "event-composite-1",
                three_quotas(1),
            ))
            .unwrap();
        let BudgetAuthorizeHoldDecision::Authorized(first) = first else {
            panic!("first composite hold should be authorized");
        };
        assert_eq!(first.invocation_counts_after.len(), 3);
        assert!(first
            .invocation_counts_after
            .iter()
            .all(|count| count.invocation_count_after().unwrap() == 1));
        assert_eq!(
            first.invocation_state,
            BudgetInvocationReservationState::Authorized
        );
        assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Exposed);

        let second = store
            .authorize_budget_hold(composite_request(
                "hold-composite-2",
                "event-composite-2",
                three_quotas(1),
            ))
            .unwrap();
        let BudgetAuthorizeHoldDecision::Denied(second) = second else {
            panic!("exhausted aggregate quota should deny the whole hold");
        };
        assert_eq!(second.invocation_counts_after.len(), 3);
        assert!(second
            .invocation_counts_after
            .iter()
            .all(|count| count.invocation_count_after().unwrap() == 1));
        assert_eq!(second.committed_cost_units_after, 100);
    }

    #[test]
    fn composite_hold_rejects_duplicate_changed_maximum_and_nine_claims() {
        let store = InMemoryBudgetStore::new();
        let mut duplicate = three_quotas(2);
        duplicate.push(duplicate[0].clone());
        assert!(matches!(
            store.authorize_budget_hold(composite_request(
                "hold-duplicate",
                "event-duplicate",
                duplicate,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        store
            .authorize_budget_hold(composite_request(
                "hold-max-1",
                "event-max-1",
                three_quotas(2),
            ))
            .unwrap();
        let mut changed = three_quotas(2);
        changed[0].max_invocations = 3;
        assert!(matches!(
            store.authorize_budget_hold(composite_request("hold-max-2", "event-max-2", changed,)),
            Err(BudgetStoreError::Invariant(_))
        ));

        let nine = (0..9)
            .map(|index| {
                quota(
                    BudgetQuotaProfile::AggregateFamilyInvocation,
                    &format!("family-{index}"),
                    None,
                    1,
                )
            })
            .collect();
        assert!(matches!(
            store.authorize_budget_hold(composite_request("hold-nine", "event-nine", nine,)),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn denied_first_presentations_pin_immutable_maxima() {
        let compatibility = InMemoryBudgetStore::new();
        assert!(!compatibility
            .try_increment("cap-denied-first", 0, Some(0))
            .unwrap());
        assert!(matches!(
            compatibility.try_increment("cap-denied-first", 0, Some(1)),
            Err(BudgetStoreError::Invariant(_))
        ));

        let composite = InMemoryBudgetStore::new();
        let denied = composite
            .authorize_budget_hold(composite_request(
                "hold-denied-first",
                "event-denied-first",
                three_quotas(0),
            ))
            .unwrap();
        assert!(matches!(denied, BudgetAuthorizeHoldDecision::Denied(_)));
        assert!(matches!(
            composite.authorize_budget_hold(composite_request(
                "hold-denied-first-raised",
                "event-denied-first-raised",
                three_quotas(1),
            )),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn capture_and_reconcile_have_independent_substates() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-independent",
                "event-independent-authorize",
                three_quotas(2),
            ))
            .unwrap();

        let captured = store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-independent".to_string()),
                event_id: Some("event-independent-capture".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(
            captured.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);
        assert_eq!(captured.committed_cost_units_after, 100);

        let reconciled = store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 60,
                hold_id: Some("hold-independent".to_string()),
                event_id: Some("event-independent-reconcile".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(
            reconciled.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(
            reconciled.monetary_state,
            BudgetMonetaryHoldState::Reconciled
        );
        assert!(reconciled
            .invocation_counts_after
            .iter()
            .all(|count| count.invocation_count_after().unwrap() == 1));
    }

    #[test]
    fn monetary_capture_preserves_and_then_allows_invocation_capture() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-monetary-capture",
                "event-monetary-capture-authorize",
                three_quotas(2),
            ))
            .unwrap();
        let captured_monetary = store
            .capture_budget_hold(BudgetCaptureHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 60,
                hold_id: Some("hold-monetary-capture".to_string()),
                event_id: Some("event-monetary-capture".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(
            captured_monetary.invocation_state,
            BudgetInvocationReservationState::Authorized
        );
        assert_eq!(
            captured_monetary.monetary_state,
            BudgetMonetaryHoldState::Captured
        );

        let captured_invocation = store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-monetary-capture".to_string()),
                event_id: Some("event-invocation-after-monetary-capture".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(
            captured_invocation.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(
            captured_invocation.monetary_state,
            BudgetMonetaryHoldState::Captured
        );
    }

    #[test]
    fn composite_authorize_event_retry_is_snapshot_stable() {
        let store = InMemoryBudgetStore::new();
        let request = composite_request("hold-retry", "event-retry-authorize", three_quotas(2));
        let first = store.authorize_budget_hold(request.clone()).unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-retry".to_string()),
                event_id: Some("event-retry-capture".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(store.authorize_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn concurrent_composite_holds_admit_exactly_one_last_unit() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(InMemoryBudgetStore::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for index in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .authorize_budget_hold(composite_request(
                        &format!("hold-race-{index}"),
                        &format!("event-race-{index}"),
                        three_quotas(1),
                    ))
                    .unwrap()
            }));
        }
        barrier.wait();
        let authorized = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(BudgetAuthorizeHoldDecision::is_authorized)
            .count();
        assert_eq!(authorized, 1);
    }

    #[test]
    fn composite_hold_rejects_ambiguous_unsorted_and_mismatched_retries() {
        let store = InMemoryBudgetStore::new();

        let mut ambiguous = composite_request("hold-ambiguous", "event-ambiguous", three_quotas(2));
        ambiguous.max_invocations = Some(2);
        assert!(matches!(
            store.authorize_budget_hold(ambiguous),
            Err(BudgetStoreError::Invariant(_))
        ));

        let mut unsorted = three_quotas(2);
        unsorted.swap(0, 1);
        assert!(matches!(
            store.authorize_budget_hold(composite_request(
                "hold-unsorted",
                "event-unsorted",
                unsorted,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        let request = composite_request("hold-mismatch", "event-mismatch", three_quotas(2));
        store.authorize_budget_hold(request.clone()).unwrap();
        let mut changed_event = request.clone();
        changed_event.requested_exposure_units = 99;
        assert!(matches!(
            store.authorize_budget_hold(changed_event),
            Err(BudgetStoreError::Invariant(_))
        ));
        let mut changed_hold = request;
        changed_hold.event_id = Some("event-mismatch-second".to_string());
        assert!(matches!(
            store.authorize_budget_hold(changed_hold),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn composite_predispatch_reverse_restores_every_quota_and_exposure() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-reverse-1",
                "event-reverse-1-authorize",
                three_quotas(1),
            ))
            .unwrap();

        let reversed = store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                reversed_exposure_units: 100,
                hold_id: Some("hold-reverse-1".to_string()),
                event_id: Some("event-reverse-1".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(
            reversed.invocation_state,
            BudgetInvocationReservationState::Reversed
        );
        assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Reversed);
        assert_eq!(reversed.committed_cost_units_after, 0);
        assert!(reversed
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().unwrap() == 0));

        let second = store
            .authorize_budget_hold(composite_request(
                "hold-reverse-2",
                "event-reverse-2-authorize",
                three_quotas(1),
            ))
            .unwrap();
        assert!(second.is_authorized());
    }

    #[test]
    fn monetary_release_then_invocation_reverse_preserves_terminal_substate() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-release-reverse",
                "event-release-reverse-authorize",
                three_quotas(1),
            ))
            .unwrap();
        let released = store
            .release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                released_exposure_units: 100,
                hold_id: Some("hold-release-reverse".to_string()),
                event_id: Some("event-release-reverse-release".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);
        assert_eq!(
            released.invocation_state,
            BudgetInvocationReservationState::Authorized
        );

        let reversed = store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                reversed_exposure_units: 0,
                hold_id: Some("hold-release-reverse".to_string()),
                event_id: Some("event-release-reverse-reverse".to_string()),
                authority: None,
            })
            .unwrap();
        assert_eq!(
            reversed.invocation_state,
            BudgetInvocationReservationState::Reversed
        );
        assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Released);
        assert!(reversed
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().unwrap() == 0));
        assert!(store
            .authorize_budget_hold(composite_request(
                "hold-release-reverse-next",
                "event-release-reverse-next",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
    }

    #[test]
    fn captured_invocations_are_terminal_while_monetary_exposure_remains_live() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-captured-terminal",
                "event-captured-terminal-authorize",
                three_quotas(2),
            ))
            .unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-captured-terminal".to_string()),
                event_id: Some("event-captured-terminal-capture".to_string()),
                authority: None,
            })
            .unwrap();

        assert!(matches!(
            store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                reversed_exposure_units: 100,
                hold_id: Some("hold-captured-terminal".to_string()),
                event_id: Some("event-captured-terminal-reverse".to_string()),
                authority: None,
            }),
            Err(BudgetStoreError::Invariant(_))
        ));
        let usage = store.get_usage("cap-composite", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 100);
        assert!(matches!(
            store.reverse_charge_cost("cap-composite", 0, 0),
            Err(BudgetStoreError::Invariant(_))
        ));
        let usage = store.get_usage("cap-composite", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 100);
    }

    #[test]
    fn compatibility_increment_pins_maximum_and_reverses_the_same_quota() {
        let store = InMemoryBudgetStore::new();
        assert!(store.try_increment("cap-compat", 0, Some(2)).unwrap());
        assert!(store
            .try_charge_cost("cap-compat", 0, Some(2), 1, None, None)
            .unwrap());
        assert!(matches!(
            store.try_increment("cap-compat", 0, Some(3)),
            Err(BudgetStoreError::Invariant(_))
        ));
        store.reverse_charge_cost("cap-compat", 0, 0).unwrap();
        assert!(store.try_increment("cap-compat", 0, Some(2)).unwrap());

        let events = store
            .list_mutation_events(10, Some("cap-compat"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].invocation_counts_after.len(), 1);
        assert_eq!(
            events[0].invocation_state,
            BudgetInvocationReservationState::Captured
        );
    }

    #[test]
    fn compatibility_charge_uses_the_same_immutable_quota_authority() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-compat-charge", 0, Some(2), 1, None, None)
            .unwrap());
        assert!(matches!(
            store.try_charge_cost("cap-compat-charge", 0, Some(3), 1, None, None),
            Err(BudgetStoreError::Invariant(_))
        ));

        let denied = InMemoryBudgetStore::new();
        assert!(!denied
            .try_charge_cost("cap-compat-charge-denied", 0, Some(2), 2, Some(1), None,)
            .unwrap());
        assert!(matches!(
            denied.try_charge_cost("cap-compat-charge-denied", 0, Some(3), 1, Some(1), None,),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn multi_quota_authority_blocks_legacy_increment_and_charge_bypasses() {
        let increment_store = InMemoryBudgetStore::new();
        assert!(increment_store
            .authorize_budget_hold(composite_request(
                "hold-multi-authority-increment",
                "event-multi-authority-increment",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
        assert!(matches!(
            increment_store.try_increment("cap-composite", 0, Some(2)),
            Err(BudgetStoreError::Invariant(_))
        ));

        let charge_store = InMemoryBudgetStore::new();
        assert!(charge_store
            .authorize_budget_hold(composite_request(
                "hold-multi-authority-charge",
                "event-multi-authority-charge",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
        assert!(matches!(
            charge_store.try_charge_cost("cap-composite", 0, Some(2), 0, None, None),
            Err(BudgetStoreError::Invariant(_))
        ));

        let hold_store = InMemoryBudgetStore::new();
        assert!(hold_store
            .authorize_budget_hold(composite_request(
                "hold-multi-authority-structured",
                "event-multi-authority-structured",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
        assert!(matches!(
            hold_store.authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "cap-composite".to_string(),
                0,
                Some(2),
                0,
                None,
                None,
                Some("hold-multi-authority-legacy".to_string()),
                Some("event-multi-authority-legacy".to_string()),
                None,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        let denied_store = InMemoryBudgetStore::new();
        assert!(matches!(
            denied_store
                .authorize_budget_hold(composite_request(
                    "hold-multi-authority-denied",
                    "event-multi-authority-denied",
                    three_quotas(0),
                ))
                .unwrap(),
            BudgetAuthorizeHoldDecision::Denied(_)
        ));
        assert!(matches!(
            denied_store.authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "cap-composite".to_string(),
                0,
                Some(2),
                0,
                None,
                None,
                Some("hold-multi-authority-after-denial".to_string()),
                Some("event-multi-authority-after-denial".to_string()),
                None,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn legacy_hold_id_collision_rejects_even_when_second_authorization_would_deny() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-legacy-hold-collision",
                0,
                Some(1),
                1,
                None,
                None,
                Some("hold-legacy-collision"),
                Some("event-legacy-collision-first"),
            )
            .unwrap());

        assert!(matches!(
            store.try_charge_cost_with_ids(
                "cap-legacy-hold-collision",
                0,
                Some(1),
                1,
                None,
                None,
                Some("hold-legacy-collision"),
                Some("event-legacy-collision-denied"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-legacy-hold-collision"), Some(0))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn denied_legacy_authorization_permanently_claims_its_hold_id() {
        let store = InMemoryBudgetStore::new();
        assert!(!store
            .try_charge_cost_with_ids(
                "cap-denied-hold-claim",
                0,
                Some(2),
                2,
                Some(1),
                Some(10),
                Some("hold-denied-claim"),
                Some("event-denied-claim-first"),
            )
            .unwrap());
        assert!(!store
            .try_charge_cost_with_ids(
                "cap-denied-hold-claim",
                0,
                Some(2),
                2,
                Some(1),
                Some(10),
                Some("hold-denied-claim"),
                Some("event-denied-claim-first"),
            )
            .unwrap());

        assert!(matches!(
            store.try_charge_cost_with_ids(
                "cap-denied-hold-claim",
                0,
                Some(2),
                1,
                Some(1),
                Some(10),
                Some("hold-denied-claim"),
                Some("event-denied-claim-second"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert!(store
            .get_usage("cap-denied-hold-claim", 0)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-denied-hold-claim"), Some(0))
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            store.authorize_budget_hold(composite_request(
                "hold-denied-claim",
                "event-denied-claim-composite",
                three_quotas(2),
            )),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn legacy_reverse_retry_returns_the_frozen_decision() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reverse-retry",
                0,
                Some(3),
                100,
                Some(100),
                Some(1_000),
                Some("hold-reverse-retry"),
                Some("event-reverse-retry-authorize"),
            )
            .unwrap());
        let request = BudgetReverseHoldRequest {
            capability_id: "cap-reverse-retry".to_string(),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some("hold-reverse-retry".to_string()),
            event_id: Some("event-reverse-retry".to_string()),
            authority: None,
        };
        let first = store.reverse_budget_hold(request.clone()).unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reverse-retry",
                0,
                Some(3),
                25,
                Some(100),
                Some(1_000),
                Some("hold-reverse-retry-later"),
                Some("event-reverse-retry-later"),
            )
            .unwrap());
        assert_eq!(store.reverse_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn legacy_release_retry_returns_the_frozen_decision() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-release-retry",
                0,
                Some(3),
                100,
                Some(100),
                Some(1_000),
                Some("hold-release-retry"),
                Some("event-release-retry-authorize"),
            )
            .unwrap());
        let request = BudgetReleaseHoldRequest {
            capability_id: "cap-release-retry".to_string(),
            grant_index: 0,
            released_exposure_units: 40,
            hold_id: Some("hold-release-retry".to_string()),
            event_id: Some("event-release-retry".to_string()),
            authority: None,
        };
        let first = store.release_budget_hold(request.clone()).unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-release-retry",
                0,
                Some(3),
                25,
                Some(100),
                Some(1_000),
                Some("hold-release-retry-later"),
                Some("event-release-retry-later"),
            )
            .unwrap());
        assert_eq!(store.release_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn legacy_reconcile_retry_returns_the_frozen_decision() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reconcile-retry",
                0,
                Some(3),
                100,
                Some(100),
                Some(1_000),
                Some("hold-reconcile-retry"),
                Some("event-reconcile-retry-authorize"),
            )
            .unwrap());
        let request = BudgetReconcileHoldRequest {
            capability_id: "cap-reconcile-retry".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 70,
            hold_id: Some("hold-reconcile-retry".to_string()),
            event_id: Some("event-reconcile-retry".to_string()),
            authority: None,
        };
        let first = store.reconcile_budget_hold(request.clone()).unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reconcile-retry",
                0,
                Some(3),
                25,
                Some(100),
                Some(1_000),
                Some("hold-reconcile-retry-later"),
                Some("event-reconcile-retry-later"),
            )
            .unwrap());
        assert_eq!(store.reconcile_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn legacy_hold_id_cannot_collide_with_composite_authorization() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-namespace",
                "event-namespace-authorize",
                three_quotas(2),
            ))
            .unwrap();

        assert!(matches!(
            store.try_charge_cost_with_ids(
                "legacy-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("hold-namespace"),
                Some("event-legacy-collision"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn event_ids_are_globally_unique_across_legacy_and_composite_mutations() {
        let legacy_first = InMemoryBudgetStore::new();
        assert!(legacy_first
            .try_charge_cost_with_ids(
                "legacy-event-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("legacy-event-hold"),
                Some("event-global-collision"),
            )
            .unwrap());
        assert!(matches!(
            legacy_first.authorize_budget_hold(composite_request(
                "hold-global-collision",
                "event-global-collision",
                three_quotas(2),
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        let composite_first = InMemoryBudgetStore::new();
        composite_first
            .authorize_budget_hold(composite_request(
                "hold-global-collision",
                "event-global-collision",
                three_quotas(2),
            ))
            .unwrap();
        assert!(matches!(
            composite_first.try_charge_cost_with_ids(
                "legacy-event-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("legacy-event-hold"),
                Some("event-global-collision"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn explicit_event_ids_cannot_enter_the_reserved_local_namespace() {
        let store = InMemoryBudgetStore::new();
        assert!(matches!(
            store.try_charge_cost_with_ids(
                "legacy-event-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("legacy-event-hold"),
                Some("local-budget-event-1"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert!(store
            .get_usage("legacy-event-capability", 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn legacy_monetary_capture_is_truthful_and_idempotent() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "legacy-capture-capability",
                0,
                Some(2),
                100,
                Some(100),
                Some(1_000),
                Some("legacy-capture-hold"),
                Some("legacy-capture-authorize"),
            )
            .unwrap());
        let request = BudgetCaptureHoldRequest {
            capability_id: "legacy-capture-capability".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 70,
            hold_id: Some("legacy-capture-hold".to_string()),
            event_id: Some("legacy-capture-event".to_string()),
            authority: None,
        };
        let captured = store.capture_budget_hold(request.clone()).unwrap();
        assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
        assert_eq!(captured.realized_spend_units, 70);
        assert!(store
            .try_charge_cost_with_ids(
                "legacy-capture-capability",
                0,
                Some(2),
                0,
                Some(100),
                Some(1_000),
                Some("legacy-capture-later-hold"),
                Some("legacy-capture-later-authorize"),
            )
            .unwrap());
        assert_eq!(store.capture_budget_hold(request).unwrap(), captured);
        let events = store
            .list_mutation_events(10, Some("legacy-capture-capability"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].kind, BudgetMutationKind::CaptureExposure);
        assert_eq!(events[1].monetary_state, BudgetMonetaryHoldState::Captured);
    }

    #[test]
    fn quota_profiles_use_normative_closed_identifiers() {
        let profiles = [
            BudgetQuotaProfile::GrantInvocation,
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            BudgetQuotaProfile::AggregateFamilyInvocation,
            BudgetQuotaProfile::SupplementalBrokerExecution,
        ];
        for profile in profiles {
            assert_eq!(BudgetQuotaProfile::parse(profile.as_str()), Some(profile));
        }
        assert_eq!(BudgetQuotaProfile::parse("grant_invocation"), None);
    }

    #[test]
    fn authorize_and_reconcile_hold_preserve_authority_metadata() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                max_invocations: Some(4),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:authorize".to_string()),
                authority: Some(authority.clone()),
                invocation_admission: None,
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            panic!("budget hold should be authorized");
        };
        assert_eq!(authorized.committed_cost_units_after, 100);
        assert_eq!(
            authorized.metadata.event_id.as_deref(),
            Some("hold-budget-1:authorize")
        );
        assert_eq!(authorized.metadata.budget_commit_index, Some(1));
        assert_eq!(
            authorized.metadata.budget_term().as_deref(),
            Some("kernel:test-authority:0")
        );

        let reconcile = store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 75,
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:reconcile".to_string()),
                authority: Some(authority.clone()),
            })
            .unwrap();
        assert_eq!(reconcile.committed_cost_units_after, 75);
        assert_eq!(reconcile.realized_spend_units, 75);
        assert_eq!(
            reconcile.metadata.event_id.as_deref(),
            Some("hold-budget-1:reconcile")
        );
        assert_eq!(reconcile.metadata.budget_commit_index, Some(2));
        assert_eq!(reconcile.metadata.authority.as_ref(), Some(&authority));

        let usage = store.get_usage("cap-budget-1", 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 75);
        assert_eq!(usage.committed_cost_units().unwrap(), 75);

        let events = store
            .list_mutation_events(10, Some("cap-budget-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, BudgetMutationKind::ReserveInvocations);
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
        assert_eq!(events[1].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].realized_spend_units, 75);
    }

    #[test]
    fn denied_authorize_hold_reports_guarantee_metadata_without_commit_index() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-deny".to_string(),
                grant_index: 0,
                max_invocations: Some(1),
                requested_exposure_units: 150,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-deny".to_string()),
                event_id: Some("hold-budget-deny:authorize".to_string()),
                authority: Some(authority.clone()),
                invocation_admission: None,
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Denied(denied) = decision else {
            panic!("budget hold should be denied");
        };
        assert_eq!(denied.committed_cost_units_after, 0);
        assert_eq!(denied.invocation_count_after, 0);
        assert_eq!(
            denied.metadata.event_id.as_deref(),
            Some("hold-budget-deny:authorize")
        );
        assert_eq!(denied.metadata.budget_commit_index, None);
        assert_eq!(
            denied.metadata.guarantee_level,
            BudgetGuaranteeLevel::SingleNodeAtomic
        );
        assert_eq!(denied.metadata.authority.as_ref(), Some(&authority));

        let events = store
            .list_mutation_events(10, Some("cap-budget-deny"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].allowed, Some(false));
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert!(store.get_usage("cap-budget-deny", 0).unwrap().is_none());
    }
}
