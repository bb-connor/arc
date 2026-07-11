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
    AuthorizeExposure,
    ReverseExposure,
    ReleaseExposure,
    ReconcileSpend,
}

impl BudgetMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncrementInvocation => "increment_invocation",
            Self::AuthorizeExposure => "authorize_exposure",
            Self::ReverseExposure => "reverse_exposure",
            Self::ReleaseExposure => "release_exposure",
            Self::ReconcileSpend => "reconcile_spend",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "increment_invocation" => Some(Self::IncrementInvocation),
            "authorize_exposure" => Some(Self::AuthorizeExposure),
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
pub struct AuthorizedBudgetHold {
    pub hold_id: Option<String>,
    pub authorized_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedBudgetHold {
    pub hold_id: Option<String>,
    pub attempted_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetAuthorizeHoldDecision {
    Authorized(AuthorizedBudgetHold),
    Denied(DeniedBudgetHold),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldMutationDecision {
    pub hold_id: Option<String>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
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
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
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
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        self.reconcile_budget_hold(request)
    }

    /// Reverse any hold that is still `open` after a process restart, arbitrated
    /// by the provided realized-spend map. Holds present in `realized_by_hold`
    /// are reconciled to their recorded amount; holds absent from it (orphans)
    /// are reversed. Stores that do not persist hold state return `Ok((0, 0))`
    /// (the default). Returns `(reconciled, reversed)` counts.
    ///
    /// Callers must supply a realized-spend map built from the durable receipt
    /// log (ADR-0013). Passing an empty map reverses all open holds, which
    /// enables double-spend: a hold left open by a crash after the spend but
    /// before reconcile represents real spent budget. Use `count_open_holds`
    /// to log the hold count and leave holds reserved (fail-closed) when the
    /// durable receipt log is not available at startup.
    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let _ = realized_by_hold;
        Ok((0, 0))
    }

    /// Return the number of holds still in the `open` state. Stores that do
    /// not persist hold state return `Ok(0)` (the default). Use at startup to
    /// log the number of holds that will remain reserved under the fail-closed
    /// policy when the durable receipt log arbitration map is unavailable.
    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(0)
    }

    /// Ids of holds that are still `open` and were stamped as a delegated
    /// reserve-for-caller reservation: marked reserved (via
    /// [`Self::mark_hold_reserved`] or [`Self::reserve_invocation_hold`]) with a
    /// delegation depth of at least one. Such a hold keeps its delegated child's
    /// sibling-sum share admitted against the parent for as long as it stays
    /// open. A freshly built mediation kernel consults this after a restart: the
    /// in-memory sibling-sum reservations were lost, and the durable hold record
    /// carries neither the immediate parent capability id nor the child and
    /// parent shares needed to rebuild them, so mediation denies delegated
    /// admission fail-closed while any such hold from a prior process is still
    /// open.
    ///
    /// `Ok(Some(ids))` enumerates those holds precisely. `Ok(None)` marks a store
    /// that cannot enumerate them; the caller then falls back to
    /// [`Self::count_open_holds`] and gates on the presence of any open hold. The
    /// default is `Ok(None)` so a store that does not persist hold state is
    /// treated as unable to enumerate rather than as having none.
    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(None)
    }

    /// Project a single hold by id, or `None` when it is unknown. Stores that
    /// do not persist hold state return `Ok(None)` (the default). Used by the
    /// reconcile-by-nonce entry point to resolve the exact reserved hold a
    /// signed execution nonce names.
    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        let _ = hold_id;
        Ok(None)
    }

    /// Stamp an open hold with the wall-clock unix second after which the TTL
    /// reaper may settle it if it is still unreconciled, and record the currency
    /// the grant was authorized in. Only the pre-execution
    /// authorization-reserving path calls this, so a normal in-flight hold
    /// (reconciled or reversed within one evaluation) is never marked and never
    /// touched by the TTL reaper. The recorded currency lets reconcile-by-nonce
    /// reject a caller-supplied realized currency that differs from the grant's.
    /// `payment_reference` records the rail transaction id of a prepaid MustPrepay
    /// reservation (`None` for a reserve with no prepayment) so reconcile-by-nonce
    /// can stamp it onto the authoritative receipt. `envelope` records the grant
    /// ceiling and delegation lineage so reconcile-by-nonce reports the grant's
    /// budget total/remaining and true lineage instead of the reservation's own
    /// exposure. Stores that do not persist hold state treat this as a no-op (the
    /// default).
    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _ = (
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        );
        Ok(())
    }

    /// Adopt an already-debited invocation into a durable reserved hold that
    /// carries zero monetary exposure, so a `max_invocations`-only reservation is
    /// reversible and reapable by hold id exactly like a monetary reserve. The
    /// invocation was already counted by [`Self::try_increment`]; this records the
    /// hold WITHOUT touching the invocation count, marks it reserved with the TTL
    /// deadline, and records no currency (there is no monetary envelope to
    /// validate on reconcile). Reversing the hold returns the invocation;
    /// reconciling or reaping it keeps the invocation consumed. `envelope` records
    /// the delegation lineage so reconcile-by-nonce stamps the true depth/root
    /// (its `budget_total` is `None`: an invocation reserve carries no monetary
    /// ceiling). Stores that do not persist hold state treat this as a no-op (the
    /// default).
    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _ = (
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        );
        Ok(())
    }

    /// Settle every reserved hold that is still `open` and whose `reserved_until`
    /// is at or before `now_unix_secs` at its reserved worst-case, forfeiting the
    /// reserved amount to realized spend. In the two-phase reserve/reconcile flow
    /// the ONLY evidence a spend occurred is the caller's reconcile; an
    /// expired-and-unreconciled hold may correspond to a call that DID execute and
    /// spend. Releasing it (realized 0) would under-count real spend and fail open
    /// for a cumulative spend cap, so an abandoning caller instead FORFEITS the
    /// reserved worst-case (the grant's realized total advances by it) and must
    /// reconcile the real cost before expiry to reclaim the difference.
    /// Fail-closed and self-healing: it settles ONLY holds that were explicitly
    /// marked reserved (via [`Self::mark_hold_reserved`]) and are past their
    /// expiry; a not-yet-expired reserved hold and a reconciled/reversed/released
    /// hold are never touched. Idempotent (a settled hold is no longer open).
    /// Returns the number of holds settled. Stores that do not persist hold state
    /// return `Ok(0)` (the default).
    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        let _ = now_unix_secs;
        Ok(0)
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

pub use in_memory::InMemoryBudgetStore;

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
        assert_eq!(events[1].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].realized_spend_units, 75);
    }

    fn authorize_reserved(
        store: &InMemoryBudgetStore,
        hold_id: &str,
        cap: &str,
        reserved_until: i64,
    ) {
        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: cap.to_string(),
                grant_index: 0,
                max_invocations: Some(10),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:authorize")),
                authority: None,
            })
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        store
            .mark_hold_reserved(
                hold_id,
                reserved_until,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
    }

    #[test]
    fn ttl_reaper_settles_expired_unreconciled_reserved_holds_at_worst_case() {
        let store = InMemoryBudgetStore::new();
        // Expired reserved hold on cap-a: reserved_until 100 <= now 1000.
        authorize_reserved(&store, "hold-expired", "cap-a", 100);
        // Not-yet-expired reserved hold on cap-b: reserved_until 5000 > now 1000.
        authorize_reserved(&store, "hold-fresh", "cap-b", 5_000);
        // Reconciled reserved hold on cap-c: reconciled before the reap.
        authorize_reserved(&store, "hold-done", "cap-c", 100);
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-done".to_string()),
                event_id: Some("hold-done:reconcile".to_string()),
                authority: None,
            })
            .unwrap();

        // Before the reap: expired/fresh committed 100 each, reconciled committed 40.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );

        let settled = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(settled, 1, "only the expired reserved hold is settled");

        // cap-a expired reserved hold SETTLED at worst-case: the reserved amount
        // is forfeited to realized spend (committed stays 100), not released to 0.
        let cap_a = store.get_usage("cap-a", 0).unwrap().unwrap();
        assert_eq!(
            cap_a.total_cost_realized_spend, 100,
            "the forfeited worst-case becomes realized spend"
        );
        assert_eq!(
            cap_a.committed_cost_units().unwrap(),
            100,
            "the reserved worst-case stays consumed, the freed difference is gone"
        );
        assert_eq!(
            store
                .get_budget_hold("hold-expired")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
        // A second reap is idempotent: the settled hold is no longer open.
        assert_eq!(store.reap_expired_reserved_holds(1_000).unwrap(), 0);
        // cap-b not-yet-expired reserved hold untouched.
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .get_budget_hold("hold-fresh")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Open
        );
        // cap-c reconciled hold untouched (still at realized 40).
        assert_eq!(
            store
                .get_usage("cap-c", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_budget_hold("hold-done")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
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
