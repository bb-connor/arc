use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(test, feature = "loom-tests"))]
use loom::sync::{Mutex as LoomMutex, MutexGuard as LoomMutexGuard};

use super::{
    budget_commit_metadata, checked_committed_cost_units, validate_invocation_quotas,
    AuthorizedBudgetHold, BudgetAuthorityProfile, BudgetAuthorizeHoldDecision,
    BudgetAuthorizeHoldRequest, BudgetCaptureHoldDecision, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetCommitMetadata, BudgetEventAuthority,
    BudgetGuaranteeLevel, BudgetHoldDispositionView, BudgetHoldMutationDecision,
    BudgetHoldSnapshot, BudgetInvocationQuota, BudgetInvocationQuotaUsage,
    BudgetInvocationReservationState, BudgetMeteringProfile, BudgetMonetaryHoldState,
    BudgetMutationKind, BudgetMutationRecord, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldDecision, BudgetReconcileHoldRequest, BudgetReleaseHoldDecision,
    BudgetReleaseHoldRequest, BudgetReverseHoldDecision, BudgetReverseHoldRequest, BudgetStore,
    BudgetStoreError, BudgetUsageRecord, DeniedBudgetHold, ReservedHoldEnvelope,
    VerifiedInvocationAdmission,
};

const LOCAL_BUDGET_EVENT_PREFIX: &str = "local-budget-event-";

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetHoldDisposition {
    Open,
    Released,
    Reversed,
    Reconciled,
    Captured,
}

impl BudgetHoldDisposition {
    fn view(&self) -> BudgetHoldDispositionView {
        match self {
            Self::Open => BudgetHoldDispositionView::Open,
            Self::Released => BudgetHoldDispositionView::Released,
            Self::Reversed => BudgetHoldDispositionView::Reversed,
            Self::Reconciled => BudgetHoldDispositionView::Reconciled,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetHoldState {
    capability_id: String,
    grant_index: usize,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    invocation_count_debited: bool,
    disposition: BudgetHoldDisposition,
    authority: Option<BudgetEventAuthority>,
    /// Set only when the reserving path marks this hold reserved; drives the
    /// TTL reaper. `None` for normal in-flight holds.
    reserved_until: Option<i64>,
    /// Currency the grant was authorized in, recorded alongside `reserved_until`
    /// by the reserving path. `None` for normal in-flight holds.
    reserved_currency: Option<String>,
    /// Rail transaction id that funded a prepaid MustPrepay reservation, recorded
    /// alongside `reserved_until` by the reserving path. `None` when the reserve
    /// carried no prepayment.
    reserved_payment_reference: Option<String>,
    /// Grant ceiling and delegation lineage recorded alongside `reserved_until` by
    /// the reserving path, so reconcile-by-nonce reports the grant's budget and
    /// true lineage rather than the reservation exposure. `None` for holds never
    /// marked reserved.
    reserved_budget_total: Option<u64>,
    reserved_delegation_depth: Option<u32>,
    reserved_root_budget_holder: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetMutationRequest {
    Increment {
        capability_id: String,
        grant_index: usize,
        max_invocations: Option<u32>,
    },
    Authorize {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        cost_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    },
    Reverse {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        cost_units: u64,
    },
    Release {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        cost_units: u64,
    },
    Reconcile {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    },
    Capture {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    },
}

#[derive(Debug, Clone)]
struct RecordedBudgetMutation {
    request: BudgetMutationRequest,
    record: BudgetMutationRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InvocationQuotaCounter {
    max_invocations: u32,
    reserved_count: u32,
    captured_count: u32,
    compatibility_reversible_count: u32,
}

impl InvocationQuotaCounter {
    fn invocation_count(&self) -> Result<u32, BudgetStoreError> {
        self.reserved_count
            .checked_add(self.captured_count)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "reserved invocation count + captured invocation count overflowed u32"
                        .to_string(),
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompositeBudgetHoldState {
    capability_id: String,
    grant_index: usize,
    invocation_admission: VerifiedInvocationAdmission,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    authority: Option<BudgetEventAuthority>,
    admission_operation: Option<super::BudgetAdmissionOperationBinding>,
}

impl CompositeBudgetHoldState {
    fn invocation_quotas(&self) -> &[BudgetInvocationQuota] {
        self.invocation_admission.quotas()
    }

    fn revocation_set(&self) -> &crate::supplemental_quota::CanonicalRevocationSet {
        self.invocation_admission.revocation_set()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CompositeMutationRequest {
    Authorize(Box<BudgetAuthorizeHoldRequest>),
    CaptureInvocation(BudgetCaptureInvocationRequest),
    Reverse(BudgetReverseHoldRequest),
    Release(BudgetReleaseHoldRequest),
    Reconcile(BudgetReconcileHoldRequest),
    CaptureMonetary(BudgetReconcileHoldRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CompositeMutationDecision {
    Authorize(BudgetAuthorizeHoldDecision),
    Hold(BudgetHoldMutationDecision),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCompositeMutation {
    request: CompositeMutationRequest,
    decision: CompositeMutationDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedHoldAuthorization {
    request: BudgetAuthorizeHoldRequest,
    decision: BudgetAuthorizeHoldDecision,
}

pub struct InMemoryBudgetStore {
    inner: InMemoryBudgetStoreMutex,
}

enum InMemoryBudgetStoreMutex {
    Std(StdMutex<InMemoryBudgetStoreInner>),
    #[cfg(all(test, feature = "loom-tests"))]
    Loom(LoomMutex<InMemoryBudgetStoreInner>),
}

enum InMemoryBudgetStoreGuard<'a> {
    Std(StdMutexGuard<'a, InMemoryBudgetStoreInner>),
    #[cfg(all(test, feature = "loom-tests"))]
    Loom(LoomMutexGuard<'a, InMemoryBudgetStoreInner>),
}

impl Deref for InMemoryBudgetStoreGuard<'_> {
    type Target = InMemoryBudgetStoreInner;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Std(guard) => guard,
            #[cfg(all(test, feature = "loom-tests"))]
            Self::Loom(guard) => guard,
        }
    }
}

impl DerefMut for InMemoryBudgetStoreGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Std(guard) => guard,
            #[cfg(all(test, feature = "loom-tests"))]
            Self::Loom(guard) => guard,
        }
    }
}

impl Default for InMemoryBudgetStore {
    fn default() -> Self {
        Self {
            inner: InMemoryBudgetStoreMutex::Std(
                StdMutex::new(InMemoryBudgetStoreInner::default()),
            ),
        }
    }
}

impl InMemoryBudgetStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(all(test, feature = "loom-tests"))]
    pub(crate) fn new_loom() -> Self {
        Self {
            inner: InMemoryBudgetStoreMutex::Loom(LoomMutex::new(
                InMemoryBudgetStoreInner::default(),
            )),
        }
    }

    fn lock_inner(&self) -> Result<InMemoryBudgetStoreGuard<'_>, BudgetStoreError> {
        match &self.inner {
            InMemoryBudgetStoreMutex::Std(mutex) => mutex
                .lock()
                .map(InMemoryBudgetStoreGuard::Std)
                .map_err(|_| {
                    BudgetStoreError::Invariant("in-memory budget store lock poisoned".to_string())
                }),
            #[cfg(all(test, feature = "loom-tests"))]
            InMemoryBudgetStoreMutex::Loom(mutex) => mutex
                .lock()
                .map(InMemoryBudgetStoreGuard::Loom)
                .map_err(|_| {
                    BudgetStoreError::Invariant("in-memory budget store lock poisoned".to_string())
                }),
        }
    }

    fn decision_from_legacy_record(
        &self,
        record: BudgetMutationRecord,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        Ok(BudgetHoldMutationDecision {
            hold_id: record.hold_id.clone(),
            exposure_units: record.exposure_units,
            realized_spend_units: record.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                record.total_cost_exposed_after,
                record.total_cost_realized_spend_after,
            )?,
            invocation_count_after: record.invocation_count_after,
            invocation_counts_after: record.invocation_counts_after.clone(),
            invocation_state: record.invocation_state,
            monetary_state: record.monetary_state,
            revocation_set: record.revocation_set.clone(),
            metadata: budget_commit_metadata(
                self,
                record.authority.clone(),
                record.usage_seq,
                Some(record.event_id.clone()),
            ),
        })
    }
}

#[derive(Default)]
struct InMemoryBudgetStoreInner {
    counts: HashMap<(String, usize), BudgetUsageRecord>,
    events: Vec<BudgetMutationRecord>,
    explicit_events: HashMap<String, RecordedBudgetMutation>,
    holds: HashMap<String, BudgetHoldState>,
    legacy_authorization_hold_ids: HashSet<String>,
    invocation_quotas: HashMap<BudgetQuotaKey, InvocationQuotaCounter>,
    multi_quota_managed_grants: HashSet<BudgetQuotaKey>,
    composite_holds: HashMap<String, CompositeBudgetHoldState>,
    composite_events: HashMap<String, RecordedCompositeMutation>,
    composite_authorizations: HashMap<String, RecordedHoldAuthorization>,
    next_seq: u64,
    next_event_ordinal: u64,
}

impl InMemoryBudgetStoreInner {
    fn next_event_id(&mut self) -> Result<String, BudgetStoreError> {
        self.next_event_ordinal = self.next_event_ordinal.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event ordinal overflowed u64".to_string())
        })?;
        Ok(format!(
            "{LOCAL_BUDGET_EVENT_PREFIX}{}",
            self.next_event_ordinal
        ))
    }

    fn duplicate_mutation(
        &self,
        event_id: Option<&str>,
        request: &BudgetMutationRequest,
    ) -> Result<Option<RecordedBudgetMutation>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        if event_id.starts_with(LOCAL_BUDGET_EVENT_PREFIX) {
            return Err(BudgetStoreError::Invariant(
                "explicit budget event_id uses the reserved local namespace".to_string(),
            ));
        }
        if self.composite_events.contains_key(event_id) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused across mutation namespaces"
            )));
        }
        let Some(existing) = self.explicit_events.get(event_id) else {
            return Ok(None);
        };
        if &existing.request != request {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Ok(Some(existing.clone()))
    }

    fn append_mutation(
        &mut self,
        explicit_event_id: Option<&str>,
        request: BudgetMutationRequest,
        mut record: BudgetMutationRecord,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        let event_id = match explicit_event_id {
            Some(event_id) => event_id.to_string(),
            None => self.next_event_id()?,
        };
        record.event_id = event_id.clone();
        self.events.push(record.clone());
        if explicit_event_id.is_some() {
            self.explicit_events
                .insert(event_id, RecordedBudgetMutation { request, record });
            return self.events.last().cloned().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget event journal lost appended mutation".to_string(),
                )
            });
        }
        Ok(record)
    }

    fn validate_open_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<&BudgetHoldState, BudgetStoreError> {
        let hold = self.holds.get(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing budget hold `{hold_id}`"))
        })?;
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        if hold.disposition != BudgetHoldDisposition::Open {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is no longer open"
            )));
        }
        Ok(hold)
    }

    fn validate_hold_authority(
        hold_id: &str,
        current: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match (current, requested) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` was created without authority lease metadata"
            ))),
            (Some(_), None) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` requires authority lease metadata"
            ))),
            (Some(current), Some(requested)) => {
                if current.authority_id != requested.authority_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority_id does not match the open lease"
                    )));
                }
                if requested.lease_id != current.lease_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` lease_id does not match the open lease epoch"
                    )));
                }
                if requested.lease_epoch < current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch regressed"
                    )));
                }
                if requested.lease_epoch > current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch advanced beyond the open lease"
                    )));
                }
                Ok(Some(requested.clone()))
            }
        }
    }

    fn default_usage_record(
        capability_id: &str,
        grant_index: usize,
    ) -> Result<BudgetUsageRecord, BudgetStoreError> {
        let grant_index = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        Ok(BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_exposed: 0,
            total_cost_realized_spend: 0,
        })
    }
}

impl InMemoryBudgetStoreInner {
    fn reject_legacy_admission_for_multi_quota(
        &self,
        grant_key: &BudgetQuotaKey,
    ) -> Result<(), BudgetStoreError> {
        if self.multi_quota_managed_grants.contains(grant_key) {
            return Err(BudgetStoreError::Invariant(format!(
                "grant `{}` requires composite invocation admission",
                grant_key.owner_id
            )));
        }
        Ok(())
    }

    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let quota_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
        self.reject_legacy_admission_for_multi_quota(&quota_key)?;
        let request = BudgetMutationRequest::Increment {
            capability_id: capability_id.to_string(),
            grant_index,
            max_invocations,
        };
        let usage_key = (capability_id.to_string(), grant_index);
        let current_usage = match self.counts.get(&usage_key).cloned() {
            Some(current_usage) => current_usage,
            None => Self::default_usage_record(capability_id, grant_index)?,
        };
        let quota = BudgetInvocationQuota {
            key: quota_key,
            max_invocations: max_invocations.unwrap_or(u32::MAX),
        };
        let mut counter = if let Some(existing) = self.invocation_quotas.get(&quota.key) {
            if existing.max_invocations != quota.max_invocations {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` was presented with a different maximum",
                    quota.key.owner_id
                )));
            }
            existing.clone()
        } else {
            InvocationQuotaCounter {
                max_invocations: quota.max_invocations,
                reserved_count: 0,
                captured_count: current_usage.invocation_count,
                compatibility_reversible_count: 0,
            }
        };
        if counter.invocation_count()? != current_usage.invocation_count {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from structured invocation quota".to_string(),
            ));
        }
        let current_count = counter.invocation_count()?;
        if current_count > quota.max_invocations {
            return Err(BudgetStoreError::Invariant(format!(
                "invocation quota `{}` maximum is below existing usage",
                quota.key.owner_id
            )));
        }
        let allowed = current_count < quota.max_invocations;
        let recorded_at = unix_now();
        let event_seq = self.next_composite_seq()?;
        if allowed {
            counter.captured_count = counter.captured_count.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("captured invocation count overflowed u32".to_string())
            })?;
            counter.compatibility_reversible_count = counter
                .compatibility_reversible_count
                .checked_add(1)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "compatibility reversible invocation count overflowed u32".to_string(),
                    )
                })?;
        }
        let invocation_count_after = counter.invocation_count()?;
        let invocation_state = if allowed {
            BudgetInvocationReservationState::Captured
        } else {
            BudgetInvocationReservationState::Denied
        };
        let quota_usage = Self::usage_from_counter(&quota, &counter);
        let mut updated_usage = current_usage.clone();
        if allowed {
            updated_usage.invocation_count = invocation_count_after;
            updated_usage.updated_at = recorded_at;
            updated_usage.seq = event_seq;
        }
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let record = BudgetMutationRecord {
            admission_operation: None,
            event_id: String::new(),
            hold_id: None,
            capability_id: capability_id.to_string(),
            grant_index: grant_index_u32,
            kind: BudgetMutationKind::IncrementInvocation,
            allowed: Some(allowed),
            recorded_at,
            event_seq,
            usage_seq: allowed.then_some(event_seq),
            exposure_units: 0,
            realized_spend_units: 0,
            max_invocations,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after,
            invocation_counts_after: vec![quota_usage],
            invocation_state,
            monetary_state: BudgetMonetaryHoldState::None,
            revocation_set: None,
            total_cost_exposed_after: current_usage.total_cost_exposed,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: None,
        };

        self.next_seq = event_seq;
        self.invocation_quotas.insert(quota.key, counter);
        if allowed {
            self.counts.insert(usage_key, updated_usage);
        }
        self.append_mutation(None, request, record)?;
        Ok(allowed)
    }

    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &mut self,
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
        let request = BudgetMutationRequest::Authorize {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            cost_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            return Ok(existing.record.allowed.unwrap_or(false));
        }
        if hold_id.is_some_and(|id| self.composite_authorizations.contains_key(id)) {
            return Err(BudgetStoreError::Invariant(
                "legacy hold_id collides with a composite authorization".to_string(),
            ));
        }
        if let Some(hold_id) = hold_id {
            if self.legacy_authorization_hold_ids.contains(hold_id)
                || self.holds.contains_key(hold_id)
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` already exists"
                )));
            }
        }

        let key = (capability_id.to_string(), grant_index);
        let current = match self.counts.get(&key).cloned() {
            Some(current) => current,
            None => Self::default_usage_record(capability_id, grant_index)?,
        };
        let quota = BudgetInvocationQuota {
            key: BudgetQuotaKey::grant(capability_id, grant_index)?,
            max_invocations: max_invocations.unwrap_or(u32::MAX),
        };
        self.reject_legacy_admission_for_multi_quota(&quota.key)?;
        let mut counter = if let Some(existing) = self.invocation_quotas.get(&quota.key) {
            if existing.max_invocations != quota.max_invocations {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` was presented with a different maximum",
                    quota.key.owner_id
                )));
            }
            existing.clone()
        } else {
            InvocationQuotaCounter {
                max_invocations: quota.max_invocations,
                reserved_count: 0,
                captured_count: current.invocation_count,
                compatibility_reversible_count: 0,
            }
        };
        let current_invocation_count = counter.invocation_count()?;
        if current_invocation_count != current.invocation_count {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from structured invocation quota".to_string(),
            ));
        }
        if current_invocation_count > quota.max_invocations {
            return Err(BudgetStoreError::Invariant(format!(
                "invocation quota `{}` maximum is below existing usage",
                quota.key.owner_id
            )));
        }

        let mut allowed = current_invocation_count < quota.max_invocations;
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                allowed = false;
            }
        }
        if let Some(max_total) = max_total_cost_units {
            let current_total = checked_committed_cost_units(
                current.total_cost_exposed,
                current.total_cost_realized_spend,
            )?;
            let new_total = current_total.checked_add(cost_units).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + cost_units overflowed u64".to_string(),
                )
            })?;
            if new_total > max_total {
                allowed = false;
            }
        }

        let recorded_at = unix_now();
        let (invocation_count_after, total_cost_exposed_after, total_cost_realized_spend_after);
        let event_seq;
        let mut usage_seq = None;

        if allowed {
            let new_total_cost_exposed = current
                .total_cost_exposed
                .checked_add(cost_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + cost_units overflowed u64".to_string(),
                    )
                })?;
            counter.captured_count = counter.captured_count.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("captured invocation count overflowed u32".to_string())
            })?;
            counter.compatibility_reversible_count = counter
                .compatibility_reversible_count
                .checked_add(1)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "compatibility reversible invocation count overflowed u32".to_string(),
                    )
                })?;
            event_seq = self.next_composite_seq()?;
            self.next_seq = event_seq;
            let entry = self.counts.entry(key).or_insert(current.clone());
            entry.invocation_count = counter.invocation_count()?;
            entry.total_cost_exposed = new_total_cost_exposed;
            entry.updated_at = recorded_at;
            entry.seq = event_seq;
            if let Some(hold_id) = hold_id {
                self.holds.insert(
                    hold_id.to_string(),
                    BudgetHoldState {
                        capability_id: capability_id.to_string(),
                        grant_index,
                        authorized_exposure_units: cost_units,
                        remaining_exposure_units: cost_units,
                        invocation_count_debited: true,
                        disposition: BudgetHoldDisposition::Open,
                        authority: authority.cloned(),
                        reserved_until: None,
                        reserved_currency: None,
                        reserved_payment_reference: None,
                        reserved_budget_total: None,
                        reserved_delegation_depth: None,
                        reserved_root_budget_holder: None,
                    },
                );
            }
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            usage_seq = Some(event_seq);
        } else {
            event_seq = self.next_composite_seq()?;
            self.next_seq = event_seq;
            invocation_count_after = current.invocation_count;
            total_cost_exposed_after = current.total_cost_exposed;
            total_cost_realized_spend_after = current.total_cost_realized_spend;
        }
        let quota_usage = Self::usage_from_counter(&quota, &counter);
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        self.invocation_quotas.insert(quota.key, counter);

        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                admission_operation: None,
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::AuthorizeExposure,
                allowed: Some(allowed),
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost_units,
                invocation_count_after,
                invocation_counts_after: vec![quota_usage],
                invocation_state: if allowed {
                    BudgetInvocationReservationState::Captured
                } else {
                    BudgetInvocationReservationState::Denied
                },
                monetary_state: if allowed {
                    BudgetMonetaryHoldState::Exposed
                } else {
                    BudgetMonetaryHoldState::None
                },
                revocation_set: None,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        )?;
        if let Some(hold_id) = hold_id {
            self.legacy_authorization_hold_ids
                .insert(hold_id.to_string());
        }

        Ok(allowed)
    }

    fn reverse_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        let request = BudgetMutationRequest::Reverse {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            cost_units,
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            return Ok(existing.record);
        }
        if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        }

        let key = (capability_id.to_string(), grant_index);
        let structured_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
        let mut reversed_compat_quota = self
            .invocation_quotas
            .get(&structured_key)
            .cloned()
            .map(|mut counter| {
                if counter.compatibility_reversible_count == 0 || counter.captured_count == 0 {
                    return Err(BudgetStoreError::Invariant(
                        "cannot reverse a compatibility invocation with zero captured count"
                            .to_string(),
                    ));
                }
                counter.captured_count -= 1;
                counter.compatibility_reversible_count -= 1;
                Ok(counter)
            })
            .transpose()?;
        if let Some(counter) = reversed_compat_quota.as_ref() {
            let current_count = self
                .counts
                .get(&key)
                .ok_or_else(|| {
                    BudgetStoreError::Invariant("missing charged budget row".to_string())
                })?
                .invocation_count;
            let expected = current_count.checked_sub(1).ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot reverse charge with zero invocation_count".to_string(),
                )
            })?;
            if counter.invocation_count()? != expected {
                return Err(BudgetStoreError::Invariant(
                    "compatibility quota projection diverged during reversal".to_string(),
                ));
            }
        }
        let compatibility_usage = reversed_compat_quota.as_ref().map(|counter| {
            Self::usage_from_counter(
                &BudgetInvocationQuota {
                    key: structured_key.clone(),
                    max_invocations: counter.max_invocations,
                },
                counter,
            )
        });
        let compatibility_invocation_reversed = compatibility_usage.is_some();
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_composite_seq()?;
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;
            if entry.invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse charge with zero invocation_count".to_string(),
                ));
            }
            if entry.total_cost_exposed < cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse charge larger than total_cost_exposed".to_string(),
                ));
            }
            self.next_seq = next_seq;
            entry.invocation_count -= 1;
            entry.total_cost_exposed -= cost_units;
            entry.updated_at = unix_now();
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        if let Some(counter) = reversed_compat_quota.take() {
            self.invocation_quotas.insert(structured_key, counter);
        }
        if let Some(hold_id) = hold_id {
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during reverse_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units = 0;
            hold.disposition = BudgetHoldDisposition::Reversed;
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                admission_operation: None,
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: if compatibility_invocation_reversed {
                    BudgetMutationKind::ReverseInvocations
                } else {
                    BudgetMutationKind::ReverseExposure
                },
                allowed: None,
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_counts_after: compatibility_usage.into_iter().collect(),
                invocation_state: if compatibility_invocation_reversed {
                    BudgetInvocationReservationState::Reversed
                } else {
                    BudgetInvocationReservationState::Absent
                },
                monetary_state: if cost_units == 0 {
                    BudgetMonetaryHoldState::None
                } else {
                    BudgetMonetaryHoldState::Reversed
                },
                revocation_set: None,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        )
    }

    fn reduce_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        let request = BudgetMutationRequest::Release {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            cost_units,
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            return Ok(existing.record);
        }
        if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units < cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        }

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_composite_seq()?;
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;

            if entry.total_cost_exposed < cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot reduce charge larger than total_cost_exposed".to_string(),
                ));
            }

            self.next_seq = next_seq;
            entry.total_cost_exposed -= cost_units;
            entry.updated_at = unix_now();
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        if let Some(hold_id) = hold_id {
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during release_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units -= cost_units;
            if hold.remaining_exposure_units == 0 {
                hold.disposition = BudgetHoldDisposition::Released;
            }
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                admission_operation: None,
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::ReleaseExposure,
                allowed: None,
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_counts_after: Vec::new(),
                invocation_state: BudgetInvocationReservationState::Absent,
                monetary_state: BudgetMonetaryHoldState::Released,
                revocation_set: None,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        )
    }

    fn settle_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
        )
    }

    fn settle_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.finalize_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            authority,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        self.finalize_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            authority,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        capture: bool,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        let request = if capture {
            BudgetMutationRequest::Capture {
                capability_id: capability_id.to_string(),
                grant_index,
                hold_id: hold_id.map(ToOwned::to_owned),
                authority: authority.cloned(),
                exposed_cost_units,
                realized_cost_units,
            }
        } else {
            BudgetMutationRequest::Reconcile {
                capability_id: capability_id.to_string(),
                grant_index,
                hold_id: hold_id.map(ToOwned::to_owned),
                authority: authority.cloned(),
                exposed_cost_units,
                realized_cost_units,
            }
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            return Ok(existing.record);
        }
        if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units != exposed_cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        }

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_composite_seq()?;
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;

            if entry.invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle charge with zero invocation_count".to_string(),
                ));
            }
            if entry.total_cost_exposed < exposed_cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle more exposure than total_cost_exposed".to_string(),
                ));
            }

            entry.total_cost_realized_spend = entry
                .total_cost_realized_spend
                .checked_add(realized_cost_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_realized_spend + realized_cost_units overflowed u64"
                            .to_string(),
                    )
                })?;
            entry.total_cost_exposed -= exposed_cost_units;

            self.next_seq = next_seq;
            entry.updated_at = unix_now();
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        if let Some(hold_id) = hold_id {
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during settle_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units = 0;
            hold.disposition = if capture {
                BudgetHoldDisposition::Captured
            } else {
                BudgetHoldDisposition::Reconciled
            };
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        let record = BudgetMutationRecord {
            admission_operation: None,
            event_id: String::new(),
            hold_id: hold_id.map(ToOwned::to_owned),
            capability_id: capability_id.to_string(),
            grant_index: grant_index_u32,
            kind: if capture {
                BudgetMutationKind::CaptureExposure
            } else {
                BudgetMutationKind::ReconcileSpend
            },
            allowed: None,
            recorded_at: unix_now(),
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: exposed_cost_units,
            realized_spend_units: realized_cost_units,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: if capture {
                BudgetMonetaryHoldState::Captured
            } else {
                BudgetMonetaryHoldState::Reconciled
            },
            revocation_set: None,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            authority: authority.cloned(),
        };
        let record = self.append_mutation(event_id, request, record)?;
        Ok(record)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut records = self
            .counts
            .values()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.capability_id.cmp(&right.capability_id))
                .then_with(|| left.grant_index.cmp(&right.grant_index))
        });
        records.truncate(limit);
        Ok(records)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        Ok(self
            .counts
            .get(&(capability_id.to_string(), grant_index))
            .cloned())
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let grant_index = grant_index.map(u32::try_from).transpose().map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let mut events = self
            .events
            .iter()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .filter(|record| grant_index.is_none_or(|value| record.grant_index == value))
            .cloned()
            .collect::<Vec<_>>();
        events.truncate(limit);
        Ok(events)
    }
}
