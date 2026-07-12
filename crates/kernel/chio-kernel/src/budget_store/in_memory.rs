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
    BudgetGuaranteeLevel, BudgetHoldMutationDecision, BudgetInvocationQuota,
    BudgetInvocationQuotaUsage, BudgetInvocationReservationState, BudgetMeteringProfile,
    BudgetMonetaryHoldState, BudgetMutationKind, BudgetMutationRecord, BudgetQuotaKey,
    BudgetQuotaProfile, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReleaseHoldDecision, BudgetReleaseHoldRequest, BudgetReverseHoldDecision,
    BudgetReverseHoldRequest, BudgetStore, BudgetStoreError, BudgetUsageRecord, DeniedBudgetHold,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetHoldState {
    capability_id: String,
    grant_index: usize,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    invocation_count_debited: bool,
    disposition: BudgetHoldDisposition,
    authority: Option<BudgetEventAuthority>,
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

impl InMemoryBudgetStoreInner {
    fn next_composite_seq(&self) -> Result<u64, BudgetStoreError> {
        self.next_seq
            .checked_add(1)
            .ok_or_else(|| BudgetStoreError::Overflow("budget sequence overflowed u64".to_string()))
    }

    fn composite_metadata(
        authority: Option<BudgetEventAuthority>,
        budget_commit_index: Option<u64>,
        event_id: String,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority,
            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index,
            event_id: Some(event_id),
        }
    }

    fn composite_duplicate(
        &self,
        event_id: &str,
        request: &CompositeMutationRequest,
    ) -> Result<Option<CompositeMutationDecision>, BudgetStoreError> {
        if event_id.starts_with(LOCAL_BUDGET_EVENT_PREFIX) {
            return Err(BudgetStoreError::Invariant(
                "explicit budget event_id uses the reserved local namespace".to_string(),
            ));
        }
        if self.explicit_events.contains_key(event_id) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused across mutation namespaces"
            )));
        }
        let Some(existing) = self.composite_events.get(event_id) else {
            if self
                .events
                .iter()
                .any(|existing| existing.event_id == event_id)
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{event_id}` was reused across mutation namespaces"
                )));
            }
            return Ok(None);
        };
        if &existing.request != request {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different composite mutation"
            )));
        }
        Ok(Some(existing.decision.clone()))
    }

    fn record_composite_mutation(
        &mut self,
        event_id: String,
        request: CompositeMutationRequest,
        decision: CompositeMutationDecision,
        record: BudgetMutationRecord,
    ) {
        self.events.push(record);
        self.composite_events
            .insert(event_id, RecordedCompositeMutation { request, decision });
    }

    fn monetary_present(request: &BudgetAuthorizeHoldRequest) -> bool {
        request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some()
    }

    fn usage_from_counter(
        quota: &BudgetInvocationQuota,
        counter: &InvocationQuotaCounter,
    ) -> BudgetInvocationQuotaUsage {
        BudgetInvocationQuotaUsage {
            quota: quota.clone(),
            reserved_invocations_after: counter.reserved_count,
            captured_invocations_after: counter.captured_count,
        }
    }

    fn invocation_usages(
        &self,
        quotas: &[BudgetInvocationQuota],
    ) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        quotas
            .iter()
            .map(|quota| {
                let counter = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key.owner_id
                    ))
                })?;
                Ok(Self::usage_from_counter(quota, counter))
            })
            .collect()
    }

    fn validate_composite_hold_identity(
        hold_id: &str,
        hold: &CompositeBudgetHoldState,
        capability_id: &str,
        grant_index: usize,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        Ok(())
    }

    fn authorize_composite_budget_hold(
        &mut self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.invocation_quotas().is_empty() {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold requires invocation quotas".to_string(),
            ));
        }
        if request.max_invocations.is_some() {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold must not also present legacy max_invocations".to_string(),
            ));
        }
        validate_invocation_quotas(request.invocation_quotas())?;
        let invocation_admission = request.invocation_admission.clone().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "composite budget hold requires verified invocation admission".to_string(),
            )
        })?;
        let manages_multiple_quotas = invocation_admission.quotas().len() > 1;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite budget hold requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite budget hold requires event_id".to_string())
        })?;
        let revocation_set = request.revocation_set().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "composite budget hold requires a canonical revocation set".to_string(),
            )
        })?;
        revocation_set.validate().map_err(|error| {
            BudgetStoreError::Invariant(format!("invalid canonical revocation set: {error}"))
        })?;
        if revocation_set
            .ids()
            .binary_search(&request.capability_id)
            .is_err()
        {
            return Err(BudgetStoreError::Invariant(
                "canonical revocation set omits the leaf capability".to_string(),
            ));
        }

        let composite_request = CompositeMutationRequest::Authorize(Box::new(request.clone()));
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Authorize(decision) => Ok(decision),
                CompositeMutationDecision::Hold(_) => Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{event_id}` has the wrong decision kind"
                ))),
            };
        }
        if let Some(existing) = self.composite_authorizations.get(hold_id) {
            if existing.request != request {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` was reused for a different authorization"
                )));
            }
            return Ok(existing.decision.clone());
        }
        if self.legacy_authorization_hold_ids.contains(hold_id) || self.holds.contains_key(hold_id)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` collides with a legacy hold"
            )));
        }

        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut saw_primary = false;
        for quota in request.invocation_quotas() {
            if quota.key.profile == BudgetQuotaProfile::GrantInvocation {
                if quota.key != primary_key || saw_primary {
                    return Err(BudgetStoreError::Invariant(
                        "composite budget hold has an ambiguous grant invocation quota".to_string(),
                    ));
                }
                saw_primary = true;
            }
        }
        if !saw_primary {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold omits the matched grant invocation quota".to_string(),
            ));
        }
        if !manages_multiple_quotas && self.multi_quota_managed_grants.contains(&primary_key) {
            return Err(BudgetStoreError::Invariant(format!(
                "grant `{}` requires composite invocation admission",
                primary_key.owner_id
            )));
        }

        let primary_usage = match self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
        {
            Some(primary_usage) => primary_usage,
            None => Self::default_usage_record(&request.capability_id, request.grant_index)?,
        };
        let mut staged_counters = Vec::with_capacity(request.invocation_quotas().len());
        let mut quota_exhausted = false;
        for quota in request.invocation_quotas() {
            let counter = if let Some(existing) = self.invocation_quotas.get(&quota.key) {
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
                    captured_count: if quota.key == primary_key {
                        primary_usage.invocation_count
                    } else {
                        0
                    },
                    compatibility_reversible_count: 0,
                }
            };
            let current_count = counter.invocation_count()?;
            if current_count > quota.max_invocations {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` maximum is below existing usage",
                    quota.key.owner_id
                )));
            }
            if current_count == quota.max_invocations {
                quota_exhausted = true;
            }
            staged_counters.push((quota.clone(), counter));
        }
        let staged_primary_count = staged_counters
            .iter()
            .find(|(quota, _)| quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota counter".to_string())
            })?
            .1
            .invocation_count()?;
        if staged_primary_count != primary_usage.invocation_count {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite invocation quota".to_string(),
            ));
        }

        let monetary_present = Self::monetary_present(&request);
        let current_committed = primary_usage.committed_cost_units()?;
        let new_committed = current_committed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let new_exposure = primary_usage
            .total_cost_exposed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total exposed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let monetary_denied = request
            .max_cost_per_invocation
            .is_some_and(|maximum| request.requested_exposure_units > maximum)
            || request
                .max_total_cost_units
                .is_some_and(|maximum| new_committed > maximum);
        let allowed = !quota_exhausted && !monetary_denied;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();

        if allowed {
            for (_, counter) in &mut staged_counters {
                counter.reserved_count =
                    counter.reserved_count.checked_add(1).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved invocation count overflowed u32".to_string(),
                        )
                    })?;
            }
        }
        let invocation_counts_after = staged_counters
            .iter()
            .map(|(quota, counter)| Self::usage_from_counter(quota, counter))
            .collect::<Vec<_>>();
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let invocation_state = if allowed {
            BudgetInvocationReservationState::Authorized
        } else {
            BudgetInvocationReservationState::Denied
        };
        let monetary_state = if allowed && monetary_present {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let committed_cost_units_after = if allowed {
            new_committed
        } else {
            current_committed
        };
        let metadata = Self::composite_metadata(
            request.authority.clone(),
            allowed.then_some(seq),
            event_id.to_string(),
        );
        let decision = if allowed {
            BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
                hold_id: request.hold_id.clone(),
                authorized_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: primary_count_after,
                invocation_counts_after: invocation_counts_after.clone(),
                invocation_state,
                monetary_state,
                revocation_set: request.revocation_set().cloned(),
                metadata: metadata.clone(),
            })
        } else {
            BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id.clone(),
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: primary_count_after,
                invocation_counts_after: invocation_counts_after.clone(),
                invocation_state,
                monetary_state,
                revocation_set: request.revocation_set().cloned(),
                metadata: metadata.clone(),
            })
        };

        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let record = BudgetMutationRecord {
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::ReserveInvocations,
            allowed: Some(allowed),
            recorded_at,
            event_seq: seq,
            usage_seq: allowed.then_some(seq),
            exposure_units: request.requested_exposure_units,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: request.max_cost_per_invocation,
            max_total_cost_units: request.max_total_cost_units,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state,
            monetary_state,
            revocation_set: request.revocation_set().cloned(),
            total_cost_exposed_after: if allowed {
                new_exposure
            } else {
                primary_usage.total_cost_exposed
            },
            total_cost_realized_spend_after: primary_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };

        self.next_seq = seq;
        for (quota, counter) in staged_counters {
            self.invocation_quotas.insert(quota.key, counter);
        }
        if allowed {
            let entry = self
                .counts
                .entry((request.capability_id.clone(), request.grant_index))
                .or_insert(primary_usage.clone());
            entry.invocation_count = primary_count_after;
            entry.total_cost_exposed = new_exposure;
            entry.updated_at = recorded_at;
            entry.seq = seq;
            self.composite_holds.insert(
                hold_id.to_string(),
                CompositeBudgetHoldState {
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    invocation_admission,
                    invocation_state,
                    monetary_state,
                    authorized_exposure_units: request.requested_exposure_units,
                    remaining_exposure_units: request.requested_exposure_units,
                    authority: request.authority.clone(),
                },
            );
        }
        self.composite_authorizations.insert(
            hold_id.to_string(),
            RecordedHoldAuthorization {
                request: request.clone(),
                decision: decision.clone(),
            },
        );
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Authorize(decision.clone()),
            record,
        );
        if manages_multiple_quotas {
            self.multi_quota_managed_grants.insert(primary_key);
        }
        Ok(decision)
    }

    fn capture_composite_invocations(
        &mut self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::CaptureInvocation(request.clone());
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }

        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation reservation is not authorized"
            )));
        }

        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut staged_counters = Vec::with_capacity(hold.invocation_quotas().len());
        for quota in hold.invocation_quotas() {
            let mut counter = self
                .invocation_quotas
                .get(&quota.key)
                .cloned()
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key.owner_id
                    ))
                })?;
            if counter.max_invocations != quota.max_invocations || counter.reserved_count == 0 {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key.owner_id
                )));
            }
            counter.reserved_count -= 1;
            counter.captured_count = counter.captured_count.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("captured invocation count overflowed u32".to_string())
            })?;
            staged_counters.push((quota.clone(), counter));
        }
        let invocation_counts_after = staged_counters
            .iter()
            .map(|(quota, counter)| Self::usage_from_counter(quota, counter))
            .collect::<Vec<_>>();
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        if current_usage.invocation_count != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let metadata =
            Self::composite_metadata(request.authority.clone(), Some(seq), event_id.to_string());
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: 0,
            realized_spend_units: 0,
            committed_cost_units_after: current_usage.committed_cost_units()?,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: hold.monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata,
        };

        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let record = BudgetMutationRecord {
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::CaptureInvocations,
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 0,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: hold.monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: current_usage.total_cost_exposed,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.invocation_state = BudgetInvocationReservationState::Captured;

        self.next_seq = seq;
        for (quota, counter) in staged_counters {
            self.invocation_quotas.insert(quota.key, counter);
        }
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn reverse_composite_hold(
        &mut self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::Reverse(request.clone());
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }
        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation reservation cannot be reversed"
            )));
        }
        match hold.monetary_state {
            BudgetMonetaryHoldState::Exposed => {
                if hold.remaining_exposure_units != request.reversed_exposure_units {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` reverse amount does not match exposure"
                    )));
                }
            }
            BudgetMonetaryHoldState::None
            | BudgetMonetaryHoldState::Released
            | BudgetMonetaryHoldState::Reversed => {
                if request.reversed_exposure_units != 0 {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` has no reversible monetary exposure"
                    )));
                }
            }
            BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary state cannot be reversed"
                )));
            }
        }

        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut staged_counters = Vec::with_capacity(hold.invocation_quotas().len());
        for quota in hold.invocation_quotas() {
            let mut counter = self
                .invocation_quotas
                .get(&quota.key)
                .cloned()
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key.owner_id
                    ))
                })?;
            if counter.max_invocations != quota.max_invocations || counter.reserved_count == 0 {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key.owner_id
                )));
            }
            counter.reserved_count -= 1;
            staged_counters.push((quota.clone(), counter));
        }
        let invocation_counts_after = staged_counters
            .iter()
            .map(|(quota, counter)| Self::usage_from_counter(quota, counter))
            .collect::<Vec<_>>();
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        let new_exposure = current_usage
            .total_cost_exposed
            .checked_sub(request.reversed_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot reverse more than total exposed cost".to_string(),
                )
            })?;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let monetary_state = match hold.monetary_state {
            BudgetMonetaryHoldState::Exposed => BudgetMonetaryHoldState::Reversed,
            BudgetMonetaryHoldState::None
            | BudgetMonetaryHoldState::Released
            | BudgetMonetaryHoldState::Reversed => hold.monetary_state,
            BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary state cannot be reversed"
                )));
            }
        };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: new_exposure
                .checked_add(current_usage.total_cost_realized_spend)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow("committed cost overflowed u64".to_string())
                })?,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: BudgetInvocationReservationState::Reversed,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata: Self::composite_metadata(
                request.authority.clone(),
                Some(seq),
                event_id.to_string(),
            ),
        };
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let record = BudgetMutationRecord {
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::ReverseInvocations,
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Reversed,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: new_exposure,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.invocation_count = primary_count_after;
        updated_usage.total_cost_exposed = new_exposure;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.invocation_state = BudgetInvocationReservationState::Reversed;
        updated_hold.monetary_state = monetary_state;
        updated_hold.remaining_exposure_units = 0;

        self.next_seq = seq;
        for (quota, counter) in staged_counters {
            self.invocation_quotas.insert(quota.key, counter);
        }
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn release_composite_hold(
        &mut self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::Release(request.clone());
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }
        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || request.released_exposure_units > hold.remaining_exposure_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` cannot release the requested exposure"
            )));
        }
        if matches!(
            hold.invocation_state,
            BudgetInvocationReservationState::Reversed
                | BudgetInvocationReservationState::Denied
                | BudgetInvocationReservationState::Absent
        ) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state cannot release monetary exposure"
            )));
        }

        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        let new_exposure = current_usage
            .total_cost_exposed
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot release more than total exposed cost".to_string(),
                )
            })?;
        let remaining_exposure = hold
            .remaining_exposure_units
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("cannot release more than hold exposure".to_string())
            })?;
        let monetary_state = if remaining_exposure == 0 {
            BudgetMonetaryHoldState::Released
        } else {
            BudgetMonetaryHoldState::Exposed
        };
        let invocation_counts_after = self.invocation_usages(hold.invocation_quotas())?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let committed_cost_units_after = new_exposure
            .checked_add(current_usage.total_cost_realized_spend)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("committed cost overflowed u64".to_string())
            })?;
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata: Self::composite_metadata(
                request.authority.clone(),
                Some(seq),
                event_id.to_string(),
            ),
        };
        let record = BudgetMutationRecord {
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::ReleaseExposure,
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: new_exposure,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.total_cost_exposed = new_exposure;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.remaining_exposure_units = remaining_exposure;
        updated_hold.monetary_state = monetary_state;

        self.next_seq = seq;
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn settle_composite_hold(
        &mut self,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires event_id".to_string())
        })?;
        let composite_request = if capture {
            CompositeMutationRequest::CaptureMonetary(request.clone())
        } else {
            CompositeMutationRequest::Reconcile(request.clone())
        };
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }
        if request.realized_spend_units > request.exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "realized spend exceeds exposed cost".to_string(),
            ));
        }
        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || hold.remaining_exposure_units != request.exposed_cost_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not contain the settled exposure"
            )));
        }
        if matches!(
            hold.invocation_state,
            BudgetInvocationReservationState::Reversed
                | BudgetInvocationReservationState::Denied
                | BudgetInvocationReservationState::Absent
        ) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state cannot settle monetary exposure"
            )));
        }

        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        let new_exposure = current_usage
            .total_cost_exposed
            .checked_sub(request.exposed_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot settle more than total exposed cost".to_string(),
                )
            })?;
        let new_realized = current_usage
            .total_cost_realized_spend
            .checked_add(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("realized spend overflowed u64".to_string())
            })?;
        let committed_cost_units_after =
            new_exposure.checked_add(new_realized).ok_or_else(|| {
                BudgetStoreError::Overflow("committed cost overflowed u64".to_string())
            })?;
        let invocation_counts_after = self.invocation_usages(hold.invocation_quotas())?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let monetary_state = if capture {
            BudgetMonetaryHoldState::Captured
        } else {
            BudgetMonetaryHoldState::Reconciled
        };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata: Self::composite_metadata(
                request.authority.clone(),
                Some(seq),
                event_id.to_string(),
            ),
        };
        let record = BudgetMutationRecord {
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: if capture {
                BudgetMutationKind::CaptureExposure
            } else {
                BudgetMutationKind::ReconcileSpend
            },
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: new_exposure,
            total_cost_realized_spend_after: new_realized,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.total_cost_exposed = new_exposure;
        updated_usage.total_cost_realized_spend = new_realized;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.remaining_exposure_units = 0;
        updated_hold.monetary_state = monetary_state;

        self.next_seq = seq;
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }
}

impl BudgetStore for InMemoryBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

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
        self.lock_inner()?.try_charge_cost_with_ids(
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
        self.lock_inner()?.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map(|_| ())
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|_| ())
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
        self.lock_inner()?
            .reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map(|_| ())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map(|_| ())
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|_| ())
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
        self.lock_inner()?
            .reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map(|_| ())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map(|_| ())
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost_with_ids(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
            )
            .map(|_| ())
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
        self.lock_inner()?
            .settle_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map(|_| ())
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        self.lock_inner()?
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn authorize_budget_hold(
        &self,
        mut request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request.invocation_admission.is_none() {
            let admission = VerifiedInvocationAdmission::grant_only(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
            )?;
            request.max_invocations = None;
            request.install_verified_invocation_admission(admission)?;
        }
        inner.authorize_composite_budget_hold(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.reverse_composite_hold(request);
        }
        let record = inner.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.decision_from_legacy_record(record)
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.release_composite_hold(request);
        }
        let record = inner.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.decision_from_legacy_record(record)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.settle_composite_hold(request, false);
        }
        let record = inner.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.decision_from_legacy_record(record)
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.settle_composite_hold(request, true);
        }
        let record = inner.capture_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
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

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.lock_inner()?.capture_composite_invocations(request)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
