use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(test, feature = "loom-tests"))]
use loom::sync::{Mutex as LoomMutex, MutexGuard as LoomMutexGuard};

use super::{
    budget_commit_metadata, checked_committed_cost_units, validate_invocation_quotas,
    AuthorizedBudgetHold, BudgetAuthorizationPolicy, BudgetAuthorityProfile,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureHoldDecision,
    BudgetCaptureHoldRequest, BudgetCaptureInvocationRequest, BudgetCommitMetadata,
    BudgetEventAuthority, BudgetGuaranteeLevel, BudgetHoldDispositionView,
    BudgetHoldMutationDecision, BudgetHoldSnapshot, BudgetInvocationQuota,
    BudgetInvocationQuotaUsage, BudgetInvocationReservationState, BudgetMeteringProfile,
    BudgetMonetaryHoldState, BudgetMutationKind, BudgetMutationRecord, BudgetQuotaKey,
    BudgetQuotaProfile, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReleaseHoldDecision, BudgetReleaseHoldRequest, BudgetReverseHoldDecision,
    BudgetReverseHoldRequest, BudgetStore, BudgetStoreError, BudgetUsageRecord, DeniedBudgetHold,
    ReservedHoldEnvelope, VerifiedInvocationAdmission,
};

const LOCAL_BUDGET_EVENT_PREFIX: &str = "local-budget-event-";

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetHoldDisposition {
    Open,
    Released,
    Reversed,
    Reconciled,
    Captured,
    Expired,
}

impl BudgetHoldDisposition {
    fn view(&self) -> BudgetHoldDispositionView {
        match self {
            Self::Open => BudgetHoldDispositionView::Open,
            Self::Released => BudgetHoldDispositionView::Released,
            Self::Reversed => BudgetHoldDispositionView::Reversed,
            Self::Reconciled => BudgetHoldDispositionView::Reconciled,
            Self::Captured => BudgetHoldDispositionView::Captured,
            Self::Expired => BudgetHoldDispositionView::Expired,
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
    authorization_metadata: BudgetCommitMetadata,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvocationQuotaMutationMode {
    Reserve,
    CaptureCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvocationQuotaMutationAction {
    Attempt,
    Reverse,
}

#[derive(Debug)]
struct InvocationQuotaMutationOutcome {
    allowed: bool,
    invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    primary_count_after: u32,
}

#[derive(Debug)]
struct LegacyAuthorizationMutationOutcome {
    allowed: bool,
    committed_cost_units_after: u64,
    record: BudgetMutationRecord,
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
    authorization_metadata: BudgetCommitMetadata,
    admission_operation: Option<super::BudgetAdmissionOperationBinding>,
    reserved_until: Option<i64>,
    reserved_currency: Option<String>,
    reserved_payment_reference: Option<String>,
    reserved_budget_total: Option<u64>,
    reserved_delegation_depth: Option<u32>,
    reserved_root_budget_holder: Option<String>,
    expired: bool,
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
    fn next_event_id(&self) -> Result<(String, u64), BudgetStoreError> {
        let next_ordinal = self.next_event_ordinal.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event ordinal overflowed u64".to_string())
        })?;
        Ok((
            format!("{LOCAL_BUDGET_EVENT_PREFIX}{next_ordinal}"),
            next_ordinal,
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
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Ok(Some(existing.clone()))
    }

    fn prepare_mutation_event_id(
        &self,
        explicit_event_id: Option<&str>,
    ) -> Result<(String, bool, Option<u64>), BudgetStoreError> {
        match explicit_event_id {
            Some(event_id) => Ok((event_id.to_string(), true, None)),
            None => self
                .next_event_id()
                .map(|(event_id, ordinal)| (event_id, false, Some(ordinal))),
        }
    }

    fn append_prepared_mutation(
        &mut self,
        event_id: String,
        explicitly_claimed: bool,
        next_local_ordinal: Option<u64>,
        request: BudgetMutationRequest,
        mut record: BudgetMutationRecord,
    ) -> BudgetMutationRecord {
        if let Some(next_local_ordinal) = next_local_ordinal {
            self.next_event_ordinal = next_local_ordinal;
        }
        record.event_id = event_id.clone();
        let result = record.clone();
        self.events.push(record.clone());
        if explicitly_claimed {
            self.explicit_events
                .insert(event_id, RecordedBudgetMutation { request, record });
        }
        result
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
        let recorded_at = unix_now();
        let event_seq = self.next_composite_seq()?;
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let (prepared_event_id, explicitly_claimed, next_local_ordinal) =
            self.prepare_mutation_event_id(None)?;
        let mutation = self.compare_and_mutate_invocation_quotas(
            std::slice::from_ref(&quota),
            &quota.key,
            current_usage.invocation_count,
            InvocationQuotaMutationMode::CaptureCompatibility,
            InvocationQuotaMutationAction::Attempt,
            || Ok(false),
        )?;
        let allowed = mutation.allowed;
        let invocation_count_after = mutation.primary_count_after;
        let invocation_state = if allowed {
            BudgetInvocationReservationState::Captured
        } else {
            BudgetInvocationReservationState::Denied
        };
        let mut updated_usage = current_usage.clone();
        if allowed {
            updated_usage.invocation_count = invocation_count_after;
            updated_usage.updated_at = recorded_at;
            updated_usage.seq = event_seq;
        }
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
            invocation_counts_after: mutation.invocation_counts_after,
            invocation_state,
            monetary_state: BudgetMonetaryHoldState::None,
            revocation_set: None,
            total_cost_exposed_after: current_usage.total_cost_exposed,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: None,
        };

        self.next_seq = event_seq;
        if allowed {
            self.counts.insert(usage_key, updated_usage);
        }
        self.append_prepared_mutation(
            prepared_event_id,
            explicitly_claimed,
            next_local_ordinal,
            request,
            record,
        );
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
        .map(|outcome| outcome.allowed)
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
    ) -> Result<LegacyAuthorizationMutationOutcome, BudgetStoreError> {
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
            let record = existing.record;
            if record.kind != BudgetMutationKind::AuthorizeExposure {
                return Err(BudgetStoreError::Invariant(
                    "budget authorization replay resolved to the wrong decision event".to_string(),
                ));
            }
            let allowed = record.allowed.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget authorization decision event omitted its outcome".to_string(),
                )
            })?;
            let committed_cost_units_after = checked_committed_cost_units(
                record.total_cost_exposed_after,
                record.total_cost_realized_spend_after,
            )?;
            return Ok(LegacyAuthorizationMutationOutcome {
                allowed,
                committed_cost_units_after,
                record,
            });
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
        let current_committed = checked_committed_cost_units(
            current.total_cost_exposed,
            current.total_cost_realized_spend,
        )?;
        let mut committed_if_allowed = current_committed;
        let mut exposed_if_allowed = current.total_cost_exposed;
        let recorded_at = unix_now();
        let event_seq = self.next_composite_seq()?;
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let (prepared_event_id, explicitly_claimed, next_local_ordinal) =
            self.prepare_mutation_event_id(event_id)?;
        let mutation = self.compare_and_mutate_invocation_quotas(
            std::slice::from_ref(&quota),
            &quota.key,
            current.invocation_count,
            InvocationQuotaMutationMode::CaptureCompatibility,
            InvocationQuotaMutationAction::Attempt,
            || {
                if max_cost_per_invocation.is_some_and(|max| cost_units > max) {
                    return Ok(true);
                }
                let prospective_committed = match current_committed.checked_add(cost_units) {
                    Some(prospective) => prospective,
                    None if max_total_cost_units.is_some() => return Ok(true),
                    None => {
                        return Err(BudgetStoreError::Overflow(
                            "authorized exposure + cost_units overflowed u64".to_string(),
                        ));
                    }
                };
                if max_total_cost_units.is_some_and(|maximum| prospective_committed > maximum) {
                    return Ok(true);
                }
                let prospective_exposed = current
                    .total_cost_exposed
                    .checked_add(cost_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "total_cost_exposed + cost_units overflowed u64".to_string(),
                        )
                    })?;
                committed_if_allowed = prospective_committed;
                exposed_if_allowed = prospective_exposed;
                Ok(false)
            },
        )?;
        let allowed = mutation.allowed;
        let invocation_count_after = mutation.primary_count_after;
        let (total_cost_exposed_after, total_cost_realized_spend_after) = if allowed {
            (exposed_if_allowed, current.total_cost_realized_spend)
        } else {
            (
                current.total_cost_exposed,
                current.total_cost_realized_spend,
            )
        };
        if allowed {
            let entry = self.counts.entry(key).or_insert(current.clone());
            entry.invocation_count = invocation_count_after;
            entry.total_cost_exposed = exposed_if_allowed;
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
                        authorization_metadata: Self::composite_metadata(
                            authority.cloned(),
                            Some(event_seq),
                            prepared_event_id.clone(),
                        ),
                        reserved_until: None,
                        reserved_currency: None,
                        reserved_payment_reference: None,
                        reserved_budget_total: None,
                        reserved_delegation_depth: None,
                        reserved_root_budget_holder: None,
                    },
                );
            }
        }
        self.next_seq = event_seq;
        let record = self.append_prepared_mutation(
            prepared_event_id,
            explicitly_claimed,
            next_local_ordinal,
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
                usage_seq: allowed.then_some(event_seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost_units,
                invocation_count_after,
                invocation_counts_after: mutation.invocation_counts_after,
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
        );
        if let Some(hold_id) = hold_id {
            self.legacy_authorization_hold_ids
                .insert(hold_id.to_string());
        }

        Ok(LegacyAuthorizationMutationOutcome {
            allowed,
            committed_cost_units_after: if allowed {
                committed_if_allowed
            } else {
                current_committed
            },
            record,
        })
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
        let updated_hold = if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
            let mut updated = hold.clone();
            updated.remaining_exposure_units = 0;
            updated.disposition = BudgetHoldDisposition::Reversed;
            updated.authority = authority.cloned().or_else(|| updated.authority.clone());
            Some((hold_id.to_string(), updated))
        } else {
            None
        };

        let key = (capability_id.to_string(), grant_index);
        let structured_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
        let current =
            self.counts.get(&key).cloned().ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;
        if current.invocation_count == 0 {
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if current.total_cost_exposed < cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_exposed".to_string(),
            ));
        }
        let max_invocations = self
            .invocation_quotas
            .get(&structured_key)
            .map_or(u32::MAX, |counter| counter.max_invocations);
        let quota = BudgetInvocationQuota {
            key: structured_key,
            max_invocations,
        };
        let grant_index_u32 = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let next_seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let (prepared_event_id, explicitly_claimed, next_local_ordinal) =
            self.prepare_mutation_event_id(event_id)?;
        let mutation = self.compare_and_mutate_invocation_quotas(
            std::slice::from_ref(&quota),
            &quota.key,
            current.invocation_count,
            InvocationQuotaMutationMode::CaptureCompatibility,
            InvocationQuotaMutationAction::Reverse,
            || Ok(false),
        )?;
        let mut updated = current;
        updated.invocation_count = mutation.primary_count_after;
        updated.total_cost_exposed -= cost_units;
        updated.updated_at = recorded_at;
        updated.seq = next_seq;
        let total_cost_exposed_after = updated.total_cost_exposed;
        let total_cost_realized_spend_after = updated.total_cost_realized_spend;
        self.next_seq = next_seq;
        self.counts.insert(key, updated);
        if let Some((hold_id, hold)) = updated_hold {
            self.holds.insert(hold_id, hold);
        }
        Ok(self.append_prepared_mutation(
            prepared_event_id,
            explicitly_claimed,
            next_local_ordinal,
            request,
            BudgetMutationRecord {
                admission_operation: None,
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::ReverseExposure,
                allowed: None,
                recorded_at,
                event_seq: next_seq,
                usage_seq: Some(next_seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: mutation.primary_count_after,
                invocation_counts_after: mutation.invocation_counts_after,
                invocation_state: BudgetInvocationReservationState::Reversed,
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
        ))
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
        let updated_hold = if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units < cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
            let mut updated = hold.clone();
            updated.remaining_exposure_units -= cost_units;
            if updated.remaining_exposure_units == 0 {
                updated.disposition = BudgetHoldDisposition::Released;
            }
            updated.authority = authority.cloned().or_else(|| updated.authority.clone());
            Some((hold_id.to_string(), updated))
        } else {
            None
        };

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
        let (prepared_event_id, explicitly_claimed, next_local_ordinal) =
            self.prepare_mutation_event_id(event_id)?;
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
        if let Some((hold_id, hold)) = updated_hold {
            self.holds.insert(hold_id, hold);
        }
        Ok(self.append_prepared_mutation(
            prepared_event_id,
            explicitly_claimed,
            next_local_ordinal,
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
        ))
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
        let updated_hold = if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units != exposed_cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
            let mut updated = hold.clone();
            updated.remaining_exposure_units = 0;
            updated.disposition = if capture {
                BudgetHoldDisposition::Captured
            } else {
                BudgetHoldDisposition::Reconciled
            };
            updated.authority = authority.cloned().or_else(|| updated.authority.clone());
            Some((hold_id.to_string(), updated))
        } else {
            None
        };

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
        let (prepared_event_id, explicitly_claimed, next_local_ordinal) =
            self.prepare_mutation_event_id(event_id)?;
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
        if let Some((hold_id, hold)) = updated_hold {
            self.holds.insert(hold_id, hold);
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
        let record = self.append_prepared_mutation(
            prepared_event_id,
            explicitly_claimed,
            next_local_ordinal,
            request,
            record,
        );
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
