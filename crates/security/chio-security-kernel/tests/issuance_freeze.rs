use std::sync::{Arc, Mutex};

use chio_security_kernel::IssuanceFreezeAdmission;
use chio_security_types::ports::{
    ActionId, CapabilityIssuanceOperation, Digest32, EffectId, EffectResultQuery,
    IssuanceFreezeAdmissionDecision, IssuanceFreezeAdmissionQuery, IssuanceFreezeApplyRequest,
    IssuanceFreezeContribution, IssuanceFreezeKey, IssuanceFreezeMatch, IssuanceFreezeMatches,
    IssuanceFreezeOperationStatus, IssuanceFreezeRemoveRequest, IssuanceFreezeSnapshot,
    IssuanceFreezeStore, LineageId, PortError, PortErrorKind, PortResult, RecordId, TenantId,
};

#[derive(Clone, Copy)]
enum Behavior {
    Allow,
    Freeze,
    Fail,
    Tamper,
}

struct FakeFreezes {
    behavior: Behavior,
    queries: Mutex<Vec<IssuanceFreezeAdmissionQuery>>,
}

impl FakeFreezes {
    fn new(behavior: Behavior) -> Self {
        Self {
            behavior,
            queries: Mutex::new(Vec::new()),
        }
    }

    fn queries(&self) -> Vec<IssuanceFreezeAdmissionQuery> {
        self.queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl IssuanceFreezeStore for FakeFreezes {
    fn ensure_issuance_freezes_ready(&self) -> PortResult<()> {
        Err(PortError::unavailable())
    }

    fn apply_issuance_freeze(
        &self,
        _: &IssuanceFreezeApplyRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        Err(PortError::unavailable())
    }

    fn prepare_issuance_freeze_remove(
        &self,
        _: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeContribution> {
        Err(PortError::unavailable())
    }

    fn complete_issuance_freeze_remove(
        &self,
        _: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        Err(PortError::unavailable())
    }

    fn load_issuance_freezes(
        &self,
        _: &IssuanceFreezeKey,
    ) -> PortResult<Option<IssuanceFreezeSnapshot>> {
        Err(PortError::unavailable())
    }

    fn evaluate_issuance_freeze(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision> {
        if matches!(self.behavior, Behavior::Fail) {
            return Err(PortError::unavailable());
        }
        self.queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(query.clone());
        let frozen = matches!(self.behavior, Behavior::Freeze | Behavior::Tamper);
        let active_matches = if frozen {
            IssuanceFreezeMatches::new(vec![IssuanceFreezeMatch {
                action_id: ActionId::new("freeze-action")
                    .unwrap_or_else(|error| panic!("action: {error}")),
                effect_id: EffectId::new("freeze-effect")
                    .unwrap_or_else(|error| panic!("effect: {error}")),
                commit_index: 11,
                affected_set_hash: Digest32::new([1_u8; 32]),
                contribution_hash: Digest32::new([2_u8; 32]),
                expires_at_unix_ms: u64::MAX,
            }])
            .unwrap_or_else(|error| panic!("matches: {error}"))
        } else {
            IssuanceFreezeMatches::new(Vec::new())
                .unwrap_or_else(|error| panic!("matches: {error}"))
        };
        let mut reflected_query = query.clone();
        if matches!(self.behavior, Behavior::Tamper) {
            reflected_query.lineage_id =
                LineageId::new("wrong-lineage").unwrap_or_else(|error| panic!("lineage: {error}"));
        }
        Ok(IssuanceFreezeAdmissionDecision {
            query: reflected_query,
            frozen,
            active_matches,
        })
    }

    fn load_issuance_freeze_operation(
        &self,
        _: &EffectResultQuery,
    ) -> PortResult<IssuanceFreezeOperationStatus> {
        Err(PortError::unavailable())
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-admission").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn lineage() -> LineageId {
    LineageId::new("capability-root").unwrap_or_else(|error| panic!("lineage: {error}"))
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record: {error}"))
}

fn issue_query() -> IssuanceFreezeAdmissionQuery {
    IssuanceFreezeAdmissionQuery {
        tenant_id: tenant(),
        lineage_id: lineage(),
        operation: CapabilityIssuanceOperation::Issue,
        parent_capability_id: None,
    }
}

fn delegate_query() -> IssuanceFreezeAdmissionQuery {
    IssuanceFreezeAdmissionQuery {
        tenant_id: tenant(),
        lineage_id: lineage(),
        operation: CapabilityIssuanceOperation::Delegate,
        parent_capability_id: Some(record("capability-child")),
    }
}

#[test]
fn issue_and_delegate_use_the_exact_authoritative_context() {
    let store = Arc::new(FakeFreezes::new(Behavior::Allow));
    let freezes: Arc<dyn IssuanceFreezeStore> = store.clone();
    let admission = IssuanceFreezeAdmission::new(freezes);
    admission
        .authorize(&issue_query())
        .unwrap_or_else(|error| panic!("authorize issue: {error:?}"));
    admission
        .authorize(&delegate_query())
        .unwrap_or_else(|error| panic!("authorize delegate: {error:?}"));
    assert_eq!(store.queries(), vec![issue_query(), delegate_query()]);
}

#[test]
fn active_freeze_store_outage_and_tamper_all_fail_closed() {
    for behavior in [Behavior::Freeze, Behavior::Fail, Behavior::Tamper] {
        let store: Arc<dyn IssuanceFreezeStore> = Arc::new(FakeFreezes::new(behavior));
        let admission = IssuanceFreezeAdmission::new(store);
        for query in [issue_query(), delegate_query()] {
            let error = admission
                .authorize(&query)
                .err()
                .unwrap_or_else(|| panic!("frozen operation unexpectedly authorized"));
            assert!(matches!(
                error.kind(),
                PortErrorKind::Conflict
                    | PortErrorKind::Unavailable
                    | PortErrorKind::IntegrityFailure
            ));
        }
    }
}

#[test]
fn malformed_parent_shape_is_rejected_before_store_access() {
    let store = Arc::new(FakeFreezes::new(Behavior::Allow));
    let freezes: Arc<dyn IssuanceFreezeStore> = store.clone();
    let admission = IssuanceFreezeAdmission::new(freezes);
    let mut malformed_issue = issue_query();
    malformed_issue.parent_capability_id = Some(record("unexpected-parent"));
    let mut malformed_delegate = delegate_query();
    malformed_delegate.parent_capability_id = None;
    for query in [malformed_issue, malformed_delegate] {
        let error = admission
            .authorize(&query)
            .err()
            .unwrap_or_else(|| panic!("malformed operation unexpectedly authorized"));
        assert_eq!(error.kind(), PortErrorKind::InvalidData);
    }
    assert!(store.queries().is_empty());
}
