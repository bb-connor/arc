use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::security::adapters::effect_port::{
    IssuanceFreezeBackend, LineageFenceMaintenanceResult, ResponseEffectBackend,
};
use chio_core::canonical::canonical_json_bytes;
use chio_quarantine::{
    build_response_plan, prepare_response_dispatch, EffectMutation, EffectMutationRequest,
    ResponseDispatchPreparationRequest, ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_types::ports::{
    empty_issuance_freeze_snapshot, issuance_freeze_version_hash, response_affected_set_hash,
    ActionId, BlastRadiusFenceAcquisition, BlastRadiusPort, BlastRadiusQueryBounds,
    BlastRadiusRequest, BlastRadiusResult, BlastRadiusSeeds, BlastRadiusSnapshotMetadata,
    CanonicalBody, CapabilityIssuanceOperation, Digest32, EffectExecutionStatus, EffectId,
    EffectOperation, EffectRequest, EffectResultQuery, IssuanceFreezeAdmissionDecision,
    IssuanceFreezeAdmissionQuery, IssuanceFreezeApplyRequest, IssuanceFreezeContribution,
    IssuanceFreezeContributions, IssuanceFreezeFenceMaintenanceRequest, IssuanceFreezeKey,
    IssuanceFreezeMatches, IssuanceFreezeOperationStatus, IssuanceFreezePendingRelease,
    IssuanceFreezeRemoveRequest, IssuanceFreezeSnapshot, IssuanceFreezeSpec, IssuanceFreezeStore,
    LeaseOwnerId, LineageFence, LineageFenceMaintenanceRequest, LineageFenceRelease,
    LineageFenceRenewal, LineageFenceRequest, LineageFenceTakeover, LineageId, OpaqueReceiptRef,
    PortError, PortErrorKind, PortResult, RecordId, RecordIdSet, ResponseCasRequest,
    ResponseDispatchApproval, ResponseDispatchLease, ResponseEffectCasRequest, ResponseEffectKey,
    ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord, ResponseScheduledMutationCasRequest,
    ResponseSchedulerStore, ResponseStore, ScheduledWork, SchedulerClaimRequest,
    SchedulerHealthAckRequest, SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest,
    SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponsePlan, ResponsePlanInput, ResponseState, ResponseTarget,
};

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

fn tenant() -> TenantId {
    TenantId::new("tenant-freeze-backend").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn lineage() -> LineageId {
    LineageId::new("capability-root").unwrap_or_else(|error| panic!("lineage: {error}"))
}

fn action() -> ActionId {
    ActionId::new("freeze-backend-action").unwrap_or_else(|error| panic!("action: {error}"))
}

fn effect() -> EffectId {
    EffectId::new("freeze-backend-effect").unwrap_or_else(|error| panic!("effect: {error}"))
}

fn record(value: impl Into<String>) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record: {error}"))
}

fn digest(value: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(value).as_bytes())
}

fn maintained_fence(result: LineageFenceMaintenanceResult) -> LineageFence {
    match result {
        LineageFenceMaintenanceResult::Maintained(fence) => fence,
        LineageFenceMaintenanceResult::ReleaseCompleted => {
            panic!("maintenance unexpectedly completed release")
        }
    }
}

fn key() -> IssuanceFreezeKey {
    IssuanceFreezeKey {
        tenant_id: tenant(),
        lineage_id: lineage(),
    }
}

fn spec() -> (IssuanceFreezeSpec, u64) {
    let now_unix_ms = now_unix_ms();
    let plan_expires_at_unix_ms = now_unix_ms.saturating_add(120_000);
    let fence_expires_at_unix_ms = now_unix_ms.saturating_add(30_000);
    let bounds = BlastRadiusQueryBounds {
        max_depth: 8,
        max_nodes: 128,
        max_edges: 256,
    };
    let affected = RecordIdSet::new(vec![record("capability-child"), record("capability-root")])
        .unwrap_or_else(|error| panic!("affected set: {error}"));
    let affected_set_hash = response_affected_set_hash(&tenant(), &affected)
        .unwrap_or_else(|error| panic!("affected hash: {error}"));
    (
        IssuanceFreezeSpec {
            lineage_id: lineage(),
            acquisition: BlastRadiusFenceAcquisition {
                request: BlastRadiusRequest {
                    tenant_id: tenant(),
                    action_id: action(),
                    seed_ids: BlastRadiusSeeds::new(vec![record("capability-root")])
                        .unwrap_or_else(|error| panic!("seeds: {error}")),
                    query_bounds: bounds.clone(),
                },
                approved_result: BlastRadiusResult::Exact {
                    metadata: BlastRadiusSnapshotMetadata {
                        query_bounds: bounds,
                        source_lineage_version: 9,
                        commit_index: 21,
                        authoritative_commit_index: 21,
                        completeness_watermark: Some(21),
                    },
                    sorted_affected_ids: affected,
                    affected_set_hash,
                    graph_slice_hash: Digest32::new([9_u8; 32]),
                },
                expires_at_unix_ms: fence_expires_at_unix_ms,
            },
        },
        plan_expires_at_unix_ms,
    )
}

fn apply_request() -> EffectRequest {
    let (spec, expires_at_unix_ms) = spec();
    let body = canonical_json_bytes(&spec).unwrap_or_else(|error| panic!("freeze spec: {error}"));
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    EffectRequest {
        tenant_id: tenant(),
        action_id: action(),
        plan_hash: digest(b"freeze-backend-plan"),
        effect_id: effect(),
        effect_kind: ResponseEffectKind::FreezeIssuance,
        target: ResponseTarget::Lineage {
            lineage_id: lineage(),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record("response_effect_command:freeze-backend-apply"),
        expected_version_hash: issuance_freeze_version_hash(&empty)
            .unwrap_or_else(|error| panic!("empty version: {error}")),
        scheduler_lease_owner_id: LeaseOwnerId::new("freeze-backend-worker")
            .unwrap_or_else(|error| panic!("scheduler owner: {error}")),
        scheduler_fencing_token: 11,
        canonical_contribution: CanonicalBody::new(body.clone())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        contribution_hash: digest(&body),
    }
}

fn replace_approved_affected_set(request: &mut EffectRequest, affected_ids: Vec<RecordId>) {
    let mut spec: IssuanceFreezeSpec =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .unwrap_or_else(|error| panic!("decode freeze contribution: {error}"));
    let affected_ids = RecordIdSet::new(affected_ids)
        .unwrap_or_else(|error| panic!("replacement affected set: {error}"));
    let affected_set_hash = response_affected_set_hash(&request.tenant_id, &affected_ids)
        .unwrap_or_else(|error| panic!("replacement affected-set hash: {error:?}"));
    let BlastRadiusResult::Exact {
        sorted_affected_ids,
        affected_set_hash: approved_hash,
        ..
    } = &mut spec.acquisition.approved_result
    else {
        panic!("freeze contribution is not exact");
    };
    *sorted_affected_ids = affected_ids;
    *approved_hash = affected_set_hash;
    let body = canonical_json_bytes(&spec)
        .unwrap_or_else(|error| panic!("canonicalize replacement freeze: {error}"));
    request.canonical_contribution = CanonicalBody::new(body.clone())
        .unwrap_or_else(|error| panic!("replacement canonical body: {error}"));
    request.contribution_hash = digest(&body);
}

fn remove_request(apply: &EffectRequest, installed_hash: Digest32) -> EffectRequest {
    let mut request = apply.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record("response_effect_command:freeze-backend-remove");
    request.expected_version_hash = installed_hash;
    request
}

fn query(request: &EffectRequest) -> EffectResultQuery {
    EffectResultQuery {
        tenant_id: request.tenant_id.clone(),
        action_id: request.action_id.clone(),
        plan_hash: request.plan_hash,
        effect_id: request.effect_id.clone(),
        effect_kind: request.effect_kind,
        target: request.target.clone(),
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key.clone(),
        expected_version_hash: request.expected_version_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
        contribution_hash: request.contribution_hash,
    }
}

#[derive(Default)]
struct FreezeModel {
    snapshot: Option<IssuanceFreezeSnapshot>,
    operations: BTreeMap<String, (EffectRequest, IssuanceFreezeOperationStatus)>,
    pending_releases: BTreeMap<String, IssuanceFreezePendingRelease>,
    completed_releases: BTreeMap<String, chio_security_types::ports::IssuanceFreezeCommand>,
    fail_apply_after_commit: bool,
    fail_prepare_after_commit: bool,
    fail_complete_before_commit: bool,
    fail_complete_after_commit: bool,
    fail_maintenance_after_commit: bool,
}

#[derive(Default)]
struct FakeFreezeStore {
    model: Mutex<FreezeModel>,
}

impl FakeFreezeStore {
    fn inject_ack_loss(&self) {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        model.fail_apply_after_commit = true;
        model.fail_prepare_after_commit = true;
        model.fail_complete_after_commit = true;
    }

    fn lose_next_maintenance_ack(&self) {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fail_maintenance_after_commit = true;
    }

    fn fail_next_complete_before_commit(&self) {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fail_complete_before_commit = true;
    }
}

impl IssuanceFreezeStore for FakeFreezeStore {
    fn ensure_issuance_freezes_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn apply_issuance_freeze(
        &self,
        request: &IssuanceFreezeApplyRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        model.snapshot = Some(request.command.resulting_snapshot.clone());
        model.operations.insert(
            request.command.request.idempotency_key.as_str().to_owned(),
            (
                request.command.request.clone(),
                IssuanceFreezeOperationStatus::Completed {
                    result: request.command.result.clone(),
                },
            ),
        );
        if std::mem::take(&mut model.fail_apply_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(request.command.resulting_snapshot.clone())
    }

    fn prepare_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeContribution> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let contribution = model
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.contributions.as_slice().first())
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
        model.operations.insert(
            request.command.request.idempotency_key.as_str().to_owned(),
            (
                request.command.request.clone(),
                IssuanceFreezeOperationStatus::ReleasePending {
                    contribution: Box::new(contribution.clone()),
                },
            ),
        );
        model.pending_releases.insert(
            request.command.request.idempotency_key.as_str().to_owned(),
            IssuanceFreezePendingRelease {
                request: request.clone(),
                contribution: contribution.clone(),
            },
        );
        if std::mem::take(&mut model.fail_prepare_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(contribution)
    }

    fn complete_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if std::mem::take(&mut model.fail_complete_before_commit) {
            return Err(PortError::unavailable());
        }
        model.snapshot = Some(request.command.resulting_snapshot.clone());
        model.operations.insert(
            request.command.request.idempotency_key.as_str().to_owned(),
            (
                request.command.request.clone(),
                IssuanceFreezeOperationStatus::Completed {
                    result: request.command.result.clone(),
                },
            ),
        );
        model
            .pending_releases
            .remove(request.command.request.idempotency_key.as_str());
        model.completed_releases.insert(
            request.command.request.idempotency_key.as_str().to_owned(),
            request.command.clone(),
        );
        if std::mem::take(&mut model.fail_complete_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(request.command.resulting_snapshot.clone())
    }

    fn load_issuance_freezes(
        &self,
        _: &IssuanceFreezeKey,
    ) -> PortResult<Option<IssuanceFreezeSnapshot>> {
        Ok(self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot
            .clone())
    }

    fn evaluate_issuance_freeze(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision> {
        query
            .operation
            .validate_parent(query.parent_capability_id.as_ref())?;
        Ok(IssuanceFreezeAdmissionDecision {
            query: query.clone(),
            frozen: false,
            active_matches: IssuanceFreezeMatches::new(Vec::new())
                .map_err(|_| PortError::integrity_failure())?,
        })
    }

    fn load_issuance_freeze_operation(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<IssuanceFreezeOperationStatus> {
        let model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((request, status)) = model.operations.get(query.idempotency_key.as_str()) else {
            return Ok(IssuanceFreezeOperationStatus::NotExecuted);
        };
        if &crate_query(request) != query {
            return Err(PortError::conflict());
        }
        Ok(status.clone())
    }

    fn load_pending_issuance_freeze_release(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        effect_id: &EffectId,
    ) -> PortResult<Option<IssuanceFreezePendingRelease>> {
        let model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut matches = model.pending_releases.values().filter(|pending| {
            &pending.request.key == key
                && &pending.request.action_id == action_id
                && &pending.request.effect_id == effect_id
        });
        let first = matches.next().cloned();
        if matches.next().is_some() {
            return Err(PortError::integrity_failure());
        }
        Ok(first)
    }

    fn load_completed_issuance_freeze_release(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        effect_id: &EffectId,
        plan_hash: Digest32,
    ) -> PortResult<Option<chio_security_types::ports::IssuanceFreezeCommand>> {
        let model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut matches = model.completed_releases.values().filter(|command| {
            command.request.tenant_id == key.tenant_id
                && matches!(
                    &command.request.target,
                    ResponseTarget::Lineage { lineage_id } if lineage_id == &key.lineage_id
                )
                && &command.request.action_id == action_id
                && &command.request.effect_id == effect_id
                && command.request.plan_hash == plan_hash
        });
        let first = matches.next().cloned();
        if matches.next().is_some() {
            return Err(PortError::integrity_failure());
        }
        Ok(first)
    }

    fn maintain_issuance_freeze_fence(
        &self,
        request: &IssuanceFreezeFenceMaintenanceRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut snapshot = model
            .snapshot
            .clone()
            .ok_or_else(PortError::integrity_failure)?;
        let contribution = snapshot
            .contributions
            .as_slice()
            .iter()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
        if contribution.external_fence == request.maintained_external_fence {
            return Ok(snapshot);
        }
        if contribution.external_fence != request.expected_external_fence {
            return Err(PortError::conflict());
        }
        let mut contributions = snapshot.contributions.into_vec();
        let entry = contributions
            .iter_mut()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .ok_or_else(PortError::integrity_failure)?;
        entry.external_fence = request.maintained_external_fence.clone();
        snapshot.contributions = IssuanceFreezeContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?;
        snapshot.generation = snapshot.generation.saturating_add(1);
        snapshot.highest_scheduler_fencing_token = snapshot
            .highest_scheduler_fencing_token
            .max(request.scheduler_work.fencing_token);
        model.snapshot = Some(snapshot.clone());
        if std::mem::take(&mut model.fail_maintenance_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(snapshot)
    }
}

fn crate_query(request: &EffectRequest) -> EffectResultQuery {
    query(request)
}

#[derive(Default)]
struct BlastModel {
    fence: Option<LineageFence>,
    next_token: u64,
    readiness_failed: bool,
    fail_acquire_after_commit: bool,
    fail_release_before_commit: bool,
    fail_release_after_commit: bool,
    fail_renew_after_commit: bool,
    fail_takeover_after_commit: bool,
    release_count: usize,
}

#[derive(Default)]
struct FakeBlastRadius {
    model: Mutex<BlastModel>,
}

impl FakeBlastRadius {
    fn fail_readiness(&self) {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .readiness_failed = true;
    }

    fn inject_ack_loss(&self) {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        model.fail_acquire_after_commit = true;
        model.fail_release_after_commit = true;
    }

    fn fail_next_release_before_commit(&self) {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fail_release_before_commit = true;
    }

    fn lose_next_renewal_ack(&self) {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fail_renew_after_commit = true;
    }

    fn lose_next_takeover_ack(&self) {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fail_takeover_after_commit = true;
    }
}

impl BlastRadiusPort for FakeBlastRadius {
    fn ensure_blast_radius_ready(&self) -> PortResult<()> {
        if self
            .model
            .lock()
            .map_err(|_| PortError::unavailable())?
            .readiness_failed
        {
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn resolve(&self, _: &BlastRadiusRequest) -> PortResult<BlastRadiusResult> {
        Err(PortError::unavailable())
    }

    fn acquire_fence(
        &self,
        acquisition: &BlastRadiusFenceAcquisition,
        expected: &LineageFenceRequest,
    ) -> PortResult<LineageFence> {
        let BlastRadiusResult::Exact {
            metadata,
            affected_set_hash,
            ..
        } = &acquisition.approved_result
        else {
            return Err(PortError::invalid_data());
        };
        if expected.tenant_id != acquisition.request.tenant_id
            || expected.action_id != acquisition.request.action_id
            || expected.expected_commit_index != metadata.commit_index
            || expected.expected_affected_set_hash != *affected_set_hash
            || expected.expires_at_unix_ms != acquisition.expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        model.next_token = model.next_token.saturating_add(1).max(1);
        let fence = LineageFence {
            tenant_id: acquisition.request.tenant_id.clone(),
            action_id: acquisition.request.action_id.clone(),
            commit_index: metadata.commit_index,
            affected_set_hash: *affected_set_hash,
            fencing_token: model.next_token,
            scheduler_lease_owner_id: expected.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: expected.scheduler_fencing_token,
            expires_at_unix_ms: acquisition.expires_at_unix_ms,
        };
        model.fence = Some(fence.clone());
        if std::mem::take(&mut model.fail_acquire_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(fence)
    }

    fn query_fence(&self, expected: &LineageFenceRequest) -> PortResult<Option<LineageFence>> {
        let model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fence) = model.fence.as_ref() else {
            return Ok(None);
        };
        if fence.tenant_id != expected.tenant_id
            || fence.action_id != expected.action_id
            || fence.commit_index != expected.expected_commit_index
            || fence.affected_set_hash != expected.expected_affected_set_hash
            || fence.scheduler_lease_owner_id != expected.scheduler_lease_owner_id
            || fence.scheduler_fencing_token != expected.scheduler_fencing_token
            || fence.expires_at_unix_ms < expected.expires_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        Ok(Some(fence.clone()))
    }

    fn renew_fence(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fence = model
            .fence
            .as_ref()
            .ok_or_else(PortError::integrity_failure)?;
        if fence.tenant_id != renewal.tenant_id
            || fence.action_id != renewal.action_id
            || fence.fencing_token != renewal.fencing_token
            || fence.scheduler_lease_owner_id != renewal.scheduler_lease_owner_id
            || fence.scheduler_fencing_token != renewal.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        if fence.expires_at_unix_ms == renewal.renewed_expires_at_unix_ms {
            return Ok(fence.clone());
        }
        if fence.expires_at_unix_ms != renewal.expected_expires_at_unix_ms
            || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        let fence = model
            .fence
            .as_mut()
            .ok_or_else(PortError::integrity_failure)?;
        fence.expires_at_unix_ms = renewal.renewed_expires_at_unix_ms;
        let renewed = fence.clone();
        if std::mem::take(&mut model.fail_renew_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(renewed)
    }

    fn takeover_fence(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fence = model
            .fence
            .as_ref()
            .ok_or_else(PortError::integrity_failure)?;
        if fence.tenant_id != takeover.tenant_id
            || fence.action_id != takeover.action_id
            || fence.fencing_token != takeover.expected_fencing_token
            || fence.scheduler_lease_owner_id != takeover.expected_scheduler_lease_owner_id
            || fence.scheduler_fencing_token != takeover.expected_scheduler_fencing_token
            || fence.expires_at_unix_ms != takeover.expected_expires_at_unix_ms
            || takeover.successor_scheduler_fencing_token <= fence.scheduler_fencing_token
            || takeover.successor_expires_at_unix_ms < fence.expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        model.next_token = model.next_token.saturating_add(1).max(1);
        let next_token = model.next_token;
        let fence = model
            .fence
            .as_mut()
            .ok_or_else(PortError::integrity_failure)?;
        fence.fencing_token = next_token;
        fence.scheduler_lease_owner_id = takeover.successor_scheduler_lease_owner_id.clone();
        fence.scheduler_fencing_token = takeover.successor_scheduler_fencing_token;
        fence.expires_at_unix_ms = takeover.successor_expires_at_unix_ms;
        let taken_over = fence.clone();
        if std::mem::take(&mut model.fail_takeover_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(taken_over)
    }

    fn release_fence(&self, release: &LineageFenceRelease) -> PortResult<()> {
        let mut model = self
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if std::mem::take(&mut model.fail_release_before_commit) {
            return Err(PortError::unavailable());
        }
        let fence = model
            .fence
            .as_ref()
            .ok_or_else(PortError::integrity_failure)?;
        if fence.tenant_id != release.tenant_id
            || fence.action_id != release.action_id
            || fence.fencing_token != release.fencing_token
            || fence.scheduler_lease_owner_id != release.scheduler_lease_owner_id
            || fence.scheduler_fencing_token != release.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        model.release_count = model.release_count.saturating_add(1);
        model.fence = None;
        if std::mem::take(&mut model.fail_release_after_commit) {
            return Err(PortError::unavailable());
        }
        Ok(())
    }
}

struct FakeSchedulerStore {
    work: Mutex<ScheduledWork>,
    plan: Mutex<ResponsePlanRecord>,
}

impl FakeSchedulerStore {
    fn new(work: ScheduledWork, plan: ResponsePlanRecord) -> Self {
        Self {
            work: Mutex::new(work),
            plan: Mutex::new(plan),
        }
    }

    fn install(&self, work: ScheduledWork) {
        *self
            .work
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = work;
    }

    fn mark_effect_applied(
        self: &Arc<Self>,
        effect_id: &EffectId,
        resulting_version_hash: Digest32,
    ) {
        let machine = ResponseStateMachine::new(Arc::clone(self));
        let current = self
            .plan
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let snapshot = chio_quarantine::decode_response_record(&current)
            .unwrap_or_else(|error| panic!("decode applying response: {error}"));
        let requested = machine
            .record_effect(
                &current,
                &EffectMutationRequest {
                    expected_generation: current.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(1),
                    mutation: EffectMutation::Requested,
                },
            )
            .unwrap_or_else(|error| panic!("record requested freeze: {error}"));
        machine
            .record_effect(
                &requested,
                &EffectMutationRequest {
                    expected_generation: requested.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(2),
                    mutation: EffectMutation::Applied {
                        resulting_version_hash,
                    },
                },
            )
            .unwrap_or_else(|error| panic!("record applied freeze: {error}"));
    }

    fn mark_effect_rollback_requested(self: &Arc<Self>, effect_id: &EffectId) {
        let machine = ResponseStateMachine::new(Arc::clone(self));
        let current = self
            .plan
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let snapshot = chio_quarantine::decode_response_record(&current)
            .unwrap_or_else(|error| panic!("decode applied response: {error}"));
        let active = machine
            .transition(
                &current,
                &ResponseTransitionRequest {
                    expected_generation: current.generation,
                    target_state: ResponseState::Active,
                    occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(3),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )
            .unwrap_or_else(|error| panic!("activate response: {error}"));
        let rolling_back = machine
            .transition(
                &active,
                &ResponseTransitionRequest {
                    expected_generation: active.generation,
                    target_state: ResponseState::RollingBack,
                    occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(4),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )
            .unwrap_or_else(|error| panic!("start rollback: {error}"));
        machine
            .record_effect(
                &rolling_back,
                &EffectMutationRequest {
                    expected_generation: rolling_back.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(5),
                    mutation: EffectMutation::RollbackRequested,
                },
            )
            .unwrap_or_else(|error| panic!("record freeze rollback request: {error}"));
    }
}

impl ResponseStore for FakeSchedulerStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        let plan = self.plan.lock().map_err(|_| PortError::unavailable())?;
        if key.tenant_id == plan.tenant_id && key.action_id == plan.action_id {
            Ok(Some(plan.clone()))
        } else {
            Ok(None)
        }
    }

    fn create(
        &self,
        _record: &ResponsePlanRecord,
    ) -> PortResult<chio_security_types::ports::CreateOutcome> {
        Err(PortError::unavailable())
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        let mut plan = self.plan.lock().map_err(|_| PortError::unavailable())?;
        if plan.tenant_id != request.record.tenant_id
            || plan.action_id != request.record.action_id
            || plan.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        *plan = request.record.clone();
        Ok(request.record.clone())
    }

    fn load_effect(&self, _key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        Err(PortError::unavailable())
    }

    fn persist_effect(
        &self,
        _record: &ResponseEffectRecord,
    ) -> PortResult<chio_security_types::ports::CreateOutcome> {
        Err(PortError::unavailable())
    }

    fn compare_and_swap_effect(
        &self,
        _request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        Err(PortError::unavailable())
    }

    fn claim_due(&self, _request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        Err(PortError::unavailable())
    }
}

impl ResponseSchedulerStore for FakeSchedulerStore {
    fn load_retry(&self, _key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        Err(PortError::unavailable())
    }

    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()> {
        if *self.work.lock().map_err(|_| PortError::unavailable())? == *work {
            Ok(())
        } else {
            Err(PortError::conflict())
        }
    }

    fn compare_and_swap_scheduled_mutation(
        &self,
        request: &ResponseScheduledMutationCasRequest,
    ) -> PortResult<ResponsePlanRecord> {
        let work = self.work.lock().map_err(|_| PortError::unavailable())?;
        if *work != request.work {
            return Err(PortError::conflict());
        }
        let mut plan = self.plan.lock().map_err(|_| PortError::unavailable())?;
        if *plan != request.current {
            return Err(PortError::conflict());
        }
        *plan = request.candidate.clone();
        Ok(request.candidate.clone())
    }

    fn validate_lease_identity(
        &self,
        tenant_id: &TenantId,
        action_id: &ActionId,
        lease_owner_id: &LeaseOwnerId,
        fencing_token: u64,
    ) -> PortResult<()> {
        let work = self.work.lock().map_err(|_| PortError::unavailable())?;
        if &work.tenant_id == tenant_id
            && &work.action_id == action_id
            && &work.lease_owner_id == lease_owner_id
            && work.fencing_token == fencing_token
        {
            Ok(())
        } else {
            Err(PortError::conflict())
        }
    }

    fn renew_lease(&self, _request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork> {
        Err(PortError::unavailable())
    }

    fn record_retry(&self, _request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState> {
        Err(PortError::unavailable())
    }

    fn acknowledge_health_event(
        &self,
        _request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState> {
        Err(PortError::unavailable())
    }

    fn release_lease(&self, _request: &SchedulerLeaseReleaseRequest) -> PortResult<()> {
        Err(PortError::unavailable())
    }
}

fn backend(
    freezes: Arc<FakeFreezeStore>,
    blast: Arc<FakeBlastRadius>,
    apply: &mut EffectRequest,
) -> IssuanceFreezeBackend {
    let plan = maintenance_plan(apply);
    let work = scheduler_work(apply);
    let scheduler = Arc::new(FakeSchedulerStore::new(
        work.clone(),
        response_plan_record(&plan, &work),
    ));
    let freeze_port: Arc<dyn IssuanceFreezeStore> = freezes;
    let blast_port: Arc<dyn BlastRadiusPort> = blast;
    let scheduler_port: Arc<dyn ResponseSchedulerStore> = scheduler;
    IssuanceFreezeBackend::new_with_scheduler(freeze_port, blast_port, scheduler_port)
}

fn maintenance_plan(apply: &mut EffectRequest) -> ResponsePlan {
    let ttl_ms = 120_000;
    let created_at_unix_ms = apply
        .plan_expires_at_unix_ms
        .checked_sub(ttl_ms)
        .unwrap_or_else(|| panic!("plan expiry is shorter than maintenance test TTL"));
    let plan = build_response_plan(ResponsePlanInput {
        action_id: apply.action_id.clone(),
        trigger_finding_id: record("freeze-maintenance-finding"),
        trigger_finding_hash: digest(b"freeze-maintenance-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("freeze-maintenance-receipt")
            .unwrap_or_else(|error| panic!("finding receipt: {error}")),
        tenant_id: apply.tenant_id.clone(),
        policy_version: record("freeze-maintenance-policy"),
        policy_hash: digest(b"freeze-maintenance-policy"),
        affected_ids: vec![record("capability-child"), record("capability-root")],
        effects: vec![ResponseEffectSpec {
            kind: apply.effect_kind,
            target: apply.target.clone(),
            canonical_contribution: apply.canonical_contribution.clone(),
            contribution_hash: apply.contribution_hash,
            observed_base_version_hash: apply.expected_version_hash,
        }],
        ttl_ms,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("freeze-maintenance-capability"),
            capability_digest: digest(b"freeze-maintenance-capability"),
            expires_at_unix_ms: apply.plan_expires_at_unix_ms.saturating_add(60_000),
            executor_subject: record("freeze-maintenance-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("freeze-maintenance-submitter"),
        reason_hash: digest(b"freeze-maintenance-reason"),
    })
    .unwrap_or_else(|error| panic!("build maintenance plan: {error}"));
    let planned_effect = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("maintenance effect missing"));
    apply.plan_hash = plan.plan_hash;
    apply.effect_id = planned_effect.effect_id.clone();
    plan
}

fn scheduler_work(apply: &EffectRequest) -> ScheduledWork {
    ScheduledWork {
        tenant_id: apply.tenant_id.clone(),
        action_id: apply.action_id.clone(),
        lease_owner_id: apply.scheduler_lease_owner_id.clone(),
        lease_expires_at_unix_ms: now_unix_ms().saturating_add(30_000),
        fencing_token: apply.scheduler_fencing_token,
    }
}

fn response_plan_record(plan: &ResponsePlan, work: &ScheduledWork) -> ResponsePlanRecord {
    prepare_response_dispatch(ResponseDispatchPreparationRequest {
        plan: plan.clone(),
        dispatch_id: record("freeze-backend-dispatch"),
        authorization_capability_hash: plan.operator_capability.capability_digest,
        governed_intent_hash: digest(b"freeze-backend-governed-intent"),
        policy_decision_hash: digest(b"freeze-backend-policy-decision"),
        executor_authority_id: record("freeze-backend-executor-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: plan.created_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: work.lease_owner_id.clone(),
            lease_expires_at_unix_ms: work.lease_expires_at_unix_ms,
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    })
    .unwrap_or_else(|error| panic!("prepare freeze response dispatch: {error}"))
    .response_plan
}

#[test]
fn readiness_requires_both_local_freeze_and_blast_radius_authorities() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    backend
        .ensure_ready()
        .unwrap_or_else(|error| panic!("healthy readiness failed: {error:?}"));
    blast.fail_readiness();
    let error = backend
        .ensure_ready()
        .err()
        .unwrap_or_else(|| panic!("blast-radius outage unexpectedly reported ready"));
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
}

#[test]
fn no_scheduler_backend_cannot_apply_an_unbound_issuance_freeze() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let freeze_port: Arc<dyn IssuanceFreezeStore> = freezes.clone();
    let blast_port: Arc<dyn BlastRadiusPort> = blast.clone();
    let backend = IssuanceFreezeBackend::new(freeze_port, blast_port);
    let request = apply_request();

    let error = backend
        .execute(&request)
        .err()
        .unwrap_or_else(|| panic!("unbound issuance freeze unexpectedly applied"));
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert!(blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_none());
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|load_error| panic!("load unbound freeze store: {load_error:?}"))
        .is_none());
}

#[test]
fn plan_binding_rejects_narrower_and_broader_approved_sets_before_mutation() {
    let exact_freezes = Arc::new(FakeFreezeStore::default());
    let exact_blast = Arc::new(FakeBlastRadius::default());
    let mut exact = apply_request();
    let exact_backend = backend(
        Arc::clone(&exact_freezes),
        Arc::clone(&exact_blast),
        &mut exact,
    );
    assert!(
        exact_backend
            .execute(&exact)
            .unwrap_or_else(|error| panic!("exact approved set rejected: {error:?}"))
            .applied
    );
    assert!(exact_blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_some());
    assert!(exact_freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load exact freeze: {error:?}"))
        .is_some());

    for (label, affected_ids) in [
        ("narrower", vec![record("capability-root")]),
        (
            "broader",
            vec![
                record("capability-child"),
                record("capability-extra"),
                record("capability-root"),
            ],
        ),
    ] {
        let freezes = Arc::new(FakeFreezeStore::default());
        let blast = Arc::new(FakeBlastRadius::default());
        let mut request = apply_request();
        let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut request);
        replace_approved_affected_set(&mut request, affected_ids);

        let error = backend
            .execute(&request)
            .err()
            .unwrap_or_else(|| panic!("{label} approved set unexpectedly applied"));
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
        assert!(blast
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fence
            .is_none());
        assert!(freezes
            .load_issuance_freezes(&key())
            .unwrap_or_else(|load_error| panic!("load {label} freeze store: {load_error:?}"))
            .is_none());
        assert!(freezes
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .operations
            .is_empty());
    }
}

#[test]
fn apply_and_remove_reconcile_every_ack_loss_boundary() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    freezes.inject_ack_loss();
    blast.inject_ack_loss();
    let mut apply = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply with ack loss: {error:?}"));
    assert!(applied.applied);
    assert!(blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_some());

    let remove = remove_request(&apply, applied.resulting_version_hash);
    let removed = backend
        .execute(&remove)
        .unwrap_or_else(|error| panic!("remove with ack loss: {error:?}"));
    assert!(!removed.applied);
    assert!(blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_none());
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load lifted snapshot: {error:?}"))
        .unwrap_or_else(|| panic!("snapshot missing"))
        .contributions
        .is_empty());
}

#[test]
fn completed_apply_load_result_requires_the_live_external_fence() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply freeze before result query: {error:?}"));
    assert_eq!(
        backend
            .load_result(&query(&apply))
            .unwrap_or_else(|error| panic!("load verified apply result: {error:?}")),
        EffectExecutionStatus::Completed {
            result: applied.clone()
        }
    );

    blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence = None;
    let error = backend
        .load_result(&query(&apply))
        .err()
        .unwrap_or_else(|| panic!("completed apply survived a missing external fence"));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn release_outage_keeps_local_freeze_pending_until_retry() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply freeze: {error:?}"));
    let remove = remove_request(&apply, applied.resulting_version_hash);
    blast.fail_next_release_before_commit();
    let error = backend
        .execute(&remove)
        .err()
        .unwrap_or_else(|| panic!("release outage unexpectedly succeeded"));
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert!(!freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|load_error| panic!("load pending freeze: {load_error:?}"))
        .unwrap_or_else(|| panic!("pending snapshot missing"))
        .contributions
        .is_empty());
    assert_eq!(
        backend
            .load_result(&query(&remove))
            .unwrap_or_else(|load_error| panic!("load pending result: {load_error:?}")),
        EffectExecutionStatus::Unknown
    );
    assert!(
        !backend
            .execute(&remove)
            .unwrap_or_else(|retry_error| panic!("retry pending release: {retry_error:?}"))
            .applied
    );
}

#[test]
fn malformed_operation_shape_is_rejected_before_any_mutation() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut request = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut request);
    request.target = ResponseTarget::Tenant {
        tenant_id: tenant(),
    };
    let error = backend
        .execute(&request)
        .err()
        .unwrap_or_else(|| panic!("malformed freeze unexpectedly succeeded"));
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|load_error| panic!("load untouched store: {load_error:?}"))
        .is_none());
    let admission = IssuanceFreezeAdmissionQuery {
        tenant_id: tenant(),
        lineage_id: lineage(),
        operation: CapabilityIssuanceOperation::Issue,
        parent_capability_id: None,
    };
    assert!(
        !freezes
            .evaluate_issuance_freeze(&admission)
            .unwrap_or_else(|evaluate_error| panic!("evaluate untouched store: {evaluate_error:?}"))
            .frozen
    );
}

#[test]
fn rejected_apply_never_leaves_an_orphan_fence() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut request = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut request);
    request.expected_version_hash = Digest32::new([88_u8; 32]);
    let error = backend
        .execute(&request)
        .err()
        .unwrap_or_else(|| panic!("stale base version unexpectedly applied"));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert!(blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_none());
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|load_error| panic!("load rejected store: {load_error:?}"))
        .is_none());
    assert!(freezes
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .operations
        .is_empty());
}

#[test]
fn expired_external_fence_can_be_lifted_from_the_recorded_set() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply before expiry: {error:?}"));
    blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence = None;
    let remove = remove_request(&apply, applied.resulting_version_hash);
    let lifted = backend
        .execute(&remove)
        .unwrap_or_else(|error| panic!("lift expired fence: {error:?}"));
    assert!(!lifted.applied);
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|load_error| panic!("load expired lift: {load_error:?}"))
        .unwrap_or_else(|| panic!("lifted snapshot missing"))
        .contributions
        .is_empty());
}

#[test]
fn restart_replay_requires_the_exact_external_fence_binding() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let active_backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    active_backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("initial apply: {error:?}"));
    let restarted = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    assert!(
        restarted
            .execute(&apply)
            .unwrap_or_else(|error| panic!("restart replay: {error:?}"))
            .applied
    );
    let mut model = blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fence = model
        .fence
        .as_mut()
        .unwrap_or_else(|| panic!("active fence missing"));
    fence.fencing_token = fence.fencing_token.saturating_add(1);
    drop(model);
    let error = restarted
        .execute(&apply)
        .err()
        .unwrap_or_else(|| panic!("rebound fence unexpectedly replayed"));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn external_lineage_fence_binds_owner_scheduler_token_and_bounded_orphan_deadline() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    apply.scheduler_lease_owner_id = LeaseOwnerId::new("freeze-scheduler-worker")
        .unwrap_or_else(|error| panic!("scheduler owner: {error}"));
    let backend = backend(Arc::clone(&freezes), Arc::clone(&blast), &mut apply);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply bound external fence: {error:?}"));

    let initial = blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .clone()
        .unwrap_or_else(|| panic!("bound external fence missing"));
    assert_eq!(
        initial.scheduler_lease_owner_id,
        apply.scheduler_lease_owner_id
    );
    assert_eq!(
        initial.scheduler_fencing_token,
        apply.scheduler_fencing_token
    );

    assert!(initial.expires_at_unix_ms <= apply.plan_expires_at_unix_ms);
    assert!(
        initial.expires_at_unix_ms.saturating_sub(now_unix_ms())
            <= chio_security_types::ports::LINEAGE_FENCE_MAX_LEASE_MS
    );

    let remove = remove_request(&apply, applied.resulting_version_hash);
    backend
        .execute(&remove)
        .unwrap_or_else(|error| panic!("lift renewed external fence: {error:?}"));
    assert!(blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_none());
}

#[test]
fn maintenance_ack_loss_rebinds_durably_fences_stale_owner_and_lifts_once() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let plan = maintenance_plan(&mut apply);
    let initial_work = ScheduledWork {
        tenant_id: apply.tenant_id.clone(),
        action_id: apply.action_id.clone(),
        lease_owner_id: apply.scheduler_lease_owner_id.clone(),
        lease_expires_at_unix_ms: now_unix_ms().saturating_add(30_000),
        fencing_token: apply.scheduler_fencing_token,
    };
    let scheduler = Arc::new(FakeSchedulerStore::new(
        initial_work.clone(),
        response_plan_record(&plan, &initial_work),
    ));
    let freeze_port: Arc<dyn IssuanceFreezeStore> = freezes.clone();
    let blast_port: Arc<dyn BlastRadiusPort> = blast.clone();
    let scheduler_port: Arc<dyn ResponseSchedulerStore> = scheduler.clone();
    let backend =
        IssuanceFreezeBackend::new_with_scheduler(freeze_port, blast_port, scheduler_port);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply maintained freeze: {error:?}"));
    scheduler.mark_effect_applied(&apply.effect_id, applied.resulting_version_hash);
    let initial_fence = blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .clone()
        .unwrap_or_else(|| panic!("initial external fence missing"));

    blast.lose_next_renewal_ack();
    freezes.lose_next_maintenance_ack();
    let renewal_observed_at_unix_ms = plan.expires_at_unix_ms.saturating_add(1);
    let renewed_expires_at_unix_ms = renewal_observed_at_unix_ms.saturating_add(10_000);
    let planned_effect = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned freeze effect missing"));
    let renewal_request = LineageFenceMaintenanceRequest {
        plan: plan.clone(),
        effect_ids: vec![planned_effect.effect_id.clone()],
        scheduler_work: initial_work.clone(),
        observed_at_unix_ms: renewal_observed_at_unix_ms,
        renewed_expires_at_unix_ms,
    };
    let renewed = maintained_fence(
        backend
            .maintain_lineage_fence(planned_effect, &renewal_request)
            .unwrap_or_else(|error| panic!("reconcile renewal acknowledgement loss: {error:?}")),
    );
    assert_eq!(renewed.fencing_token, initial_fence.fencing_token);
    assert_eq!(renewed.expires_at_unix_ms, renewed_expires_at_unix_ms);
    assert!(renewed.expires_at_unix_ms > plan.expires_at_unix_ms);
    assert_eq!(
        freezes
            .load_issuance_freezes(&key())
            .unwrap_or_else(|error| panic!("load renewed local contribution: {error:?}"))
            .unwrap_or_else(|| panic!("renewed local contribution missing"))
            .contributions
            .as_slice()[0]
            .external_fence,
        renewed
    );

    let successor_work = ScheduledWork {
        lease_owner_id: LeaseOwnerId::new("freeze-takeover-worker")
            .unwrap_or_else(|error| panic!("successor owner: {error}")),
        fencing_token: initial_work.fencing_token.saturating_add(1),
        lease_expires_at_unix_ms: now_unix_ms().saturating_add(30_000),
        ..initial_work.clone()
    };
    scheduler.install(successor_work.clone());
    blast.lose_next_takeover_ack();
    freezes.lose_next_maintenance_ack();
    let takeover_request = LineageFenceMaintenanceRequest {
        plan: plan.clone(),
        effect_ids: vec![planned_effect.effect_id.clone()],
        scheduler_work: successor_work.clone(),
        observed_at_unix_ms: renewal_observed_at_unix_ms.saturating_add(1_000),
        renewed_expires_at_unix_ms: renewed_expires_at_unix_ms.saturating_add(5_000),
    };
    let rebound = maintained_fence(
        backend
            .maintain_lineage_fence(planned_effect, &takeover_request)
            .unwrap_or_else(|error| panic!("reconcile takeover acknowledgement loss: {error:?}")),
    );
    assert!(rebound.fencing_token > renewed.fencing_token);
    assert_eq!(
        rebound.scheduler_lease_owner_id,
        successor_work.lease_owner_id
    );
    assert_eq!(
        rebound.scheduler_fencing_token,
        successor_work.fencing_token
    );
    let rebound_snapshot = freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load rebound local contribution: {error:?}"))
        .unwrap_or_else(|| panic!("rebound local contribution missing"));
    assert_eq!(
        rebound_snapshot.contributions.as_slice()[0].external_fence,
        rebound
    );
    assert_eq!(
        backend
            .load_result(&query(&apply))
            .unwrap_or_else(|error| panic!("load original apply after takeover: {error:?}")),
        EffectExecutionStatus::Completed {
            result: applied.clone()
        }
    );
    let stale_execute_error = backend
        .execute(&apply)
        .err()
        .unwrap_or_else(|| panic!("stale apply execute survived scheduler takeover"));
    assert_eq!(stale_execute_error.kind(), PortErrorKind::Conflict);

    let stale_error = backend
        .maintain_lineage_fence(planned_effect, &renewal_request)
        .err()
        .unwrap_or_else(|| panic!("stale scheduler unexpectedly mutated rebound fence"));
    assert_eq!(stale_error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        blast
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fence,
        Some(rebound.clone())
    );
    assert_eq!(
        freezes
            .load_issuance_freezes(&key())
            .unwrap_or_else(|error| panic!("load after stale mutation: {error:?}"))
            .unwrap_or_else(|| panic!("freeze missing after stale mutation")),
        rebound_snapshot
    );

    let mut remove = remove_request(&apply, applied.resulting_version_hash);
    remove.scheduler_lease_owner_id = successor_work.lease_owner_id;
    remove.scheduler_fencing_token = successor_work.fencing_token;
    let lifted = backend
        .execute(&remove)
        .unwrap_or_else(|error| panic!("lift rebound external fence: {error:?}"));
    assert!(!lifted.applied);
    let blast_model = blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(blast_model.fence.is_none());
    assert_eq!(blast_model.release_count, 1);
    drop(blast_model);
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load lifted rebound contribution: {error:?}"))
        .unwrap_or_else(|| panic!("lifted snapshot missing"))
        .contributions
        .is_empty());
}

#[test]
fn maintenance_completes_release_pending_without_recreating_the_external_fence() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let plan = maintenance_plan(&mut apply);
    let work = scheduler_work(&apply);
    let scheduler = Arc::new(FakeSchedulerStore::new(
        work.clone(),
        response_plan_record(&plan, &work),
    ));
    let freeze_port: Arc<dyn IssuanceFreezeStore> = freezes.clone();
    let blast_port: Arc<dyn BlastRadiusPort> = blast.clone();
    let scheduler_port: Arc<dyn ResponseSchedulerStore> = scheduler.clone();
    let backend =
        IssuanceFreezeBackend::new_with_scheduler(freeze_port, blast_port, scheduler_port);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply freeze: {error:?}"));
    scheduler.mark_effect_applied(&apply.effect_id, applied.resulting_version_hash);
    scheduler.mark_effect_rollback_requested(&apply.effect_id);

    let remove = remove_request(&apply, applied.resulting_version_hash);
    freezes.fail_next_complete_before_commit();
    let remove_error = backend
        .execute(&remove)
        .err()
        .unwrap_or_else(|| panic!("remove unexpectedly completed local cleanup"));
    assert_eq!(remove_error.kind(), PortErrorKind::Unavailable);
    let expected_remove_result = freezes
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_releases
        .values()
        .next()
        .unwrap_or_else(|| panic!("durable pending release missing"))
        .request
        .command
        .result
        .clone();
    assert!(blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .is_none());
    assert_eq!(
        freezes
            .load_issuance_freezes(&key())
            .unwrap_or_else(|error| panic!("load release-pending freeze: {error:?}"))
            .unwrap_or_else(|| panic!("release-pending snapshot missing"))
            .contributions
            .len(),
        1
    );

    let effect = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("freeze effect missing"));
    let maintenance = LineageFenceMaintenanceRequest {
        plan: plan.clone(),
        effect_ids: vec![effect.effect_id.clone()],
        scheduler_work: work,
        observed_at_unix_ms: now_unix_ms(),
        renewed_expires_at_unix_ms: now_unix_ms().saturating_add(10_000),
    };
    let recovered = backend
        .maintain_lineage_fence(effect, &maintenance)
        .unwrap_or_else(|error| panic!("recover release-pending cleanup: {error:?}"));
    assert_eq!(recovered, LineageFenceMaintenanceResult::ReleaseCompleted);
    let replay = backend
        .maintain_lineage_fence(effect, &maintenance)
        .unwrap_or_else(|error| panic!("replay completed release recovery: {error:?}"));
    assert_eq!(replay, LineageFenceMaintenanceResult::ReleaseCompleted);
    assert!(freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load recovered freeze state: {error:?}"))
        .unwrap_or_else(|| panic!("recovered snapshot missing"))
        .contributions
        .is_empty());
    assert_eq!(
        backend
            .load_result(&query(&remove))
            .unwrap_or_else(|error| panic!("load recovered remove result: {error:?}")),
        EffectExecutionStatus::Completed {
            result: expected_remove_result
        }
    );
    let blast = blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(blast.fence.is_none());
    assert_eq!(blast.release_count, 1);
}
