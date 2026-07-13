use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::hashing::sha256;
use chio_security_types::ports::{
    ActionId, AdvisorySecurityEvent, ApprovalReservation, ApprovalReservationCreate,
    ApprovalReservationMutation, ApprovalReservationState, ApprovalReservationStore, CanonicalBody,
    CommittedEgressFence, ContainmentOverlayStore, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventIndexRequest, CorrelationPartial, CorrelationPartitionKey, CorrelationScan,
    CreateOutcome, DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationOutcomeRequest, DeclassificationUseState, DeclassificationUseStore, Digest32,
    EffectId, EgressFence, EgressFenceCommit, EgressFenceRequest, EventAppend, EventId,
    EventPartitionScan, FlowJoinRequest, FlowStateKey, FlowStateSnapshot, FlowStateStore, GrantId,
    IsolationEpochEvidenceVerifierPort, IsolationEpochId, IsolationEpochTransition, LeaseOwnerId,
    LineageFence, LineageFenceRelease, LineageFenceRequest, LineageFenceStore, LineageId,
    OpaqueReceiptRef, OverlayApplyRequest, OverlayContribution, OverlayContributions,
    OverlayRemoveRequest, OverlaySnapshot, PortError, PortErrorKind, PortResult, ProducerId,
    ProducerTrustClass, RecordId, RequestId, ResponseCasRequest, ResponseEffectCasRequest,
    ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord, ResponseStore,
    RuleId, ScheduledWork, SchedulerClaimRequest, SecurityEventStore, SessionId,
    StoredApprovalReservation, TenantId, TenantScopedId, VerifiedEventBatch,
    VerifiedIsolationEvidence, VerifiedSecurityEvent,
};
use chio_security_types::{Compartment, InformationLabel, PrincipalId};
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultMoment {
    BeforeWrite,
    AfterCommit,
}

struct Faulting<S> {
    inner: S,
    fault: Mutex<Option<FaultMoment>>,
}

impl<S> Faulting<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            fault: Mutex::new(None),
        }
    }

    fn arm(&self, moment: FaultMoment) {
        *self
            .fault
            .lock()
            .unwrap_or_else(|_| panic!("fault mutex poisoned")) = Some(moment);
    }

    fn trip(&self, moment: FaultMoment) -> PortResult<()> {
        let mut fault = self.fault.lock().map_err(|_| PortError::unavailable())?;
        if *fault == Some(moment) {
            *fault = None;
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn write<T>(&self, write: impl FnOnce(&S) -> PortResult<T>) -> PortResult<T> {
        self.trip(FaultMoment::BeforeWrite)?;
        let value = write(&self.inner)?;
        self.trip(FaultMoment::AfterCommit)?;
        Ok(value)
    }
}

macro_rules! write_method {
    ($name:ident, $trait_name:ident, $method:ident, $request:ty, $output:ty) => {
        fn $name(&self, request: &$request) -> PortResult<$output> {
            self.write(|inner| $trait_name::$method(inner, request))
        }
    };
}

impl<S: FlowStateStore> FlowStateStore for Faulting<S> {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        self.inner.load(key)
    }

    write_method!(
        join,
        FlowStateStore,
        join,
        FlowJoinRequest,
        FlowStateSnapshot
    );
    write_method!(
        open_isolation_epoch,
        FlowStateStore,
        open_isolation_epoch,
        IsolationEpochTransition,
        FlowStateSnapshot
    );
    write_method!(
        acquire_egress_fence,
        FlowStateStore,
        acquire_egress_fence,
        EgressFenceRequest,
        EgressFence
    );

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        self.inner.validate_egress_fence(fence)
    }

    write_method!(
        commit_egress_fence,
        FlowStateStore,
        commit_egress_fence,
        EgressFenceCommit,
        CommittedEgressFence
    );
}

impl<S: DeclassificationUseStore> DeclassificationUseStore for Faulting<S> {
    write_method!(
        consume,
        DeclassificationUseStore,
        consume,
        DeclassificationConsumeRequest,
        DeclassificationConsume
    );
    write_method!(
        record_outcome,
        DeclassificationUseStore,
        record_outcome,
        DeclassificationOutcomeRequest,
        ()
    );
}

impl<S: SecurityEventStore> SecurityEventStore for Faulting<S> {
    write_method!(
        append_verified,
        SecurityEventStore,
        append_verified,
        VerifiedSecurityEvent,
        EventAppend
    );
    write_method!(
        append_advisory,
        SecurityEventStore,
        append_advisory,
        AdvisorySecurityEvent,
        EventAppend
    );
    write_method!(
        index_partition_event,
        SecurityEventStore,
        index_partition_event,
        CorrelationEventIndexRequest,
        ()
    );

    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan> {
        self.inner.scan_partition(scan)
    }

    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        self.inner.load_correlation(key)
    }

    write_method!(
        compare_and_swap_correlation,
        SecurityEventStore,
        compare_and_swap_correlation,
        CorrelationCasRequest,
        CorrelationPartial
    );
    write_method!(
        delete_correlation,
        SecurityEventStore,
        delete_correlation,
        CorrelationDeleteRequest,
        ()
    );
}

impl<S: ResponseStore> ResponseStore for Faulting<S> {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        self.inner.load_plan(key)
    }

    write_method!(
        create,
        ResponseStore,
        create,
        ResponsePlanRecord,
        CreateOutcome
    );
    write_method!(
        compare_and_swap,
        ResponseStore,
        compare_and_swap,
        ResponseCasRequest,
        ResponsePlanRecord
    );

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        self.inner.load_effect(key)
    }

    write_method!(
        persist_effect,
        ResponseStore,
        persist_effect,
        ResponseEffectRecord,
        CreateOutcome
    );
    write_method!(
        compare_and_swap_effect,
        ResponseStore,
        compare_and_swap_effect,
        ResponseEffectCasRequest,
        ResponseEffectRecord
    );
    write_method!(
        claim_due,
        ResponseStore,
        claim_due,
        SchedulerClaimRequest,
        Vec<ScheduledWork>
    );
}

impl<S: ContainmentOverlayStore> ContainmentOverlayStore for Faulting<S> {
    write_method!(
        apply_contribution,
        ContainmentOverlayStore,
        apply_contribution,
        OverlayApplyRequest,
        OverlaySnapshot
    );
    write_method!(
        remove_contribution,
        ContainmentOverlayStore,
        remove_contribution,
        OverlayRemoveRequest,
        OverlaySnapshot
    );

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        self.inner.load_effective(target)
    }
}

impl<S: ApprovalReservationStore> ApprovalReservationStore for Faulting<S> {
    write_method!(
        reserve,
        ApprovalReservationStore,
        reserve,
        ApprovalReservationCreate,
        CreateOutcome
    );

    fn load_reservation(
        &self,
        action: &TenantScopedId,
    ) -> PortResult<Option<StoredApprovalReservation>> {
        self.inner.load_reservation(action)
    }

    write_method!(
        commit_reservation,
        ApprovalReservationStore,
        commit_reservation,
        ApprovalReservationMutation,
        ()
    );
    write_method!(
        cancel_reservation,
        ApprovalReservationStore,
        cancel_reservation,
        ApprovalReservationMutation,
        ()
    );
}

impl<S: LineageFenceStore> LineageFenceStore for Faulting<S> {
    write_method!(
        acquire,
        LineageFenceStore,
        acquire,
        LineageFenceRequest,
        LineageFence
    );

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        self.inner.query(action)
    }

    write_method!(release, LineageFenceStore, release, LineageFenceRelease, ());
}

#[derive(Clone)]
struct ModelPrincipalFlow {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    isolation_epoch_id: IsolationEpochId,
    label: InformationLabel,
    generation: u64,
}

#[derive(Clone)]
struct ModelLineageFlow {
    tenant_id: TenantId,
    lineage_id: LineageId,
    label: InformationLabel,
    generation: u64,
}

#[derive(Clone)]
struct ModelSessionFlow {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    session_id: SessionId,
    isolation_epoch_id: IsolationEpochId,
    label: InformationLabel,
    generation: u64,
}

#[derive(Clone)]
struct ModelEpochAssociation {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    lineage_id: LineageId,
    isolation_epoch_id: IsolationEpochId,
}

#[derive(Clone)]
struct ModelContextGeneration {
    key: FlowStateKey,
    generation: u64,
}

#[derive(Clone)]
struct ModelOverlayBinding {
    tenant_id: TenantId,
    target_id: RecordId,
    effect_id: EffectId,
    action_id: ActionId,
}

#[derive(Default)]
struct ModelState {
    flows: Vec<(RecordId, FlowStateSnapshot)>,
    principal_flows: Vec<ModelPrincipalFlow>,
    lineage_flows: Vec<ModelLineageFlow>,
    session_flows: Vec<ModelSessionFlow>,
    epoch_associations: Vec<ModelEpochAssociation>,
    flow_contexts: Vec<ModelContextGeneration>,
    flow_generation: u64,
    egress: Vec<(EgressFence, Option<CommittedEgressFence>)>,
    declassification: Vec<(TenantId, GrantId, Digest32, DeclassificationUseState)>,
    verified: Vec<VerifiedSecurityEvent>,
    advisory: Vec<AdvisorySecurityEvent>,
    correlation_index: Vec<(CorrelationEventIndexRequest, u64)>,
    correlations: Vec<(RecordId, CorrelationPartial)>,
    correlation_deletes: Vec<RecordId>,
    response_plans: Vec<(Option<RecordId>, ResponsePlanRecord)>,
    response_effects: Vec<ResponseEffectRecord>,
    response_effect_transitions: Vec<ResponseEffectCasRequest>,
    scheduler_claims: Vec<(SchedulerClaimRequest, Vec<ScheduledWork>)>,
    scheduler_leases: Vec<ScheduledWork>,
    scheduler_tokens: Vec<(TenantId, u64)>,
    overlays: Vec<(TenantScopedId, OverlaySnapshot)>,
    overlay_bindings: Vec<ModelOverlayBinding>,
    approvals: Vec<(RecordId, StoredApprovalReservation)>,
    lineage_fences: Vec<(LineageFence, bool)>,
}

#[derive(Default)]
struct ModelStore {
    state: Mutex<ModelState>,
}

impl ModelStore {
    fn state(&self) -> PortResult<MutexGuard<'_, ModelState>> {
        self.state.lock().map_err(|_| PortError::unavailable())
    }
}

fn joined(left: &InformationLabel, right: &InformationLabel) -> PortResult<InformationLabel> {
    left.join_restrictions(right)
        .map_err(|_| PortError::invalid_data())
}

fn model_next_flow_generation(state: &mut ModelState) -> PortResult<u64> {
    state.flow_generation = state
        .flow_generation
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    Ok(state.flow_generation)
}

fn model_flow_snapshot(
    state: &ModelState,
    key: &FlowStateKey,
) -> PortResult<Option<FlowStateSnapshot>> {
    let associated = state.epoch_associations.iter().any(|association| {
        association.tenant_id == key.tenant_id
            && association.principal_id == key.principal_id
            && association.lineage_id == key.lineage_id
            && association.isolation_epoch_id == key.isolation_epoch_id
    });
    if !associated {
        return Ok(None);
    }
    let principal = state
        .principal_flows
        .iter()
        .find(|flow| {
            flow.tenant_id == key.tenant_id
                && flow.principal_id == key.principal_id
                && flow.isolation_epoch_id == key.isolation_epoch_id
        })
        .ok_or_else(PortError::integrity_failure)?;
    let lineage = state
        .lineage_flows
        .iter()
        .find(|flow| flow.tenant_id == key.tenant_id && flow.lineage_id == key.lineage_id)
        .ok_or_else(PortError::integrity_failure)?;
    let session = state.session_flows.iter().find(|flow| {
        flow.tenant_id == key.tenant_id
            && flow.principal_id == key.principal_id
            && flow.session_id == key.session_id
            && flow.isolation_epoch_id == key.isolation_epoch_id
    });
    let context = state
        .flow_contexts
        .iter()
        .find(|context| context.key == *key);
    match (session, context) {
        (Some(_), None) | (None, Some(_)) => return Err(PortError::integrity_failure()),
        _ => {}
    }
    let (stored_session, session_generation, context_generation) = match (session, context) {
        (Some(session), Some(context)) => {
            if principal.generation > context.generation
                || lineage.generation > context.generation
                || session.generation > context.generation
            {
                return Err(PortError::integrity_failure());
            }
            (
                session.label.clone(),
                session.generation,
                context.generation,
            )
        }
        (None, None) => (
            InformationLabel::bottom(),
            0,
            principal.generation.max(lineage.generation),
        ),
        _ => return Err(PortError::integrity_failure()),
    };
    if session_generation > context_generation {
        return Err(PortError::integrity_failure());
    }
    let session_label = joined(&joined(&stored_session, &principal.label)?, &lineage.label)?;
    Ok(Some(FlowStateSnapshot {
        key: key.clone(),
        principal_label: principal.label.clone(),
        lineage_label: lineage.label.clone(),
        session_label,
        context_generation,
    }))
}

impl FlowStateStore for ModelStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let state = self.state()?;
        model_flow_snapshot(&state, key)
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        let mut state = self.state()?;
        if let Some((_, snapshot)) = state
            .flows
            .iter()
            .find(|(transition, _)| transition == &request.transition_id)
        {
            return Ok(snapshot.clone());
        }
        let exact_epoch = state.epoch_associations.iter().any(|association| {
            association.tenant_id == request.key.tenant_id
                && association.principal_id == request.key.principal_id
                && association.lineage_id == request.key.lineage_id
                && association.isolation_epoch_id == request.key.isolation_epoch_id
        });
        if !exact_epoch {
            let same_principal_epoch = state.epoch_associations.iter().any(|association| {
                association.tenant_id == request.key.tenant_id
                    && association.principal_id == request.key.principal_id
                    && association.isolation_epoch_id == request.key.isolation_epoch_id
            });
            let principal_has_history = state.epoch_associations.iter().any(|association| {
                association.tenant_id == request.key.tenant_id
                    && association.principal_id == request.key.principal_id
            });
            if principal_has_history && !same_principal_epoch {
                return Err(PortError::invalid_data());
            }
            state.epoch_associations.push(ModelEpochAssociation {
                tenant_id: request.key.tenant_id.clone(),
                principal_id: request.key.principal_id.clone(),
                lineage_id: request.key.lineage_id.clone(),
                isolation_epoch_id: request.key.isolation_epoch_id.clone(),
            });
        }
        let principal_position = state.principal_flows.iter().position(|flow| {
            flow.tenant_id == request.key.tenant_id
                && flow.principal_id == request.key.principal_id
                && flow.isolation_epoch_id == request.key.isolation_epoch_id
        });
        let lineage_position = state.lineage_flows.iter().position(|flow| {
            flow.tenant_id == request.key.tenant_id && flow.lineage_id == request.key.lineage_id
        });
        let session_position = state.session_flows.iter().position(|flow| {
            flow.tenant_id == request.key.tenant_id
                && flow.principal_id == request.key.principal_id
                && flow.session_id == request.key.session_id
                && flow.isolation_epoch_id == request.key.isolation_epoch_id
        });
        let principal_current = principal_position
            .map(|position| state.principal_flows[position].label.clone())
            .unwrap_or_else(InformationLabel::bottom);
        let lineage_current = lineage_position
            .map(|position| state.lineage_flows[position].label.clone())
            .unwrap_or_else(InformationLabel::bottom);
        let session_base = session_position
            .map(|position| state.session_flows[position].label.clone())
            .unwrap_or(joined(&principal_current, &lineage_current)?);
        let principal = joined(&principal_current, &request.principal_join)?;
        let lineage = joined(&lineage_current, &request.lineage_join)?;
        let session = joined(
            &joined(&session_base, &request.session_join)?,
            &joined(&principal, &lineage)?,
        )?;
        let principal_changed = principal != principal_current;
        let lineage_changed = lineage != lineage_current;
        let session_changed = session != session_base;
        let generation = model_next_flow_generation(&mut state)?;
        for context in &mut state.flow_contexts {
            if (principal_changed
                && context.key.tenant_id == request.key.tenant_id
                && context.key.principal_id == request.key.principal_id
                && context.key.isolation_epoch_id == request.key.isolation_epoch_id)
                || (lineage_changed
                    && context.key.tenant_id == request.key.tenant_id
                    && context.key.lineage_id == request.key.lineage_id)
                || (session_changed
                    && context.key.tenant_id == request.key.tenant_id
                    && context.key.principal_id == request.key.principal_id
                    && context.key.session_id == request.key.session_id
                    && context.key.isolation_epoch_id == request.key.isolation_epoch_id)
            {
                context.generation = generation;
            }
        }
        if let Some(position) = principal_position {
            if principal_changed {
                state.principal_flows[position].label = principal.clone();
                state.principal_flows[position].generation = generation;
            }
        } else {
            state.principal_flows.push(ModelPrincipalFlow {
                tenant_id: request.key.tenant_id.clone(),
                principal_id: request.key.principal_id.clone(),
                isolation_epoch_id: request.key.isolation_epoch_id.clone(),
                label: principal.clone(),
                generation,
            });
        }
        if let Some(position) = lineage_position {
            if lineage_changed {
                state.lineage_flows[position].label = lineage.clone();
                state.lineage_flows[position].generation = generation;
            }
        } else {
            state.lineage_flows.push(ModelLineageFlow {
                tenant_id: request.key.tenant_id.clone(),
                lineage_id: request.key.lineage_id.clone(),
                label: lineage.clone(),
                generation,
            });
        }
        if let Some(position) = session_position {
            if session_changed {
                state.session_flows[position].label = session.clone();
                state.session_flows[position].generation = generation;
            }
        } else {
            state.session_flows.push(ModelSessionFlow {
                tenant_id: request.key.tenant_id.clone(),
                principal_id: request.key.principal_id.clone(),
                session_id: request.key.session_id.clone(),
                isolation_epoch_id: request.key.isolation_epoch_id.clone(),
                label: session.clone(),
                generation,
            });
        }
        if let Some(context) = state
            .flow_contexts
            .iter_mut()
            .find(|context| context.key == request.key)
        {
            context.generation = generation;
        } else {
            state.flow_contexts.push(ModelContextGeneration {
                key: request.key.clone(),
                generation,
            });
        }
        let snapshot = FlowStateSnapshot {
            key: request.key.clone(),
            principal_label: principal,
            lineage_label: lineage,
            session_label: session,
            context_generation: generation,
        };
        state
            .flows
            .push((request.transition_id.clone(), snapshot.clone()));
        Ok(snapshot)
    }

    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot> {
        let mut state = self.state()?;
        if let Some((_, snapshot)) = state
            .flows
            .iter()
            .find(|(id, _)| id == &transition.transition_id)
        {
            return Ok(snapshot.clone());
        }
        let prior_association = state.epoch_associations.iter().any(|association| {
            association.tenant_id == transition.tenant_id
                && association.principal_id == transition.principal_id
                && association.lineage_id == transition.lineage_id
                && association.isolation_epoch_id == transition.previous_isolation_epoch_id
        });
        if !prior_association
            || transition.previous_isolation_epoch_id == transition.new_isolation_epoch_id
            || transition
                .verification_evidence_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PortError::invalid_data());
        }
        if state.principal_flows.iter().any(|flow| {
            flow.tenant_id == transition.tenant_id
                && flow.principal_id == transition.principal_id
                && flow.isolation_epoch_id == transition.new_isolation_epoch_id
        }) {
            return Err(PortError::conflict());
        }
        let lineage = state
            .lineage_flows
            .iter()
            .find(|flow| {
                flow.tenant_id == transition.tenant_id && flow.lineage_id == transition.lineage_id
            })
            .map(|flow| flow.label.clone())
            .ok_or_else(PortError::integrity_failure)?;
        let generation = model_next_flow_generation(&mut state)?;
        let key = FlowStateKey {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            lineage_id: transition.lineage_id.clone(),
            session_id: transition.new_session_id.clone(),
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
        };
        state.epoch_associations.push(ModelEpochAssociation {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            lineage_id: transition.lineage_id.clone(),
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
        });
        state.principal_flows.push(ModelPrincipalFlow {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            label: InformationLabel::bottom(),
            generation,
        });
        state.session_flows.push(ModelSessionFlow {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            session_id: transition.new_session_id.clone(),
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            label: lineage.clone(),
            generation,
        });
        state.flow_contexts.push(ModelContextGeneration {
            key: key.clone(),
            generation,
        });
        let snapshot = FlowStateSnapshot {
            key,
            principal_label: InformationLabel::bottom(),
            lineage_label: lineage.clone(),
            session_label: lineage,
            context_generation: generation,
        };
        state
            .flows
            .push((transition.transition_id.clone(), snapshot.clone()));
        Ok(snapshot)
    }

    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
        let mut state = self.state()?;
        let current =
            model_flow_snapshot(&state, &request.key)?.ok_or_else(PortError::invalid_data)?;
        if current.context_generation != request.expected_context_generation
            || request.expires_at_unix_ms <= now_unix_ms()
        {
            return Err(PortError::conflict());
        }
        if let Some((fence, _)) = state.egress.iter().find(|(fence, _)| {
            fence.key.tenant_id == request.key.tenant_id && fence.request_id == request.request_id
        }) {
            return if fence.key == request.key
                && fence.request_hash == request.request_hash
                && fence.context_generation == request.expected_context_generation
                && fence.expires_at_unix_ms == request.expires_at_unix_ms
            {
                Ok(fence.clone())
            } else {
                Err(PortError::conflict())
            };
        }
        let fence = EgressFence {
            fence_id: record(&format!("fence-{}", request.request_id.as_str())),
            key: request.key.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash,
            context_generation: request.expected_context_generation,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        state.egress.push((fence.clone(), None));
        Ok(fence)
    }

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        let state = self.state()?;
        let stored = state
            .egress
            .iter()
            .find(|(stored, _)| stored == fence)
            .ok_or_else(PortError::invalid_data)?;
        let current =
            model_flow_snapshot(&state, &fence.key)?.ok_or_else(PortError::integrity_failure)?;
        if stored.0.context_generation != current.context_generation
            || fence.expires_at_unix_ms <= now_unix_ms()
        {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence> {
        self.validate_egress_fence(&commitment.fence)?;
        let mut state = self.state()?;
        let (_, stored) = state
            .egress
            .iter_mut()
            .find(|(fence, _)| fence == &commitment.fence)
            .ok_or_else(PortError::invalid_data)?;
        let value = CommittedEgressFence {
            fence_id: commitment.fence.fence_id.clone(),
            request_id: commitment.fence.request_id.clone(),
            request_hash: commitment.fence.request_hash,
            context_generation: commitment.fence.context_generation,
            dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
            committed_at_unix_ms: commitment.committed_at_unix_ms,
        };
        if let Some(existing) = stored.as_ref() {
            return if existing == &value {
                Ok(existing.clone())
            } else {
                Err(PortError::conflict())
            };
        }
        *stored = Some(value.clone());
        Ok(value)
    }
}

impl DeclassificationUseStore for ModelStore {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume> {
        let mut state = self.state()?;
        if let Some((_, _, hash, use_state)) =
            state.declassification.iter().find(|(tenant, grant, _, _)| {
                tenant == &request.tenant_id && grant == &request.grant_id
            })
        {
            if hash != &request.request_hash {
                return Err(PortError::conflict());
            }
            return Ok(DeclassificationConsume::AlreadyConsumed {
                request_hash: *hash,
                state: *use_state,
            });
        }
        state.declassification.push((
            request.tenant_id.clone(),
            request.grant_id.clone(),
            request.request_hash,
            DeclassificationUseState::ConsumedPendingDispatch,
        ));
        Ok(DeclassificationConsume::Consumed)
    }

    fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()> {
        let mut state = self.state()?;
        let (_, _, hash, use_state) = state
            .declassification
            .iter_mut()
            .find(|(tenant, grant, _, _)| {
                tenant == &request.tenant_id && grant == &request.grant_id
            })
            .ok_or_else(PortError::invalid_data)?;
        if hash != &request.request_hash {
            return Err(PortError::conflict());
        }
        if *use_state == request.new_state {
            return Ok(());
        }
        if *use_state != request.expected_state {
            return Err(PortError::conflict());
        }
        *use_state = request.new_state;
        Ok(())
    }
}

impl SecurityEventStore for ModelStore {
    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        let mut state = self.state()?;
        if let Some(existing) = state.verified.iter().find(|existing| {
            existing.tenant_id == event.tenant_id && existing.event_id == event.event_id
        }) {
            return if existing == event {
                Ok(EventAppend::Duplicate)
            } else {
                Err(PortError::conflict())
            };
        }
        if state.advisory.iter().any(|existing| {
            existing.tenant_id == event.tenant_id && existing.event_id == event.event_id
        }) {
            return Err(PortError::conflict());
        }
        state.verified.push(event.clone());
        Ok(EventAppend::Inserted)
    }

    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        let mut state = self.state()?;
        if let Some(existing) = state.advisory.iter().find(|existing| {
            existing.tenant_id == event.tenant_id && existing.event_id == event.event_id
        }) {
            return if existing == event {
                Ok(EventAppend::Duplicate)
            } else {
                Err(PortError::conflict())
            };
        }
        if state.verified.iter().any(|existing| {
            existing.tenant_id == event.tenant_id && existing.event_id == event.event_id
        }) {
            return Err(PortError::conflict());
        }
        state.advisory.push(event.clone());
        Ok(EventAppend::Inserted)
    }

    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()> {
        let mut state = self.state()?;
        if state
            .correlation_index
            .iter()
            .any(|(existing, _)| existing.transition_id == request.transition_id)
        {
            return Ok(());
        }
        if !state.verified.iter().any(|event| {
            event.tenant_id == request.key.tenant_id && event.event_id == request.event_id
        }) {
            return Err(PortError::invalid_data());
        }
        if let Some((existing, _)) = state.correlation_index.iter().find(|(existing, _)| {
            existing.key.tenant_id == request.key.tenant_id
                && existing.key.rule_id == request.key.rule_id
                && existing.event_id == request.event_id
        }) {
            return if existing.key.partition_hash == request.key.partition_hash {
                Ok(())
            } else {
                Err(PortError::conflict())
            };
        }
        let generation = state
            .correlation_index
            .iter()
            .filter(|(existing, _)| existing.key == request.key)
            .count() as u64
            + 1;
        state.correlation_index.push((request.clone(), generation));
        Ok(())
    }

    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan> {
        let state = self.state()?;
        let key = CorrelationPartitionKey {
            tenant_id: scan.tenant_id.clone(),
            rule_id: scan.rule_id.clone(),
            partition_hash: scan.partition_hash,
        };
        let mut events = state
            .correlation_index
            .iter()
            .filter(|(index, _)| index.key == key)
            .filter_map(|(index, _)| {
                state.verified.iter().find(|event| {
                    event.tenant_id == key.tenant_id && event.event_id == index.event_id
                })
            })
            .filter(|event| event.event_time_unix_ms <= scan.through_event_time_unix_ms)
            .filter(|event| match scan.after_event_time_unix_ms {
                None => true,
                Some(time) if event.event_time_unix_ms > time => true,
                Some(time) if event.event_time_unix_ms == time => scan
                    .after_event_id
                    .as_ref()
                    .is_some_and(|id| event.event_id > *id),
                Some(_) => false,
            })
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            (left.event_time_unix_ms, &left.event_id)
                .cmp(&(right.event_time_unix_ms, &right.event_id))
        });
        let truncated = events.len() > scan.max_results as usize;
        events.truncate(scan.max_results as usize);
        let partition_generation = state
            .correlation_index
            .iter()
            .filter(|(index, _)| index.key == key)
            .map(|(_, generation)| *generation)
            .max()
            .unwrap_or(0);
        Ok(CorrelationScan {
            events: VerifiedEventBatch::new(events).map_err(|_| PortError::integrity_failure())?,
            partition_generation,
            truncated,
        })
    }

    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        Ok(self
            .state()?
            .correlations
            .iter()
            .rev()
            .find(|(_, partial)| partial.key == *key)
            .map(|(_, partial)| partial.clone()))
    }

    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        let mut state = self.state()?;
        if let Some((_, partial)) = state
            .correlations
            .iter()
            .find(|(transition, _)| transition == &request.transition_id)
        {
            return Ok(partial.clone());
        }
        let partition_generation = state
            .correlation_index
            .iter()
            .filter(|(index, _)| index.key == request.partial.key)
            .map(|(_, generation)| *generation)
            .max()
            .unwrap_or(0);
        if partition_generation != request.observed_partition_generation {
            return Err(PortError::conflict());
        }
        let current = state
            .correlations
            .iter()
            .rev()
            .find(|(_, partial)| partial.key == request.partial.key)
            .map(|(_, partial)| partial);
        match (current, request.expected_generation) {
            (None, None) if request.partial.generation == 0 => {}
            (Some(current), Some(expected))
                if current.generation == expected
                    && request.partial.generation == expected.saturating_add(1) => {}
            _ => return Err(PortError::conflict()),
        }
        state
            .correlations
            .push((request.transition_id.clone(), request.partial.clone()));
        Ok(request.partial.clone())
    }

    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()> {
        let mut state = self.state()?;
        if state
            .correlation_deletes
            .iter()
            .any(|transition| transition == &request.transition_id)
        {
            return Ok(());
        }
        let position = state.correlations.iter().rposition(|(_, partial)| {
            partial.key == request.key && partial.generation == request.expected_generation
        });
        let position = position.ok_or_else(PortError::conflict)?;
        state.correlations.remove(position);
        state
            .correlation_deletes
            .push(request.transition_id.clone());
        Ok(())
    }
}

fn model_validate_scheduler_fence(
    state: &ModelState,
    tenant_id: &TenantId,
    action_id: &ActionId,
    fencing_token: u64,
) -> PortResult<()> {
    let lease = state
        .scheduler_leases
        .iter()
        .find(|lease| lease.tenant_id == *tenant_id && lease.action_id == *action_id)
        .ok_or_else(PortError::invalid_data)?;
    if lease.fencing_token != fencing_token || lease.lease_expires_at_unix_ms <= now_unix_ms() {
        return Err(PortError::conflict());
    }
    Ok(())
}

impl ResponseStore for ModelStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        let state = self.state()?;
        Ok(state
            .response_plans
            .iter()
            .find(|(_, record)| {
                record.tenant_id == key.tenant_id && record.action_id == key.action_id
            })
            .map(|(_, record)| record.clone()))
    }

    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        let mut state = self.state()?;
        if let Some((_, existing)) = state.response_plans.iter().find(|(_, existing)| {
            existing.tenant_id == record.tenant_id && existing.action_id == record.action_id
        }) {
            return if existing == record {
                Ok(CreateOutcome::Existing)
            } else {
                Err(PortError::conflict())
            };
        }
        state.response_plans.push((None, record.clone()));
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        let mut state = self.state()?;
        if let Some((_, record)) = state
            .response_plans
            .iter()
            .find(|(transition, _)| transition.as_ref() == Some(&request.transition_id))
        {
            return Ok(record.clone());
        }
        let position = state
            .response_plans
            .iter()
            .position(|(_, record)| {
                record.tenant_id == request.record.tenant_id
                    && record.action_id == request.record.action_id
            })
            .ok_or_else(PortError::invalid_data)?;
        if state.response_plans[position].1.generation != request.expected_generation
            || request.record.generation != request.expected_generation.saturating_add(1)
        {
            return Err(PortError::conflict());
        }
        state.response_plans[position] =
            (Some(request.transition_id.clone()), request.record.clone());
        Ok(request.record.clone())
    }

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        let state = self.state()?;
        Ok(state
            .response_effects
            .iter()
            .find(|record| record.tenant_id == key.tenant_id && record.effect_id == key.effect_id)
            .cloned())
    }

    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        if record.generation != 0 {
            return Err(PortError::invalid_data());
        }
        let mut state = self.state()?;
        model_validate_scheduler_fence(
            &state,
            &record.tenant_id,
            &record.action_id,
            record.scheduler_fencing_token,
        )?;
        if let Some(existing) = state.response_effects.iter().find(|existing| {
            existing.tenant_id == record.tenant_id && existing.effect_id == record.effect_id
        }) {
            return if existing == record {
                Ok(CreateOutcome::Existing)
            } else {
                Err(PortError::conflict())
            };
        }
        state.response_effects.push(record.clone());
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        let mut state = self.state()?;
        model_validate_scheduler_fence(
            &state,
            &request.record.tenant_id,
            &request.record.action_id,
            request.record.scheduler_fencing_token,
        )?;
        if let Some(existing) = state
            .response_effect_transitions
            .iter()
            .find(|existing| existing.transition_id == request.transition_id)
        {
            if existing != request {
                return Err(PortError::conflict());
            }
            return state
                .response_effects
                .iter()
                .find(|record| {
                    record.tenant_id == request.record.tenant_id
                        && record.effect_id == request.record.effect_id
                })
                .cloned()
                .ok_or_else(PortError::integrity_failure);
        }
        let position = state
            .response_effects
            .iter()
            .position(|record| {
                record.tenant_id == request.record.tenant_id
                    && record.effect_id == request.record.effect_id
            })
            .ok_or_else(PortError::invalid_data)?;
        let current = &state.response_effects[position];
        if current.action_id != request.record.action_id
            || current.generation != request.expected_generation
            || request.record.generation
                != request
                    .expected_generation
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::conflict());
        }
        state.response_effects[position] = request.record.clone();
        state.response_effect_transitions.push(request.clone());
        Ok(request.record.clone())
    }

    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        let mut state = self.state()?;
        let trusted_now = now_unix_ms();
        if request.max_claims == 0
            || request.max_claims > 1_024
            || request.lease_expires_at_unix_ms <= trusted_now
            || request.now_unix_ms.abs_diff(trusted_now) > 5_000
        {
            return Err(PortError::invalid_data());
        }
        if let Some((stored_request, stored_claim)) =
            state.scheduler_claims.iter().find(|(stored_request, _)| {
                stored_request.tenant_id == request.tenant_id
                    && stored_request.claim_id == request.claim_id
            })
        {
            if stored_request != request {
                return Err(PortError::conflict());
            }
            if request.lease_expires_at_unix_ms <= trusted_now
                || stored_claim
                    .iter()
                    .any(|work| !state.scheduler_leases.iter().any(|lease| lease == work))
            {
                return Err(PortError::conflict());
            }
            return Ok(stored_claim.clone());
        }
        let action_ids = state
            .response_plans
            .iter()
            .filter(|(_, plan)| {
                plan.tenant_id == request.tenant_id
                    && plan.due_at_unix_ms.is_some_and(|due| due <= trusted_now)
                    && !state.scheduler_leases.iter().any(|lease| {
                        lease.tenant_id == plan.tenant_id
                            && lease.action_id == plan.action_id
                            && lease.lease_expires_at_unix_ms > trusted_now
                    })
            })
            .map(|(_, plan)| plan.action_id.clone())
            .take(request.max_claims as usize)
            .collect::<Vec<_>>();
        let mut claimed = Vec::new();
        for action_id in action_ids {
            let token_position = state
                .scheduler_tokens
                .iter()
                .position(|(tenant, _)| tenant == &request.tenant_id);
            let fencing_token = if let Some(position) = token_position {
                state.scheduler_tokens[position].1 = state.scheduler_tokens[position]
                    .1
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
                state.scheduler_tokens[position].1
            } else {
                state.scheduler_tokens.push((request.tenant_id.clone(), 1));
                1
            };
            let work = ScheduledWork {
                tenant_id: request.tenant_id.clone(),
                action_id,
                lease_owner_id: request.lease_owner_id.clone(),
                lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
                fencing_token,
            };
            if let Some(position) = state.scheduler_leases.iter().position(|lease| {
                lease.tenant_id == work.tenant_id && lease.action_id == work.action_id
            }) {
                state.scheduler_leases[position] = work.clone();
            } else {
                state.scheduler_leases.push(work.clone());
            }
            claimed.push(work);
        }
        state
            .scheduler_claims
            .push((request.clone(), claimed.clone()));
        Ok(claimed)
    }
}

impl ContainmentOverlayStore for ModelStore {
    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        let mut state = self.state()?;
        model_validate_scheduler_fence(
            &state,
            &request.target.tenant_id,
            &request.action_id,
            request.scheduler_fencing_token,
        )?;
        let binding_exists = match state.overlay_bindings.iter().find(|binding| {
            binding.tenant_id == request.target.tenant_id
                && binding.effect_id == request.contribution.effect_id
        }) {
            Some(binding)
                if binding.target_id == request.target.id
                    && binding.action_id == request.action_id =>
            {
                true
            }
            Some(_) => return Err(PortError::conflict()),
            None => false,
        };
        let position = state
            .overlays
            .iter()
            .position(|(target, _)| target == &request.target);
        let current = position
            .map(|index| state.overlays[index].1.clone())
            .unwrap_or_else(|| OverlaySnapshot {
                target: request.target.clone(),
                generation: 0,
                effective_posture_rank: 0,
                active_contributions: OverlayContributions::new(Vec::new())
                    .unwrap_or_else(|error| panic!("empty contributions: {error}")),
                highest_fencing_token: 0,
            });
        if let Some(existing) = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            return if existing == &request.contribution {
                Ok(current)
            } else {
                Err(PortError::conflict())
            };
        }
        if binding_exists {
            return Err(PortError::integrity_failure());
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        let mut contributions = current.active_contributions.clone().into_vec();
        contributions.push(request.contribution.clone());
        contributions.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
        let snapshot = OverlaySnapshot {
            target: request.target.clone(),
            generation: current
                .generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?,
            effective_posture_rank: contributions
                .iter()
                .map(|entry| entry.posture_rank)
                .max()
                .unwrap_or(0),
            active_contributions: OverlayContributions::new(contributions)
                .map_err(|_| PortError::invalid_data())?,
            highest_fencing_token: current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        };
        state.overlay_bindings.push(ModelOverlayBinding {
            tenant_id: request.target.tenant_id.clone(),
            target_id: request.target.id.clone(),
            effect_id: request.contribution.effect_id.clone(),
            action_id: request.action_id.clone(),
        });
        if let Some(index) = position {
            state.overlays[index] = (request.target.clone(), snapshot.clone());
        } else {
            state
                .overlays
                .push((request.target.clone(), snapshot.clone()));
        }
        Ok(snapshot)
    }

    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        let mut state = self.state()?;
        model_validate_scheduler_fence(
            &state,
            &request.target.tenant_id,
            &request.action_id,
            request.scheduler_fencing_token,
        )?;
        let binding_position = state.overlay_bindings.iter().position(|binding| {
            binding.tenant_id == request.target.tenant_id && binding.effect_id == request.effect_id
        });
        if let Some(position) = binding_position {
            let binding = &state.overlay_bindings[position];
            if binding.target_id != request.target.id || binding.action_id != request.action_id {
                return Err(PortError::conflict());
            }
        }
        let position = state
            .overlays
            .iter()
            .position(|(target, _)| target == &request.target)
            .ok_or_else(PortError::invalid_data)?;
        let current = state.overlays[position].1.clone();
        let mut contributions = current.active_contributions.clone().into_vec();
        if !contributions
            .iter()
            .any(|entry| entry.effect_id == request.effect_id)
        {
            if binding_position.is_some() {
                return Err(PortError::integrity_failure());
            }
            return Ok(current);
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        contributions.retain(|entry| entry.effect_id != request.effect_id);
        if let Some(binding_position) = binding_position {
            state.overlay_bindings.remove(binding_position);
        }
        let snapshot = OverlaySnapshot {
            target: request.target.clone(),
            generation: current
                .generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?,
            effective_posture_rank: contributions
                .iter()
                .map(|entry| entry.posture_rank)
                .max()
                .unwrap_or(0),
            active_contributions: OverlayContributions::new(contributions)
                .map_err(|_| PortError::invalid_data())?,
            highest_fencing_token: current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        };
        state.overlays[position].1 = snapshot.clone();
        Ok(snapshot)
    }

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        Ok(self
            .state()?
            .overlays
            .iter()
            .find(|(stored, _)| stored == target)
            .map(|(_, snapshot)| snapshot.clone()))
    }
}

impl ApprovalReservationStore for ModelStore {
    fn reserve(&self, request: &ApprovalReservationCreate) -> PortResult<CreateOutcome> {
        let mut state = self.state()?;
        if let Some((_, stored)) = state.approvals.iter().find(|(_, stored)| {
            stored.reservation.tenant_id == request.reservation.tenant_id
                && stored.reservation.action_id == request.reservation.action_id
        }) {
            return if stored.reservation == request.reservation
                && stored.state == ApprovalReservationState::Reserved
            {
                Ok(CreateOutcome::Existing)
            } else {
                Err(PortError::conflict())
            };
        }
        state.approvals.push((
            request.transition_id.clone(),
            StoredApprovalReservation {
                reservation: request.reservation.clone(),
                state: ApprovalReservationState::Reserved,
            },
        ));
        Ok(CreateOutcome::Created)
    }

    fn load_reservation(
        &self,
        action: &TenantScopedId,
    ) -> PortResult<Option<StoredApprovalReservation>> {
        Ok(self
            .state()?
            .approvals
            .iter()
            .find(|(_, stored)| {
                stored.reservation.tenant_id == action.tenant_id
                    && stored.reservation.action_id.as_str() == action.id.as_str()
            })
            .map(|(_, stored)| stored.clone()))
    }

    fn commit_reservation(&self, mutation: &ApprovalReservationMutation) -> PortResult<()> {
        mutate_model_reservation(self, mutation, ApprovalReservationState::Committed)
    }

    fn cancel_reservation(&self, mutation: &ApprovalReservationMutation) -> PortResult<()> {
        mutate_model_reservation(self, mutation, ApprovalReservationState::Cancelled)
    }
}

fn mutate_model_reservation(
    store: &ModelStore,
    mutation: &ApprovalReservationMutation,
    new_state: ApprovalReservationState,
) -> PortResult<()> {
    let mut state = store.state()?;
    let (transition, stored) = state
        .approvals
        .iter_mut()
        .find(|(_, stored)| stored.reservation == mutation.reservation)
        .ok_or_else(PortError::invalid_data)?;
    if transition == &mutation.transition_id && stored.state == new_state {
        return Ok(());
    }
    if stored.state != ApprovalReservationState::Reserved {
        return Err(PortError::conflict());
    }
    *transition = mutation.transition_id.clone();
    stored.state = new_state;
    Ok(())
}

impl LineageFenceStore for ModelStore {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence> {
        let mut state = self.state()?;
        if let Some((fence, active)) = state.lineage_fences.iter().find(|(fence, _)| {
            fence.tenant_id == request.tenant_id && fence.action_id == request.action_id
        }) {
            if *active
                && fence.commit_index == request.expected_commit_index
                && fence.affected_set_hash == request.expected_affected_set_hash
                && fence.expires_at_unix_ms == request.expires_at_unix_ms
            {
                return Ok(fence.clone());
            }
            return Err(PortError::conflict());
        }
        let fence = LineageFence {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
            commit_index: request.expected_commit_index,
            affected_set_hash: request.expected_affected_set_hash,
            fencing_token: 1,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        state.lineage_fences.push((fence.clone(), true));
        Ok(fence)
    }

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        Ok(self
            .state()?
            .lineage_fences
            .iter()
            .find(|(fence, active)| {
                *active
                    && fence.tenant_id == action.tenant_id
                    && fence.action_id.as_str() == action.id.as_str()
            })
            .map(|(fence, _)| fence.clone()))
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        let mut state = self.state()?;
        let Some((fence, active)) = state.lineage_fences.iter_mut().find(|(fence, _)| {
            fence.tenant_id == release.tenant_id && fence.action_id == release.action_id
        }) else {
            return Ok(());
        };
        if fence.fencing_token != release.fencing_token {
            return Err(PortError::conflict());
        }
        *active = false;
        Ok(())
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-contract").unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn action(value: &str) -> ActionId {
    ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
}

fn effect(value: &str) -> EffectId {
    EffectId::new(value).unwrap_or_else(|error| panic!("effect id: {error}"))
}

fn now_unix_ms() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before epoch: {error}"));
    u64::try_from(duration.as_millis())
        .unwrap_or_else(|error| panic!("clock value exceeds u64: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    let hash = sha256(bytes);
    let mut value = [0_u8; 32];
    value.copy_from_slice(hash.as_ref());
    Digest32::new(value)
}

fn body(value: &'static [u8]) -> CanonicalBody {
    CanonicalBody::new(value.to_vec()).unwrap_or_else(|error| panic!("canonical body: {error}"))
}

fn label(value: &str) -> InformationLabel {
    InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([
            Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}"))
        ]),
    )
    .unwrap_or_else(|error| panic!("information label: {error}"))
}

fn flow_key(session: &str, epoch: &str) -> FlowStateKey {
    FlowStateKey {
        tenant_id: tenant(),
        principal_id: PrincipalId::new(format!("principal-{session}"))
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new(format!("lineage-{session}"))
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new(session).unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new(epoch)
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
    }
}

fn scoped_action(value: &str) -> TenantScopedId {
    TenantScopedId {
        tenant_id: tenant(),
        id: record(value),
    }
}

fn require_unavailable<T>(result: PortResult<T>) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("fault injection unexpectedly returned success"));
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert!(!error.code().as_str().is_empty());
}

fn require_error_kind<T>(result: PortResult<T>, expected: PortErrorKind) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("invalid mutation unexpectedly returned success"));
    assert_eq!(error.kind(), expected);
    assert!(!error.code().as_str().is_empty());
}

fn verified_event(value: &str, event_time: u64) -> VerifiedSecurityEvent {
    let canonical_body = body(b"{}");
    VerifiedSecurityEvent {
        tenant_id: tenant(),
        event_id: EventId::new(value).unwrap_or_else(|error| panic!("event id: {error}")),
        producer_id: ProducerId::new("producer-verified")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        trust_class: ProducerTrustClass::InternalDetector,
        event_time_unix_ms: event_time,
        received_at_unix_ms: event_time,
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
        evidence_hash: Digest32::new([9_u8; 32]),
    }
}

fn advisory_event(value: &str, event_time: u64) -> AdvisorySecurityEvent {
    let canonical_body = body(b"{}");
    AdvisorySecurityEvent {
        tenant_id: tenant(),
        event_id: EventId::new(value).unwrap_or_else(|error| panic!("event id: {error}")),
        producer_id: ProducerId::new("producer-advisory")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        event_time_unix_ms: event_time,
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
    }
}

fn response_plan(value: &str, generation: u64, due_at: Option<u64>) -> ResponsePlanRecord {
    let canonical_body = body(b"{}");
    ResponsePlanRecord {
        tenant_id: tenant(),
        action_id: action(value),
        generation,
        state: record(if generation == 0 {
            "pending"
        } else {
            "updated"
        }),
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
        due_at_unix_ms: due_at,
    }
}

struct AcceptIsolationEvidence;

impl IsolationEpochEvidenceVerifierPort for AcceptIsolationEvidence {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<VerifiedIsolationEvidence> {
        if transition.verification_evidence_hash != Digest32::new([8_u8; 32]) {
            return Err(PortError::invalid_data());
        }
        Ok(VerifiedIsolationEvidence {
            verifier_id: record("contract-verifier"),
            receipt_ref: OpaqueReceiptRef::new("contract-receipt").map_err(PortError::from)?,
        })
    }
}

fn exercise_contracts<S>(store: &Faulting<S>)
where
    S: FlowStateStore
        + DeclassificationUseStore
        + SecurityEventStore
        + ResponseStore
        + ContainmentOverlayStore
        + ApprovalReservationStore
        + LineageFenceStore,
{
    let clock = now_unix_ms();
    let expiry = clock.saturating_add(120_000);

    let first_key = flow_key("session-flow-before", "epoch-base");
    let first_join = FlowJoinRequest {
        key: first_key.clone(),
        principal_join: label("principal-before"),
        lineage_join: label("lineage-before"),
        session_join: label("session-before"),
        transition_id: record("flow-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.join(&first_join));
    assert_eq!(
        store
            .load(&first_key)
            .unwrap_or_else(|error| panic!("load flow before retry: {error}")),
        None
    );
    let first_snapshot = store
        .join(&first_join)
        .unwrap_or_else(|error| panic!("retry flow join: {error}"));

    let second_key = flow_key("session-flow-after", "epoch-base");
    let second_join = FlowJoinRequest {
        key: second_key.clone(),
        principal_join: label("principal-after"),
        lineage_join: label("lineage-after"),
        session_join: label("session-after"),
        transition_id: record("flow-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.join(&second_join));
    let committed_snapshot = store
        .load(&second_key)
        .unwrap_or_else(|error| panic!("load committed flow: {error}"))
        .unwrap_or_else(|| panic!("committed flow missing"));
    assert_eq!(
        store
            .join(&second_join)
            .unwrap_or_else(|error| panic!("recover flow join: {error}")),
        committed_snapshot
    );

    let isolation_before = IsolationEpochTransition {
        tenant_id: tenant(),
        principal_id: first_key.principal_id.clone(),
        lineage_id: first_key.lineage_id.clone(),
        previous_isolation_epoch_id: first_key.isolation_epoch_id.clone(),
        new_isolation_epoch_id: IsolationEpochId::new("epoch-before")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        new_session_id: SessionId::new("session-isolation-before")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        verification_evidence_hash: Digest32::new([8_u8; 32]),
        transition_id: record("isolation-before"),
        effective_at_unix_ms: clock,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.open_isolation_epoch(&isolation_before));
    let isolated_before = store
        .open_isolation_epoch(&isolation_before)
        .unwrap_or_else(|error| panic!("retry isolation epoch: {error}"));
    assert_eq!(isolated_before.principal_label, InformationLabel::bottom());

    let isolation_after = IsolationEpochTransition {
        new_isolation_epoch_id: IsolationEpochId::new("epoch-after")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        new_session_id: SessionId::new("session-isolation-after")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        transition_id: record("isolation-after"),
        ..isolation_before
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.open_isolation_epoch(&isolation_after));
    let isolated_key = FlowStateKey {
        tenant_id: isolation_after.tenant_id.clone(),
        principal_id: isolation_after.principal_id.clone(),
        lineage_id: isolation_after.lineage_id.clone(),
        session_id: isolation_after.new_session_id.clone(),
        isolation_epoch_id: isolation_after.new_isolation_epoch_id.clone(),
    };
    let stored_isolation = store
        .load(&isolated_key)
        .unwrap_or_else(|error| panic!("load committed isolation epoch: {error}"))
        .unwrap_or_else(|| panic!("committed isolation epoch missing"));
    assert_eq!(
        store
            .open_isolation_epoch(&isolation_after)
            .unwrap_or_else(|error| panic!("recover isolation epoch: {error}")),
        stored_isolation
    );

    let fence_before_request = EgressFenceRequest {
        key: first_key.clone(),
        request_id: RequestId::new("egress-before")
            .unwrap_or_else(|error| panic!("request id: {error}")),
        request_hash: Digest32::new([11; 32]),
        expected_context_generation: first_snapshot.context_generation,
        expires_at_unix_ms: expiry,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.acquire_egress_fence(&fence_before_request));
    let fence_before = store
        .acquire_egress_fence(&fence_before_request)
        .unwrap_or_else(|error| panic!("retry egress fence: {error}"));
    store
        .validate_egress_fence(&fence_before)
        .unwrap_or_else(|error| panic!("validate egress fence: {error}"));

    let fence_after_request = EgressFenceRequest {
        key: second_key,
        request_id: RequestId::new("egress-after")
            .unwrap_or_else(|error| panic!("request id: {error}")),
        request_hash: Digest32::new([12; 32]),
        expected_context_generation: committed_snapshot.context_generation,
        expires_at_unix_ms: expiry,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.acquire_egress_fence(&fence_after_request));
    let fence_after = store
        .acquire_egress_fence(&fence_after_request)
        .unwrap_or_else(|error| panic!("recover egress fence: {error}"));

    let commit_before = EgressFenceCommit {
        fence: fence_before,
        dispatch_commitment_id: record("dispatch-before"),
        committed_at_unix_ms: clock,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.commit_egress_fence(&commit_before));
    let committed_before = store
        .commit_egress_fence(&commit_before)
        .unwrap_or_else(|error| panic!("retry egress commit: {error}"));
    assert_eq!(
        committed_before.dispatch_commitment_id,
        record("dispatch-before")
    );

    let commit_after = EgressFenceCommit {
        fence: fence_after,
        dispatch_commitment_id: record("dispatch-after"),
        committed_at_unix_ms: clock,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.commit_egress_fence(&commit_after));
    assert_eq!(
        store
            .commit_egress_fence(&commit_after)
            .unwrap_or_else(|error| panic!("recover egress commit: {error}"))
            .dispatch_commitment_id,
        record("dispatch-after")
    );

    exercise_declassification(store);
    exercise_events(store, clock);
    let (claimed_before, claimed_after) = exercise_responses(store, clock, expiry);
    exercise_overlays(store, &claimed_before, &claimed_after);
    exercise_approvals(store, expiry);
    exercise_lineage_fences(store, expiry);
}

fn exercise_declassification<S: DeclassificationUseStore>(store: &Faulting<S>) {
    let before = DeclassificationConsumeRequest {
        tenant_id: tenant(),
        grant_id: GrantId::new("grant-before").unwrap_or_else(|error| panic!("grant id: {error}")),
        request_hash: Digest32::new([1_u8; 32]),
        consumed_at_unix_ms: 1,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.consume(&before));
    assert_eq!(
        store
            .consume(&before)
            .unwrap_or_else(|error| panic!("retry declassification consume: {error}")),
        DeclassificationConsume::Consumed
    );

    let after = DeclassificationConsumeRequest {
        grant_id: GrantId::new("grant-after").unwrap_or_else(|error| panic!("grant id: {error}")),
        request_hash: Digest32::new([2_u8; 32]),
        ..before
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.consume(&after));
    assert!(matches!(
        store
            .consume(&after)
            .unwrap_or_else(|error| panic!("recover declassification consume: {error}")),
        DeclassificationConsume::AlreadyConsumed {
            state: DeclassificationUseState::ConsumedPendingDispatch,
            ..
        }
    ));

    let outcome_before = DeclassificationOutcomeRequest {
        tenant_id: tenant(),
        grant_id: before.grant_id,
        request_hash: before.request_hash,
        expected_state: DeclassificationUseState::ConsumedPendingDispatch,
        new_state: DeclassificationUseState::Released,
        transition_id: record("declassification-outcome-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.record_outcome(&outcome_before));
    assert!(matches!(
        store
            .consume(&DeclassificationConsumeRequest {
                tenant_id: tenant(),
                grant_id: outcome_before.grant_id.clone(),
                request_hash: outcome_before.request_hash,
                consumed_at_unix_ms: 1,
            })
            .unwrap_or_else(|error| panic!("read declassification before outcome: {error}")),
        DeclassificationConsume::AlreadyConsumed {
            state: DeclassificationUseState::ConsumedPendingDispatch,
            ..
        }
    ));
    store
        .record_outcome(&outcome_before)
        .unwrap_or_else(|error| panic!("retry declassification outcome: {error}"));

    let outcome_after = DeclassificationOutcomeRequest {
        tenant_id: tenant(),
        grant_id: after.grant_id,
        request_hash: after.request_hash,
        expected_state: DeclassificationUseState::ConsumedPendingDispatch,
        new_state: DeclassificationUseState::DispatchFailed,
        transition_id: record("declassification-outcome-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.record_outcome(&outcome_after));
    assert!(matches!(
        store
            .consume(&DeclassificationConsumeRequest {
                tenant_id: tenant(),
                grant_id: outcome_after.grant_id.clone(),
                request_hash: outcome_after.request_hash,
                consumed_at_unix_ms: 1,
            })
            .unwrap_or_else(|error| panic!("read committed outcome: {error}")),
        DeclassificationConsume::AlreadyConsumed {
            state: DeclassificationUseState::DispatchFailed,
            ..
        }
    ));
    store
        .record_outcome(&outcome_after)
        .unwrap_or_else(|error| panic!("recover declassification outcome: {error}"));
}

fn correlation_key(value: u8) -> CorrelationPartitionKey {
    CorrelationPartitionKey {
        tenant_id: tenant(),
        rule_id: RuleId::new(format!("rule-{value}"))
            .unwrap_or_else(|error| panic!("rule id: {error}")),
        partition_hash: Digest32::new([value; 32]),
    }
}

fn scan_for(key: &CorrelationPartitionKey, through: u64) -> EventPartitionScan {
    EventPartitionScan {
        tenant_id: key.tenant_id.clone(),
        rule_id: key.rule_id.clone(),
        partition_hash: key.partition_hash,
        after_event_time_unix_ms: None,
        after_event_id: None,
        through_event_time_unix_ms: through,
        max_results: 8,
    }
}

fn partial(key: &CorrelationPartitionKey, generation: u64, watermark: u64) -> CorrelationPartial {
    let canonical_body = body(b"{}");
    CorrelationPartial {
        key: key.clone(),
        generation,
        watermark_unix_ms: watermark,
        expires_at_unix_ms: watermark.saturating_add(60_000),
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
    }
}

fn exercise_events<S: SecurityEventStore>(store: &Faulting<S>, clock: u64) {
    let verified_before = verified_event("verified-before", clock);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.append_verified(&verified_before));
    assert_eq!(
        store
            .append_verified(&verified_before)
            .unwrap_or_else(|error| panic!("retry verified append: {error}")),
        EventAppend::Inserted
    );

    let verified_after = verified_event("verified-after", clock.saturating_add(1));
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.append_verified(&verified_after));
    assert_eq!(
        store
            .append_verified(&verified_after)
            .unwrap_or_else(|error| panic!("recover verified append: {error}")),
        EventAppend::Duplicate
    );

    let advisory_before = advisory_event("advisory-before", clock);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.append_advisory(&advisory_before));
    assert_eq!(
        store
            .append_advisory(&advisory_before)
            .unwrap_or_else(|error| panic!("retry advisory append: {error}")),
        EventAppend::Inserted
    );

    let advisory_after = advisory_event("advisory-after", clock.saturating_add(1));
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.append_advisory(&advisory_after));
    assert_eq!(
        store
            .append_advisory(&advisory_after)
            .unwrap_or_else(|error| panic!("recover advisory append: {error}")),
        EventAppend::Duplicate
    );

    let before_key = correlation_key(3);
    let before_index = CorrelationEventIndexRequest {
        key: before_key.clone(),
        event_id: verified_before.event_id.clone(),
        transition_id: record("index-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.index_partition_event(&before_index));
    assert!(store
        .scan_partition(&scan_for(&before_key, clock.saturating_add(10)))
        .unwrap_or_else(|error| panic!("scan before index retry: {error}"))
        .events
        .is_empty());
    store
        .index_partition_event(&before_index)
        .unwrap_or_else(|error| panic!("retry event index: {error}"));

    let after_key = correlation_key(4);
    let after_index = CorrelationEventIndexRequest {
        key: after_key.clone(),
        event_id: verified_after.event_id,
        transition_id: record("index-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.index_partition_event(&after_index));
    assert_eq!(
        store
            .scan_partition(&scan_for(&after_key, clock.saturating_add(10)))
            .unwrap_or_else(|error| panic!("scan committed index: {error}"))
            .events
            .len(),
        1
    );
    store
        .index_partition_event(&after_index)
        .unwrap_or_else(|error| panic!("recover event index: {error}"));

    let before_scan = scan_for(&before_key, clock);
    let before_cas = CorrelationCasRequest {
        scan: before_scan,
        observed_partition_generation: 1,
        partial: partial(&before_key, 0, clock),
        expected_generation: None,
        transition_id: record("correlation-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.compare_and_swap_correlation(&before_cas));
    assert_eq!(
        store
            .load_correlation(&before_key)
            .unwrap_or_else(|error| panic!("load correlation before retry: {error}")),
        None
    );
    store
        .compare_and_swap_correlation(&before_cas)
        .unwrap_or_else(|error| panic!("retry correlation CAS: {error}"));

    let after_cas = CorrelationCasRequest {
        scan: scan_for(&after_key, clock.saturating_add(1)),
        observed_partition_generation: 1,
        partial: partial(&after_key, 0, clock.saturating_add(1)),
        expected_generation: None,
        transition_id: record("correlation-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.compare_and_swap_correlation(&after_cas));
    assert_eq!(
        store
            .load_correlation(&after_key)
            .unwrap_or_else(|error| panic!("load committed correlation: {error}")),
        Some(after_cas.partial.clone())
    );
    store
        .compare_and_swap_correlation(&after_cas)
        .unwrap_or_else(|error| panic!("recover correlation CAS: {error}"));

    let stale_key = correlation_key(13);
    let stale_first = verified_event("verified-stale-first", clock.saturating_add(2));
    let stale_second = verified_event("verified-stale-second", clock.saturating_add(3));
    store
        .append_verified(&stale_first)
        .unwrap_or_else(|error| panic!("append first revision event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: stale_key.clone(),
            event_id: stale_first.event_id,
            transition_id: record("index-stale-first"),
        })
        .unwrap_or_else(|error| panic!("index first revision event: {error}"));
    let observed = store
        .scan_partition(&scan_for(&stale_key, clock.saturating_add(3)))
        .unwrap_or_else(|error| panic!("scan first partition revision: {error}"));
    assert_eq!(observed.partition_generation, 1);
    store
        .append_verified(&stale_second)
        .unwrap_or_else(|error| panic!("append second revision event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: stale_key.clone(),
            event_id: stale_second.event_id,
            transition_id: record("index-stale-second"),
        })
        .unwrap_or_else(|error| panic!("index second revision event: {error}"));
    let stale_cas = CorrelationCasRequest {
        scan: scan_for(&stale_key, clock.saturating_add(3)),
        observed_partition_generation: observed.partition_generation,
        partial: partial(&stale_key, 0, clock.saturating_add(3)),
        expected_generation: None,
        transition_id: record("correlation-stale-revision"),
    };
    require_error_kind(
        store.compare_and_swap_correlation(&stale_cas),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .load_correlation(&stale_key)
            .unwrap_or_else(|error| panic!("load rejected stale correlation: {error}")),
        None
    );

    require_error_kind(
        store.delete_correlation(&CorrelationDeleteRequest {
            key: before_key.clone(),
            expected_generation: 1,
            transition_id: record("correlation-delete-wrong-generation"),
        }),
        PortErrorKind::Conflict,
    );
    assert!(store
        .load_correlation(&before_key)
        .unwrap_or_else(|error| panic!("load correlation after rejected delete: {error}"))
        .is_some());

    let delete_before = CorrelationDeleteRequest {
        key: before_key.clone(),
        expected_generation: 0,
        transition_id: record("correlation-delete-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.delete_correlation(&delete_before));
    assert!(store
        .load_correlation(&before_key)
        .unwrap_or_else(|error| panic!("load correlation before delete retry: {error}"))
        .is_some());
    store
        .delete_correlation(&delete_before)
        .unwrap_or_else(|error| panic!("retry correlation delete: {error}"));

    let delete_after = CorrelationDeleteRequest {
        key: after_key.clone(),
        expected_generation: 0,
        transition_id: record("correlation-delete-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.delete_correlation(&delete_after));
    assert_eq!(
        store
            .load_correlation(&after_key)
            .unwrap_or_else(|error| panic!("load deleted correlation: {error}")),
        None
    );
    store
        .delete_correlation(&delete_after)
        .unwrap_or_else(|error| panic!("recover correlation delete: {error}"));
}

fn claim_request(owner: &str, clock: u64, expiry: u64) -> SchedulerClaimRequest {
    SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record(&format!("claim-{owner}")),
        lease_owner_id: LeaseOwnerId::new(owner)
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: expiry,
        max_claims: 1,
    }
}

fn response_effect(action_id: &ActionId, effect_id: &str, token: u64) -> ResponseEffectRecord {
    let canonical_body = body(b"{}");
    ResponseEffectRecord {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        effect_id: effect(effect_id),
        generation: 0,
        scheduler_fencing_token: token,
        state: record("applied"),
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
        encrypted_rollback_ref: None,
    }
}

fn exercise_responses<S: ResponseStore>(
    store: &Faulting<S>,
    clock: u64,
    expiry: u64,
) -> (ScheduledWork, ScheduledWork) {
    let create_before = response_plan("response-create-before", 0, None);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.create(&create_before));
    assert_eq!(
        store
            .create(&create_before)
            .unwrap_or_else(|error| panic!("retry response create: {error}")),
        CreateOutcome::Created
    );

    let create_after = response_plan("response-create-after", 0, None);
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.create(&create_after));
    assert_eq!(
        store
            .create(&create_after)
            .unwrap_or_else(|error| panic!("recover response create: {error}")),
        CreateOutcome::Existing
    );

    let cas_before = ResponseCasRequest {
        record: response_plan("response-create-before", 1, None),
        expected_generation: 0,
        transition_id: record("response-cas-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.compare_and_swap(&cas_before));
    assert_eq!(
        store
            .compare_and_swap(&cas_before)
            .unwrap_or_else(|error| panic!("retry response CAS: {error}")),
        cas_before.record
    );

    let cas_after = ResponseCasRequest {
        record: response_plan("response-create-after", 1, None),
        expected_generation: 0,
        transition_id: record("response-cas-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.compare_and_swap(&cas_after));
    assert_eq!(
        store
            .compare_and_swap(&cas_after)
            .unwrap_or_else(|error| panic!("recover response CAS: {error}")),
        cas_after.record
    );

    let due_before = response_plan("scheduler-before", 0, Some(clock.saturating_sub(1)));
    store
        .create(&due_before)
        .unwrap_or_else(|error| panic!("create scheduler plan: {error}"));
    let claim_before = claim_request("scheduler-owner-before", clock, expiry);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.claim_due(&claim_before));
    let claimed_before = store
        .claim_due(&claim_before)
        .unwrap_or_else(|error| panic!("retry scheduler claim: {error}"));
    assert_eq!(claimed_before.len(), 1);
    let claimed_before = claimed_before
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("scheduler claim was empty"));

    let due_after = response_plan("scheduler-after", 0, Some(clock.saturating_sub(1)));
    store
        .create(&due_after)
        .unwrap_or_else(|error| panic!("create second scheduler plan: {error}"));
    let claim_after = claim_request("scheduler-owner-after", clock, expiry);
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.claim_due(&claim_after));
    let recovered_after = store
        .claim_due(&claim_after)
        .unwrap_or_else(|error| panic!("retry committed scheduler claim: {error}"));
    assert_eq!(recovered_after.len(), 1);
    let recovered_after = recovered_after
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("recovered scheduler claim was empty"));
    assert_eq!(recovered_after.action_id, due_after.action_id);
    assert_eq!(
        store
            .claim_due(&claim_after)
            .unwrap_or_else(|error| panic!("repeat exact scheduler claim: {error}")),
        vec![recovered_after.clone()]
    );
    let mismatched_claim = SchedulerClaimRequest {
        max_claims: 2,
        ..claim_after.clone()
    };
    require_error_kind(store.claim_due(&mismatched_claim), PortErrorKind::Conflict);
    let tenant_b =
        TenantId::new("tenant-contract-b").unwrap_or_else(|error| panic!("tenant id: {error}"));
    let mut tenant_b_plan = response_plan("scheduler-tenant-b", 0, Some(clock.saturating_sub(1)));
    tenant_b_plan.tenant_id = tenant_b.clone();
    store
        .create(&tenant_b_plan)
        .unwrap_or_else(|error| panic!("create other tenant scheduler plan: {error}"));
    let tenant_b_claim = SchedulerClaimRequest {
        tenant_id: tenant_b.clone(),
        ..claim_after.clone()
    };
    let tenant_b_work = store
        .claim_due(&tenant_b_claim)
        .unwrap_or_else(|error| panic!("claim other tenant plan: {error}"));
    assert_eq!(tenant_b_work.len(), 1);
    assert_eq!(tenant_b_work[0].tenant_id, tenant_b);
    assert_eq!(tenant_b_work[0].action_id, tenant_b_plan.action_id);
    assert_eq!(
        store
            .claim_due(&claim_after)
            .unwrap_or_else(|error| panic!("recover original tenant claim: {error}")),
        vec![recovered_after.clone()]
    );
    let committed_lease_probe = response_effect(
        &due_after.action_id,
        "scheduler-after-lease-probe",
        recovered_after.fencing_token,
    );
    assert_eq!(
        store
            .persist_effect(&committed_lease_probe)
            .unwrap_or_else(|error| panic!("probe committed scheduler lease: {error}")),
        CreateOutcome::Created
    );

    let effect_before = response_effect(
        &claimed_before.action_id,
        "response-effect-before",
        claimed_before.fencing_token,
    );
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.persist_effect(&effect_before));
    assert_eq!(
        store
            .persist_effect(&effect_before)
            .unwrap_or_else(|error| panic!("retry response effect: {error}")),
        CreateOutcome::Created
    );

    let effect_after = response_effect(
        &claimed_before.action_id,
        "response-effect-after",
        claimed_before.fencing_token,
    );
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.persist_effect(&effect_after));
    assert_eq!(
        store
            .persist_effect(&effect_after)
            .unwrap_or_else(|error| panic!("recover response effect: {error}")),
        CreateOutcome::Existing
    );
    (claimed_before, recovered_after)
}

fn exercise_overlays<S: ContainmentOverlayStore>(
    store: &Faulting<S>,
    claimed_before: &ScheduledWork,
    claimed_after: &ScheduledWork,
) {
    let before_target = scoped_action("overlay-before");
    let before_apply = OverlayApplyRequest {
        target: before_target.clone(),
        action_id: claimed_before.action_id.clone(),
        contribution: OverlayContribution {
            effect_id: effect("overlay-effect-before"),
            posture_rank: 4,
            contribution_hash: Digest32::new([11_u8; 32]),
            expires_at_unix_ms: None,
        },
        expected_generation: 0,
        scheduler_fencing_token: claimed_before.fencing_token,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.apply_contribution(&before_apply));
    assert_eq!(
        store
            .load_effective(&before_target)
            .unwrap_or_else(|error| panic!("load overlay before retry: {error}")),
        None
    );
    let before_snapshot = store
        .apply_contribution(&before_apply)
        .unwrap_or_else(|error| panic!("retry overlay apply: {error}"));
    assert_eq!(before_snapshot.generation, 1);

    let after_target = scoped_action("overlay-after");
    let after_apply = OverlayApplyRequest {
        target: after_target.clone(),
        action_id: claimed_after.action_id.clone(),
        contribution: OverlayContribution {
            effect_id: effect("overlay-effect-after"),
            posture_rank: 7,
            contribution_hash: Digest32::new([12_u8; 32]),
            expires_at_unix_ms: None,
        },
        expected_generation: 0,
        scheduler_fencing_token: claimed_after.fencing_token,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.apply_contribution(&after_apply));
    let after_snapshot = store
        .load_effective(&after_target)
        .unwrap_or_else(|error| panic!("load committed overlay: {error}"))
        .unwrap_or_else(|| panic!("committed overlay missing"));
    assert_eq!(after_snapshot.generation, 1);
    assert_eq!(
        store
            .apply_contribution(&after_apply)
            .unwrap_or_else(|error| panic!("recover overlay apply: {error}")),
        after_snapshot
    );

    let before_remove = OverlayRemoveRequest {
        target: before_target.clone(),
        action_id: claimed_before.action_id.clone(),
        effect_id: before_apply.contribution.effect_id,
        expected_generation: 1,
        scheduler_fencing_token: claimed_before.fencing_token,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.remove_contribution(&before_remove));
    assert_eq!(
        store
            .load_effective(&before_target)
            .unwrap_or_else(|error| panic!("load overlay before remove retry: {error}"))
            .unwrap_or_else(|| panic!("overlay missing before remove retry"))
            .active_contributions
            .len(),
        1
    );
    assert!(store
        .remove_contribution(&before_remove)
        .unwrap_or_else(|error| panic!("retry overlay remove: {error}"))
        .active_contributions
        .is_empty());

    let after_remove = OverlayRemoveRequest {
        target: after_target.clone(),
        action_id: after_apply.action_id,
        effect_id: after_apply.contribution.effect_id,
        expected_generation: 1,
        scheduler_fencing_token: claimed_after.fencing_token,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.remove_contribution(&after_remove));
    assert!(store
        .load_effective(&after_target)
        .unwrap_or_else(|error| panic!("load committed overlay removal: {error}"))
        .unwrap_or_else(|| panic!("overlay state missing after removal"))
        .active_contributions
        .is_empty());
    assert!(store
        .remove_contribution(&after_remove)
        .unwrap_or_else(|error| panic!("recover overlay removal: {error}"))
        .active_contributions
        .is_empty());
}

fn reservation(value: &str, expiry: u64) -> ApprovalReservation {
    ApprovalReservation {
        tenant_id: tenant(),
        action_id: action(value),
        reservation_id: record(&format!("reservation-{value}")),
        approval_set_hash: digest(value.as_bytes()),
        expires_at_unix_ms: expiry,
    }
}

fn load_reservation<S: ApprovalReservationStore>(
    store: &Faulting<S>,
    value: &str,
) -> Option<StoredApprovalReservation> {
    store
        .load_reservation(&scoped_action(value))
        .unwrap_or_else(|error| panic!("load approval reservation: {error}"))
}

fn exercise_approvals<S: ApprovalReservationStore>(store: &Faulting<S>, expiry: u64) {
    let reserve_before = ApprovalReservationCreate {
        reservation: reservation("approval-reserve-before", expiry),
        transition_id: record("approval-reserve-before-transition"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.reserve(&reserve_before));
    assert_eq!(load_reservation(store, "approval-reserve-before"), None);
    assert_eq!(
        store
            .reserve(&reserve_before)
            .unwrap_or_else(|error| panic!("retry approval reserve: {error}")),
        CreateOutcome::Created
    );

    let reserve_after = ApprovalReservationCreate {
        reservation: reservation("approval-reserve-after", expiry),
        transition_id: record("approval-reserve-after-transition"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.reserve(&reserve_after));
    assert_eq!(
        load_reservation(store, "approval-reserve-after")
            .unwrap_or_else(|| panic!("committed reservation missing"))
            .state,
        ApprovalReservationState::Reserved
    );
    assert_eq!(
        store
            .reserve(&reserve_after)
            .unwrap_or_else(|error| panic!("recover approval reserve: {error}")),
        CreateOutcome::Existing
    );

    let commit_before = ApprovalReservationMutation {
        reservation: reserve_before.reservation,
        transition_id: record("approval-commit-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.commit_reservation(&commit_before));
    assert_eq!(
        load_reservation(store, "approval-reserve-before")
            .unwrap_or_else(|| panic!("reserved approval missing"))
            .state,
        ApprovalReservationState::Reserved
    );
    store
        .commit_reservation(&commit_before)
        .unwrap_or_else(|error| panic!("retry approval commit: {error}"));

    let commit_after_reserve = ApprovalReservationCreate {
        reservation: reservation("approval-commit-after", expiry),
        transition_id: record("approval-commit-after-reserve"),
    };
    store
        .reserve(&commit_after_reserve)
        .unwrap_or_else(|error| panic!("reserve approval for commit: {error}"));
    let commit_after = ApprovalReservationMutation {
        reservation: commit_after_reserve.reservation,
        transition_id: record("approval-commit-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.commit_reservation(&commit_after));
    assert_eq!(
        load_reservation(store, "approval-commit-after")
            .unwrap_or_else(|| panic!("committed approval missing"))
            .state,
        ApprovalReservationState::Committed
    );
    store
        .commit_reservation(&commit_after)
        .unwrap_or_else(|error| panic!("recover approval commit: {error}"));

    let cancel_before_reserve = ApprovalReservationCreate {
        reservation: reservation("approval-cancel-before", expiry),
        transition_id: record("approval-cancel-before-reserve"),
    };
    store
        .reserve(&cancel_before_reserve)
        .unwrap_or_else(|error| panic!("reserve approval for cancellation: {error}"));
    let cancel_before = ApprovalReservationMutation {
        reservation: cancel_before_reserve.reservation,
        transition_id: record("approval-cancel-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.cancel_reservation(&cancel_before));
    assert_eq!(
        load_reservation(store, "approval-cancel-before")
            .unwrap_or_else(|| panic!("approval missing before cancel retry"))
            .state,
        ApprovalReservationState::Reserved
    );
    store
        .cancel_reservation(&cancel_before)
        .unwrap_or_else(|error| panic!("retry approval cancellation: {error}"));

    let cancel_after_reserve = ApprovalReservationCreate {
        reservation: reservation("approval-cancel-after", expiry),
        transition_id: record("approval-cancel-after-reserve"),
    };
    store
        .reserve(&cancel_after_reserve)
        .unwrap_or_else(|error| panic!("reserve second approval for cancellation: {error}"));
    let cancel_after = ApprovalReservationMutation {
        reservation: cancel_after_reserve.reservation,
        transition_id: record("approval-cancel-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.cancel_reservation(&cancel_after));
    assert_eq!(
        load_reservation(store, "approval-cancel-after")
            .unwrap_or_else(|| panic!("cancelled approval missing"))
            .state,
        ApprovalReservationState::Cancelled
    );
    store
        .cancel_reservation(&cancel_after)
        .unwrap_or_else(|error| panic!("recover approval cancellation: {error}"));
}

fn fence_request(value: &str, expiry: u64) -> LineageFenceRequest {
    LineageFenceRequest {
        tenant_id: tenant(),
        action_id: action(value),
        expected_commit_index: 7,
        expected_affected_set_hash: digest(value.as_bytes()),
        expires_at_unix_ms: expiry,
    }
}

fn exercise_lineage_fences<S: LineageFenceStore>(store: &Faulting<S>, expiry: u64) {
    let acquire_before = fence_request("lineage-acquire-before", expiry);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.acquire(&acquire_before));
    assert_eq!(
        store
            .query(&scoped_action("lineage-acquire-before"))
            .unwrap_or_else(|error| panic!("query lineage fence: {error}")),
        None
    );
    let fence_before = store
        .acquire(&acquire_before)
        .unwrap_or_else(|error| panic!("retry lineage acquire: {error}"));

    let acquire_after = fence_request("lineage-acquire-after", expiry);
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.acquire(&acquire_after));
    let fence_after = store
        .query(&scoped_action("lineage-acquire-after"))
        .unwrap_or_else(|error| panic!("query committed lineage fence: {error}"))
        .unwrap_or_else(|| panic!("committed lineage fence missing"));
    assert_eq!(
        store
            .acquire(&acquire_after)
            .unwrap_or_else(|error| panic!("recover lineage acquire: {error}")),
        fence_after
    );

    let release_before = LineageFenceRelease {
        tenant_id: tenant(),
        action_id: fence_before.action_id,
        fencing_token: fence_before.fencing_token,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.release(&release_before));
    assert!(store
        .query(&scoped_action("lineage-acquire-before"))
        .unwrap_or_else(|error| panic!("query fence before release retry: {error}"))
        .is_some());
    store
        .release(&release_before)
        .unwrap_or_else(|error| panic!("retry lineage release: {error}"));

    let release_after = LineageFenceRelease {
        tenant_id: tenant(),
        action_id: fence_after.action_id,
        fencing_token: fence_after.fencing_token,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.release(&release_after));
    assert_eq!(
        store
            .query(&scoped_action("lineage-acquire-after"))
            .unwrap_or_else(|error| panic!("query released lineage fence: {error}")),
        None
    );
    store
        .release(&release_after)
        .unwrap_or_else(|error| panic!("recover lineage release: {error}"));
}

fn has_compartment(label: &InformationLabel, value: &str) -> bool {
    label.compartments().is_some_and(|compartments| {
        compartments.contains(
            &Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}")),
        )
    })
}

fn exercise_cross_key_flow_contract<S: FlowStateStore>(store: &S) {
    let first = FlowStateKey {
        tenant_id: tenant(),
        principal_id: PrincipalId::new("scope-principal")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new("scope-lineage-a")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new("scope-shared-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("scope-epoch")
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
    };
    store
        .join(&FlowJoinRequest {
            key: first.clone(),
            principal_join: label("scope-principal-secret"),
            lineage_join: label("scope-lineage-secret"),
            session_join: label("scope-session-secret"),
            transition_id: record("scope-first-join"),
        })
        .unwrap_or_else(|error| panic!("join first scope: {error}"));

    let sibling = FlowStateKey {
        lineage_id: LineageId::new("scope-lineage-b")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        ..first.clone()
    };
    let sibling_snapshot = store
        .join(&FlowJoinRequest {
            key: sibling.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("scope-sibling-join"),
        })
        .unwrap_or_else(|error| panic!("join sibling scope: {error}"));
    assert!(has_compartment(
        &sibling_snapshot.principal_label,
        "scope-principal-secret"
    ));
    assert!(has_compartment(
        &sibling_snapshot.session_label,
        "scope-session-secret"
    ));

    let fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: sibling.clone(),
            request_id: RequestId::new("scope-sibling-fence")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([21; 32]),
            expected_context_generation: sibling_snapshot.context_generation,
            expires_at_unix_ms: now_unix_ms().saturating_add(120_000),
        })
        .unwrap_or_else(|error| panic!("acquire sibling fence: {error}"));
    store
        .join(&FlowJoinRequest {
            key: first.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: label("scope-session-late"),
            transition_id: record("scope-session-advance"),
        })
        .unwrap_or_else(|error| panic!("advance shared session: {error}"));
    require_error_kind(store.validate_egress_fence(&fence), PortErrorKind::Conflict);
    let refreshed = store
        .load(&sibling)
        .unwrap_or_else(|error| panic!("load sibling scope: {error}"))
        .unwrap_or_else(|| panic!("sibling scope missing"));
    assert!(has_compartment(
        &refreshed.session_label,
        "scope-session-late"
    ));

    let new_session = FlowStateKey {
        session_id: SessionId::new("scope-new-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        ..sibling
    };
    let inherited = store
        .load(&new_session)
        .unwrap_or_else(|error| panic!("load inherited session: {error}"))
        .unwrap_or_else(|| panic!("inherited session missing"));
    assert!(has_compartment(
        &inherited.principal_label,
        "scope-principal-secret"
    ));
    assert!(!has_compartment(
        &inherited.session_label,
        "scope-session-secret"
    ));

    let other_principal = FlowStateKey {
        principal_id: PrincipalId::new("scope-principal-b")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        session_id: SessionId::new("scope-other-principal-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("scope-other-principal-epoch")
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
        ..first
    };
    let lineage_inherited = store
        .join(&FlowJoinRequest {
            key: other_principal,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("scope-other-principal-join"),
        })
        .unwrap_or_else(|error| panic!("join other principal: {error}"));
    assert!(has_compartment(
        &lineage_inherited.lineage_label,
        "scope-lineage-secret"
    ));
}

fn exercise_scheduler_takeover_contract<S: ResponseStore>(store: &S) {
    let clock = now_unix_ms();
    let plan = response_plan("takeover-contract-action", 0, Some(clock.saturating_sub(1)));
    assert_eq!(
        store
            .create(&plan)
            .unwrap_or_else(|error| panic!("create takeover plan: {error}")),
        CreateOutcome::Created
    );
    let first_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("takeover-contract-first-claim"),
        lease_owner_id: LeaseOwnerId::new("takeover-contract-first-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: clock.saturating_add(200),
        max_claims: 1,
    };
    let first = store
        .claim_due(&first_request)
        .unwrap_or_else(|error| panic!("claim first lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("first lease missing"));
    std::thread::sleep(Duration::from_millis(250));
    let second_clock = now_unix_ms();
    let second_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("takeover-contract-second-claim"),
        lease_owner_id: LeaseOwnerId::new("takeover-contract-second-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: second_clock,
        lease_expires_at_unix_ms: second_clock.saturating_add(120_000),
        max_claims: 1,
    };
    let second = store
        .claim_due(&second_request)
        .unwrap_or_else(|error| panic!("claim takeover lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("takeover lease missing"));
    assert_eq!(second.action_id, first.action_id);
    assert!(second.fencing_token > first.fencing_token);
    require_error_kind(
        store.persist_effect(&response_effect(
            &first.action_id,
            "takeover-contract-stale-effect",
            first.fencing_token,
        )),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .persist_effect(&response_effect(
                &second.action_id,
                "takeover-contract-current-effect",
                second.fencing_token,
            ))
            .unwrap_or_else(|error| panic!("persist current effect: {error}")),
        CreateOutcome::Created
    );
}

fn exercise_response_effect_recovery_contract<S: ResponseStore>(store: &S) {
    let clock = now_unix_ms();
    let plan = response_plan(
        "effect-recovery-contract-action",
        0,
        Some(clock.saturating_sub(1)),
    );
    assert_eq!(
        store
            .create(&plan)
            .unwrap_or_else(|error| panic!("create recovery plan: {error}")),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .load_plan(&ResponsePlanKey {
                tenant_id: plan.tenant_id.clone(),
                action_id: plan.action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load recovery plan: {error}")),
        Some(plan.clone())
    );

    let first_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("effect-recovery-first-claim"),
        lease_owner_id: LeaseOwnerId::new("effect-recovery-first-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: clock.saturating_add(200),
        max_claims: 1,
    };
    let first = store
        .claim_due(&first_request)
        .unwrap_or_else(|error| panic!("claim first recovery lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("first recovery lease missing"));
    let mut intent = response_effect(
        &first.action_id,
        "effect-recovery-contract-effect",
        first.fencing_token,
    );
    intent.generation = 0;
    intent.state = record("apply_requested");
    assert_eq!(
        store
            .persist_effect(&intent)
            .unwrap_or_else(|error| panic!("persist durable effect intent: {error}")),
        CreateOutcome::Created
    );
    let effect_key = ResponseEffectKey {
        tenant_id: intent.tenant_id.clone(),
        effect_id: intent.effect_id.clone(),
    };
    assert_eq!(
        store
            .load_effect(&effect_key)
            .unwrap_or_else(|error| panic!("load durable effect intent: {error}")),
        Some(intent.clone())
    );

    std::thread::sleep(Duration::from_millis(250));
    let second_clock = now_unix_ms();
    let second_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("effect-recovery-second-claim"),
        lease_owner_id: LeaseOwnerId::new("effect-recovery-second-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: second_clock,
        lease_expires_at_unix_ms: second_clock.saturating_add(120_000),
        max_claims: 1,
    };
    let second = store
        .claim_due(&second_request)
        .unwrap_or_else(|error| panic!("claim takeover recovery lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("takeover recovery lease missing"));
    assert!(second.fencing_token > first.fencing_token);

    let applied_body = body(br#"{"phase":"applied"}"#);
    let applied = ResponseEffectRecord {
        generation: 1,
        scheduler_fencing_token: second.fencing_token,
        state: record("applied"),
        body_hash: digest(applied_body.as_bytes()),
        canonical_body: applied_body,
        ..intent.clone()
    };
    let stale_request = ResponseEffectCasRequest {
        record: ResponseEffectRecord {
            scheduler_fencing_token: first.fencing_token,
            ..applied.clone()
        },
        expected_generation: 0,
        transition_id: record("effect-recovery-stale-result"),
    };
    require_error_kind(
        store.compare_and_swap_effect(&stale_request),
        PortErrorKind::Conflict,
    );

    let takeover_request = ResponseEffectCasRequest {
        record: applied.clone(),
        expected_generation: 0,
        transition_id: record("effect-recovery-current-result"),
    };
    assert_eq!(
        store
            .compare_and_swap_effect(&takeover_request)
            .unwrap_or_else(|error| panic!("persist takeover effect result: {error}")),
        applied
    );
    assert_eq!(
        store
            .compare_and_swap_effect(&takeover_request)
            .unwrap_or_else(|error| panic!("replay takeover effect result: {error}")),
        takeover_request.record
    );
    assert_eq!(
        store
            .load_effect(&effect_key)
            .unwrap_or_else(|error| panic!("load takeover effect result: {error}")),
        Some(takeover_request.record.clone())
    );
    require_error_kind(
        store.compare_and_swap_effect(&ResponseEffectCasRequest {
            record: ResponseEffectRecord {
                state: record("forged-result"),
                ..takeover_request.record.clone()
            },
            ..takeover_request
        }),
        PortErrorKind::Conflict,
    );
}

fn exercise_overlay_action_binding_contract<S: ResponseStore + ContainmentOverlayStore>(store: &S) {
    let clock = now_unix_ms();
    for value in ["binding-action-a", "binding-action-b"] {
        store
            .create(&response_plan(value, 0, Some(clock.saturating_sub(1))))
            .unwrap_or_else(|error| panic!("create binding plan: {error}"));
    }
    let claim = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("binding-contract-claim"),
        lease_owner_id: LeaseOwnerId::new("binding-contract-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: clock.saturating_add(120_000),
        max_claims: 2,
    };
    let claimed = store
        .claim_due(&claim)
        .unwrap_or_else(|error| panic!("claim binding actions: {error}"));
    assert_eq!(claimed.len(), 2);
    let action_a = claimed
        .iter()
        .find(|work| work.action_id == action("binding-action-a"))
        .unwrap_or_else(|| panic!("binding action A missing"));
    let action_b = claimed
        .iter()
        .find(|work| work.action_id == action("binding-action-b"))
        .unwrap_or_else(|| panic!("binding action B missing"));
    let target = scoped_action("binding-contract-target");
    let contribution_a = OverlayContribution {
        effect_id: effect("binding-effect-a"),
        posture_rank: 4,
        contribution_hash: Digest32::new([31; 32]),
        expires_at_unix_ms: None,
    };
    store
        .apply_contribution(&OverlayApplyRequest {
            target: target.clone(),
            action_id: action_a.action_id.clone(),
            contribution: contribution_a.clone(),
            expected_generation: 0,
            scheduler_fencing_token: action_a.fencing_token,
        })
        .unwrap_or_else(|error| panic!("apply action A contribution: {error}"));
    store
        .apply_contribution(&OverlayApplyRequest {
            target: target.clone(),
            action_id: action_b.action_id.clone(),
            contribution: OverlayContribution {
                effect_id: effect("binding-effect-b"),
                posture_rank: 7,
                contribution_hash: Digest32::new([32; 32]),
                expires_at_unix_ms: None,
            },
            expected_generation: 1,
            scheduler_fencing_token: action_b.fencing_token,
        })
        .unwrap_or_else(|error| panic!("apply action B contribution: {error}"));
    require_error_kind(
        store.remove_contribution(&OverlayRemoveRequest {
            target: target.clone(),
            action_id: action_b.action_id.clone(),
            effect_id: contribution_a.effect_id.clone(),
            expected_generation: 2,
            scheduler_fencing_token: action_b.fencing_token,
        }),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .load_effective(&target)
            .unwrap_or_else(|error| panic!("load binding overlay: {error}"))
            .unwrap_or_else(|| panic!("binding overlay missing"))
            .active_contributions
            .len(),
        2
    );
}

#[test]
fn cross_key_flow_contract_holds_for_in_memory_model() {
    exercise_cross_key_flow_contract(&ModelStore::default());
}

#[test]
fn cross_key_flow_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("flow-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_cross_key_flow_contract(&store);
}

#[test]
fn scheduler_takeover_contract_holds_for_in_memory_model() {
    exercise_scheduler_takeover_contract(&ModelStore::default());
}

#[test]
fn scheduler_takeover_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("scheduler-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_scheduler_takeover_contract(&store);
}

#[test]
fn response_effect_recovery_contract_holds_for_in_memory_model() {
    exercise_response_effect_recovery_contract(&ModelStore::default());
}

#[test]
fn response_effect_recovery_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("effect-recovery.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_response_effect_recovery_contract(&store);
}

#[test]
fn overlay_action_binding_contract_holds_for_in_memory_model() {
    exercise_overlay_action_binding_contract(&ModelStore::default());
}

#[test]
fn overlay_action_binding_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("overlay-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_overlay_action_binding_contract(&store);
}

#[test]
fn durable_write_contracts_hold_for_in_memory_model() {
    let store = Faulting::new(ModelStore::default());
    exercise_contracts(&store);
}

#[test]
fn durable_write_contracts_hold_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("security-contract.db");
    let sqlite = SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
        &path,
        Arc::new(AcceptIsolationEvidence),
    )
    .unwrap_or_else(|error| panic!("open security store: {error}"));
    let store = Faulting::new(sqlite);
    exercise_contracts(&store);
}
