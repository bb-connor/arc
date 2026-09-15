use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::hashing::sha256;
use chio_quarantine::{
    build_response_plan, decode_response_record, ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, predict_containment_overlay_apply,
    predict_containment_overlay_remove, ActionId, AdvisorySecurityEvent, CanonicalBody,
    CommittedEgressFence, ContainmentOverlayCommand,
    ContainmentOverlayStore, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventAdmission, CorrelationEventAdmissionRequest, CorrelationEventIndexRequest,
    CorrelationOutcomeCommitRequest, CorrelationOutcomeKey, CorrelationOutcomePublication,
    CorrelationOutcomeStatus, CorrelationPartial, CorrelationPartitionKey, CorrelationScan,
    CreateOutcome, Digest32,
    EffectExecutionStatus, EffectId, EffectOperation, EffectRequest, EffectResult,
    EffectResultQuery, EgressFence, EgressFenceCommit, EgressFenceRequest, EventAppend, EventId,
    EventPartitionScan, FlowJoinRequest, FlowStateKey, FlowStateSnapshot, FlowStateStore,
    IsolationEpochEvidenceVerifierPort, IsolationEpochId, IsolationEpochTransition, LeaseOwnerId,
    LineageFence, LineageFenceRelease, LineageFenceRenewal, LineageFenceRequest, LineageFenceStore,
    LineageId, OpaqueReceiptRef, OverlayApplyRequest, OverlayContribution, OverlayContributions,
    OverlayRemoveRequest, OverlaySnapshot, PortError, PortErrorKind, PortResult, ProducerId,
    ProducerTrustClass, RecordId, RequestId, ResponseCasRequest, ResponseEffectCasRequest,
    ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord, ResponseStore,
    RuleId, ScheduledWork, SchedulerClaimRequest, SecurityEventStore, SessionId, TenantId,
    TenantScopedId, VerifiedEventBatch, VerifiedIsolationEvidence, VerifiedSecurityEvent,
};
use chio_security_types::{
    Compartment, InformationLabel, OperatorCapabilityBinding, PrincipalId,
    ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec, ResponsePlanInput,
    ResponseState, ResponseTarget,
};
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

impl<S: SecurityEventStore> SecurityEventStore for Faulting<S> {
    write_method!(
        admit_verified_correlation_event,
        SecurityEventStore,
        admit_verified_correlation_event,
        CorrelationEventAdmissionRequest,
        CorrelationEventAdmission
    );
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

    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>> {
        self.inner.load_correlation_max_seen_event_time(key)
    }

    write_method!(
        compare_and_swap_correlation,
        SecurityEventStore,
        compare_and_swap_correlation,
        CorrelationCasRequest,
        CorrelationPartial
    );
    write_method!(
        commit_correlation_outcome,
        SecurityEventStore,
        commit_correlation_outcome,
        CorrelationOutcomeCommitRequest,
        CorrelationPartial
    );
    write_method!(
        commit_correlation_outcome_only,
        SecurityEventStore,
        commit_correlation_outcome_only,
        CorrelationOutcomePublication,
        CreateOutcome
    );

    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>> {
        self.inner.load_correlation_outcome(key)
    }

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
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        self.inner.ensure_containment_overlays_ready()
    }

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

    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        self.inner.load_containment_overlay_result(query)
    }
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

    write_method!(
        renew,
        LineageFenceStore,
        renew,
        LineageFenceRenewal,
        LineageFence
    );
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

#[derive(Clone, Default)]
struct ModelState {
    flows: Vec<(RecordId, FlowStateSnapshot)>,
    principal_flows: Vec<ModelPrincipalFlow>,
    lineage_flows: Vec<ModelLineageFlow>,
    session_flows: Vec<ModelSessionFlow>,
    epoch_associations: Vec<ModelEpochAssociation>,
    flow_contexts: Vec<ModelContextGeneration>,
    flow_generation: u64,
    egress: Vec<(EgressFence, Option<CommittedEgressFence>)>,
    verified: Vec<VerifiedSecurityEvent>,
    advisory: Vec<AdvisorySecurityEvent>,
    correlation_index: Vec<(CorrelationEventIndexRequest, u64)>,
    correlations: Vec<(RecordId, CorrelationPartial)>,
    correlation_outcomes: Vec<CorrelationOutcomePublication>,
    correlation_deletes: Vec<RecordId>,
    response_plans: Vec<(Option<ResponseCasRequest>, ResponsePlanRecord)>,
    response_effects: Vec<ResponseEffectRecord>,
    response_effect_transitions: Vec<ResponseEffectCasRequest>,
    scheduler_claims: Vec<(SchedulerClaimRequest, Vec<ScheduledWork>)>,
    scheduler_leases: Vec<ScheduledWork>,
    scheduler_tokens: Vec<(TenantId, u64)>,
    overlays: Vec<(TenantScopedId, OverlaySnapshot)>,
    overlay_bindings: Vec<ModelOverlayBinding>,
    overlay_commands: Vec<ContainmentOverlayCommand>,
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

impl SecurityEventStore for ModelStore {
    fn admit_verified_correlation_event(
        &self,
        request: &CorrelationEventAdmissionRequest,
    ) -> PortResult<CorrelationEventAdmission> {
        let mut state = self.state()?;
        let staged = ModelStore {
            state: Mutex::new(state.clone()),
        };
        let append = staged.append_verified(&request.event)?;
        let capacity = request
            .capacity
            .as_ref()
            .map(|capacity| staged.compare_and_swap_correlation(capacity))
            .transpose()?;
        staged.index_partition_event(&request.index)?;
        *state = staged
            .state
            .into_inner()
            .map_err(|_| PortError::unavailable())?;
        Ok(CorrelationEventAdmission { append, capacity })
    }

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

    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>> {
        let state = self.state()?;
        state
            .correlation_index
            .iter()
            .filter(|(index, _)| index.key == *key)
            .map(|(index, _)| {
                state
                    .verified
                    .iter()
                    .find(|event| {
                        event.tenant_id == key.tenant_id && event.event_id == index.event_id
                    })
                    .map(|event| event.event_time_unix_ms)
                    .ok_or_else(PortError::integrity_failure)
            })
            .collect::<PortResult<Vec<_>>>()
            .map(|event_times| event_times.into_iter().max())
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

    fn commit_correlation_outcome(
        &self,
        request: &CorrelationOutcomeCommitRequest,
    ) -> PortResult<CorrelationPartial> {
        let mut state = self.state()?;
        if request.outcome.partition_hash.as_bytes().iter().all(|byte| *byte == 0)
            || request.outcome.status == CorrelationOutcomeStatus::Deferred
            || request.outcome.partition_hash != request.correlation.partial.key.partition_hash
        {
            return Err(PortError::invalid_data());
        }
        if let Some(existing) = state
            .correlation_outcomes
            .iter()
            .find(|existing| existing.key == request.outcome.key)
        {
            let exact_transition = state.correlations.iter().any(|(transition, partial)| {
                transition == &request.correlation.transition_id
                    && partial == &request.correlation.partial
            });
            return if existing == &request.outcome && exact_transition {
                Ok(request.correlation.partial.clone())
            } else {
                Err(PortError::conflict())
            };
        }
        let indexed = state.correlation_index.iter().any(|(index, _)| {
            index.key.tenant_id == request.outcome.key.tenant_id
                && index.key.rule_id == request.outcome.key.rule_id
                && index.event_id == request.outcome.key.event_id
                && index.key.partition_hash == request.outcome.partition_hash
        });
        let event = state
            .verified
            .iter()
            .find(|event| {
                event.tenant_id == request.outcome.key.tenant_id
                    && event.event_id == request.outcome.key.event_id
            })
            .ok_or_else(PortError::integrity_failure)?;
        if !indexed
            || event.body_hash != request.outcome.event_body_hash
            || event.evidence_hash != request.outcome.event_evidence_hash
        {
            return Err(PortError::integrity_failure());
        }
        let staged = ModelStore {
            state: Mutex::new(state.clone()),
        };
        let partial = staged.compare_and_swap_correlation(&request.correlation)?;
        staged.state()?.correlation_outcomes.push(request.outcome.clone());
        *state = staged
            .state
            .into_inner()
            .map_err(|_| PortError::unavailable())?;
        Ok(partial)
    }

    fn commit_correlation_outcome_only(
        &self,
        outcome: &CorrelationOutcomePublication,
    ) -> PortResult<CreateOutcome> {
        let mut state = self.state()?;
        if outcome.partition_hash.as_bytes().iter().all(|byte| *byte == 0)
            || outcome.status == CorrelationOutcomeStatus::Deferred
        {
            return Err(PortError::invalid_data());
        }
        if let Some(existing) = state
            .correlation_outcomes
            .iter()
            .find(|existing| existing.key == outcome.key)
        {
            return if existing == outcome {
                Ok(CreateOutcome::Existing)
            } else {
                Err(PortError::conflict())
            };
        }
        let indexed = state.correlation_index.iter().any(|(index, _)| {
            index.key.tenant_id == outcome.key.tenant_id
                && index.key.rule_id == outcome.key.rule_id
                && index.event_id == outcome.key.event_id
                && index.key.partition_hash == outcome.partition_hash
        });
        let event = state
            .verified
            .iter()
            .find(|event| {
                event.tenant_id == outcome.key.tenant_id
                    && event.event_id == outcome.key.event_id
            })
            .ok_or_else(PortError::integrity_failure)?;
        if event.body_hash != outcome.event_body_hash
            || event.evidence_hash != outcome.event_evidence_hash
        {
            return Err(PortError::integrity_failure());
        }
        if !indexed {
            if !matches!(
                outcome.status,
                CorrelationOutcomeStatus::Duplicate | CorrelationOutcomeStatus::TooLate
            ) {
                return Err(PortError::conflict());
            }
            let partition = state
                .correlations
                .iter()
                .rev()
                .find(|(_, partial)| {
                    partial.key.tenant_id == outcome.key.tenant_id
                        && partial.key.rule_id == outcome.key.rule_id
                        && partial.key.partition_hash == outcome.partition_hash
                })
                .map(|(_, partial)| partial)
                .ok_or_else(PortError::conflict)?;
            if event.event_time_unix_ms > outcome.watermark_unix_ms
                || outcome.watermark_unix_ms > partition.watermark_unix_ms
            {
                return Err(PortError::conflict());
            }
        }
        state.correlation_outcomes.push(outcome.clone());
        Ok(CreateOutcome::Created)
    }

    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>> {
        Ok(self
            .state()?
            .correlation_outcomes
            .iter()
            .find(|publication| publication.key == *key)
            .cloned())
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
        let candidate_snapshot = decode_response_record(&request.record)
            .map_err(|_| PortError::invalid_data())?;
        let candidate_mutations = candidate_snapshot.mutations.as_slice();
        let appended = candidate_mutations
            .last()
            .ok_or_else(PortError::invalid_data)?;
        if candidate_snapshot.execution_dispatch.is_some()
            || appended.transition_id() != &request.transition_id
            || appended.generation() != request.record.generation
        {
            return Err(PortError::invalid_data());
        }
        if request.record.generation
            != request
                .expected_generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::invalid_data());
        }
        let mut state = self.state()?;
        if let Some((transition, record)) = state
            .response_plans
            .iter()
            .find(|(transition, _)| {
                transition
                    .as_ref()
                    .is_some_and(|stored| stored.transition_id == request.transition_id)
            })
        {
            if transition.as_ref() != Some(request) {
                return Err(PortError::conflict());
            }
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
        let current = &state.response_plans[position].1;
        if current.tenant_id != request.record.tenant_id
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let current_snapshot = decode_response_record(current)
            .map_err(|_| PortError::integrity_failure())?;
        let current_mutations = current_snapshot.mutations.as_slice();
        let exact_prefix = current_mutations
            .len()
            .checked_add(1)
            .is_some_and(|expected| candidate_mutations.len() == expected)
            && &candidate_mutations[..current_mutations.len()] == current_mutations;
        if !exact_prefix
            || candidate_snapshot.schema_version != current_snapshot.schema_version
            || candidate_snapshot.plan != current_snapshot.plan
            || candidate_snapshot.execution_dispatch != current_snapshot.execution_dispatch
            || candidate_snapshot.dispatch_authorization_hash
                != current_snapshot.dispatch_authorization_hash
        {
            return Err(PortError::invalid_data());
        }
        state.response_plans[position] =
            (Some(request.clone()), request.record.clone());
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
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        let _state_guard = self.state()?;
        Ok(())
    }

    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        let mut state = self.state()?;
        model_validate_scheduler_fence(
            &state,
            &request.target.tenant_id,
            &request.action_id,
            request.scheduler_fencing_token,
        )?;
        if let Some(existing) = state.overlay_commands.iter().find(|command| {
            command.request.tenant_id == request.command.request.tenant_id
                && command.request.idempotency_key == request.command.request.idempotency_key
        }) {
            if existing != &request.command {
                return Err(PortError::conflict());
            }
            return Ok(existing.resulting_snapshot.clone());
        }
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
            .unwrap_or_else(|| empty_model_overlay(&request.target));
        if let Some(existing) = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            if existing != &request.contribution {
                return Err(PortError::conflict());
            }
            state.overlay_commands.push(request.command.clone());
            return Ok(current);
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
        if snapshot != request.command.resulting_snapshot {
            return Err(PortError::integrity_failure());
        }
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
        state.overlay_commands.push(request.command.clone());
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
        if let Some(existing) = state.overlay_commands.iter().find(|command| {
            command.request.tenant_id == request.command.request.tenant_id
                && command.request.idempotency_key == request.command.request.idempotency_key
        }) {
            if existing != &request.command {
                return Err(PortError::conflict());
            }
            return Ok(existing.resulting_snapshot.clone());
        }
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
            if current != request.command.resulting_snapshot {
                return Err(PortError::integrity_failure());
            }
            state.overlay_commands.push(request.command.clone());
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
        if snapshot != request.command.resulting_snapshot {
            return Err(PortError::integrity_failure());
        }
        state.overlays[position].1 = snapshot.clone();
        state.overlay_commands.push(request.command.clone());
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

    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let state = self.state()?;
        let Some(command) = state.overlay_commands.iter().find(|command| {
            command.request.tenant_id == query.tenant_id
                && command.request.idempotency_key == query.idempotency_key
        }) else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        if !model_effect_request_matches_query(&command.request, query) {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result.clone(),
        })
    }
}

fn empty_model_overlay(target: &TenantScopedId) -> OverlaySnapshot {
    OverlaySnapshot {
        target: target.clone(),
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("empty contributions: {error}")),
        highest_fencing_token: 0,
    }
}

fn model_effect_request_matches_query(request: &EffectRequest, query: &EffectResultQuery) -> bool {
    request.tenant_id == query.tenant_id
        && request.action_id == query.action_id
        && request.plan_hash == query.plan_hash
        && request.effect_id == query.effect_id
        && request.effect_kind == query.effect_kind
        && request.target == query.target
        && request.plan_expires_at_unix_ms == query.plan_expires_at_unix_ms
        && request.operation == query.operation
        && request.idempotency_key == query.idempotency_key
        && request.expected_version_hash == query.expected_version_hash
        && request.scheduler_lease_owner_id == query.scheduler_lease_owner_id
        && request.scheduler_fencing_token == query.scheduler_fencing_token
        && request.contribution_hash == query.contribution_hash
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
                && fence.scheduler_lease_owner_id == request.scheduler_lease_owner_id
                && fence.scheduler_fencing_token == request.scheduler_fencing_token
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
            scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: request.scheduler_fencing_token,
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

    fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        let mut state = self.state()?;
        let (fence, active) = state
            .lineage_fences
            .iter_mut()
            .find(|(fence, _)| {
                fence.tenant_id == renewal.tenant_id && fence.action_id == renewal.action_id
            })
            .ok_or_else(PortError::conflict)?;
        if !*active
            || fence.fencing_token != renewal.fencing_token
            || fence.scheduler_lease_owner_id != renewal.scheduler_lease_owner_id
            || fence.scheduler_fencing_token != renewal.scheduler_fencing_token
            || fence.expires_at_unix_ms != renewal.expected_expires_at_unix_ms
            || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        fence.expires_at_unix_ms = renewal.renewed_expires_at_unix_ms;
        Ok(fence.clone())
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        let mut state = self.state()?;
        let Some((fence, active)) = state.lineage_fences.iter_mut().find(|(fence, _)| {
            fence.tenant_id == release.tenant_id && fence.action_id == release.action_id
        }) else {
            return Ok(());
        };
        if fence.fencing_token != release.fencing_token
            || fence.scheduler_lease_owner_id != release.scheduler_lease_owner_id
            || fence.scheduler_fencing_token != release.scheduler_fencing_token
        {
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
