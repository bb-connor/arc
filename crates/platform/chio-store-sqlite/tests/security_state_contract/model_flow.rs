//! Independent model of tenant-scoped flow transitions and exact replay.
use super::*;

#[derive(Clone)]
pub(super) enum FlowTransition {
    Join(Box<FlowJoinRequest>),
    Epoch(Box<IsolationEpochTransition>),
}

impl FlowTransition {
    fn identity(&self) -> (&TenantId, &RecordId) {
        match self {
            Self::Join(request) => (&request.key.tenant_id, &request.transition_id),
            Self::Epoch(request) => (&request.tenant_id, &request.transition_id),
        }
    }

    fn key(&self) -> FlowStateKey {
        match self {
            Self::Join(request) => request.key.clone(),
            Self::Epoch(request) => FlowStateKey {
                tenant_id: request.tenant_id.clone(),
                principal_id: request.principal_id.clone(),
                lineage_id: request.lineage_id.clone(),
                session_id: request.new_session_id.clone(),
                isolation_epoch_id: request.new_isolation_epoch_id.clone(),
            },
        }
    }
}

impl FlowStateStore for ModelStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let state = self.state()?;
        model_flow_snapshot(&state, key)
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        let mut state = self.state()?;
        if let Some(existing) = state.flows.iter().find(|transition| {
            transition.identity() == (&request.key.tenant_id, &request.transition_id)
        }) {
            if !matches!(existing, FlowTransition::Join(stored) if stored.as_ref() == request) {
                return Err(PortError::conflict());
            }
            return model_flow_snapshot(&state, &existing.key())?
                .ok_or_else(PortError::integrity_failure);
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
            .push(FlowTransition::Join(Box::new(request.clone())));
        Ok(snapshot)
    }

    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot> {
        let mut state = self.state()?;
        if let Some(existing) = state
            .flows
            .iter()
            .find(|stored| stored.identity() == (&transition.tenant_id, &transition.transition_id))
        {
            if !matches!(existing, FlowTransition::Epoch(stored) if stored.as_ref() == transition) {
                return Err(PortError::conflict());
            }
            return model_flow_snapshot(&state, &existing.key())?
                .ok_or_else(PortError::integrity_failure);
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
            .push(FlowTransition::Epoch(Box::new(transition.clone())));
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
