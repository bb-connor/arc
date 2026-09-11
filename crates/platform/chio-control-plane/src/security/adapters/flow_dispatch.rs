//! Origin-bound, non-consuming flow dispatch preparation. A plan is not an
//! operation-owned participant, durable release authority or an execution permit.

use super::*;
use chio_flow::PreparedFlowAdmission;
use chio_kernel::ToolCallRequest;

/// A one-shot plan tied to the resolver that verified it. The resolver's manifest
/// registry and policy are immutable while borrowed. Dropping a plan does not
/// consume a grant, join flow state, acquire a fence or emit a receipt.
///
/// The plan cannot be committed twice:
///
/// ```compile_fail
/// use chio_control_plane::security::adapters::PreparedFlowDispatch;
/// fn commit_twice(plan: PreparedFlowDispatch<'_>) {
///     let _ = plan.commit();
///     let _ = plan.commit();
/// }
/// ```
///
/// The original request cannot be changed while its plan can still commit:
///
/// ```compile_fail
/// use chio_control_plane::security::adapters::PersistentFlowResolver;
/// use chio_kernel::{SecurityInvocationContextV1, ToolCallRequest};
/// use chio_security_kernel::FlowPreInvocationInput;
/// use chio_security_types::ports::RecordId;
/// fn replace_request(
///     resolver: &PersistentFlowResolver,
///     context: &SecurityInvocationContextV1,
///     request: &mut ToolCallRequest,
///     commitment: RecordId,
/// ) {
///     if let Ok(plan) = resolver.prepare_dispatch(
///         &FlowPreInvocationInput { security_context: context, request }, commitment,
///     ) {
///         request.agent_id.clear();
///         let _ = plan.commit();
///     }
/// }
/// ```
#[must_use]
pub struct PreparedFlowDispatch<'a> {
    resolver: &'a PersistentFlowResolver,
    request: &'a ToolCallRequest,
    live_request_digest: Digest32,
    request_id: RequestId,
    state: FlowStateSnapshot,
    prepared_at_unix_ms: u64,
    flow: PreparedFlowAdmission,
    grant_hash: Option<Digest32>,
    dispatch_commitment_id: RecordId,
}

impl PreparedFlowDispatch<'_> {
    /// Commitment to the complete canonical live request, including transient
    /// credentials. This is data, not credential verification or dispatch
    /// authority. The flow/declassification request hash instead binds arguments.
    #[must_use]
    pub const fn live_request_digest(&self) -> Digest32 {
        self.live_request_digest
    }

    /// Bind a later custody command to this exact prepared request. Equal
    /// arguments alone do not establish equal invocation or credential data.
    pub fn validate_live_request(&self, request: &ToolCallRequest) -> Result<(), FlowDenial> {
        if live_request_digest(request)? != self.live_request_digest {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        Ok(())
    }

    /// Read the planned transition, not evidence that any participant is owned.
    #[must_use]
    pub const fn admission(&self) -> &FlowAdmission {
        self.flow.admission()
    }

    /// Revalidate live state and time, then commit using only the original
    /// resolver and verified plan. No replacement request or backend is accepted.
    pub fn commit(self) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        if self.grant_hash.is_some() {
            return self.resolver.commit_dispatch_with_evidence(self);
        }
        let now_unix_ms = self.validate_current()?;
        let admission = self.flow.into_admission()?;
        self.resolver
            .commit_admission_at(&admission, self.dispatch_commitment_id, now_unix_ms)?;
        Ok(None)
    }

    fn validate_current(&self) -> Result<u64, FlowDenial> {
        self.validate_live_request(self.request)?;
        if self.resolver.load_state(&self.state.key)? != self.state {
            return Err(FlowDenial::StateChanged);
        }
        let now_unix_ms = self
            .resolver
            .clock
            .now_unix_ms()
            .map_err(|_| FlowDenial::StateChanged)?;
        if now_unix_ms < self.prepared_at_unix_ms {
            return Err(FlowDenial::StateChanged);
        }
        if let Some(verified) = self.flow.declassification() {
            if now_unix_ms / 1_000 >= verified.expires_at_unix_seconds() {
                return Err(FlowDenial::DeclassificationExpired);
            }
        }
        if self
            .flow
            .admission()
            .egress_fence_plan
            .as_ref()
            .is_some_and(|fence| now_unix_ms >= fence.expires_at_unix_ms)
        {
            return Err(FlowDenial::StateChanged);
        }
        Ok(now_unix_ms)
    }
}

impl PersistentFlowResolver {
    /// Resolve and validate once without mutating flow, replay or receipt state.
    /// Required durable custody must be established separately before an
    /// external execution authorization can be published.
    pub fn prepare_dispatch<'a>(
        &'a self,
        input: &FlowPreInvocationInput<'a>,
        dispatch_commitment_id: RecordId,
    ) -> Result<PreparedFlowDispatch<'a>, FlowDenial> {
        let live_request_digest = live_request_digest(input.request)?;
        if input.request.declassification_grant.is_some()
            && self.config.declassification_evidence.is_none()
        {
            return Err(FlowDenial::DeclassificationStoreFailure);
        }
        let grant_hash = input
            .request
            .declassification_grant
            .as_ref()
            .map(declassification_grant_hash)
            .transpose()?;
        let request = self.resolve_pre(input, false)?;
        let request_id = request.request_id.clone();
        let state = request.state.clone();
        let prepared_at_unix_ms = request.now_unix_ms;
        let flow = prepare_pre_invocation(request)?;
        if flow.declassification().is_some() != grant_hash.is_some() {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        Ok(PreparedFlowDispatch {
            resolver: self,
            request: input.request,
            live_request_digest,
            request_id,
            state,
            prepared_at_unix_ms,
            flow,
            grant_hash,
            dispatch_commitment_id,
        })
    }

    pub fn commit_dispatch(
        &self,
        input: &FlowPreInvocationInput<'_>,
        dispatch_commitment_id: RecordId,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        self.prepare_dispatch(input, dispatch_commitment_id)?
            .commit()
    }

    fn commit_dispatch_with_evidence(
        &self,
        prepared: PreparedFlowDispatch<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        let evidence = self
            .config
            .declassification_evidence
            .as_ref()
            .cloned()
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        let PreparedFlowDispatch {
            request_id,
            flow,
            grant_hash,
            dispatch_commitment_id,
            ..
        } = &prepared;
        let grant_hash = grant_hash.ok_or(FlowDenial::DeclassificationBindingMismatch)?;
        let verified = flow
            .declassification()
            .ok_or(FlowDenial::DeclassificationBindingMismatch)?;
        let grant_expires_at_unix_ms = verified
            .expires_at_unix_seconds()
            .checked_mul(1_000)
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        let consumption_binding = DeclassificationTransitionBinding::Consumption {
            tenant_id: verified.tenant_id().clone(),
            grant_id: verified.grant_id().clone(),
            request_hash: verified.request_hash(),
            request_id: request_id.clone(),
        };
        let use_query = DeclassificationUseQuery {
            tenant_id: verified.tenant_id().clone(),
            grant_id: verified.grant_id().clone(),
        };
        let existing_use = evidence
            .store
            .load_declassification_use(&use_query)
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
        let existing_evidence = evidence
            .store
            .load_declassification_evidence(&DeclassificationEvidenceQuery {
                tenant_id: verified.tenant_id().clone(),
                grant_id: verified.grant_id().clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            })
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
        // Read-only evidence callbacks can take time or observe a concurrent
        // flow transition. Refresh after them, before the first participant write.
        let now_unix_ms = prepared.validate_current()?;
        let consumption_commit = match (existing_use, existing_evidence) {
            (None, None) => {
                let body = declassification_consumption_body(
                    verified.tenant_id().clone(),
                    evidence.policy.clone(),
                    verified.grant_id().clone(),
                    grant_hash,
                    verified.request_hash(),
                    now_unix_ms,
                    &consumption_binding,
                )?;
                DeclassificationConsumptionEvidenceCommit {
                    consumption: DeclassificationConsumeRequest {
                        tenant_id: verified.tenant_id().clone(),
                        grant_id: verified.grant_id().clone(),
                        request_hash: verified.request_hash(),
                        consumed_at_unix_ms: now_unix_ms,
                        grant_expires_at_unix_ms,
                    },
                    transition_binding: consumption_binding.clone(),
                    receipt: active_defense_receipt_request(&body)?,
                }
            }
            (Some(use_record), Some(evidence_record)) => {
                let expected_body = declassification_consumption_body(
                    verified.tenant_id().clone(),
                    evidence.policy.clone(),
                    verified.grant_id().clone(),
                    grant_hash,
                    verified.request_hash(),
                    use_record.consumed_at_unix_ms,
                    &consumption_binding,
                )?;
                let expected_receipt = active_defense_receipt_request(&expected_body)?;
                if use_record.request_hash != verified.request_hash()
                    || use_record.grant_expires_at_unix_ms != grant_expires_at_unix_ms
                    || use_record.consumption_binding != consumption_binding
                    || evidence_record.request_hash != verified.request_hash()
                    || evidence_record.state != DeclassificationUseState::ConsumedPendingDispatch
                    || evidence_record.transition_binding != consumption_binding
                    || evidence_record.receipt != expected_receipt
                {
                    return Err(FlowDenial::DeclassificationBindingMismatch);
                }
                return Err(FlowDenial::DeclassificationReplay);
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(FlowDenial::DeclassificationStoreFailure);
            }
        };
        let dispatch_failed = DeclassificationTransitionBinding::DispatchFailed {
            tenant_id: consumption_commit.consumption.tenant_id.clone(),
            grant_id: consumption_commit.consumption.grant_id.clone(),
            request_hash: consumption_commit.consumption.request_hash,
            request_id: request_id.clone(),
            dispatch_commitment_id: dispatch_commitment_id.clone(),
        };
        let outcome_unknown_after_dispatch =
            DeclassificationTransitionBinding::OutcomeUnknownAfterDispatch {
                tenant_id: consumption_commit.consumption.tenant_id.clone(),
                grant_id: consumption_commit.consumption.grant_id.clone(),
                request_hash: consumption_commit.consumption.request_hash,
                request_id: request_id.clone(),
                dispatch_commitment_id: dispatch_commitment_id.clone(),
            };
        let receipt_failure = DeclassificationTransitionBinding::ReceiptPersistenceFailed {
            tenant_id: consumption_commit.consumption.tenant_id.clone(),
            grant_id: consumption_commit.consumption.grant_id.clone(),
            request_hash: consumption_commit.consumption.request_hash,
            request_id: request_id.clone(),
            dispatch_commitment_id: dispatch_commitment_id.clone(),
        };
        let released = DeclassificationTransitionBinding::Released {
            tenant_id: consumption_commit.consumption.tenant_id.clone(),
            grant_id: consumption_commit.consumption.grant_id.clone(),
            request_hash: consumption_commit.consumption.request_hash,
            request_id: request_id.clone(),
            dispatch_commitment_id: dispatch_commitment_id.clone(),
        };
        let atomic_store = AtomicDeclassificationConsumptionStore {
            store: Arc::clone(&evidence.store),
            commit: consumption_commit.clone(),
        };
        let dispatch_commitment_id = dispatch_commitment_id.clone();
        let admission = prepared
            .flow
            .consume_declassification_at(&atomic_store, now_unix_ms)?;
        let consumed = admission
            .declassification
            .as_ref()
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        if consumed.tenant_id() != &consumption_commit.consumption.tenant_id
            || consumed.grant_id() != &consumption_commit.consumption.grant_id
            || consumed.request_hash() != consumption_commit.consumption.request_hash
        {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        let consumption_acknowledged_at_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| FlowDenial::StateChanged)?;
        if let Err(error) = append_and_ack_exact_evidence(
            evidence.store.as_ref(),
            evidence.sink.as_ref(),
            consumed.tenant_id(),
            consumed.grant_id(),
            DeclassificationEvidencePhase::Consumption,
            &consumption_commit.receipt,
            consumption_acknowledged_at_unix_ms,
        ) {
            let failed_at_unix_ms = self
                .clock
                .now_unix_ms()
                .map_err(|_| FlowDenial::StateChanged)?;
            let receipt_failure = prepare_declassification_outcome_evidence(
                &evidence,
                &consumption_commit,
                grant_hash,
                failed_at_unix_ms,
                receipt_failure,
            )?;
            self.persist_dispatch_failed_evidence(&evidence, &receipt_failure)?;
            return Err(error);
        }
        let committed_at_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| FlowDenial::StateChanged)?;
        if let Err(error) = self.commit_admission_at(
            &admission,
            dispatch_commitment_id.clone(),
            committed_at_unix_ms,
        ) {
            let failed_at_unix_ms = self
                .clock
                .now_unix_ms()
                .map_err(|_| FlowDenial::StateChanged)?;
            let dispatch_failed = prepare_declassification_outcome_evidence(
                &evidence,
                &consumption_commit,
                grant_hash,
                failed_at_unix_ms,
                dispatch_failed,
            )?;
            let outcome_receipt =
                self.persist_dispatch_failed_evidence(&evidence, &dispatch_failed)?;
            append_and_ack_exact_evidence(
                evidence.store.as_ref(),
                evidence.sink.as_ref(),
                consumed.tenant_id(),
                consumed.grant_id(),
                DeclassificationEvidencePhase::Outcome,
                &outcome_receipt,
                failed_at_unix_ms,
            )?;
            return Err(error);
        }
        Ok(Some(Box::new(PersistentDeclassificationOutcomeRecorder {
            evidence,
            consumption: consumption_commit,
            grant_hash,
            released,
            dispatch_failed,
            outcome_unknown_after_dispatch,
            clock: Arc::clone(&self.clock),
            pending_outcome: None,
            completed_outcome: None,
        })))
    }

    fn persist_dispatch_failed_evidence(
        &self,
        evidence: &DeclassificationEvidenceConfig,
        prepared: &DeclassificationOutcomeEvidenceCommit,
    ) -> Result<ReceiptAppendRequest, FlowDenial> {
        if prepared.transition_binding.terminal_state()
            != Some(DeclassificationUseState::DispatchFailed)
            || !prepared.transition_binding.is_live_dispatch_binding()
            || prepared.outcome.new_state != DeclassificationUseState::DispatchFailed
        {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        commit_terminal_declassification_evidence(evidence.store.as_ref(), prepared)
    }

    fn commit_admission_at(
        &self,
        admission: &FlowAdmission,
        dispatch_commitment_id: RecordId,
        committed_at_unix_ms: u64,
    ) -> Result<(), FlowDenial> {
        let persisted = self.persist_admission(admission)?;
        let Some(fence_request) = prepare_egress_fence(admission, &persisted)? else {
            return Ok(());
        };
        let fence = self
            .state
            .acquire_egress_fence(&fence_request)
            .map_err(|_| FlowDenial::StateChanged)?;
        self.state
            .commit_egress_fence(&EgressFenceCommit {
                fence,
                dispatch_commitment_id,
                committed_at_unix_ms,
            })
            .map_err(|_| FlowDenial::StateChanged)?;
        Ok(())
    }
}

pub(super) fn live_request_digest(request: &ToolCallRequest) -> Result<Digest32, FlowDenial> {
    chio_core::canonical_json_bytes(request)
        .map(|bytes| digest(&bytes))
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)
}
