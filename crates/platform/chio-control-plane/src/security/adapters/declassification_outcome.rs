use super::DeclassificationDispatchOutcome;
use super::FlowDenial;

use super::FlowDispatchOutcomeRecorder;

use super::derive_declassification_transition_id;
use super::DeclassificationConsume;
use super::DeclassificationConsumeRequest;
use super::DeclassificationConsumptionEvidenceCommit;
use super::DeclassificationEvidenceCommitStore;
use super::DeclassificationEvidencePhase;
use super::DeclassificationEvidenceQuery;
use super::DeclassificationOutcomeEvidenceCommit;
use super::DeclassificationOutcomeRequest;
use super::DeclassificationTransitionBinding;
use super::DeclassificationUseState;
use super::DeclassificationUseStore;
use super::Digest32;
use super::PortError;
use super::PortResult;
use super::ReceiptAppendRequest;

use super::append_and_ack_exact_evidence;
use super::active_defense_receipt_request;
use super::declassification_outcome_body;

use super::DeclassificationEvidenceConfig;
use super::AtomicDeclassificationConsumptionStore;
use super::PersistentDeclassificationOutcomeRecorder;
use super::DeclassificationOutcomeBodyInput;

impl DeclassificationUseStore for AtomicDeclassificationConsumptionStore {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume> {
        if request != &self.commit.consumption {
            return Err(PortError::conflict());
        }
        self.store
            .commit_declassification_consumption_evidence(&self.commit)
    }

    fn record_outcome(&self, _: &DeclassificationOutcomeRequest) -> PortResult<()> {
        Err(PortError::unavailable())
    }
}

pub(super) struct PendingDeclassificationOutcome {
    outcome: DeclassificationDispatchOutcome,
    evidence: DeclassificationOutcomeEvidenceCommit,
    occurred_at_unix_ms: u64,
}

impl FlowDispatchOutcomeRecorder for PersistentDeclassificationOutcomeRecorder {
    fn record(&mut self, outcome: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
        if let Some(completed) = self.completed_outcome {
            return if completed == outcome {
                Ok(())
            } else {
                Err(FlowDenial::DeclassificationBindingMismatch)
            };
        }
        if self.pending_outcome.is_none() {
            let occurred_at_unix_ms = self
                .clock
                .unix_millis()
                .map(chio_security_types::clock::UnixMillis::get)
                .map_err(|_| FlowDenial::StateChanged)?;
            let transition_binding = match outcome {
                DeclassificationDispatchOutcome::Released => self.released.clone(),
                DeclassificationDispatchOutcome::DispatchFailed => self.dispatch_failed.clone(),
                DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch => {
                    self.outcome_unknown_after_dispatch.clone()
                }
            };
            let evidence = prepare_declassification_outcome_evidence(
                &self.evidence,
                &self.consumption,
                self.grant_hash,
                occurred_at_unix_ms,
                transition_binding,
            )?;
            self.pending_outcome = Some(PendingDeclassificationOutcome {
                outcome,
                evidence,
                occurred_at_unix_ms,
            });
        }
        let pending = self
            .pending_outcome
            .as_ref()
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        if pending.outcome != outcome {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        let prepared = &pending.evidence;
        let occurred_at_unix_ms = pending.occurred_at_unix_ms;
        let expected_state = match outcome {
            DeclassificationDispatchOutcome::Released => &self.released,
            DeclassificationDispatchOutcome::DispatchFailed => &self.dispatch_failed,
            DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch => {
                &self.outcome_unknown_after_dispatch
            }
        };
        if prepared.transition_binding != *expected_state {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        let store = self.evidence.store.as_ref();
        let receipt = commit_terminal_declassification_evidence(store, prepared)?;
        append_and_ack_exact_evidence(
            store,
            self.evidence.sink.as_ref(),
            &prepared.outcome.tenant_id,
            &prepared.outcome.grant_id,
            DeclassificationEvidencePhase::Outcome,
            &receipt,
            occurred_at_unix_ms,
        )?;
        self.completed_outcome = Some(outcome);
        Ok(())
    }
}

pub(super) fn prepare_declassification_outcome_evidence(
    evidence: &DeclassificationEvidenceConfig,
    consumption: &DeclassificationConsumptionEvidenceCommit,
    grant_hash: Digest32,
    occurred_at_unix_ms: u64,
    transition_binding: DeclassificationTransitionBinding,
) -> Result<DeclassificationOutcomeEvidenceCommit, FlowDenial> {
    let new_state = transition_binding
        .terminal_state()
        .ok_or(FlowDenial::DeclassificationBindingMismatch)?;
    if new_state == DeclassificationUseState::ConsumedPendingDispatch
        || transition_binding.tenant_id() != &consumption.consumption.tenant_id
        || transition_binding.grant_id() != &consumption.consumption.grant_id
        || transition_binding.request_hash() != consumption.consumption.request_hash
        || occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    let transition_id = derive_declassification_transition_id(&transition_binding)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    let body = declassification_outcome_body(
        DeclassificationOutcomeBodyInput {
            tenant_id: consumption.consumption.tenant_id.clone(),
            prior_receipt_id: consumption.receipt.evidence_id.clone(),
            policy: evidence.policy.clone(),
            grant_id: consumption.consumption.grant_id.clone(),
            grant_hash,
            request_hash: consumption.consumption.request_hash,
            occurred_at_unix_ms,
            to_state: new_state,
        },
        &transition_binding,
    )?;
    Ok(DeclassificationOutcomeEvidenceCommit {
        transition_binding,
        outcome: DeclassificationOutcomeRequest {
            tenant_id: consumption.consumption.tenant_id.clone(),
            grant_id: consumption.consumption.grant_id.clone(),
            request_hash: consumption.consumption.request_hash,
            expected_state: DeclassificationUseState::ConsumedPendingDispatch,
            new_state,
            transition_id,
        },
        predecessor_evidence_id: consumption.receipt.evidence_id.clone(),
        receipt: active_defense_receipt_request(&body)?,
    })
}

pub(super) fn commit_terminal_declassification_evidence(
    store: &dyn DeclassificationEvidenceCommitStore,
    prepared: &DeclassificationOutcomeEvidenceCommit,
) -> Result<ReceiptAppendRequest, FlowDenial> {
    if store
        .commit_declassification_outcome_evidence(prepared)
        .is_ok()
    {
        return Ok(prepared.receipt.clone());
    }
    let existing = store
        .load_declassification_evidence(&DeclassificationEvidenceQuery {
            tenant_id: prepared.outcome.tenant_id.clone(),
            grant_id: prepared.outcome.grant_id.clone(),
            phase: DeclassificationEvidencePhase::Outcome,
        })
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?
        .ok_or(FlowDenial::DeclassificationStoreFailure)?;
    if existing.request_hash != prepared.outcome.request_hash
        || existing.state != prepared.outcome.new_state
        || existing.transition_binding != prepared.transition_binding
        || existing.predecessor_evidence_id.as_ref() != Some(&prepared.predecessor_evidence_id)
        || existing.receipt != prepared.receipt
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    Ok(existing.receipt)
}

