//! Exact episode retention for private caller contexts. These are historical
//! bindings, not reconstructed credentials, release owners or execution permits.

use super::*;
use crate::admission_operation::dpop_claim::{
    DpopReplayClaimDisposition, DpopReplayClaimPhase, MAX_DPOP_CLAIM_EPISODES,
};
use crate::admission_operation::governed_approval_claim::{
    GovernedApprovalClaimDisposition, GovernedApprovalClaimPhase,
    MAX_GOVERNED_APPROVAL_CLAIM_EPISODES,
};
use crate::admission_operation::runtime_participant::{
    RuntimeParticipantDisposition, RuntimeParticipantPhase, MAX_RUNTIME_PARTICIPANT_EPISODES,
};
use std::collections::BTreeSet;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallerParticipantCustody {
    runtime: Option<RetainedClaim>,
    approval: Option<RetainedClaim>,
    dpop: Option<RetainedClaim>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedClaim {
    episode_id: AdmissionIdentifier,
    claim_digest: AdmissionDigest,
    intent_digest: AdmissionDigest,
    history_digest: AdmissionDigest,
}

#[derive(Serialize)]
struct Episode {
    episode_id: AdmissionIdentifier,
    claim_digest: AdmissionDigest,
    intent_digest: AdmissionDigest,
    released: bool,
}

enum Disposition {
    Reserved,
    Released,
    Retained,
}

struct ClaimInput<'a, T> {
    operation_id: &'a crate::admission_operation::AdmissionOperationId,
    request_binding: &'a AdmissionDigest,
    episode_id: &'a AdmissionIdentifier,
    intent_episode_id: &'a AdmissionIdentifier,
    claim_digest: &'a AdmissionDigest,
    grant_index: u32,
    dispatch_phase: bool,
    disposition: Disposition,
    intent: &'a T,
}

struct History<'a> {
    operation: &'a AdmissionOperationV1,
    grant_index: usize,
    family: &'static str,
    episodes: Vec<Episode>,
    selected: Option<usize>,
    seen: BTreeSet<AdmissionIdentifier>,
}

impl<'a> History<'a> {
    fn new(
        operation: &'a AdmissionOperationV1,
        grant_index: usize,
        family: &'static str,
        length: usize,
        maximum: usize,
    ) -> Result<Self, KernelError> {
        if length == 0 || length > maximum {
            return Err(invalid(
                "caller custody history is empty or exceeds its bound",
            ));
        }
        Ok(Self {
            operation,
            grant_index,
            family,
            episodes: Vec::with_capacity(length),
            selected: None,
            seen: BTreeSet::new(),
        })
    }

    fn push<T: Serialize>(&mut self, claim: ClaimInput<'_, T>) -> Result<(), KernelError> {
        if claim.operation_id != self.operation.binding().operation_id()
            || claim.request_binding != self.operation.binding().request_binding_hash()
            || claim.episode_id != claim.intent_episode_id
            || !self.seen.insert(claim.episode_id.clone())
        {
            return Err(invalid(
                "caller custody changed its operation or episode binding",
            ));
        }
        let released = matches!(claim.disposition, Disposition::Released);
        if !released {
            let phase_matches = matches!(
                (
                    self.operation.dispatch_commit().is_some(),
                    claim.disposition
                ),
                (false, Disposition::Reserved) | (true, Disposition::Retained)
            );
            if !phase_matches
                || !claim.dispatch_phase
                || usize::try_from(claim.grant_index).ok() != Some(self.grant_index)
                || self.selected.replace(self.episodes.len()).is_some()
            {
                return Err(invalid(
                    "caller custody has no unique original dispatch claim",
                ));
            }
        }
        self.episodes.push(Episode {
            episode_id: claim.episode_id.clone(),
            claim_digest: claim.claim_digest.clone(),
            intent_digest: admission_digest(
                "caller_claim_intent_digest",
                &("chio.caller-claim-intent.v1", self.family, claim.intent),
            )?,
            released,
        });
        Ok(())
    }

    fn finish(self) -> Result<RetainedClaim, KernelError> {
        let selected = self
            .selected
            .and_then(|index| self.episodes.get(index))
            .ok_or_else(|| invalid("caller custody has only released claim episodes"))?;
        Ok(RetainedClaim {
            episode_id: selected.episode_id.clone(),
            claim_digest: selected.claim_digest.clone(),
            intent_digest: selected.intent_digest.clone(),
            history_digest: admission_digest(
                "caller_claim_history_digest",
                &("chio.caller-claim-history.v1", self.family, &self.episodes),
            )?,
        })
    }
}

impl ChioKernel {
    pub(crate) fn read_caller_participant_custody(
        &self,
        admission: &DurableToolAdmission,
        grant_index: usize,
        now: u64,
    ) -> Result<CallerParticipantCustody, KernelError> {
        let operation = &admission.operation;
        let mut snapshot = CallerParticipantCustody {
            runtime: None,
            approval: None,
            dpop: None,
        };
        if admission
            .original_retained_request()
            .and_then(|request| request.authority_profile())
            .is_some_and(|profile| profile.runtime().is_some())
            && operation.runtime_participant_ledger_digest().is_none()
        {
            return Err(invalid(
                "caller custody omitted its selected runtime authority",
            ));
        }
        if operation.runtime_participant_ledger_digest().is_none()
            && operation.governed_approval_ledger_digest().is_none()
            && operation.dpop_replay_ledger_digest().is_none()
        {
            return Ok(snapshot);
        }
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(now);
        let original = admission
            .original_retained_request()
            .ok_or_else(|| invalid("caller custody lost its original request"))?;
        let profile = original
            .authority_profile()
            .ok_or_else(|| invalid("caller custody requires the original authority profile"))?;
        let operation_id = operation.binding().operation_id();
        if operation.runtime_participant_ledger_digest().is_some() {
            let (current, claims) = custody_call(|| {
                runtime
                    .store
                    .load_runtime_participant_history(operation_id, &runtime.fence, now)
            })?
            .ok_or_else(|| invalid("caller runtime custody history is missing"))?;
            require_exact_operation(operation, &current)?;
            let authority = profile
                .runtime()
                .ok_or_else(|| invalid("caller runtime authority is absent"))?;
            let mut history = History::new(
                operation,
                grant_index,
                "runtime",
                claims.len(),
                MAX_RUNTIME_PARTICIPANT_EPISODES,
            )?;
            for claim in claims {
                claim.intent.validate().map_err(durable_store_error)?;
                if claim.intent.runtime_authority_id() != authority.runtime_authority_id()
                    || claim.intent.expectation_id() != authority.expectation_id()
                {
                    return Err(invalid("caller runtime custody selected another authority"));
                }
                history.push(ClaimInput {
                    operation_id: claim.reference.operation_id(),
                    request_binding: claim.intent.request_binding_hash(),
                    episode_id: claim.reference.episode_id(),
                    intent_episode_id: claim.intent.episode_id(),
                    claim_digest: claim.reference.claim_digest(),
                    grant_index: claim.intent.grant_index(),
                    dispatch_phase: claim.intent.phase() == RuntimeParticipantPhase::Dispatch,
                    disposition: match claim.disposition {
                        RuntimeParticipantDisposition::ReservedBeforeDispatch => {
                            Disposition::Reserved
                        }
                        RuntimeParticipantDisposition::ReleasedBeforeDispatch => {
                            Disposition::Released
                        }
                        RuntimeParticipantDisposition::RetainedAfterDispatchCommit => {
                            Disposition::Retained
                        }
                    },
                    intent: &claim.intent,
                })?;
            }
            snapshot.runtime = Some(history.finish()?);
        }
        if operation.governed_approval_ledger_digest().is_some() {
            let (current, claims) = custody_call(|| {
                runtime.store.load_governed_approval_claim_history(
                    operation_id,
                    &runtime.fence,
                    now,
                )
            })?
            .ok_or_else(|| invalid("caller approval custody history is missing"))?;
            require_exact_operation(operation, &current)?;
            let authority = profile
                .approval()
                .ok_or_else(|| invalid("caller approval authority is absent"))?;
            let mut history = History::new(
                operation,
                grant_index,
                "approval",
                claims.len(),
                MAX_GOVERNED_APPROVAL_CLAIM_EPISODES,
            )?;
            for claim in claims {
                claim.intent.validate().map_err(durable_store_error)?;
                if claim.intent.approval_authority_id() != authority.approval_authority_id()
                    || claim.intent.expectation_id() != authority.expectation_id()
                {
                    return Err(invalid(
                        "caller approval custody selected another authority",
                    ));
                }
                history.push(ClaimInput {
                    operation_id: claim.reference.operation_id(),
                    request_binding: claim.intent.request_binding_hash(),
                    episode_id: claim.reference.episode_id(),
                    intent_episode_id: claim.intent.episode_id(),
                    claim_digest: claim.reference.claim_digest(),
                    grant_index: claim.intent.grant_index(),
                    dispatch_phase: claim.intent.phase() == GovernedApprovalClaimPhase::Dispatch,
                    disposition: match claim.disposition {
                        GovernedApprovalClaimDisposition::ReservedBeforeDispatch => {
                            Disposition::Reserved
                        }
                        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch => {
                            Disposition::Released
                        }
                        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit => {
                            Disposition::Retained
                        }
                    },
                    intent: &claim.intent,
                })?;
            }
            snapshot.approval = Some(history.finish()?);
        }
        if operation.dpop_replay_ledger_digest().is_some() {
            let (current, claims) = custody_call(|| {
                runtime
                    .store
                    .load_dpop_replay_claim_history(operation_id, &runtime.fence, now)
            })?
            .ok_or_else(|| invalid("caller DPoP custody history is missing"))?;
            require_exact_operation(operation, &current)?;
            let authority = profile
                .dpop()
                .ok_or_else(|| invalid("caller DPoP authority is absent"))?;
            let mut history = History::new(
                operation,
                grant_index,
                "dpop",
                claims.len(),
                MAX_DPOP_CLAIM_EPISODES,
            )?;
            for claim in claims {
                claim.intent.validate().map_err(durable_store_error)?;
                if claim.intent.credential().authority() != authority {
                    return Err(invalid("caller DPoP custody selected another authority"));
                }
                history.push(ClaimInput {
                    operation_id: claim.reference.operation_id(),
                    request_binding: claim.intent.request_binding_hash(),
                    episode_id: claim.reference.episode_id(),
                    intent_episode_id: claim.intent.episode_id(),
                    claim_digest: claim.reference.claim_digest(),
                    grant_index: claim.intent.grant_index(),
                    dispatch_phase: claim.intent.phase() == DpopReplayClaimPhase::Dispatch,
                    disposition: match claim.disposition {
                        DpopReplayClaimDisposition::ReservedBeforeDispatch => Disposition::Reserved,
                        DpopReplayClaimDisposition::ReleasedBeforeDispatch => Disposition::Released,
                        DpopReplayClaimDisposition::RetainedAfterDispatchCommit => {
                            Disposition::Retained
                        }
                    },
                    intent: &claim.intent,
                })?;
            }
            snapshot.dpop = Some(history.finish()?);
        }
        Ok(snapshot)
    }
}

fn require_exact_operation(
    expected: &AdmissionOperationV1,
    actual: &AdmissionOperationV1,
) -> Result<(), KernelError> {
    if expected != actual {
        return Err(invalid(
            "caller custody readback changed its operation snapshot",
        ));
    }
    Ok(())
}

pub(super) fn custody_call<T>(
    call: impl FnOnce() -> Result<T, crate::admission_operation::AdmissionOperationStoreError>,
) -> Result<T, KernelError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
        .map_err(|_| invalid("caller custody readback panicked"))?
        .map_err(durable_store_error)
}
