//! Predicate DAG guard: a pinned decision model evaluated as a three-valued
//! rule schedule. Every decision carries a decision-model witness that the
//! kernel binds into the receipt.

mod exact_source;
mod load;

pub use exact_source::{AtomPredicate, ExactPredicateSource, ExactPredicateSourceError, JsonKind};
pub use load::{DecisionModelBinding, DecisionModelLoadError};

use chio_core::receipt::metadata::{
    DecisionModelFallbackReason, DecisionModelOutcome, DecisionModelWitness, GuardEvidence,
};
use chio_decision_model::{Envelope, FallbackReason, ProjectionOutcome};
use chio_fixed::Q16_16;
use chio_kernel::{
    Guard, GuardContext, GuardDecision, GuardEvidenceDeclaration, KernelError, Verdict,
};
use chio_predicate_dag::{
    classify, HeapScheduleStorage, Outcome, ScoreFrame, Thresholds, ATOM_WORDS,
};
use chio_security_types::work::VerificationBudget;

pub const PREDICATE_DAG_GUARD_NAME: &str = "predicate-dag";

/// The only evidence a decision-model deny emits: no rule id, no atom.
const DENY_EVIDENCE: &str = "action=deny; reason=decision-model";

/// Verdict envelope: `Deny` is the conservative action.
const VERDICTS: [Verdict; 3] = [Verdict::Deny, Verdict::PendingApproval, Verdict::Allow];

/// One score per atom of the loaded schedule and an attestation bit per atom.
/// An unattested atom classifies as `Unknown`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scores {
    pub scores: Vec<Q16_16>,
    pub attested: [u64; ATOM_WORDS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScoreError {
    #[error("score source unavailable")]
    Unavailable,
    #[error("score source returned a malformed score frame")]
    Malformed,
}

/// Supplies atom scores for one request.
pub trait ScoreSource: Send + Sync {
    /// Atoms this source scores. `PredicateDagGuard::load` refuses a schedule
    /// that references any other atom.
    fn provided_atoms(&self) -> [u64; ATOM_WORDS];

    fn scores(&self, ctx: &GuardContext) -> Result<Scores, ScoreError>;
}

/// A pinned decision model behind the `Guard` interface. The schedule,
/// thresholds and digests are fixed at `load` and never change.
pub struct PredicateDagGuard {
    model_card_digest: String,
    artifact_digest: String,
    storage: HeapScheduleStorage,
    thresholds: Thresholds,
    source: Box<dyn ScoreSource>,
    op_count: u32,
    work_cap: u32,
}

impl PredicateDagGuard {
    /// The schedule's static work in ops, charged once per evaluation.
    pub fn op_count(&self) -> u32 {
        self.op_count
    }

    /// Evaluate against a caller-owned meter. Scores are obtained first and a
    /// scorer failure charges nothing; then `op_count()` is charged exactly
    /// once; then the schedule runs with that granted allowance.
    pub fn evaluate_with_budget(
        &self,
        ctx: &GuardContext,
        budget: &mut VerificationBudget,
    ) -> Result<GuardDecision, KernelError> {
        let envelope = Envelope::new(&VERDICTS)
            .map_err(|error| KernelError::Internal(format!("verdict envelope: {error:?}")))?;
        let proposal = self.propose(ctx, budget);
        let projected = envelope.project(proposal.map(|(verdict, _)| Some(verdict)));
        let witness = match projected.outcome() {
            ProjectionOutcome::Identity => {
                let work_ops = proposal.map(|(_, work_ops)| work_ops).unwrap_or(0);
                DecisionModelWitness::evaluated(
                    self.model_card_digest.clone(),
                    self.artifact_digest.clone(),
                    witness_outcome(projected.action()),
                    work_ops,
                )
            }
            ProjectionOutcome::Fallback(reason) => DecisionModelWitness::fallback(
                self.model_card_digest.clone(),
                self.artifact_digest.clone(),
                fallback_reason(reason),
            ),
            ProjectionOutcome::Clipped => {
                return Err(KernelError::Internal(
                    "decision-model verdict projection clipped".to_string(),
                ));
            }
        }
        .map_err(|error| KernelError::Internal(format!("decision-model witness: {error}")))?;
        let decision = match projected.action() {
            Verdict::Allow => GuardDecision::allow(),
            Verdict::PendingApproval => GuardDecision::pending_approval(Vec::new()),
            Verdict::Deny => GuardDecision::deny(vec![GuardEvidence {
                guard_name: PREDICATE_DAG_GUARD_NAME.to_string(),
                verdict: false,
                details: Some(DENY_EVIDENCE.to_string()),
            }]),
        };
        Ok(decision.with_witness(witness))
    }

    /// The D12 stages. `Ok` carries the schedule's verdict and executed ops.
    fn propose(
        &self,
        ctx: &GuardContext,
        budget: &mut VerificationBudget,
    ) -> Result<(Verdict, u32), FallbackReason> {
        let scores = self
            .source
            .scores(ctx)
            .map_err(|_| FallbackReason::ScorerError)?;
        let frame = ScoreFrame {
            scores: &scores.scores,
            attested: &scores.attested,
        };
        let atoms = classify(&frame, &self.thresholds).map_err(|_| FallbackReason::ScorerError)?;
        budget
            .charge(self.op_count)
            .map_err(|_| FallbackReason::WorkExhausted)?;
        let evaluation = self
            .storage
            .schedule()
            .and_then(|schedule| schedule.evaluate(&atoms, self.op_count))
            .map_err(|_| FallbackReason::PolicyUnavailable)?;
        let verdict = match evaluation.outcome {
            Outcome::Allow => Verdict::Allow,
            Outcome::Hold => Verdict::PendingApproval,
            Outcome::Deny => Verdict::Deny,
        };
        Ok((verdict, evaluation.work_ops))
    }
}

impl Guard for PredicateDagGuard {
    fn name(&self) -> &str {
        PREDICATE_DAG_GUARD_NAME
    }

    fn evidence_declaration(&self) -> GuardEvidenceDeclaration {
        GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let mut budget = VerificationBudget::new(self.work_cap, self.work_cap)
            .map_err(|error| KernelError::Internal(format!("decision-model budget: {error}")))?;
        self.evaluate_with_budget(ctx, &mut budget)
    }
}

fn witness_outcome(verdict: Verdict) -> DecisionModelOutcome {
    match verdict {
        Verdict::Allow => DecisionModelOutcome::Allow,
        Verdict::PendingApproval => DecisionModelOutcome::Hold,
        Verdict::Deny => DecisionModelOutcome::Deny,
    }
}

fn fallback_reason(reason: FallbackReason) -> DecisionModelFallbackReason {
    match reason {
        FallbackReason::EmptyProposal => DecisionModelFallbackReason::EmptyProposal,
        FallbackReason::ProposalInfeasible => DecisionModelFallbackReason::ProposalInfeasible,
        FallbackReason::ScorerError => DecisionModelFallbackReason::ScorerError,
        FallbackReason::WorkExhausted => DecisionModelFallbackReason::WorkExhausted,
        FallbackReason::PolicyUnavailable => DecisionModelFallbackReason::PolicyUnavailable,
    }
}
