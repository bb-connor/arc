use chio_fixed::Q16_16;

use crate::outcome::{FallbackReason, ProjectionOutcome};

/// Largest feasible set an envelope accepts.
pub const MAX_ENVELOPE_ACTIONS: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeError {
    Empty,
    TooLarge,
}

/// A feasible set whose conservative action is at index 0.
#[derive(Clone, Copy, Debug)]
pub struct Envelope<'a, A: Copy + Eq> {
    feasible: &'a [A],
    fallback: A,
}

/// An action that an envelope admitted, with how it was reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Projected<A> {
    action: A,
    outcome: ProjectionOutcome,
}

impl<'a, A: Copy + Eq> Envelope<'a, A> {
    pub fn new(feasible: &'a [A]) -> Result<Self, EnvelopeError> {
        let fallback = *feasible.first().ok_or(EnvelopeError::Empty)?;
        if feasible.len() > MAX_ENVELOPE_ACTIONS {
            return Err(EnvelopeError::TooLarge);
        }
        Ok(Self { feasible, fallback })
    }

    /// The conservative action, `feasible[0]`.
    pub fn fallback(&self) -> A {
        self.fallback
    }

    pub fn admits(&self, a: A) -> bool {
        self.feasible.contains(&a)
    }

    /// Total: every proposal yields an admitted action.
    pub fn project(&self, proposal: Result<Option<A>, FallbackReason>) -> Projected<A> {
        match proposal {
            Ok(Some(a)) if self.admits(a) => Projected {
                action: a,
                outcome: ProjectionOutcome::Identity,
            },
            Ok(Some(_)) => self.fall_back(FallbackReason::ProposalInfeasible),
            Ok(None) => self.fall_back(FallbackReason::EmptyProposal),
            Err(reason) => self.fall_back(reason),
        }
    }

    /// Argmax over `scores`, one per feasible action, with the first maximum
    /// winning ties. A length mismatch is a `ScorerError` fallback.
    pub fn select(&self, scores: &[Q16_16]) -> Projected<A> {
        if scores.len() != self.feasible.len() {
            return self.fall_back(FallbackReason::ScorerError);
        }
        let mut best: Option<(A, Q16_16)> = None;
        for (action, score) in self.feasible.iter().zip(scores) {
            if best.is_none_or(|(_, top)| *score > top) {
                best = Some((*action, *score));
            }
        }
        match best {
            Some((action, _)) => Projected {
                action,
                outcome: ProjectionOutcome::Identity,
            },
            None => self.fall_back(FallbackReason::ScorerError),
        }
    }

    fn fall_back(&self, reason: FallbackReason) -> Projected<A> {
        Projected {
            action: self.fallback,
            outcome: ProjectionOutcome::Fallback(reason),
        }
    }
}

impl<A: Copy> Projected<A> {
    pub fn action(&self) -> A {
        self.action
    }

    pub fn outcome(&self) -> ProjectionOutcome {
        self.outcome
    }

    pub fn fallback_used(&self) -> bool {
        matches!(self.outcome, ProjectionOutcome::Fallback(_))
    }
}
