/// Why a projection returned the conservative action.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FallbackReason {
    EmptyProposal,
    ProposalInfeasible,
    ScorerError,
    WorkExhausted,
    PolicyUnavailable,
}

/// How a projected action relates to the proposal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProjectionOutcome {
    /// The proposal was admitted unchanged.
    Identity,
    /// The proposal was replaced by a different admitted action.
    Clipped,
    /// The conservative action was returned.
    Fallback(FallbackReason),
}
