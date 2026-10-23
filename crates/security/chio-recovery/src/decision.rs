use crate::planning::{CandidatePlanV1, PlannerSearchLimit, MAX_PLAN_OFFERS};
use chio_security_types::recovery::BoundedList;
use chio_security_types::InformationLabel;

/// Classified snapshot advice, without durable progress or execution authority.
#[derive(Clone, Eq, PartialEq)]
pub enum PlanDecision {
    Candidates {
        plans: BoundedList<CandidatePlanV1, MAX_PLAN_OFFERS>,
        classification: InformationLabel,
    },
    NoRegisteredRemedy {
        classification: InformationLabel,
    },
    /// No candidates or validity claim about entries not reached by the search.
    SearchBoundReached {
        limit: PlannerSearchLimit,
        classification: InformationLabel,
    },
}

impl core::fmt::Debug for PlanDecision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlanDecision([redacted])")
    }
}
