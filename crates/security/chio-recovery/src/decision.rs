use crate::planning::{CandidatePlanV1, PlannerSearchLimit};
use chio_security_types::recovery::{
    AdmissionIntentRef, ApprovalIntentRef, BoundedList, EvidenceRef, OperationRef, StepId,
};
use chio_security_types::InformationLabel;

/// Snapshot planning results, separate from durable workflow progress.
#[derive(Clone, Eq, PartialEq)]
pub enum PlanDecision {
    Candidates {
        plans: BoundedList<CandidatePlanV1, 16>,
        classification: InformationLabel,
    },
    NoRegisteredRemedy {
        classification: InformationLabel,
    },
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

/// Non-authorizing advice. There is deliberately no dispatch/resend directive,
/// wire conversion, signing method, or conversion to a kernel capture owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowDirective {
    Materialize(StepId),
    RequestApproval(ApprovalIntentRef),
    ResumeNativeApproval(OperationRef),
    ResolveAdmission(AdmissionIntentRef),
    AwaitOutcome(OperationRef),
    Reconcile(OperationRef),
    ProjectOutcome(OperationRef),
    PreserveClosure(EvidenceRef),
    Halt,
}
