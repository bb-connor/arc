use alloc::vec::Vec;
use chio_security_types::{recovery::*, InformationLabel};
use chio_semantic_contracts::DependencyGraphV1;

/// Caller-selected deployment ceilings may only lower the protocol profile.
/// Each registered graph is bounded separately at 16 nodes, so node ceilings
/// from 16 through 32 accept the same representable graphs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannerLimitsV1 {
    pub(super) offers: usize,
    pub(super) steps: usize,
    pub(super) nodes: usize,
    pub(super) depth: usize,
    pub(super) work: u32,
}
impl PlannerLimitsV1 {
    pub fn new(
        offers: usize,
        steps: usize,
        nodes: usize,
        depth: usize,
        work: u32,
    ) -> Result<Self, ContractError> {
        if [(offers, 16), (steps, 8), (nodes, 32), (depth, 8)]
            .iter()
            .any(|(value, ceiling)| *value == 0 || value > ceiling)
            || work == 0
            || work > MAX_RECOVERY_VERIFICATION_WORK
        {
            return Err(ContractError::LimitExceeded);
        }
        Ok(Self {
            offers,
            steps,
            nodes,
            depth,
            work,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannerSearchLimit {
    Offers,
    Steps,
    Nodes,
    Depth,
    Work,
}

/// Classified, explicit input data. A registry is not a native materializer.
/// The consumer binds its workflow identity to authenticated native ownership
/// before materialization; the snapshot binds only scope and intent.
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryPlanningRegistryV1 {
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub intent_digest: IntentDigest,
    pub classification: InformationLabel,
    pub plans: BoundedList<RegisteredCandidatePlanV1, 16>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RegisteredCandidatePlanV1 {
    pub plan_id: PlanId,
    pub top_level_steps: NonEmptyBoundedList<StepId, 8>,
    pub graph: DependencyGraphV1,
}

/// A deterministic advisory candidate retains its exact supplied identity.
/// The candidate grants no signing, dispatch or native capture authority.
///
/// ```compile_fail
/// use chio_recovery::CandidatePlanV1;
/// use chio_core_types::recovery::RecoveryGrantBody;
/// fn authorize(candidate: CandidatePlanV1) -> RecoveryGrantBody {
///     candidate.into()
/// }
/// ```
/// Both types resolve independently:
/// ```
/// use chio_recovery::CandidatePlanV1;
/// use chio_core_types::recovery::RecoveryGrantBody;
/// fn preserve(candidate: CandidatePlanV1, grant: RecoveryGrantBody)
///     -> (CandidatePlanV1, RecoveryGrantBody) {
///     (candidate, grant)
/// }
/// let _ = preserve;
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct CandidatePlanV1 {
    pub(super) scope: RecoveryScopeV1,
    pub(super) workflow_id: WorkflowId,
    pub(super) intent_digest: IntentDigest,
    pub(super) plan_id: PlanId,
    pub(super) ordered_steps: Vec<StepId>,
    pub(super) total_cost_units: SafeInteger,
    pub(super) assessment: ExplanationAssessmentV1,
}
impl CandidatePlanV1 {
    pub fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }
    pub const fn intent_digest(&self) -> IntentDigest {
        self.intent_digest
    }
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }
    pub fn ordered_steps(&self) -> &[StepId] {
        &self.ordered_steps
    }
    pub const fn total_cost_units(&self) -> SafeInteger {
        self.total_cost_units
    }
    pub const fn assessment(&self) -> ExplanationAssessmentV1 {
        self.assessment
    }
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => { $(
        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+ };
}
redacted!(
    RecoveryPlanningRegistryV1,
    RegisteredCandidatePlanV1,
    CandidatePlanV1
);
