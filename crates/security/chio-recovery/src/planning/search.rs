use super::models::*;
use crate::evaluation::{assess, Work};
use crate::PlanDecision;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use chio_security_types::{recovery::*, InformationLabel};
use chio_semantic_contracts::{validate_dependency_graph, VerificationBudget};

enum Stop {
    Bound(PlannerSearchLimit),
    Invalid(ContractError),
}
impl From<ContractError> for Stop {
    fn from(error: ContractError) -> Self {
        match error {
            ContractError::WorkBudgetExceeded => Self::Bound(PlannerSearchLimit::Work),
            other => Self::Invalid(other),
        }
    }
}

/// Plan only over explicit, already resolved snapshot facts and registered
/// symbolic dependencies. Future steps never establish their own prerequisites,
/// replace unknown outcomes, issue approvals or acquire execution authority.
pub fn plan(
    snapshot: &RecoverySnapshotV1,
    remedies: &RecoveryRemedyRegistryV1,
    registry: &RecoveryPlanningRegistryV1,
    limits: PlannerLimitsV1,
) -> Result<PlanDecision, ContractError> {
    let snapshot = snapshot.normalized()?;
    let remedies = remedies.normalized(&snapshot)?;
    registry.scope.ensure_matches(&snapshot.scope)?;
    if registry.intent_digest != snapshot.intent_digest {
        return Err(ContractError::BindingMismatch);
    }
    match search(&snapshot, &remedies, registry, limits) {
        Ok(decision) => Ok(decision),
        Err(Stop::Bound(limit)) => Ok(PlanDecision::SearchBoundReached {
            limit,
            classification: InformationLabel::Top,
        }),
        Err(Stop::Invalid(error)) => Err(error),
    }
}

fn search(
    snapshot: &RecoverySnapshotV1,
    remedies: &RecoveryRemedyRegistryV1,
    registry: &RecoveryPlanningRegistryV1,
    limits: PlannerLimitsV1,
) -> Result<PlanDecision, Stop> {
    let mut work = Work::new(u64::from(limits.work));
    let mut classification = snapshot.context_label.clone();
    for label in core::iter::once(&registry.classification)
        .chain(core::iter::once(&remedies.classification))
        .chain(
            snapshot
                .observations
                .as_slice()
                .iter()
                .map(|fact| &fact.label),
        )
        .chain(
            remedies
                .templates
                .as_slice()
                .iter()
                .flat_map(|template| [&template.classification, &template.disclosure_label]),
        )
    {
        work.label(label)?;
        classification = classification
            .join_restrictions(label)
            .map_err(|_| Stop::Bound(PlannerSearchLimit::Work))?;
    }
    let mut plans: Vec<_> = registry.plans.as_slice().iter().collect();
    plans.sort_by(|a, b| a.plan_id.cmp(&b.plan_id));
    if plans
        .windows(2)
        .any(|pair| pair[0].plan_id == pair[1].plan_id)
    {
        return Err(ContractError::DuplicateIdentity.into());
    }
    if plans.len() > limits.offers {
        return Err(Stop::Bound(PlannerSearchLimit::Offers));
    }
    let mut candidates = Vec::new();
    for registered in plans {
        work.spend(1)?;
        candidates.push(candidate(
            snapshot, remedies, registry, registered, limits, &mut work,
        )?);
    }
    if candidates.is_empty()
        || candidates
            .iter()
            .all(|plan| plan.assessment == ExplanationAssessmentV1::NoRegisteredRemedy)
    {
        return Ok(PlanDecision::NoRegisteredRemedy { classification });
    }
    Ok(PlanDecision::Candidates {
        plans: BoundedList::new(candidates)?,
        classification,
    })
}

fn candidate(
    snapshot: &RecoverySnapshotV1,
    remedies: &RecoveryRemedyRegistryV1,
    registry: &RecoveryPlanningRegistryV1,
    registered: &RegisteredCandidatePlanV1,
    limits: PlannerLimitsV1,
    work: &mut Work,
) -> Result<CandidatePlanV1, Stop> {
    if registered.top_level_steps.as_slice().len() > limits.steps {
        return Err(Stop::Bound(PlannerSearchLimit::Steps));
    }
    let nodes = registered.graph.nodes.as_slice();
    if nodes.len() > limits.nodes {
        return Err(Stop::Bound(PlannerSearchLimit::Nodes));
    }
    let remaining =
        u32::try_from(work.remaining()?).map_err(|_| ContractError::ArithmeticOverflow)?;
    let mut graph_work = VerificationBudget::new(remaining)?;
    let validated = validate_dependency_graph(&registered.graph.nodes, &mut graph_work)?;
    work.spend(u64::from(
        remaining
            .checked_sub(graph_work.remaining())
            .ok_or(ContractError::ArithmeticOverflow)?,
    ))?;
    work.spend(u64::try_from(nodes.len()).map_err(|_| ContractError::ArithmeticOverflow)?)?;
    let indexed: BTreeMap<_, _> = nodes
        .iter()
        .map(|node| (node.step_id.clone(), node))
        .collect();
    let mut needed = BTreeSet::new();
    for step in registered.top_level_steps.as_slice() {
        work.spend(1)?;
        if !needed.insert(step.clone()) {
            return Err(ContractError::DuplicateIdentity.into());
        }
        let node = indexed.get(step).ok_or(ContractError::MissingDependency)?;
        if !template(remedies, &node.template_id, work)?.satisfies_task {
            return Err(ContractError::InvalidState.into());
        }
    }
    for step in validated.ordered_steps().iter().rev() {
        work.spend(1)?;
        if needed.contains(step) {
            let node = indexed.get(step).ok_or(ContractError::MissingDependency)?;
            for dependency in node.dependencies.as_slice() {
                work.spend(1)?;
                needed.insert(dependency.clone());
            }
        }
    }
    if needed.len() != nodes.len() {
        return Err(ContractError::InvalidState.into());
    }
    let mut depths: BTreeMap<StepId, usize> = BTreeMap::new();
    let mut assessment = ExplanationAssessmentV1::FeasibleUnderSnapshot;
    for step in validated.ordered_steps() {
        work.spend(1)?;
        let node = indexed.get(step).ok_or(ContractError::MissingDependency)?;
        let mut depth = 1;
        for dependency in node.dependencies.as_slice() {
            work.spend(1)?;
            let predecessor = depths
                .get(dependency)
                .ok_or(ContractError::MissingDependency)?;
            depth = depth.max(
                predecessor
                    .checked_add(1)
                    .ok_or(ContractError::ArithmeticOverflow)?,
            );
        }
        if depth > limits.depth {
            return Err(Stop::Bound(PlannerSearchLimit::Depth));
        }
        depths.insert(step.clone(), depth);
        let remedy = template(remedies, &node.template_id, work)?;
        if node.estimated_cost_units != remedy.cost.budget_units {
            return Err(ContractError::BindingMismatch.into());
        }
        assessment = assessment.max(assess(snapshot, remedy, work)?);
    }
    Ok(CandidatePlanV1 {
        scope: registry.scope.clone(),
        workflow_id: registry.workflow_id.clone(),
        intent_digest: registry.intent_digest,
        plan_id: registered.plan_id.clone(),
        ordered_steps: validated.ordered_steps().to_vec(),
        total_cost_units: validated.total_cost_units(),
        assessment,
    })
}

fn template<'a>(
    registry: &'a RecoveryRemedyRegistryV1,
    id: &TemplateId,
    work: &mut Work,
) -> Result<&'a RecoveryRemedyTemplateV1, Stop> {
    work.spend(
        u64::try_from(registry.templates.as_slice().len())
            .map_err(|_| ContractError::ArithmeticOverflow)?,
    )?;
    registry
        .templates
        .as_slice()
        .iter()
        .find(|template| &template.template_id == id)
        .ok_or(Stop::Invalid(ContractError::MissingDependency))
}
