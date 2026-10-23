//! Finite deterministic evaluation over supplied data, without ambient state.
use alloc::vec::Vec;
use chio_security_types::recovery::{
    BoundedList, ContractError, EffectObservationV1, ExplanationAssessmentV1,
    ExplanationCandidateV1, ExplanationFactKind, ExplanationFactSource, ExplanationFactStateV1,
    ExplanationIntegrity, ExplanationLatencyClass, ExplanationLimitsV1,
    RecoveryExplanationEvaluationV1, RecoveryExplanationFactV1, RecoveryPlannerVersion,
    RecoveryRemedyRegistryV1, RecoveryRemedyTemplateV1, RecoverySnapshotV1, SafeInteger,
};
use chio_security_types::InformationLabel;

/// A fixed allowance charged before each bounded step.
struct Work {
    used: u64,
    ceiling: u64,
}

impl Work {
    const fn new(ceiling: u64) -> Self {
        Self { used: 0, ceiling }
    }

    fn spend(&mut self, amount: u64) -> Result<(), ContractError> {
        let next = self
            .used
            .checked_add(amount)
            .ok_or(ContractError::ArithmeticOverflow)?;
        if next > self.ceiling {
            return Err(ContractError::WorkBudgetExceeded);
        }
        self.used = next;
        Ok(())
    }

    /// One unit per label operation. Label cardinality and identifier sizes
    /// have their own protocol ceilings, so a valid label cannot alone consume
    /// the whole allowance.
    fn label(&mut self, _: &InformationLabel) -> Result<(), ContractError> {
        self.spend(1)
    }
}

/// Advisory results under the observed basis. Every template and fact
/// identity is checked before evaluation, even beyond a search bound.
pub fn evaluate_explanation(
    snapshot: &RecoverySnapshotV1,
    registry: &RecoveryRemedyRegistryV1,
    limits: ExplanationLimitsV1,
) -> Result<RecoveryExplanationEvaluationV1, ContractError> {
    limits.validate()?;
    let snapshot = snapshot.normalized()?;
    let registry = registry.normalized(&snapshot)?;
    let mut work = Work::new(limits.work.get());
    let mut classification = snapshot.context_label.clone();
    let mut candidates = Vec::new();
    let complete = match search(
        &snapshot,
        &registry,
        limits,
        &mut work,
        &mut classification,
        &mut candidates,
    ) {
        Ok(()) => true,
        Err(ContractError::WorkBudgetExceeded) => {
            // An incomplete join must never make a full graph public.
            classification = InformationLabel::Top;
            false
        }
        Err(error) => return Err(error),
    };
    let assessment = if !complete {
        ExplanationAssessmentV1::SearchBoundReached
    } else {
        // A coarse summary; incomparable candidate results remain listed.
        candidates
            .iter()
            .map(|candidate| candidate.assessment)
            .min()
            .unwrap_or(ExplanationAssessmentV1::NoRegisteredRemedy)
    };
    Ok(RecoveryExplanationEvaluationV1 {
        planner_version: RecoveryPlannerVersion::V1,
        assessment,
        complete,
        work_used: SafeInteger::new(work.used)?,
        classification,
        candidates: BoundedList::new(candidates)?,
    })
}

/// Joins every input classification, assesses each task-satisfying template
/// and removes dominated candidates. On exhaustion `candidates` keeps every
/// candidate assessed so far, without the dominance filter.
fn search(
    snapshot: &RecoverySnapshotV1,
    registry: &RecoveryRemedyRegistryV1,
    limits: ExplanationLimitsV1,
    work: &mut Work,
    classification: &mut InformationLabel,
    candidates: &mut Vec<ExplanationCandidateV1>,
) -> Result<(), ContractError> {
    work.label(classification)?;
    work.label(&registry.classification)?;
    *classification = join(classification, &registry.classification)?;
    for fact in snapshot.observations.as_slice() {
        work.spend(1)?;
        work.label(&fact.label)?;
        *classification = join(classification, &fact.label)?;
    }
    for template in registry.templates.as_slice() {
        work.spend(1)?;
        work.label(&template.classification)?;
        work.label(&template.disclosure_label)?;
        *classification = join(classification, &template.classification)?;
        *classification = join(classification, &template.disclosure_label)?;
    }
    let mut assessed = Vec::new();
    for template in registry.templates.as_slice() {
        if !template.satisfies_task {
            continue;
        }
        if u64::try_from(candidates.len()).map_or(true, |count| count >= limits.offers.get()) {
            return Err(ContractError::WorkBudgetExceeded);
        }
        let candidate = ExplanationCandidateV1 {
            template_id: template.template_id.clone(),
            assessment: assess(snapshot, template, work)?,
        };
        candidates.push(candidate.clone());
        assessed.push((template, candidate));
    }
    let mut retained = Vec::with_capacity(assessed.len());
    for (template, candidate) in &assessed {
        let mut dominated = false;
        for (other_template, other) in &assessed {
            work.spend(1)?;
            if candidate.template_id != other.template_id
                && dominates(
                    other_template,
                    other.assessment,
                    template,
                    candidate.assessment,
                )
            {
                dominated = true;
            }
        }
        if !dominated {
            retained.push(candidate.clone());
        }
    }
    *candidates = retained;
    Ok(())
}

fn join(
    label: &InformationLabel,
    other: &InformationLabel,
) -> Result<InformationLabel, ContractError> {
    label
        .join_restrictions(other)
        .map_err(|_| ContractError::WorkBudgetExceeded)
}

fn assess(
    snapshot: &RecoverySnapshotV1,
    template: &RecoveryRemedyTemplateV1,
    work: &mut Work,
) -> Result<ExplanationAssessmentV1, ContractError> {
    use ExplanationAssessmentV1 as A;
    work.spend(1)?;
    match snapshot.effect {
        EffectObservationV1::NeverAdmitted | EffectObservationV1::ClosedBeforeEffect { .. } => {}
        EffectObservationV1::Complete { .. }
        | EffectObservationV1::Partial { .. }
        | EffectObservationV1::FailedAfterEffect { .. } => return Ok(A::NoRegisteredRemedy),
        EffectObservationV1::AdmissionUnresolved { .. }
        | EffectObservationV1::AwaitingApproval { .. }
        | EffectObservationV1::InFlight { .. }
        | EffectObservationV1::AwaitingCallerReport { .. }
        | EffectObservationV1::Unknown { .. } => return Ok(A::UnknownOutcome),
    }
    let mut fresh = false;
    let mut capability = false;
    let mut policy = false;
    let mut approval = false;
    let mut transformation = false;
    let mut prerequisite = false;
    for required in template.requirements.as_slice() {
        work.spend(1)?;
        let fact = snapshot
            .observations
            .as_slice()
            .iter()
            .find(|fact| &fact.id == required)
            .ok_or(ContractError::MissingDependency)?;
        let known = match &fact.state {
            ExplanationFactStateV1::Known { satisfied, .. }
            | ExplanationFactStateV1::FreshnessQualified { satisfied, .. }
                if credible(fact) && fact.expires_at_unix_ms > snapshot.observed_at_unix_ms =>
            {
                Some(*satisfied)
            }
            _ => None,
        };
        match (fact.fact, known) {
            (_, None) => fresh = true,
            (ExplanationFactKind::Capability, Some(value)) => capability |= !value,
            (ExplanationFactKind::Policy | ExplanationFactKind::DestinationAcl, Some(value)) => {
                policy |= !value
            }
            (ExplanationFactKind::AuthorityCoverage, Some(value)) => approval |= !value,
            (ExplanationFactKind::Transformation, Some(value)) => transformation |= !value,
            (ExplanationFactKind::Prerequisite, Some(value)) => prerequisite |= !value,
        }
    }
    if capability {
        return Ok(A::BlockedByCapability);
    }
    if policy {
        return Ok(A::NoRegisteredRemedy);
    }
    // Attester provenance cannot establish endorsement authority. Integrity
    // requires a separately scoped proof and a native enforcement contract.
    if template.requires_integrity {
        fresh = true;
    }
    Ok(if fresh {
        A::NeedsFreshEvidence
    } else if prerequisite {
        A::RequiresPrerequisite
    } else if transformation {
        A::RequiresTransformation
    } else if approval {
        A::RequiresExactApproval
    } else {
        A::FeasibleUnderSnapshot
    })
}

fn credible(fact: &RecoveryExplanationFactV1) -> bool {
    use ExplanationFactSource as S;
    use ExplanationIntegrity as I;
    match fact.fact {
        ExplanationFactKind::Capability => {
            (fact.source, fact.integrity) == (S::NativeAuthority, I::NativeOwned)
        }
        ExplanationFactKind::Policy
        | ExplanationFactKind::AuthorityCoverage
        | ExplanationFactKind::Transformation
        | ExplanationFactKind::Prerequisite => matches!(
            (fact.source, fact.integrity),
            (S::NativeAuthority, I::NativeOwned) | (S::OperatorRegistry, I::OperatorVerified)
        ),
        ExplanationFactKind::DestinationAcl => matches!(
            (fact.source, fact.integrity),
            (S::ProviderAcl, I::ProviderVerified)
                | (S::OperatorRegistry, I::OperatorVerified)
                | (S::NativeAuthority, I::NativeOwned)
        ),
    }
}

/// Whether `a` with `result_a` strictly improves on `b` with `result_b`.
/// Different audiences with equivalent labels remain alternatives, and no
/// candidate with an unspecified latency or a `Top` label dominates or is
/// dominated.
fn dominates(
    a: &RecoveryRemedyTemplateV1,
    result_a: ExplanationAssessmentV1,
    b: &RecoveryRemedyTemplateV1,
    result_b: ExplanationAssessmentV1,
) -> bool {
    use ExplanationAssessmentV1 as A;
    let comparable = |result| matches!(result, A::FeasibleUnderSnapshot | A::RequiresExactApproval);
    if a.family != b.family
        || a.authority_scope != b.authority_scope
        || !comparable(result_a)
        || !comparable(result_b)
        || (result_a == A::RequiresExactApproval && result_b == A::FeasibleUnderSnapshot)
        || matches!(a.disclosure_label, InformationLabel::Top)
        || matches!(b.disclosure_label, InformationLabel::Top)
        || !b.disclosure_label.flows_to(&a.disclosure_label)
        || (a.destination != b.destination && a.disclosure_label == b.disclosure_label)
        || a.cost.approvals > b.cost.approvals
        || a.cost.irreversible_effects > b.cost.irreversible_effects
        || a.cost.budget_units > b.cost.budget_units
        || a.cost.latency == ExplanationLatencyClass::Unspecified
        || b.cost.latency == ExplanationLatencyClass::Unspecified
        || a.cost.latency > b.cost.latency
    {
        return false;
    }
    result_a != result_b
        || a.disclosure_label != b.disclosure_label
        || a.cost.approvals < b.cost.approvals
        || a.cost.irreversible_effects < b.cost.irreversible_effects
        || a.cost.budget_units < b.cost.budget_units
        || a.cost.latency < b.cost.latency
}
