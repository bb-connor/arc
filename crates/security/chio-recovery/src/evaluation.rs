//! Finite deterministic evaluation over supplied data, without ambient state.
use alloc::vec::Vec;
use chio_security_types::{recovery::*, InformationLabel};

pub(crate) struct Work {
    used: u64,
    ceiling: u64,
}
impl Work {
    pub(crate) const fn new(ceiling: u64) -> Self {
        Self { used: 0, ceiling }
    }

    pub(crate) fn remaining(&self) -> Result<u64, ContractError> {
        self.ceiling
            .checked_sub(self.used)
            .ok_or(ContractError::ArithmeticOverflow)
    }

    pub(crate) fn spend(&mut self, amount: u64) -> Result<(), ContractError> {
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
    pub(crate) fn label(&mut self, _: &InformationLabel) -> Result<(), ContractError> {
        // Label cardinality and identifier sizes have their own protocol
        // ceilings. Search meters bounded label operations, rather than
        // charging the same reader memberships again at every copied fact.
        // A valid label must not alone consume the entire search allowance.
        self.spend(1)
    }
}

/// Results are advisory claims under this observed basis. All template and
/// fact identities are checked before evaluation, even beyond a search bound.
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
    let mut complete = true;
    let internal = (|| -> Result<(), ContractError> {
        work.label(&classification)?;
        work.label(&registry.classification)?;
        classification = classification
            .join_restrictions(&registry.classification)
            .map_err(|_| ContractError::WorkBudgetExceeded)?;
        for fact in snapshot.observations.as_slice() {
            work.spend(1)?;
            work.label(&fact.label)?;
            classification = classification
                .join_restrictions(&fact.label)
                .map_err(|_| ContractError::WorkBudgetExceeded)?;
        }
        for template in registry.templates.as_slice() {
            work.spend(1)?;
            work.label(&template.classification)?;
            work.label(&template.disclosure_label)?;
            classification = classification
                .join_restrictions(&template.classification)
                .map_err(|_| ContractError::WorkBudgetExceeded)?;
            classification = classification
                .join_restrictions(&template.disclosure_label)
                .map_err(|_| ContractError::WorkBudgetExceeded)?;
        }
        for template in registry.templates.as_slice() {
            if !template.satisfies_task {
                continue;
            }
            if candidates.len() as u64 >= limits.offers.get() {
                return Err(ContractError::WorkBudgetExceeded);
            }
            let assessment = assess(&snapshot, template, &mut work)?;
            candidates.push(ExplanationCandidateV1 {
                template_id: template.template_id.clone(),
                assessment,
            });
        }
        let mut dominated = alloc::vec![false; candidates.len()];
        for (index, candidate) in candidates.iter().enumerate() {
            for other in &candidates {
                work.spend(1)?;
                if candidate == other {
                    continue;
                }
                let a = registry
                    .templates
                    .as_slice()
                    .iter()
                    .find(|t| t.template_id == other.template_id)
                    .ok_or(ContractError::MissingDependency)?;
                let b = registry
                    .templates
                    .as_slice()
                    .iter()
                    .find(|t| t.template_id == candidate.template_id)
                    .ok_or(ContractError::MissingDependency)?;
                if dominates(a, other.assessment, b, candidate.assessment) {
                    dominated[index] = true;
                }
            }
        }
        candidates = candidates
            .iter()
            .zip(dominated)
            .filter(|(_, dominated)| !dominated)
            .map(|(candidate, _)| candidate.clone())
            .collect();
        Ok(())
    })();
    match internal {
        Ok(()) => {}
        Err(ContractError::WorkBudgetExceeded) => {
            complete = false;
            // Incomplete label joining must never make a full graph public.
            classification = InformationLabel::Top;
        }
        Err(error) => return Err(error),
    }
    let assessment = if !complete {
        ExplanationAssessmentV1::SearchBoundReached
    } else if candidates.is_empty() {
        ExplanationAssessmentV1::NoRegisteredRemedy
    } else {
        // This is a coarse summary; non-comparable candidate results survive.
        candidates
            .iter()
            .map(|candidate| candidate.assessment)
            .min()
            .ok_or(ContractError::InvalidState)?
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

pub(crate) fn assess(
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
        _ => return Ok(A::UnknownOutcome),
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
    // requires a separately scoped proof and native enforcement contract.
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
        ExplanationFactKind::Policy | ExplanationFactKind::AuthorityCoverage => matches!(
            (fact.source, fact.integrity),
            (S::NativeAuthority, I::NativeOwned) | (S::OperatorRegistry, I::OperatorVerified)
        ),
        ExplanationFactKind::DestinationAcl => matches!(
            (fact.source, fact.integrity),
            (S::ProviderAcl, I::ProviderVerified)
                | (S::OperatorRegistry, I::OperatorVerified)
                | (S::NativeAuthority, I::NativeOwned)
        ),
        ExplanationFactKind::Transformation | ExplanationFactKind::Prerequisite => matches!(
            (fact.source, fact.integrity),
            (S::NativeAuthority, I::NativeOwned) | (S::OperatorRegistry, I::OperatorVerified)
        ),
    }
}

fn dominates(
    a: &RecoveryRemedyTemplateV1,
    result_a: ExplanationAssessmentV1,
    b: &RecoveryRemedyTemplateV1,
    result_b: ExplanationAssessmentV1,
) -> bool {
    use ExplanationAssessmentV1 as A;
    if a.family != b.family || a.authority_scope != b.authority_scope
        || !matches!(result_a, A::FeasibleUnderSnapshot | A::RequiresExactApproval)
        || !matches!(result_b, A::FeasibleUnderSnapshot | A::RequiresExactApproval)
        || (result_a == A::RequiresExactApproval && result_b == A::FeasibleUnderSnapshot)
        || matches!(a.disclosure_label, InformationLabel::Top)
        || matches!(b.disclosure_label, InformationLabel::Top)
        || !b.disclosure_label.flows_to(&a.disclosure_label)
        // Different audiences with equivalent labels remain alternatives.
        || (a.destination != b.destination && a.disclosure_label == b.disclosure_label)
        || a.cost.approvals > b.cost.approvals || a.cost.irreversible_effects > b.cost.irreversible_effects
        || a.cost.budget_units > b.cost.budget_units
        || a.cost.latency == ExplanationLatencyClass::Unspecified
        || b.cost.latency == ExplanationLatencyClass::Unspecified || a.cost.latency > b.cost.latency
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
