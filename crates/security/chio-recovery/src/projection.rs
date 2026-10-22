//! Visibility filtering precedes search and ranking. Hidden candidates never
//! affect public counts, search exhaustion, rankings or transitive commitments.
use crate::evaluate_explanation;
use alloc::vec::Vec;
use chio_security_types::recovery::{
    BoundedList, ContractError, ExplanationLimitsV1, ExplanationProjectionV1,
    ExplanationViewSummaryV1, RecoveryRemedyRegistryV1, RecoverySnapshotV1,
};
use chio_security_types::InformationLabel;

/// The recipient's view: only facts and templates whose every label flows to
/// `clearance` take part, and the projected registry carries the context
/// classification rather than the hidden registry classification.
pub fn project_explanation(
    snapshot: &RecoverySnapshotV1,
    registry: &RecoveryRemedyRegistryV1,
    limits: ExplanationLimitsV1,
    clearance: &InformationLabel,
) -> Result<ExplanationProjectionV1, ContractError> {
    snapshot.validate()?;
    registry.validate(snapshot)?;
    limits.validate()?;
    let visible = |label: &InformationLabel| {
        !matches!(label, InformationLabel::Top) && label.flows_to(clearance)
    };
    if !visible(&snapshot.context_label) || matches!(clearance, InformationLabel::Top) {
        return Ok(ExplanationProjectionV1 {
            summary: ExplanationViewSummaryV1::AuthorizedInspectionRequired,
            candidates: BoundedList::new(Vec::new())?,
        });
    }
    let facts = snapshot
        .observations
        .as_slice()
        .iter()
        .filter(|fact| visible(&fact.label))
        .cloned()
        .collect();
    let templates = registry
        .templates
        .as_slice()
        .iter()
        .filter(|template| {
            visible(&template.classification)
                && visible(&template.disclosure_label)
                && template.requirements.as_slice().iter().all(|required| {
                    snapshot
                        .observations
                        .as_slice()
                        .iter()
                        .any(|fact| &fact.id == required && visible(&fact.label))
                })
        })
        .cloned()
        .collect();
    let mut projected_snapshot = snapshot.clone();
    projected_snapshot.observations = BoundedList::new(facts)?;
    let mut projected_registry = registry.clone();
    projected_registry.classification = snapshot.context_label.clone();
    projected_registry.templates = BoundedList::new(templates)?;
    let evaluated = evaluate_explanation(&projected_snapshot, &projected_registry, limits)?;
    let summary = if !evaluated.complete {
        ExplanationViewSummaryV1::SearchBoundReached
    } else if evaluated.candidates.as_slice().is_empty() {
        ExplanationViewSummaryV1::NoDisclosableAdvice
    } else {
        ExplanationViewSummaryV1::AlternativesUnderSnapshot
    };
    Ok(ExplanationProjectionV1 {
        summary,
        candidates: evaluated.candidates,
    })
}
