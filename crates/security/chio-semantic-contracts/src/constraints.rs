//! The resolved precedence of package and operator selectors for one route.
use crate::work::units;
use alloc::{collections::BTreeSet, vec::Vec};
use chio_security_types::flow::InformationLabel;
use chio_security_types::recovery::{
    BoundedList, CanonicalPayloadDigest, ContractError, NonEmptyBoundedList, SafeInteger,
    SemanticDestinationId, SemanticFactId, SemanticFieldId, SemanticOperationId,
    SemanticPackageDigest, SemanticRegistryDigest,
};
use chio_security_types::semantic::{
    SemanticChannelRuleV1, SemanticOperationContractV1, SemanticPrerequisiteRequirementV1,
    SemanticReviewedOverrideV1, SemanticRouteV1, SemanticSelectorV1, SemanticWithheldStatusV1,
};
use chio_security_types::work::VerificationBudget;
use serde::{Deserialize, Serialize};

/// Every use requires independently fresh capability, policy, flow,
/// actor, ACL and reservation checks inside the owning native transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticNativeCeilingRequirementV1 {
    FreshNativeAdmission,
}

/// A package selector that remains in force, with its index in the contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAppliedSelectorV1 {
    pub selector_index: SafeInteger,
    pub selector: SemanticSelectorV1,
}

/// The effective constraints of one route: package selectors still applied,
/// reviewed overrides with their reasons and fixtures, and operator selectors,
/// which always apply. Resolved contract data describes what matched; it
/// cannot be submitted as an endorsement, reservation, capability or native
/// capture witness.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSemanticConstraintsV1 {
    pub registry: SemanticRegistryDigest,
    pub package: SemanticPackageDigest,
    pub operation: SemanticOperationId,
    pub destination: SemanticDestinationId,
    pub input_schema: CanonicalPayloadDigest,
    pub output_schema: CanonicalPayloadDigest,
    pub implementation: CanonicalPayloadDigest,
    pub channels: NonEmptyBoundedList<SemanticChannelRuleV1, 13>,
    pub input_fields: BoundedList<SemanticFieldId, 16>,
    pub applied_package_selectors: BoundedList<SemanticAppliedSelectorV1, 16>,
    pub reviewed_overrides: BoundedList<SemanticReviewedOverrideV1, 16>,
    pub operator_selectors: BoundedList<SemanticSelectorV1, 16>,
    pub required_assertions: BoundedList<SemanticFactId, 8>,
    pub prerequisites: BoundedList<SemanticPrerequisiteRequirementV1, 8>,
    pub source_label: InformationLabel,
    pub destination_label: InformationLabel,
    pub withheld_status: Option<SemanticWithheldStatusV1>,
    pub native_ceilings: SemanticNativeCeilingRequirementV1,
}

impl core::fmt::Debug for ResolvedSemanticConstraintsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ResolvedSemanticConstraintsV1([redacted])")
    }
}

/// Recompute precedence from the exact selected route and contract. Authority
/// verification remains with the caller; this pure function only returns data.
///
/// Refusals: `BindingMismatch` when the route names another operation,
/// implementation or schema, when the destination is not routed, or when an
/// override names an absent selector; `DuplicateIdentity` for a selector
/// overridden twice; `WorkBudgetExceeded` on exhaustion.
pub fn resolve_semantic_constraints(
    registry: SemanticRegistryDigest,
    route: &SemanticRouteV1,
    contract: &SemanticOperationContractV1,
    destination: &SemanticDestinationId,
    source_label: &InformationLabel,
    budget: &mut VerificationBudget,
) -> Result<ResolvedSemanticConstraintsV1, ContractError> {
    if route.operation != contract.operation
        || route.implementation != contract.implementation
        || route.input_schema != contract.input_schema
        || route.output_schema != contract.output_schema
    {
        return Err(ContractError::BindingMismatch);
    }
    budget.charge(units(&[route.destinations.as_slice().len()])?)?;
    let destination = route
        .destinations
        .as_slice()
        .iter()
        .find(|candidate| candidate.destination == *destination)
        .ok_or(ContractError::BindingMismatch)?;
    let mut overridden = BTreeSet::new();
    for rule in route.reviewed_overrides.as_slice() {
        budget.charge(1)?;
        let index =
            usize::try_from(rule.selector_index.get()).map_err(|_| ContractError::LimitExceeded)?;
        if index >= contract.selectors.as_slice().len() {
            return Err(ContractError::BindingMismatch);
        }
        if !overridden.insert(index) {
            return Err(ContractError::DuplicateIdentity);
        }
    }
    let mut applied = Vec::new();
    for (index, selector) in contract.selectors.as_slice().iter().enumerate() {
        budget.charge(1)?;
        if !overridden.contains(&index) {
            applied.push(SemanticAppliedSelectorV1 {
                selector_index: SafeInteger::new(
                    u64::try_from(index).map_err(|_| ContractError::LimitExceeded)?,
                )?,
                selector: selector.clone(),
            });
        }
    }
    budget.charge(units(&[route.operator_selectors.as_slice().len()])?)?;
    Ok(ResolvedSemanticConstraintsV1 {
        registry,
        package: route.package,
        operation: contract.operation.clone(),
        destination: destination.destination.clone(),
        input_schema: contract.input_schema,
        output_schema: contract.output_schema,
        implementation: contract.implementation,
        channels: contract.channels.clone(),
        input_fields: contract.input_fields.clone(),
        applied_package_selectors: BoundedList::new(applied)?,
        reviewed_overrides: route.reviewed_overrides.clone(),
        operator_selectors: route.operator_selectors.clone(),
        required_assertions: contract.required_assertions.clone(),
        prerequisites: contract.prerequisites.clone(),
        source_label: source_label.clone(),
        destination_label: destination.audience.clone(),
        withheld_status: contract.withheld_status.clone(),
        native_ceilings: SemanticNativeCeilingRequirementV1::FreshNativeAdmission,
    })
}
