//! Bounded descriptions of selector precedence, never native execution authority.
use crate::VerificationBudget;
use alloc::{collections::BTreeSet, vec::Vec};
use chio_security_types::{flow::InformationLabel, recovery::*, semantic::*};
use serde::{Deserialize, Serialize};

/// Every use still requires independently fresh capability, policy, flow,
/// actor, ACL and reservation checks inside the owning native transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticNativeCeilingRequirementV1 {
    FreshNativeAdmission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAppliedSelectorV1 {
    pub selector_index: SafeInteger,
    pub selector: SemanticSelectorV1,
}

/// Retained contract data describes what was matched. It cannot be submitted
/// as an endorsement, reservation, capability or native capture witness.
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
    budget.charge(
        u32::try_from(route.destinations.as_slice().len())
            .map_err(|_| ContractError::LimitExceeded)?,
    )?;
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
    budget.charge(
        u32::try_from(route.operator_selectors.as_slice().len())
            .map_err(|_| ContractError::LimitExceeded)?,
    )?;
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
