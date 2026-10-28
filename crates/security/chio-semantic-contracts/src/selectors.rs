//! Flat typed payload selectors and label-preserving field projection.
use crate::work::units;
use alloc::vec::Vec;
use chio_security_types::recovery::{ContractError, NonEmptyBoundedList, SemanticFieldId};
use chio_security_types::semantic::{
    SemanticFieldV1, SemanticPayloadV1, SemanticSelectorV1, SemanticValueV1,
};
use chio_security_types::work::VerificationBudget;

pub const MAX_PROJECTED_FIELDS: usize = 8;

/// The payload carries exactly the declared input fields, each once.
/// Refuses `BindingMismatch` otherwise.
pub fn validate_semantic_payload(
    payload: &SemanticPayloadV1,
    fields: &[SemanticFieldId],
    budget: &mut VerificationBudget,
) -> Result<(), ContractError> {
    let values = payload.fields.as_slice();
    for (index, value) in values.iter().enumerate() {
        budget.charge(units(&[fields.len(), index, 1])?)?;
        if !fields.contains(&value.field)
            || values
                .iter()
                .take(index)
                .any(|prior| prior.field == value.field)
        {
            return Err(ContractError::BindingMismatch);
        }
    }
    if fields.len() != values.len() {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}

/// Whether the payload satisfies one selector. A missing field or a value of
/// another kind does not satisfy it.
pub fn evaluate_semantic_selector(
    selector: &SemanticSelectorV1,
    payload: &SemanticPayloadV1,
    budget: &mut VerificationBudget,
) -> Result<bool, ContractError> {
    budget.charge(units(&[payload.fields.as_slice().len(), 1])?)?;
    let field = match selector {
        SemanticSelectorV1::Present { field }
        | SemanticSelectorV1::Equals { field, .. }
        | SemanticSelectorV1::TextBytesAtMost { field, .. } => field,
    };
    let value = payload
        .fields
        .as_slice()
        .iter()
        .find(|value| value.field == *field);
    Ok(match (selector, value) {
        (SemanticSelectorV1::Present { .. }, Some(_)) => true,
        (
            SemanticSelectorV1::Equals {
                value: expected, ..
            },
            Some(actual),
        ) => actual.value == *expected,
        (
            SemanticSelectorV1::TextBytesAtMost { bytes, .. },
            Some(SemanticFieldV1 {
                value: SemanticValueV1::Text { value },
                ..
            }),
        ) => u64::try_from(value.as_str().len()).is_ok_and(|length| length <= bytes.get()),
        _ => false,
    })
}

/// Label-preserving deterministic field projection. The runtime admits it as a
/// separate operation and binds its completed output before any later use.
///
/// Refusals: `UnsupportedProfile` for no fields or more than eight,
/// `DuplicateIdentity` for a repeated field and `MissingDependency` for a
/// field the payload lacks.
pub fn project_semantic_fields(
    payload: &SemanticPayloadV1,
    fields: &[SemanticFieldId],
    budget: &mut VerificationBudget,
) -> Result<SemanticPayloadV1, ContractError> {
    if fields.is_empty() || fields.len() > MAX_PROJECTED_FIELDS {
        return Err(ContractError::UnsupportedProfile);
    }
    let mut output: Vec<SemanticFieldV1> = Vec::new();
    for field in fields {
        budget.charge(units(&[payload.fields.as_slice().len(), output.len(), 1])?)?;
        if output.iter().any(|entry| entry.field == *field) {
            return Err(ContractError::DuplicateIdentity);
        }
        output.push(
            payload
                .fields
                .as_slice()
                .iter()
                .find(|entry| entry.field == *field)
                .ok_or(ContractError::MissingDependency)?
                .clone(),
        );
    }
    Ok(SemanticPayloadV1 {
        fields: NonEmptyBoundedList::new(output)?,
    })
}
