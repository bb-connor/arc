use crate::VerificationBudget;
use alloc::vec::Vec;
use chio_security_types::{recovery::*, semantic::*};

pub fn validate_semantic_payload(
    payload: &SemanticPayloadV1,
    fields: &[SemanticFieldId],
    budget: &mut VerificationBudget,
) -> Result<(), ContractError> {
    for (index, value) in payload.fields.as_slice().iter().enumerate() {
        budget.charge((fields.len() + index + 1) as u32)?;
        if !fields.contains(&value.field)
            || payload.fields.as_slice()[..index]
                .iter()
                .any(|prior| prior.field == value.field)
        {
            return Err(ContractError::BindingMismatch);
        }
    }
    if fields.len() != payload.fields.as_slice().len() {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}

pub fn evaluate_semantic_selector(
    selector: &SemanticSelectorV1,
    payload: &SemanticPayloadV1,
    budget: &mut VerificationBudget,
) -> Result<bool, ContractError> {
    budget.charge(payload.fields.as_slice().len() as u32 + 1)?;
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
        ) => value.as_str().len() as u64 <= bytes.get(),
        _ => false,
    })
}

/// Label-preserving deterministic field projection. The runtime must admit this
/// as a separate operation and bind its completed output before using it again.
pub fn project_semantic_fields(
    payload: &SemanticPayloadV1,
    fields: &[SemanticFieldId],
    budget: &mut VerificationBudget,
) -> Result<SemanticPayloadV1, ContractError> {
    if fields.is_empty() || fields.len() > 8 {
        return Err(ContractError::UnsupportedProfile);
    }
    let mut output = Vec::new();
    for field in fields {
        budget.charge(payload.fields.as_slice().len() as u32 + output.len() as u32 + 1)?;
        if output
            .iter()
            .any(|entry: &SemanticFieldV1| entry.field == *field)
        {
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
