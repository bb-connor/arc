use crate::receipt_metadata::MercuryContractError;

pub(crate) fn ensure_non_empty(
    field: &'static str,
    value: &str,
) -> Result<(), MercuryContractError> {
    if value.trim().is_empty() {
        return Err(MercuryContractError::EmptyField(field));
    }
    if value.trim() != value {
        return Err(MercuryContractError::PaddedField(field));
    }
    Ok(())
}
