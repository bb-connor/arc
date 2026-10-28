use chio_security_types::recovery::ContractError;

/// The sum of bounded counts as one work charge.
pub(crate) fn units(parts: &[usize]) -> Result<u32, ContractError> {
    let total = parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(*part))
        .ok_or(ContractError::ArithmeticOverflow)?;
    u32::try_from(total).map_err(|_| ContractError::LimitExceeded)
}
