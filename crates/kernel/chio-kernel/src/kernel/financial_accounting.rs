//! Grant ceilings are optional; an invocation exposure is never a grant ceiling.
use super::KernelError;
pub(super) fn financial_budget_remaining(
    total: Option<u64>,
    committed: u64,
) -> Result<Option<u64>, KernelError> {
    total
        .map(|total| {
            total
                .checked_sub(committed)
                .ok_or(KernelError::FinancialBudgetExceeded { total, committed })
        })
        .transpose()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_bounds_distinguish_uncapped_full_width_and_corrupt_accounting() {
        assert_eq!(
            financial_budget_remaining(None, u64::MAX).unwrap_or(Some(0)),
            None
        );
        assert_eq!(
            financial_budget_remaining(Some(u64::MAX), 9).unwrap_or(None),
            Some(u64::MAX - 9)
        );
        assert_eq!(
            financial_budget_remaining(Some(100), 90).unwrap_or(None),
            Some(10)
        );
        assert!(matches!(
            financial_budget_remaining(Some(100), 101),
            Err(KernelError::FinancialBudgetExceeded {
                total: 100,
                committed: 101
            })
        ));
    }
}
