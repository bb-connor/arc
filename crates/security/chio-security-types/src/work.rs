//! A single irreversible work meter shared by every bounded verifier.

use core::fmt;

use crate::recovery::ContractError;

/// Why a work meter refused construction or a charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkBudgetError {
    /// The requested allowance is zero or exceeds the caller's cap.
    ZeroOrOverCap,
    /// The allowance is spent; every later charge refuses.
    Exhausted,
}

impl fmt::Display for WorkBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroOrOverCap => "work.zero_or_over_cap",
            Self::Exhausted => "work.exhausted",
        })
    }
}

impl core::error::Error for WorkBudgetError {}

impl From<WorkBudgetError> for ContractError {
    fn from(_: WorkBudgetError) -> Self {
        Self::WorkBudgetExceeded
    }
}

/// One shared meter per evaluation, including repeated evidence references.
/// Spending the last unit or overrunning the remainder exhausts it, and an
/// exhausted meter refuses every later charge, including a charge of zero.
#[derive(Debug)]
pub struct VerificationBudget {
    remaining: u32,
    exhausted: bool,
}

impl VerificationBudget {
    /// An allowance of `units`, which must be in `1..=cap`.
    pub fn new(units: u32, cap: u32) -> Result<Self, WorkBudgetError> {
        if units == 0 || units > cap {
            return Err(WorkBudgetError::ZeroOrOverCap);
        }
        Ok(Self {
            remaining: units,
            exhausted: false,
        })
    }

    /// Spend `units` before the work they meter runs.
    pub fn charge(&mut self, units: u32) -> Result<(), WorkBudgetError> {
        if self.exhausted {
            return Err(WorkBudgetError::Exhausted);
        }
        match self.remaining.checked_sub(units) {
            Some(remaining) => {
                self.remaining = remaining;
                self.exhausted = remaining == 0;
                Ok(())
            }
            None => {
                self.remaining = 0;
                self.exhausted = true;
                Err(WorkBudgetError::Exhausted)
            }
        }
    }

    pub const fn remaining(&self) -> u32 {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::ContractError;

    const CAP: u32 = 4096;

    #[test]
    fn construction_rejects_zero_and_units_over_the_cap() {
        assert_eq!(
            VerificationBudget::new(0, CAP).err(),
            Some(WorkBudgetError::ZeroOrOverCap)
        );
        assert_eq!(
            VerificationBudget::new(CAP + 1, CAP).err(),
            Some(WorkBudgetError::ZeroOrOverCap)
        );
        assert_eq!(
            VerificationBudget::new(1, 0).err(),
            Some(WorkBudgetError::ZeroOrOverCap)
        );
        assert_eq!(
            VerificationBudget::new(u32::MAX, u32::MAX - 1).err(),
            Some(WorkBudgetError::ZeroOrOverCap)
        );
    }

    #[test]
    fn construction_accepts_one_and_exactly_the_cap() -> Result<(), WorkBudgetError> {
        assert_eq!(VerificationBudget::new(1, CAP)?.remaining(), 1);
        assert_eq!(VerificationBudget::new(CAP, CAP)?.remaining(), CAP);
        assert_eq!(
            VerificationBudget::new(u32::MAX, u32::MAX)?.remaining(),
            u32::MAX
        );
        Ok(())
    }

    #[test]
    fn charges_subtract_exactly_and_zero_is_free_while_live() -> Result<(), WorkBudgetError> {
        let mut budget = VerificationBudget::new(10, CAP)?;
        budget.charge(3)?;
        assert_eq!(budget.remaining(), 7);
        budget.charge(0)?;
        assert_eq!(budget.remaining(), 7);
        budget.charge(6)?;
        assert_eq!(budget.remaining(), 1);
        Ok(())
    }

    #[test]
    fn spending_the_last_unit_exhausts_and_refuses_a_zero_charge() -> Result<(), WorkBudgetError> {
        let mut budget = VerificationBudget::new(5, CAP)?;
        budget.charge(5)?;
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.charge(0), Err(WorkBudgetError::Exhausted));
        assert_eq!(budget.charge(1), Err(WorkBudgetError::Exhausted));
        assert_eq!(budget.remaining(), 0);
        Ok(())
    }

    #[test]
    fn a_charge_past_remaining_exhausts_and_errors() -> Result<(), WorkBudgetError> {
        let mut budget = VerificationBudget::new(4, CAP)?;
        budget.charge(1)?;
        assert_eq!(budget.charge(4), Err(WorkBudgetError::Exhausted));
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.charge(0), Err(WorkBudgetError::Exhausted));
        let mut full = VerificationBudget::new(CAP, CAP)?;
        assert_eq!(full.charge(u32::MAX), Err(WorkBudgetError::Exhausted));
        assert_eq!(full.remaining(), 0);
        assert_eq!(full.charge(0), Err(WorkBudgetError::Exhausted));
        Ok(())
    }

    #[test]
    fn errors_map_to_the_recovery_work_budget_category() {
        assert_eq!(
            ContractError::from(WorkBudgetError::ZeroOrOverCap),
            ContractError::WorkBudgetExceeded
        );
        assert_eq!(
            ContractError::from(WorkBudgetError::Exhausted),
            ContractError::WorkBudgetExceeded
        );
    }

    #[test]
    fn errors_render_stable_codes() {
        assert_eq!(
            alloc::format!("{}", WorkBudgetError::ZeroOrOverCap),
            "work.zero_or_over_cap"
        );
        assert_eq!(
            alloc::format!("{}", WorkBudgetError::Exhausted),
            "work.exhausted"
        );
    }
}
