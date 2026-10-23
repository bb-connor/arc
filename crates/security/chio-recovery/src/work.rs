use chio_security_types::{recovery::ContractError, InformationLabel};

/// A fixed allowance charged before each bounded step.
pub(crate) struct Work {
    used: u64,
    ceiling: u64,
}

impl Work {
    pub(crate) const fn used(&self) -> u64 {
        self.used
    }

    pub(crate) fn remaining(&self) -> Result<u64, ContractError> {
        self.ceiling
            .checked_sub(self.used)
            .ok_or(ContractError::ArithmeticOverflow)
    }

    pub(crate) const fn new(ceiling: u64) -> Self {
        Self { used: 0, ceiling }
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

    /// One unit per label operation. Label cardinality and identifier sizes
    /// have their own protocol ceilings, so a valid label cannot alone consume
    /// the whole allowance.
    pub(crate) fn label(&mut self, _: &InformationLabel) -> Result<(), ContractError> {
        self.spend(1)
    }
}
