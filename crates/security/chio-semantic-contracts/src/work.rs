use chio_security_types::recovery::{ContractError, MAX_RECOVERY_VERIFICATION_WORK};

/// One shared meter per evaluation, including repeated evidence references.
#[derive(Debug)]
pub struct VerificationBudget {
    remaining: u32,
    exhausted: bool,
}
impl VerificationBudget {
    pub fn new(units: u32) -> Result<Self, ContractError> {
        if units == 0 || units > MAX_RECOVERY_VERIFICATION_WORK {
            return Err(ContractError::WorkBudgetExceeded);
        }
        Ok(Self {
            remaining: units,
            exhausted: false,
        })
    }
    pub fn charge(&mut self, units: u32) -> Result<(), ContractError> {
        if self.exhausted {
            return Err(ContractError::WorkBudgetExceeded);
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
                Err(ContractError::WorkBudgetExceeded)
            }
        }
    }
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }
}
