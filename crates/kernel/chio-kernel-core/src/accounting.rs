//! Checked amounts at the budget mutation boundary.
//!
//! Wire records retain primitive integers. Arithmetic must first enter these
//! types; there are deliberately no infallible arithmetic operators. Monetary
//! amounts use the full u64 domain. A storage adapter must additionally enforce
//! its own representable range before publishing a mutation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingError {
    ExposureOverflow,
    ExposureUnderflow,
    InvocationOverflow,
    InvocationUnderflow,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExposureUnits(u64);

impl ExposureUnits {
    pub const ZERO: Self = Self(0);

    /// Every u64 is a valid amount, including u64::MAX.
    pub const fn new(units: u64) -> Self {
        Self(units)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn try_add(self, other: Self) -> Result<Self, AccountingError> {
        match self.0.checked_add(other.0) {
            Some(units) => Ok(Self(units)),
            None => Err(AccountingError::ExposureOverflow),
        }
    }

    pub const fn try_sub(self, other: Self) -> Result<Self, AccountingError> {
        match self.0.checked_sub(other.0) {
            Some(units) => Ok(Self(units)),
            None => Err(AccountingError::ExposureUnderflow),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InvocationCount(u32);

impl InvocationCount {
    pub const ONE: Self = Self(1);

    pub const fn new(count: u32) -> Self {
        Self(count)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub const fn try_add(self, other: Self) -> Result<Self, AccountingError> {
        match self.0.checked_add(other.0) {
            Some(count) => Ok(Self(count)),
            None => Err(AccountingError::InvocationOverflow),
        }
    }

    pub const fn try_sub(self, other: Self) -> Result<Self, AccountingError> {
        match self.0.checked_sub(other.0) {
            Some(count) => Ok(Self(count)),
            None => Err(AccountingError::InvocationUnderflow),
        }
    }
}

/// Immutable monetary projection. Construction and every transition validate
/// exposed + spent so individually valid counters cannot hide an invalid total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposureBalance {
    exposed: ExposureUnits,
    spent: ExposureUnits,
}

impl ExposureBalance {
    pub fn new(exposed: u64, spent: u64) -> Result<Self, AccountingError> {
        let balance = Self {
            exposed: ExposureUnits::new(exposed),
            spent: ExposureUnits::new(spent),
        };
        balance.committed()?;
        Ok(balance)
    }

    pub fn committed(self) -> Result<ExposureUnits, AccountingError> {
        self.exposed.try_add(self.spent)
    }

    pub const fn exposed(self) -> u64 {
        self.exposed.get()
    }

    pub const fn spent(self) -> u64 {
        self.spent.get()
    }

    pub fn charge(self, amount: ExposureUnits) -> Result<Self, AccountingError> {
        Self::new(self.exposed.try_add(amount)?.get(), self.spent.get())
    }

    pub fn release(self, amount: ExposureUnits) -> Result<Self, AccountingError> {
        Self::new(self.exposed.try_sub(amount)?.get(), self.spent.get())
    }

    pub fn settle(
        self,
        exposed: ExposureUnits,
        realized: ExposureUnits,
    ) -> Result<Self, AccountingError> {
        // Realized spend must come from this reservation, even if the account
        // has other outstanding reservations that could cover the difference.
        exposed.try_sub(realized)?;
        Self::new(
            self.exposed.try_sub(exposed)?.get(),
            self.spent.try_add(realized)?.get(),
        )
    }
}

#[cfg(test)]
#[path = "accounting/tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "accounting/kani.rs"]
mod proofs;
