//! Classified advisory facts and separately projected views. None is a permit.
use super::*;
use crate::InformationLabel;
use serde::{Deserialize, Serialize};

mod registry;
mod result;
mod snapshot;
pub use registry::*;
pub use result::*;
pub use snapshot::*;

pub const MAX_EXPLANATION_FACTS: usize = 32;
pub const MAX_EXPLANATION_TEMPLATES: usize = 16;
pub const MAX_EXPLANATION_DEPENDENCIES: usize = 8;
pub const MAX_EXPLANATION_VALIDITY_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryPlannerVersion {
    #[serde(rename = "chio.recovery.planner.v1")]
    V1,
}

/// Trusted callers supply time explicitly; the evaluator reads no clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationLimitsV1 {
    pub offers: SafeInteger,
    pub work: SafeInteger,
}
impl ExplanationLimitsV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.offers.get() == 0
            || self.offers.get() > MAX_EXPLANATION_TEMPLATES as u64
            || self.work.get() == 0
            || self.work.get() > u64::from(MAX_RECOVERY_VERIFICATION_WORK)
        {
            return Err(ContractError::LimitExceeded);
        }
        Ok(())
    }
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$(
        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+};
}
pub(super) use redacted;
