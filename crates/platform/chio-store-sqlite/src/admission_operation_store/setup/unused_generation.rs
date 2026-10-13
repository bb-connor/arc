//! A transaction-bound closure witness preserves the selected original identity.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::admission_operation_store) enum UnusedSetupReplacementReason {
    ProfileChanged,
    InitialWindowExpired,
    WriterChanged,
    StaleSource,
}


impl<'tx, 'conn> VerifiedUnusedSetupGeneration<'tx, 'conn> {






}

impl core::fmt::Debug for VerifiedUnusedSetupGeneration<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedUnusedSetupGeneration([redacted])")
    }
}


