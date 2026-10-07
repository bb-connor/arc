//! Counts describe actual protected mutations and grant no resource credit.

/// Exact logical writes and canonical payload bytes in one protected writer.
/// This data does not promise SQLite pages, WAL space or finishing capacity.
pub(in crate::admission_operation_store) struct ProtectedMutationDelta {
    pub(super) mutations: u64,
    pub(super) encoded_bytes: u64,
}

impl ProtectedMutationDelta {
    /// Empty reported logical footprint. This data grants no append allowance,
    /// source authority, physical capacity, debt discharge or resource credit.
    pub(in crate::admission_operation_store) const fn zero() -> Self {
        Self {
            mutations: 0,
            encoded_bytes: 0,
        }
    }

    /// Aggregate reported logical footprints without changing their meaning.
    /// Every actual writer remains responsible for its authenticated appends.
    pub(in crate::admission_operation_store) fn checked_add(
        &self,
        other: &Self,
    ) -> Result<Self, super::AdmissionOperationStoreError> {
        Ok(Self {
            mutations: self
                .mutations
                .checked_add(other.mutations)
                .ok_or_else(|| super::invariant("protected mutation count exhausted"))?,
            encoded_bytes: self
                .encoded_bytes
                .checked_add(other.encoded_bytes)
                .ok_or_else(|| super::invariant("protected encoded byte count exhausted"))?,
        })
    }

    pub(in crate::admission_operation_store) fn mutations(&self) -> u64 {
        self.mutations
    }

    pub(in crate::admission_operation_store) fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
}
