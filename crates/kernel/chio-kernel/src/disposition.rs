//! The handling a failure requires from the loop or endpoint that ran it.

/// What a recovery loop, worker or endpoint does with one failure.
///
/// Classifiers match error types, never message text. A failure that no
/// classifier recognizes is [`Disposition::Fatal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The record's own authority or policy refuses it. The service is
    /// healthy, and the same input is refused again.
    Deny,
    /// A dependency is unavailable or a participant has not settled. The
    /// same work can succeed later without any change to it.
    Retry,
    /// This one record cannot make progress as stored. Set it aside with its
    /// evidence and continue with other records.
    Quarantine,
    /// Shared state, configuration, the clock or an invariant failed. Stop
    /// and surface the error: no other record is safe to process.
    Fatal,
}

impl Disposition {
    /// Whether the failure stays with the record that raised it, so a loop
    /// may record it and continue with the next record.
    #[must_use]
    pub fn is_item_scoped(self) -> bool {
        !matches!(self, Self::Fatal)
    }
}
