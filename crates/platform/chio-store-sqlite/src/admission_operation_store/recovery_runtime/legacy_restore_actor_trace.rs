//! Test-only bounded evidence that the exact legacy actor resolver was entered.
use crate::admission_operation_store::SqliteAdmissionOperationStore;
use std::cell::Cell;

std::thread_local! {
    // Two means at least two. No identifiers, payloads or authority are retained.
    static RESOLUTION_CALLS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn entered() {
    RESOLUTION_CALLS.with(|calls| calls.set(calls.get().saturating_add(1).min(2)));
}

impl SqliteAdmissionOperationStore {
    /// Reset and return only the calling thread's bounded resolution count.
    pub fn take_legacy_restore_actor_resolution_calls_for_test(&self) -> usize {
        RESOLUTION_CALLS.with(|calls| calls.replace(0))
    }
}
