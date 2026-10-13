//! Test-only evidence of an authenticated immutable revision collision.
use crate::admission_operation_store::SqliteAdmissionOperationStore;
use std::cell::Cell;

std::thread_local! {
    // Two means at least two. No identifiers, payloads or authority are retained.
    static IMMUTABLE_COLLISIONS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn immutable_collision() {
    IMMUTABLE_COLLISIONS.with(|count| count.set(count.get().saturating_add(1).min(2)));
}

impl SqliteAdmissionOperationStore {
    /// Reset and return the calling thread's bounded immutable collision count.
    pub fn take_checkpoint_history_collisions_for_test(&self) -> usize {
        IMMUTABLE_COLLISIONS.with(|count| count.replace(0))
    }
}
