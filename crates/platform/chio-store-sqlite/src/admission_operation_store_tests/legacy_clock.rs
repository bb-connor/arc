//! Test-only generation of authentic v1 history for schema upgrade fixtures.
//! This entire module and the writer hook are absent from production builds.

use std::cell::Cell;

thread_local! {
    static LEGACY_FIXTURE: Cell<bool> = const { Cell::new(false) };
}

pub(in crate::admission_operation_store) fn fixture_clocks(
    observed: u64,
    recorded: u64,
) -> (u64, Option<u64>) {
    if LEGACY_FIXTURE.get() {
        (recorded, None)
    } else {
        (observed, Some(observed))
    }
}

pub(super) struct LegacyClock {
    previous: bool,
    // The scope must be dropped on the thread whose fixture it controls.
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl LegacyClock {
    pub(super) fn enter() -> Self {
        Self {
            previous: LEGACY_FIXTURE.replace(true),
            _thread_bound: std::marker::PhantomData,
        }
    }
}

impl Drop for LegacyClock {
    fn drop(&mut self) {
        LEGACY_FIXTURE.set(self.previous);
    }
}
