//! Test-only entry counts do not mint candidate or process-slot authority.
use crate::admission_operation::ConfinedReturnCandidateInput;
use chio_security_types::recovery::{RecoveryScopeV1, RequestId};
use std::cell::RefCell;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Observation {
    scope: RecoveryScopeV1,
    request: RequestId,
    calls: Arc<AtomicUsize>,
}
thread_local! {
    static OBSERVATIONS: RefCell<Vec<Observation>> = const { RefCell::new(Vec::new()) };
}

/// Closed invocation counts for one genuine reserved fixture. No value,
/// classification, boundary, seal or native result is observable through it.
pub struct ConfinedCandidateVerificationFixture {
    calls: Arc<AtomicUsize>,
}
impl ConfinedCandidateVerificationFixture {
    pub fn invocations(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl Drop for ConfinedCandidateVerificationFixture {
    fn drop(&mut self) {
        OBSERVATIONS.with(|observations| {
            observations
                .borrow_mut()
                .retain(|observation| !Arc::ptr_eq(&observation.calls, &self.calls));
        });
    }
}

pub fn observe_confined_candidate_verification_fixture(
    scope: &RecoveryScopeV1,
    request: &RequestId,
) -> ConfinedCandidateVerificationFixture {
    let calls = Arc::new(AtomicUsize::new(0));
    OBSERVATIONS.with(|observations| {
        observations.borrow_mut().push(Observation {
            scope: scope.clone(),
            request: request.clone(),
            calls: calls.clone(),
        });
    });
    ConfinedCandidateVerificationFixture { calls }
}

pub(super) fn observe(input: &ConfinedReturnCandidateInput<'_>) {
    OBSERVATIONS.with(|observations| {
        for observation in observations.borrow().iter() {
            if observation.scope == *input.actor.scope()
                && observation.request == input.boundary.request
            {
                observation.calls.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
}
