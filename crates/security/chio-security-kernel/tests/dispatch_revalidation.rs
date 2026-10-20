#[path = "dispatch_revalidation/support.rs"]
mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use chio_guards::GuardPipeline;
use chio_kernel::{Guard, Verdict};
use chio_security_kernel::{CapabilitySetSuspensionGuard, ContainmentGuard, MissingContextPolicy};
use support::{Authority, State};

fn check(containment: bool, next: State) {
    for nested in [false, true] {
        for delayed in [false, true] {
            for pipeline in [false, true] {
                let authority = Arc::new(Authority::new());
                let guard: Box<dyn Guard> = if containment {
                    Box::new(ContainmentGuard::new(
                        authority.clone(),
                        MissingContextPolicy::Deny,
                    ))
                } else {
                    Box::new(CapabilitySetSuspensionGuard::new(
                        authority.clone(),
                        MissingContextPolicy::Deny,
                    ))
                };
                let guard = if pipeline {
                    let mut composed = GuardPipeline::new();
                    composed.add(guard);
                    Box::new(composed) as Box<dyn Guard>
                } else {
                    guard
                };
                let response = support::run(guard, authority.clone(), next, delayed, nested);
                let initial_queries = if containment { 4 } else { 1 };
                if next != State::Clear {
                    assert!(authority.queries.load(Ordering::SeqCst) > initial_queries,
                        "guard not revalidated, containment={containment} nested={nested} delayed={delayed} pipeline={pipeline}");
                }
                assert_eq!(
                    response.verdict,
                    if next == State::Clear {
                        Verdict::Allow
                    } else {
                        Verdict::Deny
                    }
                );
                if next != State::Clear {
                    let expected_reason = if containment {
                        "guard denied the request: guard dispatch revalidation failed: guard denied the request: chio-containment-overlay dispatch revalidation denied"
                    } else {
                        "guard denied the request: guard dispatch revalidation failed: guard denied the request: chio-capability-set-suspension dispatch revalidation denied"
                    };
                    assert_eq!(response.reason.as_deref(), Some(expected_reason));
                    assert!(response.output.is_none());
                }
            }
        }
    }
}

#[test]
fn containment_activated_after_admission_denies_dispatch() {
    check(true, State::Active);
}
#[test]
fn containment_authority_outage_after_admission_denies_dispatch() {
    check(true, State::Unavailable);
}
#[test]
fn malformed_containment_after_admission_denies_dispatch() {
    check(true, State::Malformed);
}
#[test]
fn clear_containment_preserves_single_invocation_quota() {
    check(true, State::Clear);
}
#[test]
fn suspension_activated_after_admission_denies_dispatch() {
    check(false, State::Active);
}
#[test]
fn suspension_authority_outage_after_admission_denies_dispatch() {
    check(false, State::Unavailable);
}
#[test]
fn malformed_suspension_after_admission_denies_dispatch() {
    check(false, State::Malformed);
}
#[test]
fn clear_suspension_preserves_single_invocation_quota() {
    check(false, State::Clear);
}
