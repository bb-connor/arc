//! The parent index returns exactly the shares that verifying each retained
//! operation attributes to that parent, across sibling families.

use super::*;
use chio_kernel::admission_operation::AdmissionCallerBudgetShare;

fn verified_shares(
    runtime: &Runtime,
    requests: &[&ToolCallRequest],
    parent: &AdmissionIdentifier,
    now: u64,
) -> TestResult<Vec<AdmissionCallerBudgetShare>> {
    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    let mut shares = Vec::new();
    for request in requests {
        let request_id = AdmissionIdentifier::try_new("request_id", request.request_id.clone())?;
        let (operation, retained) = store
            .load_unambiguous_retained_tool_request(&request_id, &fence, now)?
            .ok_or("retained caller request")?;
        if let Some(share) =
            AdmissionCallerBudgetShare::from_retained_operation(&operation, &retained)?
        {
            if share.parent_id() == parent {
                shares.push(share);
            }
        }
    }
    shares.sort_by(|left, right| {
        left.operation_id()
            .as_str()
            .cmp(right.operation_id().as_str())
    });
    Ok(shares)
}

#[test]
fn indexed_caller_shares_match_verified_operations_for_each_parent() -> TestResult {
    let fixture = caller_fixture()?;
    let mut runtime = fixture.open()?;
    let first_family = Siblings::new(&fixture, &mut runtime)?;
    let second_family = Siblings::new(&fixture, &mut runtime)?;
    let settled = reserve_child(&runtime, &request(&first_family.first, "indexed-settled")?)?;
    let live = reserve_child(&runtime, &request(&first_family.first, "indexed-live")?)?;
    let other = reserve_child(&runtime, &request(&second_family.first, "indexed-other")?)?;
    assert_eq!(
        reconcile(&fixture, &runtime, &settled)?.verdict,
        Verdict::Allow
    );
    assert_state(&fixture, &settled, "completed")?;

    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    let now = store.observed_authority_time()?.get();
    let requests = [&settled, &live, &other];
    for (parent, expected) in [
        (first_family.parent.id.as_str(), Some(&live)),
        (second_family.parent.id.as_str(), Some(&other)),
        ("indexed-unrelated-parent", None),
    ] {
        let parent = AdmissionIdentifier::try_new("parent_id", parent.to_owned())?;
        let indexed = store.load_caller_budget_shares(&parent, 16, &fence, now)?;
        assert_eq!(indexed, verified_shares(&runtime, &requests, &parent, now)?);
        assert_eq!(
            indexed
                .iter()
                .map(|share| share.child_id().as_str())
                .collect::<Vec<_>>(),
            expected
                .map(|request| request.capability.id.as_str())
                .into_iter()
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
