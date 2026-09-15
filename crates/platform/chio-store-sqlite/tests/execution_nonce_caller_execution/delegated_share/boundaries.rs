//! Cross-path admission and fail-closed ownership boundaries.

use super::*;

#[test]
fn a_caller_share_also_blocks_ordinary_kernel_dispatch_until_settlement() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let first = reserve_child(&runtime, &request(&siblings.first, "caller-before-kernel")?)?;
    let blocked = runtime
        .kernel
        .evaluate_tool_call_blocking(&request(&siblings.second, "kernel-share-blocked")?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    assert!(blocked
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("sibling-sum")));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    assert_eq!(reconcile(&runtime, &first)?.verdict, Verdict::Allow);
    let second = request(&siblings.second, "kernel-share-released")?;
    let nonce = preflight(&runtime, &second)?;
    let response = runtime
        .kernel
        .evaluate_tool_call_blocking(&with_nonce(&second, &nonce))?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(response.terminal_state, OperationTerminalState::Completed);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn concurrent_siblings_cannot_oversubscribe_and_denied_claims_do_not_leak() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let first = request(&siblings.first, "concurrent-share-first")?;
    let second = request(&siblings.second, "concurrent-share-second")?;
    let start = std::sync::Barrier::new(2);
    let reserve = |request: &ToolCallRequest| {
        start.wait();
        runtime.kernel.reserve_caller_execution_blocking(request)
    };
    let (first_response, second_response) = std::thread::scope(|scope| {
        let first = scope.spawn(|| reserve(&first));
        let second = scope.spawn(|| reserve(&second));
        (first.join(), second.join())
    });
    let first_response = first_response.map_err(|_| "first reservation panicked")??;
    let second_response = second_response.map_err(|_| "second reservation panicked")??;
    let admitted = [&first_response, &second_response]
        .into_iter()
        .filter(|response| response.verdict == Verdict::Allow)
        .count();
    assert!(
        admitted <= 1,
        "concurrent siblings exceeded their parent's share"
    );
    // Both pending holds can conservatively deny. Safety does not imply an
    // exactly-one-winner progress guarantee. Either way, every admitted owner
    // settles, and neither denied operation may keep an orphaned share.
    for (request, response) in [(&first, first_response), (&second, second_response)] {
        if response.verdict == Verdict::Allow {
            let reserved = with_nonce(
                request,
                response
                    .execution_nonce
                    .as_deref()
                    .ok_or("reserved nonce")?,
            );
            assert_eq!(reconcile(&runtime, &reserved)?.verdict, Verdict::Allow);
        } else {
            assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        }
    }
    let next = reserve_child(&runtime, &request(&siblings.first, "after-share-race")?)?;
    assert_eq!(reconcile(&runtime, &next)?.verdict, Verdict::Allow);
    let _sibling = reserve_child(
        &runtime,
        &request(&siblings.second, "sibling-after-share-race")?,
    )?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn an_out_of_band_terminal_edit_cannot_hide_a_live_caller_share() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let _first = reserve_child(&runtime, &request(&siblings.first, "tampered-share-first")?)?;
    // This edit would exclude the funded owner from the query's active-row
    // predicate. The serving authority must detect the external mutation
    // before trusting even an apparently empty result.
    execute_sql(
        &fixture,
        "UPDATE admission_operations SET terminal = 1, state = 'completed', version = version + 1
         WHERE request_id = 'tampered-share-first'",
    )?;
    let parent = AdmissionIdentifier::try_new("parent_id", siblings.parent.id.clone())?;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let shares = runtime
        .authority
        .admission_operation_store()
        .load_caller_budget_shares(&parent, 1, &runtime.authority.mutation_fence(), now);
    assert!(
        shares.is_err(),
        "tampering must not become an empty snapshot"
    );
    let response = runtime
        .kernel
        .reserve_caller_execution_blocking(&request(&siblings.second, "after-share-tampering")?);
    if let Ok(response) = response {
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
