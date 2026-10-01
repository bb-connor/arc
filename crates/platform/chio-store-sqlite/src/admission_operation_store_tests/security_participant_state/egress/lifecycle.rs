use super::*;

#[test]
fn acquire_commit_and_retries_preserve_join_bytes_and_anchor_both_phases() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-lifecycle", None)?;
    let original_joins = joins(&fixture)?;
    let before = counts(&fixture)?;
    let acquired = pending.acquire(&fixture)?;
    assert_eq!(pending.acquire(&fixture)?, acquired);
    assert_eq!(counts(&fixture)?, (1, 1, before.2 + 1));
    let history = fixture
        .store
        .load_security_participant_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("acquired history absent")?;
    assert_eq!(history.historical_fence(), &acquired);
    assert!(history.historical_commitment().is_none());
    assert_eq!(history.binding(), &pending.initialized.admission_binding()?);
    assert_eq!(
        history.operation_id(),
        pending.operation.binding().operation_id()
    );
    assert_eq!(
        history.live_request_hash().as_str(),
        sha256_hex(&canonical_json_bytes(&pending.request)?)
    );
    assert_ne!(
        history.live_request_hash(),
        pending.operation.binding().action_parameter_hash()
    );
    assert_eq!(
        format!("{history:?}"),
        "SecurityParticipantEgressHistory { .. }"
    );
    let acquire_digest = history.event_digest().clone();
    let commitment = commitment(&acquired)?;
    let committed = pending.commit(&fixture, &commitment)?;
    assert_eq!(pending.commit(&fixture, &commitment)?, committed);
    assert_eq!(
        pending.acquire(&fixture)?,
        acquired,
        "retry is historical, not a new pending fence"
    );
    assert_eq!(counts(&fixture)?, (2, 2, before.2 + 1));
    assert_eq!(joins(&fixture)?, original_joins);
    native::verify_coverage(&*fixture.store.connection()?)?;
    let fixture = reopen(fixture)?;
    let history = fixture
        .store
        .load_security_participant_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("committed history absent")?;
    assert_eq!(history.historical_commitment(), Some(&committed));
    assert_ne!(history.event_digest(), &acquire_digest);
    assert_eq!(joins(&fixture)?, original_joins);
    Ok(())
}

#[test]
fn interleaved_join_and_egress_replay_in_global_order_without_reviving_stale_fence(
) -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let first = pending(&fixture, "egress-first", None)?;
    let first_fence = first.acquire(&fixture)?;
    let second = pending(
        &fixture,
        "egress-second",
        Some(first_fence.context_generation),
    )?;
    assert!(second.plan.expected_context_generation > first_fence.context_generation);
    let before = counts(&fixture)?;
    assert!(first.commit(&fixture, &commitment(&first_fence)?).is_err());
    assert_eq!(counts(&fixture)?, before);
    let second_fence = second.acquire(&fixture)?;
    let second_commitment = second.commit(&fixture, &commitment(&second_fence)?)?;
    native::verify_coverage(&*fixture.store.connection()?)?;
    assert_eq!(counts(&fixture)?.0, 3);
    let original_joins = joins(&fixture)?;
    let fixture = reopen(fixture)?;
    assert_eq!(joins(&fixture)?, original_joins);
    let first_history = fixture
        .store
        .load_security_participant_egress(
            first.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("first egress history absent")?;
    assert_eq!(first_history.historical_fence(), &first_fence);
    assert!(first_history.historical_commitment().is_none());
    let second_history = fixture
        .store
        .load_security_participant_egress(
            second.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("second egress history absent")?;
    assert_eq!(
        second_history.historical_commitment(),
        Some(&second_commitment)
    );
    Ok(())
}
