use super::*;
use chio_kernel::tool_outcome::test_support::prepared_pure_evaluation;

fn commit_head(fixture: &Fixture) -> i64 {
    fixture
        .outcomes
        .connection()
        .expect("connection")
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("commit head")
}

#[test]
fn pure_results_and_resolution_keep_every_entry_with_one_anchor_write() {
    let fixture = fixture();
    let at = now_ms();
    let committed = committed(&fixture, "pure-finalization", at);
    let (operation, outcome) = record_return(&fixture, &committed, at + 20);
    let prepared =
        prepared_pure_evaluation(&operation, &outcome, at + 22).expect("pure evaluation");
    let lease = claim(&fixture, &operation, at + 22);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 23)
        .expect("begin evaluation");
    let results = [digest("pure_result", 'a'), digest("pure_result", 'b')];
    let first = prepared
        .record_next_pure_result(results[0].clone())
        .expect("first result");
    let second = first
        .record_next_pure_result(results[1].clone())
        .expect("second result");
    let (terminal, resolved, blob) =
        resolve_with_blob(&outcome, &second, SettlementDispositionV1::NotApplicable)
            .expect("resolve results");
    let generation = fixture.authority.anchor_generation().expect("anchor");
    let head = commit_head(&fixture);
    let pair = fixture
        .outcomes
        .finalize_post_return_with_pure_results(
            operation.binding().operation_id(),
            prepared.version(),
            &results,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fixture.fence,
            at + 24,
        )
        .expect("finalize all pure results");
    assert_eq!(pair, (terminal.clone(), resolved.clone()));
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        generation + 1
    );
    assert_eq!(commit_head(&fixture), head + 3);
    let kinds = {
        let connection = fixture.outcomes.connection().expect("connection");
        let mut query = connection.prepare(
            "SELECT mutation_kind FROM authority_global_commits WHERE commit_sequence > ?1 ORDER BY commit_sequence",
        ).expect("journal query");
        query
            .query_map([head], |row| row.get::<_, String>(0))
            .expect("journal rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("decode journal")
    };
    assert_eq!(kinds, vec!["participant_update"; 3]);
    let operation_id = operation.binding().operation_id();
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(operation_id)
            .expect("resolved blob"),
        Some(blob.clone())
    );
    assert_eq!(
        fixture.outcomes.finalize_post_return_with_pure_results(
            operation_id,
            prepared.version(),
            &results,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fixture.fence,
            at + 25,
        ),
        Err(ToolOutcomeStoreError::CasConflict)
    );
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        generation + 1
    );

    let database = fixture.database.clone();
    let locks = fixture.lock_root.clone();
    let Fixture {
        _temp,
        outcomes,
        operations,
        authority,
        ..
    } = fixture;
    drop(outcomes);
    drop(operations);
    drop(authority);
    let reopened =
        SqliteAuthorityStore::open_serving(&database, &locks).expect("reopen anchored result");
    let outcomes = reopened.tool_outcome_store();
    assert_eq!(
        outcomes
            .lookup_post_return_evaluation(operation_id)
            .expect("reopened evaluation"),
        Some(terminal)
    );
    assert_eq!(
        outcomes
            .lookup_by_operation(operation_id)
            .expect("reopened outcome"),
        Some(resolved)
    );
    assert_eq!(
        outcomes
            .load_resolved_output_by_operation(operation_id)
            .expect("reopened blob"),
        Some(blob)
    );
}

#[test]
fn rejected_terminal_pair_rolls_back_all_pure_steps_and_journal_entries() {
    let fixture = fixture();
    let at = now_ms();
    let committed = committed(&fixture, "pure-finalization-rejection", at);
    let (operation, outcome) = record_return(&fixture, &committed, at + 20);
    let prepared =
        prepared_pure_evaluation(&operation, &outcome, at + 22).expect("pure evaluation");
    let lease = claim(&fixture, &operation, at + 22);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 23)
        .expect("begin evaluation");
    let results = [digest("pure_result", 'a'), digest("pure_result", 'b')];
    let first = prepared
        .record_next_pure_result(results[0].clone())
        .expect("first result");
    let second = first
        .record_next_pure_result(results[1].clone())
        .expect("second result");
    let (terminal, resolved, blob) =
        resolve_with_blob(&outcome, &second, SettlementDispositionV1::NotApplicable)
            .expect("resolve results");
    let substituted = CanonicalResolvedOutputBlobV1::from_signing_preimage(b"substitute".to_vec())
        .expect("substitute blob");
    let generation = fixture.authority.anchor_generation().expect("anchor");
    let head = commit_head(&fixture);
    let operation_id = operation.binding().operation_id();
    let mut wrong_fence = fixture.fence.clone();
    wrong_fence.owner_epoch += 1;
    let wrong_results = [results[0].clone(), digest("pure_result", 'c')];
    for (candidate_results, candidate_blob, expected_outcome, fence, now) in [
        (
            results.as_slice(),
            None,
            outcome.version(),
            &fixture.fence,
            at + 24,
        ),
        (
            results.as_slice(),
            Some(&substituted),
            outcome.version(),
            &fixture.fence,
            at + 24,
        ),
        (
            wrong_results.as_slice(),
            Some(&blob),
            outcome.version(),
            &fixture.fence,
            at + 24,
        ),
        (
            results.as_slice(),
            Some(&blob),
            outcome.version() + 1,
            &fixture.fence,
            at + 24,
        ),
        (
            results.as_slice(),
            Some(&blob),
            outcome.version(),
            &wrong_fence,
            at + 24,
        ),
        (
            results.as_slice(),
            Some(&blob),
            outcome.version(),
            &fixture.fence,
            lease.expires_at_unix_ms(),
        ),
        (
            results.as_slice(),
            Some(&blob),
            outcome.version(),
            &fixture.fence,
            at,
        ),
    ] {
        assert!(fixture
            .outcomes
            .finalize_post_return_with_pure_results(
                operation_id,
                prepared.version(),
                candidate_results,
                &lease,
                &terminal,
                expected_outcome,
                &resolved,
                candidate_blob,
                fence,
                now,
            )
            .is_err());
        assert_eq!(
            fixture.authority.anchor_generation().expect("anchor"),
            generation
        );
        assert_eq!(commit_head(&fixture), head);
        assert_eq!(
            fixture
                .outcomes
                .lookup_post_return_evaluation(operation_id)
                .expect("evaluation after rejection"),
            Some(prepared.clone())
        );
        assert_eq!(
            fixture
                .outcomes
                .lookup_by_operation(operation_id)
                .expect("outcome after rejection"),
            Some(outcome.clone())
        );
        assert_eq!(
            fixture
                .outcomes
                .load_resolved_output_by_operation(operation_id)
                .expect("blob after rejection"),
            None
        );
    }
    fixture
        .outcomes
        .finalize_post_return_with_pure_results(
            operation_id,
            prepared.version(),
            &results,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fixture.fence,
            at + 25,
        )
        .expect("valid call after rejected candidates");
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        generation + 1
    );
}

#[test]
fn pure_finalization_cannot_substitute_for_an_external_step() {
    let fixture = fixture();
    let at = now_ms();
    let committed = committed(&fixture, "pure-finalization-external", at);
    let (operation, outcome) = record_return(&fixture, &committed, at + 20);
    let prepared = prepared_evaluation(&operation, &outcome, at + 22).expect("mixed plan");
    let lease = claim(&fixture, &operation, at + 22);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 23)
        .expect("begin mixed plan");
    let first = record_pure_step(&prepared).expect("pure step");
    let external = record_external_step(&first, at + 24).expect("authenticated external step");
    let (terminal, resolved, blob) =
        resolve_with_blob(&outcome, &external, SettlementDispositionV1::NotApplicable)
            .expect("resolve mixed plan");
    let generation = fixture.authority.anchor_generation().expect("anchor");
    let head = commit_head(&fixture);
    let results = [digest("pure_result", 'a'), digest("pure_result", 'b')];
    let error = fixture
        .outcomes
        .finalize_post_return_with_pure_results(
            operation.binding().operation_id(),
            prepared.version(),
            &results,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fixture.fence,
            at + 24,
        )
        .expect_err("external result cannot be represented by a pure digest");
    assert!(error
        .to_string()
        .contains("evaluation.next_step_is_not_pure"));
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        generation
    );
    assert_eq!(commit_head(&fixture), head);
    assert_eq!(
        fixture
            .outcomes
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .expect("retained mixed plan"),
        Some(prepared)
    );
}

#[test]
fn pure_finalization_resumes_a_durable_prefix_under_a_new_owner() {
    let fixture = fixture();
    let at = now_ms();
    let committed = committed(&fixture, "pure-finalization-prefix", at);
    let (operation, outcome) = record_return(&fixture, &committed, at + 20);
    let prepared =
        prepared_pure_evaluation(&operation, &outcome, at + 22).expect("pure evaluation");
    let lease = claim(&fixture, &operation, at + 22);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 23)
        .expect("begin evaluation");
    let first = prepared
        .record_next_pure_result(digest("pure_result", 'a'))
        .expect("first result");
    fixture
        .outcomes
        .stage_post_return_evaluation(
            operation.binding().operation_id(),
            prepared.version(),
            &lease,
            &first,
            &fixture.fence,
            at + 24,
        )
        .expect("persist ordinary prefix");
    let suffix = [digest("pure_result", 'b')];
    let second = first
        .record_next_pure_result(suffix[0].clone())
        .expect("second result");
    let (terminal, resolved, blob) =
        resolve_with_blob(&outcome, &second, SettlementDispositionV1::NotApplicable)
            .expect("resolve suffix");
    let database = fixture.database.clone();
    let locks = fixture.lock_root.clone();
    let Fixture {
        _temp,
        outcomes,
        operations,
        authority,
        ..
    } = fixture;
    drop(outcomes);
    drop(operations);
    drop(authority);
    let reopened =
        SqliteAuthorityStore::open_serving(&database, &locks).expect("new serving owner");
    let fence = reopened.mutation_fence();
    let outcomes = reopened.tool_outcome_store();
    let operation_id = operation.binding().operation_id();
    assert_eq!(
        outcomes
            .lookup_post_return_evaluation(operation_id)
            .expect("retained prefix"),
        Some(first.clone())
    );
    assert!(outcomes
        .finalize_post_return_with_pure_results(
            operation_id,
            first.version(),
            &suffix,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fence,
            at + 30,
        )
        .is_err());
    let claimant = id("claimant_id", "new-owner");
    let lease = reopened
        .admission_operation_store()
        .claim_recovery(
            operation_id,
            operation.version(),
            &claimant,
            at + 31,
            at + 60_000,
            &fence,
        )
        .expect("new owner recovery claim");
    let generation = reopened.anchor_generation().expect("anchor");
    outcomes
        .finalize_post_return_with_pure_results(
            operation_id,
            first.version(),
            &suffix,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fence,
            at + 32,
        )
        .expect("resume suffix under current owner");
    assert_eq!(
        reopened.anchor_generation().expect("anchor"),
        generation + 1
    );
    assert_eq!(
        outcomes
            .lookup_post_return_evaluation(operation_id)
            .expect("resolved evaluation"),
        Some(terminal)
    );
}
