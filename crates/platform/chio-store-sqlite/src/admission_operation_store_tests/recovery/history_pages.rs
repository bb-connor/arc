//! Recovery pages draw candidates from live work, never from retained terminal history.
use super::deferred_status::defer;
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionRecoveryPageQuery, AdmissionRecoveryPageV1,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const TERMINAL_HISTORY: usize = 32;

/// Each retained operation is driven through dispatch to a terminal outcome.
fn retain_terminal_history(
    fixture: &Fixture,
    label: &str,
    count: usize,
    from: u64,
) -> AnchoredTestResult<u64> {
    let mut at = from;
    for index in 0..count {
        let operation = finalizing_tool_operation(
            fixture,
            &format!("{label}-history-request-{index:03}"),
            &format!("{label}-history-capability-{index:03}"),
            at,
        );
        let projection = unknown_projection(
            fixture,
            &operation,
            &format!("{label}-history-incident-{index:03}"),
            'c',
            at + 20,
        );
        let terminal = fixture.store.commit_terminal_projection(&projection)?;
        assert_eq!(
            terminal.state,
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
        at += 40;
    }
    Ok(at)
}

fn page(
    fixture: &Fixture,
    now: u64,
    candidate_limit: usize,
    after: Option<&AdmissionOperationId>,
) -> AnchoredTestResult<AdmissionRecoveryPageV1> {
    Ok(fixture.store.recovery_page(AdmissionRecoveryPageQuery {
        not_after_unix_ms: now,
        candidate_limit,
        after_operation_id: after,
        fence: &fixture.fence,
    })?)
}

/// Counts SQLite virtual-machine steps on the store connection for one page.
fn counted_page(
    fixture: &Fixture,
    now: u64,
) -> AnchoredTestResult<(AdmissionRecoveryPageV1, usize)> {
    let steps = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&steps);
    fixture.store.connection()?.progress_handler(
        1,
        Some(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )?;
    let result = page(fixture, now, 16, None);
    fixture
        .store
        .connection()?
        .progress_handler(0, None::<fn() -> bool>)?;
    Ok((result?, steps.load(Ordering::Relaxed)))
}

#[test]
fn recovery_page_work_does_not_grow_with_retained_terminal_history() -> AnchoredTestResult {
    let at = 1_800_000_300_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let due = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "history-bound-due-request",
        "history-bound-due-capability",
    );
    fixture.store.begin(&due, &fixture.fence, at)?;
    let now = at + 10_000;

    let (before, before_steps) = counted_page(&fixture, now)?;
    assert_eq!(before.operations, vec![due.clone()]);
    assert_eq!(before.scanned_candidates, 1);
    assert_eq!(before.next_cursor, None);

    retain_terminal_history(&fixture, "bound", TERMINAL_HISTORY, at + 100)?;
    let (after, after_steps) = counted_page(&fixture, now)?;
    assert_eq!(after.operations, vec![due]);
    assert_eq!(after.scanned_candidates, 1);
    assert_eq!(after.next_cursor, None);
    assert!(
        after_steps.saturating_sub(before_steps) < TERMINAL_HISTORY,
        "a recovery page visited retained terminal rows: {before_steps} SQLite steps \
         before {TERMINAL_HISTORY} terminal operations, {after_steps} after"
    );
    Ok(())
}

#[test]
fn recovery_sweep_returns_each_due_operation_once_across_terminal_history() -> AnchoredTestResult {
    let at = 1_800_000_400_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let mut due = (0..5)
        .map(|index| {
            prepared_operation(
                &fixture.fence,
                AdmissionOperationKind::ToolDispatch,
                &format!("history-sweep-due-request-{index}"),
                &format!("history-sweep-due-capability-{index}"),
            )
        })
        .collect::<Vec<_>>();
    for operation in &due {
        fixture.store.begin(operation, &fixture.fence, at)?;
    }
    let backed_off = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "history-sweep-backed-off-request",
        "history-sweep-backed-off-capability",
    );
    fixture.store.begin(&backed_off, &fixture.fence, at)?;
    let next = retain_terminal_history(&fixture, "sweep", 12, at + 100)?;

    // A deferred operation that later reached a terminal state stays a
    // recovery candidate while its deferral is quarantined.
    let quarantined_terminal = finalizing_tool_operation(
        &fixture,
        "history-sweep-quarantined-terminal-request",
        "history-sweep-quarantined-terminal-capability",
        next,
    );
    // Each claim is taken only after the previous claimant's lease expires.
    let (_, status) = defer(&fixture, &quarantined_terminal, next + 10_100)?;
    let projection = unknown_projection(
        &fixture,
        &quarantined_terminal,
        "history-sweep-quarantined-terminal-incident",
        'c',
        next + 11_200,
    );
    fixture.store.commit_terminal_projection(&projection)?;
    let now = status.deferral.retry_not_before_unix_ms;
    defer(&fixture, &backed_off, next + 12_000)?;

    due.push(
        fixture
            .store
            .load_by_operation_id(quarantined_terminal.binding().operation_id())?
            .ok_or("quarantined terminal operation")?,
    );
    assert!(due
        .last()
        .is_some_and(|operation| operation.state().is_terminal()));
    due.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });

    let mut returned = Vec::new();
    let mut scanned = 0_usize;
    let mut pages = 0_usize;
    let mut cursor = None;
    loop {
        pages += 1;
        assert!(pages <= 8, "recovery sweep did not terminate");
        let current = page(&fixture, now, 2, cursor.as_ref())?;
        scanned += current.scanned_candidates;
        returned.extend(current.operations);
        match current.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(returned, due, "each due operation is returned exactly once");
    assert_eq!(
        scanned,
        due.len() + 1,
        "only live or quarantined operations occupy recovery candidates"
    );
    Ok(())
}
