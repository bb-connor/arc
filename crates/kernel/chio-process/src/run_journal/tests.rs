use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn observed(text: &str) -> WorkerOutcome {
    WorkerOutcome::Observed(ObservedReason(text.to_owned()))
}

#[test]
fn every_outcome_has_one_spelling_and_only_reason_tokens_parse() -> TestResult {
    for outcome in &JOURNAL_AUTHORED {
        // Adding a journal-authored variant fails here until it is listed.
        match outcome {
            WorkerOutcome::ProcessCancelled
            | WorkerOutcome::DependencyFailed
            | WorkerOutcome::HostInterrupted
            | WorkerOutcome::WorkerNotExecuted
            | WorkerOutcome::Suspended => {}
            WorkerOutcome::Observed(_) => return Err("observed in journal list".into()),
        }
        assert_eq!(&WorkerOutcome::parse(outcome.as_str())?, outcome);
    }
    for text in [
        "exit_0",
        "exit_-1",
        "container_state_unknown",
        &"x".repeat(64),
    ] {
        assert_eq!(WorkerOutcome::parse(text)?, observed(text));
    }
    for text in ["", "exit 1", "Exit_1", "exit_1\n", &"x".repeat(65)] {
        assert_eq!(
            WorkerOutcome::parse(text),
            Err(JournalError::Integrity),
            "{text:?}"
        );
    }
    assert_eq!(
        serde_json::to_value(WorkerOutcome::DependencyFailed)?,
        serde_json::json!("dependency_failed")
    );
    Ok(())
}

#[test]
fn invalid_budget_and_accounting_transitions_fail_closed() -> TestResult {
    let mut record = WorkerRecord::pending("worker".into());
    assert_eq!(
        record.transition(WorkerTransition::Start { max_attempts: 0 }, false),
        Err(JournalError::Transition)
    );
    record.attempts = u32::MAX;
    record.suspensions = 1;
    assert_eq!(
        record.transition(
            WorkerTransition::Start {
                max_attempts: u32::MAX
            },
            false
        ),
        Err(JournalError::Overflow)
    );
    record.attempts = 1;
    record.suspensions = 0;
    record.state = WorkerState::Running;
    assert_eq!(
        record.transition(WorkerTransition::Unreserve, true),
        Err(JournalError::Transition)
    );
    record.suspensions = 2;
    assert_eq!(
        record.transition(WorkerTransition::Recover { max_attempts: 1 }, false),
        Err(JournalError::Integrity)
    );
    Ok(())
}

fn finish(completion: Completion<'_>, usage: ResourceUsage) -> WorkerTransition<'_> {
    WorkerTransition::Finish {
        completion,
        max_attempts: 2,
        max_suspensions: 1,
        usage,
    }
}

#[test]
fn transitions_at_each_budget_boundary() -> TestResult {
    let (ok, exit_1, cancelled) = (observed("ok"), observed("exit_1"), observed("cancelled"));
    let running = |attempts, suspensions| WorkerRecord {
        state: WorkerState::Running,
        attempts,
        suspensions,
        outcome: Some(observed("stale")),
        ..WorkerRecord::pending("worker".into())
    };
    let none = ResourceUsage::default();
    let cases = [
        (
            running(1, 0),
            WorkerTransition::Recover { max_attempts: 2 },
            WorkerState::Pending,
        ),
        (
            running(2, 0),
            WorkerTransition::Recover { max_attempts: 2 },
            WorkerState::Failed,
        ),
        (
            running(1, 0),
            finish(Completion::Failed(&exit_1), none),
            WorkerState::Pending,
        ),
        (
            running(2, 0),
            finish(Completion::Failed(&exit_1), none),
            WorkerState::Failed,
        ),
        (
            running(2, 1),
            finish(Completion::Failed(&exit_1), none),
            WorkerState::Pending,
        ),
        (
            running(1, 0),
            finish(Completion::Suspended, none),
            WorkerState::Pending,
        ),
        (
            running(2, 1),
            finish(Completion::Suspended, none),
            WorkerState::Failed,
        ),
        (
            running(1, 0),
            finish(Completion::Terminal(&cancelled), none),
            WorkerState::Failed,
        ),
        (
            running(1, 0),
            WorkerTransition::Unreserve,
            WorkerState::Pending,
        ),
    ];
    for (record, transition, expected) in cases {
        assert_eq!(record.transition(transition, false)?.state, expected);
    }
    let pending = WorkerRecord::pending("worker".into());
    let started = pending.transition(WorkerTransition::Start { max_attempts: 1 }, false)?;
    assert_eq!((started.attempts, started.outcome), (1, None));
    for (record, transition) in [
        (pending.clone(), finish(Completion::Completed(&ok), none)),
        (pending.clone(), WorkerTransition::Unreserve),
        (running(1, 1), WorkerTransition::Unreserve),
        (running(1, 0), WorkerTransition::DependencyFailed),
        (running(1, 0), WorkerTransition::Start { max_attempts: 2 }),
    ] {
        assert_eq!(
            record.transition(transition, false),
            Err(JournalError::Transition)
        );
    }
    let saturated = WorkerRecord {
        cpu_ms: MAX_ACCOUNTED - 1,
        peak_resident_bytes: 7,
        ..running(1, 0)
    }
    .transition(
        finish(
            Completion::Completed(&ok),
            ResourceUsage {
                peak_resident_bytes: u64::MAX,
                cpu_ms: u64::MAX,
            },
        ),
        false,
    )?;
    assert_eq!(
        (saturated.cpu_ms, saturated.peak_resident_bytes),
        (MAX_ACCOUNTED, MAX_ACCOUNTED)
    );
    Ok(())
}

#[test]
fn container_binds_only_to_the_running_attempt() {
    let mut record = WorkerRecord::pending("worker".into());
    record.attempts = 2;
    assert_eq!(record.bind_container(2), Err(JournalError::ContainerIntent));
    record.state = WorkerState::Running;
    assert_eq!(record.bind_container(1), Err(JournalError::ContainerIntent));
    assert_eq!(record.bind_container(2), Ok(()));
}

#[test]
fn settlement_needs_a_running_parent_and_every_child_terminal() {
    let child = |process: &str, state| ChildOutcome {
        state,
        ..ChildOutcome::undiscovered(process.into())
    };
    let mut outcomes = vec![
        child("done", WorkerState::Completed),
        child("broken", WorkerState::Failed),
        ChildOutcome::undiscovered("late".into()),
    ];
    let running = Some(WorkerState::Running);
    for parent in [
        None,
        Some(WorkerState::Pending),
        Some(WorkerState::Completed),
    ] {
        assert_eq!(settle(parent, &outcomes), Err(JournalError::NotRunning));
    }
    assert_eq!(settle(running, &outcomes), Ok(None));
    outcomes[2].state = WorkerState::Running;
    assert_eq!(settle(running, &outcomes), Ok(None));
    outcomes[2].state = WorkerState::Failed;
    assert_eq!(settle(running, &outcomes), Ok(Some(vec!["broken", "late"])));
    assert_eq!(settle(running, &[]), Ok(Some(Vec::new())));
}

fn transition_strategy() -> impl proptest::strategy::Strategy<Value = (u8, u64, u64)> {
    (0_u8..8, proptest::num::u64::ANY, proptest::num::u64::ANY)
}

proptest::proptest! {
    #[test]
    fn accounting_and_budgets_hold_over_any_transition_sequence(
        steps in proptest::collection::vec(transition_strategy(), 0..64),
    ) {
        const MAX_ATTEMPTS: u32 = 3;
        let mut record = WorkerRecord::pending("worker".into());
        let (ok, exit_1, cancelled) = (observed("ok"), observed("exit_1"), observed("cancelled"));
        for (kind, peak, cpu) in steps {
            let usage = ResourceUsage { peak_resident_bytes: peak, cpu_ms: cpu };
            let completion = match peak % 4 {
                0 => Completion::Completed(&ok),
                1 => Completion::Suspended,
                2 => Completion::Failed(&exit_1),
                _ => Completion::Terminal(&cancelled),
            };
            let transition = match kind {
                0 => WorkerTransition::Start { max_attempts: MAX_ATTEMPTS },
                1 => WorkerTransition::CancelPending,
                2 => WorkerTransition::DependencyFailed,
                3 => WorkerTransition::Recover { max_attempts: MAX_ATTEMPTS },
                4 => WorkerTransition::Unreserve,
                _ => WorkerTransition::Finish {
                    completion,
                    max_attempts: MAX_ATTEMPTS,
                    max_suspensions: 2,
                    usage,
                },
            };
            let Ok(next) = record.transition(transition, false) else {
                continue;
            };
            proptest::prop_assert!(next.suspensions <= next.attempts);
            proptest::prop_assert!(next.attempts - next.suspensions <= MAX_ATTEMPTS);
            proptest::prop_assert!(next.suspensions <= 3);
            proptest::prop_assert!(next.cpu_ms >= record.cpu_ms && next.cpu_ms <= MAX_ACCOUNTED);
            proptest::prop_assert!(next.peak_resident_bytes >= record.peak_resident_bytes);
            if record.state.is_terminal() {
                proptest::prop_assert_eq!(next.state, record.state);
            }
            record = next;
        }
    }
}

#[test]
fn socket_history_holds_eight_abandoned_intents() {
    assert_eq!(next_abandoned_slot(1), Ok(2));
    assert_eq!(next_abandoned_slot(MAX_ABANDONED_SOCKET_INTENTS), Ok(9));
    assert_eq!(
        next_abandoned_slot(MAX_ABANDONED_SOCKET_INTENTS + 1),
        Err(JournalError::SocketHistoryFull)
    );
}

#[test]
fn worker_and_container_bounds_hold_at_the_edge() {
    assert_eq!(workers_within_capacity(MAX_WORKERS), Ok(()));
    assert_eq!(
        workers_within_capacity(MAX_WORKERS + 1),
        Err(JournalError::WorkerCapacity)
    );
    assert_eq!(container_intent_admissible(MAX_WORKERS - 1), Ok(()));
    assert_eq!(
        container_intent_admissible(MAX_WORKERS),
        Err(JournalError::ContainerCapacity)
    );
}
