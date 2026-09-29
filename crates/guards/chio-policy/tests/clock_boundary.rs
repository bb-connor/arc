#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_policy::conditions::TimeWindowCondition;
use chio_policy::evaluate::{Decision, EvaluationAction};
use chio_policy::models::HushSpec;
use chio_policy::{
    evaluate_audited, evaluate_condition, evaluate_with_context, AuditConfig, Condition,
    RuntimeContext,
};
use chio_security_types::clock::{
    Clock, ClockError, ClockReading, FixedClock, MonotonicInstant, UnixMillis,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

struct SequenceClock(Mutex<VecDeque<Result<ClockReading, ClockError>>>);
impl Clock for SequenceClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .expect("only expected clock reads")
    }
}
fn reading(wall: u64, monotonic: u64) -> Result<ClockReading, ClockError> {
    Ok(ClockReading::new(
        UnixMillis::new(wall),
        MonotonicInstant::from_nanos(monotonic),
    ))
}
fn window() -> Condition {
    Condition {
        time_window: Some(TimeWindowCondition {
            start: "09:00".into(),
            end: "17:00".into(),
            timezone: Some("UTC".into()),
            days: vec![],
        }),
        ..Condition::default()
    }
}
fn policy() -> HushSpec {
    serde_json::from_value(serde_json::json!({"hushspec":"0.1.0", "rules":{"tool_access":{"allow":["echo"],"default":"block"}}})).unwrap()
}
fn action() -> EvaluationAction {
    EvaluationAction {
        action_type: "tool_call".into(),
        target: Some("echo".into()),
        ..EvaluationAction::default()
    }
}
#[test]
fn clock_failure_cannot_be_negated_or_short_circuited_into_permission() {
    let conditions = [
        Condition {
            not: Some(Box::new(window())),
            ..Condition::default()
        },
        Condition {
            any_of: Some(vec![Condition::default(), window()]),
            ..Condition::default()
        },
    ];
    for condition in conditions {
        let clock = SequenceClock(Mutex::new(VecDeque::from([Err(ClockError::Unavailable)])));
        assert_eq!(
            evaluate_condition(&condition, &RuntimeContext::default(), &clock),
            Err(ClockError::Unavailable)
        );
    }
}
#[test]
fn rule_filtering_requires_one_successful_clock_observation() {
    let conditions = HashMap::from([("tool_access".into(), window())]);
    let failure = SequenceClock(Mutex::new(VecDeque::from([Err(ClockError::BeforeEpoch)])));
    assert_eq!(
        evaluate_with_context(
            &policy(),
            &action(),
            &RuntimeContext::default(),
            &conditions,
            &failure
        ),
        Err(ClockError::BeforeEpoch)
    );
    let clock = SequenceClock(Mutex::new(VecDeque::from([reading(1_776_254_400_000, 0)])));
    assert_eq!(
        evaluate_with_context(
            &policy(),
            &action(),
            &RuntimeContext::default(),
            &conditions,
            &clock
        )
        .unwrap()
        .decision,
        Decision::Allow
    );
    assert!(clock.0.lock().unwrap().is_empty());
}
#[test]
fn audit_refuses_faults_regressions_and_unrepresentable_timestamps() {
    for (samples, expected) in [
        (vec![Err(ClockError::Unavailable)], ClockError::Unavailable),
        (
            vec![reading(1000, 100), reading(999, 200)],
            ClockError::WallClockRegression,
        ),
        (
            vec![reading(1000, 100), reading(1001, 99)],
            ClockError::MonotonicRegression,
        ),
        (
            vec![reading(1000, 100), Err(ClockError::Unavailable)],
            ClockError::Unavailable,
        ),
        (vec![reading(u64::MAX, 0)], ClockError::Overflow),
    ] {
        let clock = SequenceClock(Mutex::new(samples.into()));
        assert_eq!(
            evaluate_audited(&policy(), &action(), &AuditConfig::default(), &clock),
            Err(expected)
        );
    }
    let failed = SequenceClock(Mutex::new(VecDeque::from([Err(ClockError::Unavailable)])));
    assert_eq!(
        evaluate_audited(
            &policy(),
            &action(),
            &AuditConfig {
                enabled: false,
                redact_content: true
            },
            &failed
        ),
        Err(ClockError::Unavailable)
    );
    let receipt = evaluate_audited(
        &policy(),
        &action(),
        &AuditConfig::default(),
        &FixedClock::from_millis(1234),
    )
    .unwrap();
    assert_eq!(receipt.timestamp, "1970-01-01T00:00:01.234Z");
    assert_eq!(receipt.evaluation_duration_us, 0);
}

#[test]
fn runtime_context_rejects_removed_clock_override() {
    let error =
        serde_json::from_str::<RuntimeContext>(r#"{"current_time":"2026-01-01T00:00:00Z"}"#)
            .unwrap_err();
    assert!(error.to_string().contains("unknown field `current_time`"));
}
