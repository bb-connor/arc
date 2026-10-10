#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_policy::conditions::{Condition, RuntimeContext, TimeWindowCondition};
use chio_policy::evaluate_condition;

fn context_at(time: &str) -> chio_security_types::clock::FixedClock {
    let millis = chrono::DateTime::parse_from_rfc3339(time)
        .unwrap_or_else(|error| panic!("fixture: {error}"))
        .timestamp_millis();
    chio_security_types::clock::FixedClock::from_millis(
        u64::try_from(millis).unwrap_or_else(|error| panic!("fixture: {error}")),
    )
}

fn window(start: &str, end: &str, days: &[&str]) -> Condition {
    Condition {
        time_window: Some(TimeWindowCondition {
            start: start.to_string(),
            end: end.to_string(),
            timezone: Some("UTC".to_string()),
            days: days.iter().map(|day| (*day).to_string()).collect(),
        }),
        ..Condition::default()
    }
}

#[test]
fn weekday_match_arms_cover_saturday_and_sunday() {
    assert!(evaluate_condition(
        &window("15:00", "16:00", &["sat"]),
        &RuntimeContext::default(),
        &context_at("2026-05-02T15:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));
    assert!(!evaluate_condition(
        &window("15:00", "16:00", &["fri"]),
        &RuntimeContext::default(),
        &context_at("2026-05-02T15:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));
    assert!(evaluate_condition(
        &window("15:00", "16:00", &["sun"]),
        &RuntimeContext::default(),
        &context_at("2026-05-03T15:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));
}

#[test]
fn midnight_wrap_uses_previous_effective_day_before_end_boundary() {
    assert!(evaluate_condition(
        &window("23:00", "01:00", &["sat"]),
        &RuntimeContext::default(),
        &context_at("2026-05-03T00:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));
    assert!(!evaluate_condition(
        &window("23:00", "01:00", &["sun"]),
        &RuntimeContext::default(),
        &context_at("2026-05-03T00:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));
}

#[test]
fn invalid_time_or_timezone_fails_closed() {
    let mut bad_time = window("24:00", "25:00", &[]);
    assert!(!evaluate_condition(
        &bad_time,
        &RuntimeContext::default(),
        &context_at("2026-05-02T15:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));

    if let Some(time_window) = bad_time.time_window.as_mut() {
        time_window.start = "15:00".to_string();
        time_window.end = "16:00".to_string();
        time_window.timezone = Some("Not/AZone".to_string());
    }
    assert!(!evaluate_condition(
        &bad_time,
        &RuntimeContext::default(),
        &context_at("2026-05-02T15:30:00Z")
    )
    .unwrap_or_else(|error| panic!("fixture: {error}")));
}
