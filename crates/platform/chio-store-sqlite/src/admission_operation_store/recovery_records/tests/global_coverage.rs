use super::super::{verify_global_coverage, verify_local_history, RecordKind};
use super::fixture::{assert_refused, Ledger, TestResult};

fn two_events(ledger: &mut Ledger) -> Result<[String; 2], Box<dyn std::error::Error>> {
    let first = ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    let second = ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":2}"#, None)?;
    ledger.install_global_commits()?;
    Ok([first.event_digest, second.event_digest])
}

#[test]
fn exactly_one_ordered_commit_per_event_verifies() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, second] = two_events(&mut ledger)?;
    ledger.commit(2, "deployment:a", 1, &first)?;
    ledger.commit(7, "deployment:a", 2, &second)?;
    verify_local_history(&ledger.connection)?;
    verify_global_coverage(&ledger.connection)?;
    Ok(())
}

#[test]
fn missing_global_catalog_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, b"{}", None)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery global commit catalog is absent",
    );
    Ok(())
}

#[test]
fn event_without_its_commit_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, _] = two_events(&mut ledger)?;
    ledger.commit(1, "deployment:a", 1, &first)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery event lacks its global commit",
    );
    Ok(())
}

#[test]
fn event_with_two_commits_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, second] = two_events(&mut ledger)?;
    ledger.commit(1, "deployment:a", 1, &first)?;
    ledger.commit(2, "deployment:a", 1, &first)?;
    ledger.commit(3, "deployment:a", 2, &second)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery event has duplicate global commits",
    );
    Ok(())
}

#[test]
fn commit_referencing_another_digest_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, _] = two_events(&mut ledger)?;
    ledger.commit(1, "deployment:a", 1, &first)?;
    ledger.commit(2, "deployment:a", 2, &first)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery global commit reference differs",
    );
    Ok(())
}

#[test]
fn commits_out_of_event_order_refuse() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, second] = two_events(&mut ledger)?;
    ledger.commit(5, "deployment:a", 1, &first)?;
    ledger.commit(3, "deployment:a", 2, &second)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery global commit order regressed",
    );
    Ok(())
}

#[test]
fn commit_without_its_event_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, second] = two_events(&mut ledger)?;
    ledger.commit(1, "deployment:a", 1, &first)?;
    ledger.commit(2, "deployment:a", 2, &second)?;
    ledger.commit(3, "deployment:a", 3, &second)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery global commit names an absent event",
    );
    Ok(())
}

#[test]
fn sole_commit_of_another_mutation_kind_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, second] = two_events(&mut ledger)?;
    ledger.commit_as("budget_transition", 1, "deployment:a", 1, &first)?;
    ledger.commit(2, "deployment:a", 2, &second)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery global commit mutation kind differs",
    );
    Ok(())
}

/// Every matching commit counts toward exclusive event ownership.
#[test]
fn wrong_kind_commit_beside_the_correct_commit_refuses() -> TestResult {
    let mut ledger = Ledger::new()?;
    let [first, second] = two_events(&mut ledger)?;
    ledger.commit(1, "deployment:a", 1, &first)?;
    ledger.commit_as("recovery_transition\0x", 2, "deployment:a", 1, &first)?;
    ledger.commit(3, "deployment:a", 2, &second)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery event has duplicate global commits",
    );
    Ok(())
}
