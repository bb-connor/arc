//! New native admissions are refused with a typed, retryable operator error
//! before the store-wide current-row budget, and admit again once finished
//! sessions leave. Each identity class keeps a measured number of rows.
use super::session_churn::{checkpoint, clock, finish, key, request, rows, session_rows, taint};
use super::*;
use chio_security_types::InformationLabel;

fn exhausted(error: &(dyn Error + 'static)) -> Option<String> {
    match error.downcast_ref::<AdmissionOperationStoreError>() {
        Some(AdmissionOperationStoreError::Unavailable(detail))
            if detail.starts_with("native security current-row capacity is exhausted: ") =>
        {
            Some(detail.clone())
        }
        _ => None,
    }
}

/// Admit and join one operation in a new session, leaving it unfinished.
fn admit(fixture: &Fixture, principal: &str, name: &str) -> AnchoredTestResult<Pending> {
    let label = taint("capacity")?;
    let identity = key(principal, "capacity-lineage", name)?;
    let (context, join) = request(name, &identity, &label, &label)?;
    pending_with(fixture, name, None, context, join)
}

#[test]
fn new_admissions_past_the_budget_refuse_typed_and_recover_after_session_churn(
) -> AnchoredTestResult {
    const HEAD_ROOM: u64 = 60;
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let budget = rows(&fixture)? + HEAD_ROOM;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        let mut admitted = Vec::new();
        let refusal = loop {
            // A new principal each time, so no single principal's share binds.
            let index = admitted.len();
            match admit(
                &fixture,
                &format!("churn-principal-{index}"),
                &format!("fill-{index}"),
            ) {
                Ok(pending) => admitted.push(pending),
                Err(error) => break error,
            }
            assert!(rows(&fixture)? <= budget);
            if admitted.len() > usize::try_from(HEAD_ROOM)? {
                return Err("new admissions were never refused".into());
            }
        };
        let detail = exhausted(refusal.as_ref()).ok_or_else(|| refusal.to_string())?;
        assert!(detail.contains("budget"), "{detail}");
        assert!(!admitted.is_empty());
        // Churn stops: the admitted operations finish and their sessions leave.
        for pending in &admitted {
            compensation::compensate(&fixture, pending)?;
        }
        checkpoint(&fixture)?;
        let first = key("churn-principal-0", "capacity-lineage", "fill-0")?;
        assert_eq!(session_rows(&fixture, &first)?, (0, 0, 0));
        // New admissions succeed again without a restart.
        let label = taint("capacity")?;
        let again = key("churn-principal", "capacity-lineage", "after-churn")?;
        finish(&fixture, "after-churn", &again, &label, &label)?;
        assert!(rows(&fixture)? <= budget);
        Ok(())
    })?;
    let fixture = reopen(fixture)?;
    let connection = fixture.store.connection()?;
    native::verify_all(&connection)?;
    native::verify_coverage(&connection)?;
    Ok(())
}

#[test]
fn identity_classes_keep_measured_current_rows() -> AnchoredTestResult {
    const ROOTS: u64 = 8;
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("measured")?;
    let only = taint("measured-session-only")?;
    let bottom = InformationLabel::bottom();
    let settle = |fixture: &Fixture| -> AnchoredTestResult<u64> {
        checkpoint(fixture)?;
        checkpoint(fixture)?;
        rows(fixture)
    };
    let first = key("measured-principal", "root-0", "session-0")?;
    finish(&fixture, "measured-0", &first, &label, &label)?;
    let before = settle(&fixture)?;
    // A finished session whose label its principal dominates keeps nothing.
    for index in 1..=ROOTS {
        let session = key("measured-principal", "root-0", &format!("session-{index}"))?;
        finish(
            &fixture,
            &format!("session-{index}"),
            &session,
            &label,
            &label,
        )?;
    }
    assert_eq!(settle(&fixture)?, before);
    // A session carrying taint its principal lacks keeps label, membership, context.
    let before = settle(&fixture)?;
    for index in 1..=ROOTS {
        let session = key("measured-principal", "root-0", &format!("only-{index}"))?;
        finish(&fixture, &format!("only-{index}"), &session, &bottom, &only)?;
    }
    assert_eq!(settle(&fixture)? - before, 3 * ROOTS);
    // A new lineage root of an existing principal keeps its lineage label and
    // its copied isolation epoch.
    let before = settle(&fixture)?;
    for index in 1..=ROOTS {
        let root = key(
            "measured-principal",
            &format!("root-{index}"),
            &format!("rooted-{index}"),
        )?;
        finish(&fixture, &format!("rooted-{index}"), &root, &label, &label)?;
    }
    assert_eq!(settle(&fixture)? - before, 2 * ROOTS);
    // A new principal on a new lineage root keeps its principal label, its
    // genesis epoch and the lineage label.
    let before = settle(&fixture)?;
    for index in 1..=ROOTS {
        let principal = key(
            &format!("measured-principal-{index}"),
            &format!("principal-root-{index}"),
            &format!("principal-session-{index}"),
        )?;
        finish(
            &fixture,
            &format!("principal-{index}"),
            &principal,
            &label,
            &label,
        )?;
    }
    assert_eq!(settle(&fixture)? - before, 3 * ROOTS);
    Ok(())
}
