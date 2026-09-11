use super::*;
use std::sync::Barrier;

#[test]
fn two_operations_racing_for_one_replay_key_leave_one_physical_owner() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let domain = activate(&fixture, &source)?;
    let mut contenders = Vec::new();
    for name in ["racer-one", "racer-two"] {
        let (operation, lease, credential) = setup(
            &fixture,
            &domain,
            name,
            "shared-nonce",
            DpopReplayClaimPhase::Dispatch,
        )?;
        let intent = candidate(&operation, name, credential, DpopReplayClaimPhase::Dispatch)?;
        contenders.push((operation, lease, intent));
    }
    // This exercises concurrent clients of one serving owner, not independent
    // process crash safety or multiple simultaneous serving-owner authority.
    let barrier = Arc::new(Barrier::new(3));
    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = contenders
            .into_iter()
            .map(|(operation, lease, intent)| {
                let store = fixture.store.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    store.claim_dpop_replay(&operation, &lease, &intent, now_ms())
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("claim worker panicked"))
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let error = outcomes
        .into_iter()
        .find_map(Result::err)
        .ok_or("missing losing claimant")?;
    assert!(
        error
            .to_string()
            .contains("already owned or historically spent"),
        "{error}"
    );
    let connection = fixture.store.connection()?;
    for table in ["dpop_replay_claim_episodes", "dpop_replay_claim_resources"] {
        assert_eq!(
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))?,
            1
        );
    }
    verify_admission_operation_invariants(&connection)?;
    Ok(())
}
