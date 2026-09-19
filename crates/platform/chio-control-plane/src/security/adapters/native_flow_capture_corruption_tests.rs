// Corrupt actual committed history, independently of the callback fault seam.
use super::*;

#[test]
fn native_capture_physical_corruption_denies_readback_and_reopen() -> TestResult {
    let mutations = [
        (false, "UPDATE budget_mutation_events SET exposure_units = exposure_units + 1 WHERE event_id = ?1"),
        (false, "UPDATE budget_event_quota_members SET captured_after = 0 WHERE event_id = ?1"),
        (false, "DELETE FROM budget_event_quota_members WHERE event_id = ?1"),
        (true, "UPDATE authority_global_commits SET store_lease_id = 'foreign-owner' WHERE projection_kind = 'budget' AND projection_key = ?1"),
        (true, "DELETE FROM authority_global_commits WHERE projection_kind = 'budget' AND projection_key = ?1"),
        (true, "UPDATE authority_global_commits SET projection_key = printf('%01025d', 0) WHERE projection_kind = 'budget' AND projection_key = ?1"),
    ];
    for egress in [false, true] {
        for (global, mutation) in mutations {
            let mut fixture = super::super::super::public_fixture()?;
            let ledger = run_capture(&mut fixture, egress)?;
            let store = fixture.authority.admission_operation_store();
            let fence = fixture.authority.mutation_fence();
            let capture = store
                .load_native_dispatch_capture(&ledger.operation_id, &fence, now_ms()?)?
                .ok_or("uncorrupted capture readback")?;
            let chio_kernel::budget_store::BudgetInvocationCaptureDecision::Captured(decision) =
                &capture.decision
            else {
                return Err("fresh physical capture required".into());
            };
            let event_id = decision
                .metadata
                .event_id
                .as_deref()
                .ok_or("capture event")?;
            let database = fixture._directory.path().join("admission.db");
            {
                let connection = rusqlite::Connection::open(&database)?;
                // Offline corruption is not an authorized store mutation. Remove
                // only the two global-history guards when needed, and restore
                // their exact definitions before testing either read path.
                let guards = if global {
                    let mut statement = connection.prepare(
                        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name IN ('authority_global_commits_immutable', 'authority_global_commits_no_delete') ORDER BY name",
                    )?;
                    let guards = statement
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    assert_eq!(guards.len(), 2);
                    connection.execute_batch("DROP TRIGGER authority_global_commits_immutable; DROP TRIGGER authority_global_commits_no_delete;")?;
                    guards
                } else {
                    Vec::new()
                };
                assert_eq!(connection.execute(mutation, [event_id])?, 1, "{mutation}");
                for guard in guards {
                    connection.execute_batch(&guard)?;
                }
            }
            assert!(
                store
                    .load_native_dispatch_capture(&ledger.operation_id, &fence, now_ms()?)
                    .is_err(),
                "corrupt live readback succeeded: egress={egress}, {mutation}"
            );
            assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
            drop(store);
            let Fixture {
                kernel,
                authority,
                _directory,
                ..
            } = fixture;
            drop(kernel);
            drop(authority);
            assert!(
                SqliteAuthorityStore::open_serving(&database, _directory.path().join("locks"))
                    .is_err(),
                "corrupt owner reopen succeeded: egress={egress}, {mutation}"
            );
        }
    }
    Ok(())
}
