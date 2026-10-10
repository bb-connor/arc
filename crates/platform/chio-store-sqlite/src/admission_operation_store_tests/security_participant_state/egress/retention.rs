//! Finished native invocations stop occupying the current-row budget, while
//! live custody and replay evidence remain bounded and authenticated.
use super::*;
use std::collections::BTreeSet;

/// Head room above the steady state. Automatic maintenance seals the suffix
/// every twenty events, and one invocation appends three (join, acquire,
/// commit) while creating one transition row and one fence row.
const MARGIN: u64 = 24;
/// Over twice the head room in finished rows: far beyond anything the budget could
/// hold if finished invocations kept their current rows.
const INVOCATIONS: usize = 32;

fn native_rows(fixture: &Fixture) -> AnchoredTestResult<u64> {
    let connection = fixture.store.connection()?;
    let mut total = 0_u64;
    for table in native::schema::TABLES {
        let count: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM {}", table.native),
            [],
            |row| row.get(0),
        )?;
        total = total
            .checked_add(u64::try_from(count)?)
            .ok_or("native row total overflow")?;
    }
    Ok(total)
}

/// Every current transition and fence identity, as (table, tenant, identifier).
fn identities(fixture: &Fixture) -> AnchoredTestResult<BTreeSet<(String, String, String)>> {
    let connection = fixture.store.connection()?;
    let mut statement = connection.prepare(
        "SELECT 'transition', tenant_id, transition_id FROM security_participant_state_transitions
         UNION ALL SELECT 'fence', tenant_id, fence_id FROM security_participant_state_egress_fences",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(rows)
}

fn sealed(fixture: &Fixture) -> AnchoredTestResult<i64> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_checkpoint_events",
        [],
        |row| row.get(0),
    )?)
}

fn initialization(fixture: &Fixture) -> AnchoredTestResult<SecurityParticipantStateInitialization> {
    Ok(fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("native initialization absent")?)
}

/// The trusted host's per-evaluation maintenance tick, as the kernel runs it.
fn maintenance_tick(fixture: &Fixture) -> AnchoredTestResult {
    let binding = initialization(fixture)?.admission_binding()?;
    fixture
        .store
        .checkpoint_native_security_history_if_due(&binding, &fixture.fence, now_ms())?;
    Ok(())
}

/// The typed, retryable store-wide capacity refusal.
fn capacity_refused(error: &(dyn Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<AdmissionOperationStoreError>(),
        Some(AdmissionOperationStoreError::Unavailable(detail))
            if detail.starts_with("native security current-row capacity is exhausted: ")
    )
}

struct Finished {
    pending: Pending,
    fence: EgressFence,
    commitment: EgressFenceCommit,
    committed: CommittedEgressFence,
}

/// One complete native egress invocation preceded by the maintenance tick.
fn invoke(fixture: &Fixture, name: &str, generation: Option<u64>) -> AnchoredTestResult<Finished> {
    maintenance_tick(fixture)?;
    let pending = pending(fixture, name, generation)?;
    let fence = pending.acquire(fixture)?;
    let commitment = commitment(&fence)?;
    let committed = pending.commit(fixture, &commitment)?;
    Ok(Finished {
        pending,
        fence,
        commitment,
        committed,
    })
}

#[test]
fn automatic_maintenance_keeps_sustained_native_calls_within_current_row_budget(
) -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let imported = identities(&fixture)?;
    assert!(!imported.is_empty());
    let mut first = invoke(&fixture, "retention-0", None)?;
    let mut generation = first.fence.context_generation;
    let budget = native_rows(&fixture)? + MARGIN;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        for index in 1..=INVOCATIONS {
            let finished = invoke(&fixture, &format!("retention-{index}"), Some(generation))
                .map_err(|error| {
                    format!("native invocation {index} under a {budget}-row budget: {error}")
                })?;
            generation = finished.fence.context_generation;
            // A sustained call finishes, releasing its reserved completion rows;
            // only the first stays open for the retry checks below.
            compensation::compensate(&fixture, &finished.pending)?;
            assert!(native_rows(&fixture)? <= budget);
        }
        // No operator call: the per-evaluation tick sealed every segment.
        assert!(sealed(&fixture)? >= 2);
        // Recorded retries return history after their current rows left.
        first.pending.lease = renew(&fixture, &first.pending.operation, &first.pending.lease)?;
        let identities = identities(&fixture)?;
        assert!(!identities.contains(&(
            "fence".into(),
            first.fence.key.tenant_id.as_str().into(),
            first.fence.fence_id.as_str().into(),
        )));
        assert_eq!(first.pending.acquire(&fixture)?, first.fence);
        assert_eq!(
            first.pending.commit(&fixture, &first.commitment)?,
            first.committed
        );
        Ok(())
    })?;
    // Imported identities are never compacted.
    assert!(imported.is_subset(&identities(&fixture)?));
    let fixture = reopen(fixture)?;
    {
        let connection = fixture.store.connection()?;
        native::verify_all(&connection)?;
        native::verify_coverage(&connection)?;
    }
    fixture.store.checkpoint_security_participant_history(
        &initialization(&fixture)?,
        &fixture.fence,
        now_ms(),
    )?;
    let fixture = reopen(fixture)?;
    invoke(&fixture, "retention-reopened", Some(generation))?;
    assert!(imported.is_subset(&identities(&fixture)?));
    Ok(())
}

#[test]
fn live_pending_fences_beyond_current_row_budget_remain_refused() -> AnchoredTestResult {
    // Room for a few live operations, each holding eight reserved completion rows.
    const LIVE_MARGIN: u64 = 40;
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut generation = invoke(&fixture, "live-0", None)?.fence.context_generation;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let budget = native_rows(&fixture)? + LIVE_MARGIN;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        let mut live = Vec::new();
        let refusal = loop {
            // Operator maintenance before every call cannot release live custody.
            fixture.store.checkpoint_security_participant_history(
                &initialized,
                &fixture.fence,
                now_ms(),
            )?;
            let index = live.len() + 1;
            let pending = match pending(&fixture, &format!("live-{index}"), Some(generation)) {
                Ok(pending) => pending,
                Err(error) => break error,
            };
            // The join committed even when acquisition is refused.
            generation = pending.plan.expected_context_generation;
            match pending.acquire(&fixture) {
                Ok(fence) => live.push(fence),
                Err(error) => break error,
            }
            if live.len() > 2 * usize::try_from(LIVE_MARGIN)? {
                return Err("live pending fences exceeded the current-row budget".into());
            }
        };
        assert!(capacity_refused(refusal.as_ref()), "{refusal}");
        assert!(!live.is_empty());
        fixture.store.checkpoint_security_participant_history(
            &initialized,
            &fixture.fence,
            now_ms(),
        )?;
        let connection = fixture.store.connection()?;
        for fence in &live {
            let pending: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_egress_fences
                 WHERE fence_id = ?1 AND dispatch_commitment_id IS NULL AND committed_at IS NULL)",
                [fence.fence_id.as_str()],
                |row| row.get(0),
            )?;
            assert!(pending, "maintenance released live custody");
        }
        drop(connection);
        let retry = pending(&fixture, "live-retry", Some(generation))
            .and_then(|pending| pending.acquire(&fixture));
        assert!(
            retry
                .as_ref()
                .is_err_and(|error| capacity_refused(error.as_ref())),
            "live state beyond the budget was admitted"
        );
        assert!(native_rows(&fixture)? <= budget);
        Ok(())
    })
}

#[test]
fn expired_pending_fence_compacts_and_cannot_be_committed() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut pending = pending(&fixture, "expiring", None)?;
    pending.plan.expires_at_unix_ms = now_ms() + 1_500;
    let fence = pending.acquire(&fixture)?;
    while now_ms() <= fence.expires_at_unix_ms + 50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let identity = (
        "fence".to_owned(),
        fence.key.tenant_id.as_str().to_owned(),
        fence.fence_id.as_str().to_owned(),
    );
    assert!(!identities(&fixture)?.contains(&identity));
    assert!(native::fence_occupied(
        &*fixture.store.connection()?,
        initialized.security_authority_id().as_str(),
        fence.key.tenant_id.as_str(),
        fence.request_id.as_str(),
        fence.fence_id.as_str(),
    )?);
    assert_eq!(pending.acquire(&fixture)?, fence);
    let before = counts(&fixture)?;
    let late = EgressFenceCommit {
        fence: fence.clone(),
        dispatch_commitment_id: RecordId::new("native-egress-dispatch")?,
        committed_at_unix_ms: fence.expires_at_unix_ms,
    };
    // The compacted fence is absent, so no commitment can revive it.
    assert!(pending
        .commit(&fixture, &late)
        .is_err_and(|error| error.to_string().contains("store.invalid_data")));
    assert_eq!(counts(&fixture)?, before);
    let fixture = reopen(fixture)?;
    native::verify_all(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn compacted_join_identity_keeps_replay_refusal_and_recorded_retry() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, join) = mutations::request("compacted-join")?;
    let (operation, lease) = mutations::setup(&fixture, "compacted-join-operation", &context)?;
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &join,
        now_ms(),
    )?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let identity = (
        "transition".to_owned(),
        join.key.tenant_id.as_str().to_owned(),
        join.transition_id.as_str().to_owned(),
    );
    assert!(!identities(&fixture)?.contains(&identity));
    assert!(native::transition_occupied(
        &*fixture.store.connection()?,
        initialized.security_authority_id().as_str(),
        join.key.tenant_id.as_str(),
        join.transition_id.as_str(),
    )?);
    assert_eq!(
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &join,
            now_ms(),
        )?,
        joined
    );
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(joined.context_generation),
    );
    let (other, other_lease) = mutations::setup(&fixture, "compacted-join-reuse", &context)?;
    let before = joins(&fixture)?;
    let refused = fixture.store.join_security_participant_flow(
        &other,
        &other_lease,
        &initialized,
        &context,
        &join,
        now_ms(),
    );
    assert!(
        refused.as_ref().is_err_and(|error| error
            .to_string()
            .contains("native transition belongs to another operation or imported history")),
        "a compacted transition identifier was claimed again"
    );
    assert_eq!(joins(&fixture)?, before);
    assert!(!identities(&fixture)?.contains(&identity));
    Ok(())
}

#[test]
fn failure_after_compaction_restores_rows_anchor_and_denying_callbacks() -> AnchoredTestResult {
    let _reset = ResetCutpoint;
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let finished = invoke(&fixture, "rollback", None)?;
    let rows = identities(&fixture)?;
    let anchor: (i64, String) = fixture.store.connection()?.query_row(
        "SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    // Stage 70 follows the deletes, inside the snapshot copy.
    FAIL_AFTER.set(70);
    let failed = fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    );
    FAIL_AFTER.set(0);
    assert!(failed.is_err_and(|error| error
        .to_string()
        .contains("injected native hydration failure")));
    assert_eq!(identities(&fixture)?, rows);
    assert_eq!(sealed(&fixture)?, 0);
    {
        let connection = fixture.store.connection()?;
        let after: (i64, String) = connection.query_row(
            "SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(after, anchor);
        // No compaction custody survives: the native triggers deny again.
        let denied = connection.execute(
            "DELETE FROM security_participant_state_transitions WHERE transition_kind = 'flow_join'",
            [],
        );
        assert!(
            denied.as_ref().is_err_and(|error| error
                .to_string()
                .contains("native security state lacks operation custody")),
            "{denied:?}"
        );
    }
    assert_eq!(identities(&fixture)?, rows);
    initialization(&fixture)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let compacted = identities(&fixture)?;
    assert_eq!(rows.difference(&compacted).count(), 2);
    assert!(!compacted.contains(&(
        "fence".into(),
        finished.fence.key.tenant_id.as_str().into(),
        finished.fence.fence_id.as_str().into(),
    )));
    let fixture = reopen(fixture)?;
    native::verify_all(&*fixture.store.connection()?)?;
    Ok(())
}

/// Family journal and checkpoint event counts.
fn journals(fixture: &Fixture) -> AnchoredTestResult<(i64, i64, i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM security_participant_state_mutations),
            (SELECT COUNT(*) FROM security_participant_egress_events),
            (SELECT COUNT(*) FROM security_participant_output_events),
            (SELECT COUNT(*) FROM security_participant_nonce_preflight_events),
            (SELECT COUNT(*) FROM security_participant_checkpoint_events)",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?)
}

/// Pending fences left to expire under the sealed full head.
const LIVE_FENCES: u64 = 10;

#[test]
fn expiry_under_a_sealed_full_head_is_recovered_by_either_maintenance_path() -> AnchoredTestResult {
    for automatic in [true, false] {
        let _start = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let maintain = |fixture: &Fixture| -> AnchoredTestResult<Option<AdmissionDigest>> {
            if automatic {
                Ok(fixture.store.checkpoint_native_security_history_if_due(
                    &initialized.admission_binding()?,
                    &fixture.fence,
                    now_ms(),
                )?)
            } else {
                Ok(Some(
                    fixture.store.checkpoint_security_participant_history(
                        &initialized,
                        &fixture.fence,
                        now_ms(),
                    )?,
                ))
            }
        };
        let first = invoke(&fixture, "sealed-0", None)?;
        let mut generation = first.fence.context_generation;
        let mut live = Vec::new();
        // Their release must cover the next invocation's join and fence rows
        // and its eight reserved completion rows.
        for index in 1..=LIVE_FENCES {
            let pending = pending(&fixture, &format!("sealed-{index}"), Some(generation))?;
            generation = pending.plan.expected_context_generation;
            let fence = pending.acquire(&fixture)?;
            live.push((pending, fence));
        }
        let digest = fixture.store.checkpoint_security_participant_history(
            &initialized,
            &fixture.fence,
            now_ms(),
        )?;
        let full = native_rows(&fixture)?;
        native::with_test_current_rows(full, || -> AnchoredTestResult {
            // The sealed head is full: a new command is refused before any event.
            let journal = journals(&fixture)?;
            let refused = pending(&fixture, "sealed-refused", Some(generation));
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|error| capacity_refused(error.as_ref())),
                "a command was admitted beyond the current-row budget"
            );
            assert_eq!(journals(&fixture)?, journal);
            // Nothing is dead yet, so maintenance stays an idempotent no-op.
            assert_eq!(
                maintain(&fixture)?,
                if automatic {
                    None
                } else {
                    Some(digest.clone())
                }
            );
            assert_eq!(journals(&fixture)?, journal);
            Ok(())
        })?;
        // Advance past every pending fence's expiry without any new event.
        let expired = live
            .iter()
            .map(|(_, fence)| fence.expires_at_unix_ms)
            .max()
            .ok_or("live fences absent")?
            .div_ceil(1_000);
        let _expired = chio_test_support::clock::scope_unix_secs(expired);
        native::with_test_current_rows(full, || -> AnchoredTestResult {
            let journal = journals(&fixture)?;
            let sealed = maintain(&fixture)?.ok_or("maintenance stranded expired fences")?;
            assert_ne!(sealed, digest);
            // Only one checkpoint event: no family journal or identity authority.
            assert_eq!(
                journals(&fixture)?,
                (journal.0, journal.1, journal.2, journal.3, journal.4 + 1)
            );
            assert_eq!(native_rows(&fixture)?, full - LIVE_FENCES);
            let journal = journals(&fixture)?;
            for (pending, fence) in &live {
                assert!(!identities(&fixture)?.contains(&(
                    "fence".into(),
                    fence.key.tenant_id.as_str().into(),
                    fence.fence_id.as_str().into(),
                )));
                assert!(native::fence_occupied(
                    &*fixture.store.connection()?,
                    initialized.security_authority_id().as_str(),
                    fence.key.tenant_id.as_str(),
                    fence.request_id.as_str(),
                    fence.fence_id.as_str(),
                )?);
                // History stays readable but never becomes fresh custody.
                assert_eq!(pending.acquire(&fixture)?, *fence);
                let late = EgressFenceCommit {
                    fence: fence.clone(),
                    dispatch_commitment_id: RecordId::new("native-egress-dispatch")?,
                    committed_at_unix_ms: fence.expires_at_unix_ms,
                };
                // The compacted fence is absent, so no commitment can revive it.
                assert!(pending
                    .commit(&fixture, &late)
                    .is_err_and(|error| error.to_string().contains("store.invalid_data")));
            }
            assert_eq!(journals(&fixture)?, journal);
            // The expired operations can never commit; they finish and release
            // their reserved rows. Recovered capacity admits the next invocation.
            compensation::compensate(&fixture, &first.pending)?;
            for (pending, _) in &live {
                compensation::compensate(&fixture, pending)?;
            }
            invoke(&fixture, "sealed-recovered", Some(generation))?;
            Ok(())
        })?;
        let fixture = reopen(fixture)?;
        native::verify_all(&*fixture.store.connection()?)?;
    }
    Ok(())
}
