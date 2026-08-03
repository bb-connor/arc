pub(crate) fn budget_invocation_quota_usage_record_from_view(
    record: &BudgetInvocationQuotaUsageRecordView,
) -> Result<BudgetInvocationQuotaUsageRecord, CliError> {
    let usage = BudgetInvocationQuotaUsage {
        quota: service_runtime::budget::invocation_quota_from_view(&record.usage.quota)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        reserved_invocations_after: record.usage.reserved_invocations_after,
        captured_invocations_after: record.usage.captured_invocations_after,
    };
    let record = BudgetInvocationQuotaUsageRecord {
        usage,
        updated_at: record.updated_at,
        seq: record.seq,
    };
    record
        .validate_compatibility_projection()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(record)
}

pub(crate) fn budget_cursor_from_event(event: &BudgetMutationEventView) -> BudgetCursor {
    BudgetCursor {
        seq: event.event_seq,
        updated_at: event.recorded_at,
        capability_id: event.capability_id.clone(),
        grant_index: event.grant_index,
    }
}

pub(crate) fn merge_budget_cursor(
    current: Option<BudgetCursor>,
    candidate: BudgetCursor,
) -> BudgetCursor {
    match current {
        Some(existing)
            if existing.seq > candidate.seq
                || (existing.seq == candidate.seq
                    && existing.updated_at >= candidate.updated_at) =>
        {
            existing
        }
        _ => candidate,
    }
}

fn budget_event_authority_from_view(
    authority: &BudgetMutationAuthorityView,
) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority.authority_id.clone(),
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    }
}

pub(crate) fn budget_mutation_record_from_view(
    event: &BudgetMutationEventView,
) -> Result<BudgetMutationRecord, CliError> {
    let admission_operation = super::super::budget_handlers::budget_admission_operation_binding(
        event.operation_id.as_deref(),
        event.request_binding_hash.as_deref(),
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let kind = BudgetMutationKind::parse(&event.kind).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "unknown budget mutation kind `{}` in cluster snapshot",
            event.kind
        ))
    })?;
    let invocation_state = match event.invocation_state {
        BudgetInvocationReservationStateView::Absent => BudgetInvocationReservationState::Absent,
        BudgetInvocationReservationStateView::Authorized => {
            BudgetInvocationReservationState::Authorized
        }
        BudgetInvocationReservationStateView::Captured => {
            BudgetInvocationReservationState::Captured
        }
        BudgetInvocationReservationStateView::Reversed => {
            BudgetInvocationReservationState::Reversed
        }
        BudgetInvocationReservationStateView::Denied => BudgetInvocationReservationState::Denied,
    };
    let monetary_state = match event.monetary_state {
        BudgetMonetaryHoldStateView::None => BudgetMonetaryHoldState::None,
        BudgetMonetaryHoldStateView::Exposed => BudgetMonetaryHoldState::Exposed,
        BudgetMonetaryHoldStateView::Released => BudgetMonetaryHoldState::Released,
        BudgetMonetaryHoldStateView::Reconciled => BudgetMonetaryHoldState::Reconciled,
        BudgetMonetaryHoldStateView::Captured => BudgetMonetaryHoldState::Captured,
        BudgetMonetaryHoldStateView::Reversed => BudgetMonetaryHoldState::Reversed,
    };
    let invocation_counts_after = event
        .invocation_counts_after
        .iter()
        .map(|usage| {
            let usage = BudgetInvocationQuotaUsage {
                quota: service_runtime::budget::invocation_quota_from_view(&usage.quota)
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                reserved_invocations_after: usage.reserved_invocations_after,
                captured_invocations_after: usage.captured_invocations_after,
            };
            usage
                .validate()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            Ok(usage)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let revocation_set = event
        .revocation_set
        .as_ref()
        .map(service_runtime::budget::canonical_revocation_set_from_view)
        .transpose()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    Ok(BudgetMutationRecord {
        event_id: event.event_id.clone(),
        hold_id: event.hold_id.clone(),
        admission_operation,
        capability_id: event.capability_id.clone(),
        grant_index: event.grant_index,
        kind,
        allowed: event.allowed,
        recorded_at: event.recorded_at,
        event_seq: event.event_seq,
        usage_seq: event.usage_seq,
        exposure_units: event.exposure_units,
        realized_spend_units: event.realized_spend_units,
        max_invocations: event.max_invocations,
        max_cost_per_invocation: event.max_cost_per_invocation,
        max_total_cost_units: event.max_total_cost_units,
        invocation_count_after: event.invocation_count_after,
        invocation_counts_after,
        invocation_state,
        monetary_state,
        revocation_set,
        total_cost_exposed_after: event.total_cost_exposed_after,
        total_cost_realized_spend_after: event.total_cost_realized_spend_after,
        authority: event
            .authority
            .as_ref()
            .map(budget_event_authority_from_view),
    })
}

#[cfg(test)]
mod budget_write_authority_tests {
    use super::{budget_write_matches_live_authority, BudgetEventAuthority, BudgetWriteToken};

    #[test]
    fn quorum_write_requires_the_same_live_authority_and_term() {
        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 42,
            budget_term: 7,
        };
        let matching = BudgetEventAuthority {
            authority_id: "http://node-a".to_string(),
            lease_id: "http://node-a#term-7".to_string(),
            lease_epoch: 7,
        };
        assert!(budget_write_matches_live_authority(&write, Some(&matching)));
        assert!(!budget_write_matches_live_authority(&write, None));

        let next_term = BudgetEventAuthority {
            authority_id: "http://node-a".to_string(),
            lease_id: "http://node-a#term-8".to_string(),
            lease_epoch: 8,
        };
        assert!(!budget_write_matches_live_authority(
            &write,
            Some(&next_term)
        ));

        let next_leader = BudgetEventAuthority {
            authority_id: "http://node-b".to_string(),
            lease_id: "http://node-b#term-7".to_string(),
            lease_epoch: 7,
        };
        assert!(!budget_write_matches_live_authority(
            &write,
            Some(&next_leader)
        ));
    }
}

#[cfg(test)]
mod capability_revocation_lag_tests {
    use super::observe_capability_revocation_lag;

    fn lag_count() -> u64 {
        let mut rendered = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut rendered);
        rendered
            .lines()
            .find(|line| {
                line.starts_with(
                    "chio_capability_revocation_lag_seconds_count{authority=\"control_plane\"}",
                )
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// A capability revoke path observes the capability-revocation lag family, so
    /// a backdated (propagated) revoke advances the SLO histogram.
    #[test]
    fn capability_revoke_observes_revocation_lag() {
        let before = lag_count();
        // Backdate the revoke instant by 45 seconds relative to now.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        observe_capability_revocation_lag(now.saturating_sub(45));
        assert!(
            lag_count() > before,
            "a capability revoke must observe a capability-revocation lag sample"
        );
    }
}

#[cfg(test)]
mod deltas_tests {
    use super::*;
    use chio_test_support::plain::{TestResultErr, TestResultOk};
    use std::time::Duration;

    #[test]
    fn peer_round_stops_visiting_when_shutdown_fires_midround() {
        // A stop signal that lands while a sync round is partway through its peers
        // must halt the round at the current peer rather than dialing every
        // remaining peer (each up to CONTROL_HTTP_TIMEOUT) before the loop can
        // observe shutdown and exit.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let peers = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let mut visited = Vec::new();
        visit_peers_until_shutdown(&peers, &rx, |peer_url| {
            visited.push(peer_url.to_string());
            if visited.len() == 2 {
                let _ = tx.send(true);
            }
        });
        assert_eq!(
            visited,
            vec!["a".to_string(), "b".to_string()],
            "the round must stop at the peer where shutdown fired, not finish the peer list"
        );
    }

    #[test]
    fn budget_pull_is_prioritized_first() {
        // Budget replication is pulled FIRST so a receipt/lineage backlog cannot
        // spend the shared round budget and starve the quorum-critical budget pull.
        assert_eq!(
            peer_pullers()[0] as usize,
            sync_peer_budgets as Puller as usize,
            "the budget pull must run first in the per-peer pull order"
        );
    }

    #[test]
    fn revocations_are_not_in_the_shared_budget_round() {
        // Revocations must replicate on their OWN round budget in sync_peer, NOT
        // share the budget/receipt round. If they were in this shared list a
        // sustained budget backlog (shared-round exhaustion) or a broken budget
        // endpoint could starve security-critical revocation propagation. Budget
        // stays first here.
        let shared = peer_pullers();
        assert_eq!(
            shared[0] as usize, sync_peer_budgets as Puller as usize,
            "budget remains first in the shared round"
        );
        assert!(
            !shared
                .iter()
                .any(|puller| *puller as usize == sync_peer_revocations as Puller as usize),
            "revocations must be pulled on an independent round budget, not the shared one"
        );
    }

    #[test]
    fn quorum_commit_timeout_covers_full_per_peer_sync_and_is_bounded() {
        // The wait must outlast a FULL serial sync_peer visit for every peer
        // preceding the quorum peer, not just one CONTROL_HTTP_TIMEOUT per peer. A
        // full visit is the three fixed blocking stages plus the two
        // wall-clock-bounded delta rounds.
        let interval = Duration::from_millis(25);
        let per_peer_sync =
            CONTROL_HTTP_TIMEOUT * 3 + PEER_ROUND_WALL_CLOCK_BUDGET + PEER_ROUND_WALL_CLOCK_BUDGET;

        assert!(budget_write_quorum_commit_timeout(interval, 0) >= Duration::from_secs(5));

        // One preceding peer must be budgeted a full sync_peer visit. A bound of one
        // CONTROL_HTTP_TIMEOUT per peer would give only 30s here, far short of it.
        let one = budget_write_quorum_commit_timeout(interval, 1);
        assert!(
            one >= per_peer_sync,
            "one preceding peer must allow a full serial sync_peer visit, got {one:?}"
        );

        // Still bounded by a fixed ceiling so a misconfigured huge peer list cannot
        // make the wait unbounded.
        assert!(budget_write_quorum_commit_timeout(interval, 10_000) <= Duration::from_secs(300));
    }

    fn storm_event(seq: u64) -> BudgetMutationEventView {
        BudgetMutationEventView {
            operation_id: None,
            request_binding_hash: None,
            event_id: format!("evt-{seq}"),
            hold_id: None,
            capability_id: "cap-page".to_string(),
            grant_index: 0,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: seq as i64,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 1,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: 1,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationStateView::Absent,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: None,
            total_cost_exposed_after: 1,
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: "http://origin-page".to_string(),
                lease_id: "http://origin-page#term-1".to_string(),
                lease_epoch: 1,
            }),
        }
    }

    fn storm_invocation_quota() -> BudgetInvocationQuotaUsageRecordView {
        BudgetInvocationQuotaUsageRecordView {
            usage: BudgetInvocationQuotaUsageView {
                quota: BudgetInvocationQuotaView {
                    key: BudgetQuotaKeyView {
                        profile: BudgetQuotaProfileView::GrantInvocation,
                        owner_id: "cap-page".to_string(),
                        grant_index: Some(0),
                    },
                    max_invocations: u32::MAX,
                },
                reserved_invocations_after: 0,
                captured_invocations_after: 1,
            },
            updated_at: 3,
            seq: 3,
        }
    }

    #[test]
    fn expired_hold_delta_preserves_terminal_projection_states() {
        let mut event = storm_event(7);
        event.kind = BudgetMutationKind::ExpireHold.as_str().to_string();
        event.hold_id = Some("hold-expired-delta".to_string());
        event.exposure_units = 5;
        event.realized_spend_units = 0;
        event.total_cost_exposed_after = 0;
        event.total_cost_realized_spend_after = 0;

        let record = budget_mutation_record_from_view(&event).test_unwrap();
        assert_eq!(record.kind, BudgetMutationKind::ExpireHold);
        assert_eq!(
            record.invocation_state,
            BudgetInvocationReservationState::Absent
        );
        assert_eq!(record.monetary_state, BudgetMonetaryHoldState::Released);
    }

    fn storm_usage(seq: u64) -> BudgetUsageView {
        BudgetUsageView {
            capability_id: "cap-page".to_string(),
            grant_index: 0,
            invocation_count: 1,
            total_cost_exposed: 1,
            total_cost_realized_spend: 0,
            updated_at: seq as i64,
            seq: Some(seq),
        }
    }

    #[test]
    fn budget_delta_round_trip_preserves_immutable_invocation_maximum() {
        let source_db = temp_budget_db("quota-delta-source");
        let target_db = temp_budget_db("quota-delta-target");
        let source = SqliteBudgetStore::open(&source_db).test_unwrap();
        assert!(source
            .try_increment("cap-quota-delta", 0, Some(1))
            .test_unwrap());

        let mutation_events =
            collect_budget_mutation_event_views_after_seq(&source, 0, 10).test_unwrap();
        let records =
            collect_budget_projection_views_for_events(&source, &mutation_events).test_unwrap();
        let invocation_quotas =
            collect_budget_invocation_quota_views_for_events(&source, &mutation_events)
                .test_unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(invocation_quotas.len(), 1);
        assert_eq!(invocation_quotas[0].usage.quota.max_invocations, 1);

        let response = BudgetDeltaResponse {
            records,
            invocation_quotas,
            mutation_events,
            abandoned_seqs: Vec::new(),
        };
        let mut target = SqliteBudgetStore::open(&target_db).test_unwrap();
        let outcome =
            import_budget_delta_response(&mut target, &response, None, &mut PullRoundBudget::new())
                .test_unwrap();
        assert_eq!(outcome.applied_count, 1);
        let error = target
            .try_increment("cap-quota-delta", 0, Some(2))
            .test_unwrap_err();
        assert!(error.to_string().contains("different maximum"));
        assert!(!target
            .try_increment("cap-quota-delta", 0, Some(1))
            .test_unwrap());

        let _ = std::fs::remove_file(source_db);
        let _ = std::fs::remove_file(target_db);
    }

    #[test]
    fn budget_delta_reverse_round_trip_retains_original_invocation_maximum() {
        let source_db = temp_budget_db("reverse-quota-delta-source");
        let target_db = temp_budget_db("reverse-quota-delta-target");
        let source = SqliteBudgetStore::open(&source_db).test_unwrap();
        assert!(source
            .try_charge_cost_with_ids(
                "cap-reverse-quota-delta",
                0,
                Some(1),
                5,
                None,
                None,
                Some("hold-reverse-quota-delta"),
                Some("event-reverse-quota-delta-authorize"),
            )
            .test_unwrap());
        source
            .reverse_charge_cost_with_ids(
                "cap-reverse-quota-delta",
                0,
                5,
                Some("hold-reverse-quota-delta"),
                Some("event-reverse-quota-delta-reverse"),
            )
            .test_unwrap();

        let mutation_events =
            collect_budget_mutation_event_views_after_seq(&source, 0, 10).test_unwrap();
        let records =
            collect_budget_projection_views_for_events(&source, &mutation_events).test_unwrap();
        let invocation_quotas =
            collect_budget_invocation_quota_views_for_events(&source, &mutation_events)
                .test_unwrap();
        assert_eq!(records[0].invocation_count, 0);
        assert_eq!(invocation_quotas[0].usage.quota.max_invocations, 1);
        assert_eq!(invocation_quotas[0].usage.captured_invocations_after, 0);

        let response = BudgetDeltaResponse {
            records,
            invocation_quotas,
            mutation_events,
            abandoned_seqs: Vec::new(),
        };
        let mut target = SqliteBudgetStore::open(&target_db).test_unwrap();
        let outcome =
            import_budget_delta_response(&mut target, &response, None, &mut PullRoundBudget::new())
                .test_unwrap();
        assert_eq!(outcome.applied_count, 2);
        let error = target
            .try_increment("cap-reverse-quota-delta", 0, Some(2))
            .test_unwrap_err();
        assert!(error.to_string().contains("different maximum"));
        assert!(target
            .try_increment("cap-reverse-quota-delta", 0, Some(1))
            .test_unwrap());

        let _ = std::fs::remove_file(source_db);
        let _ = std::fs::remove_file(target_db);
    }

    #[test]
    fn budget_delta_omitted_quota_fails_closed_for_denied_only_event() {
        let source_db = temp_budget_db("denied-quota-delta-source");
        let target_db = temp_budget_db("denied-quota-delta-target");
        let source = SqliteBudgetStore::open(&source_db).test_unwrap();
        assert!(!source
            .try_increment("cap-denied-quota-delta", 0, Some(0))
            .test_unwrap());
        let mutation_events =
            collect_budget_mutation_event_views_after_seq(&source, 0, 10).test_unwrap();
        assert_eq!(mutation_events.len(), 1);
        let source_quotas =
            collect_budget_invocation_quota_views_for_events(&source, &mutation_events)
                .test_unwrap();
        assert_eq!(source_quotas.len(), 1);
        let response = BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: Vec::new(),
            mutation_events,
            abandoned_seqs: Vec::new(),
        };

        let mut target = SqliteBudgetStore::open(&target_db).test_unwrap();
        let existing_quota =
            budget_invocation_quota_usage_record_from_view(&source_quotas[0]).test_unwrap();
        target
            .import_snapshot_records_with_invocation_quotas(&[], &[existing_quota], &[])
            .test_unwrap();
        assert!(import_budget_delta_response(
            &mut target,
            &response,
            None,
            &mut PullRoundBudget::new(),
        )
        .is_err());
        assert_eq!(target.max_mutation_event_seq().test_unwrap(), 0);
        let retained_quota = target
            .get_compatibility_invocation_quota_usage("cap-denied-quota-delta", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(retained_quota.usage.quota.max_invocations(), 0);

        let _ = std::fs::remove_file(source_db);
        let _ = std::fs::remove_file(target_db);
    }

    #[test]
    fn budget_delta_record_cap_counts_invocation_quota_projections() {
        let db = temp_budget_db("quota-delta-record-cap");
        let mut store = SqliteBudgetStore::open(&db).test_unwrap();
        let response = BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: vec![storm_invocation_quota()],
            mutation_events: vec![storm_event(1)],
            abandoned_seqs: (2..=(BUDGET_DELTA_MAX_RECORDS as u64)).collect(),
        };

        let error =
            import_budget_delta_response(&mut store, &response, None, &mut PullRoundBudget::new())
                .test_unwrap_err();
        assert!(matches!(error, PullError::ForceSnapshot(_)));
        assert_eq!(store.max_mutation_event_seq().test_unwrap(), 0);

        let _ = std::fs::remove_file(db);
    }

    #[test]
    fn budget_mutation_replication_preserves_admission_operation_ownership() {
        let mut event = storm_event(1);
        event.operation_id = Some("operation-1".to_string());
        event.request_binding_hash = Some("44".repeat(32));
        let record = budget_mutation_record_from_view(&event).test_unwrap();
        let binding = record.admission_operation.test_unwrap();
        assert_eq!(binding.operation_id(), "operation-1");
        assert_eq!(binding.request_binding_hash(), "44".repeat(32));

        event.request_binding_hash = None;
        assert!(budget_mutation_record_from_view(&event).is_err());
    }

    fn temp_budget_db(tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("chio-{tag}-{nonce}.sqlite3"))
    }

    #[test]
    fn oversized_budget_page_retries_smaller_before_snapshotting() {
        // A page can exceed BUDGET_DELTA_MAX_RECORDS just because we asked for a full
        // MAX_LIST_LIMIT window (events + their usages + abandoned seqs). Such a
        // large-but-PAGEABLE window must be delivered incrementally via a SMALLER
        // event limit, not routed straight to a full snapshot: the drain refetches
        // the SAME cursor with a smaller limit and imports the window (still
        // contiguity-checked, so no skip / no over-count).
        use chio_test_support::prelude::*;
        let db = temp_budget_db("retry-smaller-budget-page");
        let mut store = SqliteBudgetStore::open(&db).test_unwrap();

        // The oversized first page: MAX_LIST_LIMIT events plus a dense abandoned burst,
        // so record_count > BUDGET_DELTA_MAX_RECORDS. It carries MANY events, so it is
        // reducible: a smaller event window would fit under the cap.
        let over_cap = || BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: Vec::new(),
            mutation_events: (1..=MAX_LIST_LIMIT as u64).map(storm_event).collect(),
            abandoned_seqs: ((MAX_LIST_LIMIT as u64 + 1)..=(BUDGET_DELTA_MAX_RECORDS as u64 + 1))
                .collect(),
        };
        // The smaller retry page: a short contiguous run that imports cleanly.
        let small = || BudgetDeltaResponse {
            records: vec![storm_usage(3)],
            invocation_quotas: vec![storm_invocation_quota()],
            mutation_events: (1..=3).map(storm_event).collect(),
            abandoned_seqs: Vec::new(),
        };

        let calls = std::cell::RefCell::new(Vec::<(Option<u64>, usize)>::new());
        let result = drain_budget_delta_pages(
            &mut store,
            &mut PullRoundBudget::new(),
            None,
            |after_seq, limit| {
                calls.borrow_mut().push((after_seq, limit));
                Ok(match (after_seq, limit) {
                    // First fetch: full limit from the head -> the oversized window.
                    (None, l) if l >= MAX_LIST_LIMIT => over_cap(),
                    // Retry from the SAME head at a reduced limit -> the pageable window.
                    (None, _) => small(),
                    // Cursor advanced past the imported window -> the stream is drained.
                    _ => BudgetDeltaResponse {
                        records: Vec::new(),
                        invocation_quotas: Vec::new(),
                        mutation_events: Vec::new(),
                        abandoned_seqs: Vec::new(),
                    },
                })
            },
            |_cursor| {},
        );

        // The window drained incrementally; no ForceSnapshot escaped the drain.
        let applied = match result {
            Ok(applied) => applied,
            Err(other) => {
                panic!("a large-but-pageable window must drain, not force-snapshot: {other:?}")
            }
        };
        assert_eq!(applied, 3, "the smaller page's events were imported");
        // The drain retried the same cursor with a limit strictly below
        // MAX_LIST_LIMIT before ever force-snapshotting.
        let calls = calls.into_inner();
        assert!(
            calls
                .iter()
                .any(|(after, limit)| after.is_none() && *limit < MAX_LIST_LIMIT),
            "the drain must retry the SAME cursor with a smaller event limit before snapshotting, got {calls:?}"
        );
        // The follower actually holds the imported events (contiguity preserved).
        assert_eq!(store.max_mutation_event_seq().test_unwrap(), 3);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn unpageable_single_event_budget_page_still_force_snapshots() {
        // A GENUINELY unpageable window - a single live event preceded by a dense
        // rollback burst of abandoned seqs that alone exceeds the record cap -
        // cannot be split smaller, so the drain must still route the peer to full
        // snapshot recovery (ForceSnapshot) rather than shrink-looping forever.
        use chio_test_support::prelude::*;
        let db = temp_budget_db("unpageable-budget-page");
        let mut store = SqliteBudgetStore::open(&db).test_unwrap();

        let fetches = std::cell::RefCell::new(0usize);
        let result = drain_budget_delta_pages(
            &mut store,
            &mut PullRoundBudget::new(),
            None,
            |_after_seq, _limit| {
                *fetches.borrow_mut() += 1;
                Ok(BudgetDeltaResponse {
                    records: Vec::new(),
                    invocation_quotas: Vec::new(),
                    // ONE event; the abandoned burst ALONE exceeds the record cap, so
                    // no smaller event page can bring the count under the cap.
                    mutation_events: vec![storm_event(1)],
                    abandoned_seqs: (2..=(BUDGET_DELTA_MAX_RECORDS as u64 + 2)).collect(),
                })
            },
            |_cursor| {},
        );

        match result {
            Err(PullError::ForceSnapshot(_)) => {}
            other => {
                panic!("a minimal one-event over-cap page must force-snapshot, got {other:?}")
            }
        }
        // A single-event page is not reducible, so it force-snapshots after exactly
        // ONE fetch: no unbounded shrink-retry loop.
        assert_eq!(
            fetches.into_inner(),
            1,
            "no shrink-retry for an unpageable single-event page"
        );

        let _ = std::fs::remove_file(&db);
    }
}
