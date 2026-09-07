#[test]
fn scheduler_and_effect_reads_verify_canonical_hashes() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let now = current_unix_ms();
    let action_id = chio_security_types::ports::ActionId::new("canonical-action")
        .unwrap_or_else(|error| panic!("action id: {error}"));
    store
        .create(&ResponsePlanRecord {
            tenant_id: tenant("tenant-a"),
            action_id: action_id.clone(),
            generation: 0,
            state: record("active"),
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            due_at_unix_ms: Some(now.saturating_sub(1)),
        })
        .unwrap_or_else(|error| panic!("create plan: {error}"));
    let claim = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant("tenant-a"),
            claim_id: record("canonical-claim"),
            lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("canonical-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now + 60_000,
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim plan: {error}"));
    let effect = ResponseEffectRecord {
        tenant_id: tenant("tenant-a"),
        effect_id: EffectId::new("canonical-effect")
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        action_id: action_id.clone(),
        generation: 0,
        scheduler_lease_owner_id: claim[0].lease_owner_id.clone(),
        scheduler_fencing_token: claim[0].fencing_token,
        state: record("applied"),
        canonical_body: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: digest(b"{}"),
        encrypted_rollback_ref: None,
    };
    store
        .persist_effect(&effect)
        .unwrap_or_else(|error| panic!("persist effect: {error}"));
    rusqlite::Connection::open(&path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_response_effects SET body_hash = zeroblob(32) WHERE effect_id = 'canonical-effect'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt effect hash: {error}"));
    let effect_error = require_error(store.load_effect(&ResponseEffectKey {
        tenant_id: effect.tenant_id.clone(),
        effect_id: effect.effect_id.clone(),
    }));
    assert_eq!(effect_error.kind(), PortErrorKind::IntegrityFailure);
    rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_response_plans SET body_hash = zeroblob(32) WHERE action_id = 'canonical-action'",
                [],
            )?;
            connection.execute(
                "UPDATE security_scheduler_leases SET lease_expires_at = 0 WHERE action_id = 'canonical-action'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt plan hash: {error}"));
    let plan_error = require_error(store.load_plan(&ResponsePlanKey {
        tenant_id: tenant("tenant-a"),
        action_id,
    }));
    assert_eq!(plan_error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn overlapping_overlay_contributions_are_removed_independently() {
    for reverse in [false, true] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let now = current_unix_ms();
        let store = SqliteSecurityStateStore::open(directory.path().join("state.db"))
            .unwrap_or_else(|error| panic!("open store: {error}"));
        let action_id = chio_security_types::ports::ActionId::new("action-overlap")
            .unwrap_or_else(|error| panic!("action id: {error}"));
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant("tenant-a"),
                action_id: action_id.clone(),
                generation: 0,
                state: record("active"),
                canonical_body: CanonicalBody::new(b"{}".to_vec())
                    .unwrap_or_else(|error| panic!("canonical body: {error}")),
                body_hash: digest(b"{}"),
                due_at_unix_ms: Some(now.saturating_sub(1)),
            })
            .unwrap_or_else(|error| panic!("create plan: {error}"));
        let lease = store
            .claim_due(&SchedulerClaimRequest {
                tenant_id: tenant("tenant-a"),
                claim_id: record("overlay-claim"),
                lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("worker")
                    .unwrap_or_else(|error| panic!("owner id: {error}")),
                now_unix_ms: now,
                lease_expires_at_unix_ms: now + 60_000,
                max_claims: 1,
            })
            .unwrap_or_else(|error| panic!("claim plan: {error}"));
        let token = lease[0].fencing_token;
        let overlay_session = "session-overlap";
        let target = overlay_target(overlay_session);
        let empty = empty_overlay(target.clone());
        let first_apply = overlay_apply_request(
            &empty,
            overlay_session,
            action_id.clone(),
            EffectId::new("effect-low").unwrap_or_else(|error| panic!("effect id: {error}")),
            2,
            token,
            if reverse {
                "overlap-r-low"
            } else {
                "overlap-f-low"
            },
        );
        let one = store
            .apply_contribution(&first_apply)
            .unwrap_or_else(|error| panic!("apply first: {error}"));
        let second_apply = overlay_apply_request(
            &one,
            overlay_session,
            action_id.clone(),
            EffectId::new("effect-high").unwrap_or_else(|error| panic!("effect id: {error}")),
            4,
            token,
            if reverse {
                "overlap-r-high"
            } else {
                "overlap-f-high"
            },
        );
        let two = store
            .apply_contribution(&second_apply)
            .unwrap_or_else(|error| panic!("apply second: {error}"));
        assert_eq!(two.effective_posture_rank, 4);
        let (remove_first, remaining_rank, remove_second) = if reverse {
            (&second_apply, 2, &first_apply)
        } else {
            (&first_apply, 4, &second_apply)
        };
        let first_remove = overlay_remove_request(
            remove_first,
            &two,
            overlay_session,
            action_id.clone(),
            token,
            if reverse {
                "overlap-r-remove-1"
            } else {
                "overlap-f-remove-1"
            },
        );
        let after_one = store
            .remove_contribution(&first_remove)
            .unwrap_or_else(|error| panic!("remove first: {error}"));
        assert_eq!(after_one.effective_posture_rank, remaining_rank);
        let second_remove = overlay_remove_request(
            remove_second,
            &after_one,
            overlay_session,
            action_id,
            token,
            if reverse {
                "overlap-r-remove-2"
            } else {
                "overlap-f-remove-2"
            },
        );
        let after_two = store
            .remove_contribution(&second_remove)
            .unwrap_or_else(|error| panic!("remove second: {error}"));
        assert_eq!(after_two.effective_posture_rank, 0);
        assert!(after_two.active_contributions.is_empty());
    }
}

#[test]
fn overlay_effect_identity_cannot_cross_action_boundaries() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let now = current_unix_ms();
    let first_action = chio_security_types::ports::ActionId::new("action-first")
        .unwrap_or_else(|error| panic!("action id: {error}"));
    let second_action = chio_security_types::ports::ActionId::new("action-second")
        .unwrap_or_else(|error| panic!("action id: {error}"));
    for action_id in [&first_action, &second_action] {
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant("tenant-a"),
                action_id: action_id.clone(),
                generation: 0,
                state: record("active"),
                canonical_body: CanonicalBody::new(b"{}".to_vec())
                    .unwrap_or_else(|error| panic!("canonical body: {error}")),
                body_hash: digest(b"{}"),
                due_at_unix_ms: Some(now.saturating_sub(1)),
            })
            .unwrap_or_else(|error| panic!("create plan: {error}"));
    }
    let claim_request = SchedulerClaimRequest {
        tenant_id: tenant("tenant-a"),
        claim_id: record("multi-action-claim"),
        lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("worker")
            .unwrap_or_else(|error| panic!("owner id: {error}")),
        now_unix_ms: now,
        lease_expires_at_unix_ms: now + 60_000,
        max_claims: 2,
    };
    let claims = store
        .claim_due(&claim_request)
        .unwrap_or_else(|error| panic!("claim actions: {error}"));
    assert_eq!(claims.len(), 2);
    assert_eq!(
        store
            .claim_due(&claim_request)
            .unwrap_or_else(|error| panic!("recover multi-action claim: {error}")),
        claims
    );
    let first_token = claims
        .iter()
        .find(|claim| claim.action_id == first_action)
        .map(|claim| claim.fencing_token)
        .unwrap_or_else(|| panic!("first action lease missing"));
    let second_token = claims
        .iter()
        .find(|claim| claim.action_id == second_action)
        .map(|claim| claim.fencing_token)
        .unwrap_or_else(|| panic!("second action lease missing"));
    assert!(second_token > first_token);
    let overlay_session = "shared-target-session";
    let target = overlay_target(overlay_session);
    let empty = empty_overlay(target.clone());
    let first_apply = overlay_apply_request(
        &empty,
        overlay_session,
        first_action.clone(),
        EffectId::new("shared-effect").unwrap_or_else(|error| panic!("effect id: {error}")),
        7,
        first_token,
        "action-boundary-first",
    );
    let applied = store
        .apply_contribution(&first_apply)
        .unwrap_or_else(|error| panic!("apply first action: {error}"));
    let wrong_session = "wrong-target-session";
    let wrong_target = overlay_target(wrong_session);
    let wrong_empty = empty_overlay(wrong_target);
    let wrong_target_remove = overlay_remove_request(
        &first_apply,
        &wrong_empty,
        wrong_session,
        first_action.clone(),
        first_token,
        "action-boundary-wrong-target",
    );
    let wrong_target_error = require_error(store.remove_contribution(&wrong_target_remove));
    assert_eq!(wrong_target_error.kind(), PortErrorKind::Conflict);
    let wrong_action_apply = overlay_apply_request(
        &applied,
        overlay_session,
        second_action.clone(),
        first_apply.contribution.effect_id.clone(),
        7,
        second_token,
        "action-boundary-wrong-action",
    );
    let error = require_error(store.apply_contribution(&wrong_action_apply));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    let second_apply = overlay_apply_request(
        &applied,
        overlay_session,
        second_action.clone(),
        EffectId::new("second-effect").unwrap_or_else(|error| panic!("effect id: {error}")),
        9,
        second_token,
        "action-boundary-second",
    );
    let both = store
        .apply_contribution(&second_apply)
        .unwrap_or_else(|error| panic!("apply second action: {error}"));
    let remove_first = overlay_remove_request(
        &first_apply,
        &both,
        overlay_session,
        first_action,
        first_token,
        "action-boundary-remove-first",
    );
    let remaining = store
        .remove_contribution(&remove_first)
        .unwrap_or_else(|error| panic!("remove live older action: {error}"));
    assert_eq!(remaining.active_contributions.len(), 1);
    assert_eq!(
        remaining.active_contributions.as_slice()[0].effect_id,
        second_apply.contribution.effect_id
    );
    rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_overlay_state SET effective_posture_rank = 0 WHERE target_id = ?1",
                rusqlite::params![target.id.as_str()],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt overlay posture: {error}"));
    let corruption_error = require_error(store.load_effective(&target));
    assert_eq!(corruption_error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn verified_event_correlation_is_durable_and_advisory_events_remain_segregated() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("state.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("canonical body: {error}"));
    store
        .append_verified(&VerifiedSecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-a").unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("detector-a")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            trust_class: ProducerTrustClass::InternalDetector,
            event_time_unix_ms: 1,
            received_at_unix_ms: 2,
            canonical_body: body,
            body_hash: digest(b"{}"),
            evidence_hash: digest(b"evidence"),
        })
        .unwrap_or_else(|error| panic!("append verified event: {error}"));
    store
        .append_verified(&VerifiedSecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-b").unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("detector-a")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            trust_class: ProducerTrustClass::InternalDetector,
            event_time_unix_ms: 1,
            received_at_unix_ms: 3,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            evidence_hash: digest(b"evidence-b"),
        })
        .unwrap_or_else(|error| panic!("append second verified event: {error}"));
    store
        .append_advisory(&AdvisorySecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-advisory")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("external-source")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            event_time_unix_ms: 1,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
        })
        .unwrap_or_else(|error| panic!("append advisory event: {error}"));
    let partition = digest(b"partition");
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: CorrelationPartitionKey {
                tenant_id: tenant("tenant-a"),
                rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
                partition_hash: partition,
            },
            event_id: EventId::new("event-a").unwrap_or_else(|error| panic!("event id: {error}")),
            transition_id: record("index-event-a"),
        })
        .unwrap_or_else(|error| panic!("index verified event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: CorrelationPartitionKey {
                tenant_id: tenant("tenant-a"),
                rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
                partition_hash: partition,
            },
            event_id: EventId::new("event-b").unwrap_or_else(|error| panic!("event id: {error}")),
            transition_id: record("index-event-b"),
        })
        .unwrap_or_else(|error| panic!("index second verified event: {error}"));
    let advisory_error =
        require_error(store.index_partition_event(&CorrelationEventIndexRequest {
            key: CorrelationPartitionKey {
                tenant_id: tenant("tenant-a"),
                rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
                partition_hash: partition,
            },
            event_id:
                EventId::new("event-advisory").unwrap_or_else(|error| panic!("event id: {error}")),
            transition_id: record("index-advisory"),
        }));
    assert!(matches!(
        advisory_error.kind(),
        PortErrorKind::Conflict | PortErrorKind::InvalidData
    ));
    let verified = store
        .scan_partition(&EventPartitionScan {
            tenant_id: tenant("tenant-a"),
            rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
            partition_hash: partition,
            after_event_time_unix_ms: None,
            after_event_id: None,
            through_event_time_unix_ms: 10,
            max_results: 1,
        })
        .unwrap_or_else(|error| panic!("scan verified events: {error}"));
    assert!(verified.truncated);
    assert_eq!(verified.events.len(), 1);
    assert_eq!(verified.events.as_slice()[0].event_id.as_str(), "event-a");
    let next = store
        .scan_partition(&EventPartitionScan {
            tenant_id: tenant("tenant-a"),
            rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
            partition_hash: partition,
            after_event_time_unix_ms: Some(1),
            after_event_id: Some(
                EventId::new("event-a").unwrap_or_else(|error| panic!("event id: {error}")),
            ),
            through_event_time_unix_ms: 10,
            max_results: 1,
        })
        .unwrap_or_else(|error| panic!("scan next verified event: {error}"));
    assert!(!next.truncated);
    assert_eq!(next.events.len(), 1);
    assert_eq!(next.events.as_slice()[0].event_id.as_str(), "event-b");
    let unrelated = store
        .scan_partition(&EventPartitionScan {
            tenant_id: tenant("tenant-a"),
            rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
            partition_hash: digest(b"unrelated-partition"),
            after_event_time_unix_ms: None,
            after_event_id: None,
            through_event_time_unix_ms: 10,
            max_results: 10,
        })
        .unwrap_or_else(|error| panic!("scan unrelated partition: {error}"));
    assert!(unrelated.events.is_empty());
    let complete_scan = EventPartitionScan {
        tenant_id: tenant("tenant-a"),
        rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
        partition_hash: partition,
        after_event_time_unix_ms: None,
        after_event_id: None,
        through_event_time_unix_ms: 10,
        max_results: 10,
    };
    let observed = store
        .scan_partition(&complete_scan)
        .unwrap_or_else(|error| panic!("scan complete partition: {error}"));
    assert!(!observed.truncated);
    assert_eq!(observed.events.len(), 2);
    store
        .append_verified(&VerifiedSecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-future")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("detector-a")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            trust_class: ProducerTrustClass::InternalDetector,
            event_time_unix_ms: 11,
            received_at_unix_ms: 11,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            evidence_hash: digest(b"future evidence"),
        })
        .unwrap_or_else(|error| panic!("append future event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: CorrelationPartitionKey {
                tenant_id: tenant("tenant-a"),
                rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
                partition_hash: partition,
            },
            event_id: EventId::new("event-future")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            transition_id: record("index-future-event"),
        })
        .unwrap_or_else(|error| panic!("index future event: {error}"));
    assert_eq!(
        store
            .load_correlation_max_seen_event_time(&CorrelationPartitionKey {
                tenant_id: tenant("tenant-a"),
                rule_id: RuleId::new("rule-a")
                    .unwrap_or_else(|error| panic!("rule id: {error}")),
                partition_hash: partition,
            })
            .unwrap_or_else(|error| panic!("load indexed max seen: {error}")),
        Some(11)
    );
    let partial = CorrelationPartial {
        key: CorrelationPartitionKey {
            tenant_id: tenant("tenant-a"),
            rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
            partition_hash: partition,
        },
        generation: 0,
        watermark_unix_ms: 10,
        expires_at_unix_ms: 20,
        canonical_body: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: digest(b"{}"),
    };
    let stale_revision_error =
        require_error(store.compare_and_swap_correlation(&CorrelationCasRequest {
            scan: complete_scan.clone(),
            observed_partition_generation: observed.partition_generation,
            partial: partial.clone(),
            expected_generation: None,
            transition_id: record("advance-watermark"),
        }));
    assert_eq!(stale_revision_error.kind(), PortErrorKind::Conflict);
    let refreshed = store
        .scan_partition(&complete_scan)
        .unwrap_or_else(|error| panic!("rescan complete partition: {error}"));
    let skipped_prefix_error =
        require_error(store.compare_and_swap_correlation(&CorrelationCasRequest {
            scan: EventPartitionScan {
                after_event_time_unix_ms: Some(9),
                ..complete_scan.clone()
            },
            observed_partition_generation: refreshed.partition_generation,
            partial: partial.clone(),
            expected_generation: None,
            transition_id: record("skip-correlation-prefix"),
        }));
    assert_eq!(skipped_prefix_error.kind(), PortErrorKind::Conflict);
    store
        .compare_and_swap_correlation(&CorrelationCasRequest {
            scan: complete_scan,
            observed_partition_generation: refreshed.partition_generation,
            partial,
            expected_generation: None,
            transition_id: record("advance-watermark"),
        })
        .unwrap_or_else(|error| panic!("advance correlation: {error}"));
    store
        .append_verified(&VerifiedSecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-late")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("detector-a")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            trust_class: ProducerTrustClass::InternalDetector,
            event_time_unix_ms: 5,
            received_at_unix_ms: 11,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            evidence_hash: digest(b"late evidence"),
        })
        .unwrap_or_else(|error| panic!("append late event: {error}"));
    let late_error = require_error(store.index_partition_event(&CorrelationEventIndexRequest {
        key: CorrelationPartitionKey {
            tenant_id: tenant("tenant-a"),
            rule_id: RuleId::new("rule-a").unwrap_or_else(|error| panic!("rule id: {error}")),
            partition_hash: partition,
        },
        event_id: EventId::new("event-late").unwrap_or_else(|error| panic!("event id: {error}")),
        transition_id: record("index-late-event"),
    }));
    assert_eq!(late_error.kind(), PortErrorKind::Conflict);
    store
        .append_verified(&VerifiedSecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-zero")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("detector-a")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            trust_class: ProducerTrustClass::InternalDetector,
            event_time_unix_ms: 0,
            received_at_unix_ms: 1,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            evidence_hash: digest(b"zero evidence"),
        })
        .unwrap_or_else(|error| panic!("append zero-time event: {error}"));
    let zero_partition = digest(b"zero partition");
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: CorrelationPartitionKey {
                tenant_id: tenant("tenant-a"),
                rule_id: RuleId::new("rule-zero")
                    .unwrap_or_else(|error| panic!("rule id: {error}")),
                partition_hash: zero_partition,
            },
            event_id: EventId::new("event-zero")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            transition_id: record("index-zero-event"),
        })
        .unwrap_or_else(|error| panic!("index zero-time event: {error}"));
    let zero_time = store
        .scan_partition(&EventPartitionScan {
            tenant_id: tenant("tenant-a"),
            rule_id: RuleId::new("rule-zero").unwrap_or_else(|error| panic!("rule id: {error}")),
            partition_hash: zero_partition,
            after_event_time_unix_ms: None,
            after_event_id: None,
            through_event_time_unix_ms: 0,
            max_results: 1,
        })
        .unwrap_or_else(|error| panic!("scan zero-time event: {error}"));
    assert_eq!(zero_time.events.len(), 1);
    rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_verified_events SET body_hash = zeroblob(32) WHERE event_id = 'event-a'",
                [],
            )?;
            connection.execute(
                "UPDATE security_advisory_events SET body_hash = zeroblob(32) WHERE event_id = 'event-advisory'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt event hashes: {error}"));
    let verified_error = require_error(
        store.append_verified(&VerifiedSecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-a").unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("detector-a")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            trust_class: ProducerTrustClass::InternalDetector,
            event_time_unix_ms: 1,
            received_at_unix_ms: 2,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
            evidence_hash: digest(b"evidence"),
        }),
    );
    assert_eq!(verified_error.kind(), PortErrorKind::IntegrityFailure);
    let advisory_error = require_error(
        store.append_advisory(&AdvisorySecurityEvent {
            tenant_id: tenant("tenant-a"),
            event_id: EventId::new("event-advisory")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            producer_id: ProducerId::new("external-source")
                .unwrap_or_else(|error| panic!("producer id: {error}")),
            event_time_unix_ms: 1,
            canonical_body: CanonicalBody::new(b"{}".to_vec())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: digest(b"{}"),
        }),
    );
    assert_eq!(advisory_error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn verified_event_capacity_and_rule_index_roll_back_as_one_sqlite_transaction() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("atomic-correlation.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let tenant_id = tenant("tenant-atomic");
    let rule_id = RuleId::new("rule-atomic").unwrap_or_else(|error| panic!("rule id: {error}"));
    let partition = CorrelationPartitionKey {
        tenant_id: tenant_id.clone(),
        rule_id: rule_id.clone(),
        partition_hash: digest(b"atomic-partition"),
    };
    let partition_scan = EventPartitionScan {
        tenant_id: tenant_id.clone(),
        rule_id: rule_id.clone(),
        partition_hash: partition.partition_hash,
        after_event_time_unix_ms: None,
        after_event_id: None,
        through_event_time_unix_ms: 100,
        max_results: 1,
    };
    store
        .compare_and_swap_correlation(&CorrelationCasRequest {
            scan: partition_scan,
            observed_partition_generation: 0,
            partial: CorrelationPartial {
                key: partition.clone(),
                generation: 0,
                watermark_unix_ms: 100,
                expires_at_unix_ms: 200,
                canonical_body: CanonicalBody::new(b"{}".to_vec())
                    .unwrap_or_else(|error| panic!("partition body: {error}")),
                body_hash: digest(b"{}"),
            },
            expected_generation: None,
            transition_id: record("seed-atomic-partition"),
        })
        .unwrap_or_else(|error| panic!("seed partition: {error}"));

    let capacity_key = CorrelationPartitionKey {
        tenant_id: tenant_id.clone(),
        rule_id: rule_id.clone(),
        partition_hash: digest(b"atomic-capacity"),
    };
    let event_id = EventId::new("event-atomic").unwrap_or_else(|error| panic!("event id: {error}"));
    let error = require_error(
        store.admit_verified_correlation_event(&CorrelationEventAdmissionRequest {
            event: VerifiedSecurityEvent {
                tenant_id: tenant_id.clone(),
                event_id: event_id.clone(),
                producer_id: ProducerId::new("detector-atomic")
                    .unwrap_or_else(|error| panic!("producer id: {error}")),
                trust_class: ProducerTrustClass::InternalDetector,
                event_time_unix_ms: 50,
                received_at_unix_ms: 51,
                canonical_body: CanonicalBody::new(b"{}".to_vec())
                    .unwrap_or_else(|error| panic!("event body: {error}")),
                body_hash: digest(b"{}"),
                evidence_hash: digest(b"atomic evidence"),
            },
            index: CorrelationEventIndexRequest {
                key: partition,
                event_id: event_id.clone(),
                transition_id: record("index-atomic-event"),
            },
            capacity: Some(CorrelationCasRequest {
                scan: EventPartitionScan {
                    tenant_id: tenant_id.clone(),
                    rule_id: rule_id.clone(),
                    partition_hash: capacity_key.partition_hash,
                    after_event_time_unix_ms: None,
                    after_event_id: None,
                    through_event_time_unix_ms: 50,
                    max_results: 1,
                },
                observed_partition_generation: 0,
                partial: CorrelationPartial {
                    key: capacity_key.clone(),
                    generation: 0,
                    watermark_unix_ms: 50,
                    expires_at_unix_ms: 200,
                    canonical_body: CanonicalBody::new(b"{}".to_vec())
                        .unwrap_or_else(|error| panic!("capacity body: {error}")),
                    body_hash: digest(b"{}"),
                },
                expected_generation: None,
                transition_id: record("reserve-atomic-capacity"),
            }),
        }),
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);

    let connection =
        rusqlite::Connection::open(&path).unwrap_or_else(|error| panic!("inspect store: {error}"));
    let event_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_verified_events WHERE tenant_id = ?1 AND event_id = ?2",
            rusqlite::params![tenant_id.as_str(), event_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count event: {error}"));
    let index_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_correlation_events WHERE tenant_id = ?1 AND event_id = ?2",
            rusqlite::params![tenant_id.as_str(), event_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count index: {error}"));
    let capacity_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_correlation_partials WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3",
            rusqlite::params![
                tenant_id.as_str(),
                rule_id.as_str(),
                capacity_key.partition_hash.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count capacity: {error}"));
    assert_eq!((event_count, capacity_count, index_count), (0, 0, 0));
}

#[test]
fn correlation_ingress_orders_due_event_time_ahead_of_a_future_fifo_prefix() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("correlation-event-time-order.db");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open correlation ingress store: {error}"));
    let (future, future_verified) =
        authenticated_correlation_event_at("future-prefix", 20_000, 20_001);
    let (due, due_verified) = authenticated_correlation_event_at("due-behind-prefix", 10, 11);
    store
        .enqueue_verified_correlation_event(&future, &future_verified)
        .unwrap_or_else(|error| panic!("enqueue future event: {error:?}"));
    store
        .enqueue_verified_correlation_event(&due, &due_verified)
        .unwrap_or_else(|error| panic!("enqueue due event: {error:?}"));

    let pending = store
        .load_pending_correlation_events(1)
        .unwrap_or_else(|error| panic!("load oldest event-time record: {error:?}"));
    assert_eq!(pending.as_slice(), std::slice::from_ref(&due));
}

#[test]
fn correlation_ingress_pending_snapshot_survives_a_concurrent_acknowledgement() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("correlation-concurrent-ack.db");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open correlation ingress store: {error}"));
    let (event, verified) = authenticated_correlation_event("concurrent-ack");
    store
        .enqueue_verified_correlation_event(&event, &verified)
        .unwrap_or_else(|error| panic!("enqueue authenticated event: {error:?}"));
    let pending = store
        .load_pending_correlation_events(1)
        .unwrap_or_else(|error| panic!("load pending event: {error:?}"));
    assert_eq!(pending.as_slice(), std::slice::from_ref(&event));

    store
        .acknowledge_correlated_event(&event)
        .unwrap_or_else(|error| panic!("acknowledge event: {error:?}"));
    store
        .validate_pending_correlation_event(&event, &verified)
        .unwrap_or_else(|error| panic!("validate acknowledged snapshot: {error:?}"));
    store
        .acknowledge_correlated_event(&event)
        .unwrap_or_else(|error| panic!("re-acknowledge event: {error:?}"));
}

#[test]
fn correlation_ingress_upgrades_the_known_legacy_pending_index() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("correlation-legacy-index.db");
    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("create canonical store: {error}")),
    );
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open legacy index fixture: {error}"));
    connection
        .execute_batch(
            r#"
            DROP INDEX security_correlation_ingress_pending;
            CREATE INDEX security_correlation_ingress_pending
                ON security_correlation_ingress (acknowledged, sequence);
            "#,
        )
        .unwrap_or_else(|error| panic!("install legacy pending index: {error}"));
    drop(connection);

    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("upgrade legacy pending index: {error}")),
    );
    let upgraded_sql: String = rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'security_correlation_ingress_pending'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap_or_else(|error| panic!("load upgraded pending index: {error}"));
    assert!(upgraded_sql.contains("acknowledged, event_time, sequence"));
}

#[test]
fn correlation_schema_drift_fails_startup() {
    let mutations = [
        (
            "weakened ingress table and foreign key",
            r#"
            DROP TABLE security_correlation_ingress;
            CREATE TABLE security_correlation_ingress (
                sequence INTEGER,
                tenant_id TEXT,
                event_id TEXT,
                producer_id TEXT,
                event_time INTEGER,
                received_at INTEGER,
                body BLOB,
                body_hash BLOB,
                source_evidence BLOB,
                evidence_hash BLOB,
                acknowledged INTEGER
            );
            "#,
        ),
        (
            "weakened ingress index",
            r#"
            DROP INDEX security_correlation_ingress_pending;
            CREATE INDEX security_correlation_ingress_pending
                ON security_correlation_ingress (sequence);
            "#,
        ),
        (
            "same-name no-op ingress trigger",
            r#"
            DROP TRIGGER security_correlation_ingress_immutable;
            CREATE TRIGGER security_correlation_ingress_immutable
            BEFORE UPDATE ON security_correlation_ingress
            BEGIN
                SELECT 1;
            END;
            "#,
        ),
        (
            "weakened outcome table and foreign key",
            r#"
            DROP TABLE security_correlation_outcomes;
            CREATE TABLE security_correlation_outcomes (
                tenant_id TEXT,
                rule_id TEXT,
                event_id TEXT,
                rule_version_hash BLOB,
                event_body_hash BLOB,
                event_evidence_hash BLOB,
                body BLOB,
                body_hash BLOB
            );
            "#,
        ),
        (
            "same-name no-op outcome trigger",
            r#"
            DROP TRIGGER security_correlation_outcomes_delete_rejected;
            CREATE TRIGGER security_correlation_outcomes_delete_rejected
            BEFORE DELETE ON security_correlation_outcomes
            BEGIN
                SELECT 1;
            END;
            "#,
        ),
    ];

    for (index, (case, mutation)) in mutations.into_iter().enumerate() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory
            .path()
            .join(format!("correlation-schema-{index}.db"));
        drop(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("create canonical store for {case}: {error}")),
        );
        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("open schema mutation store for {case}: {error}"));
        connection
            .execute_batch(mutation)
            .unwrap_or_else(|error| panic!("install schema mutation for {case}: {error}"));
        drop(connection);

        let error = match SqliteSecurityStateStore::open(&path) {
            Ok(_) => panic!("{case} unexpectedly passed startup validation"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{case}");
    }
}

#[test]
fn acknowledged_correlation_tombstone_source_binding_corruption_fails_readiness() {
    for corrupt_source_evidence in [true, false] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join(if corrupt_source_evidence {
            "corrupt-acknowledged-source.db"
        } else {
            "corrupt-acknowledged-evidence-hash.db"
        });
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open correlation ingress store: {error}"));
        let (event, verified) = authenticated_correlation_event(if corrupt_source_evidence {
            "event-corrupt-acknowledged-source"
        } else {
            "event-corrupt-acknowledged-evidence-hash"
        });
        store
            .enqueue_verified_correlation_event(&event, &verified)
            .unwrap_or_else(|error| panic!("enqueue authenticated event: {error:?}"));
        store
            .acknowledge_correlated_event(&event)
            .unwrap_or_else(|error| panic!("acknowledge authenticated event: {error:?}"));
        drop(store);

        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("open corruption fixture: {error}"));
        connection
            .execute_batch("DROP TRIGGER security_correlation_ingress_immutable;")
            .unwrap_or_else(|error| panic!("drop ingress immutability trigger: {error}"));
        if corrupt_source_evidence {
            connection
                .execute(
                    r#"
                    UPDATE security_correlation_ingress
                    SET source_evidence = x'7b7d'
                    WHERE tenant_id = ?1 AND event_id = ?2
                    "#,
                    rusqlite::params![event.tenant_id.as_str(), event.event_id.as_str()],
                )
                .unwrap_or_else(|error| panic!("corrupt acknowledged source evidence: {error}"));
        } else {
            let corrupted_hash = [91_u8; 32];
            connection
                .execute(
                    r#"
                    UPDATE security_correlation_ingress
                    SET evidence_hash = ?1
                    WHERE tenant_id = ?2 AND event_id = ?3
                    "#,
                    rusqlite::params![
                        corrupted_hash.as_slice(),
                        event.tenant_id.as_str(),
                        event.event_id.as_str()
                    ],
                )
                .unwrap_or_else(|error| panic!("corrupt ingress evidence hash: {error}"));
            connection
                .execute(
                    r#"
                    UPDATE security_verified_events
                    SET evidence_hash = ?1
                    WHERE tenant_id = ?2 AND event_id = ?3
                    "#,
                    rusqlite::params![
                        corrupted_hash.as_slice(),
                        event.tenant_id.as_str(),
                        event.event_id.as_str()
                    ],
                )
                .unwrap_or_else(|error| panic!("corrupt verified evidence hash: {error}"));
        }
        connection
            .execute_batch(
                r#"
                CREATE TRIGGER security_correlation_ingress_immutable
                BEFORE UPDATE ON security_correlation_ingress
                WHEN OLD.sequence != NEW.sequence
                    OR OLD.tenant_id != NEW.tenant_id
                    OR OLD.event_id != NEW.event_id
                    OR OLD.producer_id != NEW.producer_id
                    OR OLD.event_time != NEW.event_time
                    OR OLD.received_at != NEW.received_at
                    OR OLD.body != NEW.body
                    OR OLD.body_hash != NEW.body_hash
                    OR OLD.source_evidence != NEW.source_evidence
                    OR OLD.evidence_hash != NEW.evidence_hash
                    OR OLD.acknowledged = 1
                    OR NEW.acknowledged != 1
                BEGIN
                    SELECT RAISE(ABORT, 'correlation ingress mutation is rejected');
                END;
                "#,
            )
            .unwrap_or_else(|error| panic!("restore ingress immutability trigger: {error}"));
        drop(connection);

        let reopened = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen corrupted correlation ingress: {error}"));
        let error = require_error(reopened.ensure_correlation_ingress_ready());
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}
