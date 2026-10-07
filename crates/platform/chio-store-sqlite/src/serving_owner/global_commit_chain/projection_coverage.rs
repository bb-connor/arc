//! Local projection completeness against the protected global commit chain.
use super::*;

pub(super) fn verify_global_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    crate::admission_operation_store::verify_recovery_records(connection)
        .map_err(|error| invalid(error.to_string()))?;
    let recovery_exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_events')", [], |row| row.get(0))?;
    let recovery_uncovered: bool = recovery_exists && connection.query_row("SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_events e WHERE (SELECT count(*) FROM authority_global_commits g WHERE g.projection_kind='recovery' AND g.projection_key=e.record_key AND g.projection_sequence=e.record_version)<>1)", [], |row|row.get(0))?;
    if recovery_uncovered {
        return Err(invalid("recovery history lacks global authority coverage"));
    }
    crate::admission_operation_store::verify_runtime_replay_projection_coverage(connection)?;
    crate::admission_operation_store::verify_governed_approval_replay_projection_coverage(
        connection,
    )?;
    crate::admission_operation_store::verify_dpop_replay_projection_coverage(connection)?;
    crate::admission_operation_store::verify_security_participant_migration_coverage(connection)?;
    verify_channel_release_projection_coverage(connection)?;
    verify_finding_challenge_projection_coverage(connection)?;
    verify_finding_status_projection_coverage(connection)?;
    let incomplete = connection.query_row(
        r#"
        SELECT
            EXISTS(
                SELECT 1 FROM admission_operation_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'admission'
                      AND global.projection_key = local.operation_id
                      AND global.projection_sequence = local.commit_sequence
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM budget_mutation_events AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'budget'
                      AND global.projection_key = local.event_id
                      AND global.projection_sequence = local.event_seq
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM admission_authority_commits AS local
                WHERE local.kind = 'revocation'
                  AND (
                      SELECT COUNT(*) FROM authority_global_commits AS global
                      WHERE global.projection_kind = 'revocation'
                        AND global.projection_key = local.capability_id
                        AND global.projection_sequence = local.commit_index
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM frost_projection_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'frost'
                      AND global.projection_key = local.projection_key
                      AND global.projection_sequence = local.projection_sequence
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM payment_journal AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'payment'
                      AND global.projection_key = local.operation_id
                      AND global.projection_sequence = local.journal_version
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM economic_state_stage_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'economic'
                      AND global.projection_key = local.batch_id
                      AND global.projection_sequence = local.stage_version
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM fiscal_projection_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'fiscal'
                      AND global.projection_key = local.projection_key
                      AND global.projection_sequence = local.projection_sequence
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM factor_assignment_authority_sets AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'factor_assignment_authority_set'
                      AND global.projection_key = 'active'
                      AND global.projection_sequence = local.generation
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM authority_global_commits AS global
                WHERE global.projection_kind = 'factor_assignment_authority_set'
                  AND (
                      global.projection_key <> 'active'
                      OR NOT EXISTS(
                          SELECT 1 FROM factor_assignment_authority_sets AS local
                          WHERE local.generation = global.projection_sequence
                      )
                  )
            )
            OR EXISTS(
                SELECT 1 FROM authority_global_commits AS global
                WHERE global.projection_kind = 'payment'
                  AND NOT EXISTS(
                      SELECT 1 FROM payment_journal AS local
                      WHERE local.operation_id = global.projection_key
                        AND local.journal_version >= global.projection_sequence
                  )
            )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if incomplete {
        return Err(invalid("global authority projection coverage is not exact"));
    }
    Ok(())
}

pub(in crate::serving_owner) fn verify_finding_challenge_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let projection_table_present = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'finding_challenge_projection_commits')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !projection_table_present {
        let global_reference_present = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'finding_challenge')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        return if global_reference_present {
            Err(invalid("finding challenge projection table is absent"))
        } else {
            Ok(())
        };
    }
    let mut statement = connection.prepare(
        r#"
        SELECT projection_sequence, mutation_kind, snapshot_digest,
               previous_commit_digest, commit_digest
        FROM finding_challenge_projection_commits
        ORDER BY projection_sequence
        "#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut previous = GLOBAL_GENESIS_DIGEST.to_owned();
    let mut expected_sequence = 1_u64;
    for (stored_sequence, mutation_kind, snapshot_digest, previous_digest, commit_digest) in &rows {
        let sequence = read_u64(*stored_sequence, "finding challenge projection sequence")?;
        if sequence != expected_sequence
            || mutation_kind != "finding_challenge_write"
            || previous_digest != &previous
            || !is_digest(snapshot_digest)
            || !is_digest(commit_digest)
        {
            return Err(invalid("finding challenge projection chain is malformed"));
        }
        let expected_digest = digest(&FindingChallengeProjectionEntry {
            format: "chio.sqlite-finding-challenge-projection.v1",
            previous_commit_digest: &previous,
            projection_sequence: sequence,
            mutation_kind,
            snapshot_digest,
        })?;
        if expected_digest != *commit_digest {
            return Err(invalid("finding challenge projection digest mismatch"));
        }
        let global_count = connection.query_row(
            r#"
            SELECT COUNT(*) FROM authority_global_commits
            WHERE projection_kind = 'finding_challenge'
              AND projection_key = 'market' AND projection_sequence = ?1
            "#,
            [sqlite_u64(
                sequence,
                "finding challenge projection sequence",
            )?],
            |row| row.get::<_, i64>(0),
        )?;
        if global_count != 1 {
            return Err(invalid(
                "finding challenge global projection coverage is not exact",
            ));
        }
        previous.clone_from(commit_digest);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("finding challenge projection sequence overflowed"))?;
    }
    let orphaned_global = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM authority_global_commits AS global
            WHERE global.projection_kind = 'finding_challenge'
              AND (
                  global.projection_key <> 'market'
                  OR NOT EXISTS(
                      SELECT 1 FROM finding_challenge_projection_commits AS local
                      WHERE local.projection_sequence = global.projection_sequence
                  )
              )
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if orphaned_global {
        return Err(invalid(
            "finding challenge global projection reference is orphaned",
        ));
    }
    let has_state = connection.query_row(
        r#"
        SELECT EXISTS(SELECT 1 FROM challenges)
            OR EXISTS(SELECT 1 FROM finding_challenge_submissions)
            OR EXISTS(SELECT 1 FROM dispute_lock_reservations)
            OR EXISTS(SELECT 1 FROM dispute_locks)
            OR EXISTS(SELECT 1 FROM liability_heads)
            OR EXISTS(SELECT 1 FROM finding_finalizing_authorizations)
            OR EXISTS(SELECT 1 FROM finding_finalizing_authorization_refreshes)
            OR EXISTS(SELECT 1 FROM governance_case_index)
            OR EXISTS(SELECT 1 FROM claim_snapshots)
            OR EXISTS(SELECT 1 FROM effect_intents)
            OR EXISTS(SELECT 1 FROM finding_seller_impairment_reconciliations)
            OR EXISTS(SELECT 1 FROM effect_root_bindings)
            OR EXISTS(SELECT 1 FROM finding_challenge_outcomes)
            OR EXISTS(SELECT 1 FROM listing_sales_blocks)
            OR EXISTS(SELECT 1 FROM purchase_records)
            OR EXISTS(SELECT 1 FROM failed_delivery_records)
            OR EXISTS(SELECT 1 FROM purchase_reservations)
            OR EXISTS(SELECT 1 FROM payout_destinations)
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    match rows.last() {
        Some((_, _, snapshot_digest, _, _)) => {
            let current_market = finding_market_snapshot_digest(connection)?;
            let current_market_v13 = finding_market_snapshot_digest_v13(connection)?;
            let current_market_v12 = finding_market_snapshot_digest_v12(connection)?;
            let current_market_v11 = finding_market_snapshot_digest_v11(connection)?;
            let current_market_v10 = finding_market_snapshot_digest_v10(connection)?;
            let current_market_v9 = finding_market_snapshot_digest_v9(connection)?;
            let current_market_v8 = finding_market_snapshot_digest_v8(connection)?;
            let current_market_v7 = finding_market_snapshot_digest_v7(connection)?;
            let current_market_v6 = finding_market_snapshot_digest_v6(connection)?;
            let current_market_v5 = finding_market_snapshot_digest_v5(connection)?;
            let current_market_v4 = finding_market_snapshot_digest_v4(connection)?;
            let current_market_v3 = finding_market_snapshot_digest_v3(connection)?;
            let current_market_v2 = finding_market_snapshot_digest_v2(connection)?;
            let current_legacy = finding_challenge_snapshot_digest_v1(connection)?;
            let has_uncommitted_purchase_state = connection.query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM purchase_reservations
                    WHERE state IN ('open', 'slot_reserved')
                      AND reservation_id NOT IN (
                          SELECT reservation_id FROM purchase_records
                      )
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v6_root_binding = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM effect_root_bindings)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v7_outcome = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_challenge_outcomes)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v8_capture_intent = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM purchase_capture_intents)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v9_failed_delivery = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM failed_delivery_records)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v10_finalizing_authorization = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_finalizing_authorizations)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v10_actionable_payout_slot = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM payout_destinations WHERE slot_index > 0)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v11_finalizing_authorization_refresh = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_finalizing_authorization_refreshes)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v12_terminal_reservation = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM purchase_reservations WHERE state IN ('released', 'expired'))",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v13_seller_impairment_reconciliation = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_seller_impairment_reconciliations)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v14_challenge_submission = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_challenge_submissions)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let uncovered_before_v10 = current_market_v9 != *snapshot_digest
                && (has_v9_failed_delivery
                    || (current_market_v8 != *snapshot_digest
                        && (has_v8_capture_intent
                            || (current_market_v7 != *snapshot_digest
                                && (has_uncommitted_purchase_state
                                    || has_v7_outcome
                                    || (current_market_v6 != *snapshot_digest
                                        && (has_v6_root_binding
                                            || (current_market_v4 != *snapshot_digest
                                                && current_market_v5 != *snapshot_digest
                                                && current_market_v3 != *snapshot_digest
                                                && current_market_v2 != *snapshot_digest
                                                && current_legacy != *snapshot_digest))))))));
            let uncovered_before_v11 = current_market_v10 != *snapshot_digest
                && (has_v10_finalizing_authorization
                    || has_v10_actionable_payout_slot
                    || uncovered_before_v10);
            let uncovered_before_v12 = current_market_v11 != *snapshot_digest
                && (has_v11_finalizing_authorization_refresh || uncovered_before_v11);
            let uncovered_before_v13 = current_market_v12 != *snapshot_digest
                && (has_v12_terminal_reservation || uncovered_before_v12);
            let uncovered_before_v14 = current_market_v13 != *snapshot_digest
                && (has_v13_seller_impairment_reconciliation || uncovered_before_v13);
            if current_market != *snapshot_digest
                && (has_v14_challenge_submission || uncovered_before_v14)
            {
                return Err(invalid(
                    "finding challenge projection does not cover current state",
                ));
            }
        }
        None if has_state => {
            return Err(invalid(
                "finding challenge state has no authenticated projection",
            ));
        }
        None => {}
    }
    Ok(())
}
