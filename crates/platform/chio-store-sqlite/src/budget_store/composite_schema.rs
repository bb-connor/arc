#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use super::*;

mod state_invariants;

pub(super) fn verify_budget_foreign_keys(connection: &Connection) -> Result<(), BudgetStoreError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if let Some((table, rowid)) = violation {
        return Err(BudgetStoreError::Invariant(format!(
            "sqlite foreign key violation in `{table}` row {rowid}"
        )));
    }
    Ok(())
}

impl SqliteBudgetStore {
    pub(crate) fn verify_supplemental_artifact_selector_index(
        connection: &Connection,
    ) -> Result<(), BudgetStoreError> {
        let definition: Option<Option<String>> = connection.query_row(
            "SELECT CASE WHEN typeof(sql) = 'text' AND length(CAST(sql AS BLOB)) BETWEEN 1 AND 1024 THEN sql END
             FROM sqlite_schema WHERE type = 'index' AND name = 'idx_budget_holds_supplemental_artifact'
             AND tbl_name = 'budget_authorization_holds'",
            [], |row| row.get(0),
        ).optional()?;
        let definition = definition.flatten().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "supplemental artifact selector index is missing or exceeds bounds".into(),
            )
        })?;
        let normalized = definition
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if normalized != "CREATE INDEX idx_budget_holds_supplemental_artifact ON budget_authorization_holds(supplemental_artifact_digest, operation_id) WHERE supplemental_artifact_digest IS NOT NULL" {
            return Err(BudgetStoreError::Invariant(
                "supplemental artifact selector index definition differs".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn verify_budget_projection_invariants(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let invalid = connection
        .query_row(
            r#"
            WITH projection_rows AS (
                SELECT 'hold' AS kind, hold_id AS owner_id,
                       artifact_index AS member_index,
                       artifact_digest AS value,
                       'artifact' AS member_kind
                FROM budget_hold_authorization_artifacts
                UNION ALL
                SELECT 'event', event_id, artifact_index, artifact_digest,
                       'artifact'
                FROM budget_event_authorization_artifacts
                UNION ALL
                SELECT 'hold', hold_id, member_index, capability_id,
                       'revocation'
                FROM budget_hold_revocation_members
                UNION ALL
                SELECT 'event', event_id, member_index, capability_id,
                       'revocation'
                FROM budget_event_revocation_members
            ), checked AS (
                SELECT kind, owner_id, member_kind, member_index, value,
                       ROW_NUMBER() OVER (
                           PARTITION BY kind, owner_id, member_kind
                           ORDER BY member_index
                       ) - 1 AS expected_index,
                       LAG(value) OVER (
                           PARTITION BY kind, owner_id, member_kind
                           ORDER BY member_index
                       ) AS previous_value
                FROM projection_rows
            )
            SELECT kind, owner_id, member_kind FROM checked
            WHERE member_index <> expected_index
               OR previous_value >= value
               OR (
                   member_kind = 'artifact'
                   AND (
                       member_index < 0
                       OR member_index >= 8
                       OR length(value) <> 64
                       OR value GLOB '*[^0-9a-f]*'
                   )
               )
               OR (
                   member_kind = 'revocation'
                   AND (
                       member_index < 0
                       OR member_index >= 256
                       OR length(CAST(value AS BLOB)) NOT BETWEEN 1 AND 512
                   )
               )
            LIMIT 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((kind, owner_id, member_kind)) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has non-canonical {member_kind} members"
        )));
    }
    verify_revocation_set_digests(connection)?;
    let invalid_contract = connection
        .query_row(
            r#"
            WITH parents AS (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       projection_kind, operation_id, revocation_set_digest,
                       expected_quota_count, expected_artifact_count,
                       has_cumulative_approval, has_revocation_commit,
                       expected_revocation_count,
                       authorization_outcome,
                       invocation_state AS invocation_before,
                       invocation_state AS invocation_after,
                       monetary_state AS monetary_before,
                       monetary_state AS monetary_after,
                       (SELECT COUNT(*) FROM budget_hold_revocation_members
                        WHERE hold_id = parent.hold_id) AS revocation_count,
                       (SELECT COUNT(*) FROM budget_hold_quota_members
                        WHERE hold_id = parent.hold_id) AS quota_count,
                       (SELECT COUNT(*) FROM budget_hold_authorization_artifacts
                        WHERE hold_id = parent.hold_id) AS artifact_count,
                       (SELECT COUNT(*) FROM budget_cumulative_approval_operations
                        WHERE hold_id = parent.hold_id) AS cumulative_count,
                       (SELECT COUNT(*) FROM budget_hold_revocation_commits
                        WHERE hold_id = parent.hold_id) AS commit_count
                FROM budget_authorization_holds AS parent
                UNION ALL
                SELECT 'event', event_id, projection_kind, operation_id,
                       revocation_set_digest, expected_quota_count,
                       expected_artifact_count, has_cumulative_approval,
                       has_revocation_commit, expected_revocation_count,
                       authorization_outcome,
                       invocation_state_before, invocation_state_after,
                       monetary_state_before, monetary_state_after,
                       (SELECT COUNT(*) FROM budget_event_revocation_members
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_quota_members
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_authorization_artifacts
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_cumulative_approval
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_revocation_commits
                        WHERE event_id = parent.event_id)
                FROM budget_mutation_events AS parent
            )
            SELECT owner_kind, owner_id FROM parents
            WHERE projection_kind NOT IN ('standalone', 'composite_v1') OR (
                projection_kind = 'composite_v1'
                AND (
                    operation_id IS NULL OR operation_id = ''
                    OR revocation_set_digest IS NULL
                    OR length(revocation_set_digest) <> 64
                    OR revocation_set_digest GLOB '*[^0-9a-f]*'
                    OR expected_revocation_count IS NULL
                    OR expected_revocation_count NOT BETWEEN 1 AND 256
                    OR expected_quota_count IS NULL
                    OR expected_quota_count NOT BETWEEN 0 AND 8
                    OR expected_artifact_count IS NULL
                    OR expected_artifact_count NOT BETWEEN 0 AND 8
                    OR has_cumulative_approval IS NULL
                    OR has_cumulative_approval NOT IN (0, 1)
                    OR has_revocation_commit IS NULL
                    OR has_revocation_commit NOT IN (0, 1)
                    OR revocation_count <> expected_revocation_count
                    OR quota_count <> expected_quota_count
                    OR artifact_count <> expected_artifact_count
                    OR cumulative_count <> has_cumulative_approval
                    OR commit_count <> has_revocation_commit
                    OR (owner_kind = 'hold' AND authorization_outcome IS NULL)
                    OR authorization_outcome NOT IN (
                        'authorized', 'approval_required', 'denied'
                    )
                    OR invocation_before IS NULL
                    OR invocation_before NOT IN (
                        'absent', 'authorized', 'captured', 'reversed', 'denied'
                    )
                    OR invocation_after IS NULL
                    OR invocation_after NOT IN (
                        'authorized', 'captured', 'reversed', 'denied'
                    )
                    OR monetary_before IS NULL
                    OR monetary_before NOT IN (
                        'none', 'exposed', 'released', 'reconciled',
                        'captured', 'reversed'
                    )
                    OR monetary_after IS NULL
                    OR monetary_after NOT IN (
                        'none', 'exposed', 'released', 'reconciled',
                        'captured', 'reversed'
                    )
                    OR (invocation_after = 'authorized'
                        AND monetary_after NOT IN ('none', 'exposed', 'released'))
                    OR (invocation_after = 'captured'
                        AND monetary_after NOT IN (
                            'none', 'exposed', 'reconciled', 'captured'
                        ))
                    OR (invocation_after = 'reversed'
                        AND monetary_after NOT IN ('none', 'reversed'))
                    OR (invocation_after = 'denied' AND monetary_after <> 'none')
                )
            ) OR (
                projection_kind = 'standalone'
                AND (
                    operation_id IS NOT NULL
                    OR revocation_set_digest IS NOT NULL
                    OR expected_revocation_count IS NOT NULL
                    OR expected_quota_count IS NOT NULL
                    OR expected_artifact_count IS NOT NULL
                    OR has_cumulative_approval IS NOT NULL
                    OR has_revocation_commit IS NOT NULL
                    OR revocation_count <> 0 OR quota_count <> 0
                    OR artifact_count <> 0 OR cumulative_count <> 0
                    OR commit_count <> 0
                )
            )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_contract {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has an incomplete composite projection contract"
        )));
    }
    let invalid_quota = connection
        .query_row(
            r#"
            WITH quotas AS (
                SELECT 'quota' AS owner_kind,
                       profile || ':' || owner_id || ':' || grant_index AS owner_id,
                       profile, owner_id AS quota_owner, grant_index, max_invocations,
                       reserved_invocations AS reserved_before,
                       captured_invocations AS captured_before,
                       reserved_invocations AS reserved_after,
                       captured_invocations AS captured_after,
                       NULL AS authorization_outcome
                FROM budget_invocation_quotas
                UNION ALL
                SELECT 'event-quota', member.event_id || ':' || member.owner_id,
                       member.profile, member.owner_id, member.grant_index,
                       member.max_invocations, member.reserved_before,
                       member.captured_before, member.reserved_after,
                       member.captured_after, event.authorization_outcome
                FROM budget_event_quota_members AS member
                JOIN budget_mutation_events AS event
                  ON event.event_id = member.event_id
            )
            SELECT owner_kind, owner_id FROM quotas
            WHERE quota_owner = '' OR max_invocations < 0
               OR (
                   max_invocations = 0
                   AND (
                       owner_kind <> 'event-quota'
                       OR authorization_outcome IS NOT 'denied'
                   )
               )
               OR reserved_before < 0 OR captured_before < 0
               OR reserved_after < 0 OR captured_after < 0
               OR reserved_before > max_invocations
               OR captured_before > max_invocations - reserved_before
               OR reserved_after > max_invocations
               OR captured_after > max_invocations - reserved_after
               OR NOT (
                   (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
                   OR (profile IN (
                       'chio.aggregate-capability-invocation.v1',
                       'chio.aggregate-family-invocation.v1',
                       'chio.broker-capability-execution.v1'
                   ) AND grant_index = -1)
               )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_quota {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` is outside durable quota bounds"
        )));
    }
    let invalid_approval = connection
        .query_row(
            r#"
            SELECT owner_kind, owner_id FROM (
                SELECT 'operation' AS owner_kind, operation_id AS owner_id,
                       approval_set_digest AS digest
                FROM budget_cumulative_approval_operations
                UNION ALL
                SELECT 'event', event_id, cumulative_approval_set_digest
                FROM budget_mutation_events
            )
            WHERE digest IS NOT NULL
              AND (
                  length(digest) <> 64
                  OR digest GLOB '*[^0-9a-f]*'
              )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_approval {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has a non-canonical approval set digest"
        )));
    }
    let invalid_commit = connection
        .query_row(
            r#"
            SELECT owner_kind, owner_id FROM (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       authority_id, lease_id, lease_epoch,
                       guarantee_level, commit_index
                FROM budget_hold_revocation_commits
                UNION ALL
                SELECT 'event', event_id, authority_id, lease_id,
                       lease_epoch, guarantee_level, commit_index
                FROM budget_event_revocation_commits
            )
            WHERE authority_id = ''
               OR lease_id = ''
               OR lease_epoch <= 0
               OR commit_index <= 0
               OR guarantee_level NOT IN (
                   'single_node_atomic', 'ha_linearizable'
               )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_commit {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has invalid revocation commit metadata"
        )));
    }
    let invalid_supplemental = connection
        .query_row(
            r#"
            WITH supplemental AS (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       supplemental_verifier_id AS verifier_id,
                       supplemental_verifier_config_digest AS config_digest,
                       supplemental_artifact_digest AS artifact_digest,
                       supplemental_expires_at AS expires_at
                FROM budget_authorization_holds
                UNION ALL
                SELECT 'event', event_id, supplemental_verifier_id,
                       supplemental_verifier_config_digest,
                       supplemental_artifact_digest, supplemental_expires_at
                FROM budget_mutation_events
            )
            SELECT owner_kind, owner_id FROM supplemental AS value
            WHERE (
                    verifier_id IS NOT NULL
                    OR config_digest IS NOT NULL
                    OR artifact_digest IS NOT NULL
                    OR expires_at IS NOT NULL
                  )
              AND (
                    verifier_id IS NULL OR verifier_id = ''
                    OR config_digest IS NULL
                    OR length(config_digest) <> 64
                    OR config_digest GLOB '*[^0-9a-f]*'
                    OR artifact_digest IS NULL
                    OR length(artifact_digest) <> 64
                    OR artifact_digest GLOB '*[^0-9a-f]*'
                    OR expires_at IS NULL OR expires_at <= 0
                    OR NOT EXISTS (
                        SELECT 1 FROM budget_hold_authorization_artifacts
                        WHERE value.owner_kind = 'hold'
                          AND hold_id = value.owner_id
                          AND artifact_digest = value.artifact_digest
                        UNION ALL
                        SELECT 1 FROM budget_event_authorization_artifacts
                        WHERE value.owner_kind = 'event'
                          AND event_id = value.owner_id
                          AND artifact_digest = value.artifact_digest
                    )
                    OR NOT EXISTS (
                        SELECT 1 FROM budget_hold_revocation_commits
                        WHERE value.owner_kind = 'hold'
                          AND hold_id = value.owner_id
                        UNION ALL
                        SELECT 1 FROM budget_event_revocation_commits
                        WHERE value.owner_kind = 'event'
                          AND event_id = value.owner_id
                    )
                  )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_supplemental {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has an incomplete supplemental authority binding"
        )));
    }
    state_invariants::verify_budget_state_invariants(connection)?;
    Ok(())
}

#[path = "composite_schema/revocation_integrity.rs"]
mod revocation_integrity;
use revocation_integrity::verify_revocation_set_digests;
