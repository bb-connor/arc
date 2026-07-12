use super::*;

pub(super) fn ensure_composite_budget_schema(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS budget_invocation_quota_usage (
            profile TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            grant_index_key INTEGER NOT NULL,
            max_invocations INTEGER NOT NULL,
            reserved_invocations INTEGER NOT NULL DEFAULT 0,
            captured_invocations INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            seq INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (profile, owner_id, grant_index_key),
            CHECK (max_invocations >= 0),
            CHECK (reserved_invocations >= 0),
            CHECK (captured_invocations >= 0),
            CHECK (reserved_invocations + captured_invocations <= max_invocations),
            CHECK (
                (profile = 'chio.grant-invocation.v1' AND grant_index_key >= 0)
                OR
                (profile IN (
                    'chio.aggregate-capability-invocation.v1',
                    'chio.aggregate-family-invocation.v1',
                    'chio.broker-capability-execution.v1'
                ) AND grant_index_key = -1)
            )
        );

        CREATE TABLE IF NOT EXISTS budget_composite_authorizations (
            hold_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            capability_id TEXT NOT NULL,
            grant_index INTEGER NOT NULL,
            requested_exposure_units INTEGER NOT NULL,
            max_cost_per_invocation INTEGER,
            max_total_cost_units INTEGER,
            authority_id TEXT,
            lease_id TEXT,
            lease_epoch INTEGER,
            allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
            invocation_state TEXT NOT NULL,
            monetary_state TEXT NOT NULL,
            revocation_set_digest TEXT NOT NULL,
            revocation_ids_json TEXT NOT NULL,
            committed_cost_units_after INTEGER NOT NULL,
            invocation_count_after INTEGER NOT NULL,
            event_seq INTEGER NOT NULL UNIQUE,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS budget_composite_authorization_quotas (
            hold_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            profile TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            grant_index_key INTEGER NOT NULL,
            max_invocations INTEGER NOT NULL,
            reserved_invocations_after INTEGER NOT NULL,
            captured_invocations_after INTEGER NOT NULL,
            PRIMARY KEY (hold_id, position),
            UNIQUE (hold_id, profile, owner_id, grant_index_key),
            CHECK (position >= 0),
            CHECK (max_invocations >= 0),
            CHECK (reserved_invocations_after >= 0),
            CHECK (captured_invocations_after >= 0),
            CHECK (
                reserved_invocations_after + captured_invocations_after
                <= max_invocations
            )
        );

        CREATE TABLE IF NOT EXISTS budget_composite_holds (
            hold_id TEXT PRIMARY KEY,
            invocation_state TEXT NOT NULL,
            monetary_state TEXT NOT NULL,
            revocation_set_digest TEXT NOT NULL,
            revocation_ids_json TEXT NOT NULL,
            remaining_exposure_units INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS budget_composite_managed_grants (
            capability_id TEXT NOT NULL,
            grant_index INTEGER NOT NULL,
            first_hold_id TEXT NOT NULL,
            PRIMARY KEY (capability_id, grant_index)
        );

        CREATE TABLE IF NOT EXISTS budget_composite_mutation_snapshots (
            event_id TEXT PRIMARY KEY,
            invocation_state TEXT NOT NULL,
            monetary_state TEXT NOT NULL,
            revocation_set_digest TEXT NOT NULL,
            revocation_ids_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS budget_composite_mutation_quota_snapshots (
            event_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            profile TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            grant_index_key INTEGER NOT NULL,
            max_invocations INTEGER NOT NULL,
            reserved_invocations_after INTEGER NOT NULL,
            captured_invocations_after INTEGER NOT NULL,
            PRIMARY KEY (event_id, position),
            UNIQUE (event_id, profile, owner_id, grant_index_key)
        );

        CREATE INDEX IF NOT EXISTS idx_budget_invocation_quota_usage_seq
            ON budget_invocation_quota_usage(seq);

        CREATE TRIGGER IF NOT EXISTS budget_invocation_quota_identity_immutable
        BEFORE UPDATE OF profile, owner_id, grant_index_key, max_invocations
        ON budget_invocation_quota_usage
        WHEN OLD.profile IS NOT NEW.profile
          OR OLD.owner_id IS NOT NEW.owner_id
          OR OLD.grant_index_key IS NOT NEW.grant_index_key
          OR OLD.max_invocations IS NOT NEW.max_invocations
        BEGIN
            SELECT RAISE(ABORT, 'immutable invocation quota maximum or identity');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_immutable
        BEFORE UPDATE ON budget_composite_authorizations
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_delete_forbidden
        BEFORE DELETE ON budget_composite_authorizations
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_quota_immutable
        BEFORE UPDATE ON budget_composite_authorization_quotas
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization quota snapshot');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_quota_delete_forbidden
        BEFORE DELETE ON budget_composite_authorization_quotas
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization quota snapshot');
        END;
        "#,
    )?;
    Ok(())
}

pub(super) fn ensure_budget_seq_column(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let has_seq = columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "seq");
    if !has_seq {
        connection.execute(
            "ALTER TABLE capability_grant_budgets ADD COLUMN seq INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_seq ON capability_grant_budgets(seq)",
        [],
    )?;
    Ok(())
}

pub(super) fn ensure_split_budget_cost_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|c| c == "total_cost_exposed")
        || !columns.iter().any(|c| c == "total_cost_realized_spend")
    {
        return Err(BudgetStoreError::Invariant(
            "unsupported budget schema: missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_budget_hold_authority_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "authority_id") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN authority_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_id") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN lease_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_epoch") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN lease_epoch INTEGER",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_mutation_event_authority_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_mutation_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "authority_id") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN authority_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_id") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN lease_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_epoch") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN lease_epoch INTEGER",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_mutation_event_seq_column(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_mutation_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "event_seq") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN event_seq INTEGER",
            [],
        )?;
    }
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_mutation_events_event_seq ON budget_mutation_events(event_seq)",
        [],
    )?;
    Ok(())
}

/// Backfill immutable hold-ID authorization claims on upgrade.
///
/// A database created before the claim table may contain at most one surviving
/// authorization event per hold ID. Multiple events prove that the old fresh-event
/// replay bug already rebound the namespace, so opening that database fails closed
/// instead of choosing one history arbitrarily.
pub(super) fn ensure_budget_authorization_claims(
    connection: &mut Connection,
) -> Result<(), BudgetStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let undecided_hold = transaction
        .query_row(
            r#"
            SELECT hold_id
            FROM budget_mutation_events
            WHERE kind = 'authorize_exposure'
              AND hold_id IS NOT NULL
              AND allowed IS NULL
            LIMIT 1
            "#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(hold_id) = undecided_hold {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` has an authorization event without a frozen decision"
        )));
    }
    let conflicting_hold = transaction
        .query_row(
            r#"
            SELECT hold_id
            FROM budget_mutation_events
            WHERE kind = 'authorize_exposure' AND hold_id IS NOT NULL
            GROUP BY hold_id
            HAVING COUNT(*) > 1
            LIMIT 1
            "#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(hold_id) = conflicting_hold {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` has conflicting historical authorization events"
        )));
    }

    let mismatched_claim = transaction
        .query_row(
            r#"
            SELECT claim.hold_id
            FROM budget_authorization_claims AS claim
            JOIN budget_mutation_events AS event
              ON event.hold_id = claim.hold_id
             AND event.kind = 'authorize_exposure'
            WHERE NOT (
                claim.event_id IS event.event_id
                AND claim.capability_id IS event.capability_id
                AND claim.grant_index IS event.grant_index
                AND claim.requested_exposure_units IS event.exposure_units
                AND claim.max_invocations IS event.max_invocations
                AND claim.max_exposure_per_invocation IS event.max_exposure_per_invocation
                AND claim.max_total_exposure_units IS event.max_total_exposure_units
                AND claim.authority_id IS event.authority_id
                AND claim.lease_id IS event.lease_id
                AND claim.lease_epoch IS event.lease_epoch
                AND claim.allowed IS event.allowed
            )
            LIMIT 1
            "#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(hold_id) = mismatched_claim {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` has a claim that conflicts with its authorization event"
        )));
    }

    transaction.execute(
        r#"
        INSERT INTO budget_authorization_claims (
            hold_id,
            event_id,
            capability_id,
            grant_index,
            requested_exposure_units,
            max_invocations,
            max_exposure_per_invocation,
            max_total_exposure_units,
            authority_id,
            lease_id,
            lease_epoch,
            allowed,
            created_at
        )
        SELECT
            hold_id,
            event_id,
            capability_id,
            grant_index,
            exposure_units,
            max_invocations,
            max_exposure_per_invocation,
            max_total_exposure_units,
            authority_id,
            lease_id,
            lease_epoch,
            allowed,
            recorded_at
        FROM budget_mutation_events
        WHERE kind = 'authorize_exposure'
          AND hold_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1
              FROM budget_authorization_claims AS existing
              WHERE existing.hold_id = budget_mutation_events.hold_id
          )
        "#,
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

/// Ensure the AFTER DELETE trigger that resets the ack-head watermark AND clears
/// the per-origin heads exists, so any delete from `budget_mutation_events`
/// forces `budget_ack_heads` to re-verify contiguity from genesis (fail-closed).
///
/// The trigger deliberately does NOT record the deleted seq as abandoned: a delete
/// caused by DATA LOSS (a restored older DB) must CAP the head below the hole so a
/// data-losing node cannot over-count. Only a genuine rollback-retry records the
/// abandoned seq, explicitly at its own call site.
///
/// Idempotent and non-churning: the trigger is (re)created
/// only when it is absent or an OLDER version (one that predates the per-origin
/// `budget_origin_ack_heads` clear). Steady state is a single `sqlite_master`
/// read with NO DDL, so concurrent opens on the hot status path do not take
/// repeated schema locks. In the one-time upgrade window the drop and the create
/// are BOTH idempotent (`DROP TRIGGER IF EXISTS` then `CREATE TRIGGER IF NOT
/// EXISTS`), so two opens racing the upgrade cannot fail with "trigger already
/// exists"; the momentary drop window is covered by the manual
/// `reset_budget_ack_head_watermark` calls at each delete site (belt-and-suspenders).
pub(super) fn ensure_budget_ack_head_reset_trigger(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    const TRIGGER_NAME: &str = "budget_mutation_events_reset_ack_head_watermark";
    let existing_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            rusqlite::params![TRIGGER_NAME],
            |row| row.get(0),
        )
        .optional()?;
    // Up to date iff the trigger exists AND already clears the per-origin heads.
    let up_to_date = existing_sql
        .as_deref()
        .is_some_and(|sql| sql.contains("budget_origin_ack_heads"));
    if up_to_date {
        return Ok(());
    }
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS budget_mutation_events_reset_ack_head_watermark;
        CREATE TRIGGER IF NOT EXISTS budget_mutation_events_reset_ack_head_watermark
        AFTER DELETE ON budget_mutation_events
        BEGIN
            UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1;
            DELETE FROM budget_origin_ack_heads;
        END;
        "#,
    )?;
    Ok(())
}
