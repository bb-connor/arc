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
            operation_id TEXT NOT NULL,
            request_binding_hash TEXT NOT NULL,
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
            aggregate_root_capability_id TEXT,
            aggregate_root_binding_digest TEXT,
            committed_cost_units_after INTEGER NOT NULL,
            invocation_count_after INTEGER NOT NULL,
            event_seq INTEGER NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            CHECK (
                (aggregate_root_capability_id IS NULL AND aggregate_root_binding_digest IS NULL)
                OR
                (aggregate_root_capability_id IS NOT NULL AND aggregate_root_binding_digest IS NOT NULL)
            )
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

        CREATE TABLE IF NOT EXISTS budget_composite_authorization_artifacts (
            hold_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            artifact_digest TEXT NOT NULL,
            PRIMARY KEY (hold_id, position),
            UNIQUE (hold_id, artifact_digest),
            CHECK (position >= 0 AND position < 8),
            CHECK (length(artifact_digest) = 64)
        );

        CREATE TABLE IF NOT EXISTS budget_composite_holds (
            hold_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            request_binding_hash TEXT NOT NULL,
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
            operation_id TEXT NOT NULL,
            request_binding_hash TEXT NOT NULL,
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

        CREATE TRIGGER IF NOT EXISTS budget_invocation_quota_delete_forbidden
        BEFORE DELETE ON budget_invocation_quota_usage
        BEGIN
            SELECT RAISE(ABORT, 'immutable invocation quota authority');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_managed_grant_insert_guard
        BEFORE INSERT ON budget_composite_managed_grants
        WHEN NOT EXISTS (
            SELECT 1 FROM budget_composite_authorizations
            WHERE hold_id = NEW.first_hold_id
              AND capability_id = NEW.capability_id
              AND grant_index = NEW.grant_index
        )
        BEGIN
            SELECT RAISE(ABORT, 'managed grant requires its composite authorization');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_managed_grant_update_forbidden
        BEFORE UPDATE ON budget_composite_managed_grants
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite grant authority');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_managed_grant_delete_forbidden
        BEFORE DELETE ON budget_composite_managed_grants
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite grant authority');
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

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_artifact_immutable
        BEFORE UPDATE ON budget_composite_authorization_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization artifact');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_artifact_delete_forbidden
        BEFORE DELETE ON budget_composite_authorization_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization artifact');
        END;

        "#,
    )?;
    ensure_aggregate_family_evidence_columns(connection)?;
    reject_unsafe_aggregate_family_authorizations(connection)?;
    reject_unsafe_composite_managed_grants(connection)?;
    Ok(())
}

fn reject_unsafe_composite_managed_grants(connection: &Connection) -> Result<(), BudgetStoreError> {
    let unsafe_rows = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM budget_composite_authorizations AS authorization
            WHERE NOT EXISTS (
                SELECT 1
                FROM budget_composite_managed_grants AS managed
                WHERE managed.capability_id = authorization.capability_id
                  AND managed.grant_index = authorization.grant_index
            )
        ) OR EXISTS(
            SELECT 1
            FROM budget_composite_managed_grants AS managed
            WHERE NOT EXISTS (
                SELECT 1
                FROM budget_composite_authorizations AS authorization
                WHERE authorization.hold_id = managed.first_hold_id
                  AND authorization.capability_id = managed.capability_id
                  AND authorization.grant_index = managed.grant_index
            )
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if unsafe_rows {
        return Err(BudgetStoreError::Invariant(
            "composite grant authority markers are missing, orphaned, or rebound".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_composite_budget_namespace_guards(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS budget_legacy_claim_rejects_composite_hold_id;
        DROP TRIGGER IF EXISTS budget_legacy_hold_rejects_composite_hold_id;
        DROP TRIGGER IF EXISTS budget_composite_authorization_rejects_legacy_hold_id;

        CREATE TRIGGER IF NOT EXISTS budget_legacy_claim_rejects_composite_hold_id_v2
        BEFORE INSERT ON budget_authorization_claims
        WHEN EXISTS (
            SELECT 1 FROM budget_composite_authorizations
            WHERE hold_id = NEW.hold_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'hold_id belongs to a composite authorization');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_legacy_hold_rejects_composite_hold_id_v2
        BEFORE INSERT ON budget_authorization_holds
        WHEN EXISTS (
            SELECT 1 FROM budget_composite_authorizations
            WHERE hold_id = NEW.hold_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'hold_id belongs to a composite authorization');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_authorization_requires_owned_base_hold_v2
        BEFORE INSERT ON budget_composite_authorizations
        WHEN EXISTS (
            SELECT 1 FROM budget_authorization_claims
            WHERE hold_id = NEW.hold_id
        ) OR (
            NEW.allowed = 0
            AND (
                EXISTS (
                    SELECT 1 FROM budget_authorization_holds
                    WHERE hold_id = NEW.hold_id
                )
                OR EXISTS (
                    SELECT 1 FROM budget_composite_holds
                    WHERE hold_id = NEW.hold_id
                )
            )
        ) OR (
            NEW.allowed = 1
            AND NOT EXISTS (
                SELECT 1
                FROM budget_authorization_holds AS hold
                WHERE hold.hold_id = NEW.hold_id
                  AND hold.operation_id IS NEW.operation_id
                  AND hold.request_binding_hash IS NEW.request_binding_hash
                  AND hold.capability_id IS NEW.capability_id
                  AND hold.grant_index IS NEW.grant_index
                  AND hold.authorized_exposure_units IS NEW.requested_exposure_units
                  AND hold.remaining_exposure_units IS NEW.requested_exposure_units
                  AND hold.invocation_count_debited = 1
                  AND hold.disposition = 'open'
                  AND hold.authority_id IS NEW.authority_id
                  AND hold.lease_id IS NEW.lease_id
                  AND hold.lease_epoch IS NEW.lease_epoch
            )
        ) OR (
            NEW.allowed = 1
            AND NOT EXISTS (
                SELECT 1
                FROM budget_composite_holds AS hold
                WHERE hold.hold_id = NEW.hold_id
                  AND hold.operation_id IS NEW.operation_id
                  AND hold.request_binding_hash IS NEW.request_binding_hash
                  AND hold.invocation_state IS NEW.invocation_state
                  AND hold.monetary_state IS NEW.monetary_state
                  AND hold.revocation_set_digest IS NEW.revocation_set_digest
                  AND hold.revocation_ids_json IS NEW.revocation_ids_json
                  AND hold.remaining_exposure_units IS NEW.requested_exposure_units
            )
        ) OR NOT EXISTS (
            SELECT 1
            FROM budget_mutation_events AS event
            WHERE event.event_id = NEW.event_id
              AND event.hold_id IS NEW.hold_id
              AND event.operation_id IS NEW.operation_id
              AND event.request_binding_hash IS NEW.request_binding_hash
              AND event.capability_id IS NEW.capability_id
              AND event.grant_index IS NEW.grant_index
              AND event.kind = 'reserve_invocations'
              AND event.allowed IS NEW.allowed
              AND event.event_seq IS NEW.event_seq
              AND event.exposure_units IS NEW.requested_exposure_units
              AND event.max_exposure_per_invocation IS NEW.max_cost_per_invocation
              AND event.max_total_exposure_units IS NEW.max_total_cost_units
              AND event.authority_id IS NEW.authority_id
              AND event.lease_id IS NEW.lease_id
              AND event.lease_epoch IS NEW.lease_epoch
        )
        BEGIN
            SELECT RAISE(ABORT, 'composite authorization lacks matching admission-owned rows');
        END;
        "#,
    )?;
    reject_inconsistent_composite_budget_ownership(connection)
}

fn reject_inconsistent_composite_budget_ownership(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let inconsistent = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM budget_composite_authorizations AS authorization
            WHERE EXISTS (
                SELECT 1
                FROM budget_authorization_claims AS claim
                WHERE claim.hold_id = authorization.hold_id
            )
            OR (
                authorization.allowed = 0
                AND (
                    EXISTS (
                        SELECT 1
                        FROM budget_authorization_holds AS hold
                        WHERE hold.hold_id = authorization.hold_id
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM budget_composite_holds AS hold
                        WHERE hold.hold_id = authorization.hold_id
                    )
                )
            )
            OR (
                authorization.allowed = 1
                AND NOT EXISTS (
                    SELECT 1
                    FROM budget_authorization_holds AS hold
                    WHERE hold.hold_id = authorization.hold_id
                      AND hold.operation_id IS authorization.operation_id
                      AND hold.request_binding_hash IS authorization.request_binding_hash
                      AND hold.capability_id IS authorization.capability_id
                      AND hold.grant_index IS authorization.grant_index
                      AND hold.authorized_exposure_units IS authorization.requested_exposure_units
                )
            )
            OR (
                authorization.allowed = 1
                AND NOT EXISTS (
                    SELECT 1
                    FROM budget_composite_holds AS hold
                    WHERE hold.hold_id = authorization.hold_id
                      AND hold.operation_id IS authorization.operation_id
                      AND hold.request_binding_hash IS authorization.request_binding_hash
                )
            )
            OR NOT EXISTS (
                SELECT 1
                FROM budget_mutation_events AS event
                WHERE event.event_id = authorization.event_id
                  AND event.hold_id IS authorization.hold_id
                  AND event.operation_id IS authorization.operation_id
                  AND event.request_binding_hash IS authorization.request_binding_hash
                  AND event.capability_id IS authorization.capability_id
                  AND event.grant_index IS authorization.grant_index
                  AND event.kind = 'reserve_invocations'
                  AND event.allowed IS authorization.allowed
                  AND event.event_seq IS authorization.event_seq
                  AND event.exposure_units IS authorization.requested_exposure_units
                  AND event.max_exposure_per_invocation IS authorization.max_cost_per_invocation
                  AND event.max_total_exposure_units IS authorization.max_total_cost_units
                  AND event.authority_id IS authorization.authority_id
                  AND event.lease_id IS authorization.lease_id
                  AND event.lease_epoch IS authorization.lease_epoch
            )
            OR NOT EXISTS (
                SELECT 1
                FROM budget_composite_mutation_snapshots AS snapshot
                WHERE snapshot.event_id = authorization.event_id
                  AND snapshot.operation_id IS authorization.operation_id
                  AND snapshot.request_binding_hash IS authorization.request_binding_hash
                  AND snapshot.invocation_state IS authorization.invocation_state
                  AND snapshot.monetary_state IS authorization.monetary_state
                  AND snapshot.revocation_set_digest IS authorization.revocation_set_digest
                  AND snapshot.revocation_ids_json IS authorization.revocation_ids_json
            )
        )
        OR EXISTS(
            SELECT 1
            FROM budget_composite_holds AS hold
            WHERE NOT EXISTS (
                SELECT 1
                FROM budget_composite_authorizations AS authorization
                WHERE authorization.allowed = 1
                  AND authorization.hold_id = hold.hold_id
                  AND authorization.operation_id IS hold.operation_id
                  AND authorization.request_binding_hash IS hold.request_binding_hash
            )
        )
        OR EXISTS(
            SELECT 1
            FROM budget_composite_mutation_snapshots AS snapshot
            WHERE NOT EXISTS (
                SELECT 1
                FROM budget_mutation_events AS event
                WHERE event.event_id = snapshot.event_id
                  AND event.operation_id IS snapshot.operation_id
                  AND event.request_binding_hash IS snapshot.request_binding_hash
            )
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if inconsistent {
        return Err(BudgetStoreError::Invariant(
            "budget database contains inconsistent composite admission ownership".to_string(),
        ));
    }
    Ok(())
}

fn ensure_aggregate_family_evidence_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_composite_authorizations)")?;
    let existing = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for column in [
        "aggregate_root_capability_id",
        "aggregate_root_binding_digest",
    ] {
        if !existing.iter().any(|existing| existing == column) {
            connection.execute(
                &format!("ALTER TABLE budget_composite_authorizations ADD COLUMN {column} TEXT"),
                [],
            )?;
        }
    }
    Ok(())
}

fn reject_unsafe_aggregate_family_authorizations(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let unsafe_rows = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM budget_composite_authorizations AS authorization
            WHERE
                (authorization.aggregate_root_capability_id IS NULL)
                    != (authorization.aggregate_root_binding_digest IS NULL)
                OR (
                    EXISTS(
                        SELECT 1
                        FROM budget_composite_authorization_quotas AS quota
                        WHERE quota.hold_id = authorization.hold_id
                          AND quota.profile = 'chio.aggregate-family-invocation.v1'
                    )
                    != (authorization.aggregate_root_capability_id IS NOT NULL)
                )
                OR (
                    SELECT COUNT(*)
                    FROM budget_composite_authorization_quotas AS quota
                    WHERE quota.hold_id = authorization.hold_id
                      AND quota.profile = 'chio.aggregate-family-invocation.v1'
                ) > 1
                OR (
                    authorization.aggregate_root_capability_id IS NOT NULL
                    AND (
                        length(authorization.aggregate_root_capability_id) NOT BETWEEN 1 AND 512
                        OR instr(authorization.aggregate_root_capability_id, char(0)) != 0
                        OR length(authorization.aggregate_root_binding_digest) != 64
                        OR authorization.aggregate_root_binding_digest GLOB '*[^0-9a-f]*'
                    )
                )
        )
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if unsafe_rows != 0 {
        return Err(BudgetStoreError::Invariant(
            "budget database contains aggregate-family authorizations without complete authenticated root identity evidence"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_budget_admission_operation_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    for (table, columns) in [
        (
            "budget_authorization_holds",
            ["operation_id", "request_binding_hash"],
        ),
        (
            "budget_mutation_events",
            ["operation_id", "request_binding_hash"],
        ),
        (
            "budget_composite_authorizations",
            ["operation_id", "request_binding_hash"],
        ),
        (
            "budget_composite_holds",
            ["operation_id", "request_binding_hash"],
        ),
        (
            "budget_composite_mutation_snapshots",
            ["operation_id", "request_binding_hash"],
        ),
    ] {
        let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
        let existing = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for column in columns {
            if !existing.iter().any(|existing| existing.as_str() == column) {
                connection.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"), [])?;
            }
        }
    }
    let unsafe_rows = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM budget_composite_authorizations
            WHERE operation_id IS NULL OR request_binding_hash IS NULL
            UNION ALL
            SELECT 1 FROM budget_composite_holds
            WHERE operation_id IS NULL OR request_binding_hash IS NULL
            UNION ALL
            SELECT 1 FROM budget_composite_mutation_snapshots
            WHERE operation_id IS NULL OR request_binding_hash IS NULL
            UNION ALL
            SELECT 1
            FROM budget_mutation_events AS event
            JOIN budget_composite_authorizations AS authorization
              ON authorization.hold_id = event.hold_id
            WHERE event.operation_id IS NULL OR event.request_binding_hash IS NULL
            UNION ALL
            SELECT 1
            FROM budget_authorization_holds AS hold
            JOIN budget_composite_authorizations AS authorization
              ON authorization.hold_id = hold.hold_id
            WHERE hold.operation_id IS NULL OR hold.request_binding_hash IS NULL
            UNION ALL
            SELECT 1 FROM budget_mutation_events
            WHERE (operation_id IS NULL) != (request_binding_hash IS NULL)
            UNION ALL
            SELECT 1 FROM budget_authorization_holds
            WHERE (operation_id IS NULL) != (request_binding_hash IS NULL)
        )
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if unsafe_rows != 0 {
        return Err(BudgetStoreError::Invariant(
            "budget database contains admission-owned rows without complete operation_id and request_binding_hash; ownership cannot be inferred safely"
                .to_string(),
        ));
    }
    connection.execute_batch(
        r#"
        CREATE TRIGGER IF NOT EXISTS budget_authorization_hold_admission_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_authorization_holds
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable budget hold admission owner');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_mutation_event_admission_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_mutation_events
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable budget mutation admission owner');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_hold_admission_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_composite_holds
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite hold admission owner');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_composite_mutation_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_composite_mutation_snapshots
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite mutation admission owner');
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
