// Schema initialization and catalog checks.

pub(crate) fn initialize_finding_challenge_schema(
    schema: &crate::schema_version::SchemaTransaction<'_>,
) -> std::result::Result<(), FindingChallengeStoreError> {
    let transaction = schema.connection();

    if schema.is_fresh() {
        transaction
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .map_err(sqlite_error)?;

        schema
            .stamp(FINDING_CHALLENGE_SCHEMA_KEY)
            .map_err(|error| invariant(error.to_string()))?;
    }
    verify_finding_challenge_invariants(transaction)
}

/// Verify the challenge schema's shape: this database's table, index, and
/// trigger definitions against a freshly created canonical schema. The
/// cost is a handful of `sqlite_schema` rows, independent of how many
/// challenges have accumulated, so this runs on every open.
///
/// Fails closed: any schema-shape difference rejects the open, because a
/// missing lifecycle trigger is exactly the difference between a state
/// machine and a mutable row.
pub(crate) fn verify_finding_challenge_invariants(
    connection: &Connection,
) -> Result<(), FindingChallengeStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .map_err(sqlite_error)?;
    let actual = finding_challenge_schema_catalog(connection)?;
    let canonical = finding_challenge_schema_catalog(&expected)?;
    if actual != canonical {
        return Err(invariant(
            "finding challenge schema differs from the canonical definition",
        ));
    }
    verify_challenge_submissions(connection)?;
    let invalid_authorization_coverage = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM liability_heads AS liability
                LEFT JOIN finding_finalizing_authorizations AS authorization
                  ON authorization.liability_key = liability.liability_key
                WHERE liability.state = 'finalizing'
                  AND authorization.liability_key IS NULL
            ) OR EXISTS(
                SELECT 1 FROM finding_finalizing_authorizations AS authorization
                JOIN liability_heads AS liability
                  ON liability.liability_key = authorization.liability_key
                WHERE liability.state NOT IN ('finalizing', 'settled')
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_authorization_coverage {
        return Err(invariant("finalizing authorization coverage is not exact"));
    }
    let invalid_authorization_refresh = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_finalizing_authorization_refreshes AS refresh
                JOIN liability_heads AS liability
                  ON liability.liability_key = refresh.liability_key
                WHERE liability.state NOT IN ('finalizing', 'settled')
            ) OR EXISTS(
                SELECT 1
                FROM finding_finalizing_authorization_refreshes AS refresh
                WHERE (
                    refresh.refresh_ordinal = 1
                    AND refresh.previous_authorization_sha256 <> (
                        SELECT base.authorization_sha256
                        FROM finding_finalizing_authorizations AS base
                        WHERE base.liability_key = refresh.liability_key
                    )
                ) OR (
                    refresh.refresh_ordinal > 1
                    AND NOT EXISTS(
                        SELECT 1
                        FROM finding_finalizing_authorization_refreshes AS previous
                        WHERE previous.liability_key = refresh.liability_key
                          AND previous.refresh_ordinal = refresh.refresh_ordinal - 1
                          AND previous.authorization_sha256 =
                              refresh.previous_authorization_sha256
                          AND previous.recorded_at < refresh.recorded_at
                    )
                )
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_authorization_refresh {
        return Err(invariant(
            "finalizing authorization refresh lineage is invalid",
        ));
    }
    let invalid_seller_reconciliation = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM effect_intents AS intent
                LEFT JOIN finding_seller_impairment_reconciliations AS reconciliation
                  ON reconciliation.intent_key = intent.intent_key
                WHERE intent.kind = 'seller_impair'
                  AND intent.settlement_required = 1
                  AND intent.state = 'confirmed'
                  AND reconciliation.intent_key IS NULL
            ) OR EXISTS(
                SELECT 1
                FROM finding_seller_impairment_reconciliations AS reconciliation
                LEFT JOIN effect_intents AS intent
                  ON intent.intent_key = reconciliation.intent_key
                WHERE intent.intent_key IS NULL
                   OR intent.kind <> 'seller_impair'
                   OR intent.settlement_required <> 1
                   OR intent.state <> 'confirmed'
                   OR intent.liability_key <> reconciliation.liability_key
                   OR intent.intent_digest <> reconciliation.intent_digest
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_seller_reconciliation {
        return Err(invariant(
            "confirmed seller impairment reconciliation coverage is not exact",
        ));
    }
    verify_effect_root_refresh_invariants(connection)?;
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn finding_challenge_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingChallengeStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'challenges*' OR tbl_name GLOB 'challenges*'
               OR name GLOB 'finding_challenge_submissions*'
               OR tbl_name GLOB 'finding_challenge_submissions*'
               OR name GLOB 'finding_challenge_outcomes*'
               OR tbl_name GLOB 'finding_challenge_outcomes*'
               OR name GLOB 'dispute_locks*' OR tbl_name GLOB 'dispute_locks*'
               OR name GLOB 'liability_heads*'
               OR tbl_name GLOB 'liability_heads*'
               OR name GLOB 'finding_finalizing_authorizations*'
               OR tbl_name GLOB 'finding_finalizing_authorizations*'
               OR name GLOB 'finding_finalizing_authorization_refreshes*'
               OR tbl_name GLOB 'finding_finalizing_authorization_refreshes*'
               OR name GLOB 'governance_case_index*'
               OR tbl_name GLOB 'governance_case_index*'
               OR name GLOB 'claim_snapshots*'
               OR tbl_name GLOB 'claim_snapshots*'
               OR name GLOB 'effect_intents*'
               OR tbl_name GLOB 'effect_intents*'
               OR name GLOB 'finding_seller_impairment_reconciliations*'
               OR tbl_name GLOB 'finding_seller_impairment_reconciliations*'
               OR name GLOB 'effect_root_bindings*'
               OR tbl_name GLOB 'effect_root_bindings*'
               ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}
