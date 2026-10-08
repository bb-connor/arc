//! Finding status schema initialization and whole-store invariants.

use super::*;

pub(crate) fn initialize_finding_status_schema(
    connection: &mut Connection,
) -> Result<(), FindingStatusStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FINDING_STATUS_SCHEMA_KEY,
        FINDING_STATUS_SUPPORTED_SCHEMA_VERSION,
        FINDING_STATUS_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FINDING_STATUS_SUPPORTED_SCHEMA_VERSION {
        return verify_finding_status_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    if on_disk == 1 {
        // Revision 2 starts the enforceable inclusion window at finality.
        // The only schema change is the lifecycle trigger that permits the
        // waiting-to-eligible edge to atomically replace the provisional
        // timestamps with that finality-derived window.
        transaction
            .execute_batch("DROP TRIGGER IF EXISTS finding_retraction_intents_lifecycle;")
            .map_err(sqlite_error)?;
    }
    if (1..=4).contains(&on_disk) {
        // Revision 3 permits authenticated revocation-state changes for the
        // same operator key and key epoch. Key substitution remains fenced.
        // Revision 3 permits deletion of superseded non-inclusion proofs, and
        // revision 5 extends that bounded retention to inclusion proofs.
        // Recreate both changed triggers because older databases retain a
        // stricter proof-retention definition. Revision 4 also lets an otherwise
        // unchanged feed floor advance its trusted-time high-water.
        transaction
            .execute_batch(
                "DROP TRIGGER IF EXISTS finding_status_feed_floors_monotonic;\
                 DROP TRIGGER IF EXISTS finding_status_proofs_no_delete;",
            )
            .map_err(sqlite_error)?;
    }
    transaction
        .execute_batch(FINDING_STATUS_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FINDING_STATUS_SCHEMA_KEY,
        FINDING_STATUS_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_finding_status_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_finding_status_invariants(
    connection: &Connection,
) -> Result<(), FindingStatusStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_STATUS_SCHEMA)
        .map_err(sqlite_error)?;
    if finding_status_schema_catalog(connection)? != finding_status_schema_catalog(&expected)? {
        return Err(invariant(
            "finding status schema differs from the canonical definition",
        ));
    }
    verify_status_content_invariants(connection)
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

pub(super) fn finding_status_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingStatusStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name LIKE 'finding_status_%'
               OR tbl_name LIKE 'finding_status_%'
               OR name LIKE 'finding_retraction_%'
               OR tbl_name LIKE 'finding_retraction_%'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(catalog)
}

pub(super) fn verify_status_content_invariants(
    connection: &Connection,
) -> Result<(), FindingStatusStoreError> {
    let missing_floor_epoch: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_status_feed_floors f
                LEFT JOIN finding_status_epochs e
                  ON e.feed_id = f.feed_id AND e.map_epoch = f.map_epoch
                WHERE e.feed_id IS NULL
                   OR e.epoch_id <> f.epoch_id
                   OR e.root_hash <> f.root_hash
                   OR e.signed_epoch_sha256 <> f.signed_epoch_sha256
                   OR e.operator_id <> f.operator_id
                   OR e.key_domain_nonce <> f.key_domain_nonce
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if missing_floor_epoch {
        return Err(invariant(
            "finding status floor is missing its exact retained epoch",
        ));
    }

    let epoch_without_floor: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_status_epochs e
                LEFT JOIN finding_status_feed_floors f
                  ON f.feed_id = e.feed_id
                WHERE f.feed_id IS NULL
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if epoch_without_floor {
        return Err(invariant(
            "retained finding status epoch is missing its feed floor",
        ));
    }

    let missing_sticky_state: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_retraction_intents i
                LEFT JOIN finding_status_states s
                  ON s.feed_id = i.feed_id AND s.finding_id = i.finding_id
                WHERE s.finding_id IS NULL
                   OR s.retraction_intent_sha256 <> i.intent_sha256
                   OR (i.state = 'published' AND s.state <> 'retracted')
                   OR (i.state <> 'published' AND s.state <> 'pending')
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if missing_sticky_state {
        return Err(invariant(
            "finding retraction intent is missing its sticky status state",
        ));
    }
    let missing_leaf_state: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_status_leaves l
                LEFT JOIN finding_status_states s
                  ON s.feed_id = l.feed_id AND s.finding_id = l.finding_id
                WHERE s.finding_id IS NULL
                   OR s.state <> 'retracted'
                   OR s.retraction_intent_sha256
                      <> l.retraction_intent_sha256
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if missing_leaf_state {
        return Err(invariant(
            "finding status leaf is missing its sticky retracted state",
        ));
    }
    Ok(())
}
