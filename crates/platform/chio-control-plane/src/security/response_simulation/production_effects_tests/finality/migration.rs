use super::*;

const TABLE: &str = "security_response_effect_finality";
const UPDATE_TRIGGER: &str = "security_response_effect_finality_immutable";
const DELETE_TRIGGER: &str = "security_response_effect_finality_delete_rejected";

#[derive(Debug, PartialEq)]
struct SchemaSnapshot {
    rows: Vec<(String, Vec<Vec<Value>>)>,
    catalog: Vec<(String, String, String, Option<String>)>,
    stamp: i32,
    schema_version: i64,
    application_id: i64,
}

fn open_connection(case: &FinalityCase) -> rusqlite::Connection {
    rusqlite::Connection::open(case.fixture._directory.path().join("production-effects.db"))
        .unwrap_or_else(|error| panic!("open finality fixture: {error}"))
}

fn schema_snapshot(case: &FinalityCase) -> SchemaSnapshot {
    let connection = open_connection(case);
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
        )
        .unwrap_or_else(|error| panic!("prepare finality schema snapshot: {error}"));
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap_or_else(|error| panic!("read finality schema snapshot: {error}"))
        .map(|row| row.unwrap_or_else(|error| panic!("finality schema row: {error}")))
        .collect();
    SchemaSnapshot {
        rows: case.snapshot(),
        catalog,
        stamp: connection
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("security schema stamp: {error}")),
        schema_version: connection
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("SQLite schema version: {error}")),
        application_id: connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("SQLite application identity: {error}")),
    }
}

fn reopen(case: &FinalityCase) -> PortResult<SqliteSecurityStateStore> {
    SqliteSecurityStateStore::open_with_trusted_clock(
        case.fixture._directory.path().join("production-effects.db"),
        Arc::clone(&case.fixture.trusted_clock),
    )
}

fn remove_marker_schema(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS security_response_effect_finality_immutable; \
         DROP TRIGGER IF EXISTS security_response_effect_finality_delete_rejected; \
         DROP TABLE IF EXISTS security_response_effect_finality;",
        )
        .unwrap_or_else(|error| panic!("legacy-only fixture inverse: {error}"));
}

fn command_table(kind: ResponseEffectKind) -> &'static str {
    match kind {
        ResponseEffectKind::SuspendSession => "security_containment_overlay_commands",
        ResponseEffectKind::RestrictEgress => "security_egress_restriction_commands",
        ResponseEffectKind::ThrottleSession => "security_session_throttle_commands",
        ResponseEffectKind::SuspendCapabilitySet => "security_capability_set_suspension_commands",
        _ => panic!("unexpected overlay command kind"),
    }
}

#[test]
fn legacy0_completed_lifts_backfill_without_changing_original_journal_bytes() {
    for (index, kind) in REMOVABLE_KINDS.into_iter().enumerate() {
        let label = format!("legacy-backfill-{index}");
        let case = FinalityCase::new(kind, &label);
        let removed = case.remove_original(&label);
        let connection = open_connection(&case);
        // This is a fixture inverse only. It retains the actual completed
        // legacy journal, aggregates, leases and preparation, without creating
        // fake command history or weakening the serving schema.
        remove_marker_schema(&connection);
        connection.execute(
            "UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state'",
            [],
        ).unwrap_or_else(|error| panic!("legacy fixture stamp: {error}"));
        let journal_table = command_table(kind);
        let original_journal = case
            .snapshot()
            .into_iter()
            .find(|(name, _)| name == journal_table)
            .unwrap_or_else(|| panic!("original journal absent"));
        drop(connection);
        let reopened = reopen(&case).unwrap_or_else(|error| panic!("legacy migration: {error}"));
        let connection = open_connection(&case);
        let stamp: i32 = connection
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("migrated stamp: {error}"));
        assert_eq!(stamp, 1);
        let marker: (String, String) = connection
            .query_row(
                "SELECT action_id, remove_idempotency_key FROM security_response_effect_finality \
             WHERE tenant_id = ?1 AND effect_id = ?2",
                rusqlite::params![
                    removed.remove.tenant_id.as_str(),
                    removed.remove.effect_id.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or_else(|error| panic!("verified legacy marker: {error}"));
        assert_eq!(
            marker,
            (
                removed.remove.action_id.as_str().to_owned(),
                removed.remove.idempotency_key.as_str().to_owned()
            )
        );
        assert_eq!(
            case.snapshot()
                .into_iter()
                .find(|(name, _)| name == journal_table),
            Some(original_journal)
        );
        let before = case.snapshot();
        let restarted_effects = case.fixture.effects();
        for (request, result) in [
            (&removed.apply, &removed.applied),
            (&removed.remove, &removed.removed),
        ] {
            assert_eq!(
                restarted_effects
                    .execute(request)
                    .unwrap_or_else(|error| panic!("legacy exact replay: {error}")),
                *result
            );
            assert_eq!(case.snapshot(), before);
            assert!(case.installed_ids().is_empty());
        }
        let mut fresh = removed.apply;
        fresh.idempotency_key = record(format!("response_effect_command:{label}-fresh"));
        assert_eq!(
            restarted_effects
                .execute(&fresh)
                .map_err(|error| error.kind()),
            Err(PortErrorKind::Conflict)
        );
        assert_eq!(case.snapshot(), before);
        drop(reopened);
    }
}

#[test]
fn revision1_missing_or_foreign_marker_schema_is_refused_before_normalization() {
    for damage in [
        "missing",
        "foreign-columns",
        "extra-index",
        "missing-update-trigger",
    ] {
        let case = FinalityCase::new(ResponseEffectKind::RestrictEgress, damage);
        case.remove_original(damage);
        let connection = open_connection(&case);
        match damage {
            "missing" => remove_marker_schema(&connection),
            "foreign-columns" => {
                remove_marker_schema(&connection);
                connection.execute_batch(
                    "CREATE TABLE security_response_effect_finality (tenant_id TEXT, effect_id TEXT PRIMARY KEY, unchecked_json TEXT)",
                ).unwrap_or_else(|error| panic!("foreign marker fixture: {error}"));
            }
            "extra-index" => connection.execute_batch(
                "CREATE INDEX foreign_finality_lookup ON security_response_effect_finality(effect_id)",
            ).unwrap_or_else(|error| panic!("foreign marker index: {error}")),
            "missing-update-trigger" => connection.execute_batch(
                "DROP TRIGGER security_response_effect_finality_immutable",
            ).unwrap_or_else(|error| panic!("missing marker trigger: {error}")),
            _ => panic!("unexpected schema damage"),
        }
        connection.execute(
            "UPDATE chio_store_schema_versions SET version = 1 WHERE store_key = 'security_state'",
            [],
        ).unwrap_or_else(|error| panic!("revision1 fixture stamp: {error}"));
        drop(connection);
        let before = schema_snapshot(&case);
        let error = reopen(&case)
            .err()
            .unwrap_or_else(|| panic!("damaged revision1 schema was normalized: {damage}"));
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
        assert_eq!(schema_snapshot(&case), before);
    }
}

#[test]
fn marker_update_and_delete_are_denied_and_missing_coverage_is_not_rebuilt() {
    let case = FinalityCase::new(ResponseEffectKind::ThrottleSession, "marker-immutable");
    case.remove_original("marker-immutable");
    let connection = open_connection(&case);
    let before = schema_snapshot(&case);
    assert!(connection
        .execute(
            "UPDATE security_response_effect_finality SET action_id = 'foreign-action'",
            []
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM security_response_effect_finality", [])
        .is_err());
    assert_eq!(schema_snapshot(&case), before);
    let deletion_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [DELETE_TRIGGER],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("retained deletion trigger: {error}"));
    connection
        .execute_batch(&format!(
            "DROP TRIGGER {DELETE_TRIGGER}; DELETE FROM {TABLE}; {deletion_sql};"
        ))
        .unwrap_or_else(|error| panic!("offline missing-marker fixture: {error}"));
    drop(connection);
    let before = schema_snapshot(&case);
    let error = reopen(&case)
        .err()
        .unwrap_or_else(|| panic!("revision1 missing removal coverage was rebuilt"));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(schema_snapshot(&case), before);
}

#[test]
fn missing_referenced_remove_and_rehashed_foreign_marker_fail_closed() {
    for damage in ["missing-remove", "rehashed-foreign-marker"] {
        let case = FinalityCase::new(ResponseEffectKind::SuspendSession, damage);
        let removed = case.remove_original(damage);
        let connection = open_connection(&case);
        if damage == "missing-remove" {
            assert_eq!(connection.execute(
                "DELETE FROM security_containment_overlay_commands WHERE tenant_id = ?1 AND idempotency_key = ?2",
                rusqlite::params![removed.remove.tenant_id.as_str(), removed.remove.idempotency_key.as_str()],
            ).unwrap_or_else(|error| panic!("missing referenced journal fixture: {error}")), 1);
        } else {
            let update_sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [UPDATE_TRIGGER],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("retained update trigger: {error}"));
            let bytes: Vec<u8> = connection
                .query_row(
                    "SELECT marker_body FROM security_response_effect_finality",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("marker body fixture: {error}"));
            let mut body: serde_json::Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("decode real marker fixture: {error}"));
            body["action_id"] = serde_json::json!("foreign-action");
            let bytes = canonical_json_bytes(&body)
                .unwrap_or_else(|error| panic!("rehash foreign marker: {error}"));
            let hash = chio_core::sha256(&bytes);
            connection
                .execute_batch(&format!("DROP TRIGGER {UPDATE_TRIGGER}"))
                .unwrap_or_else(|error| panic!("offline marker fixture: {error}"));
            assert_eq!(connection.execute(
                "UPDATE security_response_effect_finality SET action_id = 'foreign-action', marker_body = ?1, marker_body_hash = ?2",
                rusqlite::params![bytes, hash.as_bytes().as_slice()],
            ).unwrap_or_else(|error| panic!("rehashed foreign marker fixture: {error}")), 1);
            connection
                .execute_batch(&update_sql)
                .unwrap_or_else(|error| panic!("restore exact marker trigger: {error}"));
        }
        drop(connection);
        let before = schema_snapshot(&case);
        let mut fresh = removed.apply;
        fresh.idempotency_key = record(format!("response_effect_command:{damage}-fresh"));
        assert_eq!(
            case.effects.execute(&fresh).map_err(|error| error.kind()),
            Err(PortErrorKind::IntegrityFailure)
        );
        assert_eq!(schema_snapshot(&case), before);
        assert!(case.installed_ids().is_empty());
    }
}

#[test]
fn upgraded_revision1_is_refused_by_the_actual_legacy_writer_version_gate() {
    let case = FinalityCase::new(ResponseEffectKind::RestrictEgress, "old-writer");
    case.remove_original("old-writer");
    let connection = open_connection(&case);
    let before = schema_snapshot(&case);
    assert_eq!(before.stamp, 1);
    let result = chio_store_sqlite::check_schema_version(
        &connection,
        "security_state",
        0,
        &["security_flow_contexts"],
    );
    assert!(matches!(
        result,
        Err(chio_store_sqlite::SchemaVersionError::FutureSchema {
            found: 1,
            supported: 0
        })
    ));
    assert_eq!(schema_snapshot(&case), before);
}

#[test]
fn concurrent_connections_cannot_reinstall_an_effect_after_the_real_remove_commits() {
    for (index, kind) in REMOVABLE_KINDS.into_iter().enumerate() {
        for attempt in 0..4 {
            let label = format!("atomic-lift-{index}-{attempt}");
            let case = FinalityCase::new(kind, &label);
            let apply = case.request(&format!("{label}-original"));
            let applied = case
                .effects
                .execute(&apply)
                .unwrap_or_else(|error| panic!("original concurrent Apply: {error}"));
            assert!(applied.applied);
            let mut remove = case.request(&format!("{label}-remove"));
            remove.operation = EffectOperation::Remove;
            remove.expected_version_hash = applied.resulting_version_hash;
            let mut concurrent_apply = apply.clone();
            concurrent_apply.idempotency_key =
                record(format!("response_effect_command:{label}-concurrent"));
            let other_store = Arc::new(
                reopen(&case).unwrap_or_else(|error| panic!("second real connection: {error}")),
            );
            let blast: Arc<dyn BlastRadiusPort> = case.fixture.resolver.clone();
            let other_effects = production_response_effects(
                ResponseExecutionMode::Live,
                other_store,
                Arc::clone(&case.fixture.outbox),
                blast,
                Arc::clone(&case.fixture.trusted_clock),
            )
            .unwrap_or_else(|error| panic!("second real effect router: {error}"));
            let start = Arc::new(std::sync::Barrier::new(3));
            let (removed, concurrent) = std::thread::scope(|scope| {
                let remove_start = Arc::clone(&start);
                let apply_start = Arc::clone(&start);
                let remove_effects = Arc::clone(&case.effects);
                let apply_effects = Arc::clone(&other_effects);
                let remove_request = remove.clone();
                let apply_request = concurrent_apply.clone();
                let remove_handle = scope.spawn(move || {
                    remove_start.wait();
                    remove_effects.execute(&remove_request)
                });
                let apply_handle = scope.spawn(move || {
                    apply_start.wait();
                    apply_effects.execute(&apply_request)
                });
                start.wait();
                (
                    remove_handle
                        .join()
                        .unwrap_or_else(|_| panic!("real Remove thread panicked")),
                    apply_handle
                        .join()
                        .unwrap_or_else(|_| panic!("real Apply thread panicked")),
                )
            });
            assert!(
                !removed
                    .unwrap_or_else(|error| panic!("concurrent Remove: {error}"))
                    .applied
            );
            match concurrent {
                Ok(result) => assert_eq!(result, applied),
                Err(error) if error.kind() == PortErrorKind::Conflict => {}
                Err(error) if error.kind() == PortErrorKind::IntegrityFailure => {
                    // Some backends recheck their committed aggregate after
                    // returning from the store. Removal can win that read;
                    // it is acceptable only with the exact durable Apply.
                    assert_eq!(
                        other_effects
                            .load_result(&query(&concurrent_apply))
                            .unwrap_or_else(|read_error| panic!(
                                "concurrent Apply readback: {read_error}"
                            )),
                        EffectExecutionStatus::Completed {
                            result: applied.clone()
                        }
                    );
                }
                Err(error) => panic!("unexpected concurrent Apply error: {error}"),
            }
            assert!(
                case.installed_ids().is_empty(),
                "a cross-connection Apply committed after removal and resurrected {kind:?}"
            );
            let mut after = apply;
            after.idempotency_key = record(format!("response_effect_command:{label}-after"));
            let before = case.snapshot();
            assert_eq!(
                case.effects.execute(&after).map_err(|error| error.kind()),
                Err(PortErrorKind::Conflict)
            );
            assert_eq!(case.snapshot(), before);
        }
    }
}
