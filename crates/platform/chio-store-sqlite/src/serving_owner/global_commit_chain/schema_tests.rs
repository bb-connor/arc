use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn create_catalog(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let transaction = connection.unchecked_transaction()?;
    let schema = crate::schema_version::SchemaTransaction::from_transaction(
        transaction,
        &["global_catalog_test"],
    )
    .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    initialize_global_commit_schema(&schema)?;
    schema
        .stamp("global_catalog_test")
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    schema
        .commit()
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))
}

fn seed_history(connection: &Connection) -> TestResult {
    let transaction = connection.unchecked_transaction()?;
    let reference = sha256_hex(b"global-catalog-baseline");
    let projection = projection_root_digest(&ProjectionRootEntry {
        format: "chio.sqlite-authority-projection-root.v1",
        previous_projection_digest: GLOBAL_GENESIS_DIGEST,
        commit_sequence: 1,
        mutation_kind: "baseline",
        projection_kind: "baseline",
        projection_key: "",
        projection_sequence: 0,
        projection_reference_digest: &reference,
    })?;
    append_entry(
        &transaction,
        "baseline",
        "baseline",
        "",
        0,
        &reference,
        &projection,
        "global-catalog-fixture",
        None,
        0,
    )?;
    transaction.commit()?;
    Ok(())
}

fn history_bytes(connection: &Connection) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(canonical_json_bytes(&table_snapshot(
        connection,
        "authority_global_commits",
        None,
    )?)?)
}

fn assert_catalog_refused(connection: &Connection) {
    match verify_global_commit_schema(connection) {
        Err(SqliteServingOwnerError::Invalid(message)) => {
            assert_eq!(message, "global authority commit schema is not canonical");
        }
        other => panic!("expected exact global catalog refusal, got {other:?}"),
    }
}

#[test]
fn canonical_global_catalog_reopens_without_rewriting_history() -> TestResult {
    let connection = Connection::open_in_memory()?;
    create_catalog(&connection)?;
    seed_history(&connection)?;
    let catalog = global_schema_catalog(&connection)?;
    let history = history_bytes(&connection)?;
    let head = load_global_commit_head(&connection)?;
    verify_global_commit_schema(&connection)?;
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    assert_eq!(history_bytes(&connection)?, history);
    assert_eq!(load_global_commit_head(&connection)?, head);
    Ok(())
}

#[test]
fn missing_projection_kinds_refuse_without_rewriting_catalog_or_history() -> TestResult {
    let mut schema = GLOBAL_COMMIT_SCHEMA.to_owned();
    for kind in [
        "revocation_entry",
        "recovery",
        "stop_epoch",
        "security_participant_checkpoint",
        "security_participant_nonce_preflight",
        "security_participant_output",
        "native_dispatch_ledger",
        "security_participant_egress",
        "security_participant_state",
        "security_participant_migration",
        "dpop_replay_migration",
        "governed_approval_replay_migration",
        "runtime_replay_migration",
        "finding_status",
        "finding_challenge",
    ] {
        schema = schema.replace(&format!(", '{kind}'"), "");
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(&schema)?;
        seed_history(&connection)?;
        let catalog = global_schema_catalog(&connection)?;
        let history = history_bytes(&connection)?;
        let head = load_global_commit_head(&connection)?;
        assert_catalog_refused(&connection);
        assert_eq!(global_schema_catalog(&connection)?, catalog);
        assert_eq!(history_bytes(&connection)?, history);
        assert_eq!(load_global_commit_head(&connection)?, head);
    }
    Ok(())
}

#[test]
fn missing_commit_table_refuses_without_recreating_history() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    seed_history(&connection)?;
    let head = load_global_commit_head(&connection)?;
    connection.execute_batch("DROP TABLE authority_global_commits;")?;
    let catalog = global_schema_catalog(&connection)?;
    assert_catalog_refused(&connection);
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    assert_eq!(load_global_commit_head(&connection)?, head);
    Ok(())
}

#[test]
fn missing_metadata_refuses_without_recreating_a_head() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    seed_history(&connection)?;
    let history = history_bytes(&connection)?;
    connection.execute_batch("DROP TABLE authority_global_commit_meta;")?;
    let catalog = global_schema_catalog(&connection)?;
    assert_catalog_refused(&connection);
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    assert_eq!(history_bytes(&connection)?, history);
    Ok(())
}

#[test]
fn missing_global_guards_refuse_without_repair() -> TestResult {
    for statement in [
        "DROP TRIGGER authority_global_commits_immutable",
        "DROP TRIGGER authority_global_commits_no_delete",
        "DROP INDEX authority_global_commits_projection",
    ] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
        seed_history(&connection)?;
        connection.execute_batch(statement)?;
        let catalog = global_schema_catalog(&connection)?;
        let history = history_bytes(&connection)?;
        let head = load_global_commit_head(&connection)?;
        assert_catalog_refused(&connection);
        assert_eq!(global_schema_catalog(&connection)?, catalog);
        assert_eq!(history_bytes(&connection)?, history);
        assert_eq!(load_global_commit_head(&connection)?, head);
    }
    Ok(())
}

#[test]
fn unexpected_global_guard_refuses_without_repair() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    seed_history(&connection)?;
    connection.execute_batch(
        "CREATE TRIGGER unrelated_global_hook BEFORE INSERT ON authority_global_commits
         BEGIN SELECT 1; END",
    )?;
    let catalog = global_schema_catalog(&connection)?;
    let history = history_bytes(&connection)?;
    let head = load_global_commit_head(&connection)?;
    assert_catalog_refused(&connection);
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    assert_eq!(history_bytes(&connection)?, history);
    assert_eq!(load_global_commit_head(&connection)?, head);
    Ok(())
}

#[test]
fn reserved_global_catalog_names_are_not_adopted() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE unrelated (value TEXT);
         INSERT INTO unrelated VALUES ('preserved');
         CREATE INDEX authority_global_commits_projection ON unrelated(value);",
    )?;
    let catalog = global_schema_catalog(&connection)?;
    assert_catalog_refused(&connection);
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    let value: String =
        connection.query_row("SELECT value FROM unrelated", [], |row| row.get(0))?;
    assert_eq!(value, "preserved");
    Ok(())
}

#[test]
fn failed_catalog_creation_rolls_back_every_created_object() -> TestResult {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    let connection = Connection::open_in_memory()?;
    connection.authorizer(Some(|context: AuthContext<'_>| match context.action {
        AuthAction::CreateIndex {
            index_name: "authority_global_commits_projection",
            ..
        } => Authorization::Deny,
        _ => Authorization::Allow,
    }))?;
    let result = create_catalog(&connection);
    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
    match result {
        Err(SqliteServingOwnerError::Sqlite(rusqlite::Error::SqliteFailure(
            error,
            Some(message),
        )))
        | Err(SqliteServingOwnerError::Sqlite(rusqlite::Error::SqlInputError {
            error,
            msg: message,
            ..
        })) => {
            assert_eq!(error.extended_code, rusqlite::ffi::SQLITE_AUTH);
            assert_eq!(message, "not authorized");
        }
        other => panic!("expected SQLite authorization refusal, got {other:?}"),
    }
    assert!(connection.is_autocommit());
    assert_eq!(global_schema_catalog(&connection)?, Vec::new());
    create_catalog(&connection)?;
    verify_global_commit_schema(&connection)?;
    Ok(())
}

#[test]
fn differently_cased_reserved_names_refuse_without_catalog_changes() -> TestResult {
    for statement in [
        "CREATE TABLE AUTHORITY_GLOBAL_COMMITS (value TEXT)",
        "CREATE TABLE unrelated (value TEXT);
         CREATE INDEX AUTHORITY_GLOBAL_COMMITS_PROJECTION ON unrelated(value)",
    ] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(statement)?;
        let catalog = global_schema_catalog(&connection)?;
        assert!(!catalog.is_empty());
        assert_catalog_refused(&connection);
        assert_eq!(global_schema_catalog(&connection)?, catalog);
    }
    Ok(())
}

#[test]
fn partial_catalog_with_a_genesis_head_refuses_without_repair() -> TestResult {
    let connection = Connection::open_in_memory()?;
    create_catalog(&connection)?;
    let head = load_global_commit_head(&connection)?;
    assert_eq!(head.head_sequence, 0);
    connection.execute_batch("DROP TABLE authority_global_commits")?;
    let catalog = global_schema_catalog(&connection)?;
    assert_catalog_refused(&connection);
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    assert_eq!(load_global_commit_head(&connection)?, head);
    Ok(())
}
