use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn seed_history(connection: &Connection) -> TestResult {
    let transaction = connection.unchecked_transaction()?;
    let reference = sha256_hex(b"schema-migration-baseline");
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
        "schema-migration-fixture",
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

#[test]
fn supported_previous_global_schemas_preserve_history_when_adding_replay_kinds() -> TestResult {
    let without_preflight =
        GLOBAL_COMMIT_SCHEMA.replace(", 'security_participant_nonce_preflight'", "");
    let without_output = without_preflight.replace(", 'security_participant_output'", "");
    let without_dispatch = without_output.replace(", 'native_dispatch_ledger'", "");
    let without_egress = without_dispatch.replace(", 'security_participant_egress'", "");
    let without_native = without_egress.replace(", 'security_participant_state'", "");
    let without_security = without_native.replace(", 'security_participant_migration'", "");
    let without_dpop = without_security.replace(", 'dpop_replay_migration'", "");
    let previous = without_dpop.replace(", 'governed_approval_replay_migration'", "");
    let without_runtime = previous.replace(", 'runtime_replay_migration'", "");
    let without_status = without_runtime.replace(", 'finding_status'", "");
    let without_challenge = without_status.replace(", 'finding_challenge'", "");
    for schema in [
        without_preflight,
        without_output,
        without_dispatch,
        without_egress,
        without_native,
        without_security,
        without_dpop,
        previous,
        without_runtime,
        without_status,
        without_challenge,
    ] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(&schema)?;
        seed_history(&connection)?;
        let head = load_global_commit_head(&connection)?;
        let before = history_bytes(&connection)?;
        assert!(verify_global_commit_schema(&connection).is_err());
        initialize_global_commit_schema(&connection)?;
        verify_global_commit_schema(&connection)?;
        assert_eq!(load_global_commit_head(&connection)?, head);
        assert_eq!(history_bytes(&connection)?, before);
        initialize_global_commit_schema(&connection)?;
        assert_eq!(load_global_commit_head(&connection)?, head);
        assert_eq!(history_bytes(&connection)?, before);
    }
    Ok(())
}

#[test]
fn nonhistorical_runtime_kind_without_status_is_not_an_upgrade_predecessor() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        &GLOBAL_COMMIT_SCHEMA
            .replace(", 'security_participant_nonce_preflight'", "")
            .replace(", 'security_participant_output'", "")
            .replace(", 'native_dispatch_ledger'", "")
            .replace(", 'security_participant_egress'", "")
            .replace(", 'security_participant_state'", "")
            .replace(", 'security_participant_migration'", "")
            .replace(", 'dpop_replay_migration'", "")
            .replace(", 'governed_approval_replay_migration'", "")
            .replace(", 'finding_status'", ""),
    )?;
    seed_history(&connection)?;
    let catalog = global_schema_catalog(&connection)?;
    let before = history_bytes(&connection)?;
    assert!(matches!(
        initialize_global_commit_schema(&connection),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
    assert_eq!(global_schema_catalog(&connection)?, catalog);
    assert_eq!(history_bytes(&connection)?, before);
    Ok(())
}

#[test]
fn unexpected_trigger_on_previous_global_schema_is_not_repaired() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        &GLOBAL_COMMIT_SCHEMA
            .replace(", 'security_participant_nonce_preflight'", "")
            .replace(", 'security_participant_output'", "")
            .replace(", 'native_dispatch_ledger'", "")
            .replace(", 'security_participant_egress'", "")
            .replace(", 'security_participant_state'", "")
            .replace(", 'security_participant_migration'", "")
            .replace(", 'dpop_replay_migration'", "")
            .replace(", 'governed_approval_replay_migration'", "")
            .replace(", 'runtime_replay_migration'", ""),
    )?;
    connection.execute_batch(
        "CREATE TRIGGER unrelated_global_hook BEFORE INSERT ON authority_global_commits
         BEGIN SELECT 1; END",
    )?;
    let before = global_schema_catalog(&connection)?;
    assert!(matches!(
        initialize_global_commit_schema(&connection),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
    assert_eq!(global_schema_catalog(&connection)?, before);
    Ok(())
}

#[test]
fn ignored_check_cannot_smuggle_future_projection_into_a_supported_predecessor() -> TestResult {
    let mut schema = GLOBAL_COMMIT_SCHEMA.to_owned();
    for kind in [
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
        connection.execute_batch("PRAGMA ignore_check_constraints = ON; DROP TRIGGER authority_global_commits_immutable;")?;
        connection.execute(
            "UPDATE authority_global_commits SET projection_kind = ?1",
            [kind],
        )?;
        connection.execute_batch(&schema)?;
        let catalog = global_schema_catalog(&connection)?;
        let before = history_bytes(&connection)?;
        let head = load_global_commit_head(&connection)?;
        assert!(initialize_global_commit_schema(&connection).is_err());
        assert_eq!(global_schema_catalog(&connection)?, catalog);
        assert_eq!(history_bytes(&connection)?, before);
        assert_eq!(load_global_commit_head(&connection)?, head);
    }
    Ok(())
}
