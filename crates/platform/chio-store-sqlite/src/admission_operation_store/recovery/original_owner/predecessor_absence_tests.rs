use super::*;

fn predecessor_location_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE admission_operation_recovery_records(record_key TEXT PRIMARY KEY);
         CREATE TABLE admission_operation_recovery_events(record_key TEXT NOT NULL);
         CREATE TABLE authority_global_commits(projection_kind TEXT,projection_key TEXT);",
    )?;
    Ok(connection)
}

#[test]
fn predecessor_original_authority_rejects_future_ownership_in_every_location(
) -> Result<(), Box<dyn std::error::Error>> {
    for prefix in [
        "recovery-original-owner:",
        "recovery-original-transfer:",
        "recovery-original-tombstone:",
        "unused-setup-generation:",
    ] {
        for location in ["current", "events", "global"] {
            let connection = predecessor_location_fixture()?;
            require_predecessor_original_owner_absence(&connection)?;
            let key = format!("{prefix}retained-future-ownership");
            match location {
                "current" => connection.execute(
                    "INSERT INTO admission_operation_recovery_records VALUES(?1)",
                    [key],
                )?,
                "events" => connection.execute(
                    "INSERT INTO admission_operation_recovery_events VALUES(?1)",
                    [key],
                )?,
                "global" => connection.execute(
                    "INSERT INTO authority_global_commits VALUES('recovery',?1)",
                    [key],
                )?,
                _ => return Err("unknown ownership location".into()),
            };
            assert!(
                require_predecessor_original_owner_absence(&connection).is_err(),
                "predecessor accepted {prefix} ownership retained in {location}"
            );
        }
    }
    Ok(())
}

#[test]
fn predecessor_original_authority_rejects_future_catalog_before_any_heads(
) -> Result<(), Box<dyn std::error::Error>> {
    for index in [
        "admission_operation_recovery_original_owner",
        "admission_operation_recovery_original_transfer",
        "admission_operation_recovery_original_tombstone",
        "admission_operation_recovery_unused_setup_generation",
    ] {
        let connection = predecessor_location_fixture()?;
        require_predecessor_original_owner_absence(&connection)?;
        connection.execute_batch(&format!(
            "CREATE INDEX {index} ON admission_operation_recovery_records(record_key);"
        ))?;
        assert!(
            require_predecessor_original_owner_absence(&connection).is_err(),
            "predecessor accepted future {index} without heads"
        );
    }
    Ok(())
}
