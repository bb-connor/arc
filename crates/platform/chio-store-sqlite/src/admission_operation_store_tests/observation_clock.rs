use super::*;

#[test]
fn observed_clock_is_authenticated_and_cannot_be_removed_or_forged() -> AnchoredTestResult {
    for replacement in ["NULL", "observed_at_unix_ms + 1"] {
        let fixture = fixture();
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "tamper-clock",
            "tamper-cap",
        );
        fixture.store.begin(&operation, &fixture.fence, now_ms())?;
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
        connection.execute_batch(&format!(
            "UPDATE admission_operation_commits SET observed_at_unix_ms = {replacement};"
        ))?;
        assert!(verify_admission_commit_chain(&connection).is_err());
    }
    Ok(())
}

#[test]
fn current_version_cannot_silently_regenerate_a_missing_observation_column() -> AnchoredTestResult {
    let fixture = fixture();
    let mut connection = fixture.store.connection()?;
    connection.execute_batch(
        "ALTER TABLE admission_operation_commits DROP COLUMN observed_at_unix_ms;",
    )?;
    assert!(initialize_admission_operation_schema(&mut connection).is_err());
    Ok(())
}
