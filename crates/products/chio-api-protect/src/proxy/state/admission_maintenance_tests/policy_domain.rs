use super::*;

fn default_policy_hash(domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(chio_core_types::sha256_hex(
        &chio_core_types::canonical::canonical_json_bytes(&(
            domain,
            chio_guards::default_runtime_guard_profile_identity()?,
        ))?,
    ))
}

type OperationRows = Vec<(String, String, i64, i64)>;

fn durable_rows(fixture: &Fixture) -> Result<(OperationRows, i64), Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open_with_flags(
        &fixture.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT operation_id, state, version, updated_at_unix_ms
         FROM admission_operations ORDER BY operation_id",
    )?;
    let operations = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    let commits = connection.query_row(
        "SELECT count(*) FROM admission_operation_commits",
        [],
        |row| row.get(0),
    )?;
    Ok((operations, commits))
}

fn assert_no_effect(fixture: &Fixture) -> TestResult {
    assert_eq!(fixture.trace.dispatches.load(Ordering::SeqCst), 0);
    assert!(fixture
        .trace
        .authorizations
        .lock()
        .map_err(|_| "trace lock")?
        .is_empty());
    assert!(fixture
        .trace
        .captures
        .lock()
        .map_err(|_| "trace lock")?
        .is_empty());
    assert_eq!(fixture.trace.financial_effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn admission_reopened_under_v1_default_refuses_v2_default_operation() -> TestResult {
    let previous = default_policy_hash("chio-api-protect-mediation-v2")?;
    let current = default_policy_hash("chio-api-protect-mediation-v1")?;
    let mut fixture = Fixture::provisioned(Some(&previous))?;
    {
        let kernel = fixture
            .state
            .mediation_kernel
            .as_ref()
            .ok_or("previous kernel")?
            .lock()
            .await;
        let preflight = kernel.evaluate_tool_call(&fixture.request).await?;
        assert_eq!(
            preflight.verdict,
            chio_kernel::Verdict::Allow,
            "{:?}",
            preflight.reason
        );
        assert_eq!(preflight.receipt.policy_hash, previous);
        fixture.request.execution_nonce = Some(*preflight.execution_nonce.ok_or("previous nonce")?);
    }
    let persisted = durable_rows(&fixture)?;
    assert_eq!(persisted.0.len(), 1);

    let fixture = fixture.reopen(None)?;
    let kernel = fixture
        .state
        .mediation_kernel
        .as_ref()
        .ok_or("reopened kernel")?
        .lock()
        .await;
    assert_eq!(kernel.policy_hash(), current);

    let refusal = persisted.0[0].0.to_string();
    let claim = kernel.evaluate_tool_call(&fixture.request).await;
    assert!(
        matches!(&claim, Err(KernelError::OperationConflict { operation_id }) if *operation_id == refusal),
        "{claim:?}"
    );
    let mut restart = fixture.request.clone();
    restart.execution_nonce = None;
    let start = kernel.evaluate_tool_call(&restart).await;
    assert!(
        matches!(&start, Err(KernelError::OperationConflict { operation_id }) if *operation_id == refusal),
        "{start:?}"
    );
    assert_no_effect(&fixture)?;
    assert_eq!(durable_rows(&fixture)?, persisted);

    let mut fresh = restart;
    fresh.request_id = "api-protect-v1-default-request".into();
    let admitted = kernel.evaluate_tool_call(&fresh).await?;
    assert_eq!(
        admitted.verdict,
        chio_kernel::Verdict::Allow,
        "{:?}",
        admitted.reason
    );
    assert_eq!(admitted.receipt.policy_hash, current);
    assert!(admitted.receipt.verify_integrity_embedded_key()?);
    let (operations, _) = durable_rows(&fixture)?;
    assert_eq!(operations.len(), 2);
    let store = fixture.authority.admission_operation_store();
    let mut digests = Vec::new();
    for (operation_id, ..) in operations {
        let operation = store
            .load_by_operation_id(&AdmissionOperationId::from_persisted(operation_id)?)?
            .ok_or("persisted operation")?;
        digests.push(operation.binding().policy_hash().as_str().to_owned());
    }
    digests.sort();
    let mut expected = vec![previous, current];
    expected.sort();
    assert_eq!(digests, expected);
    Ok(())
}
