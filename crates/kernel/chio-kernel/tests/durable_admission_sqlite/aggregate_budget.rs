use super::*;

#[test]
fn aggregate_invocation_budget_exhausts_across_grants_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_core::capability::aggregate_invocation::{
        AggregateInvocationBudget, AggregateInvocationScope,
    };

    let mut first_grant = scope().grants.remove(0);
    first_grant.max_invocations = Some(1);
    let mut second_grant = first_grant.clone();
    second_grant.tool_name = "mutate-alt".into();
    second_grant.max_invocations = Some(1);
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    chio_store_sqlite::SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock(),
    )?;
    let operations = std::sync::Arc::new(authority.admission_operation_store());
    let budget = std::sync::Arc::new(authority.budget_store());
    let keypair = Keypair::generate();
    let mut kernel = ChioKernel::new_with_clock(
        kernel_config(keypair.clone()),
        chio_test_support::clock::clock(),
    );
    kernel.set_durable_admission_store(
        operations.clone(),
        std::sync::Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(budget.clone());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(MutationServer {
        invocations: invocations.clone(),
    }));
    let agent = Keypair::generate();
    let mut scope = scope();
    scope.grants = vec![first_grant, second_grant];
    let capability = kernel.issue_capability(&agent.public_key(), scope, 300)?;
    let mut first = request(&capability);
    let mut body = first.capability.body();
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 1,
        root_binding: None,
    });
    first.capability = CapabilityToken::sign(body, &keypair)?;

    let first_response = kernel.evaluate_tool_call_blocking(&first)?;
    assert_eq!(
        first_response.verdict,
        Verdict::Allow,
        "{:?}",
        first_response.reason
    );

    assert!(first_response.receipt.verify_integrity_embedded_key()?);
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
        first_response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .ok_or("first admission metadata missing")?,
    )?;
    let original = operations
        .load_by_operation_id(&metadata.operation_id)?
        .ok_or("first completed admission missing")?;
    assert_eq!(original.state(), AdmissionOperationState::Completed);
    assert_eq!(original.binding().request_id().as_str(), first.request_id);
    let mut second = first.clone();
    second.request_id = "aggregate-second".to_string();
    second.tool_name = "mutate-alt".to_string();
    let second_response = kernel.evaluate_tool_call_blocking(&second)?;
    assert_eq!(second_response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let second_grant_usage = budget.get_invocation_quota_usage(
        &chio_kernel::budget_store::BudgetQuotaKey::grant(first.capability.id.clone(), 1),
    )?;
    assert!(second_grant_usage.is_none());
    assert!(second_response.receipt.verify_integrity_embedded_key()?);
    assert_eq!(
        second_response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata
                    .pointer("/chio_runtime/identity_disposition")
                    .and_then(serde_json::Value::as_str)
            }),
        Some("terminal")
    );
    let second_operation =
        operations.load_by_replay_key(&chio_kernel::admission_operation::AdmissionReplayKey {
            request_namespace_digest: original.binding().request_namespace_digest().clone(),
            request_id: chio_kernel::admission_operation::AdmissionIdentifier::try_new(
                "request_id",
                second.request_id.clone(),
            )?,
        })?;
    assert_eq!(
        second_operation.map(|operation| operation.state()),
        Some(AdmissionOperationState::CompensatedBeforeDispatch)
    );
    assert_eq!(
        operations.load_by_operation_id(original.binding().operation_id())?,
        Some(original)
    );
    Ok(())
}
