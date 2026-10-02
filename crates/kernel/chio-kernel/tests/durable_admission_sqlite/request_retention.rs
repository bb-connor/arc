use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, DurableAdmissionMode};

#[test]
fn sqlite_direct_paid_admission_retains_original_request_with_one_hold(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    secure_directory(directory.path())?;
    let locks = directory.path().join("locks");
    create_private_directory(&locks)?;
    let database = directory.path().join("authority.sqlite");
    SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let operations = authority.admission_operation_store();
    let invocations = Arc::new(AtomicU64::new(0));
    let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
    kernel.require_durable_request_retention();
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter::default()));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    kernel.set_durable_admission_store(
        Arc::new(operations.clone()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    let capability =
        kernel.issue_capability(&Keypair::generate().public_key(), paid_scope(), 300)?;
    let request = paid_request(&capability);
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let (operation, retained) = operations
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &authority.mutation_fence(),
            now_unix_ms()?,
        )?
        .ok_or("direct admission did not retain its original request")?;
    assert_eq!(
        canonical_json_bytes(retained.request_for_revalidation())?,
        canonical_json_bytes(&request)?
    );
    retained.validate_binding(operation.binding())?;
    let payment = operations
        .load_payment_journal(
            operation.binding().operation_id().as_str(),
            &authority.mutation_fence(),
        )?
        .ok_or("original payment journal missing")?;
    assert!(payment.hold_id.is_some());
    let reader = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let holds: i64 = reader.query_row(
        "SELECT count(*) FROM budget_authorization_holds",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        holds, 1,
        "direct admission must not add a nonce-preflight hold"
    );
    Ok(())
}
