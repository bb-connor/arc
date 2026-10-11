use super::*;

fn count(fixture: &NonceFixture, table: &str) -> TestResult<u32> {
    assert!(matches!(
        table,
        "budget_authorization_holds" | "budget_mutation_events" | "admission_nonce_preflight_holds"
    ));
    Ok(Connection::open(&fixture.fixture.database)?.query_row(
        &format!("SELECT COUNT(*) FROM {table}"),
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn durable_nonce_preflight_ack_loss_requires_current_fences_and_never_reopens_cleanup() -> TestResult
{
    let mut fixture = unowned_prepared_nonce_fixture(None)?;
    let old_operation = fixture.operation.clone();
    let old_lease = lease(&fixture)?;
    // Discard the first acknowledgement, including the returned operation.
    fixture.fixture.store.authorize_execution_nonce_preflight(
        &old_operation,
        &old_lease,
        request(&fixture)?,
        now_ms(),
    )?;
    assert!(matches!(
        fixture.fixture.store.authorize_execution_nonce_preflight(
            &old_operation,
            &old_lease,
            request(&fixture)?,
            now_ms(),
        ),
        Err(AdmissionCaptureError::Fenced)
    ));
    fixture.operation = fixture
        .fixture
        .store
        .load_by_operation_id(old_operation.binding().operation_id())?
        .ok_or("operation")?;
    let exact = fixture.operation.clone();
    authorize(&mut fixture)?;
    assert_eq!(fixture.operation, exact);
    assert_eq!(count(&fixture, "budget_authorization_holds")?, 1);
    let old_lease = lease(&fixture)?;
    fixture = lifecycle::reopen(fixture)?;
    assert!(fixture
        .fixture
        .store
        .load_execution_nonce_preflight(
            fixture.operation.binding().operation_id(),
            old_lease.store_fence(),
            now_ms(),
        )
        .is_err());
    let recovery = fixture
        .fixture
        .store
        .load_execution_nonce_preflight(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            now_ms(),
        )?
        .ok_or("preflight recovery")?;
    assert_eq!(recovery.identity(), &identity(&fixture)?);
    assert_eq!(
        recovery.hold(),
        AdmissionNoncePreflightHoldDisposition::Reserved
    );
    assert!(matches!(
        fixture.fixture.store.authorize_execution_nonce_preflight(
            &fixture.operation,
            &old_lease,
            request(&fixture)?,
            now_ms(),
        ),
        Err(AdmissionCaptureError::Fenced)
    ));
    reverse(&fixture, 0)?;
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(quota(&fixture)?, (0, 0));
    let reversed = fixture
        .fixture
        .store
        .load_execution_nonce_preflight(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            now_ms(),
        )?
        .ok_or("preflight recovery after reversal")?;
    assert_eq!(reversed.identity(), recovery.identity());
    assert_eq!(
        reversed.authorization_commit_index(),
        recovery.authorization_commit_index()
    );
    assert_eq!(
        reversed.hold(),
        AdmissionNoncePreflightHoldDisposition::Reversed
    );
    let error = fixture
        .fixture
        .store
        .authorize_execution_nonce_preflight(
            &fixture.operation,
            &lease(&fixture)?,
            request(&fixture)?,
            now_ms(),
        )
        .expect_err("never reopen a reversed hold");
    assert!(error.to_string().contains("terminally reversed"), "{error}");
    fixture.operation = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &issue_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    fixture = lifecycle::reopen(fixture)?;
    assert!(fixture
        .operation
        .execution_nonce_issuance_digest()
        .is_some());
    assert_eq!(count(&fixture, "admission_nonce_preflight_holds")?, 1);
    Ok(())
}

#[test]
fn durable_nonce_preflight_rolls_back_physical_and_operation_sql_cutpoints() -> TestResult {
    for (table, mutation) in [
        ("admission_operations", "UPDATE"),
        ("admission_operation_commits", "INSERT"),
        ("admission_nonce_preflight_holds", "INSERT"),
    ] {
        let mut fixture = unowned_prepared_nonce_fixture(None)?;
        let lease = lease(&fixture)?;
        fixture.fixture.store.connection()?.execute_batch(&format!(
            "CREATE TRIGGER preflight_cutpoint BEFORE {mutation} ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected preflight cutpoint'); END;"
        ))?;
        let error = fixture
            .fixture
            .store
            .authorize_execution_nonce_preflight(
                &fixture.operation,
                &lease,
                request(&fixture)?,
                now_ms(),
            )
            .expect_err("injected cutpoint");
        assert!(
            error.to_string().contains("injected preflight cutpoint"),
            "{error}"
        );
        for table in [
            "budget_authorization_holds",
            "budget_mutation_events",
            "admission_nonce_preflight_holds",
        ] {
            assert_eq!(count(&fixture, table)?, 0, "{table}");
        }
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?,
            Some(fixture.operation.clone())
        );
        fixture
            .fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER preflight_cutpoint")?;
        authorize(&mut fixture)?;
        assert_eq!(quota(&fixture)?, (1, 0));
    }
    Ok(())
}

#[test]
fn durable_nonce_preflight_rejects_generic_identity_and_attachment_forgery() -> TestResult {
    let fixture = unowned_prepared_nonce_fixture(None)?;
    let error = chio_kernel::InMemoryBudgetStore::new()
        .authorize_budget_hold(request(&fixture)?)
        .expect_err("ephemeral budget cannot acquire an internal identity");
    assert!(error.to_string().contains("owning participant"), "{error}");
    let error = fixture
        .fixture
        .authority
        .budget_store()
        .authorize_budget_hold(request(&fixture)?)
        .expect_err("generic budget cannot acquire an internal identity");
    assert!(error.to_string().contains("owning participant"), "{error}");
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::ExecutionNoncePreflightDigest(digest(
            "preflight",
            'b',
        ))],
        AdmissionOperationState::Prepared,
    )?;
    assert!(fixture
        .fixture
        .store
        .compare_and_swap(&command, now_ms())
        .is_err());
    assert_eq!(count(&fixture, "budget_authorization_holds")?, 0);
    let forged = fixture
        .operation
        .apply_command(&command, now_ms())?
        .into_operation();
    let mut persisted = forged.to_persisted();
    persisted.version = 1;
    let forged = AdmissionOperationV1::from_persisted(persisted)?;
    let fresh = super::super::super::fixture();
    let error = fresh
        .store
        .begin(&forged, &fresh.fence, now_ms())
        .expect_err("begin cannot forge preflight");
    assert!(
        error
            .to_string()
            .contains("fabricate nonce issuance evidence"),
        "{error}"
    );
    Ok(())
}

#[test]
fn durable_nonce_preflight_rejects_changed_parent_request_and_grant_bindings() -> TestResult {
    for mutation in 0..7 {
        let fixture = unowned_prepared_nonce_fixture(None)?;
        let mut request = request(&fixture)?;
        match mutation {
            0 => request.capability_id = "foreign-capability".into(),
            1 => {
                request.grant_index = 1;
                let identity =
                    AdmissionNoncePreflightIdentityV1::for_operation(&fixture.operation, 1)?;
                request.hold_id = Some(identity.hold_id().as_str().into());
                request.event_id = Some(identity.authorization_event_id().as_str().into());
            }
            2 => request.hold_id = Some("foreign-hold".into()),
            3 => request.event_id = Some("foreign-event".into()),
            4 => request
                .admission_binding
                .as_mut()
                .ok_or("binding")?
                .operation_id
                .push('x'),
            5 => {
                request
                    .admission_binding
                    .as_mut()
                    .ok_or("binding")?
                    .revocation_set =
                    CanonicalRevocationSet::canonicalize(vec!["foreign-capability".into()])?
            }
            6 => {
                request
                    .admission_binding
                    .as_mut()
                    .ok_or("binding")?
                    .operation_id = fixture.operation.binding().operation_id().as_str().into()
            }
            _ => unreachable!(),
        }
        assert!(
            fixture
                .fixture
                .store
                .authorize_execution_nonce_preflight(
                    &fixture.operation,
                    &lease(&fixture)?,
                    request,
                    now_ms(),
                )
                .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(count(&fixture, "budget_authorization_holds")?, 0);
        assert_eq!(count(&fixture, "budget_mutation_events")?, 0);
        assert_eq!(count(&fixture, "admission_nonce_preflight_holds")?, 0);
    }
    Ok(())
}

#[test]
fn durable_nonce_preflight_denial_records_no_physical_ownership() -> TestResult {
    let fixture = unowned_prepared_nonce_fixture(None)?;
    let mut request = request(&fixture)?;
    request.max_invocations = Some(0);
    let (decision, operation) = fixture.fixture.store.authorize_execution_nonce_preflight(
        &fixture.operation,
        &lease(&fixture)?,
        request,
        now_ms(),
    )?;
    assert!(matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)));
    assert_eq!(operation, fixture.operation);
    assert_eq!(count(&fixture, "budget_authorization_holds")?, 0);
    assert_eq!(count(&fixture, "admission_nonce_preflight_holds")?, 0);
    assert_eq!(count(&fixture, "budget_mutation_events")?, 1);
    Ok(())
}

#[test]
fn durable_nonce_preflight_concurrent_exact_candidates_have_one_physical_reservation() -> TestResult
{
    let mut fixture = unowned_prepared_nonce_fixture(None)?;
    let lease = lease(&fixture)?;
    let request = request(&fixture)?;
    let barrier = std::sync::Barrier::new(2);
    let at = now_ms();
    let results = std::thread::scope(|scope| {
        let contenders: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    fixture.fixture.store.authorize_execution_nonce_preflight(
                        &fixture.operation,
                        &lease,
                        request.clone(),
                        at,
                    )
                })
            })
            .collect();
        contenders
            .into_iter()
            .map(|contender| contender.join().expect("contender"))
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AdmissionCaptureError::Fenced)))
            .count(),
        1
    );
    fixture.operation = fixture
        .fixture
        .store
        .load_by_operation_id(fixture.operation.binding().operation_id())?
        .ok_or("operation")?;
    assert_eq!(quota(&fixture)?, (1, 0));
    assert_eq!(count(&fixture, "budget_authorization_holds")?, 1);
    assert_eq!(count(&fixture, "admission_nonce_preflight_holds")?, 1);
    Ok(())
}

#[test]
fn durable_nonce_preflight_ownership_is_permanent_and_corruption_fails_reads_and_restart(
) -> TestResult {
    for mutation in [
        "DELETE FROM admission_nonce_preflight_holds",
        "UPDATE admission_nonce_preflight_holds SET budget_operation_id = 'foreign-budget-operation'",
        "UPDATE admission_nonce_preflight_holds SET ownership_json = X'7b7d'",
        "UPDATE admission_nonce_preflight_holds SET ownership_json = zeroblob(4097)",
        "UPDATE admission_nonce_preflight_holds SET operation_json = zeroblob(262145)",
        "UPDATE admission_nonce_preflight_holds SET recorded_at_unix_ms = recorded_at_unix_ms + 1",
    ] {
        let mut fixture = prepared_nonce_fixture(None)?;
        fixture.operation = fixture.fixture.store.issue_execution_nonce_and_commit_admission(
            &issue_command(&fixture)?, &fixture.reservation, now_ms(),
        )?.into_operation();
        assert!(fixture.fixture.store.connection()?.execute_batch(mutation).is_err());
        fixture.fixture.store.connection()?.execute_batch(&format!(
            "DROP TRIGGER admission_nonce_preflight_holds_immutable;
             DROP TRIGGER admission_nonce_preflight_holds_no_delete;
             PRAGMA ignore_check_constraints = ON;
             {mutation};
             PRAGMA ignore_check_constraints = OFF;"
        ))?;
        let error = fixture.fixture.store.load_by_operation_id(fixture.operation.binding().operation_id())
            .expect_err("corrupt preflight ownership must fail reads");
        assert!(matches!(error, AdmissionOperationStoreError::Invariant(_)), "{error}");
        assert!(fixture.fixture.store.load_execution_nonce_issuance(
            fixture.operation.binding().operation_id(), &fixture.fixture.fence, now_ms(),
        ).is_err());
        assert!(lifecycle::reopen(fixture).is_err());
    }
    Ok(())
}

#[test]
fn durable_nonce_preflight_requires_original_provenance_and_cannot_start_after_issuance(
) -> TestResult {
    let fixture = unowned_prepared_nonce_fixture(None)?;
    let lease = lease(&fixture)?;
    fixture.fixture.store.connection()?.execute_batch(
        "DROP TRIGGER admission_operation_tool_requests_no_delete;
         DELETE FROM admission_operation_tool_requests;",
    )?;
    let error = fixture
        .fixture
        .store
        .authorize_execution_nonce_preflight(
            &fixture.operation,
            &lease,
            request(&fixture)?,
            now_ms(),
        )
        .expect_err("missing original provenance");
    assert!(
        error
            .to_string()
            .contains("committed original tool request is missing"),
        "{error}"
    );
    assert_eq!(count(&fixture, "budget_authorization_holds")?, 0);
    let mut fixture = prepared_nonce_fixture(None)?;
    fixture.operation = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &issue_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    assert!(fixture
        .fixture
        .store
        .authorize_execution_nonce_preflight(
            &fixture.operation,
            &super::lease(&fixture)?,
            request(&fixture)?,
            now_ms(),
        )
        .is_err());
    assert_eq!(count(&fixture, "budget_authorization_holds")?, 1);
    Ok(())
}

#[test]
fn durable_nonce_preflight_replay_callback_cannot_backfill_physical_ownership() -> TestResult {
    let fixture = unowned_prepared_nonce_fixture(None)?;
    let request = request(&fixture)?;
    let mut legacy = request.clone();
    legacy
        .admission_binding
        .as_mut()
        .ok_or("binding")?
        .operation_id = "unowned-budget-operation".into();
    let decision = fixture
        .fixture
        .authority
        .budget_store()
        .authorize_budget_hold(legacy)?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let lease = lease(&fixture)?;
    {
        // Exercise the replay callback directly: an existing physical decision
        // must not be adopted when its parent never committed ownership.
        let store = &fixture.fixture.store;
        let mut connection = store.connection()?;
        let transaction = store.begin_write(&mut connection, Some(&fixture.fixture.fence))?;
        let error = crate::admission_operation_store::bind_nonce_preflight_tx(
            &transaction,
            &store.serving_owner,
            &request,
            &decision,
            crate::budget_store::NoncePreflightAuthorizationBinding {
                operation: &fixture.operation,
                recovery_lease: &lease,
                trusted_now_unix_ms: now_ms(),
            },
            false,
        )
        .expect_err("replay cannot backfill ownership");
        assert!(
            error.to_string().contains("cannot backfill ownership"),
            "{error}"
        );
        transaction.rollback()?;
    }
    assert_eq!(count(&fixture, "admission_nonce_preflight_holds")?, 0);
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation)
    );
    Ok(())
}
