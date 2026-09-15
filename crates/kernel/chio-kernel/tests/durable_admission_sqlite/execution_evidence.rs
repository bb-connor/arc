use super::*;

struct UnexpectedExecutionSettlement;
impl chio_settle::SettlementHook for UnexpectedExecutionSettlement {
    fn observe(
        &self,
        _: &chio_settle::SettlementObservation,
        _: &chio_settle::SettlementIdempotencyKey,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        panic!("execution-only evidence must not invoke a settlement observer")
    }
}

#[test]
fn sqlite_execution_evidence_precedes_payment_and_replays_after_restart(
) -> Result<(), Box<dyn Error>> {
    for corruption in ["delete", "replace", "rollback"] {
        execution_evidence_scenario(corruption)?;
    }
    Ok(())
}

fn execution_evidence_scenario(corruption: &str) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let snapshot = temp.path().join("before-execution.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());
    payment_calls
        .fail_next_capture
        .store(true, Ordering::SeqCst);

    let (request, operation_id, execution_bytes) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
        kernel.require_durable_request_retention();
        kernel.set_durable_admission_store(operations.clone(), outcomes.clone(), fence.clone())?;
        kernel.set_budget_store_handle(budget);
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let request = paid_request(&capability);
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .err()
            .ok_or_else(|| std::io::Error::other("the injected capture must fail"))?;
        assert!(matches!(
            error,
            KernelError::DurableAdmission(ref reason)
                if reason.contains("injected capture interruption")
        ));
        let recoverable = operations.list_recoverable(now_unix_ms()? + 120_000, 10)?;
        assert_eq!(recoverable.len(), 1);
        let operation = &recoverable[0];
        assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
        let journal = operations
            .load_payment_journal(operation.binding().operation_id().as_str(), &fence)?
            .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;
        assert_eq!(journal.state, PaymentJournalState::Settling);
        let receipts_path = temp.path().join("receipts.sqlite");
        let receipts = Arc::new(chio_store_sqlite::SqliteReceiptStore::open(&receipts_path)?);
        let settlement =
            Arc::new(chio_store_sqlite::SqliteSettlementOutcomeStore::open_alongside(&receipts)?);
        kernel.set_receipt_store_handle(receipts.clone())?;
        kernel.set_settlement_observer_runtime(
            Arc::new(UnexpectedExecutionSettlement),
            settlement,
            chio_settle::RetryPolicy::default(),
        )?;
        let mut wrong_signer = ChioKernel::new(kernel_config(Keypair::generate()));
        wrong_signer.set_durable_admission_store(
            operations.clone(),
            outcomes.clone(),
            fence.clone(),
        )?;
        assert!(wrong_signer
            .export_durable_execution_evidence(&request)
            .is_err());
        if corruption == "rollback" {
            // Capture committed pre-projection state while preserving the newer
            // out-of-database rollback anchor for the later restore attempt.
            let connection = rusqlite::Connection::open(&database)?;
            connection.execute(
                "VACUUM INTO ?1",
                [snapshot.to_str().ok_or("snapshot path")?],
            )?;
            std::fs::set_permissions(&snapshot, std::fs::metadata(&database)?.permissions())?;
        }
        let before = operation.clone();
        let execution = kernel.export_durable_execution_evidence(&request)?;
        let metadata =
            chio_core::receipt::execution_evidence::verify_pre_settlement_execution_receipt(
                &execution,
                &[kernel_keypair.public_key()],
            )?;
        assert_eq!(
            metadata.operation_id,
            operation.binding().operation_id().as_str()
        );
        assert_eq!(
            metadata.hold_id,
            journal.hold_id.clone().ok_or("missing hold")?
        );
        assert_eq!(
            metadata.authorization_id,
            journal
                .authorization_id
                .clone()
                .ok_or("missing authorization")?
        );
        assert_eq!(
            operations.load_by_operation_id(operation.binding().operation_id())?,
            Some(before)
        );
        assert_eq!(
            operations.load_payment_journal(operation.binding().operation_id().as_str(), &fence)?,
            Some(journal.clone())
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 1);
        let record = outcomes
            .lookup_execution_evidence(operation.binding().operation_id())?
            .ok_or("missing execution record")?;
        let raw = outcomes
            .load_raw_invocation_by_operation(operation.binding().operation_id())?
            .ok_or("missing raw")?;
        let outcome = outcomes
            .lookup_by_operation(operation.binding().operation_id())?
            .ok_or("missing outcome")?;
        let evaluation = outcomes
            .lookup_post_return_evaluation(operation.binding().operation_id())?
            .ok_or("missing evaluation")?;
        let resolved = outcomes
            .load_resolved_output_by_operation(operation.binding().operation_id())?
            .ok_or("missing resolved")?;
        record.validate_against(
            operation,
            &raw,
            &outcome,
            &evaluation,
            &journal,
            resolved.bytes(),
        )?;
        for mutation in ["authorization", "hold", "amount", "rail"] {
            let mut changed = journal.clone();
            match mutation {
                "authorization" => {
                    changed.authorization_id = Some("different-authorization".into())
                }
                "hold" => changed.hold_id = Some("different-hold".into()),
                "amount" => changed.amount_units += 1,
                _ => changed.rail = "different-rail".into(),
            }
            assert!(
                record
                    .validate_against(
                        operation,
                        &raw,
                        &outcome,
                        &evaluation,
                        &changed,
                        resolved.bytes()
                    )
                    .is_err(),
                "{mutation}"
            );
        }
        let mut changed = raw.to_persisted();
        changed.output = chio_kernel::tool_outcome::InvocationOutputV1::Value {
            value: serde_json::json!({"forged":true}),
        };
        let changed = RawInvocationOutcomeV1::from_persisted(changed)?;
        assert!(record
            .validate_against(
                operation,
                &changed,
                &outcome,
                &evaluation,
                &journal,
                resolved.bytes()
            )
            .is_err());
        assert!(record
            .validate_against(operation, &raw, &outcome, &evaluation, &journal, b"null")
            .is_err());
        let bytes = canonical_json_bytes(&execution)?;
        assert_eq!(
            canonical_json_bytes(&kernel.export_durable_execution_evidence(&request)?)?,
            bytes
        );
        assert_eq!(
            canonical_json_bytes(&wrong_signer.export_durable_execution_evidence(&request)?)?,
            bytes
        );
        assert!(receipts.load_chio_receipt(&execution.id)?.is_some());
        let receipt_connection = rusqlite::Connection::open(&receipts_path)?;
        assert_eq!(
            receipt_connection
                .query_row("SELECT COUNT(*) FROM settle_attempts", [], |row| row
                    .get::<_, i64>(0))?,
            0
        );
        let mut changed = request.clone();
        changed.arguments = serde_json::json!({"substituted": true});
        assert!(kernel.export_durable_execution_evidence(&changed).is_err());
        (request, operation.binding().operation_id().clone(), bytes)
    };

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut recovered_kernel = ChioKernel::new(kernel_config(kernel_keypair));
    recovered_kernel.require_durable_request_retention();
    recovered_kernel.set_durable_admission_store(
        operations.clone(),
        outcomes.clone(),
        fence.clone(),
    )?;
    recovered_kernel.set_budget_store_handle(budget);
    recovered_kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    recovered_kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));

    assert_eq!(
        canonical_json_bytes(&recovered_kernel.export_durable_execution_evidence(&request)?)?,
        execution_bytes
    );
    assert_eq!(recovered_kernel.reconcile_durable_admission_startup()?, 1);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or_else(|| std::io::Error::other("recovered payment journal is absent"))?;
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_action, Some(PaymentSettleAction::Capture));
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 2);
    let completed = operations
        .load_by_operation_id(&operation_id)?
        .ok_or_else(|| std::io::Error::other("completed operation is absent"))?;
    assert_eq!(completed.state(), AdmissionOperationState::Completed);

    let response = recovered_kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_ne!(canonical_json_bytes(&response.receipt)?, execution_bytes);
    assert_eq!(
        canonical_json_bytes(&recovered_kernel.export_durable_execution_evidence(&request)?)?,
        execution_bytes
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 2);
    drop(recovered_kernel);
    drop(operations);
    drop(outcomes);
    drop(authority);
    if corruption == "rollback" {
        for suffix in ["-wal", "-shm"] {
            let mut path = database.as_os_str().to_owned();
            path.push(suffix);
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        std::fs::copy(&snapshot, &database)?;
    } else {
        // Restore the exact schema after a self-consistent offline corruption.
        // Triggers alone cannot provide the anchored participant commitment.
        let connection = rusqlite::Connection::open(&database)?;
        let name = if corruption == "delete" {
            "tool_outcome_execution_evidence_no_delete"
        } else {
            "tool_outcome_execution_evidence_no_update"
        };
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1",
            [name],
            |row| row.get(0),
        )?;
        if corruption == "delete" {
            connection.execute_batch("DROP TRIGGER tool_outcome_execution_evidence_no_delete; DELETE FROM tool_outcome_execution_evidence;")?;
        } else {
            let bytes: Vec<u8> = connection.query_row(
                "SELECT canonical_record FROM tool_outcome_execution_evidence",
                [],
                |r| r.get(0),
            )?;
            let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
            let recorded = record["recorded_at_unix_ms"]
                .as_u64()
                .ok_or("recorded time")?
                + 1;
            record["recorded_at_unix_ms"] = serde_json::json!(recorded);
            let canonical = canonical_json_bytes(&record)?;
            let participant = sha256_hex(&canonical_json_bytes(&serde_json::json!({
                "schema": "chio.execution-evidence-participant.v1",
                "record": record,
            }))?);
            connection.execute_batch("DROP TRIGGER tool_outcome_execution_evidence_no_update;")?;
            connection.execute("UPDATE tool_outcome_execution_evidence SET canonical_record=?1,participant_digest=?2,recorded_at_unix_ms=?3",
                rusqlite::params![canonical, participant, i64::try_from(recorded)?])?;
        }
        connection.execute_batch(&trigger)?;
    }
    let error = SqliteAuthorityStore::open_serving(&database, &lock_root)
        .err()
        .ok_or("corrupt projection admitted")?;
    let message = error.to_string().to_ascii_lowercase();
    assert!(
        message.contains("projection")
            || message.contains("rollback")
            || message.contains("anchor")
            || message.contains("commit"),
        "{corruption}: {error}"
    );
    Ok(())
}
