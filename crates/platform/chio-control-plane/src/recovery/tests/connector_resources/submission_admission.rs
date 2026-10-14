// Capacity refusal must close the actual native operation before commitment.
use super::*;

fn operation_for_workflow(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<chio_kernel::admission_operation::AdmissionOperationV1> {
    let record = fixture.record(workflow)?;
    let intent = record.admission.as_ref().ok_or("native intent is absent")?;
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?,
        )?
        .ok_or("actual native operation is absent")?;
    assert_eq!(operation.binding().to_persisted(), intent.native_binding);
    Ok(operation)
}

#[tokio::test]
async fn saturated_submission_closes_the_owned_native_continuation_before_dispatch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut contract = authority_history::fixture_effect_contract(directory.path())?;
    contract.resource = ProtectedText::new(&format!("https://{}/issues", listener.local_addr()?))?;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-effect-contract.json"),
        chio_core::canonical_json_bytes(&contract)?,
    )?;
    let connector = pinned_connector(contract)?;
    let held_capacity = capacity_test_support::hold_submission_capacity(&connector)?;
    let fixture = RecoveryFixture::open_with_tool_server(
        directory.path().to_path_buf(),
        Some(directory),
        false,
        None,
        Some(Box::new(connector)),
    )?;
    // This uses the original no-grant process denial, installed native binding,
    // reviewed action, signed approval, and original-only Resume path.
    let workflow = Box::pin(fixture.ready()).await?;
    let result = fixture
        .execute(
            "owned-submission-capacity",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )
        .await?;
    let operation = operation_for_workflow(&fixture, &workflow)?;
    let (retained_operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_retained_tool_request(
            operation.binding().operation_id(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("actual native retained request is absent")?;
    assert_eq!(retained_operation.to_persisted(), operation.to_persisted());
    assert_eq!(
        retained
            .native_security_authority_binding()
            .map(|binding| binding.store_uuid().as_str()),
        Some(fixture.runtime.scope().authority_domain.as_str())
    );
    let record = fixture.record(&workflow)?;
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            fixture.seed.capability.id.as_str(),
            0,
        ))?
        .ok_or("native invocation quota is absent")?;
    let connection = listener.accept();
    eprintln!(
        "OWNED_SUBMISSION_CAPACITY state={:?} dispatch={} workflow_captured={} reserved={} captured={} provider_connected={}",
        operation.state(), operation.dispatch_commit().is_some(), record.captured,
        usage.reserved_invocations, usage.captured_invocations, connection.is_ok(),
    );
    assert!(matches!(connection, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(external_count(&fixture.path)?, 0);
    assert!(result.original_response.is_none());
    // The first target is the real owning operation, after every native fixture
    // premise above. Current code reaches Unknown/dispatch commitment here.
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(!record.captured);
    assert!(matches!(
        result.status.effect,
        EffectObservationV1::ClosedBeforeEffect { .. }
    ));
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 0)
    );
    let old_operation = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    drop(held_capacity);

    // A distinct reviewed original can use the same actual connector once its
    // permit is released. Closing this local TCP peer produces an ambiguous
    // delivery, which must remain captured Unknown and must not retry.
    let positive = Box::pin(fixture.ready_named("capacity-positive", "capacity-positive")).await?;
    let positive_revision = fixture.record(&positive)?.revision;
    struct SubmissionFinished(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for SubmissionFinished {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let execution_finished = SubmissionFinished(finished.clone());
    let (connected, receiver) = std::sync::mpsc::sync_channel(1);
    let acceptor = std::thread::Builder::new()
        .name("native-submission-positive-peer".into())
        .spawn(move || loop {
            match listener.accept() {
                Ok((peer, _)) => {
                    drop(peer);
                    let _ = connected.send(true);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if finished.load(std::sync::atomic::Ordering::Acquire) {
                        let _ = connected.send(false);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => {
                    let _ = connected.send(false);
                    return;
                }
            }
        })?;
    let positive_result = fixture
        .execute(
            "owned-submission-positive",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: positive.clone(),
                expected_revision: positive_revision,
            },
        )
        .await;
    drop(execution_finished);
    acceptor
        .join()
        .map_err(|_| "native submission positive peer panicked")?;
    assert!(receiver.recv()?);
    let positive_result = positive_result?;
    let positive_operation = operation_for_workflow(&fixture, &positive)?;
    assert!(positive_operation.dispatch_commit().is_some());
    assert_eq!(
        positive_operation.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(matches!(
        positive_result.status.effect,
        EffectObservationV1::Unknown { .. }
    ));
    assert!(fixture.record(&positive)?.captured);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(
        chio_core::canonical_json_bytes(
            &operation_for_workflow(&fixture, &workflow)?.to_persisted()
        )?,
        old_operation
    );
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            fixture.seed.capability.id.as_str(),
            0,
        ))?
        .ok_or("positive native invocation quota is absent")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 1)
    );
    Ok(())
}
