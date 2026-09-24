// Exercise the production connector and signed broker control IPC before capture.
// This peer deliberately performs no provider execution or credential access.
use super::*;
use chio_kernel::{BlockingToolServerAdapter, BlockingToolServerConnection};
use chio_secret_broker::kernel_admission::BrokerKernelConnection;
use chio_secret_broker::registration::{
    verify_register_attempt_authorization, AuthenticatedAttemptRequest,
    PrepareDispatchAcknowledgement, RegisterAttemptAcknowledgement, RegisterAttemptAction,
    SignedRegisterAttemptAuthorization,
};
use chio_secret_broker::service::{
    read_bounded_frame, write_bounded_frame, IpcOperation, IpcResponse,
};
use chio_secret_broker::store::AttemptStore;
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::time::{Duration, Instant};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlEnvelope {
    operation: IpcOperation,
    tenant_scope: String,
    authorization: Vec<u8>,
    payload: Vec<u8>,
}

#[test]
fn native_broker_connection_prepares_original_and_refuses_misbound_acknowledgement() -> TestResult {
    for (misbind, lose_execution_reply) in [(false, false), (true, false), (false, true)] {
        let mut fixture = super::super::super::super::public_fixture()?;
        let (execute, participant, observer) = install_broker(&mut fixture)?;
        fixture.kernel.set_supplemental_admission_participant(
            observer.registrar.clone(),
            participant.clone(),
        )?;
        let connection = Arc::new(BrokerKernelConnection::new(
            BrokerNativeCaptureReader::new(
                &fixture.authority,
                fixture.binding.clone(),
                participant,
            )?,
            observer.registrar.clone(),
        )?);
        assert!(connection
            .invoke_blocking("send", serde_json::to_value(&execute)?)
            .is_err());
        fixture
            .kernel
            .register_tool_server(Box::new(BlockingToolServerAdapter::new(
                connection.clone(),
            )?));
        let socket = fixture._directory.path().join("b.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let database = fixture._directory.path().join("broker-attempts.db");
        let kernel_store = fixture.authority.admission_operation_store();
        let kernel_fence = fixture.authority.mutation_fence();
        let peer = std::thread::spawn(move || {
            let serve = || -> TestResult<chio_secret_broker::store::AttemptRegistration> {
                let mut original = None;
                for (operation, action) in [
                    (
                        IpcOperation::RegisterAttempt,
                        RegisterAttemptAction::Register,
                    ),
                    (
                        IpcOperation::PrepareDispatch,
                        RegisterAttemptAction::Prepare,
                    ),
                ] {
                    let mut stream = accept_control(&listener)?;
                    let wire: ControlEnvelope =
                        serde_json::from_slice(&read_bounded_frame(&mut stream)?)?;
                    assert_eq!(wire.operation, operation);
                    assert_eq!(wire.tenant_scope, "native-broker-tenant");
                    let attempt: AuthenticatedAttemptRequest =
                        serde_json::from_slice(&wire.payload)?;
                    assert_eq!(attempt.request, execute);
                    let signed: SignedRegisterAttemptAuthorization =
                        serde_json::from_slice(&wire.authorization)?;
                    let now = now_ms()? / 1000;
                    verify_register_attempt_authorization(
                        &signed,
                        &attempt.registration,
                        action,
                        &wire.tenant_scope,
                        &Keypair::from_seed(&[34; 32]).public_key(),
                        now,
                        2,
                    )?;
                    let store = chio_secret_broker::sqlite::SqliteAttemptStore::open(&database)?;
                    let response = if operation == IpcOperation::RegisterAttempt {
                        original = Some(attempt.registration.clone());
                        chio_core::canonical::canonical_json_bytes(
                            &RegisterAttemptAcknowledgement::from_outcome(
                                store.register_intent(&attempt.registration, now)?,
                                now,
                            )?,
                        )?
                    } else {
                        assert_eq!(original.as_ref(), Some(&attempt.registration));
                        assert_eq!(
                            store
                                .load_attempt(&attempt.registration.ids.attempt_id)?
                                .ok_or("durable original registration")?
                                .registration,
                            attempt.registration
                        );
                        let mut ack = PrepareDispatchAcknowledgement::new(
                            &attempt.registration,
                            &attempt.request,
                            now,
                        )?;
                        if misbind {
                            ack.operation_id.push_str("-substituted");
                        }
                        chio_core::canonical::canonical_json_bytes(&ack)?
                    };
                    drop(store);
                    write_bounded_frame(
                        &mut stream,
                        &chio_core::canonical::canonical_json_bytes(&IpcResponse {
                            operation,
                            accepted: true,
                            response,
                            error_code: None,
                        })?,
                    )?;
                }
                let original = original.ok_or("no original broker registration")?;
                if lose_execution_reply {
                    let mut stream = accept_control(&listener)?;
                    let wire: ControlEnvelope =
                        serde_json::from_slice(&read_bounded_frame(&mut stream)?)?;
                    assert_eq!(wire.operation, IpcOperation::Execute);
                    assert_eq!(wire.tenant_scope, "native-broker-tenant");
                    let delivered: BrokerExecuteRequest = serde_json::from_slice(&wire.payload)?;
                    assert_eq!(delivered, execute);
                    assert_eq!(
                        wire.authorization,
                        chio_core::canonical::canonical_json_bytes(&execute.proof)?
                    );
                    let operation_id =
                        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                            &original.ids.operation_id,
                        )?;
                    let witness = kernel_store
                        .load_native_dispatch_capture_witness(
                            &operation_id,
                            &kernel_fence,
                            now_ms()?,
                        )?
                        .ok_or("execute arrived before native capture")?;
                    assert_eq!(
                        witness.capture.operation.state(),
                        AdmissionOperationState::DispatchCommitted
                    );
                    assert!(matches!(
                        witness.capture.decision,
                        BudgetInvocationCaptureDecision::Captured(_)
                    ));
                    // Lose the reply after receiving the exact execution request.
                    // The kernel cannot infer whether an external effect happened.
                    drop(stream);
                }
                Ok(original)
            };
            serve().map_err(|error| error.to_string())
        });
        let captured = if lose_execution_reply {
            let resolver = NativeFlowResolver::new(
                fixture.binding.clone(),
                super::super::super::super::registry(true, InformationLabel::bottom())?,
                Arc::new(CountingEmptyClassifier::new()),
                Arc::new(Clock::default()),
                flow_config(),
            )?
            .with_captured_lifecycle();
            fixture
                .kernel
                .set_security_pre_dispatch_hook(Arc::new(resolver));
            let response = fixture
                .kernel
                .evaluate_tool_call_blocking_with_security_context(
                    &fixture.request,
                    &fixture.context,
                );
            assert!(!matches!(&response, Ok(response) if response.verdict == Verdict::Allow));
            let (operation, _) = fixture
                .authority
                .admission_operation_store()
                .load_unambiguous_retained_tool_request(
                    &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
                    &fixture.authority.mutation_fence(),
                    now_ms()?,
                )?
                .ok_or("original execution operation")?;
            assert_eq!(
                operation.state(),
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                "lost broker reply: {response:?}"
            );
            Ok(operation.binding().operation_id().clone())
        } else {
            run_capture(&mut fixture, true).map(|ledger| ledger.operation_id)
        };
        let registration = peer
            .join()
            .map_err(|_| "broker preparation peer panicked")?
            .map_err(|error| format!("broker preparation peer: {error}"))?;
        if misbind {
            assert!(
                captured.is_err(),
                "misbound preparation must deny before capture"
            );
            let usage = fixture
                .authority
                .budget_store()
                .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                    &fixture.request.capability.id,
                    0,
                ))?
                .ok_or("original compensated quota")?;
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (0, 0)
            );
        } else {
            let operation_id = captured?;
            assert_eq!(operation_id.as_str(), registration.ids.operation_id);
            let witness = fixture
                .authority
                .admission_operation_store()
                .load_native_dispatch_capture_witness(
                    &operation_id,
                    &fixture.authority.mutation_fence(),
                    now_ms()?,
                )?
                .ok_or("original native capture")?;
            let public_context = chio_kernel::ToolDispatchContext::new(
                &fixture.request.request_id,
                witness
                    .capture
                    .operation
                    .provider_attempt()
                    .cloned()
                    .ok_or("original attempt")?,
            );
            assert!(
                matches!(
                    connection.invoke_blocking_in_context(
                        &public_context,
                        "send",
                        fixture.request.arguments.clone(),
                    ),
                    Err(KernelError::GuardDenied(_))
                ),
                "historical capture and public dispatch identity cannot authorize broker execution"
            );
            if lose_execution_reply {
                let budget = fixture.authority.budget_store();
                let usage = budget
                    .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                        &fixture.request.capability.id,
                        0,
                    ))?
                    .ok_or("captured original quota")?;
                assert_eq!(
                    (usage.reserved_invocations, usage.captured_invocations),
                    (0, 1)
                );
                let before =
                    budget.list_mutation_events(100, Some(&fixture.request.capability.id), None)?;
                let retry = fixture
                    .kernel
                    .evaluate_tool_call_blocking_with_security_context(
                        &fixture.request,
                        &fixture.context,
                    );
                assert!(!matches!(retry, Ok(response) if response.verdict == Verdict::Allow));
                assert_eq!(
                    budget.list_mutation_events(100, Some(&fixture.request.capability.id), None)?,
                    before
                );
            }
        }
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

fn accept_control(listener: &UnixListener) -> TestResult<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(stream)
}
