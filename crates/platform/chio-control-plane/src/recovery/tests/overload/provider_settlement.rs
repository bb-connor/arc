//! Provider finality retains native execution while real commands await effects.
use super::*;
use crate::recovery::connector::capacity_test_support;
use crate::recovery::PinnedSupportIssueConnector;
use chio_core_types::recovery::{RecoveryDigestDomain, SignedRecoveryProviderFinalityV1};
use chio_egress_contract::HttpEgressContract;
use std::collections::BTreeSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::{rustls, TlsAcceptor};

// The durable external effect is the existing fixture server. Only its response
// timing changes: each accepted provider call has its own stored release permit.
struct HeldResponseServer {
    durable: PersistentEffectServer,
    hold: Arc<AtomicUsize>,
    started: mpsc::Sender<()>,
    release: Arc<Semaphore>,
}
#[async_trait::async_trait]
impl ToolServerConnection for HeldResponseServer {
    fn recovery_effect_contract(&self) -> Option<RecoveryEffectContractV1> {
        self.durable.recovery_effect_contract()
    }
    fn server_id(&self) -> &str {
        self.durable.server_id()
    }
    fn tool_names(&self) -> Vec<String> {
        self.durable.tool_names()
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::Internal("native context required".into()))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invoke_with_cost_and_context(context, arguments, nested)
            .await
            .map(|(value, _)| value)
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<chio_kernel::ToolInvocationCost>), KernelError> {
        let response = self
            .durable
            .invoke_with_cost_and_context(context, arguments, nested)
            .await?;
        match self.hold.load(Ordering::SeqCst) {
            1 => return Err(KernelError::Internal("external response lost".into())),
            2 => {
                self.started.try_send(()).map_err(|_| {
                    KernelError::Internal("provider synchronization refused".into())
                })?;
                self.release
                    .acquire()
                    .await
                    .map_err(|_| KernelError::Internal("provider release unavailable".into()))?
                    .forget();
            }
            _ => {}
        }
        Ok(response)
    }
}

struct HeldProvider {
    fixture: RecoveryFixture,
    hold: Arc<AtomicUsize>,
    started: mpsc::Receiver<()>,
    release: Arc<Semaphore>,
}
impl HeldProvider {
    fn new(contract: Option<RecoveryEffectContractV1>) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        if let Some(contract) = contract {
            std::fs::write(
                directory
                    .path()
                    .join("current-recovery-effect-contract.json"),
                chio_core_types::canonical_json_bytes(&contract)?,
            )?;
        }
        let hold = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (started, observations) = mpsc::channel(2);
        let durable = PersistentEffectServer::new(
            directory.path().join("effects.db"),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        )?;
        let server = HeldResponseServer {
            durable,
            hold: hold.clone(),
            started,
            release: release.clone(),
        };
        let fixture = RecoveryFixture::open_with_tool_server(
            directory.path().to_path_buf(),
            Some(directory),
            false,
            None,
            Some(Box::new(server)),
        )?;
        Ok(Self {
            fixture,
            hold,
            started: observations,
            release,
        })
    }
}
impl Drop for HeldProvider {
    fn drop(&mut self) {
        // Release both original-only drivers even if setup or an assertion fails.
        self.release.add_permits(2);
    }
}

fn effect_kind(effect: &EffectObservationV1) -> &'static str {
    match effect {
        EffectObservationV1::NeverAdmitted => "never_admitted",
        EffectObservationV1::AdmissionUnresolved { .. } => "admission_unresolved",
        EffectObservationV1::ClosedBeforeEffect { .. } => "closed_before_effect",
        EffectObservationV1::AwaitingApproval { .. } => "awaiting_approval",
        EffectObservationV1::InFlight { .. } => "in_flight",
        EffectObservationV1::AwaitingCallerReport { .. } => "awaiting_caller_report",
        EffectObservationV1::Unknown { .. } => "unknown",
        EffectObservationV1::Complete { .. } => "complete",
        EffectObservationV1::Partial { .. } => "partial",
        EffectObservationV1::FailedAfterEffect { .. } => "failed_after_effect",
    }
}

fn diagnose_original_capture(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
    response: &RecoveryCommandResultV1,
) -> TestResult {
    use chio_core::receipt::decision::Decision;
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
    use chio_kernel::ReceiptStore;

    let record = fixture.record(workflow)?;
    let store = fixture.authority.admission_operation_store();
    let native = match &record.admission {
        Some(intent) => store.load_by_operation_id(&AdmissionOperationId::from_persisted(
            intent.native_operation_id.as_str(),
        )?)?,
        None => None,
    };
    let receipt = match native.as_ref().and_then(|native| native.terminal_replay()) {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => {
            store.load_chio_receipt(receipt_id.as_str())?
        }
        _ => None,
    };
    let denial_guard = receipt
        .as_ref()
        .and_then(|receipt| match &receipt.decision {
            Some(Decision::Deny { guard, .. }) => Some(guard.as_str()),
            _ => None,
        })
        .map(|guard| {
            if guard.len() <= 96
                && guard
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            {
                guard
            } else {
                "non_code_guard"
            }
        });
    // Print only closed state tags, one bounded guard code and durable counts.
    // Receipt payloads, admission material and credentials never enter this log.
    eprintln!(
        "PROVIDER_ORIGINAL_CAPTURE effect={} retained_effect={} control={:?} admission_present={} admission_closed={} captured={} native_state={:?} dispatch_committed={} denial_guard={denial_guard:?} persisted_effects={}",
        effect_kind(&response.status.effect),
        effect_kind(&record.effect),
        response.status.control,
        record.admission.is_some(),
        record.admission_closed,
        record.captured,
        native.as_ref().map(|native| native.state()),
        native.as_ref().is_some_and(|native| native.dispatch_commit().is_some()),
        external_count(&fixture.path)?,
    );
    Ok(())
}

fn finality_for_original(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<SignedRecoveryProviderFinalityV1> {
    let record = fixture.record(workflow)?;
    let intent = record.admission.as_ref().ok_or("original intent missing")?;
    let native = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?,
        )?
        .ok_or("captured native original missing")?;
    let operation = match &record.effect {
        EffectObservationV1::Unknown { operation } => operation,
        _ => return Err("captured unknown original required".into()),
    };
    let profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let now = now_ms()?;
    Ok(SignedRecoveryProviderFinalityV1::sign(
        RecoveryProviderFinalityV1 {
            schema: RecoveryProviderFinalitySchema::V1,
            version: VersionV1,
            scope: record.scope.clone(),
            workflow_id: record.workflow_id.clone(),
            continuation_id: record.continuation_id.clone(),
            operation_id: operation.operation_id().clone(),
            native_admission_digest: operation.native_admission_digest(),
            attempt_id: ProviderAttemptId::new(
                &native
                    .provider_attempt()
                    .ok_or("provider attempt missing")?
                    .attempt_id,
            )?,
            provider: profile.effect_contract.provider.clone(),
            account: profile.effect_contract.account.clone(),
            resource_digest: ResourceDigest::from_bytes(recovery_digest(
                RecoveryDigestDomain::ProviderResource,
                &profile.effect_contract.resource,
            )?),
            contract_digest: profile.contract_digest,
            observed_at_unix_ms: SafeInteger::new(now)?,
            expires_at_unix_ms: SafeInteger::new(now + 30_000)?,
            disposition: RecoveryEffectDisposition::Succeeded,
            applied_effects: SafeInteger::new(1)?,
        },
        &Keypair::from_seed(&[143; 32]),
    )?)
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_provider_commands_cannot_starve_original_provider_finality() -> TestResult {
    // Sharing any native finality phase with command execution breaks this test:
    // all four command jobs have reached real durable provider effects and wait.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let directory = tempfile::tempdir()?;
    let mut contract = authority_history::fixture_effect_contract(directory.path())?;
    contract.resource = ProtectedText::new(&format!("https://{address}/issues"))?;
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
    let certificate = reqwest::Certificate::from_der(certified.cert.der())?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        )),
    )?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let mut providers = vec![
        HeldProvider::new(Some(contract.clone()))?,
        HeldProvider::new(None)?,
    ];
    let first = &providers[0].fixture;
    let original = Box::pin(first.ready_named("unknown-original", "unknown-original")).await?;
    providers[0].hold.store(1, Ordering::SeqCst);
    let response = first
        .execute(
            "capture-unknown-original",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: original.clone(),
                expected_revision: first.record(&original)?.revision,
            },
        )
        .await?;
    diagnose_original_capture(first, &original, &response)?;
    assert!(matches!(
        response.status.effect,
        EffectObservationV1::Unknown { .. }
    ));
    assert_eq!(external_count(&first.path)?, 1);
    let proof = finality_for_original(first, &original)?;
    let body = chio_core_types::canonical_json_bytes(&proof)?;
    let operation = first
        .record(&original)?
        .admission
        .ok_or("original intent missing")?
        .native_operation_id;
    let mut server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut stream = acceptor.accept(socket).await?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await?;
            if read == 0 || request.len() + read > 8192 {
                return Err(std::io::Error::other("bounded provider request missing"));
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
            body.len(),
        );
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        Ok::<_, std::io::Error>(request)
    });
    let mut connector = PinnedSupportIssueConnector::new(
        "server-a".into(),
        "send".into(),
        contract,
        HttpEgressContract {
            tenant_egress_namespace: "tests.recovery.provider-finality".into(),
            allowed_schemes: BTreeSet::from(["https".into()]),
            allowed_authority_set: BTreeSet::from([address.to_string()]),
            deny_loopback: false,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 65536,
        },
        "submission-fixture-secret".into(),
        "observation-fixture-secret".into(),
    )?;
    capacity_test_support::trust_fixture_certificate(&mut connector, certificate)?;

    let mut drivers = Vec::new();
    for (provider_index, provider) in providers.iter_mut().enumerate() {
        eprintln!("PROVIDER_FINALITY_FIXTURE preparing_held_domain={provider_index}");
        for identity in ["held-first", "held-second"] {
            // Each approval observes the source basis of its own capture. Do
            // not preapprove another workflow before the earlier native join.
            let workflow = Box::pin(provider.fixture.ready_named(identity, identity)).await?;
            provider.hold.store(2, Ordering::SeqCst);
            let command = provider.fixture.command(
                &format!("held-resume:{}", workflow.as_str()),
                RecoveryCommandBodyV1::ResumeWorkflow {
                    expected_revision: provider.fixture.record(&workflow)?.revision,
                    workflow_id: workflow.clone(),
                },
            )?;
            let runtime = provider.fixture.runtime.clone();
            let capability = provider.fixture.control.clone();
            drivers.push(tokio::spawn(async move {
                runtime.execute_command(&capability, &command).await
            }));
            let started =
                tokio::time::timeout(Duration::from_secs(2), provider.started.recv()).await;
            if let Err(error) = &started {
                if let Some(driver) = drivers.last_mut() {
                    if driver.is_finished() {
                        let result = driver.await?;
                        return Err(format!(
                            "held provider command ended before its durable effect: domain={provider_index} workflow={} result={result:?}",
                            workflow.as_str(),
                        )
                        .into());
                    }
                }
                return Err(format!(
                    "held provider capture did not arrive: domain={provider_index} workflow={} error={error}",
                    workflow.as_str(),
                )
                .into());
            }
            started?.ok_or("provider command did not reach its held durable effect")?;
            eprintln!(
                "PROVIDER_FINALITY_FIXTURE held_domain={provider_index} workflow={}",
                workflow.as_str()
            );
            assert!(provider.fixture.record(&workflow)?.captured);
        }
    }
    assert_eq!(drivers.len(), 4);
    assert!(drivers.iter().all(|driver| !driver.is_finished()));
    assert_eq!(external_count(&providers[0].fixture.path)?, 3);
    assert_eq!(external_count(&providers[1].fixture.path)?, 2);
    let first = &providers[0].fixture;
    let charged = first.process.process("root")?.tree_calls;
    let settled = tokio::time::timeout(
        Duration::from_secs(2),
        Box::pin(
            first
                .runtime
                .settle_from_provider(&first.control, &original, &connector),
        ),
    )
    .await;
    eprintln!("PROVIDER_FINALITY_WITH_SATURATED_COMMANDS result={settled:?}");
    let commands_still_held = drivers.iter().all(|driver| !driver.is_finished());
    // Drain genuine accepted work before evaluating the RED/GREEN oracle.
    for provider in &providers {
        provider.release.add_permits(2);
    }
    for (index, driver) in drivers.into_iter().enumerate() {
        tokio::time::timeout(Duration::from_secs(2), driver)
            .await
            .map_err(|error| {
                format!("released original driver {index} did not complete: {error}")
            })???;
    }
    assert!(
        commands_still_held,
        "command work stopped holding capacity before finality finished"
    );
    if !matches!(settled, Ok(Ok(_))) {
        server.abort();
        let _ = (&mut server).await;
    }
    assert!(
        matches!(settled, Ok(Ok(_))),
        "native finality shared saturated command capacity: {settled:?}"
    );
    let settled = settled??;
    assert!(settled.effect.is_settled());
    assert_eq!(settled.effect.applied_effects(), Some(SafeInteger::new(1)?));
    let retained = first.record(&original)?;
    assert!(retained.effect.is_settled());
    assert_eq!(retained.provider_lookups.get(), 1);
    assert_eq!(first.process.process("root")?.tree_calls, charged);
    assert_eq!(external_count(&first.path)?, 3);
    let request = tokio::time::timeout(Duration::from_secs(2), server).await???;
    let request = std::str::from_utf8(&request)?;
    assert!(request.starts_with(&format!(
        "GET /issues/operations/{} HTTP/1.1\r\n",
        operation.as_str()
    )));
    assert!(request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: Bearer observation-fixture-secret")));
    assert!(!request.contains("submission-fixture-secret"));
    Ok(())
}
