// The broker reads the original kernel capture; it cannot acquire another hold.
use super::*;
use chio_core::crypto::Ed25519Backend;
use chio_kernel::admission_operation::AdmissionDigest;
use chio_kernel::budget_store::BudgetInvocationCaptureDecision;
use chio_kernel::supplemental_admission::{
    SupplementalAdmissionAuthorityBindingV1, SupplementalAdmissionParticipant,
    SupplementalAdmissionRegistrationContext,
};
use chio_kernel::supplemental_quota::SupplementalQuotaVerifierError;
use chio_secret_broker::budget::CaptureExecutionHoldRequest;
use chio_secret_broker::kernel_admission::{
    BrokerAdmissionParticipant, BrokerNativeCaptureReader, BrokerQuotaVerifier,
    BrokerQuotaVerifierConfig,
};
use chio_secret_broker::protocol::*;
use chio_secret_broker::{capability::issue_capability, proof::issue_request_proof};

#[cfg(target_os = "linux")]
mod connection {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_broker_connection_tests.rs"
    ));
}

struct ObserveRegistration {
    count: AtomicUsize,
    reader: BrokerNativeCaptureReader,
    registrar: Arc<BrokerAdmissionParticipant>,
    prepared: Mutex<Option<chio_secret_broker::store::AttemptRegistration>>,
}

impl SupplementalAdmissionParticipant for ObserveRegistration {
    fn register_original(
        &self,
        context: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> Result<(), SupplementalQuotaVerifierError> {
        let check = || -> TestResult {
            let execute = serde_json::from_value(context.request().arguments.clone())?;
            let binding = context
                .budget()
                .admission_binding
                .as_ref()
                .ok_or("budget binding")?;
            let request = capture_request(
                &execute,
                context.operation().binding(),
                binding.revocation_set.ids().to_vec(),
            )?;
            assert_eq!(self.reader.read_capture(&request, now_ms()?)?, None);
            assert!(self
                .reader
                .read_registration(
                    self.registrar.as_ref(),
                    context.operation().binding().operation_id(),
                    now_ms()?
                )?
                .is_none());
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        check().map_err(|_| SupplementalQuotaVerifierError::new("pre-capture readback failed"))
    }
}

struct ObserveBrokerPreparation(Arc<ObserveRegistration>);

#[async_trait::async_trait]
impl ToolServerConnection for ObserveBrokerPreparation {
    fn server_id(&self) -> &str {
        "server-a"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["send".into()]
    }
    async fn prepare_delivery(
        &self,
        context: &chio_kernel::ToolDispatchContext,
    ) -> Result<(), KernelError> {
        let read = || -> TestResult {
            let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                context.operation_id(),
            )?;
            let (registration, execute) = self
                .0
                .reader
                .read_registration(self.0.registrar.as_ref(), &operation, now_ms()?)?
                .ok_or("prepared original broker hold")?;
            assert_eq!(registration.ids.operation_id, context.operation_id());
            assert_eq!(registration.invocation_id, context.request_id());
            assert_eq!(execute.invocation_id, context.request_id());
            assert_eq!(
                registration.revocation_authority_domain,
                "native-broker-domain"
            );
            assert_eq!(registration.quotas.len(), 2);
            assert!(registration
                .quotas
                .iter()
                .all(|quota| quota.maximum_executions == 1));
            registration.validate()?;
            *self.0.prepared.lock().map_err(|_| "preparation lock")? = Some(registration);
            Ok(())
        };
        read().map_err(|error| KernelError::GuardDenied(error.to_string()))
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::GuardDenied(
            "readback fixture stops at native capture".into(),
        ))
    }
}

#[test]
fn native_broker_capture_reads_only_original_operation_and_never_recharges() -> TestResult {
    use chio_kernel::RevocationStore;
    let mut fixture = super::super::super::public_fixture()?;
    let (execute, participant, registrations) = install_broker(&mut fixture)?;
    let reader = BrokerNativeCaptureReader::new(
        &fixture.authority,
        fixture.binding.clone(),
        participant.clone(),
    )?;
    let ledger = run_capture(&mut fixture, true)?;
    let registrar = registrations.registrar.clone();
    let original_registration = reader
        .read_registration(registrar.as_ref(), &ledger.operation_id, now_ms()?)?
        .ok_or("original broker registration")?;
    assert_eq!(original_registration.1, execute);
    assert!(reader
        .read_registration(
            registrar.as_ref(),
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                "f".repeat(64)
            )?,
            now_ms()?,
        )?
        .is_none());
    assert_eq!(registrations.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        registrations
            .prepared
            .lock()
            .map_err(|_| "preparation lock")?
            .as_ref()
            .ok_or("preparation was not reached")?
            .ids
            .operation_id,
        ledger.operation_id.as_str()
    );
    let store = fixture.authority.admission_operation_store();
    let witness = store
        .load_native_dispatch_capture_witness(
            &ledger.operation_id,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("original native capture")?;
    let BudgetInvocationCaptureDecision::Captured(capture) = &witness.capture.decision else {
        return Err("expected capture".into());
    };
    let binding = capture
        .admission_binding
        .as_ref()
        .ok_or("capture binding")?;
    let request = capture_request(
        &execute,
        witness.capture.operation.binding(),
        binding.revocation_set.ids().to_vec(),
    )?;
    let before = fixture.authority.budget_store().list_mutation_events(
        100,
        Some(&fixture.request.capability.id),
        None,
    )?;
    let commit = reader
        .read_capture(&request, now_ms()?)?
        .ok_or("broker capture readback")?;
    assert_eq!(
        commit.budget_commit_index,
        capture.metadata.budget_commit_index.ok_or("index")?
    );
    assert_eq!(
        commit.authority_commit_index,
        witness.authority_commit_index
    );
    assert_eq!(
        commit.revocation_commit_index,
        witness.revocation_commit_index
    );
    assert_eq!(
        commit.checked_revocation_set_digest,
        request.revocation_set_digest
    );
    assert_eq!(
        commit.leader_epoch,
        witness
            .capture
            .operation
            .dispatch_commit()
            .ok_or("dispatch")?
            .store_fence
            .owner_epoch
    );
    assert_ne!(
        request.revocation_set_digest,
        binding.revocation_set.digest()
    );
    for field in [
        "invocationId",
        "parentCapabilityId",
        "brokerCapabilityId",
        "holdId",
        "captureEventId",
        "authorityMetadataDigest",
        "authorizationArtifactDigest",
    ] {
        let mut value = serde_json::to_value(&request)?;
        value[field] = serde_json::Value::String("e".repeat(64));
        let changed: CaptureExecutionHoldRequest = serde_json::from_value(value)?;
        assert!(reader.read_capture(&changed, now_ms()?).is_err(), "{field}");
    }
    let mut changed = request.clone();
    changed.revocation_ids.push("unrelated-extra-member".into());
    changed.revocation_ids.sort();
    changed.revocation_set_digest = broker_revocations(&execute, &changed.revocation_ids)?
        .digest()
        .into();
    assert!(reader.read_capture(&changed, now_ms()?).is_err());
    let wrong_participant = SupplementalAdmissionAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("participant", "foreign-participant")?,
        AdmissionDigest::try_new("configuration", "d".repeat(64))?,
        AdmissionIdentifier::try_new("verifier", "foreign-verifier")?,
        AdmissionDigest::try_new("verifier configuration", "c".repeat(64))?,
    );
    let wrong_reader = BrokerNativeCaptureReader::new(
        &fixture.authority,
        fixture.binding.clone(),
        wrong_participant,
    )?;
    assert!(wrong_reader.read_capture(&request, now_ms()?).is_err());
    assert!(wrong_reader
        .read_registration(registrar.as_ref(), &ledger.operation_id, now_ms()?)
        .is_err());
    drop(wrong_reader);
    assert!(fixture
        .authority
        .revocation_store()
        .revoke(&fixture.request.capability.id)?);
    assert_eq!(
        reader.read_capture(&request, now_ms()?)?,
        Some(commit.clone())
    );
    assert_eq!(
        reader.read_registration(registrar.as_ref(), &ledger.operation_id, now_ms()?)?,
        Some(original_registration.clone())
    );
    assert_eq!(
        fixture.authority.budget_store().list_mutation_events(
            100,
            Some(&fixture.request.capability.id),
            None
        )?,
        before
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    drop(store);
    drop(registrations);
    let Fixture {
        kernel,
        authority,
        binding: native,
        _directory,
        ..
    } = fixture;
    drop(kernel);
    drop(authority);
    // The old reader keeps its owner alive. Dropping it is required before a
    // new owner can open the same authority and read the historical decision.
    drop(reader);
    let reopened = SqliteAuthorityStore::open_serving(
        _directory.path().join("admission.db"),
        _directory.path().join("locks"),
    )?;
    let reader = BrokerNativeCaptureReader::new(&reopened, native, participant)?;
    assert_eq!(reader.read_capture(&request, now_ms()?)?, Some(commit));
    assert_eq!(
        reader.read_registration(registrar.as_ref(), &ledger.operation_id, now_ms()?)?,
        Some(original_registration)
    );
    Ok(())
}

fn install_broker(
    fixture: &mut Fixture,
) -> TestResult<(
    BrokerExecuteRequest,
    SupplementalAdmissionAuthorityBindingV1,
    Arc<ObserveRegistration>,
)> {
    let issuer = Keypair::from_seed(&[31; 32]);
    let verifier = BrokerQuotaVerifier::new(
        BrokerQuotaVerifierConfig {
            issuer: issuer.public_key(),
            audience: "native-broker".into(),
            server_id: fixture.request.server_id.clone(),
            tool_name: fixture.request.tool_name.clone(),
            provider_adapter_id: "bearer".into(),
            provider_adapter_version: 1,
            credential_placement:
                chio_secret_broker::daemon_runtime::ProviderPlacementConfig::BearerAuthorization,
        },
        Arc::new(chio_secret_broker::daemon::SystemDaemonClock),
    )?;
    let selected = verifier.binding().clone();
    // No broker transport is invoked by this custody-read test. Its production
    // configuration still determines the exact original participant identity.
    let registrar = Arc::new(BrokerAdmissionParticipant::new(
        chio_secret_broker::ipc_client::BrokerIpcClientConfig {
            socket_path: fixture._directory.path().join("b.sock"),
            tenant_scope: "native-broker-tenant".into(),
            timeout_ms: 1000,
            expected_peer: chio_secret_broker::ipc_client::BrokerPeerIdentity {
                process_id: std::process::id(),
                user_id: rustix::process::geteuid().as_raw(),
                group_id: rustix::process::getegid().as_raw(),
            },
            trusted_receipt_signer: Keypair::from_seed(&[35; 32]).public_key(),
        },
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[34; 32]))),
        "native-broker-domain".into(),
        &verifier,
    )?);
    let participant = registrar.binding().clone();
    fixture
        .kernel
        .set_supplemental_quota_verifier(Arc::new(verifier), selected)?;
    let registrations = Arc::new(ObserveRegistration {
        count: AtomicUsize::new(0),
        registrar,
        prepared: Mutex::new(None),
        reader: BrokerNativeCaptureReader::new(
            &fixture.authority,
            fixture.binding.clone(),
            participant.clone(),
        )?,
    });
    fixture
        .kernel
        .set_supplemental_admission_participant(registrations.clone(), participant.clone())?;
    fixture
        .kernel
        .register_tool_server(Box::new(ObserveBrokerPreparation(registrations.clone())));
    let now = now_ms()? / 1000;
    let request = BrokerRequest {
        destination: BrokerDestination::parse("https://example.com/v1", "POST", false)?,
        headers: vec![HeaderField::normalized(
            "content-type",
            b"application/json",
        )?],
        body: b"{}".to_vec(),
        approved_preview_sha256: None,
        options: CallerOptions {
            timeout_ms: 1000,
            streaming: false,
            response_limit_bytes: 256,
        },
    };
    let capability = issue_capability(
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.into(),
            issuer: issuer.public_key(),
            capability_id: "native-broker-cap".into(),
            parent_capability_id: fixture.request.capability.id.clone(),
            subject: fixture.agent.public_key(),
            audience: "native-broker".into(),
            issued_at_unix_seconds: now,
            not_before_unix_seconds: now,
            expires_at_unix_seconds: now + 300,
            credential: CredentialRef {
                provider: "generic-https".into(),
                credential_id: "credential".into(),
                version: 1,
            },
            provider_adapter_id: "bearer".into(),
            provider_adapter_version: 1,
            destination: request.destination.clone(),
            constraints: RequestConstraints {
                allowed_caller_headers: vec!["content-type".into()],
                provider_owned_headers: vec!["authorization".into()],
                maximum_body_bytes: 128,
                required_body_sha256: chio_secret_broker::proof::body_digest(&request.body),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 256,
                streaming_allowed: false,
                maximum_timeout_ms: 1000,
            },
            broker_quota_key_id: "native-broker-quota".into(),
            maximum_executions: 1,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "native-broker-revocation".into(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: fixture.agent.public_key(),
                nonce_ttl_seconds: 300,
            },
        },
        &Ed25519Backend::new(issuer),
        true,
    )?;
    let proof = issue_request_proof(&capability, &request, "1".repeat(32), now, &fixture.agent)?;
    let execute = BrokerExecuteRequest {
        schema: BROKER_EXECUTE_SCHEMA.into(),
        invocation_id: fixture.request.request_id.clone(),
        capability,
        proof,
        request,
    };
    fixture.request.arguments = serde_json::to_value(&execute)?;
    fixture.request.supplemental_authorization = Some(serde_json::from_value(serde_json::json!({
        "signed_extension": String::from_utf8(chio_core::canonical::canonical_json_bytes(&execute)?)?,
    }))?);
    Ok((execute, participant, registrations))
}

fn capture_request(
    execute: &BrokerExecuteRequest,
    operation: &chio_kernel::admission_operation::AdmissionOperationBindingV1,
    revocation_ids: Vec<String>,
) -> TestResult<CaptureExecutionHoldRequest> {
    let ids = chio_secret_broker::store::derive_attempt_ids_for_operation(
        &execute.capability.body.capability_id,
        &execute.invocation_id,
        &execute.proof.body.nonce,
        &chio_secret_broker::service::broker_request_digest(execute)?,
        operation.operation_id().as_str(),
    )?;
    Ok(CaptureExecutionHoldRequest {
        operation_id: ids.operation_id,
        invocation_id: execute.invocation_id.clone(),
        parent_capability_id: execute.capability.body.parent_capability_id.clone(),
        broker_capability_id: execute.capability.body.capability_id.clone(),
        hold_id: ids.hold_id,
        capture_event_id: ids.capture_event_id,
        revocation_set_digest: broker_revocations(execute, &revocation_ids)?
            .digest()
            .into(),
        revocation_ids,
        authorization_artifact_digest: chio_secret_broker::capability::capability_digest(
            &execute.capability,
        )?,
        authority_metadata_digest: operation.request_binding_hash().as_str().into(),
    })
}

fn broker_revocations(
    execute: &BrokerExecuteRequest,
    ids: &[String],
) -> TestResult<chio_secret_broker::revocation::CanonicalBrokerRevocationSet> {
    let body = &execute.capability.body;
    let ancestors = ids
        .iter()
        .filter(|id| {
            *id != &body.parent_capability_id
                && *id != &body.capability_id
                && *id != &body.revocation_id
        })
        .cloned()
        .collect::<Vec<_>>();
    let set = chio_secret_broker::revocation::CanonicalBrokerRevocationSet::new(
        &body.parent_capability_id,
        &ancestors,
        &body.capability_id,
        &body.revocation_id,
    )?;
    assert_eq!(set.ids(), ids);
    Ok(set)
}
