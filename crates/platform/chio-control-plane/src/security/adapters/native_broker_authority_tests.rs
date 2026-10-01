// The real native lifecycle owns every change observed by the broker authority.
use super::*;
use chio_secret_broker::authority_ipc::BrokerAdmissionAuthority;
use chio_secret_broker::budget::{
    AuthorizeExecutionHoldRequest, BrokerExecutionBudget, ExecutionHoldState,
    QueryExecutionHoldRequest, ReverseExecutionHoldRequest,
};
use chio_secret_broker::kernel_admission::BrokerKernelAdmissionAuthority;
use chio_secret_broker::store::AttemptRegistration;

struct AuthorityProbe {
    authority: Arc<BrokerKernelAdmissionAuthority>,
    registration: Arc<ObserveRegistration>,
    execute: BrokerExecuteRequest,
    refuse_preparation: bool,
    invocations: AtomicUsize,
}

impl AuthorityProbe {
    fn original(&self) -> TestResult<AttemptRegistration> {
        self.registration
            .prepared
            .lock()
            .map_err(|_| "registration lock")?
            .clone()
            .ok_or_else(|| "original registration missing".into())
    }

    fn observe_capture(&self, arguments: &serde_json::Value) -> TestResult {
        assert_eq!(arguments, &serde_json::to_value(&self.execute)?);
        let registration = self.original()?;
        let trusted = self.authority.prepare_execution(&self.execute)?;
        trusted.validate_for(&self.execute)?;
        assert_eq!(
            trusted.admission_operation_id,
            registration.ids.operation_id
        );
        assert_eq!(trusted.quotas, registration.quotas);
        assert_eq!(
            trusted.authority_metadata_digest,
            registration.authority_metadata_digest
        );
        assert_eq!(
            trusted.revocation_authority_domain,
            registration.revocation_authority_domain
        );
        assert_eq!(
            trusted.prepared_dispatch_id,
            chio_secret_broker::registration::prepared_dispatch_id(&registration, &self.execute)?
        );
        assert!(trusted.source_receipt_ids.is_empty());
        let state = self.authority.query_execution_hold(&query(&registration))?;
        assert!(matches!(&state, ExecutionHoldState::Captured(_)));
        assert_eq!(
            self.authority.query_execution_hold(&query(&registration))?,
            state
        );
        assert_eq!(
            self.authority
                .authorize_execution_hold(&authorize(&registration))?,
            state
        );
        let capture = capture(&registration, &self.execute)?;
        assert_eq!(self.authority.capture_execution_hold(&capture)?, state);
        let mut changed_capture = capture;
        changed_capture.authorization_artifact_digest = "f".repeat(64);
        assert!(self
            .authority
            .capture_execution_hold(&changed_capture)
            .is_err());
        assert!(self
            .authority
            .reverse_execution_hold(&reverse(&registration))
            .is_err());
        for change in ["invocation", "body", "parent", "proof"] {
            let mut altered = self.execute.clone();
            match change {
                "invocation" => altered.invocation_id.push_str("-other"),
                "body" => altered.request.body.push(b' '),
                "parent" => altered
                    .capability
                    .body
                    .parent_capability_id
                    .push_str("-other"),
                _ => altered.proof.body.nonce.push('f'),
            }
            assert!(
                self.authority.prepare_execution(&altered).is_err(),
                "{change}"
            );
        }
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for AuthorityProbe {
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
        ObserveBrokerPreparation(self.registration.clone())
            .prepare_delivery(context)
            .await?;
        let check = || -> TestResult {
            let registration = self.original()?;
            assert_eq!(
                self.authority.query_execution_hold(&query(&registration))?,
                ExecutionHoldState::Held
            );
            assert_eq!(
                self.authority
                    .authorize_execution_hold(&authorize(&registration))?,
                ExecutionHoldState::Held
            );
            assert!(self
                .authority
                .reverse_execution_hold(&reverse(&registration))
                .is_err());
            assert!(self.authority.prepare_execution(&self.execute).is_err());
            assert_eq!(
                self.authority
                    .capture_execution_hold(&capture(&registration, &self.execute)?)?,
                ExecutionHoldState::Held
            );
            let mut changed = authorize(&registration);
            changed.quotas[0].maximum_executions += 1;
            assert!(self.authority.authorize_execution_hold(&changed).is_err());
            let mut changed = query(&registration);
            changed.capture_event_id.push_str("-other");
            assert!(self.authority.query_execution_hold(&changed).is_err());
            Ok(())
        };
        check().map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        if self.refuse_preparation {
            return Err(KernelError::GuardDenied(
                "test refusal before capture".into(),
            ));
        }
        Ok(())
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.observe_capture(&arguments)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        Ok(arguments)
    }
}

#[test]
fn native_broker_authority_observes_original_lifecycle_without_mutating_custody() -> TestResult {
    use chio_kernel::RevocationStore;
    for (refuse_preparation, strict_nonce) in [(false, false), (true, false), (false, true)] {
        let mut fixture = super::super::super::super::public_fixture()?;
        let (execute, participant, registration) = install_broker(&mut fixture)?;
        let authority = Arc::new(BrokerKernelAdmissionAuthority::new(
            BrokerNativeCaptureReader::new(
                &fixture.authority,
                fixture.binding.clone(),
                participant,
            )?,
            registration.registrar.clone(),
        )?);
        authority.capabilities().require_production()?;
        assert!(authority.prepare_execution(&execute).is_err());
        let probe = Arc::new(AuthorityProbe {
            authority: authority.clone(),
            registration: registration.clone(),
            execute: execute.clone(),
            refuse_preparation,
            invocations: AtomicUsize::new(0),
        });
        fixture
            .kernel
            .register_tool_server(Box::new(ProbeConnection(probe.clone())));
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
        if strict_nonce {
            use super::super::super::nonce::execution::{install_nonce, issue};
            install_nonce(&mut fixture, 120);
            issue(&mut fixture)?;
            assert!(authority.prepare_execution(&execute).is_err());
        }
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(
            response.verdict,
            if refuse_preparation {
                Verdict::Deny
            } else {
                Verdict::Allow
            },
            "{:?}",
            response.reason
        );
        assert_eq!(
            probe.invocations.load(Ordering::SeqCst),
            usize::from(!refuse_preparation)
        );
        let registration = probe.original()?;
        let before = fixture.authority.budget_store().list_mutation_events(
            100,
            Some(&fixture.request.capability.id),
            None,
        )?;
        let state = authority.query_execution_hold(&query(&registration))?;
        if refuse_preparation {
            assert_eq!(state, ExecutionHoldState::Reversed);
            assert_eq!(
                authority.reverse_execution_hold(&reverse(&registration))?,
                state
            );
        } else {
            assert!(matches!(&state, ExecutionHoldState::Captured(_)));
            assert!(authority
                .reverse_execution_hold(&reverse(&registration))
                .is_err());
        }
        assert!(
            authority.prepare_execution(&execute).is_err(),
            "terminal history is not dispatch authority"
        );
        assert!(fixture
            .authority
            .revocation_store()
            .revoke(&fixture.request.capability.id)?);
        assert_eq!(
            authority.query_execution_hold(&query(&registration))?,
            state
        );
        assert_eq!(
            authority.authorize_execution_hold(&authorize(&registration))?,
            state
        );
        assert_eq!(
            authority.capture_execution_hold(&capture(&registration, &execute)?)?,
            state
        );
        assert_eq!(
            fixture.authority.budget_store().list_mutation_events(
                100,
                Some(&fixture.request.capability.id),
                None
            )?,
            before
        );
    }
    Ok(())
}

struct ProbeConnection(Arc<AuthorityProbe>);
#[async_trait::async_trait]
impl ToolServerConnection for ProbeConnection {
    fn server_id(&self) -> &str {
        self.0.server_id()
    }
    fn tool_names(&self) -> Vec<String> {
        self.0.tool_names()
    }
    async fn prepare_delivery(
        &self,
        context: &chio_kernel::ToolDispatchContext,
    ) -> Result<(), KernelError> {
        self.0.prepare_delivery(context).await
    }
    async fn invoke(
        &self,
        name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.invoke(name, arguments, bridge).await
    }
}

fn query(registration: &AttemptRegistration) -> QueryExecutionHoldRequest {
    QueryExecutionHoldRequest {
        operation_id: registration.ids.operation_id.clone(),
        invocation_id: registration.invocation_id.clone(),
        parent_capability_id: registration.parent_capability_id.clone(),
        broker_capability_id: registration.broker_capability_id.clone(),
        hold_id: registration.ids.hold_id.clone(),
        authorize_event_id: registration.ids.authorize_event_id.clone(),
        reverse_event_id: registration.ids.reverse_event_id.clone(),
        capture_event_id: registration.ids.capture_event_id.clone(),
    }
}
fn authorize(registration: &AttemptRegistration) -> AuthorizeExecutionHoldRequest {
    AuthorizeExecutionHoldRequest {
        operation_id: registration.ids.operation_id.clone(),
        invocation_id: registration.invocation_id.clone(),
        parent_capability_id: registration.parent_capability_id.clone(),
        broker_capability_id: registration.broker_capability_id.clone(),
        hold_id: registration.ids.hold_id.clone(),
        authorize_event_id: registration.ids.authorize_event_id.clone(),
        quotas: registration.quotas.clone(),
        authority_metadata_digest: registration.authority_metadata_digest.clone(),
    }
}
fn reverse(registration: &AttemptRegistration) -> ReverseExecutionHoldRequest {
    ReverseExecutionHoldRequest {
        operation_id: registration.ids.operation_id.clone(),
        invocation_id: registration.invocation_id.clone(),
        parent_capability_id: registration.parent_capability_id.clone(),
        broker_capability_id: registration.broker_capability_id.clone(),
        hold_id: registration.ids.hold_id.clone(),
        reverse_event_id: registration.ids.reverse_event_id.clone(),
        proof_dispatch_did_not_begin: true,
    }
}

fn capture(
    registration: &AttemptRegistration,
    execute: &BrokerExecuteRequest,
) -> TestResult<CaptureExecutionHoldRequest> {
    let revocations = chio_secret_broker::revocation::CanonicalBrokerRevocationSet::new(
        &registration.parent_capability_id,
        &[],
        &registration.broker_capability_id,
        &execute.capability.body.revocation_id,
    )?;
    Ok(CaptureExecutionHoldRequest {
        operation_id: registration.ids.operation_id.clone(),
        invocation_id: registration.invocation_id.clone(),
        parent_capability_id: registration.parent_capability_id.clone(),
        broker_capability_id: registration.broker_capability_id.clone(),
        hold_id: registration.ids.hold_id.clone(),
        capture_event_id: registration.ids.capture_event_id.clone(),
        revocation_ids: revocations.ids().to_vec(),
        revocation_set_digest: revocations.digest().into(),
        authorization_artifact_digest: chio_secret_broker::capability::capability_digest(
            &execute.capability,
        )?,
        authority_metadata_digest: registration.authority_metadata_digest.clone(),
    })
}
