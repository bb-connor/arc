//! Public caller routes use exact original custody across namespace collisions
//! and approval waits, with the same library identity as physical SQLite.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, ThresholdApprovalProposal,
};
use chio_core::capability::threshold_approval::ThresholdApprovalRequirement;
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::caller_delivery::CallerExecutorIdentityV1;
use chio_kernel::{CallerExecutionReport, CallerStartResponse};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct MovingClock {
    epoch_ms: u64,
    now_ms: AtomicU64,
}
impl Clock for MovingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let now = self.now_ms.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::new(now),
            MonotonicInstant::from_nanos((now - self.epoch_ms) * 1_000_000),
        ))
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    clock: Arc<MovingClock>,
    kernel: ChioKernel,
    authority: SqliteAuthorityStore,
    executor: CallerExecutorIdentityV1,
    executor_key: Keypair,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let locks = directory.path().join("locks");
        create_private_directory(&locks)?;
        let database = directory.path().join("authority.db");
        SqliteAuthorityStore::provision(&database, &locks)?;
        let epoch_ms = now_unix_ms()? / 1000 * 1000;
        let clock = Arc::new(MovingClock {
            epoch_ms,
            now_ms: AtomicU64::new(epoch_ms),
        });
        let authority =
            SqliteAuthorityStore::open_serving_with_clock(&database, &locks, clock.clone())?;
        let mut kernel =
            ChioKernel::new_with_clock(kernel_config(Keypair::generate()), clock.clone());
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.register_tool_server(Box::new(MutationServer {
            invocations: Arc::new(AtomicU64::new(0)),
        }));
        let executor_key = Keypair::generate();
        let executor = CallerExecutorIdentityV1 {
            executor_id: AdmissionIdentifier::try_new("executor_id", "review-caller")?,
            public_key: executor_key.public_key(),
            key_epoch: 1,
        };
        kernel.set_caller_executor(executor.clone())?;
        Ok(Self {
            directory,
            clock,
            kernel,
            authority,
            executor,
            executor_key,
        })
    }
    fn strict_nonces(&mut self) {
        let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 16,
            require_nonce: true,
        };
        self.kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(
                chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config),
            ),
        );
    }
    fn finish(
        &self,
        authorization: &chio_kernel::caller_delivery::SignedCallerDispatchAuthorizationV1,
    ) -> TestResult<ToolCallResponse> {
        let ledger = SqliteCallerExecutionLedger::provision_with_clock(
            &self.directory.path().join("executor.db"),
            self.executor.clone(),
            4,
            self.clock.clone(),
        )?;
        let report = ledger.execute_once(
            authorization,
            &self.kernel.public_key(),
            &authorization.authorization.invocation,
            &self.executor_key,
            || {
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"external": true}),
                    realized_cost: None,
                })
            },
        )?;
        Ok(self
            .kernel
            .reconcile_authenticated_caller_execution_blocking(authorization, &report)?)
    }
}

#[cfg(unix)]
#[test]
fn caller_start_and_report_select_original_operation_across_tenants() -> TestResult {
    use chio_core::session::{
        EnterpriseFederationMethod, EnterpriseIdentityContext, OAuthBearerFederatedClaims,
        OAuthBearerSessionAuthInput, OperationContext, RequestId, SessionAuthContext,
        SessionOperation, ToolCallOperation,
    };
    let mut fixture = Fixture::new()?;
    let agent = Keypair::generate();
    let mut grant_scope = scope();
    grant_scope.grants[0].max_invocations = Some(4);
    let capability = fixture
        .kernel
        .issue_capability(&agent.public_key(), grant_scope, 300)?;
    let mut request = request(&capability);
    request.request_id = "reused-caller-request".into();
    let session = fixture
        .kernel
        .open_session(agent.public_key().to_hex(), vec![capability.clone()])?;
    fixture.kernel.set_session_auth_context(
        &session,
        SessionAuthContext::streamable_http_oauth_bearer_with_claims(OAuthBearerSessionAuthInput {
            principal: Some("oidc:https://issuer.example#sub:tenant-b".into()),
            issuer: Some("https://issuer.example".into()),
            subject: Some("tenant-b".into()),
            audience: Some("chio-mcp".into()),
            scopes: vec!["mcp:invoke".into()],
            federated_claims: OAuthBearerFederatedClaims::default(),
            enterprise_identity: Some(EnterpriseIdentityContext {
                provider_id: "review-tenant-provider".into(),
                provider_record_id: None,
                provider_kind: "oidc_jwks".into(),
                federation_method: EnterpriseFederationMethod::Jwt,
                principal: "oidc:https://issuer.example#sub:tenant-b".into(),
                subject_key: "tenant-b-subject".into(),
                client_id: None,
                object_id: None,
                tenant_id: Some("caller-tenant-b".into()),
                organization_id: None,
                groups: vec![],
                roles: vec![],
                source_subject: None,
                attribute_sources: Default::default(),
                trust_material_ref: None,
            }),
            token_fingerprint: Some("review-tenant-b".into()),
            origin: None,
        }),
    )?;
    fixture.kernel.activate_session(&session)?;
    let context = OperationContext::new(
        session,
        RequestId::new(&request.request_id),
        agent.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability,
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        extra_metadata: None,
    }));
    let response = fixture
        .kernel
        .evaluate_session_operation(&context, &operation)?;
    let chio_kernel::SessionOperationResponse::ToolCall(tenant_response) = response else {
        return Err("tenant operation omitted its tool response".into());
    };
    assert_eq!(
        tenant_response.verdict,
        Verdict::Allow,
        "{:?}",
        tenant_response.reason
    );
    assert_eq!(
        tenant_response.receipt.tenant_id.as_deref(),
        Some("caller-tenant-b")
    );
    fixture.strict_nonces();
    let reserved = fixture.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let nonce = reserved.execution_nonce.ok_or("original caller nonce")?;
    let authorization = match fixture
        .kernel
        .start_caller_execution_blocking(&nonce, &request.arguments)?
    {
        CallerStartResponse::Authorized(value) => *value,
        CallerStartResponse::Denied(response) => {
            return Err(format!("{:?}", response.reason).into())
        }
    };
    let completed = fixture.finish(&authorization)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert!(completed.receipt.verify_signature()?);
    assert_eq!(
        fixture
            .authority
            .admission_operation_store()
            .load_by_operation_id(&authorization.authorization.invocation.operation_id)?
            .ok_or("original caller")?
            .state(),
        AdmissionOperationState::Completed
    );
    Ok(())
}

struct Requirement(ThresholdApprovalRequirement);
impl chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver for Requirement {
    fn resolve_requirement(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String> {
        Ok(Some(self.0.clone()))
    }
}

#[cfg(unix)]
#[test]
fn caller_approval_wait_past_nonce_ttl_keeps_only_original_bound_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.strict_nonces();
    let approver = Keypair::generate();
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(Arc::new(Requirement(
            ThresholdApprovalRequirement::new(
                fixture.kernel.policy_hash().into(),
                1,
                vec![
                    chio_core::capability::threshold_approval::ThresholdApproverIdentity {
                        identifier: "original-reviewer".into(),
                        public_key: approver.public_key(),
                    },
                ],
                "original-directory".into(),
                120,
            )?,
        )));
    let mut grant_scope = scope();
    grant_scope.grants[0].max_invocations = Some(4);
    grant_scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".into(),
            },
            approval_budget_id: "bound-nonce-budget".into(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    let capability =
        fixture
            .kernel
            .issue_capability(&Keypair::generate().public_key(), grant_scope, 300)?;
    let mut request = request(&capability);
    request.request_id = "approval-after-nonce-ttl".into();
    let mut intent = GovernedTransactionIntent {
        id: "bound-nonce-intent".into(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "wait for original approval".into(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".into(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    chio_kernel::approval::ToolApprovalContext::bind(
        &mut intent,
        &capability,
        &request.arguments,
        &request.request_id,
        fixture.kernel.policy_hash(),
        "original-approval-context",
    )?;
    request.governed_intent = Some(intent);
    let pending = fixture.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(
        pending.verdict,
        Verdict::PendingApproval,
        "{:?}",
        pending.reason
    );
    let store = fixture.authority.admission_operation_store();
    let original = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            fixture.clock.epoch_ms,
        )?
        .ok_or("pending original")?
        .0;
    let issued = store
        .load_execution_nonce_issuance(
            original.binding().operation_id(),
            &fixture.authority.mutation_fence(),
            fixture.clock.epoch_ms,
        )?
        .ok_or("original nonce issuance")?;
    request.execution_nonce = Some(issued.signed_nonce().clone());
    let Some(chio_kernel::ToolCallOutput::Value(value)) = pending.output else {
        return Err("approval proposal".into());
    };
    let proposal: ThresholdApprovalProposal = serde_json::from_value(value)?;
    request.approval_tokens = vec![GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "original-approved-vote".into(),
            approver: approver.public_key(),
            subject: capability.subject.clone(),
            governed_intent_hash: proposal.body.governed_intent_hash.clone(),
            request_id: request.request_id.clone(),
            threshold_proposal_hash: Some(proposal.artifact_digest()?),
            issued_at: proposal.body.proposal_created_at,
            expires_at: proposal.body.proposal_deadline,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )?];
    request.threshold_approval_proposal = Some(proposal);
    fixture
        .clock
        .now_ms
        .store(fixture.clock.epoch_ms + 31_000, Ordering::SeqCst);
    let reserved = fixture.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let authorization = match fixture
        .kernel
        .start_caller_execution_with_credentials_blocking(
            request
                .execution_nonce
                .as_ref()
                .ok_or("presented original")?,
            &request.arguments,
            chio_kernel::CallerStartCredentials {
                approval_tokens: request.approval_tokens.clone(),
                threshold_approval_proposal: request.threshold_approval_proposal.clone(),
                ..Default::default()
            },
        )? {
        CallerStartResponse::Authorized(value) => *value,
        CallerStartResponse::Denied(response) => {
            return Err(format!("{:?}", response.reason).into())
        }
    };
    assert!(authorization.authorization.expires_at_unix_ms > fixture.clock.epoch_ms + 31_000);
    assert!(authorization.authorization.expires_at_unix_ms <= fixture.clock.epoch_ms + 120_000);
    assert_eq!(fixture.finish(&authorization)?.verdict, Verdict::Allow);
    Ok(())
}
