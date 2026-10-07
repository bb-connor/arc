// Cumulative threshold approval resumes the original native caller custody,
// including after the issued nonce lifetime, through actual native capture,
// signed external delivery and reopened physical authority.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, ThresholdApprovalProposal,
};
use chio_core::capability::scope::{Constraint, MonetaryAmount};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_kernel::admission_operation::{AdmissionOperationId, NativeSecurityInputJoinRecordV1};
use chio_kernel::caller_delivery::{
    CallerDeliveryEvidenceV1, SignedCallerDeliveryReportV1, SignedCallerDispatchAuthorizationV1,
};
use chio_kernel::execution_nonce::SignedExecutionNonce;

const APPROVAL_WINDOW_SECS: u64 = 120;
/// Outlives the approval window: only approval and custody bound delivery.
const LONG_NONCE_TTL_SECS: u64 = 300;
/// Expires while the original approval window is still open.
const SHORT_NONCE_TTL_SECS: u64 = 30;

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

/// One original native caller operation parked for cumulative approval, with
/// its nonce issued and proposal created by the real authority before the TTL.
struct ParkedApproval {
    fixture: Fixture,
    legacy: Arc<AtomicUsize>,
    approver: Keypair,
    requirement: ThresholdApprovalRequirement,
    executor: CallerExecutorIdentityV1,
    executor_key: Keypair,
    ledger: SqliteCallerExecutionLedger,
    operation_id: AdmissionOperationId,
    issued: SignedExecutionNonce,
    proposal: ThresholdApprovalProposal,
    input_join: NativeSecurityInputJoinRecordV1,
}

struct Executed {
    nonce: SignedExecutionNonce,
    authorization: SignedCallerDispatchAuthorizationV1,
    report: SignedCallerDeliveryReportV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonceWindow {
    Live,
    Expired,
}

fn millis(seconds: u64) -> TestResult<u64> {
    Ok(seconds.checked_mul(1_000).ok_or("deadline overflow")?)
}

fn nonce_expiry_ms(nonce: &SignedExecutionNonce) -> TestResult<u64> {
    millis(u64::try_from(nonce.expires_at())?)
}

impl ParkedApproval {
    fn new(nonce_ttl_secs: u64) -> TestResult<Self> {
        let approver = Keypair::generate();
        let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
        let mut scope = fixture.request.capability.body().scope;
        scope.grants[0].max_invocations = Some(4);
        scope.grants[0]
            .constraints
            .push(Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 100,
                    currency: "USD".into(),
                },
                approval_budget_id: "native-approval-wait-budget".into(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            });
        fixture.request.capability =
            fixture
                .kernel
                .issue_capability(&fixture.agent.public_key(), scope, 600)?;
        let context = fixture.context.as_v1();
        fixture.context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            context.tenant_id().clone(),
            context.session_id().clone(),
            context.principal_id().clone(),
            context.isolation_epoch_id().clone(),
            LineageId::new(&fixture.request.capability.id)?,
            1,
        ));
        fixture.request.governed_intent = Some(GovernedTransactionIntent {
            id: "native-approval-wait-intent".into(),
            server_id: fixture.request.server_id.clone(),
            tool_name: fixture.request.tool_name.clone(),
            purpose: "approve the original native caller invocation".into(),
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
        });
        fixture.request.governed_intent =
            Some(fixture.kernel.bind_tool_approval_intent(&fixture.request)?);
        let requirement = ThresholdApprovalRequirement::new(
            fixture.kernel.policy_hash().into(),
            1,
            vec![ThresholdApproverIdentity {
                identifier: "native-original-reviewer".into(),
                public_key: approver.public_key(),
            }],
            "native-original-directory".into(),
            APPROVAL_WINDOW_SECS,
        )?;
        fixture
            .kernel
            .set_threshold_approval_requirement_resolver(Arc::new(Requirement(
                requirement.clone(),
            )));
        super::super::nonce::execution::configure(&mut fixture, false)?;
        let legacy = super::super::nonce::execution::install_nonce(&mut fixture, nonce_ttl_secs);
        let executor_key = Keypair::generate();
        let executor = CallerExecutorIdentityV1 {
            executor_id: AdmissionIdentifier::try_new("executor_id", "native-approval-executor")?,
            public_key: executor_key.public_key(),
            key_epoch: 43,
        };
        fixture.kernel.set_caller_executor(executor.clone())?;
        let ledger = SqliteCallerExecutionLedger::provision_with_clock(
            &fixture._directory.path().join("executor.db"),
            executor.clone(),
            4,
            fixture.clock.clone(),
        )?;
        let operation_id = super::super::nonce::execution::issue(&mut fixture)?;
        let issued = fixture
            .request
            .execution_nonce
            .clone()
            .ok_or("issued nonce")?;
        let parked = fixture
            .kernel
            .reserve_caller_execution_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(
            parked.verdict,
            Verdict::PendingApproval,
            "{:?}",
            parked.reason
        );
        assert!(parked.receipt.verify_signature()?);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let Some(chio_kernel::ToolCallOutput::Value(value)) = parked.output else {
            return Err("pending approval proposal".into());
        };
        let proposal: ThresholdApprovalProposal = serde_json::from_value(value)?;
        // The proposal binds the nonce inside its lifetime. Neither deadline
        // depends on wall time or host load.
        assert!(millis(proposal.body.proposal_created_at)? < nonce_expiry_ms(&issued)?);
        assert_eq!(proposal.body.proposal_id, operation_id.as_str());
        let retained = fixture
            .authority
            .admission_operation_store()
            .load_by_operation_id(&operation_id)?
            .ok_or("parked operation")?;
        assert_eq!(retained.state(), AdmissionOperationState::ApprovalRequired);
        assert!(retained.threshold_proposal() == Some(&proposal));
        let input_join = fixture
            .authority
            .admission_operation_store()
            .load_native_security_input_join(
                &operation_id,
                &fixture.authority.mutation_fence(),
                fixture.clock.snapshot(),
            )?
            .ok_or("parked input operation")?
            .1
            .ok_or("parked original input join")?;
        Ok(Self {
            fixture,
            legacy,
            approver,
            requirement,
            executor,
            executor_key,
            ledger,
            operation_id,
            issued,
            proposal,
            input_join,
        })
    }

    fn current_input_join(&self) -> TestResult<Option<NativeSecurityInputJoinRecordV1>> {
        Ok(self
            .fixture
            .authority
            .admission_operation_store()
            .load_native_security_input_join(
                &self.operation_id,
                &self.fixture.authority.mutation_fence(),
                self.fixture.clock.snapshot(),
            )?
            .ok_or("current input operation")?
            .1)
    }

    fn approval_deadline_ms(&self) -> TestResult<u64> {
        millis(self.proposal.body.proposal_deadline)
    }

    fn approve(&mut self) -> TestResult {
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "native-original-approved-vote".into(),
                approver: self.approver.public_key(),
                subject: self.fixture.request.capability.subject.clone(),
                governed_intent_hash: self.proposal.body.governed_intent_hash.clone(),
                request_id: self.fixture.request.request_id.clone(),
                threshold_proposal_hash: Some(self.proposal.artifact_digest()?),
                issued_at: self.proposal.body.proposal_created_at,
                expires_at: self.proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approver,
        )?;
        self.fixture.request.approval_tokens = vec![token];
        self.fixture.request.threshold_approval_proposal = Some(self.proposal.clone());
        Ok(())
    }

    /// Present the original approval at `resolved_at` with refreshed native
    /// host context. Only the original parked operation may resume.
    fn reserve_approved(&mut self, resolved_at: u64) -> TestResult<chio_kernel::ToolCallResponse> {
        Ok(self.try_reserve_approved(resolved_at, |_| Ok(()))??)
    }

    /// As `reserve_approved`, after `alter` changes the presentation or host.
    fn try_reserve_approved(
        &mut self,
        resolved_at: u64,
        alter: impl FnOnce(&mut Self) -> TestResult,
    ) -> TestResult<Result<chio_kernel::ToolCallResponse, KernelError>> {
        self.approve()?;
        self.fixture.clock.advance_to(resolved_at)?;
        self.fixture.context = self
            .fixture
            .kernel
            .refresh_native_security_context(&self.fixture.context)?;
        alter(self)?;
        Ok(self
            .fixture
            .kernel
            .reserve_caller_execution_blocking_with_security_context(
                &self.fixture.request,
                &self.fixture.context,
            ))
    }

    /// Reserve and start through the actual native capture, then run the
    /// external effect once through the pinned executor's durable ledger.
    fn execute_at(&mut self, resolved_at: u64, effects: &AtomicUsize) -> TestResult<Executed> {
        let reserved = self.reserve_approved(resolved_at)?;
        assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
        assert!(
            self.current_input_join()?.as_ref() == Some(&self.input_join),
            "approved resume must reuse its original input join"
        );
        assert!(reserved.output.is_none());
        let nonce = *reserved.execution_nonce.ok_or("reserved nonce")?;
        assert!(nonce == self.issued);
        let authorization = match self
            .fixture
            .kernel
            .start_caller_execution_blocking_with_security_context(
                &nonce,
                &self.fixture.request.arguments,
                start_credentials(&self.fixture),
                &self.fixture.context,
            )? {
            CallerStartResponse::Authorized(authorization) => *authorization,
            CallerStartResponse::Denied(response) => {
                return Err(format!(
                    "approval-bound native caller start denied: {:?}",
                    response.reason
                )
                .into())
            }
        };
        assert_eq!(
            authorization.authorization.invocation.operation_id,
            self.operation_id
        );
        let report = self.ledger.execute_once(
            &authorization,
            &self.fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &self.executor_key,
            || {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"native_external_effect": "approval-bound"}),
                    realized_cost: None,
                })
            },
        )?;
        Ok(Executed {
            nonce,
            authorization,
            report,
        })
    }

    /// Close every original owner and reopen the same SQLite authority with
    /// the original pins, selecting the original at the owned authority time.
    fn reopen(mut self) -> TestResult<Self> {
        let witness = super::super::process_recovery::caller_restart_witness(&self.fixture, None);
        let previous_fence = self.fixture.authority.mutation_fence();
        let Fixture {
            kernel,
            clock,
            authority,
            binding,
            request,
            context,
            invocations: _,
            hook,
            agent,
            signer,
            _directory,
        } = self.fixture;
        drop(kernel);
        drop(authority);
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            _directory.path().join("admission.db"),
            _directory.path().join("locks"),
            clock.clone(),
        )?;
        assert_ne!(authority.mutation_fence(), previous_fence);
        let (mut kernel, invocations) =
            open_kernel(_directory.path(), &authority, &signer, clock.clone())?;
        let (_, original) = authority
            .admission_operation_store()
            .load_retained_tool_request(
                &self.operation_id,
                &authority.mutation_fence(),
                clock.snapshot(),
            )?
            .ok_or("original native caller request")?;
        super::super::process_recovery::configure_caller_restart(&mut kernel, &original, &witness)?;
        kernel.set_caller_executor(self.executor.clone())?;
        kernel.set_threshold_approval_requirement_resolver(Arc::new(Requirement(
            self.requirement.clone(),
        )));
        kernel.reconcile_durable_admission_startup()?;
        self.fixture = Fixture {
            kernel,
            clock,
            authority,
            binding,
            request,
            context,
            invocations,
            hook,
            agent,
            signer,
            _directory,
        };
        Ok(self)
    }
}

/// Approve the parked original at `resolved_at`, execute it once, reopen the
/// authority and release only the authenticated original native output.
fn deliver_approved(window: NonceWindow) -> TestResult {
    let nonce_ttl_secs = match window {
        NonceWindow::Live => LONG_NONCE_TTL_SECS,
        NonceWindow::Expired => SHORT_NONCE_TTL_SECS,
    };
    let mut parked = ParkedApproval::new(nonce_ttl_secs)?;
    let nonce_expiry = nonce_expiry_ms(&parked.issued)?;
    let approval_deadline = parked.approval_deadline_ms()?;
    let capability_deadline = millis(parked.fixture.request.capability.expires_at)?;
    let resolved_at = match window {
        NonceWindow::Live => parked.fixture.clock.snapshot() + 1_000,
        NonceWindow::Expired => nonce_expiry + 1_000,
    };
    assert!(resolved_at < approval_deadline);
    assert_eq!(window == NonceWindow::Live, resolved_at < nonce_expiry);
    let effects = AtomicUsize::new(0);
    let executed = parked.execute_at(resolved_at, &effects)?;
    let authorization = &executed.authorization;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(parked.fixture.invocations.load(Ordering::SeqCst), 0);
    let expires_at = authorization.authorization.expires_at_unix_ms;
    assert!(expires_at <= approval_deadline.min(capability_deadline));
    assert_eq!(window == NonceWindow::Expired, nonce_expiry < expires_at);
    let captured = parked
        .fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&parked.operation_id)?
        .ok_or("captured operation")?;
    assert_eq!(captured.state(), AdmissionOperationState::DispatchCommitted);
    assert!(captured.threshold_proposal() == Some(&parked.proposal));
    assert!(captured.native_dispatch_ledger_digest().is_some());
    assert_captured_quota(&parked.fixture)?;

    let parked = parked.reopen()?;
    let observed_at = parked.fixture.clock.snapshot();
    let store = parked.fixture.authority.admission_operation_store();
    let fence = parked.fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_retained_tool_request(&parked.operation_id, &fence, observed_at)?
        .ok_or("reopened original")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::AwaitingCallerReport
    );
    let nonce = store
        .load_execution_nonce_reservation(&parked.operation_id, &fence, observed_at)?
        .ok_or("reopened nonce")?;
    let frame = store
        .load_caller_dispatch_context(&parked.operation_id, &fence, observed_at)?
        .ok_or("reopened caller frame")?;
    drop(store);
    assert!(nonce.signed_nonce() == &executed.nonce);
    let custody = frame
        .native_release_custody(&operation, &original)?
        .ok_or("reopened native custody")?;
    let custody_until = custody.valid_until_unix_ms();
    assert_eq!(expires_at, capability_deadline.min(custody_until));
    assert!(custody_until <= approval_deadline);
    let evidence = CallerDeliveryEvidenceV1 {
        authorization: authorization.clone(),
        report: executed.report.clone(),
    };
    let retained = evidence.validate_native_original(&operation, &original, &nonce, &frame);
    let reconciled = parked
        .fixture
        .kernel
        .reconcile_authenticated_caller_execution_blocking(authorization, &executed.report);
    let completed = match (retained, reconciled) {
        (Ok(_), Ok(response)) if response.verdict == Verdict::Allow => response,
        (retained, reconciled) => {
            return Err(format!(
                "approval-bound native delivery rejected after its effect ran \
                 (window={window:?}, effects={}, authorization_expires_at_unix_ms={expires_at}, \
                 nonce_expires_at_unix_ms={nonce_expiry}, custody_valid_until_unix_ms={custody_until}, \
                 approval_deadline_unix_ms={approval_deadline}, capability_expires_at_unix_ms={capability_deadline}): \
                 retained_validation={:?} reconcile={:?}",
                effects.load(Ordering::SeqCst),
                retained.err(),
                reconciled.map(|response| (response.verdict, response.reason)),
            )
            .into())
        }
    };
    assert!(
        matches!(&completed.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &executed.report.report.output)
    );
    assert!(completed.receipt.verify_signature()?);
    assert!(completed.execution_nonce.is_none());
    assert_retained_horizon_is_exact(
        &parked, window, &evidence, &operation, &original, &nonce, &frame,
    )?;
    assert_eq!(
        parked
            .fixture
            .authority
            .admission_operation_store()
            .load_by_operation_id(&parked.operation_id)?
            .ok_or("terminal operation")?
            .state(),
        AdmissionOperationState::Completed
    );
    assert!(parked
        .fixture
        .authority
        .tool_outcome_store()
        .lookup_security_release(&parked.operation_id)?
        .is_some());

    // Reopen the same SQLite again and independently read the exact original
    // output, signed evidence and custody. History grants no second dispatch.
    let parked = parked.reopen()?;
    let observed_at = parked.fixture.clock.snapshot();
    assert_native_original_evidence(
        &parked.fixture,
        &parked.operation_id,
        &parked.executor_key,
        observed_at,
    )?;
    let raw = parked
        .fixture
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(&parked.operation_id)?
        .ok_or("reopened raw return")?
        .to_persisted();
    assert!(matches!(
        &raw.output,
        chio_kernel::tool_outcome::InvocationOutputV1::Value { value } if value == &executed.report.report.output
    ));
    let retained_evidence = raw
        .caller_delivery_evidence
        .ok_or("reopened private signed evidence")?;
    assert!(retained_evidence.authorization == *authorization);
    assert!(retained_evidence.report == executed.report);
    let store = parked.fixture.authority.admission_operation_store();
    let fence = parked.fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_retained_tool_request(&parked.operation_id, &fence, observed_at)?
        .ok_or("completed original")?;
    assert!(operation.threshold_proposal() == Some(&parked.proposal));
    assert_eq!(
        operation
            .execution_nonce_id()
            .map(AdmissionIdentifier::as_str),
        Some(parked.issued.nonce_id())
    );
    let frame = store
        .load_caller_dispatch_context(&parked.operation_id, &fence, observed_at)?
        .ok_or("completed caller frame")?;
    assert_eq!(
        frame
            .native_release_custody(&operation, &original)?
            .ok_or("completed native custody")?
            .valid_until_unix_ms(),
        custody_until
    );
    drop(store);
    let replay = parked
        .fixture
        .kernel
        .reconcile_authenticated_caller_execution_blocking(authorization, &executed.report)?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&completed.receipt)?,
        chio_core::canonical::canonical_json_bytes(&replay.receipt)?
    );
    let restarted = match parked
        .fixture
        .kernel
        .start_caller_execution_blocking_with_security_context(
            &executed.nonce,
            &parked.fixture.request.arguments,
            start_credentials(&parked.fixture),
            &parked.fixture.context,
        )? {
        CallerStartResponse::Authorized(authorization) => *authorization,
        CallerStartResponse::Denied(response) => {
            return Err(format!("historical start lost: {:?}", response.reason).into())
        }
    };
    assert_eq!(&restarted, authorization);
    let redelivered = parked.ledger.execute_once(
        &restarted,
        &parked.fixture.signer.public_key(),
        &restarted.authorization.invocation,
        &parked.executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Err(KernelError::Internal("history redispatched".into()))
        },
    )?;
    assert!(redelivered == executed.report);
    assert_captured_quota(&parked.fixture)?;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(parked.fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(parked.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_caller_approval_within_nonce_ttl_resumes_original_native_custody() -> TestResult {
    deliver_approved(NonceWindow::Live)
}

#[test]
fn native_caller_approval_wait_past_nonce_ttl_releases_output_and_reopens() -> TestResult {
    deliver_approved(NonceWindow::Expired)
}

/// The historical verifier accepts only the exact signed horizon. Without the
/// operation's authenticated threshold proposal the original nonce expiry
/// still caps it, so a nonce that expired before approval no longer verifies.
fn assert_retained_horizon_is_exact(
    parked: &ParkedApproval,
    window: NonceWindow,
    evidence: &CallerDeliveryEvidenceV1,
    operation: &chio_kernel::admission_operation::AdmissionOperationV1,
    original: &chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
    nonce: &chio_kernel::admission_operation::AdmissionExecutionNonceReservationV1,
    frame: &chio_kernel::admission_operation::AdmissionCallerDispatchContextV1,
) -> TestResult {
    for shifted in [
        evidence.authorization.authorization.expires_at_unix_ms - 1,
        evidence.authorization.authorization.expires_at_unix_ms + 1,
    ] {
        let mut body = evidence.authorization.authorization.clone();
        body.expires_at_unix_ms = shifted;
        let authorization =
            SignedCallerDispatchAuthorizationV1::sign(body, &parked.fixture.signer)?;
        let mut report = evidence.report.report.clone();
        report.authorization_digest = authorization.verify_historical(
            &parked.fixture.signer.public_key(),
            &authorization.authorization.executor,
            &authorization.authorization.invocation,
        )?;
        let resigned = CallerDeliveryEvidenceV1 {
            authorization,
            report: SignedCallerDeliveryReportV1::sign(report, &parked.executor_key)?,
        };
        assert!(
            resigned
                .validate_native_original(operation, original, nonce, frame)
                .is_err(),
            "authorization interval ending at {shifted} must not verify"
        );
    }
    let mut persisted = serde_json::to_value(operation.to_persisted())?;
    persisted["attachments"]
        .as_array_mut()
        .ok_or("operation attachments")?
        .retain(|attachment| {
            attachment.get("ThresholdProposal").is_none()
                && attachment.get("ThresholdProposalHash").is_none()
        });
    let unbound = chio_kernel::admission_operation::AdmissionOperationV1::from_persisted(
        serde_json::from_value(persisted)?,
    )?;
    assert!(unbound.threshold_proposal().is_none());
    assert_eq!(
        evidence
            .validate_native_original(&unbound, original, nonce, frame)
            .is_ok(),
        window == NonceWindow::Live
    );
    Ok(())
}

/// A hook that returns success without presenting the original input join.
struct SkippedJoin(NativeSecurityAuthorityBindingV1);

impl SecurityPreDispatchHook for SkippedJoin {
    fn name(&self) -> &str {
        "native-approval-skipped-join"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.0.clone()))
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        _: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::GuardDenied(
            "legacy dispatch is forbidden".into(),
        ))
    }
}

#[derive(Clone, Copy, Debug)]
enum Substitution {
    Proposal,
    MissingProposal,
    Nonce,
    Operation,
    MissingApproval,
    ExpiredApproval,
    Executor,
    Grant,
    Context,
    RawJoin,
    SkippedJoin,
}

#[test]
fn native_caller_approval_resume_refuses_substituted_or_missing_original_custody() -> TestResult {
    for substitution in [
        Substitution::Proposal,
        Substitution::MissingProposal,
        Substitution::Nonce,
        Substitution::Operation,
        Substitution::MissingApproval,
        Substitution::ExpiredApproval,
        Substitution::Executor,
        Substitution::Grant,
        Substitution::Context,
        Substitution::RawJoin,
        Substitution::SkippedJoin,
    ] {
        let mut parked = ParkedApproval::new(LONG_NONCE_TTL_SECS)?;
        let resolved_at = match substitution {
            Substitution::ExpiredApproval => parked.approval_deadline_ms()?,
            _ => parked.fixture.clock.snapshot() + 1_000,
        };
        let result = parked.try_reserve_approved(resolved_at, |parked| {
            let request = &mut parked.fixture.request;
            match substitution {
                Substitution::Proposal => {
                    request
                        .threshold_approval_proposal
                        .as_mut()
                        .ok_or("presented proposal")?
                        .body
                        .proposal_deadline += 1;
                }
                Substitution::MissingProposal => request.threshold_approval_proposal = None,
                Substitution::Nonce => request
                    .execution_nonce
                    .as_mut()
                    .ok_or("presented nonce")?
                    .nonce
                    .nonce_id
                    .push_str("-substituted"),
                Substitution::Operation => request.request_id.push_str("-substituted"),
                Substitution::MissingApproval => request.approval_tokens.clear(),
                Substitution::ExpiredApproval => {}
                Substitution::Executor => {
                    let foreign = Keypair::generate();
                    parked
                        .fixture
                        .kernel
                        .set_caller_executor(CallerExecutorIdentityV1 {
                            executor_id: AdmissionIdentifier::try_new(
                                "executor_id",
                                "native-approval-executor",
                            )?,
                            public_key: foreign.public_key(),
                            key_epoch: 43,
                        })?;
                }
                Substitution::Grant => {
                    let scope = request.capability.body().scope;
                    request.capability = parked.fixture.kernel.issue_capability(
                        &parked.fixture.agent.public_key(),
                        scope,
                        600,
                    )?;
                }
                Substitution::Context => {
                    let context = parked.fixture.context.as_v1();
                    parked.fixture.context =
                        SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
                            context.tenant_id().clone(),
                            SessionId::new("foreign-native-session")?,
                            context.principal_id().clone(),
                            context.isolation_epoch_id().clone(),
                            context.lineage_root_id().clone(),
                            1,
                        ));
                }
                Substitution::RawJoin => {
                    let hook = parked.fixture.hook.clone();
                    parked.fixture.kernel.set_security_pre_dispatch_hook(hook);
                }
                Substitution::SkippedJoin => {
                    let hook = Arc::new(SkippedJoin(parked.fixture.binding.clone()));
                    parked.fixture.kernel.set_security_pre_dispatch_hook(hook);
                }
            }
            Ok(())
        })?;
        if let Ok(response) = &result {
            assert_ne!(
                response.verdict,
                Verdict::Allow,
                "{substitution:?}: {:?}",
                response.reason
            );
            assert!(response
                .output
                .as_ref()
                .is_none_or(|_| response.verdict == Verdict::PendingApproval));
        }
        let operation = parked
            .fixture
            .authority
            .admission_operation_store()
            .load_by_operation_id(&parked.operation_id)?
            .ok_or("original parked operation")?;
        assert!(operation.dispatch_commit().is_none(), "{substitution:?}");
        assert!(
            matches!(
                operation.state(),
                AdmissionOperationState::ApprovalRequired
                    | AdmissionOperationState::CompensatedBeforeDispatch
            ),
            "{substitution:?}: {:?}",
            operation.state()
        );
        assert!(
            parked
                .current_input_join()?
                .is_none_or(|join| join == parked.input_join),
            "{substitution:?} replaced the original input join"
        );
        assert_eq!(parked.fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(parked.legacy.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
