//! Proposal issuance through the real cumulative-budget admission path.

use super::*;
use crate::boot::{KernelSelfQuoteOutcome, KernelSelfQuoteVerifier};
use chio_core::{SigningAlgorithm, SigningBackend};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct QuoteVerifier {
    expected_key: chio_core::PublicKey,
    accept: bool,
    calls: AtomicU64,
}

impl KernelSelfQuoteVerifier for QuoteVerifier {
    fn verify_self_quote(
        &self,
        bytes: &[u8],
        expected_key: &chio_core::PublicKey,
    ) -> KernelSelfQuoteOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(bytes, b"threshold-test-self-quote");
        assert_eq!(expected_key, &self.expected_key);
        if self.accept {
            KernelSelfQuoteOutcome::accepted()
        } else {
            KernelSelfQuoteOutcome::rejected("test quote rejected")
        }
    }
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    store: StdArc<TestAdmissionOperationStore>,
    invocations: StdArc<AtomicU64>,
    approver: CoreKeypair,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let (mut kernel, mut request, store, invocations) =
            durable_admission_fixture("threshold-issuance-request");
        let approver = CoreKeypair::from_seed(&[71; 32]);
        kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
            ThresholdApprovalRequirement::new(
                kernel.config.policy_hash.clone(),
                1,
                vec![ThresholdApproverIdentity {
                    identifier: "threshold-reviewer".into(),
                    public_key: approver.public_key(),
                }],
                "threshold-issuance-directory-v1".into(),
                120,
            )?,
        )));
        let mut body = request.capability.body();
        body.scope.grants[0]
            .constraints
            .push(Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 100,
                    currency: "USD".into(),
                },
                approval_budget_id: "threshold-issuance-budget".into(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            });
        request.capability = CapabilityToken::sign(body, &kernel.config.keypair)?;
        request.governed_intent = Some(GovernedTransactionIntent {
            id: "threshold-issuance-intent".into(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: "authorize a bounded mutation".into(),
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
        Ok(Self {
            kernel,
            request,
            store,
            invocations,
            approver,
        })
    }

    fn configure(&mut self, floor: KernelCryptoFloor) -> TestResult<Box<dyn SigningBackend>> {
        let verifier = QuoteVerifier {
            expected_key: self.kernel.config.keypair.public_key(),
            accept: true,
            calls: AtomicU64::new(0),
        };
        let backend = self.kernel.with_hybrid_signing_backend(
            &HybridSigningConfig {
                crypto_floor: floor,
                pq_signing_seed: Some([83; 32]),
            },
            b"threshold-test-self-quote",
            &verifier,
        )?;
        assert_eq!(
            verifier.calls.load(Ordering::SeqCst),
            u64::from(floor.allows_hybrid())
        );
        Ok(backend)
    }

    fn pending(&mut self) -> TestResult<ThresholdApprovalProposal> {
        let response = self.kernel.evaluate_tool_call_blocking(&self.request)?;
        assert_eq!(
            response.verdict,
            Verdict::PendingApproval,
            "{:?}",
            response.reason
        );
        assert_eq!(self.invocations.load(Ordering::SeqCst), 0);
        let Some(ToolCallOutput::Value(value)) = response.output else {
            return Err("pending response omitted its proposal".into());
        };
        let proposal: ThresholdApprovalProposal = serde_json::from_value(value)?;
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::ApprovalRequired
        );
        assert_eq!(self.store.operation().threshold_proposal(), Some(&proposal));
        assert!(proposal.verify_signature()?);
        Ok(proposal)
    }
}

#[test]
fn classical_boot_preserves_canonical_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    let backend = fixture.configure(KernelCryptoFloor::AllowClassical)?;
    assert_eq!(backend.algorithm(), SigningAlgorithm::Ed25519);
    let proposal = fixture.pending()?;
    assert_eq!(proposal.body.policy_authority, backend.public_key());
    let legacy =
        ThresholdApprovalProposal::sign(proposal.body.clone(), &fixture.kernel.config.keypair)?;
    assert_eq!(
        canonical_json_bytes(&proposal)?,
        canonical_json_bytes(&legacy)?
    );
    Ok(())
}

#[test]
fn hybrid_signing_config_debug_omits_seed() {
    let config = HybridSigningConfig {
        crypto_floor: KernelCryptoFloor::PqRequired,
        pq_signing_seed: Some([83; 32]),
    };
    let diagnostic = format!("{config:?}");
    assert!(!diagnostic.contains("83"), "PQ seed leaked through Debug");
    assert!(diagnostic.contains("PqRequired"));
}

#[cfg(feature = "pq")]
#[test]
fn installed_hybrid_backend_signs_cumulative_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    let backend = fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let proposal = fixture.pending()?;
    assert_eq!(proposal.algorithm, Some(SigningAlgorithm::Hybrid));
    assert_eq!(proposal.body.policy_authority, backend.public_key());
    assert_eq!(proposal.signature.algorithm(), SigningAlgorithm::Hybrid);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn pq_required_proposal_uses_the_boot_verified_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    let backend = fixture.configure(KernelCryptoFloor::PqRequired)?;
    let mut capability = fixture.request.capability.body();
    capability.issuer = backend.public_key();
    fixture
        .kernel
        .config
        .ca_public_keys
        .push(backend.public_key());
    fixture.request.capability = CapabilityToken::sign_with_backend(capability, backend.as_ref())?;
    let proposal = fixture.pending()?;
    assert_eq!(proposal.algorithm, Some(SigningAlgorithm::Hybrid));
    assert_eq!(proposal.body.policy_authority, backend.public_key());
    Ok(())
}

impl Fixture {
    fn approve(&mut self, proposal: ThresholdApprovalProposal) -> TestResult {
        self.request.approval_tokens = vec![GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "threshold-issuance-vote".into(),
                approver: self.approver.public_key(),
                subject: self.request.capability.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: self.request.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest()?),
                issued_at: proposal.body.proposal_created_at,
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approver,
        )?];
        self.request.threshold_approval_proposal = Some(proposal);
        Ok(())
    }

    fn dispatch_and_retry_once(&self) -> TestResult {
        let original_operation = self.store.operation();
        for _ in 0..2 {
            let response = self.kernel.evaluate_tool_call_blocking(&self.request)?;
            assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
            assert_eq!(self.invocations.load(Ordering::SeqCst), 1);
            assert_eq!(
                self.store.operation().binding().operation_id(),
                original_operation.binding().operation_id()
            );
            assert_eq!(
                self.store.operation().budget_hold_id(),
                original_operation.budget_hold_id()
            );
        }
        let operation = self.store.operation();
        let usage = crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
            self.store.budget_store().as_ref(),
            operation.binding().operation_id().as_str(),
        )?
        .ok_or("cumulative usage missing")?;
        assert_eq!(
            usage.state,
            crate::budget_store::BudgetCumulativeApprovalState::Captured
        );
        Ok(())
    }

    #[cfg(feature = "pq")]
    fn reconstruct_kernel(&mut self) -> TestResult {
        let resolver = self
            .kernel
            .threshold_approval_requirement_resolver
            .as_ref()
            .cloned()
            .ok_or("threshold resolver missing")?;
        let mut config = make_config();
        config.keypair = self.kernel.config.keypair.clone();
        config.policy_hash = self.kernel.config.policy_hash.clone();
        config.ca_public_keys = self.kernel.config.ca_public_keys.clone();
        let mut kernel = make_kernel(config);
        let fence = self
            .store
            .fence
            .lock()
            .map_err(|_| "fixture fence lock poisoned")?
            .clone();
        kernel.set_durable_admission_store(self.store.clone(), self.store.clone(), fence)?;
        kernel.set_budget_store_handle(self.store.budget_store());
        kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
            id: "durable-server".into(),
            tools: vec!["mutate".into()],
            invocations: self.invocations.clone(),
            store: self.store.clone(),
        }));
        kernel.set_threshold_approval_requirement_resolver(resolver);
        self.kernel = kernel;
        Ok(())
    }

    fn assert_pending_unchanged(&self, proposal: &ThresholdApprovalProposal) -> TestResult {
        let operation = self.store.operation();
        assert_eq!(operation.state(), AdmissionOperationState::ApprovalRequired);
        assert_eq!(operation.threshold_proposal(), Some(proposal));
        assert_eq!(self.invocations.load(Ordering::SeqCst), 0);
        let usage = crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
            self.store.budget_store().as_ref(),
            operation.binding().operation_id().as_str(),
        )?
        .ok_or("pending cumulative usage missing")?;
        assert_eq!(
            usage.state,
            crate::budget_store::BudgetCumulativeApprovalState::PendingApproval
        );
        Ok(())
    }

    #[cfg(feature = "pq")]
    fn assert_no_cumulative_reservation(&self) -> TestResult {
        let operation = self.store.operation();
        assert!(operation.threshold_proposal().is_none());
        assert!(
            crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
                self.store.budget_store().as_ref(),
                operation.binding().operation_id().as_str(),
            )?
            .is_none()
        );
        assert_eq!(self.invocations.load(Ordering::SeqCst), 0);
        Ok(())
    }
}

#[test]
fn classical_installed_proposal_dispatches_and_replays_once() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowClassical)?;
    let proposal = fixture.pending()?;
    fixture.approve(proposal)?;
    fixture.dispatch_and_retry_once()
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_proposal_dispatches_and_replays_once() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let proposal = fixture.pending()?;
    assert_eq!(proposal.algorithm, Some(SigningAlgorithm::Hybrid));
    fixture.approve(proposal)?;
    fixture.dispatch_and_retry_once()
}

#[cfg(feature = "pq")]
#[test]
fn returned_backend_drop_keeps_installed_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    let backend = fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let public_key = backend.public_key();
    drop(backend);
    assert_eq!(fixture.pending()?.body.policy_authority, public_key);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn failed_boot_reconfiguration_preserves_previous_authority_and_floor() -> TestResult {
    let mut fixture = Fixture::new()?;
    let backend = fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let verifier = QuoteVerifier {
        expected_key: fixture.kernel.config.keypair.public_key(),
        accept: false,
        calls: AtomicU64::new(0),
    };
    assert!(matches!(
        fixture.kernel.with_hybrid_signing_backend(
            &HybridSigningConfig {
                crypto_floor: KernelCryptoFloor::PqRequired,
                pq_signing_seed: Some([84; 32])
            },
            b"threshold-test-self-quote",
            &verifier,
        ),
        Err(crate::boot::KernelBootError::SelfQuoteRejected { .. })
    ));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.kernel.capability_crypto_floor,
        KernelCryptoFloor::AllowHybrid
    );
    assert_eq!(
        fixture.pending()?.body.policy_authority,
        backend.public_key()
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn missing_seed_preserves_previous_authority_and_floor() -> TestResult {
    let mut fixture = Fixture::new()?;
    let backend = fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let verifier = QuoteVerifier {
        expected_key: fixture.kernel.config.keypair.public_key(),
        accept: true,
        calls: AtomicU64::new(0),
    };
    assert!(matches!(
        fixture.kernel.with_hybrid_signing_backend(
            &HybridSigningConfig {
                crypto_floor: KernelCryptoFloor::PqRequired,
                pq_signing_seed: None
            },
            b"threshold-test-self-quote",
            &verifier,
        ),
        Err(crate::boot::KernelBootError::SigningBackend(_))
    ));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.kernel.capability_crypto_floor,
        KernelCryptoFloor::AllowHybrid
    );
    assert_eq!(
        fixture.pending()?.body.policy_authority,
        backend.public_key()
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn incompatible_installed_signer_denies_without_publishing_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::AllowClassical);
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("signing backend")));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert!(fixture.store.operation().threshold_proposal().is_none());
    fixture.assert_no_cumulative_reservation()
}

#[cfg(feature = "pq")]
#[test]
fn pending_retry_rechecks_crypto_floor_without_reissuing_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let proposal = fixture.pending()?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::AllowClassical);
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.assert_pending_unchanged(&proposal)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::AllowHybrid);
    assert_eq!(fixture.pending()?, proposal);
    fixture.approve(proposal)?;
    fixture.dispatch_and_retry_once()
}

#[test]
fn pending_retry_rechecks_current_directory() -> TestResult {
    let mut fixture = Fixture::new()?;
    let proposal = fixture.pending()?;
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
            ThresholdApprovalRequirement::new(
                fixture.kernel.config.policy_hash.clone(),
                1,
                vec![ThresholdApproverIdentity {
                    identifier: "threshold-reviewer".into(),
                    public_key: CoreKeypair::from_seed(&[72; 32]).public_key(),
                }],
                "threshold-issuance-directory-v2".into(),
                120,
            )?,
        )));
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.assert_pending_unchanged(&proposal)
}

#[cfg(feature = "pq")]
#[test]
fn reconstructed_kernel_preserves_pending_hybrid_artifact_and_dispatch_identity() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let proposal = fixture.pending()?;
    let operation_id = fixture.store.operation().binding().operation_id().clone();
    fixture.reconstruct_kernel()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let retried = fixture.pending()?;
    assert_eq!(
        canonical_json_bytes(&retried)?,
        canonical_json_bytes(&proposal)?
    );
    assert_eq!(
        fixture.store.operation().binding().operation_id(),
        &operation_id
    );
    fixture.approve(retried)?;
    fixture.dispatch_and_retry_once()
}

#[cfg(feature = "pq")]
#[test]
fn reconstructed_kernel_without_signer_refuses_retained_hybrid_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let proposal = fixture.pending()?;
    fixture.reconstruct_kernel()?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.assert_pending_unchanged(&proposal)
}

#[cfg(feature = "pq")]
#[test]
fn rotated_authority_does_not_resign_retained_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.configure(KernelCryptoFloor::AllowHybrid)?;
    let proposal = fixture.pending()?;
    let verifier = QuoteVerifier {
        expected_key: fixture.kernel.config.keypair.public_key(),
        accept: true,
        calls: AtomicU64::new(0),
    };
    fixture.kernel.with_hybrid_signing_backend(
        &HybridSigningConfig {
            crypto_floor: KernelCryptoFloor::AllowHybrid,
            pq_signing_seed: Some([84; 32]),
        },
        b"threshold-test-self-quote",
        &verifier,
    )?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.assert_pending_unchanged(&proposal)
}

#[cfg(feature = "pq")]
#[test]
fn pq_capability_without_boot_signer_cannot_publish_classical_proposal() -> TestResult {
    let mut fixture = Fixture::new()?;
    let issuer = chio_core::HybridBackend::new(
        Box::new(chio_core::Ed25519Backend::new(CoreKeypair::from_seed(
            &[92; 32],
        ))),
        chio_core::MlDsa65Backend::from_seed(&[93; 32]),
    )?;
    let mut capability = fixture.request.capability.body();
    capability.issuer = issuer.public_key();
    fixture
        .kernel
        .config
        .ca_public_keys
        .push(issuer.public_key());
    fixture.request.capability = CapabilityToken::sign_with_backend(capability, &issuer)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    fixture.kernel.verify_capability_full_pre_admit(
        &fixture.request.capability,
        None,
        current_unix_timestamp(),
    )?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("signing backend")));
    assert!(fixture.store.operation().threshold_proposal().is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.assert_no_cumulative_reservation()
}
