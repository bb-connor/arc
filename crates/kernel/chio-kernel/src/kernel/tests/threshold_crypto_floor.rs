//! The policy floor applies to every threshold artifact at both verifier entrypoints.

use super::*;
use crate::threshold_approval::{
    verify_threshold_approval_set, ThresholdApprovalVerificationInput,
};
use chio_core::{Ed25519Backend, SigningAlgorithm, SigningBackend};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    requirement: ThresholdApprovalRequirement,
    intent_hash: String,
    now: u64,
    approver: Box<dyn SigningBackend>,
}

fn backend(seed: u8, hybrid: bool) -> TestResult<Box<dyn SigningBackend>> {
    let classical = Ed25519Backend::new(Keypair::from_seed(&[seed; 32]));
    if hybrid {
        #[cfg(feature = "pq")]
        return Ok(Box::new(chio_core::HybridBackend::new(
            Box::new(classical),
            chio_core::MlDsa65Backend::from_seed(&[seed + 1; 32]),
        )?));
        #[cfg(not(feature = "pq"))]
        return Err("hybrid fixture requires the pq feature".into());
    }
    Ok(Box::new(classical))
}

impl Fixture {
    fn new(hybrid_proposal: bool, hybrid_vote: bool) -> TestResult<Self> {
        let authority = backend(10, hybrid_proposal)?;
        let approver = backend(20, hybrid_vote)?;
        let issuer = backend(30, hybrid_proposal || hybrid_vote)?;
        let subject = Keypair::from_seed(&[40; 32]);
        let now = current_unix_timestamp();
        let policy_hash = sha256_hex(b"threshold-crypto-floor-policy");
        let mut config = make_config();
        config.policy_hash = policy_hash.clone();
        config
            .ca_public_keys
            .extend([authority.public_key(), issuer.public_key()]);
        let mut kernel = make_kernel(config);
        let requirement = ThresholdApprovalRequirement::new(
            policy_hash.clone(),
            1,
            vec![ThresholdApproverIdentity {
                identifier: "reviewer".into(),
                public_key: approver.public_key(),
            }],
            "directory-v1".into(),
            90,
        )?;
        kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
            requirement.clone(),
        )));
        let capability = CapabilityToken::sign_with_backend(
            CapabilityTokenBody {
                id: "threshold-floor-capability".into(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: make_scope(vec![make_grant("threshold-server", "transfer")]),
                issued_at: now - 1,
                expires_at: now + 120,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            issuer.as_ref(),
        )?;
        let intent = GovernedTransactionIntent {
            id: "threshold-floor-intent".into(),
            server_id: "threshold-server".into(),
            tool_name: "transfer".into(),
            purpose: "test threshold signature policy".into(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        };
        let intent_hash = intent.binding_hash()?;
        let proposal = ThresholdApprovalProposal::sign_with_backend(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
                proposal_id: "threshold-floor-proposal".into(),
                request_id: "threshold-floor-request".into(),
                governed_intent_hash: intent_hash.clone(),
                subject: subject.public_key(),
                authorizing_capability_digest: sha256_hex(&canonical_json_bytes(&capability)?),
                policy_hash,
                threshold: 1,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: now,
                proposal_deadline: now + 90,
                policy_authority: authority.public_key(),
            },
            authority.as_ref(),
        )?;
        let token = GovernedApprovalToken::sign_with_backend(
            GovernedApprovalTokenBody {
                id: "threshold-floor-vote".into(),
                approver: approver.public_key(),
                subject: subject.public_key(),
                governed_intent_hash: intent_hash.clone(),
                request_id: "threshold-floor-request".into(),
                threshold_proposal_hash: Some(proposal.artifact_digest()?),
                issued_at: now,
                expires_at: now + 90,
                decision: GovernedApprovalDecision::Approved,
            },
            approver.as_ref(),
        )?;
        let mut request = make_request(
            "threshold-floor-request",
            &capability,
            "transfer",
            "threshold-server",
        );
        request.governed_intent = Some(intent);
        request.threshold_approval_proposal = Some(proposal);
        request.approval_tokens = vec![token];
        Ok(Self {
            kernel,
            request,
            requirement,
            intent_hash,
            now,
            approver,
        })
    }

    fn rebind_vote_to_proposal(&mut self) -> TestResult {
        let proposal = self
            .request
            .threshold_approval_proposal
            .as_ref()
            .ok_or("fixture omitted its proposal")?;
        for token in &mut self.request.approval_tokens {
            let mut body = token.body();
            body.threshold_proposal_hash = Some(proposal.artifact_digest()?);
            *token = GovernedApprovalToken::sign_with_backend(body, self.approver.as_ref())?;
        }
        Ok(())
    }

    fn verify_tool(&self) -> Result<super::super::VerifiedThresholdApprovalSet, KernelError> {
        self.kernel.validate_threshold_approval_set(
            &self.request,
            &self.request.capability,
            &self.intent_hash,
            self.now,
        )
    }

    fn verify_shared(
        &self,
        algorithms: &[SigningAlgorithm],
    ) -> TestResult<crate::threshold_approval::VerifiedThresholdApprovalSet> {
        self.verify_shared_with_resolver(
            algorithms,
            &FixedThresholdRequirement(self.requirement.clone()),
        )
    }

    fn verify_shared_with_resolver(
        &self,
        algorithms: &[SigningAlgorithm],
        resolver: &dyn ThresholdApprovalRequirementResolver,
    ) -> TestResult<crate::threshold_approval::VerifiedThresholdApprovalSet> {
        let proposal = self
            .request
            .threshold_approval_proposal
            .as_ref()
            .ok_or("fixture omitted its proposal")?;
        Ok(verify_threshold_approval_set(
            &ThresholdApprovalVerificationInput {
                request_id: &self.request.request_id,
                server_id: &self.request.server_id,
                tool_name: &self.request.tool_name,
                governed_intent_hash: &self.intent_hash,
                subject: &self.request.capability.subject,
                authorization_capability_hash: &sha256_hex(&canonical_json_bytes(
                    &self.request.capability,
                )?),
                authorizing_capability_expires_at: self.request.capability.expires_at,
                governed_operation_expires_at: u64::MAX,
                policy_hash: &self.requirement.policy_hash,
                proposal,
                approval_tokens: &self.request.approval_tokens,
                trusted_policy_authorities: &self.kernel.config.ca_public_keys,
                allowed_signing_algorithms: algorithms,
                now: self.now,
            },
            resolver,
        )?)
    }
}

#[test]
fn classical_threshold_verifiers_agree_on_canonical_replay_identity() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    for floor in [
        KernelCryptoFloor::AllowClassical,
        KernelCryptoFloor::AllowHybrid,
    ] {
        fixture.kernel.set_capability_crypto_floor(floor);
        let tool = fixture.verify_tool()?;
        let shared = fixture.verify_shared(&[SigningAlgorithm::Ed25519])?;
        assert_eq!(tool.body, *shared.body());
        assert_eq!(
            tool.body.approval_set_hash()?,
            shared.reservation_input()?.approval_set_hash()
        );
    }
    Ok(())
}

#[test]
fn tool_threshold_verifier_enforces_pq_floor_independently() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    assert!(
        fixture.verify_tool().is_err(),
        "threshold validator ignored the required PQ floor"
    );
    Ok(())
}

#[test]
fn shared_threshold_rejects_proposal_algorithm_metadata_substitution() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    let proposal = fixture
        .request
        .threshold_approval_proposal
        .as_mut()
        .ok_or("fixture omitted its proposal")?;
    proposal.algorithm = Some(SigningAlgorithm::P256);
    assert!(proposal.verify_signature()?);
    fixture.rebind_vote_to_proposal()?;
    assert!(
        fixture
            .verify_shared(&[SigningAlgorithm::Ed25519, SigningAlgorithm::P256])
            .is_err(),
        "proposal algorithm metadata did not match its signing key and signature"
    );
    Ok(())
}

#[test]
fn tool_threshold_rejects_proposal_algorithm_metadata_substitution() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    let proposal = fixture
        .request
        .threshold_approval_proposal
        .as_mut()
        .ok_or("fixture omitted its proposal")?;
    proposal.algorithm = Some(SigningAlgorithm::P256);
    assert!(proposal.verify_signature()?);
    fixture.rebind_vote_to_proposal()?;
    assert!(
        fixture.verify_tool().is_err(),
        "proposal algorithm metadata substitution admitted"
    );
    Ok(())
}

#[test]
fn tool_threshold_rejects_vote_algorithm_metadata_substitution() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    for token in &mut fixture.request.approval_tokens {
        token.algorithm = Some(SigningAlgorithm::P256);
        assert!(token.verify_signature()?);
    }
    assert!(
        fixture.verify_tool().is_err(),
        "vote algorithm metadata substitution admitted"
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn pq_capability_cannot_authorize_classical_threshold_votes() -> TestResult {
    let mut fixture = Fixture::new(true, false)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    fixture.kernel.verify_capability_full_pre_admit(
        &fixture.request.capability,
        None,
        fixture.now,
    )?;
    assert!(
        fixture.verify_tool().is_err(),
        "classical vote admitted with a valid PQ capability"
    );
    assert!(fixture.verify_shared(&[SigningAlgorithm::Hybrid]).is_err());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn shared_threshold_verifier_rejects_classical_proposal_with_hybrid_votes() -> TestResult {
    let fixture = Fixture::new(false, true)?;
    assert!(
        fixture.verify_shared(&[SigningAlgorithm::Hybrid]).is_err(),
        "hybrid votes laundered a classical proposal through a PQ-only allowlist"
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn tool_threshold_verifier_rejects_classical_proposal_with_hybrid_votes() -> TestResult {
    let mut fixture = Fixture::new(false, true)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    fixture.kernel.verify_capability_full_pre_admit(
        &fixture.request.capability,
        None,
        fixture.now,
    )?;
    assert!(
        fixture.verify_tool().is_err(),
        "hybrid votes laundered a classical proposal"
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn all_hybrid_threshold_artifacts_preserve_replay_identity_under_pq_floor() -> TestResult {
    let mut fixture = Fixture::new(true, true)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    fixture.kernel.verify_capability_full_pre_admit(
        &fixture.request.capability,
        None,
        fixture.now,
    )?;
    let tool = fixture.verify_tool()?;
    let shared = fixture.verify_shared(&[SigningAlgorithm::Hybrid])?;
    assert_eq!(tool.body, *shared.body());
    assert_eq!(
        tool.body.approval_set_hash()?,
        shared.reservation_input()?.approval_set_hash()
    );
    Ok(())
}

#[test]
fn algorithm_allowlist_matches_floor_semantics() {
    for floor in [
        KernelCryptoFloor::AllowClassical,
        KernelCryptoFloor::AllowHybrid,
        KernelCryptoFloor::PqRequired,
    ] {
        for algorithm in [
            SigningAlgorithm::Ed25519,
            SigningAlgorithm::P256,
            SigningAlgorithm::P384,
            SigningAlgorithm::Hybrid,
        ] {
            let permitted = if algorithm == SigningAlgorithm::Hybrid {
                floor.allows_hybrid()
            } else {
                floor.allows_classical_only()
            };
            assert_eq!(
                floor.allowed_signing_algorithms().contains(&algorithm),
                permitted
            );
        }
    }
}

fn counting_resolver(
    requirement: ThresholdApprovalRequirement,
    calls: StdArc<AtomicUsize>,
) -> impl ThresholdApprovalRequirementResolver {
    move |policy_hash: &str, server_id: &str, tool_name: &str| {
        assert_eq!(policy_hash, requirement.policy_hash);
        assert_eq!(server_id, "threshold-server");
        assert_eq!(tool_name, "transfer");
        if calls.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err("policy was resolved more than once".to_owned());
        }
        Ok(Some(requirement.clone()))
    }
}

#[test]
fn tool_threshold_resolves_current_route_exactly_once() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    let calls = StdArc::new(AtomicUsize::new(0));
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(counting_resolver(
            fixture.requirement.clone(),
            StdArc::clone(&calls),
        )));
    fixture.verify_tool()?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn shared_threshold_resolves_current_route_exactly_once() -> TestResult {
    let fixture = Fixture::new(false, false)?;
    let calls = StdArc::new(AtomicUsize::new(0));
    fixture.verify_shared_with_resolver(
        &[SigningAlgorithm::Ed25519],
        &counting_resolver(fixture.requirement.clone(), StdArc::clone(&calls)),
    )?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn tool_threshold_rejects_empty_and_oversized_sets_before_policy_lookup() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    let calls = StdArc::new(AtomicUsize::new(0));
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(counting_resolver(
            fixture.requirement.clone(),
            StdArc::clone(&calls),
        )));
    let token = fixture.request.approval_tokens[0].clone();
    for size in [
        0,
        chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS + 1,
    ] {
        fixture.request.approval_tokens = vec![token.clone(); size];
        assert!(fixture.verify_tool().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn shared_threshold_rejects_oversized_set_before_policy_lookup() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    let calls = StdArc::new(AtomicUsize::new(0));
    fixture.request.approval_tokens = vec![
        fixture.request.approval_tokens[0].clone();
        chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
            + 1
    ];
    assert!(fixture
        .verify_shared_with_resolver(
            &[SigningAlgorithm::Ed25519],
            &counting_resolver(fixture.requirement.clone(), StdArc::clone(&calls)),
        )
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn threshold_verifiers_enforce_replay_member_id_bounds() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    for (id, permitted) in [
        ("x".repeat(512), true),
        ("x".repeat(513), false),
        ("vote\0id".into(), false),
    ] {
        fixture.request.approval_tokens[0].id = id;
        fixture.rebind_vote_to_proposal()?;
        assert!(fixture.request.approval_tokens[0].verify_signature()?);
        assert_eq!(fixture.verify_tool().is_ok(), permitted);
        assert_eq!(
            fixture.verify_shared(&[SigningAlgorithm::Ed25519]).is_ok(),
            permitted
        );
    }
    Ok(())
}

#[test]
fn classical_envelopes_allow_omitted_ed25519_metadata() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    fixture
        .request
        .threshold_approval_proposal
        .as_mut()
        .ok_or("fixture omitted its proposal")?
        .algorithm = None;
    fixture.rebind_vote_to_proposal()?;
    fixture.request.approval_tokens[0].algorithm = None;
    let tool = fixture.verify_tool()?;
    let shared = fixture.verify_shared(&[SigningAlgorithm::Ed25519])?;
    assert_eq!(tool.body, *shared.body());
    Ok(())
}

#[test]
fn shared_threshold_rejects_vote_algorithm_metadata_substitution() -> TestResult {
    let mut fixture = Fixture::new(false, false)?;
    fixture.request.approval_tokens[0].algorithm = Some(SigningAlgorithm::P256);
    assert!(fixture.request.approval_tokens[0].verify_signature()?);
    assert!(fixture
        .verify_shared(&[SigningAlgorithm::Ed25519, SigningAlgorithm::P256])
        .is_err());
    Ok(())
}

#[test]
fn empty_algorithm_allowlist_denies() -> TestResult {
    assert!(Fixture::new(false, false)?.verify_shared(&[]).is_err());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_envelopes_require_explicit_consistent_metadata() -> TestResult {
    for algorithm in [None, Some(SigningAlgorithm::P256)] {
        for mutate_proposal in [true, false] {
            let mut fixture = Fixture::new(true, true)?;
            fixture
                .kernel
                .set_capability_crypto_floor(KernelCryptoFloor::AllowHybrid);
            if mutate_proposal {
                let proposal = fixture
                    .request
                    .threshold_approval_proposal
                    .as_mut()
                    .ok_or("fixture omitted its proposal")?;
                proposal.algorithm = algorithm;
                assert!(proposal.verify_signature()?);
                fixture.rebind_vote_to_proposal()?;
            } else {
                fixture.request.approval_tokens[0].algorithm = algorithm;
                assert!(fixture.request.approval_tokens[0].verify_signature()?);
            }
            assert!(fixture.verify_tool().is_err());
            assert!(fixture
                .verify_shared(KernelCryptoFloor::AllowHybrid.allowed_signing_algorithms())
                .is_err());
        }
    }
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn allow_classical_rejects_hybrid_threshold_artifacts() -> TestResult {
    let mut fixture = Fixture::new(true, true)?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::AllowHybrid);
    fixture.verify_tool()?;
    fixture
        .kernel
        .set_capability_crypto_floor(KernelCryptoFloor::AllowClassical);
    assert!(fixture.verify_tool().is_err());
    assert!(fixture
        .verify_shared(KernelCryptoFloor::AllowClassical.allowed_signing_algorithms())
        .is_err());
    Ok(())
}
