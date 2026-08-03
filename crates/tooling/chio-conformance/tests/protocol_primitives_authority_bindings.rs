use std::collections::BTreeMap;
use std::error::Error;

use chio_adversarial_suite::{bundled_cases_by_class, AttackClass};
use chio_core::capability::aggregate_budget::{
    issue_aggregate_family_root, verify_aggregate_invocation_authority,
    verify_direct_aggregate_family_root, AggregateBudgetDelegationMarker,
    AggregateBudgetRootBinding, AggregateBudgetRootBindingBody, AggregateFamilyRootResolution,
    VerifiedAggregateFamilyRoot,
};
use chio_core::capability::attenuation::{
    compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink, DelegationLinkBody,
};
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    ThresholdApprovalRequirement, VerifiedApprovalSetBody,
};
use chio_core::capability::token::{
    CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
};
use chio_core::crypto::{sha256_hex, Keypair, PublicKey, SigningAlgorithm};
use chio_kernel::threshold_approval::{
    verify_threshold_approval_set, ThresholdApprovalVerificationInput,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn tool_scope(delegable: bool) -> ChioScope {
    let mut operations = vec![Operation::Invoke];
    if delegable {
        operations.push(Operation::Delegate);
    }
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server".to_string(),
            tool_name: "tool".to_string(),
            operations,
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn token_body(
    id: &str,
    issuer: &PublicKey,
    subject: &PublicKey,
    scope: ChioScope,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.clone(),
        subject: subject.clone(),
        scope,
        issued_at: 100,
        expires_at: 1_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    }
}

fn family_root(
    issuer: &Keypair,
    subject: &Keypair,
    max_invocations: u32,
) -> chio_core::Result<CapabilityToken> {
    issue_aggregate_family_root(
        token_body(
            "family-root",
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(true),
        ),
        max_invocations,
        issuer,
    )
}

fn family_descendant(
    root: &CapabilityToken,
    verified_root: &VerifiedAggregateFamilyRoot,
    root_subject: &Keypair,
    delegatee: &Keypair,
    marker_digest: String,
) -> chio_core::Result<CapabilityToken> {
    let budget = root.aggregate_invocation_budget.clone().ok_or_else(|| {
        chio_core::Error::CanonicalJson("aggregate root budget missing".to_string())
    })?;
    let marker = AggregateBudgetDelegationMarker {
        root_binding_digest: marker_digest,
        max_invocations: budget.max_invocations,
    };
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: root.id.clone(),
            delegator: root.subject.clone(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp: 200,
            scope_hash: Some(scope_hash(&root.scope)?),
            aggregate_budget: Some(marker),
            cumulative_approval: None,
            aggregate_family_preservation: Some(verified_root.preservation_evidence()),
        },
        root_subject,
    )?;
    let child_scope = tool_scope(false);
    let mut body = token_body(
        "family-child",
        &root_subject.public_key(),
        &delegatee.public_key(),
        child_scope.clone(),
    );
    body.issued_at = 200;
    body.expires_at = 900;
    body.delegation_chain = vec![link];
    body.aggregate_invocation_budget = Some(budget);
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&root.scope)?,
                child_scope_hash: scope_hash(&child_scope)?,
                normalized_subset_proof: compute_attenuation_witness(&root.scope, &child_scope)?,
                aggregate_family_preservation: Some(verified_root.preservation_evidence()),
            },
            budget_share_bps: None,
        },
        root_subject,
    )
}

fn resign_root_binding(
    root: &CapabilityToken,
    outer_signer: &Keypair,
    binding_signer: &Keypair,
    mutate: impl FnOnce(&mut AggregateBudgetRootBindingBody),
) -> chio_core::Result<CapabilityToken> {
    let mut body = root.body();
    let budget = body.aggregate_invocation_budget.as_mut().ok_or_else(|| {
        chio_core::Error::CanonicalJson("aggregate root budget missing".to_string())
    })?;
    let binding = budget.root_binding.as_mut().ok_or_else(|| {
        chio_core::Error::CanonicalJson("aggregate root binding missing".to_string())
    })?;
    mutate(&mut binding.body);
    *binding = AggregateBudgetRootBinding {
        signature: binding_signer.sign(&binding.body.signing_bytes()?),
        algorithm: None,
        body: binding.body.clone(),
    };
    CapabilityToken::sign(body, outer_signer)
}

fn mutation_names(primitive: &str) -> TestResult<Vec<String>> {
    let cases = bundled_cases_by_class(AttackClass::AuthorityBindingMutation)?;
    let case = cases
        .iter()
        .find(|case| case.artifact["primitive"] == primitive)
        .ok_or_else(|| std::io::Error::other(format!("missing {primitive} vector")))?;
    serde_json::from_value(case.artifact["mutations"].clone()).map_err(Into::into)
}

#[test]
fn aggregate_root_binding_mutation_vectors_fail_closed() -> TestResult {
    let issuer = Keypair::from_seed(&[1; 32]);
    let root_subject = Keypair::from_seed(&[2; 32]);
    let attacker = Keypair::from_seed(&[3; 32]);
    let root = family_root(&issuer, &root_subject, 7)?;
    let trusted = [issuer.public_key()];
    let verified_root = verify_direct_aggregate_family_root(&root, &trusted)?;

    for mutation in mutation_names("aggregate_budget_root_binding")? {
        if mutation == "root_binding_digest" {
            let delegatee = Keypair::from_seed(&[4; 32]);
            let child = family_descendant(
                &root,
                &verified_root,
                &root_subject,
                &delegatee,
                sha256_hex(b"forged-binding-digest"),
            );
            if let Ok(child) = child {
                assert!(verify_aggregate_invocation_authority(
                    &child,
                    &trusted,
                    &[root_subject.public_key()],
                    &|root_id: &str| {
                        assert_eq!(root_id, root.id);
                        Ok(AggregateFamilyRootResolution::FamilyBound(
                            verified_root.clone(),
                        ))
                    },
                )
                .is_err());
            }
            continue;
        }

        let forged = match mutation.as_str() {
            "root_capability_id" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_capability_id = "forged-root".to_string();
            }),
            "root_capability_hash" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_capability_hash = sha256_hex(b"forged-root");
            }),
            "root_issuer" => resign_root_binding(&root, &issuer, &attacker, |body| {
                body.root_issuer = attacker.public_key();
            }),
            "root_subject" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_subject = attacker.public_key();
            }),
            "root_scope_hash" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_scope_hash = sha256_hex(b"forged-scope");
            }),
            "root_expires_at" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_expires_at = body.root_expires_at.saturating_add(1);
            }),
            "signature" => {
                let mut body = root.body();
                let budget = body.aggregate_invocation_budget.as_mut().ok_or_else(|| {
                    chio_core::Error::CanonicalJson("aggregate root budget missing".to_string())
                })?;
                let binding = budget.root_binding.as_mut().ok_or_else(|| {
                    chio_core::Error::CanonicalJson("aggregate root binding missing".to_string())
                })?;
                let mut other_body = binding.body.clone();
                other_body.root_capability_id = "signature-source".to_string();
                binding.signature = issuer.sign(&other_body.signing_bytes()?);
                CapabilityToken::sign(body, &issuer)
            }
            other => return Err(std::io::Error::other(format!("unknown mutation {other}")).into()),
        };
        let Ok(forged) = forged else {
            continue;
        };
        assert!(
            verify_direct_aggregate_family_root(&forged, &trusted).is_err(),
            "mutation {mutation} was accepted"
        );
    }
    Ok(())
}

struct ThresholdFixture {
    authority: Keypair,
    alice: Keypair,
    bob: Keypair,
    subject: Keypair,
    requirement: ThresholdApprovalRequirement,
    intent_hash: String,
    capability_hash: String,
}

fn threshold_fixture() -> TestResult<ThresholdFixture> {
    let authority = Keypair::from_seed(&[11; 32]);
    let alice = Keypair::from_seed(&[12; 32]);
    let bob = Keypair::from_seed(&[13; 32]);
    let subject = Keypair::from_seed(&[14; 32]);
    let policy_hash = sha256_hex(b"active-policy");
    let intent_hash = sha256_hex(b"intent");
    let capability_hash = sha256_hex(b"capability");
    let requirement = ThresholdApprovalRequirement::new(
        2,
        BTreeMap::from([
            ("alice".to_string(), alice.public_key()),
            ("bob".to_string(), bob.public_key()),
        ]),
        100,
        policy_hash,
        1,
    )
    .map_err(std::io::Error::other)?;
    Ok(ThresholdFixture {
        authority,
        alice,
        bob,
        subject,
        requirement,
        intent_hash,
        capability_hash,
    })
}

fn proposal(fixture: &ThresholdFixture) -> chio_core::Result<ThresholdApprovalProposal> {
    ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-1",
            "request-1",
            fixture.intent_hash.clone(),
            fixture.subject.public_key(),
            fixture.capability_hash.clone(),
            fixture.requirement.policy_hash(),
            fixture.requirement.required(),
            fixture.requirement.eligible_set_digest(),
            100,
            fixture.requirement.proposal_timeout_seconds(),
            200,
            200,
        )?,
        &fixture.authority,
    )
}

fn approval_token(
    proposal: &ThresholdApprovalProposal,
    approver: &Keypair,
    id: &str,
) -> chio_core::Result<GovernedApprovalToken> {
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: id.to_string(),
            approver: approver.public_key(),
            subject: proposal.body().subject().clone(),
            governed_intent_hash: proposal.body().governed_intent_hash().to_string(),
            request_id: proposal.body().request_id().to_string(),
            threshold_proposal_hash: Some(proposal.proposal_hash()?),
            issued_at: 101,
            expires_at: 199,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
}

fn verify_threshold(
    fixture: &ThresholdFixture,
    proposal: &ThresholdApprovalProposal,
    tokens: &[GovernedApprovalToken],
    now: u64,
) -> TestResult {
    let trusted_authorities = [fixture.authority.public_key()];
    verify_threshold_approval_set(
        &ThresholdApprovalVerificationInput {
            request_id: "request-1",
            server_id: "server",
            tool_name: "tool",
            governed_intent_hash: &fixture.intent_hash,
            subject: &fixture.subject.public_key(),
            authorization_capability_hash: &fixture.capability_hash,
            authorizing_capability_expires_at: 200,
            governed_operation_expires_at: 200,
            policy_hash: fixture.requirement.policy_hash(),
            proposal,
            approval_tokens: tokens,
            trusted_policy_authorities: &trusted_authorities,
            allowed_token_algorithms: &[SigningAlgorithm::Ed25519],
            now,
        },
        &|_: &ThresholdApprovalRequest, _: &str| Ok(fixture.requirement.clone()),
    )?;
    Ok(())
}

fn mutate_proposal(
    proposal: &ThresholdApprovalProposal,
    field: &str,
    value: serde_json::Value,
) -> TestResult<ThresholdApprovalProposal> {
    let mut wire = serde_json::to_value(proposal)?;
    let body = wire
        .get_mut("body")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| std::io::Error::other("proposal body missing from wire artifact"))?;
    body.insert(field.to_string(), value);
    serde_json::from_value(wire).map_err(Into::into)
}

#[test]
fn threshold_proposal_mutations_and_exact_quorum_fail_closed() -> TestResult {
    let fixture = threshold_fixture()?;
    let proposal = proposal(&fixture)?;

    for mutation in mutation_names("threshold_approval_proposal")? {
        match mutation.as_str() {
            "future" => assert!(verify_threshold(&fixture, &proposal, &[], 99).is_err()),
            "expired" => assert!(verify_threshold(&fixture, &proposal, &[], 200).is_err()),
            "proposal_deadline" => {
                let changed = mutate_proposal(&proposal, "proposalDeadline", 201.into())?;
                assert!(verify_threshold(&fixture, &changed, &[], 110).is_err());
            }
            "eligible_set_digest" => {
                let changed = mutate_proposal(
                    &proposal,
                    "eligibleSetDigest",
                    sha256_hex(b"changed-set").into(),
                )?;
                assert!(verify_threshold(&fixture, &changed, &[], 110).is_err());
            }
            "governed_intent_hash" => {
                let changed = mutate_proposal(
                    &proposal,
                    "governedIntentHash",
                    sha256_hex(b"changed-intent").into(),
                )?;
                assert!(verify_threshold(&fixture, &changed, &[], 110).is_err());
            }
            "authorizing_capability_digest" => {
                let changed = mutate_proposal(
                    &proposal,
                    "authorizationCapabilityHash",
                    sha256_hex(b"changed-capability").into(),
                )?;
                assert!(verify_threshold(&fixture, &changed, &[], 110).is_err());
            }
            other => return Err(std::io::Error::other(format!("unknown mutation {other}")).into()),
        }
    }

    let alice = approval_token(&proposal, &fixture.alice, "token-alice")?;
    let replay = approval_token(&proposal, &fixture.alice, "token-alice-replay")?;
    let bob = approval_token(&proposal, &fixture.bob, "token-bob")?;
    assert!(verify_threshold(&fixture, &proposal, std::slice::from_ref(&alice), 110).is_err());
    assert!(verify_threshold(&fixture, &proposal, &[alice.clone(), replay], 111).is_err());
    verify_threshold(&fixture, &proposal, &[alice, bob], 112)?;
    Ok(())
}

#[test]
fn verified_approval_set_is_order_invariant_and_domain_separated() -> TestResult {
    let fixture = threshold_fixture()?;
    let proposal = proposal(&fixture)?;
    let alice = approval_token(&proposal, &fixture.alice, "token-alice")?.token_digest()?;
    let bob = approval_token(&proposal, &fixture.bob, "token-bob")?.token_digest()?;
    let first = VerifiedApprovalSetBody::new(vec![alice.clone(), bob.clone()], &proposal)?;
    let second = VerifiedApprovalSetBody::new(vec![bob, alice], &proposal)?;

    assert_eq!(first, second);
    assert_eq!(first.approval_set_hash()?, second.approval_set_hash()?);
    assert_ne!(first.approval_set_hash()?, proposal.proposal_hash()?);
    assert!(VerifiedApprovalSetBody::new(
        vec![sha256_hex(b"duplicate"), sha256_hex(b"duplicate")],
        &proposal,
    )
    .is_err());
    Ok(())
}
