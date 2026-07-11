use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use crate::canonical::canonical_json_bytes;
use crate::capability::aggregate_budget::{
    issue_aggregate_family_root, verify_aggregate_invocation_authority,
    verify_direct_aggregate_family_root, AggregateFamilyPreservationEvidence,
    AggregateFamilyRootResolution, AggregateFamilyRootResolutionError, AggregateFamilyRootResolver,
    AggregateInvocationAuthorityError, AggregateInvocationBudget, AggregateInvocationScope,
    LegacyUnboundAggregateRoot, VerifiedAggregateFamilyRoot,
};
use crate::capability::attenuation::{
    compute_attenuation_witness, delegate, delegate_with_aggregate_family_authority, scope_hash,
    AttenuationProof, AttenuationWitness, DelegationLink, DelegationLinkBody,
};
use crate::capability::scope::{ChioScope, Operation, ToolGrant};
use crate::capability::token::{
    CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
};
use crate::crypto::{Keypair, SigningAlgorithm};
use crate::delegation_receipt::{DelegationReceipt, ScopeAttenuation};
use crate::error::Error;

struct FamilyFixture {
    root_issuer: Keypair,
    root_subject: Keypair,
    child_subject: Keypair,
    root_token: CapabilityToken,
    verified_root: VerifiedAggregateFamilyRoot,
}

impl FamilyFixture {
    fn new(root_id: &str, max_invocations: u32) -> Self {
        let root_issuer = Keypair::from_seed(&[41; 32]);
        let root_subject = Keypair::from_seed(&[42; 32]);
        let child_subject = Keypair::from_seed(&[43; 32]);
        let body = CapabilityTokenBody {
            id: root_id.to_string(),
            issuer: root_issuer.public_key(),
            subject: root_subject.public_key(),
            scope: family_root_scope(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        };
        let root_token = issue_aggregate_family_root(body, max_invocations, &root_issuer).unwrap();
        let verified_root =
            verify_direct_aggregate_family_root(&root_token, &[root_issuer.public_key()]).unwrap();
        Self {
            root_issuer,
            root_subject,
            child_subject,
            root_token,
            verified_root,
        }
    }

    fn family_budget(&self) -> AggregateInvocationBudget {
        self.root_token.aggregate_invocation_budget.clone().unwrap()
    }

    fn evidence(&self) -> AggregateFamilyPreservationEvidence {
        self.verified_root.preservation_evidence()
    }

    fn child_scope(&self) -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "family-server".to_string(),
                tool_name: "family-tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        }
    }

    fn proof(&self, evidence: Option<AggregateFamilyPreservationEvidence>) -> AttenuationProof {
        let child_scope = self.child_scope();
        AttenuationProof {
            parent_scope_hash: scope_hash(&self.root_token.scope).unwrap(),
            child_scope_hash: scope_hash(&child_scope).unwrap(),
            normalized_subset_proof: compute_attenuation_witness(
                &self.root_token.scope,
                &child_scope,
            )
            .unwrap(),
            aggregate_family_preservation: evidence,
        }
    }

    fn link(&self, evidence: Option<AggregateFamilyPreservationEvidence>) -> DelegationLink {
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: self.root_token.id.clone(),
                delegator: self.root_subject.public_key(),
                delegatee: self.child_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 1_100,
                scope_hash: Some(scope_hash(&self.root_token.scope).unwrap()),
                aggregate_family_preservation: evidence,
            },
            &self.root_subject,
        )
        .unwrap()
    }

    fn signed_descendant(
        &self,
        proof_evidence: Option<AggregateFamilyPreservationEvidence>,
        link_evidence: Option<AggregateFamilyPreservationEvidence>,
    ) -> CapabilityToken {
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: "family-child".to_string(),
                    issuer: self.root_subject.public_key(),
                    subject: self.child_subject.public_key(),
                    scope: self.child_scope(),
                    issued_at: 1_100,
                    expires_at: 1_900,
                    delegation_chain: vec![self.link(link_evidence)],
                    aggregate_invocation_budget: Some(self.family_budget()),
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: self.proof(proof_evidence),
                budget_share_bps: None,
            },
            &self.root_subject,
        )
        .unwrap()
    }

    fn legacy_record(&self) -> LegacyUnboundAggregateRoot {
        LegacyUnboundAggregateRoot::new(
            self.root_token.id.clone(),
            self.root_subject.public_key(),
            scope_hash(&self.root_token.scope).unwrap(),
            self.root_token.expires_at,
        )
    }
}

fn family_root_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "family-server".to_string(),
            tool_name: "family-tool".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn capability_budget(max_invocations: u32) -> AggregateInvocationBudget {
    AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations,
        root_binding: None,
    }
}

fn resign(token: &mut CapabilityToken, signer: &Keypair) {
    token.signature = signer.sign_canonical(&token.signing_body()).unwrap().0;
}

#[derive(Clone)]
enum ResolverOutcome {
    Family(VerifiedAggregateFamilyRoot),
    Legacy(LegacyUnboundAggregateRoot),
    Error(AggregateFamilyRootResolutionError),
}

struct CountingResolver {
    expected_root_id: String,
    outcome: ResolverOutcome,
    calls: Cell<usize>,
}

impl CountingResolver {
    fn family(fixture: &FamilyFixture) -> Self {
        Self {
            expected_root_id: fixture.root_token.id.clone(),
            outcome: ResolverOutcome::Family(fixture.verified_root.clone()),
            calls: Cell::new(0),
        }
    }

    fn legacy(fixture: &FamilyFixture) -> Self {
        Self {
            expected_root_id: fixture.root_token.id.clone(),
            outcome: ResolverOutcome::Legacy(fixture.legacy_record()),
            calls: Cell::new(0),
        }
    }

    fn error(fixture: &FamilyFixture, error: AggregateFamilyRootResolutionError) -> Self {
        Self {
            expected_root_id: fixture.root_token.id.clone(),
            outcome: ResolverOutcome::Error(error),
            calls: Cell::new(0),
        }
    }
}

impl AggregateFamilyRootResolver for CountingResolver {
    fn resolve_aggregate_family_root(
        &self,
        root_capability_id: &str,
    ) -> core::result::Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError>
    {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(root_capability_id, self.expected_root_id);
        match &self.outcome {
            ResolverOutcome::Family(root) => {
                Ok(AggregateFamilyRootResolution::FamilyBound(root.clone()))
            }
            ResolverOutcome::Legacy(root) => {
                Ok(AggregateFamilyRootResolution::LegacyUnbound(root.clone()))
            }
            ResolverOutcome::Error(error) => Err(error.clone()),
        }
    }
}

fn assert_attenuation_reason(error: Error, expected: &str) {
    match error {
        Error::AttenuationViolation { reason } => assert_eq!(reason, expected),
        other => panic!("expected attenuation rejection, got {other:?}"),
    }
}

fn assert_authority_reason(error: AggregateInvocationAuthorityError, expected: &str) {
    match error {
        AggregateInvocationAuthorityError::Verification(Error::AttenuationViolation { reason }) => {
            assert_eq!(reason, expected)
        }
        other => panic!("expected authority attenuation rejection, got {other:?}"),
    }
}

#[test]
fn aggregate_invocation_attenuation_absent_proof_evidence_preserves_canonical_bytes() {
    let proof = AttenuationProof {
        parent_scope_hash: "parent-hash".to_string(),
        child_scope_hash: "child-hash".to_string(),
        normalized_subset_proof: AttenuationWitness {
            normalized_parent_scope: "parent-scope".to_string(),
            normalized_child_scope: "child-scope".to_string(),
            subset_relations: vec![],
            restricted_predicates: vec![],
        },
        aggregate_family_preservation: None,
    };

    assert_eq!(
        canonical_json_bytes(&proof).unwrap(),
        br#"{"childScopeHash":"child-hash","normalizedSubsetProof":{"normalizedChildScope":"child-scope","normalizedParentScope":"parent-scope"},"parentScopeHash":"parent-hash"}"#
    );
}

#[test]
fn aggregate_invocation_attenuation_absent_link_evidence_preserves_signing_bytes() {
    let delegator = Keypair::from_seed(&[51; 32]);
    let delegatee = Keypair::from_seed(&[52; 32]);
    let body = DelegationLinkBody {
        capability_id: "root-capability".to_string(),
        delegator: delegator.public_key(),
        delegatee: delegatee.public_key(),
        attenuations: Vec::new(),
        timestamp: 1_100,
        scope_hash: Some("scope-hash".to_string()),
        aggregate_family_preservation: None,
    };
    let expected = format!(
        "{{\"capability_id\":\"root-capability\",\"delegatee\":\"{}\",\"delegator\":\"{}\",\"scope_hash\":\"scope-hash\",\"timestamp\":1100}}",
        delegatee.public_key().to_hex(),
        delegator.public_key().to_hex()
    );

    assert_eq!(canonical_json_bytes(&body).unwrap(), expected.as_bytes());
    let link = DelegationLink::sign(body, &delegator).unwrap();
    assert!(link.verify_signature().unwrap());
    assert_eq!(link.aggregate_family_preservation, None);
}

#[test]
fn aggregate_invocation_attenuation_evidence_has_closed_camel_case_wire_shape() {
    let evidence = AggregateFamilyPreservationEvidence {
        root_binding_digest: "binding-digest".to_string(),
        max_invocations: 7,
    };

    assert_eq!(
        canonical_json_bytes(&evidence).unwrap(),
        br#"{"maxInvocations":7,"rootBindingDigest":"binding-digest"}"#
    );
    assert!(serde_json::from_str::<AggregateFamilyPreservationEvidence>(
        r#"{"rootBindingDigest":"binding-digest","maxInvocations":7,"extra":true}"#
    )
    .is_err());
}

#[test]
fn aggregate_invocation_attenuation_verified_projection_is_family_only_and_stable() {
    let fixture = FamilyFixture::new("projection-root", 7);
    let resolver = CountingResolver::family(&fixture);
    let root_authority = verify_aggregate_invocation_authority(
        &fixture.root_token,
        &[fixture.root_issuer.public_key()],
        &[],
        &resolver,
    )
    .unwrap()
    .unwrap();
    let descendant = fixture.signed_descendant(Some(fixture.evidence()), None);
    let descendant_authority = verify_aggregate_invocation_authority(
        &descendant,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap()
    .unwrap();

    assert_eq!(
        root_authority.preservation_evidence(),
        descendant_authority.preservation_evidence()
    );
    assert_eq!(
        root_authority.preservation_evidence(),
        Some(fixture.evidence())
    );

    let issuer = Keypair::from_seed(&[53; 32]);
    let subject = Keypair::from_seed(&[54; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-only".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: Some(capability_budget(3)),
        },
        &issuer,
    )
    .unwrap();
    let capability_authority =
        verify_aggregate_invocation_authority(&capability, &[issuer.public_key()], &[], &resolver)
            .unwrap()
            .unwrap();
    assert_eq!(capability_authority.preservation_evidence(), None);
}

#[test]
fn aggregate_invocation_attenuation_family_proof_requires_exact_evidence() {
    let fixture = FamilyFixture::new("proof-evidence-root", 7);

    for (evidence, expected) in [
        (
            None,
            "attenuated delegation-family capability must preserve aggregate family evidence",
        ),
        (
            Some(AggregateFamilyPreservationEvidence {
                root_binding_digest: "wrong-digest".to_string(),
                max_invocations: 7,
            }),
            "aggregate family preservation digest does not match the root binding",
        ),
        (
            Some(AggregateFamilyPreservationEvidence {
                root_binding_digest: fixture.verified_root.root_binding_digest().to_string(),
                max_invocations: 8,
            }),
            "aggregate family preservation maximum does not match the immutable maximum",
        ),
    ] {
        let error = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: "invalid-proof-evidence".to_string(),
                    issuer: fixture.root_subject.public_key(),
                    subject: fixture.child_subject.public_key(),
                    scope: fixture.child_scope(),
                    issued_at: 1_100,
                    expires_at: 1_900,
                    delegation_chain: vec![fixture.link(None)],
                    aggregate_invocation_budget: Some(fixture.family_budget()),
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: fixture.proof(evidence),
                budget_share_bps: None,
            },
            &fixture.root_subject,
        )
        .unwrap_err();
        assert_attenuation_reason(error, expected);
    }
}

#[test]
fn aggregate_invocation_attenuation_rejects_spurious_proof_evidence() {
    let fixture = FamilyFixture::new("spurious-proof-root", 7);

    for aggregate_invocation_budget in [None, Some(capability_budget(3))] {
        let error = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: "spurious-proof-evidence".to_string(),
                    issuer: fixture.root_subject.public_key(),
                    subject: fixture.child_subject.public_key(),
                    scope: fixture.child_scope(),
                    issued_at: 1_100,
                    expires_at: 1_900,
                    delegation_chain: vec![fixture.link(None)],
                    aggregate_invocation_budget,
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: fixture.proof(Some(fixture.evidence())),
                budget_share_bps: None,
            },
            &fixture.root_subject,
        )
        .unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family preservation evidence requires a delegation-family budget",
        );
    }
}

#[test]
fn aggregate_invocation_attenuation_signed_token_mutations_are_rejected() {
    let fixture = FamilyFixture::new("signed-proof-root", 7);
    let valid = fixture.signed_descendant(Some(fixture.evidence()), Some(fixture.evidence()));

    for mutation in ["missing", "digest", "maximum"] {
        let mut token = valid.clone();
        let evidence = &mut token
            .attenuation_proof
            .as_mut()
            .unwrap()
            .aggregate_family_preservation;
        match mutation {
            "missing" => *evidence = None,
            "digest" => evidence.as_mut().unwrap().root_binding_digest = "wrong".to_string(),
            "maximum" => evidence.as_mut().unwrap().max_invocations = 8,
            _ => unreachable!(),
        }
        resign(&mut token, &fixture.root_subject);
        let resolver = CountingResolver::family(&fixture);
        let error = verify_aggregate_invocation_authority(
            &token,
            &[],
            &[fixture.root_subject.public_key()],
            &resolver,
        )
        .unwrap_err();
        let expected = match mutation {
            "missing" => {
                "attenuated delegation-family capability must preserve aggregate family evidence"
            }
            "digest" => "aggregate family preservation digest does not match the root binding",
            "maximum" => {
                "aggregate family preservation maximum does not match the immutable maximum"
            }
            _ => unreachable!(),
        };
        assert_authority_reason(error, expected);
    }
}

#[test]
fn aggregate_invocation_attenuation_plain_family_descendant_remains_resolver_authoritative() {
    let fixture = FamilyFixture::new("plain-descendant-root", 7);
    let plain = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "plain-family-child".to_string(),
            issuer: fixture.root_subject.public_key(),
            subject: fixture.child_subject.public_key(),
            scope: fixture.child_scope(),
            issued_at: 1_100,
            expires_at: 1_900,
            delegation_chain: vec![fixture.link(None)],
            aggregate_invocation_budget: Some(fixture.family_budget()),
        },
        &fixture.root_subject,
    )
    .unwrap();
    let resolver = CountingResolver::family(&fixture);

    let authority = verify_aggregate_invocation_authority(
        &plain,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap()
    .unwrap();

    assert_eq!(resolver.calls.get(), 1);
    assert_eq!(authority.preservation_evidence(), Some(fixture.evidence()));
}

#[test]
fn aggregate_invocation_attenuation_evidence_never_bypasses_root_resolution() {
    let fixture = FamilyFixture::new("resolver-required-root", 7);
    let token = fixture.signed_descendant(Some(fixture.evidence()), Some(fixture.evidence()));

    for expected in [
        AggregateFamilyRootResolutionError::Missing,
        AggregateFamilyRootResolutionError::Unavailable("offline".to_string()),
        AggregateFamilyRootResolutionError::Corrupt("invalid row".to_string()),
    ] {
        let resolver = CountingResolver::error(&fixture, expected.clone());
        let error = verify_aggregate_invocation_authority(
            &token,
            &[],
            &[fixture.root_subject.public_key()],
            &resolver,
        )
        .unwrap_err();
        assert_eq!(resolver.calls.get(), 1);
        match error {
            AggregateInvocationAuthorityError::RootResolution(actual) => {
                assert_eq!(actual, expected)
            }
            other => panic!("expected root resolution rejection, got {other:?}"),
        }
    }
}

#[test]
fn aggregate_invocation_attenuation_spurious_legacy_evidence_denies() {
    let fixture = FamilyFixture::new("legacy-evidence-root", 7);
    let mut token = fixture.signed_descendant(Some(fixture.evidence()), Some(fixture.evidence()));
    token.aggregate_invocation_budget = None;
    resign(&mut token, &fixture.root_subject);
    let resolver = CountingResolver::legacy(&fixture);

    let error = verify_aggregate_invocation_authority(
        &token,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "aggregate family preservation evidence requires a delegation-family budget",
    );
}

#[test]
fn aggregate_invocation_attenuation_legacy_delegate_rejects_family_parent() {
    let fixture = FamilyFixture::new("legacy-delegate-root", 7);

    let error = delegate(
        &fixture.root_token,
        &fixture.child_scope(),
        &fixture.root_subject,
        &fixture.child_subject.public_key(),
        ScopeAttenuation::empty(),
        1_100,
        [7; 16],
    )
    .unwrap_err();

    assert_attenuation_reason(
        error,
        "delegation-family parent requires verified aggregate family authority",
    );
}

#[test]
fn aggregate_invocation_attenuation_delegate_checks_signature_before_family_authority() {
    let fixture = FamilyFixture::new("delegate-signature-root", 7);
    let mut tampered = fixture.root_token.clone();
    tampered.expires_at -= 1;

    let error = delegate(
        &tampered,
        &fixture.child_scope(),
        &fixture.root_subject,
        &fixture.child_subject.public_key(),
        ScopeAttenuation::empty(),
        1_100,
        [11; 16],
    )
    .unwrap_err();

    assert!(matches!(error, Error::SignatureVerificationFailed));
}

#[test]
fn aggregate_invocation_attenuation_verified_delegate_signs_receipt_evidence() {
    let fixture = FamilyFixture::new("verified-delegate-root", 7);
    let receipt = delegate_with_aggregate_family_authority(
        &fixture.root_token,
        &fixture.verified_root,
        &fixture.child_scope(),
        &fixture.root_subject,
        &fixture.child_subject.public_key(),
        ScopeAttenuation::empty(),
        1_100,
        [8; 16],
    )
    .unwrap();

    assert_eq!(
        receipt.aggregate_family_preservation(),
        Some(&fixture.evidence())
    );
    receipt
        .verify_aggregate_family_preservation(&fixture.verified_root)
        .unwrap();
    assert!(receipt.link.verify_signature().unwrap());

    let bytes = receipt.canonical_bytes().unwrap();
    let decoded: crate::delegation_receipt::DelegationReceipt =
        serde_json::from_slice(bytes.as_bytes()).unwrap();
    decoded
        .verify_aggregate_family_preservation(&fixture.verified_root)
        .unwrap();
}

#[test]
fn aggregate_invocation_attenuation_verified_delegate_supports_family_descendants() {
    let fixture = FamilyFixture::new("recursive-delegate-root", 7);
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "family-intermediate".to_string(),
            issuer: fixture.root_subject.public_key(),
            subject: fixture.child_subject.public_key(),
            scope: family_root_scope(),
            issued_at: 1_100,
            expires_at: 1_900,
            delegation_chain: vec![fixture.link(Some(fixture.evidence()))],
            aggregate_invocation_budget: Some(fixture.family_budget()),
        },
        &fixture.root_subject,
    )
    .unwrap();
    let grandchild = Keypair::from_seed(&[44; 32]);

    let receipt = delegate_with_aggregate_family_authority(
        &parent,
        &fixture.verified_root,
        &fixture.child_scope(),
        &fixture.child_subject,
        &grandchild.public_key(),
        ScopeAttenuation::empty(),
        1_200,
        [12; 16],
    )
    .unwrap();

    assert_eq!(receipt.parent_chain.len(), 1);
    assert_eq!(
        receipt.aggregate_family_preservation(),
        Some(&fixture.evidence())
    );
    receipt
        .verify_aggregate_family_preservation(&fixture.verified_root)
        .unwrap();
}

#[test]
fn aggregate_invocation_attenuation_verified_delegate_rejects_wrong_parent_link_evidence() {
    let fixture = FamilyFixture::new("wrong-parent-evidence-root", 7);
    let wrong_evidence = AggregateFamilyPreservationEvidence {
        root_binding_digest: "wrong-parent-digest".to_string(),
        max_invocations: 7,
    };
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "wrong-evidence-intermediate".to_string(),
            issuer: fixture.root_subject.public_key(),
            subject: fixture.child_subject.public_key(),
            scope: family_root_scope(),
            issued_at: 1_100,
            expires_at: 1_900,
            delegation_chain: vec![fixture.link(Some(wrong_evidence))],
            aggregate_invocation_budget: Some(fixture.family_budget()),
        },
        &fixture.root_subject,
    )
    .unwrap();
    let grandchild = Keypair::from_seed(&[45; 32]);

    let error = delegate_with_aggregate_family_authority(
        &parent,
        &fixture.verified_root,
        &fixture.child_scope(),
        &fixture.child_subject,
        &grandchild.public_key(),
        ScopeAttenuation::empty(),
        1_200,
        [13; 16],
    )
    .unwrap_err();

    assert_attenuation_reason(
        error,
        "aggregate family preservation digest does not match the root binding",
    );
}

#[test]
fn aggregate_invocation_attenuation_verified_delegate_uses_canonical_binding_identity() {
    let fixture = FamilyFixture::new("canonical-binding-root", 7);
    let mut parent = fixture.root_token.clone();
    parent
        .aggregate_invocation_budget
        .as_mut()
        .unwrap()
        .root_binding
        .as_mut()
        .unwrap()
        .algorithm = Some(SigningAlgorithm::Ed25519);
    assert!(parent.verify_signature().unwrap());

    let receipt = delegate_with_aggregate_family_authority(
        &parent,
        &fixture.verified_root,
        &fixture.child_scope(),
        &fixture.root_subject,
        &fixture.child_subject.public_key(),
        ScopeAttenuation::empty(),
        1_100,
        [14; 16],
    )
    .unwrap();

    receipt
        .verify_aggregate_family_preservation(&fixture.verified_root)
        .unwrap();
}

#[test]
fn aggregate_invocation_attenuation_verified_delegate_rejects_unrelated_authority() {
    let fixture = FamilyFixture::new("delegate-authority-root", 7);
    let unrelated = FamilyFixture::new("unrelated-authority-root", 7);

    let error = delegate_with_aggregate_family_authority(
        &fixture.root_token,
        &unrelated.verified_root,
        &fixture.child_scope(),
        &fixture.root_subject,
        &fixture.child_subject.public_key(),
        ScopeAttenuation::empty(),
        1_100,
        [9; 16],
    )
    .unwrap_err();

    assert_attenuation_reason(
        error,
        "verified aggregate family authority does not match the parent root binding",
    );
}

#[test]
fn aggregate_invocation_attenuation_receipt_rejects_unrelated_signed_lineage() {
    let fixture = FamilyFixture::new("receipt-lineage-root", 7);
    let attacker = Keypair::from_seed(&[61; 32]);
    let attacker_delegatee = Keypair::from_seed(&[62; 32]);
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: fixture.root_token.id.clone(),
            delegator: attacker.public_key(),
            delegatee: attacker_delegatee.public_key(),
            attenuations: Vec::new(),
            timestamp: 1_100,
            scope_hash: Some(scope_hash(&fixture.root_token.scope).unwrap()),
            aggregate_family_preservation: Some(fixture.evidence()),
        },
        &attacker,
    )
    .unwrap();
    let receipt = DelegationReceipt {
        parent_chain: Vec::new(),
        attenuation: ScopeAttenuation::empty(),
        signed_at: 1_100,
        nonce: [15; 16],
        link,
        parent_capability_id: fixture.root_token.id.clone(),
    };

    let error = receipt
        .verify_aggregate_family_preservation(&fixture.verified_root)
        .unwrap_err();

    assert_attenuation_reason(
        error,
        "delegation receipt root delegator does not match aggregate family root subject",
    );
}

#[test]
fn aggregate_invocation_attenuation_receipt_evidence_is_covered_by_link_signature() {
    let fixture = FamilyFixture::new("receipt-signature-root", 7);
    let mut receipt = delegate_with_aggregate_family_authority(
        &fixture.root_token,
        &fixture.verified_root,
        &fixture.child_scope(),
        &fixture.root_subject,
        &fixture.child_subject.public_key(),
        ScopeAttenuation::empty(),
        1_100,
        [10; 16],
    )
    .unwrap();
    receipt
        .link
        .aggregate_family_preservation
        .as_mut()
        .unwrap()
        .max_invocations = 8;

    assert!(!receipt.link.verify_signature().unwrap());
    assert!(matches!(
        receipt.verify_aggregate_family_preservation(&fixture.verified_root),
        Err(Error::SignatureVerificationFailed)
    ));
}
