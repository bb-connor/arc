use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use crate::capability::aggregate_budget::{
    issue_aggregate_family_root, verify_aggregate_invocation_authority,
    verify_direct_aggregate_family_root, AggregateFamilyRootResolution,
    AggregateFamilyRootResolutionError, AggregateFamilyRootResolver,
    AggregateInvocationAuthorityError, AggregateInvocationBudget, AggregateInvocationScope,
    LegacyUnboundAggregateRoot,
};
use crate::capability::attenuation::{scope_hash, DelegationLink, DelegationLinkBody, ScopeHash};
use crate::capability::scope::{ChioScope, Operation, ToolGrant};
use crate::capability::token::{CapabilityToken, CapabilityTokenBody};
use crate::crypto::{Keypair, PublicKey};
use crate::error::Error;

struct FamilyFixture {
    root_issuer: Keypair,
    root_subject: Keypair,
    child_subject: Keypair,
    root_token: CapabilityToken,
    verified_root: super::aggregate_budget::VerifiedAggregateFamilyRoot,
}

impl FamilyFixture {
    fn new(root_id: &str, max_invocations: u32) -> Self {
        let root_issuer = Keypair::generate();
        let root_subject = Keypair::generate();
        let child_subject = Keypair::generate();
        let mut root_body = ordinary_body(
            root_id,
            root_issuer.public_key(),
            root_subject.public_key(),
            Vec::new(),
            None,
            2_000,
        );
        root_body.scope = family_root_scope();
        let root_token = issue_aggregate_family_root(root_body, max_invocations, &root_issuer)
            .expect("issue family root");
        let verified_root =
            verify_direct_aggregate_family_root(&root_token, &[root_issuer.public_key()])
                .expect("verify family root");
        Self {
            root_issuer,
            root_subject,
            child_subject,
            root_token,
            verified_root,
        }
    }

    fn family_budget(&self) -> AggregateInvocationBudget {
        self.root_token
            .aggregate_invocation_budget
            .clone()
            .expect("family budget")
    }

    fn root_scope_hash(&self) -> ScopeHash {
        scope_hash(&self.root_token.scope).expect("root scope hash")
    }

    fn legacy_record(&self) -> LegacyUnboundAggregateRoot {
        LegacyUnboundAggregateRoot::new(
            self.root_token.id.clone(),
            self.root_subject.public_key(),
            self.root_scope_hash(),
            self.root_token.expires_at,
        )
    }

    fn one_hop_descendant(&self, id: &str) -> CapabilityToken {
        let link = signed_link(
            &self.root_token.id,
            &self.root_subject,
            self.child_subject.public_key(),
            Some(self.root_scope_hash()),
            1_100,
        );
        sign_leaf(
            id,
            &self.root_subject,
            self.child_subject.public_key(),
            vec![link],
            Some(self.family_budget()),
            1_900,
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

#[derive(Clone)]
enum ResolverOutcome {
    Resolved(Box<AggregateFamilyRootResolution>),
    Error(AggregateFamilyRootResolutionError),
}

impl ResolverOutcome {
    fn resolved(resolution: AggregateFamilyRootResolution) -> Self {
        Self::Resolved(Box::new(resolution))
    }
}

struct CountingResolver {
    expected_root_id: String,
    outcome: ResolverOutcome,
    calls: Cell<usize>,
}

impl CountingResolver {
    fn new(expected_root_id: &str, outcome: ResolverOutcome) -> Self {
        Self {
            expected_root_id: expected_root_id.to_string(),
            outcome,
            calls: Cell::new(0),
        }
    }

    fn family(fixture: &FamilyFixture) -> Self {
        Self::new(
            &fixture.root_token.id,
            ResolverOutcome::resolved(AggregateFamilyRootResolution::FamilyBound(
                fixture.verified_root.clone(),
            )),
        )
    }

    fn legacy(fixture: &FamilyFixture) -> Self {
        Self::new(
            &fixture.root_token.id,
            ResolverOutcome::resolved(AggregateFamilyRootResolution::LegacyUnbound(
                fixture.legacy_record(),
            )),
        )
    }

    fn calls(&self) -> usize {
        self.calls.get()
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
            ResolverOutcome::Resolved(root) => Ok(root.as_ref().clone()),
            ResolverOutcome::Error(error) => Err(error.clone()),
        }
    }
}

fn ordinary_body(
    id: &str,
    issuer: PublicKey,
    subject: PublicKey,
    delegation_chain: Vec<DelegationLink>,
    aggregate_invocation_budget: Option<AggregateInvocationBudget>,
    expires_at: u64,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: id.to_string(),
        issuer,
        subject,
        scope: ChioScope::default(),
        issued_at: 1_000,
        expires_at,
        delegation_chain,
        aggregate_invocation_budget,
    }
}

fn signed_link(
    capability_id: &str,
    signer: &Keypair,
    delegatee: PublicKey,
    scope_hash: Option<ScopeHash>,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: signer.public_key(),
            delegatee,
            attenuations: Vec::new(),
            timestamp,
            scope_hash,
            aggregate_family_preservation: None,
        },
        signer,
    )
    .expect("sign delegation link")
}

fn sign_leaf(
    id: &str,
    signer: &Keypair,
    subject: PublicKey,
    chain: Vec<DelegationLink>,
    budget: Option<AggregateInvocationBudget>,
    expires_at: u64,
) -> CapabilityToken {
    CapabilityToken::sign(
        ordinary_body(id, signer.public_key(), subject, chain, budget, expires_at),
        signer,
    )
    .expect("sign leaf")
}

fn capability_budget(max_invocations: u32) -> AggregateInvocationBudget {
    AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations,
        root_binding: None,
    }
}

fn assert_authority_reason(error: AggregateInvocationAuthorityError, expected: &str) {
    match error {
        AggregateInvocationAuthorityError::Verification(Error::AttenuationViolation { reason })
        | AggregateInvocationAuthorityError::Verification(Error::DelegationChainBroken {
            reason,
        }) => assert_eq!(reason, expected),
        other => panic!("expected authority rejection, got {other:?}"),
    }
}

fn assert_resolution_error(
    error: AggregateInvocationAuthorityError,
    expected: AggregateFamilyRootResolutionError,
) {
    match error {
        AggregateInvocationAuthorityError::RootResolution(actual) => assert_eq!(actual, expected),
        other => panic!("expected root resolution error, got {other:?}"),
    }
}

#[test]
fn delegation_family_direct_root_and_descendants_share_owner_digest_and_maximum() {
    let fixture = FamilyFixture::new("family-root", 7);
    let direct_resolver = CountingResolver::family(&fixture);
    let direct = verify_aggregate_invocation_authority(
        &fixture.root_token,
        &[fixture.root_issuer.public_key()],
        &[],
        &direct_resolver,
    )
    .expect("verify direct root")
    .expect("direct aggregate authority");
    assert_eq!(direct_resolver.calls(), 0);

    let descendant_token = fixture.one_hop_descendant("family-child");
    let descendant_resolver = CountingResolver::family(&fixture);
    let descendant = verify_aggregate_invocation_authority(
        &descendant_token,
        &[],
        &[fixture.root_subject.public_key()],
        &descendant_resolver,
    )
    .expect("verify descendant")
    .expect("descendant aggregate authority");

    assert_eq!(descendant_resolver.calls(), 1);
    assert_eq!(direct.scope(), AggregateInvocationScope::DelegationFamily);
    assert_eq!(
        descendant.scope(),
        AggregateInvocationScope::DelegationFamily
    );
    assert_eq!(direct.owner(), descendant.owner());
    assert_eq!(
        direct.root_binding_digest(),
        descendant.root_binding_digest()
    );
    assert_eq!(direct.max_invocations(), descendant.max_invocations());
    assert_eq!(descendant.max_invocations(), 7);
}

#[test]
fn delegation_family_direct_root_rejects_descendant_leaf_only_trusted_issuer() {
    let attacker = FamilyFixture::new("leaf-only-self-issued-root", 3);
    let descendant_leaf_issuers = [attacker.root_issuer.public_key()];
    let resolver = CountingResolver::family(&attacker);

    let error = verify_aggregate_invocation_authority(
        &attacker.root_token,
        &[],
        &descendant_leaf_issuers,
        &resolver,
    )
    .expect_err("leaf-only trust must not authorize an empty-chain root");

    match error {
        AggregateInvocationAuthorityError::Verification(Error::InvalidPublicKey(reason)) => {
            assert_eq!(
                reason,
                "aggregate direct capability issuer is not trusted as a root authority"
            );
        }
        other => panic!("expected direct-root trust rejection, got {other:?}"),
    }

    let accepted = verify_aggregate_invocation_authority(
        &attacker.root_token,
        &[attacker.root_issuer.public_key()],
        &[],
        &resolver,
    )
    .expect("independently trusted direct root must verify")
    .expect("direct family authority");
    assert_eq!(accepted.scope(), AggregateInvocationScope::DelegationFamily);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn delegation_family_descendant_rejects_direct_root_only_trusted_issuer() {
    let fixture = FamilyFixture::new("direct-root-only-descendant", 3);
    let descendant = fixture.one_hop_descendant("direct-root-only-child");
    let direct_root_issuers = [fixture.root_subject.public_key()];
    let resolver = CountingResolver::family(&fixture);

    let error =
        verify_aggregate_invocation_authority(&descendant, &direct_root_issuers, &[], &resolver)
            .expect_err("direct-root-only trust must not authorize a descendant");

    match error {
        AggregateInvocationAuthorityError::Verification(Error::InvalidPublicKey(reason)) => {
            assert_eq!(
                reason,
                "aggregate descendant capability issuer is not trusted as a leaf authority"
            );
        }
        other => panic!("expected descendant-leaf trust rejection, got {other:?}"),
    }

    assert_eq!(resolver.calls(), 0);
}

#[test]
fn delegation_family_multi_hop_descendant_is_accepted() {
    let fixture = FamilyFixture::new("family-root-multi-hop", 5);
    let intermediate = Keypair::generate();
    let leaf_subject = Keypair::generate();
    let first = signed_link(
        &fixture.root_token.id,
        &fixture.root_subject,
        intermediate.public_key(),
        Some(fixture.root_scope_hash()),
        1_100,
    );
    let second = signed_link(
        "intermediate-capability",
        &intermediate,
        leaf_subject.public_key(),
        Some(fixture.root_scope_hash()),
        1_200,
    );
    let leaf = sign_leaf(
        "family-grandchild",
        &intermediate,
        leaf_subject.public_key(),
        vec![first, second],
        Some(fixture.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::family(&fixture);

    let authority =
        verify_aggregate_invocation_authority(&leaf, &[], &[intermediate.public_key()], &resolver)
            .expect("verify multi-hop")
            .expect("family authority");

    assert_eq!(resolver.calls(), 1);
    assert_eq!(authority.owner(), fixture.verified_root.family_owner());
}

#[test]
fn delegation_family_direct_capability_aggregate_and_no_aggregate_remain_supported() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let resolver = CountingResolver::new(
        "unused",
        ResolverOutcome::Error(AggregateFamilyRootResolutionError::Missing),
    );
    let capability = CapabilityToken::sign(
        ordinary_body(
            "direct-capability-aggregate",
            issuer.public_key(),
            subject.public_key(),
            Vec::new(),
            Some(capability_budget(3)),
            2_000,
        ),
        &issuer,
    )
    .expect("sign direct capability aggregate");
    let authority =
        verify_aggregate_invocation_authority(&capability, &[issuer.public_key()], &[], &resolver)
            .expect("verify capability aggregate")
            .expect("capability authority");
    assert_eq!(authority.scope(), AggregateInvocationScope::Capability);
    assert_eq!(authority.owner(), capability.id);
    assert_eq!(authority.max_invocations(), 3);
    assert_eq!(authority.root_binding_digest(), None);

    let plain = CapabilityToken::sign(
        ordinary_body(
            "direct-no-aggregate",
            issuer.public_key(),
            subject.public_key(),
            Vec::new(),
            None,
            2_000,
        ),
        &issuer,
    )
    .expect("sign direct plain token");
    assert!(
        verify_aggregate_invocation_authority(&plain, &[issuer.public_key()], &[], &resolver,)
            .expect("verify direct plain token")
            .is_none()
    );
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn delegation_family_trusted_unrelated_leaf_issuer_denies_before_resolution() {
    let fixture = FamilyFixture::new("family-root-unrelated-leaf", 4);
    let unrelated = Keypair::generate();
    let valid = fixture.one_hop_descendant("unrelated-leaf");
    let leaf = sign_leaf(
        "unrelated-leaf",
        &unrelated,
        fixture.child_subject.public_key(),
        valid.delegation_chain,
        Some(fixture.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::family(&fixture);

    let error =
        verify_aggregate_invocation_authority(&leaf, &[], &[unrelated.public_key()], &resolver)
            .unwrap_err();

    assert_authority_reason(
        error,
        "delegation chain final delegator does not match capability issuer",
    );
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn delegation_family_final_subject_mismatch_denies_before_resolution() {
    let fixture = FamilyFixture::new("family-root-subject-mismatch", 4);
    let wrong_subject = Keypair::generate();
    let valid = fixture.one_hop_descendant("subject-mismatch");
    let leaf = sign_leaf(
        "subject-mismatch",
        &fixture.root_subject,
        wrong_subject.public_key(),
        valid.delegation_chain,
        Some(fixture.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::family(&fixture);

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "delegation chain final delegatee does not match capability subject",
    );
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn delegation_family_missing_unavailable_and_corrupt_resolution_fail_closed() {
    let fixture = FamilyFixture::new("family-root-resolution-errors", 4);
    let leaf = fixture.one_hop_descendant("resolution-errors");

    for expected in [
        AggregateFamilyRootResolutionError::Missing,
        AggregateFamilyRootResolutionError::Unavailable("store offline".to_string()),
        AggregateFamilyRootResolutionError::Corrupt("bad root row".to_string()),
    ] {
        let resolver = CountingResolver::new(
            &fixture.root_token.id,
            ResolverOutcome::Error(expected.clone()),
        );
        let error = verify_aggregate_invocation_authority(
            &leaf,
            &[],
            &[fixture.root_subject.public_key()],
            &resolver,
        )
        .unwrap_err();
        assert_resolution_error(error, expected);
        assert_eq!(resolver.calls(), 1);
    }
}

#[test]
fn delegation_family_authenticated_legacy_accepts_none_and_capability_scope() {
    let fixture = FamilyFixture::new("legacy-root", 4);
    let family_leaf = fixture.one_hop_descendant("legacy-leaf");

    let no_aggregate = sign_leaf(
        "legacy-no-aggregate",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        family_leaf.delegation_chain.clone(),
        None,
        1_900,
    );
    let resolver = CountingResolver::legacy(&fixture);
    assert!(verify_aggregate_invocation_authority(
        &no_aggregate,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .expect("legacy no aggregate")
    .is_none());

    let capability = sign_leaf(
        "legacy-capability-aggregate",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        family_leaf.delegation_chain,
        Some(capability_budget(2)),
        1_900,
    );
    let authority = verify_aggregate_invocation_authority(
        &capability,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .expect("legacy capability aggregate")
    .expect("capability authority");
    assert_eq!(authority.scope(), AggregateInvocationScope::Capability);
    assert_eq!(authority.owner(), capability.id);
    assert_eq!(authority.max_invocations(), 2);
    assert_eq!(resolver.calls(), 2);
}

#[test]
fn delegation_family_authenticated_legacy_rejects_new_family_creation() {
    let fixture = FamilyFixture::new("legacy-no-family-creation", 4);
    let leaf = fixture.one_hop_descendant("legacy-family-attempt");
    let resolver = CountingResolver::legacy(&fixture);

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "legacy-unbound root cannot create a delegation-family aggregate budget",
    );
}

#[test]
fn delegation_family_bound_root_rejects_omission_and_capability_downgrade() {
    let fixture = FamilyFixture::new("bound-root-no-downgrade", 4);
    let family_leaf = fixture.one_hop_descendant("bound-leaf");
    let resolver = CountingResolver::family(&fixture);

    let omitted = sign_leaf(
        "bound-omitted",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        family_leaf.delegation_chain.clone(),
        None,
        1_900,
    );
    let omission_error = verify_aggregate_invocation_authority(
        &omitted,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();
    assert_authority_reason(
        omission_error,
        "family-bound descendant must preserve aggregate_invocation_budget",
    );

    let downgraded = sign_leaf(
        "bound-capability-downgrade",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        family_leaf.delegation_chain,
        Some(capability_budget(4)),
        1_900,
    );
    let downgrade_error = verify_aggregate_invocation_authority(
        &downgraded,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();
    assert_authority_reason(
        downgrade_error,
        "family-bound descendant cannot downgrade aggregate scope",
    );
}

#[test]
fn delegation_family_bound_root_rejects_maximum_lowering_and_raising() {
    let fixture = FamilyFixture::new("bound-root-max", 4);
    let valid = fixture.one_hop_descendant("bound-max-leaf");
    let resolver = CountingResolver::family(&fixture);

    for changed_maximum in [3, 5] {
        let mut budget = fixture.family_budget();
        budget.max_invocations = changed_maximum;
        let leaf = sign_leaf(
            "bound-max-mutation",
            &fixture.root_subject,
            fixture.child_subject.public_key(),
            valid.delegation_chain.clone(),
            Some(budget),
            1_900,
        );
        let error = verify_aggregate_invocation_authority(
            &leaf,
            &[],
            &[fixture.root_subject.public_key()],
            &resolver,
        )
        .unwrap_err();
        assert_authority_reason(
            error,
            "family-bound descendant changed the immutable aggregate maximum",
        );
    }
}

#[test]
fn delegation_family_bound_root_rejects_validly_resigned_binding_mutation() {
    let fixture = FamilyFixture::new("bound-root-binding", 4);
    let valid = fixture.one_hop_descendant("bound-binding-leaf");
    let mut budget = fixture.family_budget();
    let binding = budget.root_binding.as_mut().expect("root binding");
    binding.body.root_capability_hash = "ff".repeat(32);
    binding.signature = fixture
        .root_issuer
        .sign(&binding.body.signing_bytes().expect("binding bytes"));
    let leaf = sign_leaf(
        "bound-binding-mutation",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        valid.delegation_chain,
        Some(budget),
        1_900,
    );
    let resolver = CountingResolver::family(&fixture);

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "family-bound descendant changed the root binding envelope",
    );
}

#[test]
fn delegation_family_bound_root_rejects_unrelated_chain_graft() {
    let family = FamilyFixture::new("binding-family", 4);
    let unrelated = FamilyFixture::new("unrelated-family", 4);
    let unrelated_leaf = unrelated.one_hop_descendant("unrelated-chain");
    let grafted = sign_leaf(
        "unrelated-chain-graft",
        &unrelated.root_subject,
        unrelated.child_subject.public_key(),
        unrelated_leaf.delegation_chain,
        Some(family.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::family(&unrelated);

    let error = verify_aggregate_invocation_authority(
        &grafted,
        &[],
        &[unrelated.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "family-bound descendant changed the root binding envelope",
    );
}

#[test]
fn delegation_family_first_link_id_mismatch_is_corrupt_resolution() {
    let fixture = FamilyFixture::new("first-link-id-root", 4);
    let wrong_id = "wrong-first-link-id";
    let link = signed_link(
        wrong_id,
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        Some(fixture.root_scope_hash()),
        1_100,
    );
    let leaf = sign_leaf(
        "first-link-id-leaf",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        vec![link],
        Some(fixture.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::new(
        wrong_id,
        ResolverOutcome::resolved(AggregateFamilyRootResolution::FamilyBound(
            fixture.verified_root.clone(),
        )),
    );

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_resolution_error(
        error,
        AggregateFamilyRootResolutionError::Corrupt(
            "resolved root capability ID does not match lookup key".to_string(),
        ),
    );
}

#[test]
fn delegation_family_first_link_delegator_mismatch_is_rejected() {
    let fixture = FamilyFixture::new("first-link-delegator-root", 4);
    let unrelated_delegator = Keypair::generate();
    let link = signed_link(
        &fixture.root_token.id,
        &unrelated_delegator,
        fixture.child_subject.public_key(),
        Some(fixture.root_scope_hash()),
        1_100,
    );
    let leaf = sign_leaf(
        "first-link-delegator-leaf",
        &unrelated_delegator,
        fixture.child_subject.public_key(),
        vec![link],
        Some(fixture.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::family(&fixture);

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[unrelated_delegator.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "delegation chain first delegator does not match resolved root subject",
    );
}

#[test]
fn delegation_family_first_link_scope_hash_mismatch_is_rejected() {
    let fixture = FamilyFixture::new("first-link-scope-root", 4);
    let link = signed_link(
        &fixture.root_token.id,
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        Some("00".repeat(32)),
        1_100,
    );
    let leaf = sign_leaf(
        "first-link-scope-leaf",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        vec![link],
        Some(fixture.family_budget()),
        1_900,
    );
    let resolver = CountingResolver::family(&fixture);

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "delegation chain first scope hash does not match resolved root scope hash",
    );
}

#[test]
fn delegation_family_descendant_cannot_outlive_resolved_root() {
    let fixture = FamilyFixture::new("expiry-root", 4);
    let valid = fixture.one_hop_descendant("expiry-leaf");
    let leaf = sign_leaf(
        "expiry-extension",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        valid.delegation_chain,
        Some(fixture.family_budget()),
        fixture.root_token.expires_at + 1,
    );
    let resolver = CountingResolver::family(&fixture);

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_authority_reason(
        error,
        "descendant capability outlives resolved aggregate root",
    );
}

#[test]
fn delegation_family_resolver_root_record_id_mismatch_is_corrupt() {
    let fixture = FamilyFixture::new("record-key-root", 4);
    let wrong_record = FamilyFixture::new("wrong-record-root", 4);
    let leaf = fixture.one_hop_descendant("record-key-leaf");
    let resolver = CountingResolver::new(
        &fixture.root_token.id,
        ResolverOutcome::resolved(AggregateFamilyRootResolution::FamilyBound(
            wrong_record.verified_root,
        )),
    );

    let error = verify_aggregate_invocation_authority(
        &leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();

    assert_resolution_error(
        error,
        AggregateFamilyRootResolutionError::Corrupt(
            "resolved root capability ID does not match lookup key".to_string(),
        ),
    );
}

#[test]
fn delegation_family_legacy_record_still_binds_first_hop_and_expiry() {
    let fixture = FamilyFixture::new("legacy-binding-root", 4);
    let valid = fixture.one_hop_descendant("legacy-binding-leaf");
    let resolver = CountingResolver::legacy(&fixture);

    let wrong_delegator = Keypair::generate();
    let wrong_link = signed_link(
        &fixture.root_token.id,
        &wrong_delegator,
        fixture.child_subject.public_key(),
        Some(fixture.root_scope_hash()),
        1_100,
    );
    let wrong_leaf = sign_leaf(
        "legacy-wrong-delegator",
        &wrong_delegator,
        fixture.child_subject.public_key(),
        vec![wrong_link],
        None,
        1_900,
    );
    let delegator_error = verify_aggregate_invocation_authority(
        &wrong_leaf,
        &[],
        &[wrong_delegator.public_key()],
        &resolver,
    )
    .unwrap_err();
    assert_authority_reason(
        delegator_error,
        "delegation chain first delegator does not match resolved root subject",
    );

    let expired_leaf = sign_leaf(
        "legacy-expiry-extension",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        valid.delegation_chain,
        None,
        fixture.root_token.expires_at + 1,
    );
    let expiry_error = verify_aggregate_invocation_authority(
        &expired_leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();
    assert_authority_reason(
        expiry_error,
        "descendant capability outlives resolved aggregate root",
    );
}

#[test]
fn delegation_family_tampered_leaf_and_link_deny_before_resolution() {
    let fixture = FamilyFixture::new("tamper-root", 4);
    let mut tampered_leaf = fixture.one_hop_descendant("tampered-leaf");
    tampered_leaf.id = "tampered-after-signing".to_string();
    let resolver = CountingResolver::family(&fixture);
    let leaf_error = verify_aggregate_invocation_authority(
        &tampered_leaf,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();
    match leaf_error {
        AggregateInvocationAuthorityError::Verification(Error::InvalidSignature(_)) => {}
        other => panic!("expected invalid leaf signature, got {other:?}"),
    }
    assert_eq!(resolver.calls(), 0);

    let valid = fixture.one_hop_descendant("tampered-link");
    let mut chain = valid.delegation_chain;
    chain[0].capability_id = "tampered-link-id".to_string();
    let leaf_with_tampered_link = sign_leaf(
        "tampered-link",
        &fixture.root_subject,
        fixture.child_subject.public_key(),
        chain,
        Some(fixture.family_budget()),
        1_900,
    );
    let link_error = verify_aggregate_invocation_authority(
        &leaf_with_tampered_link,
        &[],
        &[fixture.root_subject.public_key()],
        &resolver,
    )
    .unwrap_err();
    assert_authority_reason(link_error, "signature invalid at link index 0");
    assert_eq!(resolver.calls(), 0);
}
