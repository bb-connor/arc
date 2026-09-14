use chio_core_types::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    crypto_floor::CapabilityCryptoFloor,
    features::CapabilityNegotiation,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_kernel_core::{
    verify_capability_full_with_evidence, CapabilityEvidenceContext, CapabilityFeatureContext,
    FixedClock, NoopBudgetRegistry,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn scope(tools: &[&str]) -> ChioScope {
    ChioScope {
        grants: tools
            .iter()
            .map(|tool| ToolGrant {
                server_id: "server".into(),
                tool_name: (*tool).into(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            })
            .collect(),
        ..Default::default()
    }
}

fn issue_child(
    parent: &CapabilityToken,
    signer: &Keypair,
    issuer: &Keypair,
    subject: &PublicKey,
    id: &str,
    scope: ChioScope,
    proof: bool,
) -> Result<CapabilityToken> {
    let mut chain = parent.delegation_chain.clone();
    chain.push(DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent.id.clone(),
            delegator: signer.public_key(),
            delegatee: subject.clone(),
            attenuations: Vec::new(),
            timestamp: 110,
            scope_hash: Some(scope_hash(&parent.scope)?),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        signer,
    )?);
    let body = CapabilityTokenBody {
        id: id.into(),
        issuer: issuer.public_key(),
        subject: subject.clone(),
        scope: scope.clone(),
        issued_at: 110,
        expires_at: 250,
        delegation_chain: chain,
        aggregate_invocation_budget: None,
    };
    if !proof {
        return Ok(CapabilityToken::sign(body, issuer)?);
    }
    Ok(CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            budget_share_bps: Some(1000),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent.scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &scope)?,
            },
        },
        issuer,
    )?)
}

struct Fixture {
    issuer: Keypair,
    root_key: Keypair,
    child_key: Keypair,
    root: CapabilityToken,
    child: CapabilityToken,
    leaf: CapabilityToken,
}

fn fixture() -> Result<Fixture> {
    let issuer = Keypair::generate();
    let root_key = Keypair::generate();
    let child_key = Keypair::generate();
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "root".into(),
            issuer: issuer.public_key(),
            subject: root_key.public_key(),
            scope: scope(&["read", "write"]),
            issued_at: 100,
            expires_at: 300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let child = issue_child(
        &root,
        &root_key,
        &issuer,
        &child_key.public_key(),
        "child",
        scope(&["read"]),
        true,
    )?;
    let mut leaf_scope = scope(&["read"]);
    leaf_scope.grants[0].max_invocations = Some(1);
    let leaf = issue_child(
        &child,
        &child_key,
        &issuer,
        &Keypair::generate().public_key(),
        "leaf",
        leaf_scope,
        true,
    )?;
    Ok(Fixture {
        issuer,
        root_key,
        child_key,
        root,
        child,
        leaf,
    })
}

fn accepted(
    f: &Fixture,
    ancestors: &[CapabilityToken],
    leaf: &CapabilityToken,
    peer: &CapabilityNegotiation,
) -> Result<bool> {
    let root_hash = scope_hash(&f.root.scope)?;
    let resolver = |_: &PublicKey| Some(root_hash.clone());
    Ok(verify_capability_full_with_evidence(
        leaf,
        &[f.issuer.public_key()],
        &FixedClock::new(150),
        CapabilityCryptoFloor::AllowClassical,
        CapabilityEvidenceContext {
            features: CapabilityFeatureContext {
                peer,
                direct_root: None,
            },
            ancestors,
        },
        &resolver,
        &mut NoopBudgetRegistry,
    )
    .is_ok())
}

fn lineage_refusal(
    f: &Fixture,
    ancestors: &[CapabilityToken],
    leaf: &CapabilityToken,
    direct_root: Option<&CapabilityToken>,
) -> Result<String> {
    let root_hash = scope_hash(&f.root.scope)?;
    let resolver = |_: &PublicKey| Some(root_hash.clone());
    let peer = CapabilityNegotiation::v1_default();
    let result = verify_capability_full_with_evidence(
        leaf,
        &[f.issuer.public_key()],
        &FixedClock::new(150),
        CapabilityCryptoFloor::AllowClassical,
        CapabilityEvidenceContext {
            features: CapabilityFeatureContext {
                peer: &peer,
                direct_root,
            },
            ancestors,
        },
        &resolver,
        &mut NoopBudgetRegistry,
    );
    match result {
        Err(chio_kernel_core::CapabilityError::AttenuationViolation(reason)) => Ok(reason),
        other => Err(format!("expected owning lineage refusal, got {other:?}").into()),
    }
}

#[test]
fn signed_lineage_refuses_missing_delegate_for_each_grant_family() -> Result {
    use chio_core_types::capability::scope::{PromptGrant, ResourceGrant};
    for family in ["tool", "resource", "prompt"] {
        let mut f = fixture()?;
        let mut root_scope = ChioScope::default();
        match family {
            "tool" => {
                root_scope = scope(&["read"]);
                root_scope.grants[0].operations = vec![Operation::Invoke];
            }
            "resource" => root_scope.resource_grants.push(ResourceGrant {
                uri_pattern: "data:*".into(),
                operations: vec![Operation::Read],
            }),
            _ => root_scope.prompt_grants.push(PromptGrant {
                prompt_name: "prompt".into(),
                operations: vec![Operation::Get],
            }),
        }
        let mut root_body = f.root.body();
        root_body.scope = root_scope.clone();
        f.root = CapabilityToken::sign(root_body, &f.issuer)?;
        f.child = issue_child(
            &f.root,
            &f.root_key,
            &f.issuer,
            &f.child_key.public_key(),
            "child",
            root_scope.clone(),
            true,
        )?;
        f.leaf = issue_child(
            &f.child,
            &f.child_key,
            &f.issuer,
            &f.leaf.subject,
            "leaf",
            root_scope,
            true,
        )?;
        let error = lineage_refusal(&f, &[f.root.clone(), f.child.clone()], &f.leaf, None)?;
        assert!(
            error.contains("signed parent does not grant delegation for the child scope"),
            "{family}: {error}"
        );
    }
    Ok(())
}

#[test]
fn signed_lineage_refuses_invalid_link_times_at_the_validity_boundary() -> Result {
    for timestamp in [99, 111, 300] {
        let f = fixture()?;
        let mut child = f.child.clone();
        let mut leaf = f.leaf.clone();
        let index = usize::from(timestamp != 99);
        let mut body = leaf.delegation_chain[index].body();
        body.timestamp = timestamp;
        leaf.delegation_chain[index] = DelegationLink::sign(
            body,
            if index == 0 {
                &f.root_key
            } else {
                &f.child_key
            },
        )?;
        if index == 0 {
            child.delegation_chain[0] = leaf.delegation_chain[0].clone();
            child.signature = f.issuer.sign_canonical(&child.signing_body())?.0;
        }
        leaf.signature = f.issuer.sign_canonical(&leaf.signing_body())?.0;
        let error = lineage_refusal(&f, &[f.root.clone(), child], &leaf, None)?;
        assert!(
            error.contains("delegated validity or budget share widens its signed parent"),
            "{timestamp}: {error}"
        );
    }
    Ok(())
}

#[test]
fn signed_lineage_refuses_repeated_identity_and_mismatched_negotiated_root() -> Result {
    let f = fixture()?;
    let mut repeated = f.leaf.clone();
    repeated.id = f.child.id.clone();
    repeated.signature = f.issuer.sign_canonical(&repeated.signing_body())?.0;
    let error = lineage_refusal(&f, &[f.root.clone(), f.child.clone()], &repeated, None)?;
    assert!(
        error.contains("signed lineage repeats a capability identity"),
        "{error}"
    );
    let mut another_body = f.root.body();
    another_body.id = "other-root".into();
    let other_root = CapabilityToken::sign(another_body, &f.issuer)?;
    let error = lineage_refusal(
        &f,
        &[f.root.clone(), f.child.clone()],
        &f.leaf,
        Some(&other_root),
    )?;
    assert!(
        error.contains("signed lineage differs from the negotiated family root"),
        "{error}"
    );
    Ok(())
}

#[test]
fn recursive_narrowing_requires_complete_signed_evidence() -> Result {
    let f = fixture()?;
    let peer = CapabilityNegotiation::v1_default();
    assert!(accepted(
        &f,
        &[f.root.clone(), f.child.clone()],
        &f.leaf,
        &peer
    )?);
    assert!(!accepted(&f, &[], &f.leaf, &peer)?);
    assert!(!accepted(
        &f,
        std::slice::from_ref(&f.root),
        &f.leaf,
        &peer
    )?);
    assert!(!accepted(
        &f,
        &[f.child.clone(), f.root.clone()],
        &f.leaf,
        &peer
    )?);
    Ok(())
}

#[test]
fn tampered_signed_ancestors_and_disabled_binding_are_rejected() -> Result {
    let f = fixture()?;
    let mut peer = CapabilityNegotiation::v1_default();
    let mut bad = f.child.clone();
    bad.scope = scope(&["read", "write"]);
    assert!(!accepted(&f, &[f.root.clone(), bad], &f.leaf, &peer)?);
    let mut bad_root = f.root.body();
    bad_root.expires_at = 140;
    let expired = CapabilityToken::sign(bad_root, &f.issuer)?;
    assert!(!accepted(&f, &[expired, f.child.clone()], &f.leaf, &peer)?);
    peer.features
        .insert("delegation_chain_binding".into(), false);
    assert!(!accepted(
        &f,
        &[f.root.clone(), f.child.clone()],
        &f.leaf,
        &peer
    )?);
    Ok(())
}

#[test]
fn correctly_signed_hidden_widening_is_rejected() -> Result {
    let f = fixture()?;
    let peer = CapabilityNegotiation::v1_default();
    // All signatures and link hashes are internally consistent. The middle
    // token secretly grants an extra tool that the root never held.
    let widened = issue_child(
        &f.root,
        &f.root_key,
        &f.issuer,
        &f.child_key.public_key(),
        "child",
        scope(&["read", "write", "delete"]),
        false,
    )?;
    let leaf = issue_child(
        &widened,
        &f.child_key,
        &f.issuer,
        &f.leaf.subject,
        "leaf",
        scope(&["read"]),
        true,
    )?;
    assert!(!accepted(&f, &[f.root.clone(), widened], &leaf, &peer)?);
    Ok(())
}

#[test]
fn signed_ancestor_from_another_prefix_is_rejected() -> Result {
    let f = fixture()?;
    let peer = CapabilityNegotiation::v1_default();
    let mut body = f.root.body();
    body.id = "another-root".into();
    let another = CapabilityToken::sign(body, &f.issuer)?;
    let child = issue_child(
        &another,
        &f.root_key,
        &f.issuer,
        &f.child_key.public_key(),
        "child",
        scope(&["read"]),
        true,
    )?;
    assert!(!accepted(&f, &[f.root.clone(), child], &f.leaf, &peer)?);
    Ok(())
}

#[test]
fn a_signed_leaf_cannot_extend_its_parents_validity_or_budget_share() -> Result {
    let f = fixture()?;
    let peer = CapabilityNegotiation::v1_default();
    let mut late = f.leaf.clone();
    late.expires_at = 260;
    late.signature = f.issuer.sign_canonical(&late.signing_body())?.0;
    assert!(!accepted(
        &f,
        &[f.root.clone(), f.child.clone()],
        &late,
        &peer
    )?);
    let mut oversized = f.leaf.clone();
    oversized.budget_share_bps = Some(1001);
    oversized.signature = f.issuer.sign_canonical(&oversized.signing_body())?.0;
    assert!(!accepted(
        &f,
        &[f.root.clone(), f.child.clone()],
        &oversized,
        &peer
    )?);
    Ok(())
}
