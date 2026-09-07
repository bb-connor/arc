#[cfg(feature = "delegation")]
use super::attenuation::delegate;
use super::attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof};
use super::caveat::{
    CapabilitySecurityBinding, Caveat, CaveatKind, CAPABILITY_SECURITY_BINDING_SCHEMA,
};
use super::scope::{ChioScope, Operation, ToolGrant};
use super::token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody};
use crate::crypto::Keypair;
use crate::error::Error;

fn security_binding(issuer: &Keypair) -> CapabilitySecurityBinding {
    CapabilitySecurityBinding {
        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
        tenant_id: "tenant-1".to_string(),
        lineage_id: "lineage-1".to_string(),
        session_id: "session-1".to_string(),
        principal_id: "agent-1".to_string(),
        isolation_epoch_id: "epoch-1".to_string(),
        context_generation: 7,
        workload_id: "workload-1".to_string(),
        server_id: "server-1".to_string(),
        workload_signer_public_key: issuer.public_key().to_hex(),
    }
}

fn direct_body(issuer: &Keypair, subject: &Keypair) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap-security-bound".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]),
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    }
}

#[test]
fn security_binding_is_canonical_signed_and_strict() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let binding = security_binding(&issuer);
    let token = CapabilityToken::sign_with_security_binding(
        direct_body(&issuer, &subject),
        binding.clone(),
        &issuer,
    )
    .unwrap();

    assert!(token.verify_signature().unwrap());
    assert_eq!(token.security_binding().unwrap(), Some(binding));
    assert_eq!(token.caveats.len(), 1);
    assert_eq!(token.caveats[0].kind, CaveatKind::BindSecurityContext);

    let mut noncanonical = token.clone();
    noncanonical.caveats[0].predicate = format!(" {}", noncanonical.caveats[0].predicate);
    assert!(noncanonical.validate_schema().is_err());

    let mut detached = token.clone();
    detached.caveats[0].sig = Some(token.signature.clone());
    assert!(detached.validate_schema().is_err());

    let mut unknown = serde_json::to_value(token.security_binding().unwrap().unwrap()).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    let mut unknown_token = token;
    unknown_token.caveats[0].predicate =
        String::from_utf8(crate::canonical_json_bytes(&unknown).unwrap()).unwrap();
    assert!(unknown_token.validate_schema().is_err());
}

#[test]
fn security_binding_mutation_invalidates_capability_signature() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = CapabilityToken::sign_with_security_binding(
        direct_body(&issuer, &subject),
        security_binding(&issuer),
        &issuer,
    )
    .unwrap();
    let mut mutated = token.clone();
    let mut binding = mutated.security_binding().unwrap().unwrap();
    binding.context_generation += 1;
    mutated.caveats = vec![Caveat::bind_security_context(&binding).unwrap()];
    assert!(!mutated.verify_signature().unwrap());

    let plain = CapabilityToken::sign(direct_body(&issuer, &subject), &issuer).unwrap();
    assert!(plain.verify_signature().unwrap());
    assert_eq!(plain.security_binding().unwrap(), None);
}

fn make_grant(server: &str, tool: &str, ops: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: ops,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

#[test]
fn capability_caveats_reject_fail_closed_until_admission_enforces_them() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent).unwrap(),
        child_scope_hash: scope_hash(&child).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(&parent, &child).unwrap(),
    };
    let body = CapabilityTokenBody {
        id: "cap-caveated".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child,
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let caveat = Caveat {
        kind: CaveatKind::RestrictAudience,
        predicate: "session:abc".to_string(),
        sig: None,
    };

    let err = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: body.clone(),
            caveats: vec![caveat.clone()],
            scope_attenuations: vec![],
            attenuation_proof: proof.clone(),
            budget_share_bps: None,
        },
        &issuer,
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
    assert!(err.to_string().contains("caveats are not enforced"));

    let mut token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .unwrap();
    token.caveats = vec![caveat];
    assert!(token.verify_signature().is_err());
}

#[cfg(feature = "delegation")]
fn delegate_parent_token(
    parent_kp: &Keypair,
    subject_kp: &Keypair,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-parent".to_string(),
        issuer: parent_kp.public_key(),
        subject: subject_kp.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, parent_kp).unwrap()
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_child_grant_without_delegate_on_covering_parent_grant() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![
        make_grant("srv-a", "tool-x", vec![Operation::Invoke]),
        make_grant("srv-b", "delegator-only", vec![Operation::Delegate]),
    ]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
    assert!(err
        .to_string()
        .contains("not covered by a parent grant that authorizes delegation"));
}
