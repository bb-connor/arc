//! A weak (small-order) Ed25519 key never authenticates a capability
//! artifact. The identity point as public key and the signature
//! `(R = identity, s = 0)` satisfy the cofactorless Ed25519 equation for
//! every message, so each verifier below must refuse it.

use chio_core_types::capability::attenuation::DelegationLink;
use chio_core_types::capability::crypto_floor::CapabilityCryptoFloor;
use chio_core_types::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::{Error, Keypair, PublicKey, Result, Signature, TrustedPublicKey};

const IDENTITY_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const UNIVERSAL_SIGNATURE: &str =
    "0100000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000";

fn weak_key() -> Result<PublicKey> {
    PublicKey::from_hex(IDENTITY_KEY)
}

fn universal_signature() -> Result<Signature> {
    Signature::from_hex(UNIVERSAL_SIGNATURE)
}

fn token_body(issuer: PublicKey) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap-weak-issuer".to_string(),
        issuer,
        subject: Keypair::from_seed(&[2; 32]).public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "shell_exec".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        issued_at: 1_000,
        expires_at: 2_000,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

#[test]
fn weak_key_is_refused_as_trusted_verifier() -> Result<()> {
    assert!(matches!(
        TrustedPublicKey::new(weak_key()?),
        Err(Error::InvalidPublicKey(_))
    ));
    Ok(())
}

#[test]
fn capability_token_from_weak_issuer_does_not_verify() -> Result<()> {
    let issuer = Keypair::from_seed(&[1; 32]);
    let honest = CapabilityToken::sign(token_body(issuer.public_key()), &issuer)?;
    assert!(honest.verify_signature()?);

    let mut forged = honest;
    forged.issuer = weak_key()?;
    forged.signature = universal_signature()?;
    assert!(!forged.verify_signature()?);
    assert!(matches!(
        forged.verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical),
        Ok(false)
    ));
    Ok(())
}

#[test]
fn delegation_link_from_weak_delegator_does_not_verify() -> Result<()> {
    let delegator = Keypair::from_seed(&[3; 32]);
    let mut link = DelegationLink {
        capability_id: "cap-parent".to_string(),
        delegator: delegator.public_key(),
        delegatee: Keypair::from_seed(&[4; 32]).public_key(),
        attenuations: Vec::new(),
        timestamp: 1_500,
        scope_hash: None,
        aggregate_budget: None,
        cumulative_approval: None,
        signature: universal_signature()?,
    };
    link.signature = delegator.sign_canonical(&link.body())?.0;
    assert!(link.verify_signature()?);

    link.delegator = weak_key()?;
    link.signature = universal_signature()?;
    assert!(!link.verify_signature()?);
    Ok(())
}

#[test]
fn governed_approval_token_from_weak_approver_does_not_verify() -> Result<()> {
    let approver = Keypair::from_seed(&[5; 32]);
    let honest = GovernedApprovalToken::sign(
        chio_core_types::capability::governance::GovernedApprovalTokenBody {
            id: "approval-1".to_string(),
            approver: approver.public_key(),
            subject: Keypair::from_seed(&[6; 32]).public_key(),
            governed_intent_hash: "intent-hash".to_string(),
            request_id: "request-1".to_string(),
            threshold_proposal_hash: None,
            issued_at: 1_000,
            expires_at: 2_000,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )?;
    assert!(honest.verify_signature()?);

    let mut forged = honest;
    forged.approver = weak_key()?;
    forged.signature = universal_signature()?;
    assert!(!forged.verify_signature()?);
    Ok(())
}
