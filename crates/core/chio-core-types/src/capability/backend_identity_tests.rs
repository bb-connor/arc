//! Embedded capability issuers must survive a selector change during signing.
use super::aggregate_invocation::{
    AggregateBudgetRootBinding, AggregateBudgetRootBindingBody, AGGREGATE_BUDGET_ROOT_SCHEMA,
};
use super::attenuation::scope_hash;
use super::caveat::{CapabilitySecurityBinding, CAPABILITY_SECURITY_BINDING_SCHEMA};
use super::cumulative_approval::{
    CumulativeApprovalRootBinding, CumulativeApprovalRootBindingBody,
    CUMULATIVE_APPROVAL_ROOT_SCHEMA,
};
use super::scope::{ChioScope, MonetaryAmount};
use super::token::{CapabilityToken, CapabilityTokenBody};
use crate::crypto::{
    Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend, SigningOutcome,
};
use crate::error::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};

struct IdentityBackend {
    original: Ed25519Backend,
    replacement: Ed25519Backend,
    fault: u8,
    bound_calls: AtomicUsize,
}

impl IdentityBackend {
    fn new(fault: u8) -> Self {
        Self {
            original: Ed25519Backend::new(Keypair::from_seed(&[71; 32])),
            replacement: Ed25519Backend::new(Keypair::from_seed(&[72; 32])),
            fault,
            bound_calls: AtomicUsize::new(0),
        }
    }
}

impl SigningBackend for IdentityBackend {
    fn public_key(&self) -> PublicKey {
        self.original.public_key()
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.original.algorithm()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
        self.replacement.sign_bytes(message)
    }

    fn sign_bytes_with_identity(&self, message: &[u8]) -> Result<SigningOutcome> {
        self.replacement.sign_bytes_with_identity(message)
    }

    fn sign_bytes_for_identity(&self, key: &PublicKey, message: &[u8]) -> Result<SigningOutcome> {
        self.bound_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(key, &self.original.public_key());
        let mut outcome = self.original.sign_bytes_for_identity(key, message)?;
        match self.fault {
            0 => {}
            1 => outcome.public_key = self.replacement.public_key(),
            2 => outcome.algorithm = SigningAlgorithm::P256,
            3 => outcome.signature = self.replacement.sign_bytes(message)?,
            _ => return Err(Error::InvalidSignature("original signer retired".into())),
        }
        Ok(outcome)
    }
}

fn sign(artifact: u8, backend: &dyn SigningBackend) -> Result<(Vec<u8>, bool)> {
    let issuer = backend.public_key();
    let body = CapabilityTokenBody {
        id: "cap-atomic-identity".into(),
        issuer: issuer.clone(),
        subject: Keypair::from_seed(&[73; 32]).public_key(),
        scope: ChioScope::default(),
        issued_at: 10,
        expires_at: 100,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    match artifact {
        0 | 1 => {
            let token = if artifact == 0 {
                CapabilityToken::sign_with_backend(body, backend)?
            } else {
                CapabilityToken::sign_with_security_binding_backend(
                    body,
                    CapabilitySecurityBinding {
                        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.into(),
                        tenant_id: "tenant".into(),
                        lineage_id: "lineage".into(),
                        session_id: "session".into(),
                        principal_id: "principal".into(),
                        isolation_epoch_id: "epoch".into(),
                        context_generation: 1,
                        workload_id: "workload".into(),
                        server_id: "server".into(),
                        workload_signer_public_key: issuer.to_hex(),
                    },
                    backend,
                )?
            };
            Ok((
                crate::canonical_json_bytes(&token)?,
                token.verify_signature()?,
            ))
        }
        2 => {
            let root = AggregateBudgetRootBinding::sign_with_backend(
                AggregateBudgetRootBindingBody {
                    schema: AGGREGATE_BUDGET_ROOT_SCHEMA.into(),
                    root_capability_id: body.id,
                    root_capability_hash: "ab".repeat(32),
                    root_issuer: issuer,
                    root_subject: body.subject,
                    max_invocations: 1,
                    root_expires_at: body.expires_at,
                    root_scope_hash: scope_hash(&body.scope)?,
                },
                backend,
            )?;
            Ok((
                crate::canonical_json_bytes(&root)?,
                root.verify_signature()?,
            ))
        }
        _ => {
            let root = CumulativeApprovalRootBinding::sign_with_backend(
                CumulativeApprovalRootBindingBody {
                    schema: CUMULATIVE_APPROVAL_ROOT_SCHEMA.into(),
                    signer_key_epoch: 1,
                    root_capability_id: body.id,
                    root_capability_hash: "ab".repeat(32),
                    root_issuer: issuer,
                    root_subject: body.subject,
                    root_scope_hash: scope_hash(&body.scope)?,
                    root_grant_hash: "cd".repeat(32),
                    approval_budget_id: "budget".into(),
                    approval_budget_epoch: 1,
                    threshold: MonetaryAmount {
                        currency: "USD".into(),
                        units: 100,
                    },
                    root_expires_at: body.expires_at,
                },
                backend,
            )?;
            Ok((
                crate::canonical_json_bytes(&root)?,
                root.verify_signature()?,
            ))
        }
    }
}

#[test]
fn capability_and_budget_roots_use_the_original_atomic_identity() -> Result<()> {
    for artifact in 0..=3 {
        let backend = IdentityBackend::new(0);
        let expected = sign(artifact, &backend.original)?;
        let actual = sign(artifact, &backend)?;
        assert!(
            actual.1,
            "artifact {artifact} returned an invalid signature"
        );
        assert_eq!(actual, expected, "artifact {artifact} changed signed bytes");
        assert_eq!(backend.bound_calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn capability_and_budget_roots_reject_mismatched_atomic_results() {
    for artifact in 0..=3 {
        for fault in 1..=3 {
            let backend = IdentityBackend::new(fault);
            assert!(
                sign(artifact, &backend).is_err(),
                "artifact {artifact}, fault {fault}"
            );
            assert_eq!(backend.bound_calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn capability_and_budget_roots_refuse_a_retired_original_signer() {
    for artifact in 0..=3 {
        let backend = IdentityBackend::new(4);
        assert!(
            sign(artifact, &backend).is_err(),
            "artifact {artifact} accepted a replacement signer"
        );
        assert_eq!(backend.bound_calls.load(Ordering::SeqCst), 1);
    }
}
