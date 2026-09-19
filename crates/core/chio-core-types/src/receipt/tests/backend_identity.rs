use super::*;
use crate::crypto::{
    Ed25519Backend, PublicKey, Signature, SigningAlgorithm, SigningBackend, SigningOutcome,
};
use crate::error::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};

struct IdentityBackend {
    inner: Ed25519Backend,
    other: Ed25519Backend,
    fault: u8,
    calls: AtomicUsize,
}

impl SigningBackend for IdentityBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }
    fn sign_bytes(&self, _: &[u8]) -> Result<Signature> {
        Err(Error::InvalidSignature(
            "unbound signing is forbidden".into(),
        ))
    }
    fn sign_bytes_with_identity(&self, _: &[u8]) -> Result<SigningOutcome> {
        Err(Error::InvalidSignature(
            "generic signing is forbidden".into(),
        ))
    }
    fn sign_bytes_for_identity(&self, key: &PublicKey, message: &[u8]) -> Result<SigningOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(key, &self.inner.public_key());
        let mut outcome = self.inner.sign_bytes_for_identity(key, message)?;
        match self.fault {
            0 => {}
            1 => outcome.public_key = self.other.public_key(),
            2 => outcome.algorithm = SigningAlgorithm::P256,
            3 => outcome.signature = self.other.sign_bytes(message)?,
            _ => return Err(Error::InvalidSignature("unknown test fault".into())),
        }
        Ok(outcome)
    }
}

#[test]
fn receipt_signing_uses_only_the_embedded_identity_entrypoint() -> Result<()> {
    let key = Keypair::generate();
    let backend = IdentityBackend {
        inner: Ed25519Backend::new(key.clone()),
        other: Ed25519Backend::generate(),
        fault: 0,
        calls: AtomicUsize::new(0),
    };
    let body = make_receipt_body(&key);
    let expected = ChioReceipt::sign_with_backend(body.clone(), &backend.inner)?;
    let receipt = ChioReceipt::sign_with_backend(body, &backend)?;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert!(receipt.verify_signature()?);
    assert_eq!(
        crate::canonical::canonical_json_bytes(&receipt)?,
        crate::canonical::canonical_json_bytes(&expected)?
    );
    Ok(())
}

#[test]
fn receipt_signing_rejects_each_mismatched_atomic_result() -> Result<()> {
    let key = Keypair::generate();
    for fault in 1..=3 {
        let backend = IdentityBackend {
            inner: Ed25519Backend::new(key.clone()),
            other: Ed25519Backend::generate(),
            fault,
            calls: AtomicUsize::new(0),
        };
        assert!(
            matches!(
                ChioReceipt::sign_with_backend(make_receipt_body(&key), &backend),
                Err(Error::InvalidSignature(_))
            ),
            "accepted atomic result fault {fault}"
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
