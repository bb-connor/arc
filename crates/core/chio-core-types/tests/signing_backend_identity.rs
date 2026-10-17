#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

use chio_core_types::crypto::{
    Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use chio_core_types::{Error, Result};

struct UnreadableIdentity {
    signed: AtomicBool,
}

impl SigningBackend for UnreadableIdentity {
    fn public_key(&self) -> Result<PublicKey> {
        Err(Error::InvalidPublicKey("selector unreadable".into()))
    }

    fn sign_bytes(&self, _message: &[u8]) -> Result<Signature> {
        self.signed.store(true, SeqCst);
        Err(Error::InvalidSignature("unreachable".into()))
    }
}

#[test]
fn identity_signing_fails_before_signing_when_identity_is_unreadable() {
    let backend = UnreadableIdentity {
        signed: AtomicBool::new(false),
    };
    let err = backend.sign_bytes_with_identity(b"m").unwrap_err();
    assert!(matches!(err, Error::InvalidPublicKey(ref m) if m == "selector unreadable"));
    let key = Keypair::from_seed(&[7u8; 32]).public_key();
    assert!(backend.sign_bytes_for_identity(&key, b"m").is_err());
    assert!(!backend.signed.load(SeqCst));
}

#[test]
fn static_backends_report_identity_through_fallible_public_key() {
    let kp = Keypair::from_seed(&[7u8; 32]);
    let backend = Ed25519Backend::new(kp.clone());
    assert_eq!(backend.public_key().unwrap(), kp.public_key());
    assert_eq!(
        backend.public_key().unwrap().algorithm(),
        SigningAlgorithm::Ed25519
    );
    let outcome = backend.sign_bytes_with_identity(b"m").unwrap();
    assert_eq!(outcome.public_key, kp.public_key());
    assert_eq!(outcome.algorithm, SigningAlgorithm::Ed25519);
}
