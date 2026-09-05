use super::*;
use chio_core::{CanonicalBytes, CanonicalJsonWitness, Ed25519Backend, PublicKey, Signature};
use std::sync::atomic::{AtomicU64, Ordering};

struct BackendSpy {
    inner: Ed25519Backend,
    calls: [AtomicU64; 6],
}

impl SigningBackend for BackendSpy {
    fn algorithm(&self) -> SigningAlgorithm {
        self.calls[0].fetch_add(1, Ordering::SeqCst);
        self.inner.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.calls[1].fetch_add(1, Ordering::SeqCst);
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature, chio_core::Error> {
        self.calls[2].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_bytes(message)
    }

    fn sign_bytes_with_identity(&self, message: &[u8]) -> Result<SigningOutcome, chio_core::Error> {
        self.calls[3].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_bytes_with_identity(message)
    }

    fn sign_bytes_for_identity(
        &self,
        key: &PublicKey,
        message: &[u8],
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls[4].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_bytes_for_identity(key, message)
    }

    fn sign_canonical_bytes(
        &self,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<Signature, chio_core::Error> {
        self.calls[5].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_canonical_bytes(canonical)
    }
}

#[test]
fn shared_backend_forwards_every_atomic_signing_entrypoint() -> Result<(), chio_core::Error> {
    let spy = Arc::new(BackendSpy {
        inner: Ed25519Backend::new(chio_core::Keypair::from_seed(&[61; 32])),
        calls: std::array::from_fn(|_| AtomicU64::new(0)),
    });
    let shared = SharedSigningBackend(spy.clone());
    assert_eq!(shared.algorithm(), SigningAlgorithm::Ed25519);
    let public_key = shared.public_key();
    assert!(public_key.verify(b"message", &shared.sign_bytes(b"message")?));
    assert_eq!(
        shared.sign_bytes_with_identity(b"message")?.public_key,
        public_key
    );
    assert_eq!(
        shared
            .sign_bytes_for_identity(&public_key, b"message")?
            .public_key,
        public_key
    );
    let canonical =
        CanonicalBytes::from_serializable(&serde_json::json!({"message": "canonical"}))?;
    assert!(public_key.verify(
        canonical.as_bytes(),
        &shared.sign_canonical_bytes(&canonical)?
    ));
    for calls in &spy.calls {
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
