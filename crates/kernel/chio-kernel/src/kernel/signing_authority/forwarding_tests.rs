use super::*;
use chio_core::crypto::{verify_exempt, verify_wrapped_bytes, ExemptFormat, SigningAlgorithm};
use chio_core::{CanonicalBytes, CanonicalJsonWitness, Ed25519Backend, PublicKey, Signature};
use std::sync::atomic::{AtomicU64, Ordering};

fn message() -> SigningMessage<'static> {
    SigningMessage::exempt(ExemptFormat::JwsSigningInput, b"e30.e30")
}

struct BackendSpy {
    inner: Ed25519Backend,
    calls: [AtomicU64; 6],
}

impl SigningBackend for BackendSpy {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        self.calls[0].fetch_add(1, Ordering::SeqCst);
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature, chio_core::Error> {
        self.calls[1].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_bytes(message)
    }

    fn sign_bytes_with_identity(
        &self,
        message: SigningMessage<'_>,
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls[2].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_bytes_with_identity(message)
    }

    fn sign_bytes_for_identity(
        &self,
        key: &PublicKey,
        message: SigningMessage<'_>,
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls[3].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_bytes_for_identity(key, message)
    }

    fn sign_wrapped(
        &self,
        schema_id: &str,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls[4].fetch_add(1, Ordering::SeqCst);
        self.inner.sign_wrapped(schema_id, canonical)
    }

    fn sign_wrapped_for_identity(
        &self,
        key: &PublicKey,
        schema_id: &str,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls[5].fetch_add(1, Ordering::SeqCst);
        self.inner
            .sign_wrapped_for_identity(key, schema_id, canonical)
    }
}

#[test]
fn shared_backend_forwards_an_unreadable_current_key() {
    let shared = SharedSigningBackend(Arc::new(
        crate::authority::tests::UnreadableSelectorBackend(Ed25519Backend::new(
            chio_core::Keypair::from_seed(&[62; 32]),
        )),
    ));
    assert!(matches!(
        shared.public_key(),
        Err(chio_core::Error::InvalidPublicKey(message)) if message == "selector unavailable"
    ));
}

#[test]
fn shared_backend_forwards_every_atomic_signing_entrypoint() -> Result<(), chio_core::Error> {
    let spy = Arc::new(BackendSpy {
        inner: Ed25519Backend::new(chio_core::Keypair::from_seed(&[61; 32])),
        calls: std::array::from_fn(|_| AtomicU64::new(0)),
    });
    let shared = SharedSigningBackend(spy.clone());
    let public_key = shared.public_key()?;
    assert_eq!(public_key.algorithm(), SigningAlgorithm::Ed25519);
    verify_exempt(
        &public_key,
        ExemptFormat::JwsSigningInput,
        message().as_bytes(),
        &shared.sign_bytes(message())?,
    )?;
    assert_eq!(
        shared.sign_bytes_with_identity(message())?.public_key,
        public_key
    );
    assert_eq!(
        shared
            .sign_bytes_for_identity(&public_key, message())?
            .public_key,
        public_key
    );
    let canonical =
        CanonicalBytes::from_serializable(&serde_json::json!({"message": "canonical"}))?;
    let schema_id = chio_core_types::CHIO_DECLASSIFICATION_GRANT_SCHEMA;
    verify_wrapped_bytes(
        &public_key,
        schema_id,
        &canonical,
        &shared.sign_wrapped(schema_id, &canonical)?.signature,
    )?;
    assert_eq!(
        shared
            .sign_wrapped_for_identity(&public_key, schema_id, &canonical)?
            .public_key,
        public_key
    );
    for calls in &spy.calls {
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
