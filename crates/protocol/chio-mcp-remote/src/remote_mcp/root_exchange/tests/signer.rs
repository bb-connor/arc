//! The exchange signer: built from the signing backend the binary owns,
//! and every artifact it signs verifying under the exchange key.

use std::sync::Arc;

use super::*;
use crate::idp_keys::{KeyResolutionError, SnapshotNotSigned};
use crate::root_exchange::signer::{ExchangeSigner, ExchangeSignerError};
use chio_core::capability::token::{CapabilityTokenBody, CHIO_CAPABILITY_SCHEMA};
use chio_core::crypto::{
    verify_wrapped, Ed25519Backend, Signature, SigningBackend, SigningMessage,
};
use chio_core::root_authority::{HttpsUrl, KeySnapshotSource, Uri};

const SEED: [u8; 32] = [0x41; 32];

fn exchange_key() -> PublicKey {
    Keypair::from_seed(&SEED).public_key()
}

fn foreign_key() -> PublicKey {
    Keypair::from_seed(&[0x43; 32]).public_key()
}

fn signer() -> ExchangeSigner {
    ExchangeSigner::new(Arc::new(Ed25519Backend::new(Keypair::from_seed(&SEED)))).unwrap()
}

fn root_body(issuer: PublicKey) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap_root_1".to_owned(),
        issuer,
        subject: Keypair::from_seed(&[0x42; 32]).public_key(),
        scope: ChioScope {
            grants: vec![grant("search")],
            ..ChioScope::default()
        },
        issued_at: NOW,
        expires_at: NOW + 300,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

fn sign_snapshot(signer: &ExchangeSigner) -> Result<IdpKeySnapshot, KeyResolutionError> {
    signer.sign_snapshot(
        &Uri::new(ISSUER).unwrap(),
        &KeySnapshotSource::JwksUrl(HttpsUrl::new(JWKS_URL).unwrap()),
        Vec::new(),
        NOW,
    )
}

/// Reports the exchange key but signs with another key.
struct ForeignSigningBackend {
    reported: Ed25519Backend,
    signing: Ed25519Backend,
}

impl SigningBackend for ForeignSigningBackend {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        self.reported.public_key()
    }

    fn sign_bytes(&self, message: SigningMessage<'_>) -> chio_core::error::Result<Signature> {
        self.signing.sign_bytes(message)
    }
}

/// Cannot report the key it signs with.
struct KeylessBackend;

impl SigningBackend for KeylessBackend {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        Err(chio_core::Error::InvalidPublicKey(
            "signing identity unavailable".to_owned(),
        ))
    }

    fn sign_bytes(&self, _message: SigningMessage<'_>) -> chio_core::error::Result<Signature> {
        Err(chio_core::Error::InvalidSignature(
            "signing identity unavailable".to_owned(),
        ))
    }
}

#[test]
fn exchange_signer_signature_verifies_against_pinned_exchange_key() {
    let signer = signer();
    assert_eq!(signer.key(), &exchange_key());

    let root = signer.sign_root(root_body(exchange_key())).unwrap();
    verify_wrapped(
        &exchange_key(),
        CHIO_CAPABILITY_SCHEMA,
        &root.signing_body(),
        &root.signature,
    )
    .unwrap();
    assert!(matches!(
        verify_wrapped(
            &foreign_key(),
            CHIO_CAPABILITY_SCHEMA,
            &root.signing_body(),
            &root.signature,
        ),
        Err(chio_core::Error::SignatureRejected)
    ));

    let snapshot = sign_snapshot(&signer).unwrap();
    assert_eq!(snapshot.exchange_key, exchange_key());
    snapshot.verify_signature(&exchange_key()).unwrap();
}

#[test]
fn exchange_signer_without_a_backend_key_refuses() {
    assert!(matches!(
        ExchangeSigner::new(Arc::new(KeylessBackend)),
        Err(ExchangeSignerError::BackendKeyUnavailable)
    ));
}

#[test]
fn exchange_signer_refuses_a_root_with_a_foreign_issuer() {
    assert_eq!(
        signer().sign_root(root_body(foreign_key())).unwrap_err(),
        ExchangeSignerError::IssuerNotExchangeKey
    );
}

#[test]
fn exchange_signer_refuses_a_backend_that_signs_under_another_key() {
    let signer = ExchangeSigner::new(Arc::new(ForeignSigningBackend {
        reported: Ed25519Backend::new(Keypair::from_seed(&SEED)),
        signing: Ed25519Backend::new(Keypair::from_seed(&[0x43; 32])),
    }))
    .unwrap();
    assert_eq!(
        signer.sign_root(root_body(exchange_key())).unwrap_err(),
        ExchangeSignerError::RootNotSigned
    );
    assert_eq!(
        sign_snapshot(&signer).unwrap_err(),
        KeyResolutionError::SnapshotNotSigned(SnapshotNotSigned)
    );
}
