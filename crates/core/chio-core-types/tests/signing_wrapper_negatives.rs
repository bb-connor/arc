#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use chio_core_types::crypto::{
    verify_wrapped, verify_wrapped_bytes, Ed25519Backend, ExemptFormat, Keypair, PublicKey,
    Signature, SigningBackend, SigningMessage, SigningWrapper, SIGNING_WRAPPER_LEN,
    SIGNING_WRAPPER_PREFIX,
};
use chio_core_types::{CanonicalBytes, Error, Result, SigningAlgorithm};

struct CountingBackend {
    inner: Ed25519Backend,
    calls: AtomicUsize,
}

impl CountingBackend {
    fn new(keypair: Keypair) -> Self {
        Self {
            inner: Ed25519Backend::new(keypair),
            calls: AtomicUsize::new(0),
        }
    }

    fn sign_calls(&self) -> usize {
        self.calls.load(SeqCst)
    }
}

impl SigningBackend for CountingBackend {
    fn public_key(&self) -> Result<PublicKey> {
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature> {
        self.calls.fetch_add(1, SeqCst);
        self.inner.sign_bytes(message)
    }
}

struct UnreadableIdentity {
    signed: AtomicBool,
}

impl SigningBackend for UnreadableIdentity {
    fn public_key(&self) -> Result<PublicKey> {
        Err(Error::InvalidPublicKey("selector unreadable".into()))
    }

    fn sign_bytes(&self, _message: SigningMessage<'_>) -> Result<Signature> {
        self.signed.store(true, SeqCst);
        Err(Error::InvalidSignature("unreachable".into()))
    }
}

fn body() -> CanonicalBytes {
    CanonicalBytes::from_serializable(&serde_json::json!({"a": 1})).unwrap()
}

#[test]
fn wrapper_is_88_bytes_with_nul_at_23() {
    let w = SigningWrapper::new("chio.receipt.v1", &body()).unwrap();
    assert_eq!(w.as_bytes().len(), SIGNING_WRAPPER_LEN);
    assert_eq!(SIGNING_WRAPPER_LEN, 88);
    assert_eq!(&w.as_bytes()[..24], SIGNING_WRAPPER_PREFIX);
    assert_eq!(w.as_bytes()[23], 0);
}

#[test]
fn unregistered_schema_id_refuses_before_signing() {
    let backend = CountingBackend::new(Keypair::from_seed(&[1; 32]));
    let err = backend
        .sign_wrapped("chio.unregistered-fixture.v1", &body())
        .unwrap_err();
    assert!(
        matches!(err, Error::UnregisteredSchemaId(ref id) if id == "chio.unregistered-fixture.v1")
    );
    assert_eq!(backend.sign_calls(), 0);
    let key = backend.public_key().unwrap();
    assert!(matches!(
        backend.sign_wrapped_for_identity(&key, "chio.unregistered-fixture.v1", &body()),
        Err(Error::UnregisteredSchemaId(_))
    ));
    assert!(matches!(
        Keypair::from_seed(&[1; 32]).sign_wrapped("chio.unregistered-fixture.v1", &body()),
        Err(Error::UnregisteredSchemaId(_))
    ));
    assert_eq!(backend.sign_calls(), 0);
}

#[test]
fn unregistered_schema_id_refuses_verification() {
    let kp = Keypair::from_seed(&[1; 32]);
    let sig = kp.sign_wrapped("chio.receipt.v1", &body()).unwrap();
    assert!(matches!(
        verify_wrapped_bytes(&kp.public_key(), "chio.unregistered-fixture.v1", &body(), &sig),
        Err(Error::UnregisteredSchemaId(ref id)) if id == "chio.unregistered-fixture.v1"
    ));
    assert!(matches!(
        verify_wrapped(
            &kp.public_key(),
            "chio.unregistered-fixture.v1",
            &serde_json::json!({"a": 1}),
            &sig
        ),
        Err(Error::UnregisteredSchemaId(_))
    ));
}

#[test]
fn unreadable_identity_refuses_wrapped_signing() {
    let backend = UnreadableIdentity {
        signed: AtomicBool::new(false),
    };
    assert!(matches!(
        backend.sign_wrapped("chio.receipt.v1", &body()),
        Err(Error::InvalidPublicKey(ref m)) if m == "selector unreadable"
    ));
    let key = Keypair::from_seed(&[7u8; 32]).public_key();
    assert!(matches!(
        backend.sign_wrapped_for_identity(&key, "chio.receipt.v1", &body()),
        Err(Error::InvalidPublicKey(ref m)) if m == "selector unreadable"
    ));
    assert!(!backend.signed.load(SeqCst));
}

#[test]
fn wrapped_signing_for_another_identity_refuses() {
    let backend = CountingBackend::new(Keypair::from_seed(&[1; 32]));
    let other = Keypair::from_seed(&[2; 32]).public_key();
    assert!(matches!(
        backend.sign_wrapped_for_identity(&other, "chio.receipt.v1", &body()),
        Err(Error::InvalidPublicKey(_))
    ));
}

#[test]
fn schema_id_substitution_rejects() {
    let kp = Keypair::from_seed(&[3; 32]);
    let sig = kp.sign_wrapped("chio.capability.v1", &body()).unwrap();
    verify_wrapped_bytes(&kp.public_key(), "chio.capability.v1", &body(), &sig).unwrap();
    assert!(matches!(
        verify_wrapped_bytes(&kp.public_key(), "chio.receipt.v1", &body(), &sig),
        Err(Error::SignatureRejected)
    ));
}

#[test]
fn wrong_key_rejects() {
    let kp = Keypair::from_seed(&[3; 32]);
    let sig = kp.sign_wrapped("chio.receipt.v1", &body()).unwrap();
    let other = Keypair::from_seed(&[4; 32]).public_key();
    assert!(matches!(
        verify_wrapped_bytes(&other, "chio.receipt.v1", &body(), &sig),
        Err(Error::SignatureRejected)
    ));
}

#[test]
fn algorithm_prefix_mismatch_rejects_before_crypto() {
    let kp = Keypair::from_seed(&[5; 32]);
    let p256_sig = Signature::from_p256_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    assert!(matches!(
        verify_wrapped_bytes(&kp.public_key(), "chio.receipt.v1", &body(), &p256_sig),
        Err(Error::SignatureAlgorithmMismatch {
            key: SigningAlgorithm::Ed25519,
            signature: SigningAlgorithm::P256,
        })
    ));
}

#[test]
fn raw_body_signature_rejects() {
    let kp = Keypair::from_seed(&[6; 32]);
    let sig = kp.sign_exempt(ExemptFormat::JwsSigningInput, body().as_bytes());
    assert!(matches!(
        verify_wrapped_bytes(&kp.public_key(), "chio.receipt.v1", &body(), &sig),
        Err(Error::SignatureRejected)
    ));
}

#[cfg(feature = "pq")]
mod pq {
    use super::*;
    use chio_core_types::crypto::{HybridBackend, MlDsa65Backend};

    fn hybrid() -> HybridBackend {
        HybridBackend::new(
            Box::new(Ed25519Backend::new(Keypair::from_seed(&[8; 32]))),
            MlDsa65Backend::from_seed(&[9; 32]),
        )
        .unwrap()
    }

    #[test]
    fn hybrid_wrapped_signature_verifies() {
        let backend = hybrid();
        let outcome = backend.sign_wrapped("chio.receipt.v1", &body()).unwrap();
        verify_wrapped_bytes(
            &backend.public_key().unwrap(),
            "chio.receipt.v1",
            &body(),
            &outcome.signature,
        )
        .unwrap();
    }

    #[test]
    fn stripped_hybrid_rejects() {
        let backend = hybrid();
        let classical = Keypair::from_seed(&[8; 32])
            .sign_wrapped("chio.receipt.v1", &body())
            .unwrap();
        assert!(matches!(
            verify_wrapped_bytes(
                &backend.public_key().unwrap(),
                "chio.receipt.v1",
                &body(),
                &classical
            ),
            Err(Error::SignatureAlgorithmMismatch {
                key: SigningAlgorithm::Hybrid,
                signature: SigningAlgorithm::Ed25519,
            })
        ));
    }

    #[test]
    fn mldsa_nonempty_context_rejects() {
        use fips204::ml_dsa_65;
        use fips204::traits::{SerDes, Signer};
        use rand_core::OsRng;

        let backend = hybrid();
        let wrapper = SigningWrapper::new("chio.receipt.v1", &body()).unwrap();
        let pq = MlDsa65Backend::from_seed(&[9; 32]);
        let private = ml_dsa_65::PrivateKey::try_from_bytes(pq.secret_key_bytes()).unwrap();
        let pq_sig = private
            .try_sign_with_rng(&mut OsRng, wrapper.as_bytes(), b"chio-context")
            .unwrap();
        let classical = Keypair::from_seed(&[8; 32])
            .sign_wrapped("chio.receipt.v1", &body())
            .unwrap();
        let sig = Signature::from_hybrid_parts(
            classical,
            &pq_sig,
            chio_core_types::crypto::HYBRID_ED25519_MLDSA65,
        )
        .unwrap();
        assert!(matches!(
            verify_wrapped_bytes(
                &backend.public_key().unwrap(),
                "chio.receipt.v1",
                &body(),
                &sig
            ),
            Err(Error::SignatureRejected)
        ));
    }
}

mod algorithm_member {
    use super::*;
    use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt, ChioReceiptBody};
    use chio_core_types::receipt::decision::{Decision, ToolCallAction};
    use chio_core_types::receipt::kinds::TrustLevel;

    fn capability(key: &Keypair) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: "cap-algorithm-member".to_string(),
            issuer: key.public_key(),
            subject: Keypair::from_seed(&[12; 32]).public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_792_234_800,
            expires_at: 1_792_238_400,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, key).unwrap()
    }

    fn receipt_body(key: &Keypair, metadata: Option<serde_json::Value>) -> ChioReceiptBody {
        ChioReceiptBody {
            id: String::new(),
            timestamp: 1_792_234_800,
            capability_id: "cap-algorithm-member".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"a": 1})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy".to_string(),
            evidence: Vec::new(),
            metadata,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        }
    }

    fn with_member(value: &impl serde::Serialize, algorithm: &str) -> serde_json::Value {
        let mut value = serde_json::to_value(value).unwrap();
        value["algorithm"] = serde_json::json!(algorithm);
        value
    }

    #[test]
    fn capability_with_algorithm_member_fails_decoding() {
        let token = capability(&Keypair::from_seed(&[11; 32]));
        assert!(token.verify_integrity_embedded_key().unwrap());
        for algorithm in ["ed25519", "p256"] {
            assert!(serde_json::from_value::<CapabilityToken>(with_member(&token, algorithm)).is_err());
        }
    }

    #[test]
    fn receipt_with_algorithm_member_fails_decoding() {
        let key = Keypair::from_seed(&[11; 32]);
        let receipt = ChioReceipt::sign(receipt_body(&key, None), &key).unwrap();
        assert!(receipt.verify_integrity_embedded_key().unwrap());
        for algorithm in ["ed25519", "p256"] {
            assert!(serde_json::from_value::<ChioReceipt>(with_member(&receipt, algorithm)).is_err());
        }
    }

    #[test]
    fn verifier_choice_ignores_algorithm_member() {
        let ed25519 = Keypair::from_seed(&[11; 32]);
        let mut token = capability(&ed25519);
        let p256 = PublicKey::from_hex(
            "p256:046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        token.issuer = p256;
        assert!(serde_json::from_value::<CapabilityToken>(with_member(&token, "ed25519")).is_err());
        assert!(matches!(
            token.verify_integrity_embedded_key(),
            Err(Error::SignatureAlgorithmMismatch {
                key: SigningAlgorithm::P256,
                signature: SigningAlgorithm::Ed25519,
            })
        ));
    }

    #[test]
    fn receipt_id_survives_outer_signature_change() {
        let key = Keypair::from_seed(&[11; 32]);
        let mut receipt = ChioReceipt::sign(receipt_body(&key, None), &key).unwrap();
        let id = receipt.id.clone();
        receipt.signature = Keypair::from_seed(&[13; 32]).sign_exempt(ExemptFormat::JwsSigningInput, b"other");
        assert_eq!(chio_receipt_id(&receipt.body()).unwrap(), id);
    }

    #[test]
    fn receipt_id_follows_nested_signature_change() {
        let key = Keypair::from_seed(&[11; 32]);
        let nested = |signature: &str| Some(serde_json::json!({"child_receipt_signature": signature}));
        let first = ChioReceipt::sign(receipt_body(&key, nested("aa")), &key).unwrap();
        let second = ChioReceipt::sign(receipt_body(&key, nested("bb")), &key).unwrap();
        assert_ne!(first.id, second.id);
    }
}
