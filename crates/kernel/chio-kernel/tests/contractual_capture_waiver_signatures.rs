use chio_core::crypto::{Keypair, PublicKey, Signature};
use chio_kernel::payment::{
    capture_waiver_digest, ContractualCaptureWaiverPolicyV1, ContractualCaptureWaiverTermsV1,
    SignedContractualCaptureWaiverTermsV1, CONTRACTUAL_CAPTURE_WAIVER_SCHEMA,
};

fn low_order_forgery() -> Result<(PublicKey, Signature), Box<dyn std::error::Error>> {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut signature = [0; 64];
    signature[0] = 1;
    Ok((
        PublicKey::from_bytes(&identity)?,
        Signature::from_bytes(&signature),
    ))
}

#[test]
fn waiver_terms_reject_either_low_order_consent_key() -> Result<(), Box<dyn std::error::Error>> {
    let receiver = Keypair::generate();
    let counterparty = Keypair::generate();
    let observer = Keypair::generate();
    let (weak_key, forged) = low_order_forgery()?;
    assert!(weak_key.verify(b"no consent", &forged));
    for receiver_forged in [true, false] {
        let policy = ContractualCaptureWaiverPolicyV1 {
            receiver_key: if receiver_forged {
                weak_key.clone()
            } else {
                receiver.public_key()
            },
            counterparty_key: if receiver_forged {
                counterparty.public_key()
            } else {
                weak_key.clone()
            },
            observation_key: observer.public_key(),
            rail: "test-reversible".into(),
            currency: "USD".into(),
        };
        let body = ContractualCaptureWaiverTermsV1 {
            schema: CONTRACTUAL_CAPTURE_WAIVER_SCHEMA.into(),
            policy_digest: capture_waiver_digest(&policy)?,
            contract_context_digest: "a".repeat(64),
            capability_digest: "b".repeat(64),
            request_id: "waiver-request".into(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        };
        let mut terms =
            SignedContractualCaptureWaiverTermsV1::sign(body, &receiver, &counterparty)?;
        if receiver_forged {
            terms.receiver_signature = forged.clone();
        } else {
            terms.counterparty_signature = forged.clone();
        }
        match &terms.verify(&policy) {
            Err(chio_kernel::payment::CaptureWaiverError(reason)) => {
                assert_eq!(reason, "invalid receiver-pinned policy");
            }
            result => panic!("unexpected rejection: {:?}", result.as_ref().err()),
        };
    }
    Ok(())
}

#[test]
fn waiver_policy_rejects_a_low_order_observer_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = ContractualCaptureWaiverPolicyV1 {
        receiver_key: Keypair::generate().public_key(),
        counterparty_key: Keypair::generate().public_key(),
        observation_key: Keypair::generate().public_key(),
        rail: "test-reversible".into(),
        currency: "USD".into(),
    };
    policy.validate()?;
    policy.observation_key = low_order_forgery()?.0;
    match &policy.validate() {
        Err(chio_kernel::payment::CaptureWaiverError(reason)) => {
            assert_eq!(reason, "invalid receiver-pinned policy");
        }
        result => panic!("unexpected rejection: {:?}", result.as_ref().err()),
    };
    Ok(())
}
