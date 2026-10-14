//! Counterexample for the breakthrough review: the published token carrier and
//! the existing receiver do not require a caller-controlled authorization server.
//! This exercises issuer ownership and replay, not full Chio admission binding
//! or durable recovery. No production receiver or wire type is changed.

use chio_composed_baseline::receiver::{BaselineProfile, ComposedReceiver, DurabilityMode};
use chio_composed_baseline::request::{ComposedEnvelope, JoseHeader};
use chio_composed_baseline::scenario::{self, CallBuilder, Credential, Keys};
use chio_composed_baseline::store::BaselineStore;
use chio_core_types::crypto::Keypair;
use std::cell::Cell;
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn receiver_owned_issuer_admits_and_caller_cannot_remint_a_spent_token() -> TestResult {
    let keys = Keys::fixed();
    // A separate receiver-owned issuer key, not the receipt key or any key the
    // adversary holds. Installed before any call, through existing local state.
    let receiver_issuer = Keypair::from_seed(&[0x55; 32]);
    let issuer_name = "https://auth.vendor.example";
    let mut state = scenario::vendor_state(&keys, false);
    let peer = state
        .bundle
        .get_mut(scenario::BUYER_AGENT)
        .ok_or("fixture must contain the buyer workload")?;
    peer.issuer = issuer_name.to_string();
    peer.issuer_key = receiver_issuer.public_key();

    // An in-memory database suffices for this trust-placement counterexample.
    // This test makes no claim about crash durability or concurrent admission.
    let store = BaselineStore::open(Path::new(":memory:"))?;
    let receiver = ComposedReceiver {
        state: &state,
        profile: BaselineProfile::Hardened,
        durability: DurabilityMode::BeforeDispatch,
        signing_key: &keys.vendor_decision,
        store: &store,
        private_profile: None,
    };
    let dispatches = Cell::new(0_u32);
    let mut dispatch = |_: &ComposedEnvelope| dispatches.set(dispatches.get() + 1);

    let mut valid = CallBuilder::new(&keys, "receiver-issued");
    valid.header = JoseHeader::ed25519("vendor-issuer-2026");
    valid.claims.iss = issuer_name.to_string();
    valid.claims.jti = "receiver-created-authorization-1".to_string();
    valid.credential = Credential::Issue(&receiver_issuer);
    let valid = valid.build()?;
    let outcome = receiver.admit(&valid, scenario::NOW_MS, &mut dispatch)?;
    assert!(outcome.admitted && outcome.dispatched);
    assert_eq!(dispatches.get(), 1);

    // A new message and fresh channel proof cannot reuse the receiver's token.
    let mut replay = CallBuilder::new(&keys, "new-message-same-authorization");
    replay.credential = Credential::Reuse(
        valid
            .credential
            .clone()
            .ok_or("valid call must carry its token")?,
    );
    let outcome = receiver.admit(&replay.build()?, scenario::NOW_MS, &mut dispatch)?;
    assert!(!outcome.admitted && !outcome.dispatched);
    assert_eq!(outcome.denial_code.as_deref(), Some("replay.token_id_seen"));
    assert_eq!(dispatches.get(), 1);

    // The caller controls its own issuer and can claim the receiver's issuer
    // name and a fresh jti, but cannot create a signature under the pinned key.
    let mut reminted = CallBuilder::new(&keys, "caller-remints");
    reminted.header = JoseHeader::ed25519("vendor-issuer-2026");
    reminted.claims.iss = issuer_name.to_string();
    reminted.claims.jti = "receiver-created-authorization-2".to_string();
    let outcome = receiver.admit(&reminted.build()?, scenario::NOW_MS, &mut dispatch)?;
    assert!(!outcome.admitted && !outcome.dispatched);
    assert_eq!(
        outcome.denial_code.as_deref(),
        Some("token.signature_invalid")
    );
    assert_eq!(dispatches.get(), 1);

    // The invalid mint did not spend this identifier: the receiver's own
    // authorization of another call still works on the same store and wiring.
    let mut next = CallBuilder::new(&keys, "receiver-issues-next");
    next.header = JoseHeader::ed25519("vendor-issuer-2026");
    next.claims.iss = issuer_name.to_string();
    next.claims.jti = "receiver-created-authorization-2".to_string();
    next.credential = Credential::Issue(&receiver_issuer);
    let outcome = receiver.admit(&next.build()?, scenario::NOW_MS, &mut dispatch)?;
    assert!(outcome.admitted && outcome.dispatched);
    assert_eq!(dispatches.get(), 2);
    assert_eq!(store.decision_count()?, 4);
    Ok(())
}
