//! Sign request decoding and the snapshot checks that authorize signing.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::crypto::Keypair;
use chio_core_types::root_authority::{
    check_snapshot_sign, EnterpriseProviderIdentity, IdpKeySnapshotBody, RootExchangeSignRefusal,
    RootExchangeSignRequest, MAX_SIGN_CLOCK_SKEW_SECS,
};
use serde_json::{json, Value};

const NOW: u64 = 1_800_000_000;
const JWKS_URL: &str = "https://issuer.example/jwks";

fn key_json() -> Value {
    json!({ "kid": "k-1", "kty": "RSA", "n": "AQAB", "e": "AQAB" })
}

fn identity(edit: impl FnOnce(&mut Value)) -> EnterpriseProviderIdentity {
    let mut value = json!({
        "schema": "chio.enterprise-provider-identity.v1",
        "provider_id": "acme-okta",
        "kind": "oidc_jwks",
        "issuer": "https://issuer.example",
        "jwks_url": JWKS_URL,
        "audiences": [],
        "subject_mapping": { "principal_source": "sub", "tenant_id_field": "iss" },
        "trust_material_ref": "okta-org-acme"
    });
    edit(&mut value);
    serde_json::from_value(value).unwrap()
}

fn inline_identity() -> EnterpriseProviderIdentity {
    identity(|value| {
        value.as_object_mut().unwrap().remove("jwks_url");
        value["jwks"] = json!({ "keys": [key_json()] });
    })
}

fn body_json(exchange: &Keypair) -> Value {
    json!({
        "schema": "chio.idp-key-snapshot.v1",
        "issuer": "https://issuer.example",
        "source": JWKS_URL,
        "keys": [key_json()],
        "observed_at": NOW,
        "exchange_key": exchange.public_key()
    })
}

fn body(exchange: &Keypair, edit: impl FnOnce(&mut Value)) -> IdpKeySnapshotBody {
    let mut value = body_json(exchange);
    edit(&mut value);
    serde_json::from_value(value).unwrap()
}

fn check(
    body: &IdpKeySnapshotBody,
    identity: &EnterpriseProviderIdentity,
    exchange: &Keypair,
) -> Result<(), RootExchangeSignRefusal> {
    let digest = identity.digest().unwrap();
    check_snapshot_sign(body, identity, &digest, &exchange.public_key(), NOW)
}

#[test]
fn matching_snapshot_is_authorized() {
    let exchange = Keypair::generate();
    assert_eq!(
        check(&body(&exchange, |_| {}), &identity(|_| {}), &exchange),
        Ok(())
    );
}

#[test]
fn matching_inline_snapshot_is_authorized() {
    let exchange = Keypair::generate();
    let inline = body(&exchange, |value| {
        value["source"] = json!("registry:acme-okta")
    });
    assert_eq!(check(&inline, &inline_identity(), &exchange), Ok(()));
}

#[test]
fn snapshot_record_digest_differs_from_edge_refuses() {
    let exchange = Keypair::generate();
    let edge_digest = identity(|value| value["trust_material_ref"] = json!("other"))
        .digest()
        .unwrap();
    assert_eq!(
        check_snapshot_sign(
            &body(&exchange, |_| {}),
            &identity(|_| {}),
            &edge_digest,
            &exchange.public_key(),
            NOW
        ),
        Err(RootExchangeSignRefusal::ProviderIdentityMismatch)
    );
}

#[test]
fn snapshot_issuer_mismatch_refuses() {
    let exchange = Keypair::generate();
    let foreign = body(&exchange, |value| {
        value["issuer"] = json!("https://other.example")
    });
    assert_eq!(
        check(&foreign, &identity(|_| {}), &exchange),
        Err(RootExchangeSignRefusal::IssuerMismatch)
    );
}

#[test]
fn snapshot_source_mismatch_refuses() {
    let exchange = Keypair::generate();
    let other_url = body(&exchange, |value| {
        value["source"] = json!("https://issuer.example/other")
    });
    let registry = body(&exchange, |value| {
        value["source"] = json!("registry:acme-okta")
    });
    let other_record = body(&exchange, |value| value["source"] = json!("registry:other"));
    for (snapshot, record) in [
        (&other_url, identity(|_| {})),
        (&registry, identity(|_| {})),
        (&other_record, inline_identity()),
        (&body(&exchange, |_| {}), inline_identity()),
    ] {
        assert_eq!(
            check(snapshot, &record, &exchange),
            Err(RootExchangeSignRefusal::SourceMismatch)
        );
    }
}

#[test]
fn snapshot_inline_keys_mismatch_refuses() {
    let exchange = Keypair::generate();
    let foreign = body(&exchange, |value| {
        value["source"] = json!("registry:acme-okta");
        value["keys"] = json!([]);
    });
    assert_eq!(
        check(&foreign, &inline_identity(), &exchange),
        Err(RootExchangeSignRefusal::InlineKeysMismatch)
    );
}

#[test]
fn snapshot_foreign_exchange_key_refuses() {
    let exchange = Keypair::generate();
    assert_eq!(
        check(
            &body(&Keypair::generate(), |_| {}),
            &identity(|_| {}),
            &exchange
        ),
        Err(RootExchangeSignRefusal::ForeignExchangeKey)
    );
}

#[test]
fn snapshot_observed_at_skew_boundary() {
    let exchange = Keypair::generate();
    let at = |observed_at: u64| body(&exchange, |value| value["observed_at"] = json!(observed_at));
    for edge in [
        NOW - MAX_SIGN_CLOCK_SKEW_SECS,
        NOW + MAX_SIGN_CLOCK_SKEW_SECS,
    ] {
        assert_eq!(check(&at(edge), &identity(|_| {}), &exchange), Ok(()));
    }
    for past in [
        NOW - MAX_SIGN_CLOCK_SKEW_SECS - 1,
        NOW + MAX_SIGN_CLOCK_SKEW_SECS + 1,
    ] {
        assert_eq!(
            check(&at(past), &identity(|_| {}), &exchange),
            Err(RootExchangeSignRefusal::ObservedAtOutsideSkew {
                observed_at: past,
                now: NOW
            })
        );
    }
}

fn request_json(exchange: &Keypair) -> Value {
    json!({
        "kind": "idp_key_snapshot",
        "provider_record_id": "acme-okta",
        "provider_identity_digest": identity(|_| {}).digest().unwrap(),
        "body": body_json(exchange)
    })
}

#[test]
fn sign_request_round_trips() {
    let value = request_json(&Keypair::generate());
    let request: RootExchangeSignRequest = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&request).unwrap(), value);
}

#[test]
fn sign_request_refuses_every_other_shape() {
    let exchange = Keypair::generate();
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut value = request_json(&exchange);
        edit(&mut value);
        serde_json::from_value::<RootExchangeSignRequest>(value).is_err()
    };
    assert!(refused(&|value| value["kind"] = json!("message")));
    assert!(refused(&|value| {
        value.as_object_mut().unwrap().remove("kind");
    }));
    assert!(refused(&|value| value["bytes"] = json!("AQAB")));
    assert!(refused(&|value| value["body"]["signature"] = json!("00")));
    assert!(refused(
        &|value| value["body"]["schema"] = json!("chio.capability.v1")
    ));
    assert!(refused(
        &|value| value["body"]["keys"] = json!(vec![key_json(); 65])
    ));
}
