//! `root_anchor` as a signed member of the `chio.capability.v1` body.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::anchor::{AnchorKind, RootAnchor};
use chio_core_types::capability::attenuation::delegate;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{
    CapabilityToken, CapabilityTokenBody, CHIO_CAPABILITY_SCHEMA,
};
use chio_core_types::crypto::{verify_wrapped, Keypair};
use chio_core_types::root_authority::Sha256Digest;
use chio_core_types::{canonical_json_bytes, CanonicalBytes, ScopeAttenuation};
use serde_json::{json, Value};

const CAPABILITY_VECTORS: &str =
    include_str!("../../../../tests/bindings/vectors/capability/v1.json");

fn issuer() -> Keypair {
    Keypair::from_seed(&[2; 32])
}

fn holder() -> Keypair {
    Keypair::from_seed(&[3; 32])
}

fn anchor() -> RootAnchor {
    RootAnchor {
        kind: AnchorKind::OauthIdJag,
        context_digest: Sha256Digest::from_bytes([0x11; 32]),
        root_policy_digest: Sha256Digest::from_bytes([0x22; 32]),
        anchored_at: 1_792_234_795,
        assertion_exp: 1_792_235_090,
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "crm".into(),
            tool_name: "search".into(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn anchored_root() -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-root".into(),
            issuer: issuer().public_key(),
            subject: holder().public_key(),
            scope: scope(),
            issued_at: 1_792_234_795,
            expires_at: 1_792_235_090,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
            root_anchor: Some(anchor()),
        },
        &issuer(),
    )
    .unwrap()
}

/// The token's JSON with `edit` applied, re-signed by the issuer over the
/// edited signing body, and the signing body that signature covers.
fn resigned(edit: impl FnOnce(&mut Value)) -> (Value, Value) {
    let mut body = serde_json::to_value(anchored_root()).unwrap();
    let object = body.as_object_mut().unwrap();
    object.remove("signature");
    edit(&mut body);
    let signature = issuer()
        .sign_wrapped(
            CHIO_CAPABILITY_SCHEMA,
            &CanonicalBytes::from_serializable(&body).unwrap(),
        )
        .unwrap();
    let mut token = body.clone();
    token["signature"] = serde_json::to_value(signature).unwrap();
    (token, body)
}

#[test]
fn root_anchor_round_trips_in_the_signed_body() {
    let root = anchored_root();
    assert!(root.verify_signature(&issuer().public_key()).unwrap());
    let signing_bytes = canonical_json_bytes(&root.signing_body()).unwrap();
    let signing: Value = serde_json::from_slice(&signing_bytes).unwrap();
    assert_eq!(
        signing["root_anchor"],
        serde_json::to_value(anchor()).unwrap()
    );

    let decoded: CapabilityToken =
        serde_json::from_str(&serde_json::to_string(&root).unwrap()).unwrap();
    assert_eq!(decoded.root_anchor, Some(anchor()));
    assert_eq!(decoded.body().root_anchor, Some(anchor()));
    assert!(decoded.verify_signature(&issuer().public_key()).unwrap());
}

#[test]
fn unanchored_token_bytes_are_unchanged() {
    let vectors: Value = serde_json::from_str(CAPABILITY_VECTORS).unwrap();
    let mut checked = 0;
    for case in vectors["cases"].as_array().unwrap() {
        let Some(expected) = case["capability_signing_body_canonical_json"].as_str() else {
            continue;
        };
        let token: CapabilityToken = serde_json::from_value(case["capability"].clone()).unwrap();
        assert_eq!(token.root_anchor, None);
        let bytes = canonical_json_bytes(&token.signing_body()).unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
        checked += 1;
    }
    assert!(checked > 0);
}

#[test]
fn root_anchor_padding_refuses_even_with_a_valid_signature() {
    let (token, signed_body) = resigned(|body| body["root_anchor"]["padding"] = json!(1));
    let signature = serde_json::from_value(token["signature"].clone()).unwrap();
    assert!(verify_wrapped(
        &issuer().public_key(),
        CHIO_CAPABILITY_SCHEMA,
        &signed_body,
        &signature
    )
    .is_ok());

    let error = serde_json::from_value::<CapabilityToken>(token).unwrap_err();
    assert!(
        error.to_string().starts_with("unknown field `padding`"),
        "{error}"
    );
}

#[test]
fn root_anchor_unknown_kind_refuses_at_decode() {
    let (token, _) = resigned(|body| body["root_anchor"]["kind"] = json!("saml_assertion"));
    let error = serde_json::from_value::<CapabilityToken>(token).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("unknown variant `saml_assertion`"),
        "{error}"
    );
}

#[test]
fn delegate_copies_root_anchor_byte_for_byte() {
    let root = anchored_root();
    let child_scope = ChioScope {
        grants: vec![ToolGrant {
            operations: vec![Operation::Invoke],
            ..scope().grants[0].clone()
        }],
        ..ChioScope::default()
    };
    let receipt = delegate(
        &root,
        &child_scope,
        &holder(),
        &Keypair::from_seed(&[4; 32]).public_key(),
        ScopeAttenuation::default(),
        root.issued_at,
        [7; 16],
    )
    .unwrap();
    assert_eq!(
        canonical_json_bytes(&receipt.root_anchor).unwrap(),
        canonical_json_bytes(&root.root_anchor).unwrap()
    );
    assert_eq!(receipt.root_anchor, Some(anchor()));
}
