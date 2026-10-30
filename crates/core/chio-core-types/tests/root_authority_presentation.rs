//! `chio.capability-presentation.v1` decoding and the capability chain digest.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::root_authority::{chain_digest, CapabilityPresentation, Sha256Digest};
use serde_json::{json, Value};

const VALID: &str = include_str!(
    "../../../../spec/schemas/chio-wire/v1/root_authority/examples/valid/presentation.json"
);

fn valid() -> Value {
    serde_json::from_str(VALID).unwrap()
}

fn decode(value: Value) -> Result<CapabilityPresentation, String> {
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn token(id: &str) -> Value {
    let mut token = valid()["leaf"].clone();
    token["id"] = json!(id);
    token
}

fn presentation(ancestors: Vec<Value>, leaf: Value) -> CapabilityPresentation {
    let mut value = valid();
    value["ancestors"] = Value::Array(ancestors);
    value["leaf"] = leaf;
    decode(value).unwrap()
}

#[test]
fn presentation_refuses_padding_in_every_carried_object() {
    for pointer in [
        "",
        "/leaf",
        "/delegation_context",
        "/delegation_context/anchor",
        "/delegation_context/exchange",
    ] {
        let mut value = valid();
        value
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("pad".to_owned(), json!(0));
        let error = decode(value).expect_err(pointer);
        assert!(error.contains("unknown field `pad`"), "{pointer}: {error}");
    }
}

#[test]
fn presentation_ancestors_bound_matches_the_schema() {
    let leaf = valid()["leaf"].clone();
    let mut at_bound = valid();
    at_bound["ancestors"] = Value::Array(vec![leaf.clone(); 16]);
    assert_eq!(decode(at_bound).unwrap().ancestors.len(), 16);
    let mut over = valid();
    over["ancestors"] = Value::Array(vec![leaf; 17]);
    let error = decode(over).unwrap_err();
    assert!(
        error.starts_with("`ancestors` has 17 items, outside 0..=16"),
        "{error}"
    );
}

#[test]
fn presentation_refuses_another_schema() {
    let mut value = valid();
    value["schema"] = json!("chio.capability-presentation.v2");
    let error = decode(value).unwrap_err();
    assert!(
        error.starts_with("`schema` must be `chio.capability-presentation.v1`"),
        "{error}"
    );
}

#[test]
fn presentation_round_trips_without_a_delegation_context() {
    let mut value = valid();
    value.as_object_mut().unwrap().remove("delegation_context");
    let decoded = decode(value.clone()).unwrap();
    assert!(decoded.delegation_context.is_none());
    assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
}

#[test]
fn chain_digest_uses_the_spec_domain_and_root_to_leaf_order() {
    let (root, leaf) = (token("cap-root"), token("cap-leaf"));
    let presented = presentation(vec![root.clone()], leaf.clone());
    let expected = Sha256Digest::of_domain(
        b"chio.receipt.chain-digest.v1\0",
        &canonical_json_bytes(&json!([root, leaf])).unwrap(),
    );
    assert_eq!(presented.chain_digest().unwrap(), expected);
    assert_eq!(
        chain_digest(&presented.ancestors, &presented.leaf).unwrap(),
        expected
    );
}

#[test]
fn chain_digest_depends_on_the_order_of_the_chain() {
    let (first, second) = (token("cap-first"), token("cap-second"));
    let forward = presentation(vec![first.clone()], second.clone());
    let reversed = presentation(vec![second], first);
    assert_ne!(
        forward.chain_digest().unwrap(),
        reversed.chain_digest().unwrap()
    );
}

#[test]
fn chain_digest_of_a_lone_root_covers_one_token() {
    let root = token("cap-root");
    let presented = presentation(Vec::new(), root.clone());
    let expected = Sha256Digest::of_domain(
        b"chio.receipt.chain-digest.v1\0",
        &canonical_json_bytes(&json!([root])).unwrap(),
    );
    assert_eq!(presented.chain_digest().unwrap(), expected);
}
