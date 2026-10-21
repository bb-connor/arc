//! Every validated root-authority type has exactly one decoder, and it
//! validates. `T::deserialize` resolves to the trait impl, so a value that
//! breaks a rule only `validate` enforces is refused through that path.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use chio_core_types::root_authority::{
    DelegationAnchor, DelegationContext, EnterpriseProviderIdentity, IdpKeySnapshot, Jwk,
    RootPolicy, RootPolicyDisclosure, RootPolicyRule,
};
use serde::Deserialize;
use serde_json::{json, Value};

fn example(kind: &str, name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/root_authority/examples")
        .join(kind)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Decodes through the concrete path `Type::deserialize(value)`.
macro_rules! refused {
    ($ty:ty, $value:expr) => {
        match <$ty>::deserialize($value) {
            Ok(_) => panic!("decoded a value that breaks a validated rule"),
            Err(error) => error.to_string(),
        }
    };
}

#[test]
fn jwk_decode_refuses_an_rsa_key_carrying_a_curve() {
    let key = json!({ "kid": "k-1", "kty": "RSA", "n": "AQAB", "e": "AQAB", "crv": "P-256" });
    assert_eq!(refused!(Jwk, key), "`crv` is not allowed for RSA");
}

#[test]
fn delegation_anchor_decode_applies_its_kind_rules() {
    let anchor =
        example("invalid", "delegation-context.static-bearer-issuer.json")["anchor"].clone();
    assert_eq!(
        refused!(DelegationAnchor, anchor),
        "`issuer` has a value not admitted for operator_static_bearer"
    );
}

#[test]
fn delegation_context_decode_pins_its_schema() {
    let mut context = example("valid", "delegation-context.spec-5-6-3.json");
    context["schema"] = json!("chio.delegation-context.v2");
    assert_eq!(
        refused!(DelegationContext, context),
        "`schema` must be `chio.delegation-context.v1`"
    );
}

#[test]
fn idp_key_snapshot_decode_pins_its_schema() {
    let mut snapshot = example("valid", "idp-key-snapshot.spec-5-6-4.json");
    snapshot["schema"] = json!("chio.idp-key-snapshot.v2");
    assert_eq!(
        refused!(IdpKeySnapshot, snapshot),
        "`schema` must be `chio.idp-key-snapshot.v1`"
    );
}

#[test]
fn provider_identity_decode_requires_exactly_one_key_source() {
    let identity = example(
        "invalid",
        "enterprise-provider-identity.both-key-sources.json",
    );
    assert_eq!(
        refused!(EnterpriseProviderIdentity, identity),
        "exactly one of `jwks_url, jwks` is required"
    );
}

#[test]
fn root_policy_rule_decode_applies_its_kind_rules() {
    let rule = example(
        "invalid",
        "root-policy.static-bearer-without-principal.json",
    )["rules"][3]
        .clone();
    assert_eq!(
        refused!(RootPolicyRule, rule),
        "`principal` is required for operator_static_bearer"
    );
}

#[test]
fn root_policy_disclosure_decode_checks_tool_names() {
    let disclosure = json!({
        "default": "committed",
        "tools": { "crmsearch": { "parameters": { "inline_fields": [] }, "result": { "inline_fields": [] } } }
    });
    assert_eq!(
        refused!(RootPolicyDisclosure, disclosure),
        "`disclosure.tools` is not server/tool of at most 256 characters without NUL"
    );
}

#[test]
fn root_policy_decode_bounds_exchange_keys() {
    let policy = example("invalid", "root-policy.too-many-exchange-keys.json");
    assert_eq!(
        refused!(RootPolicy, policy),
        "`exchange_keys` has 17 items, outside 1..=16"
    );
}
