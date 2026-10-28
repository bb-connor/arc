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
fn root_policy_rule_decode_checks_projection_targets() {
    let valid = example("valid", "root-policy.spec-5-6-4.json")["rules"][0].clone();
    for target in ["crm", "/search", "crm/", "crm/search/extra", "/"] {
        let mut rule = valid.clone();
        rule["idp_scope_projection"]["crm.read"] = json!([target]);
        assert_eq!(
            refused!(RootPolicyRule, rule),
            "`idp_scope_projection` is not server/tool with a non-empty server and a non-empty tool without `/`",
            "{target}"
        );
    }
    RootPolicyRule::deserialize(valid).unwrap();
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

#[test]
fn root_policy_rule_refuses_empty_ceiling_grant_members() {
    let policy = example("valid", "root-policy.spec-5-6-4.json");
    for (scope, field, expected) in [
        (
            json!({"grants": [{"server_id": "", "tool_name": "read", "operations": ["invoke"]}]}),
            "ceiling_scope.grants.server_id",
            "a non-empty string",
        ),
        (
            json!({"grants": [{"server_id": "server", "tool_name": "", "operations": ["invoke"]}]}),
            "ceiling_scope.grants.tool_name",
            "a non-empty string",
        ),
        (
            json!({"grants": [{"server_id": "server", "tool_name": "read", "operations": []}]}),
            "ceiling_scope.grants.operations",
            "a non-empty operation list",
        ),
        (
            json!({"resource_grants": [{"uri_pattern": "", "operations": ["read"]}]}),
            "ceiling_scope.resource_grants.uri_pattern",
            "a non-empty string",
        ),
        (
            json!({"resource_grants": [{"uri_pattern": "file:///*", "operations": []}]}),
            "ceiling_scope.resource_grants.operations",
            "a non-empty operation list",
        ),
        (
            json!({"prompt_grants": [{"prompt_name": "", "operations": ["read"]}]}),
            "ceiling_scope.prompt_grants.prompt_name",
            "a non-empty string",
        ),
        (
            json!({"prompt_grants": [{"prompt_name": "prompt", "operations": []}]}),
            "ceiling_scope.prompt_grants.operations",
            "a non-empty operation list",
        ),
    ] {
        let mut rule = policy["rules"][0].clone();
        rule["ceiling_scope"] = scope;
        let fields = serde_json::from_value(rule.clone()).unwrap();
        assert_eq!(
            RootPolicyRule::new(fields).unwrap_err(),
            chio_core_types::root_authority::RootAuthorityShapeError::Pattern { field, expected }
        );
        assert_eq!(
            refused!(RootPolicyRule, rule.clone()),
            format!("`{field}` is not {expected}")
        );
        let mut invalid_policy = policy.clone();
        invalid_policy["rules"][0] = rule;
        assert_eq!(
            refused!(RootPolicy, invalid_policy),
            format!("`{field}` is not {expected}")
        );
    }
}

#[test]
fn root_policy_rule_accepts_empty_scope_and_nonempty_grant_members() {
    let policy = example("valid", "root-policy.spec-5-6-4.json");
    for scope in [
        json!({}),
        json!({
            "grants": [{"server_id": "*", "tool_name": "*", "operations": ["invoke"]}],
            "resource_grants": [{"uri_pattern": "file:///*", "operations": ["read"]}],
            "prompt_grants": [{"prompt_name": "*", "operations": ["read"]}]
        }),
    ] {
        let mut rule = policy["rules"][0].clone();
        rule["ceiling_scope"] = scope.clone();
        let decoded = RootPolicyRule::deserialize(rule).unwrap();
        assert_eq!(serde_json::to_value(&decoded.ceiling_scope).unwrap(), scope);
    }
}
