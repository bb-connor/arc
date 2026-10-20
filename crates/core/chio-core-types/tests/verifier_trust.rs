#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test fixtures deliberately fail on violated setup invariants."
)]

use chio_core_types::root_authority::{ReportColumn, VerifierTrust, VerifierTrustError};

const EXAMPLES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-wire/v1/root_authority/examples"
);

const WEAK_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";

fn example(path: &str) -> serde_json::Value {
    let bytes = std::fs::read(format!("{EXAMPLES}/{path}")).expect("example");
    serde_json::from_slice(&bytes).expect("example json")
}

fn load(value: &serde_json::Value) -> Result<VerifierTrust, VerifierTrustError> {
    VerifierTrust::load(&serde_json::to_vec(value).expect("encode"))
}

fn kernel_key(value: &serde_json::Value) -> serde_json::Value {
    value["kernel_keys"][0].clone()
}

#[test]
fn staged_valid_example_loads() {
    let trust = load(&example("valid/verifier-trust.json")).expect("valid trust file");
    assert_eq!(trust.kernel_keys.len(), 1);
    assert_eq!(
        trust.required_columns,
        vec![
            ReportColumn::IdentityRoot,
            ReportColumn::DelegationChain,
            ReportColumn::Decision,
            ReportColumn::Content,
        ]
    );
}

#[test]
fn staged_invalid_examples_refuse() {
    for path in [
        "invalid/verifier-trust.empty-kernel-keys.json",
        "invalid/verifier-trust.unknown-member.json",
    ] {
        assert!(load(&example(path)).is_err(), "{path} must refuse");
    }
}

#[test]
fn rootless_trust_with_only_kernel_keys_loads() {
    let mut value = example("valid/verifier-trust.json");
    value["exchange_keys"] = serde_json::json!([]);
    value["root_policy_keys"] = serde_json::json!([]);
    load(&value).expect("exchange and root policy keys may be empty");
}

#[test]
fn padded_members_refuse_at_every_level() {
    let mut top = example("valid/verifier-trust.json");
    top["padding"] = serde_json::json!(true);
    assert!(load(&top).is_err());

    let mut nested = example("valid/verifier-trust.json");
    nested["idp_keys"]["https://acme.okta.com"][0]["padding"] = serde_json::json!("x");
    assert!(load(&nested).is_err());

    let mut anchor = example("valid/verifier-trust.json");
    anchor["checkpoint_trust_anchor"] = serde_json::json!({
        "publicationIdentity": {"kind": "local_log", "identity": "local-log-1"},
        "trustAnchorIdentity": {"kind": "transparency_root", "identity": "root-set-1"},
        "trustAnchorRef": "anchor-root-1",
        "signerCertRef": "cert-chain-1",
        "publicationProfileVersion": "profile-1",
        "padding": true
    });
    assert!(matches!(
        load(&anchor),
        Err(VerifierTrustError::DroppedInput)
    ));
}

#[test]
fn key_pinned_in_two_roles_refuses() {
    let mut value = example("valid/verifier-trust.json");
    value["exchange_keys"] = serde_json::json!([kernel_key(&value)]);
    assert!(matches!(
        load(&value),
        Err(VerifierTrustError::KeyInTwoRoles)
    ));
}

#[test]
fn weak_ed25519_key_refuses() {
    let mut value = example("valid/verifier-trust.json");
    value["kernel_keys"] = serde_json::json!([WEAK_KEY]);
    assert!(matches!(
        load(&value),
        Err(VerifierTrustError::WeakKey {
            field: "kernel_keys"
        })
    ));
}

#[test]
fn duplicate_key_and_column_refuse() {
    let mut keys = example("valid/verifier-trust.json");
    keys["kernel_keys"] = serde_json::json!([kernel_key(&keys), kernel_key(&keys)]);
    assert!(load(&keys).is_err());

    let mut columns = example("valid/verifier-trust.json");
    columns["required_columns"] = serde_json::json!(["decision", "decision"]);
    assert!(load(&columns).is_err());
}

#[test]
fn checkpoint_trust_anchor_round_trips_and_requires_every_member() {
    let mut value = example("valid/verifier-trust.json");
    value["checkpoint_trust_anchor"] = serde_json::json!({
        "publicationIdentity": {"kind": "local_log", "identity": "local-log-1"},
        "trustAnchorIdentity": {"kind": "transparency_root", "identity": "root-set-1"},
        "trustAnchorRef": "anchor-root-1",
        "signerCertRef": "cert-chain-1",
        "publicationProfileVersion": "profile-1"
    });
    let trust = load(&value).expect("anchored trust file");
    let anchor = trust.checkpoint_trust_anchor.expect("anchor");
    assert_eq!(anchor.trust_anchor_ref, "anchor-root-1");

    value["checkpoint_trust_anchor"]["trustAnchorRef"] = serde_json::json!("   ");
    assert!(matches!(
        load(&value),
        Err(VerifierTrustError::TrustAnchor(_))
    ));
}

#[test]
fn wrong_schema_refuses() {
    let mut value = example("valid/verifier-trust.json");
    value["schema"] = serde_json::json!("chio.verifier-trust.v2");
    assert!(matches!(load(&value), Err(VerifierTrustError::Shape(_))));
}
