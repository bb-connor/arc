use chio_core::Keypair;
use serde_json::{json, Value};

use super::{PartnerCardError, PartnerCardRegistry, PARTNER_CARD_REGISTRY_SCHEMA};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn card(partner_id: &str, url: &str, ttl: Value) -> Value {
    json!({
        "partnerId": partner_id,
        "trustControlUrl": url,
        "authorityPublicKey": Keypair::from_seed(&[7; 32]).public_key().to_hex(),
        "federationPolicy": { "revocationFreshnessTtlSeconds": ttl },
    })
}

fn registry(partners: Value) -> Vec<u8> {
    json!({ "schema": PARTNER_CARD_REGISTRY_SCHEMA, "partners": partners })
        .to_string()
        .into_bytes()
}

fn single(ttl: Value) -> Vec<u8> {
    registry(json!({ "acme": card("acme", "https://trust.acme.example", ttl) }))
}

#[test]
fn a_valid_card_loads_and_resolves_by_id_and_url() -> TestResult {
    let loaded = PartnerCardRegistry::from_json(&single(json!(300)))?;
    let card = loaded.get("acme").ok_or("card missing")?;
    assert_eq!(card.revocation_freshness_ttl_ms(), 300_000);
    assert_eq!(
        loaded.by_trust_control_url("https://trust.acme.example"),
        Some(card)
    );
    assert_eq!(
        loaded.by_trust_control_url("https://trust.acme.example/"),
        None
    );
    Ok(())
}

#[test]
fn a_missing_freshness_ttl_refuses_the_registry() {
    let mut value = card("acme", "https://trust.acme.example", json!(60));
    value["federationPolicy"] = json!({});
    assert_eq!(
        PartnerCardRegistry::from_json(&registry(json!({ "acme": value }))),
        Err(PartnerCardError::MissingRevocationFreshnessTtl(
            "acme".to_owned()
        ))
    );
}

#[test]
fn a_freshness_ttl_outside_the_ceiling_refuses_the_registry() {
    for ttl in [0, 301, u64::MAX] {
        assert_eq!(
            PartnerCardRegistry::from_json(&single(json!(ttl))),
            Err(PartnerCardError::InvalidRevocationFreshnessTtl {
                partner_id: "acme".to_owned(),
                ttl,
            })
        );
    }
}

#[test]
fn a_foreign_schema_refuses_the_registry() {
    let bytes = json!({ "schema": "chio.partner-card-registry.v2", "partners": {} })
        .to_string()
        .into_bytes();
    assert_eq!(
        PartnerCardRegistry::from_json(&bytes),
        Err(PartnerCardError::UnsupportedSchema(
            "chio.partner-card-registry.v2".to_owned()
        ))
    );
}

#[test]
fn a_map_key_must_name_its_card() {
    let bytes = registry(json!({ "other": card("acme", "https://trust.acme.example", json!(60)) }));
    assert_eq!(
        PartnerCardRegistry::from_json(&bytes),
        Err(PartnerCardError::KeyMismatch {
            key: "other".to_owned(),
            partner_id: "acme".to_owned(),
        })
    );
}

#[test]
fn a_partner_id_that_is_not_a_safe_file_name_component_is_refused() {
    for partner_id in ["", "Acme", "../acme", "acme.b", &"a".repeat(65)] {
        let bytes = registry(json!({
            partner_id: card(partner_id, "https://trust.acme.example", json!(60)),
        }));
        assert_eq!(
            PartnerCardRegistry::from_json(&bytes),
            Err(PartnerCardError::InvalidPartnerId(partner_id.to_owned()))
        );
    }
}

#[test]
fn a_trust_control_url_must_be_a_bare_https_origin_or_path() {
    for (url, reason) in [
        ("http://trust.acme.example", "scheme must be https"),
        ("https://user@trust.acme.example", "userinfo is not allowed"),
        (
            "https://trust.acme.example?x=1",
            "a query or fragment is not allowed",
        ),
        (
            "https://trust.acme.example/base/",
            "a trailing slash is not allowed",
        ),
    ] {
        let bytes = registry(json!({ "acme": card("acme", url, json!(60)) }));
        assert_eq!(
            PartnerCardRegistry::from_json(&bytes),
            Err(PartnerCardError::InvalidTrustControlUrl {
                partner_id: "acme".to_owned(),
                reason: reason.to_owned(),
            }),
            "{url}"
        );
    }
}

#[test]
fn two_partners_cannot_share_a_trust_control_url() {
    let bytes = registry(json!({
        "acme": card("acme", "https://trust.acme.example", json!(60)),
        "bravo": card("bravo", "https://trust.acme.example", json!(60)),
    }));
    assert_eq!(
        PartnerCardRegistry::from_json(&bytes),
        Err(PartnerCardError::DuplicateTrustControlUrl {
            first: "acme".to_owned(),
            second: "bravo".to_owned(),
        })
    );
}

#[test]
fn an_unknown_field_refuses_the_registry() {
    let mut value = card("acme", "https://trust.acme.example", json!(60));
    value["federationPolicy"]["graceSeconds"] = json!(10);
    assert!(matches!(
        PartnerCardRegistry::from_json(&registry(json!({ "acme": value }))),
        Err(PartnerCardError::Malformed(_))
    ));
}

#[test]
fn a_missing_registry_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(matches!(
        PartnerCardRegistry::load(&dir.path().join("partner-cards.json")),
        Err(PartnerCardError::Unreadable(_))
    ));
    Ok(())
}
