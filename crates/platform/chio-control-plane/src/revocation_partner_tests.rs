use chio_core::Keypair;
use serde_json::{json, Value};

use super::{
    RevocationPartnerError, RevocationPartnerRegistry, REVOCATION_PARTNER_REGISTRY_SCHEMA,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn partner(partner_id: &str, url: &str, ttl: Value) -> Value {
    json!({
        "partnerId": partner_id,
        "issuer": url,
        "authorityPublicKey": Keypair::from_seed(&[7; 32]).public_key().to_hex(),
        "revocationFreshnessTtlSeconds": ttl,
    })
}

fn registry(partners: Value) -> Vec<u8> {
    json!({ "schema": REVOCATION_PARTNER_REGISTRY_SCHEMA, "partners": partners })
        .to_string()
        .into_bytes()
}

fn single(ttl: Value) -> Vec<u8> {
    registry(json!({ "acme": partner("acme", "https://trust.acme.example", ttl) }))
}

#[test]
fn a_valid_partner_loads_and_resolves_by_id_and_issuer() -> TestResult {
    let loaded = RevocationPartnerRegistry::from_json(&single(json!(300)))?;
    let partner = loaded.get("acme").ok_or("partner missing")?;
    assert_eq!(partner.revocation_freshness_ttl_ms(), 300_000);
    assert_eq!(
        loaded.by_issuer("https://trust.acme.example")?,
        Some(partner)
    );
    Ok(())
}

#[test]
fn a_missing_freshness_ttl_refuses_the_registry() -> TestResult {
    let mut value = partner("acme", "https://trust.acme.example", json!(60));
    value
        .as_object_mut()
        .ok_or("partner is not an object")?
        .remove("revocationFreshnessTtlSeconds");
    assert_eq!(
        RevocationPartnerRegistry::from_json(&registry(json!({ "acme": value }))),
        Err(RevocationPartnerError::Malformed(
            "urn:chio:error:attest:signed-json-invalid-shape".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn a_freshness_ttl_outside_the_ceiling_refuses_the_registry() {
    for ttl in [0, 301, u64::MAX] {
        assert_eq!(
            RevocationPartnerRegistry::from_json(&single(json!(ttl))),
            Err(RevocationPartnerError::InvalidRevocationFreshnessTtl {
                partner_id: "acme".to_owned(),
                ttl,
            })
        );
    }
}

#[test]
fn a_foreign_schema_refuses_the_registry() {
    let bytes = json!({ "schema": "chio.revocation-partner-registry.v2", "partners": {} })
        .to_string()
        .into_bytes();
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::UnsupportedSchema(
            "chio.revocation-partner-registry.v2".to_owned()
        ))
    );
}

#[test]
fn a_map_key_must_name_its_partner() {
    let bytes =
        registry(json!({ "other": partner("acme", "https://trust.acme.example", json!(60)) }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::KeyMismatch {
            key: "other".to_owned(),
            partner_id: "acme".to_owned(),
        })
    );
}

#[test]
fn a_partner_id_that_is_not_a_safe_file_name_component_is_refused() {
    for partner_id in ["", "Acme", "../acme", "acme.b", &"a".repeat(65)] {
        let bytes = registry(json!({
            partner_id: partner(partner_id, "https://trust.acme.example", json!(60)),
        }));
        assert_eq!(
            RevocationPartnerRegistry::from_json(&bytes),
            Err(RevocationPartnerError::InvalidPartnerId(
                partner_id.to_owned()
            ))
        );
    }
}

#[test]
fn a_issuer_must_be_a_bare_https_origin_or_path() {
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
        let bytes = registry(json!({ "acme": partner("acme", url, json!(60)) }));
        assert_eq!(
            RevocationPartnerRegistry::from_json(&bytes),
            Err(RevocationPartnerError::InvalidIssuer {
                partner_id: "acme".to_owned(),
                reason: reason.to_owned(),
            }),
            "{url}"
        );
    }
}

#[test]
fn two_partners_cannot_share_a_issuer() {
    let bytes = registry(json!({
        "acme": partner("acme", "https://trust.acme.example", json!(60)),
        "bravo": partner("bravo", "https://trust.acme.example", json!(60)),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::DuplicateIssuer {
            first: "acme".to_owned(),
            second: "bravo".to_owned(),
        })
    );
}

#[test]
fn an_unknown_field_refuses_the_registry() {
    let mut value = partner("acme", "https://trust.acme.example", json!(60));
    value["graceSeconds"] = json!(10);
    assert!(matches!(
        RevocationPartnerRegistry::from_json(&registry(json!({ "acme": value }))),
        Err(RevocationPartnerError::Malformed(_))
    ));
}

#[test]
fn a_missing_registry_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(matches!(
        RevocationPartnerRegistry::load(&dir.path().join("revocation-partners.json")),
        Err(RevocationPartnerError::Unreadable(_))
    ));
    Ok(())
}

#[test]
fn a_partner_resolves_by_the_did_of_its_authority_key() -> TestResult {
    let loaded = RevocationPartnerRegistry::from_json(&single(json!(60)))?;
    let did =
        chio_did::DidChio::from_public_key(Keypair::from_seed(&[7; 32]).public_key())?.to_string();
    let other =
        chio_did::DidChio::from_public_key(Keypair::from_seed(&[8; 32]).public_key())?.to_string();
    let found = loaded.by_issuer_dids(&[other.clone(), did]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].partner_id, "acme");
    assert!(loaded.by_issuer_dids(&[other]).is_empty());
    Ok(())
}

#[test]
fn the_registry_schema_identifier_is_v1() {
    assert_eq!(
        REVOCATION_PARTNER_REGISTRY_SCHEMA,
        "chio.revocation-partner-registry.v1"
    );
}

#[test]
fn a_registry_past_the_shared_read_bound_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("revocation-partners.json");
    std::fs::write(
        &path,
        vec![b' '; crate::signed_input::MAX_SIGNED_FILE_BYTES + 1],
    )?;
    assert_eq!(
        RevocationPartnerRegistry::load(&path),
        Err(RevocationPartnerError::Malformed(
            "urn:chio:error:attest:signed-json-too-large".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn an_issuer_matches_its_partner_under_rfc3986_equivalence() -> TestResult {
    let loaded = RevocationPartnerRegistry::from_json(&single(json!(60)))?;
    for presented in [
        "https://trust.acme.example",
        "https://trust.acme.example/",
        "HTTPS://TRUST.Acme.Example",
        "https://trust.acme.example:443",
        "https://trust.acme.example//",
    ] {
        assert_eq!(
            loaded
                .by_issuer(presented)?
                .map(|partner| partner.partner_id.as_str()),
            Some("acme"),
            "{presented}"
        );
    }
    for other in [
        "https://trust.acme.example:8443",
        "https://trust.acme.example/base",
        "http://trust.acme.example",
    ] {
        assert_eq!(loaded.by_issuer(other)?, None, "{other}");
    }
    Ok(())
}

#[test]
fn a_presented_issuer_with_userinfo_a_query_or_a_fragment_is_refused() -> TestResult {
    let loaded = RevocationPartnerRegistry::from_json(&single(json!(60)))?;
    for (presented, reason) in [
        ("https://x@trust.acme.example", "userinfo is not allowed"),
        ("https://x:y@trust.acme.example", "userinfo is not allowed"),
        ("https://trust.acme.example/?a=1", "a query is not allowed"),
        ("https://trust.acme.example/#b", "a fragment is not allowed"),
        ("not a url", "not a URL"),
    ] {
        assert_eq!(
            loaded.by_issuer(presented),
            Err(RevocationPartnerError::MalformedPresentedIssuer {
                issuer: presented.to_owned(),
                reason: reason.to_owned(),
            }),
            "{presented}"
        );
    }
    Ok(())
}

#[test]
fn two_partners_whose_issuers_differ_only_in_form_are_refused() {
    let bytes = registry(json!({
        "acme": partner("acme", "https://trust.acme.example", json!(60)),
        "bravo": partner("bravo", "https://TRUST.acme.example:443", json!(60)),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::DuplicateIssuer {
            first: "acme".to_owned(),
            second: "bravo".to_owned(),
        })
    );
}
