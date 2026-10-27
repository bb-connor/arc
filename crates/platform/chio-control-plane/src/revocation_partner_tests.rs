use chio_core::Keypair;
use serde_json::{json, Value};

use super::{
    RevocationPartnerError, RevocationPartnerRegistry, MAX_PARTNER_ISSUER_KEYS,
    REVOCATION_PARTNER_REGISTRY_SCHEMA,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(seed: u8) -> String {
    Keypair::from_seed(&[seed; 32]).public_key().to_hex()
}

fn did(seed: u8) -> Result<String, Box<dyn std::error::Error>> {
    Ok(
        chio_did::DidChio::from_public_key(Keypair::from_seed(&[seed; 32]).public_key())?
            .to_string(),
    )
}

fn partner_keyed(partner_id: &str, url: &str, ttl: Value, authority: u8, issuers: &[u8]) -> Value {
    json!({
        "partnerId": partner_id,
        "issuer": url,
        "authorityPublicKey": key(authority),
        "issuerPublicKeys": issuers.iter().map(|seed| key(*seed)).collect::<Vec<_>>(),
        "revocationFreshnessTtlSeconds": ttl,
    })
}

fn partner(partner_id: &str, url: &str, ttl: Value, seed: u8) -> Value {
    partner_keyed(partner_id, url, ttl, seed, &[seed])
}

fn registry(partners: Value) -> Vec<u8> {
    json!({ "schema": REVOCATION_PARTNER_REGISTRY_SCHEMA, "partners": partners })
        .to_string()
        .into_bytes()
}

fn single(ttl: Value) -> Vec<u8> {
    registry(json!({ "acme": partner("acme", "https://trust.acme.example", ttl, 7) }))
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
    let mut value = partner("acme", "https://trust.acme.example", json!(60), 7);
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
fn missing_issuer_keys_refuse_the_registry() -> TestResult {
    let mut value = partner("acme", "https://trust.acme.example", json!(60), 7);
    value
        .as_object_mut()
        .ok_or("partner is not an object")?
        .remove("issuerPublicKeys");
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
        registry(json!({ "other": partner("acme", "https://trust.acme.example", json!(60), 7) }));
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
            partner_id: partner(partner_id, "https://trust.acme.example", json!(60), 7),
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
fn an_issuer_must_be_a_bare_https_origin_or_path() {
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
        let bytes = registry(json!({ "acme": partner("acme", url, json!(60), 7) }));
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
fn two_partners_cannot_share_an_issuer() {
    let bytes = registry(json!({
        "acme": partner("acme", "https://trust.acme.example", json!(60), 7),
        "bravo": partner("bravo", "https://trust.acme.example", json!(60), 8),
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
fn an_unknown_field_refuses_the_registry() -> TestResult {
    let mut value = partner("acme", "https://trust.acme.example", json!(60), 7);
    value["graceSeconds"] = json!(10);
    assert_eq!(
        RevocationPartnerRegistry::from_json(&registry(json!({ "acme": value }))),
        Err(RevocationPartnerError::Malformed(
            "urn:chio:error:attest:signed-json-invalid-shape".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn a_missing_registry_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let refused = RevocationPartnerRegistry::load(&dir.path().join("revocation-partners.json"))
        .err()
        .ok_or("a missing registry must refuse")?;
    assert!(
        matches!(&refused, RevocationPartnerError::Unreadable(reason) if !reason.is_empty()),
        "{refused}"
    );
    Ok(())
}

#[test]
fn a_partner_lists_its_issuer_key_lineage_and_resolves_every_did() -> TestResult {
    let bytes = registry(json!({
        "acme": partner_keyed("acme", "https://trust.acme.example", json!(60), 7, &[6, 7]),
    }));
    let loaded = RevocationPartnerRegistry::from_json(&bytes)?;
    let partner = loaded.get("acme").ok_or("partner missing")?;
    assert_eq!(partner.issuer_dids()?, vec![did(6)?, did(7)?]);
    for seed in [6, 7] {
        let found = loaded.by_issuer_dids(&[did(9)?, did(seed)?]);
        assert_eq!(found, vec![partner], "{seed}");
    }
    assert!(loaded.by_issuer_dids(&[did(9)?]).is_empty());
    Ok(())
}

#[test]
fn the_authority_key_must_be_one_of_the_issuer_keys() {
    let bytes = registry(json!({
        "acme": partner_keyed("acme", "https://trust.acme.example", json!(60), 7, &[6]),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::AuthorityKeyNotAnIssuerKey(
            "acme".to_owned()
        ))
    );
}

#[test]
fn an_issuer_key_shared_by_two_partners_refuses_the_registry() {
    let bytes = registry(json!({
        "acme": partner_keyed("acme", "https://trust.acme.example", json!(60), 7, &[5, 7]),
        "bravo": partner_keyed("bravo", "https://trust.bravo.example", json!(60), 8, &[8, 5]),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::DuplicateIssuerKey {
            first: "acme".to_owned(),
            second: "bravo".to_owned(),
        })
    );
}

#[test]
fn two_partners_with_one_authority_key_refuse_the_registry() {
    let bytes = registry(json!({
        "acme": partner("acme", "https://trust.acme.example", json!(60), 7),
        "bravo": partner("bravo", "https://trust.bravo.example", json!(60), 7),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::DuplicateIssuerKey {
            first: "acme".to_owned(),
            second: "bravo".to_owned(),
        })
    );
}

#[test]
fn more_than_eight_issuer_keys_refuses_the_registry() {
    let seeds = (1..=9).collect::<Vec<u8>>();
    let bytes = registry(json!({
        "acme": partner_keyed("acme", "https://trust.acme.example", json!(60), 1, &seeds),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::IssuerKeyCount {
            partner_id: "acme".to_owned(),
            count: MAX_PARTNER_ISSUER_KEYS + 1,
        })
    );
    let empty = registry(json!({
        "acme": partner_keyed("acme", "https://trust.acme.example", json!(60), 1, &[]),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&empty),
        Err(RevocationPartnerError::IssuerKeyCount {
            partner_id: "acme".to_owned(),
            count: 0,
        })
    );
}

#[test]
fn a_repeated_issuer_key_refuses_the_registry() {
    let bytes = registry(json!({
        "acme": partner_keyed("acme", "https://trust.acme.example", json!(60), 7, &[7, 7]),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::RepeatedIssuerKey("acme".to_owned()))
    );
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
        "acme": partner("acme", "https://trust.acme.example", json!(60), 7),
        "bravo": partner("bravo", "https://TRUST.acme.example:443", json!(60), 8),
    }));
    assert_eq!(
        RevocationPartnerRegistry::from_json(&bytes),
        Err(RevocationPartnerError::DuplicateIssuer {
            first: "acme".to_owned(),
            second: "bravo".to_owned(),
        })
    );
}
