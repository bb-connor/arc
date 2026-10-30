use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde_json::{json, Value};

use super::{
    EnterpriseProviderKind as Kind, EnterpriseProviderRecord, EnterpriseProviderRegistry,
    EnterpriseProviderRegistryError, JwtProviderProfile,
};

fn record(kind: Kind, edit: impl FnOnce(&mut Value)) -> EnterpriseProviderRecord {
    let mut value = json!({
        "provider_id": "acme", "kind": kind, "enabled": true,
        "provenance": { "configured_from": "manual", "trust_material_ref": "jwks-primary" },
        "trust_boundary": { "allowed_issuers": ["https://issuer.example"] },
        "issuer": "https://issuer.example", "jwks_url": "https://issuer.example/jwks",
        "introspection_url": "https://issuer.example/introspect",
        "scim_base_url": "https://issuer.example/scim", "saml_entity_id": "urn:example:saml",
        "saml_metadata_url": "https://issuer.example/metadata",
        "subject_mapping": { "principal_source": "sub", "tenant_id_field": "iss" }
    });
    edit(&mut value);
    serde_json::from_value(value).unwrap_or_else(|error| panic!("fixture record: {error}"))
}

#[test]
fn each_kind_requires_its_members_and_its_trust_boundary() {
    let cases = [
        (Kind::OidcJwks, "issuer", "issuer is required"),
        (
            Kind::OauthIntrospection,
            "introspection_url",
            "introspection_url is required",
        ),
        (Kind::Scim, "scim_base_url", "scim_base_url is required"),
        (
            Kind::Saml,
            "saml_metadata_url",
            "saml_metadata_url is required",
        ),
    ];
    for (kind, member, expected) in cases {
        assert_eq!(record(kind, |_| {}).validate(), Vec::<String>::new());
        let errors = record(kind, |value| value[member] = Value::Null).validate();
        assert!(
            errors.iter().any(|error| error == expected),
            "{kind:?}: {errors:?}"
        );
    }
    let rogue = record(Kind::OidcJwks, |value| {
        value["issuer"] = json!("https://rogue.example")
    });
    assert_eq!(
        rogue.validate(),
        vec!["issuer `https://rogue.example` falls outside trust_boundary.allowed_issuers"]
    );
}

#[test]
fn the_registry_stores_validation_state_and_refuses_inconsistent_files() {
    let mut registry = EnterpriseProviderRegistry::default();
    let invalid = registry.upsert(record(Kind::OidcJwks, |value| {
        value["issuer"] = Value::Null
    }));
    assert!(!invalid.validation_errors.is_empty());
    assert!(registry.validated_provider("acme").is_none());
    registry.upsert(record(Kind::OidcJwks, |_| {}));
    assert!(registry.validated_provider("acme").is_some());
    assert!(registry.remove("acme") && !registry.remove("acme"));

    let stale = EnterpriseProviderRegistry {
        version: "chio.enterprise-providers.v0".to_owned(),
        ..EnterpriseProviderRegistry::default()
    };
    assert_eq!(
        stale.revalidated(),
        Err(EnterpriseProviderRegistryError::UnsupportedVersion(
            "chio.enterprise-providers.v0".to_owned()
        ))
    );
    let mut aliased = EnterpriseProviderRegistry::default();
    aliased
        .providers
        .insert("alias".to_owned(), record(Kind::OidcJwks, |_| {}));
    let error = aliased.revalidated().err();
    assert_eq!(
        error,
        Some(EnterpriseProviderRegistryError::ProviderKeyMismatch)
    );
    assert_eq!(
        error.map(|error| error.to_string()).as_deref(),
        Some("enterprise provider map key must match provider_id")
    );
}

#[test]
fn provider_profiles_use_their_registry_names() {
    for profile in JwtProviderProfile::ALL {
        assert_eq!(profile.as_str().parse::<JwtProviderProfile>(), Ok(profile));
        let decoded = record(Kind::OidcJwks, |value| {
            value["provider_profile"] = json!(profile.as_str());
        });
        assert_eq!(decoded.provider_profile, Some(profile));
    }
    let mut unknown = serde_json::to_value(record(Kind::OidcJwks, |_| {}))
        .unwrap_or_else(|error| panic!("{error}"));
    unknown["provider_profile"] = json!("AzureAd");
    let error = serde_json::from_value::<EnterpriseProviderRecord>(unknown)
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        error.as_deref(),
        Some("unsupported jwt provider profile `AzureAd`")
    );
}
