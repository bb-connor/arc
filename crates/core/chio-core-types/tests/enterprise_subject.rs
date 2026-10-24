//! Keyed enterprise subjects, SCIM capability ids and SCIM policy hashes.

use chio_core_types::enterprise_subject::{
    EnterpriseSubjectError, EnterpriseSubjectKey, ScimCapabilityId, ScimPolicyHash,
    SCIM_CAPABILITY_ID_PREFIX,
};
use chio_core_types::root_authority::Sha256Digest;
use chio_core_types::tenant_index::{
    IndexPurpose, KeyedIndexValue, TenantBindingError, TenantIndexKey, TenantIndexKeySet,
};
use chio_test_support::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const KAT: &str = include_str!("fixtures/enterprise_subject_kat_v1.json");
const TENANT_INDEX_KAT: &str = include_str!("fixtures/tenant_index_kat_v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Kat {
    schema: String,
    generator: String,
    generations: Vec<KatGeneration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KatGeneration {
    set_key_hex: String,
    key_id_hex: String,
    subjects: Vec<KatSubject>,
    scim_capabilities: Vec<KatCapability>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KatSubject {
    provider_scope: String,
    principal: String,
    subject: String,
    scim_policy_provider_id: String,
    scim_policy_hash_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KatCapability {
    provider_id: String,
    user_id: String,
    capability_id: String,
}

fn key(byte: u8) -> TenantIndexKey {
    TenantIndexKey::from_set_key(&[byte; 32]).test_unwrap()
}

fn key_id(byte: u8) -> Sha256Digest {
    *key(byte).key_id()
}

fn set(active: u8, retired: &[u8]) -> TenantIndexKeySet {
    TenantIndexKeySet::new(key(active), retired.iter().map(|byte| key(*byte)).collect())
        .test_unwrap()
}

fn set_from_hex(hex_text: &str) -> TenantIndexKeySet {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(hex_text, &mut bytes).test_unwrap();
    TenantIndexKeySet::new(
        TenantIndexKey::from_set_key(&bytes).test_unwrap(),
        Vec::new(),
    )
    .test_unwrap()
}

fn subject(keys: &TenantIndexKeySet, scope: &str, principal: &str) -> EnterpriseSubjectKey {
    EnterpriseSubjectKey::derive(keys, scope, principal).test_unwrap()
}

#[test]
fn enterprise_subject_kat_matches_reference() {
    let kat: Kat = serde_json::from_str(KAT).test_unwrap();
    assert_eq!(kat.schema, "chio.enterprise-subject-kat.v1");
    assert!(kat.generator.contains("gen-enterprise-subject-kat.py"));
    assert_eq!(kat.generations.len(), 3);
    for generation in &kat.generations {
        let keys = set_from_hex(&generation.set_key_hex);
        assert_eq!(keys.active_key_id().to_bare_hex(), generation.key_id_hex);
        assert_eq!(generation.subjects.len(), 6);
        for vector in &generation.subjects {
            let derived = subject(&keys, &vector.provider_scope, &vector.principal);
            assert_eq!(derived.to_string(), vector.subject);
            assert_eq!(
                EnterpriseSubjectKey::parse(&vector.subject).test_unwrap(),
                derived
            );
            let policy = ScimPolicyHash::derive(&keys, &vector.scim_policy_provider_id, &derived)
                .test_unwrap();
            assert_eq!(policy.to_hex(), vector.scim_policy_hash_hex);
            assert_eq!(policy.key_id(), keys.active_key_id());
        }
        assert_eq!(generation.scim_capabilities.len(), 3);
        for vector in &generation.scim_capabilities {
            let derived =
                ScimCapabilityId::derive(&keys, &vector.provider_id, &vector.user_id).test_unwrap();
            assert_eq!(derived.to_string(), vector.capability_id);
        }
    }
}

#[test]
fn enterprise_subject_kat_agrees_with_the_tenant_index_kat() {
    let kat: Kat = serde_json::from_str(KAT).test_unwrap();
    let reference: serde_json::Value = serde_json::from_str(TENANT_INDEX_KAT).test_unwrap();
    let values = reference
        .get("values")
        .and_then(serde_json::Value::as_array)
        .test_unwrap();
    let mut checked = 0;
    for (index, generation) in kat.generations.iter().enumerate().take(2) {
        let reference_form = values
            .iter()
            .find(|value| {
                value.get("generation").and_then(serde_json::Value::as_u64)
                    == u64::try_from(index).ok()
                    && value.get("purpose").and_then(serde_json::Value::as_str)
                        == Some("enterprise_subject")
            })
            .and_then(|value| value.get("string_form"))
            .and_then(serde_json::Value::as_str)
            .test_unwrap();
        let vector = generation
            .subjects
            .iter()
            .find(|vector| vector.provider_scope == "scope-a" && vector.principal == "alice")
            .test_unwrap();
        assert_eq!(vector.subject, reference_form);
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
fn enterprise_subject_string_form_round_trips() {
    let keys = set(1, &[]);
    let derived = subject(
        &keys,
        "https://idp.example",
        "oidc:https://idp.example#sub:u-1",
    );
    let text = derived.to_string();
    assert_eq!(
        text,
        derived
            .keyed_value()
            .to_string_form(IndexPurpose::EnterpriseSubject)
    );
    assert!(text.starts_with("esk1."));
    assert_eq!(EnterpriseSubjectKey::parse(&text), Ok(derived));
    let encoded = serde_json::to_string(&derived).test_unwrap();
    assert_eq!(encoded, format!("\"{text}\""));
    assert_eq!(
        serde_json::from_str::<EnterpriseSubjectKey>(&encoded).test_unwrap(),
        derived
    );
}

#[test]
fn old_unkeyed_shape_refuses() {
    let unkeyed = hex::encode(Sha256::digest(
        b"chio.identity_federation.v1\x01scope\x00alice",
    ));
    assert_eq!(unkeyed.len(), 64);
    let malformed = EnterpriseSubjectError::Index(TenantBindingError::MalformedStringForm {
        purpose: IndexPurpose::EnterpriseSubject,
    });
    let derived = subject(&set(1, &[]), "scope", "alice");
    let value_hex = derived.keyed_value().value.to_bare_hex();
    let key_hex = derived.key_id().to_bare_hex();
    for candidate in [
        unkeyed.clone(),
        format!("esk1.{unkeyed}"),
        format!("esk1.{value_hex}"),
        format!("{key_hex}.{value_hex}"),
        format!("tt1.{key_hex}.{value_hex}"),
        format!("{SCIM_CAPABILITY_ID_PREFIX}{derived}"),
        derived.to_string().to_uppercase(),
    ] {
        assert_eq!(
            EnterpriseSubjectKey::parse(&candidate),
            Err(malformed),
            "accepted {candidate:?}"
        );
    }
    let decoded = serde_json::from_str::<EnterpriseSubjectKey>(&format!("\"{unkeyed}\""));
    assert_eq!(
        decoded.test_unwrap_err().to_string(),
        "keyed index value is not `esk1.<64 hex>.<64 hex>`"
    );
}

#[test]
fn unknown_generation_refuses() {
    let derived = subject(&set(1, &[]), "scope", "alice");
    let unknown = EnterpriseSubjectError::Index(TenantBindingError::TenantIndexKeyUnknown {
        key_id: key_id(1),
    });
    assert_eq!(
        derived.verify(&set(2, &[3]), "scope", "alice"),
        Err(unknown)
    );
    let policy = ScimPolicyHash::derive(&set(1, &[]), "scim-provider", &derived).test_unwrap();
    assert_eq!(
        ScimPolicyHash::verify(
            &set(2, &[]),
            policy.key_id(),
            &policy.to_hex(),
            "scim-provider",
            &derived,
        ),
        Err(unknown)
    );
}

#[test]
fn enterprise_subject_verifies_across_generations() {
    let before = set(1, &[]);
    let old = subject(&before, "scope", "alice");
    let after = set(2, &[1]);
    let new = subject(&after, "scope", "alice");
    assert_eq!(old.key_id(), &key_id(1));
    assert_eq!(new.key_id(), &key_id(2));
    assert_ne!(old, new);
    assert_ne!(old.keyed_value().value, new.keyed_value().value);
    assert_eq!(old.verify(&after, "scope", "alice"), Ok(()));
    assert_eq!(new.verify(&after, "scope", "alice"), Ok(()));
    let mismatch = Err(EnterpriseSubjectError::Index(TenantBindingError::Mismatch));
    assert_eq!(old.verify(&after, "scope", "bob"), mismatch);
    assert_eq!(old.verify(&after, "other-scope", "alice"), mismatch);
}

#[test]
fn cross_generation_values_are_never_equal_by_value() {
    let keys = set(2, &[1]);
    let old = subject(&set(1, &[]), "scope", "alice");
    let value_hex = old.keyed_value().value.to_bare_hex();
    let relabeled =
        EnterpriseSubjectKey::parse(&format!("esk1.{}.{value_hex}", key_id(2).to_bare_hex()))
            .test_unwrap();
    assert_eq!(relabeled.keyed_value().value, old.keyed_value().value);
    assert_ne!(relabeled, old);
    assert_eq!(
        relabeled.verify(&keys, "scope", "alice"),
        Err(EnterpriseSubjectError::Index(TenantBindingError::Mismatch))
    );
    assert_eq!(old.verify(&keys, "scope", "alice"), Ok(()));
}

#[test]
fn length_prefixes_keep_scope_and_principal_apart() {
    let keys = set(1, &[]);
    let pairs = [
        ("ab", "c"),
        ("a", "bc"),
        ("abc", ""),
        ("", "abc"),
        ("a\u{0}", "bc"),
        ("a", "\u{0}bc"),
    ];
    let derived: Vec<EnterpriseSubjectKey> = pairs
        .iter()
        .map(|(scope, principal)| subject(&keys, scope, principal))
        .collect();
    for (index, left) in derived.iter().enumerate() {
        for right in derived.iter().skip(index + 1) {
            assert_ne!(left, right);
        }
    }
}

#[test]
fn distinct_scopes_and_deployments_do_not_alias() {
    let deployment_a = set(1, &[]);
    let deployment_b = set(2, &[]);
    let in_a = subject(&deployment_a, "https://idp-a.example", "alice");
    assert_ne!(
        in_a,
        subject(&deployment_a, "https://idp-b.example", "alice")
    );
    let in_b = subject(&deployment_b, "https://idp-a.example", "alice");
    assert_ne!(in_a.keyed_value().value, in_b.keyed_value().value);
    assert_eq!(
        in_a.verify(&deployment_b, "https://idp-a.example", "alice"),
        Err(EnterpriseSubjectError::Index(
            TenantBindingError::TenantIndexKeyUnknown { key_id: key_id(1) }
        ))
    );
}

#[test]
fn a_dictionary_of_principals_cannot_reconstruct_a_subject_without_the_key() {
    let deployment = set(1, &[]);
    let retained = subject(&deployment, "https://idp.example", "user-42");
    let guess_key = set(9, &[]);
    for index in 0..256 {
        let principal = format!("user-{index}");
        let guessed = subject(&guess_key, "https://idp.example", &principal);
        assert_ne!(guessed.keyed_value().value, retained.keyed_value().value);
        for unkeyed in [
            Sha256::digest(principal.as_bytes()),
            Sha256::digest(format!("https://idp.example:{principal}").as_bytes()),
            Sha256::digest(
                format!("chio.identity_federation.v1\u{1}https://idp.example\u{0}{principal}")
                    .as_bytes(),
            ),
        ] {
            assert_ne!(unkeyed.as_slice(), retained.keyed_value().value.as_bytes());
        }
    }
}

#[test]
fn scim_capability_id_is_keyed() {
    let keys = set(1, &[]);
    let capability = ScimCapabilityId::derive(&keys, "scim-provider", "user-1").test_unwrap();
    let text = capability.to_string();
    let suffix = text.strip_prefix("scim-user:").test_unwrap();
    assert_eq!(
        KeyedIndexValue::parse_string_form(IndexPurpose::EnterpriseSubject, suffix),
        Ok(*capability.keyed_value())
    );
    assert_eq!(capability.keyed_value().key_id, key_id(1));
    assert!(!text.contains("user-1"));
    assert!(!text.contains("scim-provider"));
    assert_ne!(
        capability,
        ScimCapabilityId::derive(&keys, "scim-provider", "user-2").test_unwrap()
    );
    assert_ne!(
        capability,
        ScimCapabilityId::derive(&keys, "scim-provider-2", "user-1").test_unwrap()
    );
    assert_ne!(
        capability.keyed_value().value,
        ScimCapabilityId::derive(&set(2, &[]), "scim-provider", "user-1")
            .test_unwrap()
            .keyed_value()
            .value
    );
}

#[test]
fn scim_policy_hash_is_keyed_and_verifies_under_its_recorded_generation() {
    let before = set(1, &[]);
    let alice = subject(&before, "scim-provider", "alice");
    let policy = ScimPolicyHash::derive(&before, "scim-provider", &alice).test_unwrap();
    let hash_hex = policy.to_hex();
    assert_eq!(hash_hex.len(), 64);
    let after = set(2, &[1]);
    assert_eq!(
        ScimPolicyHash::verify(&after, &key_id(1), &hash_hex, "scim-provider", &alice),
        Ok(())
    );
    let mismatch = Err(EnterpriseSubjectError::Index(TenantBindingError::Mismatch));
    assert_eq!(
        ScimPolicyHash::verify(&after, &key_id(2), &hash_hex, "scim-provider", &alice),
        mismatch
    );
    let bob = subject(&before, "scim-provider", "bob");
    assert_eq!(
        ScimPolicyHash::verify(&after, &key_id(1), &hash_hex, "scim-provider", &bob),
        mismatch
    );
    assert_eq!(
        ScimPolicyHash::verify(&after, &key_id(1), &hash_hex, "other-provider", &alice),
        mismatch
    );
    for malformed in [
        hash_hex.to_uppercase(),
        format!("sha256:{hash_hex}"),
        hash_hex.get(..63).test_unwrap().to_owned(),
        format!("{hash_hex}0"),
        String::new(),
    ] {
        assert_eq!(
            ScimPolicyHash::verify(&after, &key_id(1), &malformed, "scim-provider", &alice),
            Err(EnterpriseSubjectError::MalformedPolicyHash),
            "accepted {malformed:?}"
        );
    }
}

#[test]
fn subject_and_scim_values_never_verify_in_each_others_domain() {
    let keys = set(1, &[]);
    let alice = subject(&keys, "scim-provider", "alice");
    let capability = ScimCapabilityId::derive(&keys, "scim-provider", "alice").test_unwrap();
    assert_ne!(alice.keyed_value(), capability.keyed_value());
    let policy = ScimPolicyHash::derive(&keys, "scim-provider", &alice).test_unwrap();
    let policy_value = policy.to_hex();
    assert_ne!(alice.keyed_value().value.to_bare_hex(), policy_value);
    assert_ne!(capability.keyed_value().value.to_bare_hex(), policy_value);
}
