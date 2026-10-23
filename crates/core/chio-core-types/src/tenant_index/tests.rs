use alloc::string::String;
use alloc::vec::Vec;

use chio_test_support::prelude::*;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    IndexPurpose, KeyedIndexValue, TenantIndexKey, TenantIndexKeySet, TENANT_BINDING_DOMAIN,
    TENANT_INDEX_HKDF_SALT, TENANT_INDEX_KEY_ID_DOMAIN,
};

const KAT: &str = include_str!("../../tests/fixtures/tenant_index_kat_v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Kat {
    schema: String,
    generator: String,
    key_id_domain_hex: String,
    hkdf_salt_hex: String,
    generations: Vec<KatGeneration>,
    values: Vec<KatValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KatGeneration {
    set_key_hex: String,
    key_id_hex: String,
    subkeys_hex: KatSubkeys,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KatSubkeys {
    tenant_binding: String,
    tenant_tag: String,
    subject_tag: String,
    enterprise_subject: String,
    active_defense_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KatValue {
    generation: usize,
    purpose: String,
    domain_hex: String,
    preimage_hex: String,
    value_hex: String,
    string_form: String,
}

fn kat() -> Kat {
    serde_json::from_str(KAT).test_unwrap()
}

fn set_key(hex_text: &str) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(hex_text, &mut bytes).test_unwrap();
    bytes
}

fn purpose_named(name: &str) -> IndexPurpose {
    IndexPurpose::ALL
        .into_iter()
        .find(|purpose| purpose.label().replace('-', "_") == name)
        .test_unwrap()
}

#[test]
fn kat_constants_match_reference() {
    let kat = kat();
    assert_eq!(kat.schema, "chio.tenant-index-kat.v1");
    assert!(kat.generator.contains("gen-tenant-index-kat.py"));
    assert_eq!(
        kat.key_id_domain_hex,
        hex::encode(TENANT_INDEX_KEY_ID_DOMAIN)
    );
    assert_eq!(kat.hkdf_salt_hex, hex::encode(TENANT_INDEX_HKDF_SALT));
}

#[test]
fn hkdf_subkeys_match_reference() {
    let kat = kat();
    assert_eq!(kat.generations.len(), 3);
    for generation in &kat.generations {
        let key = TenantIndexKey::from_set_key(&set_key(&generation.set_key_hex)).test_unwrap();
        assert_eq!(key.key_id().to_bare_hex(), generation.key_id_hex);
        let expected = [
            (
                IndexPurpose::TenantBinding,
                &generation.subkeys_hex.tenant_binding,
            ),
            (IndexPurpose::TenantTag, &generation.subkeys_hex.tenant_tag),
            (
                IndexPurpose::SubjectTag,
                &generation.subkeys_hex.subject_tag,
            ),
            (
                IndexPurpose::EnterpriseSubject,
                &generation.subkeys_hex.enterprise_subject,
            ),
            (
                IndexPurpose::ActiveDefenseDigest,
                &generation.subkeys_hex.active_defense_digest,
            ),
        ];
        for (purpose, subkey_hex) in expected {
            assert_eq!(&hex::encode(key.subkey(purpose)), subkey_hex, "{purpose:?}");
        }
    }
}

#[test]
fn hmac_values_match_reference() {
    let kat = kat();
    assert!(kat.values.len() >= 15);
    for case in &kat.values {
        let generation = kat.generations.get(case.generation).test_unwrap();
        let key = TenantIndexKey::from_set_key(&set_key(&generation.set_key_hex)).test_unwrap();
        let set = TenantIndexKeySet::new(key, Vec::new()).test_unwrap();
        let purpose = purpose_named(&case.purpose);
        let domain = hex::decode(&case.domain_hex).test_unwrap();
        let preimage = hex::decode(&case.preimage_hex).test_unwrap();
        let derived = set.derive(purpose, &domain, &preimage);
        assert_eq!(derived.key_id.to_bare_hex(), generation.key_id_hex);
        assert_eq!(derived.value.to_bare_hex(), case.value_hex);
        assert_eq!(derived.to_string_form(purpose), case.string_form);
        assert_eq!(
            KeyedIndexValue::parse_string_form(purpose, &case.string_form).test_unwrap(),
            derived
        );
        if purpose == IndexPurpose::TenantBinding && domain == TENANT_BINDING_DOMAIN {
            let tenant = core::str::from_utf8(&preimage).test_unwrap();
            let binding = set.bind(tenant);
            assert_eq!(binding.keyed_value(), derived);
        }
    }
}

#[test]
fn zeroize_wipes_every_subkey() {
    fn zeroized_on_drop<T: ZeroizeOnDrop>() {}
    zeroized_on_drop::<TenantIndexKey>();
    let mut key = TenantIndexKey::from_set_key(&[7; 32]).test_unwrap();
    assert!(IndexPurpose::ALL
        .into_iter()
        .all(|purpose| key.subkey(purpose) != &[0; 32]));
    key.zeroize();
    assert!(IndexPurpose::ALL
        .into_iter()
        .all(|purpose| key.subkey(purpose) == &[0; 32]));
}
