//! Tenant index key set: purpose isolation, generations, string forms and loading.

use chio_core_types::root_authority::Sha256Digest;
use chio_core_types::tenant_index::{
    IndexPurpose, KeyedIndexValue, TenantBinding, TenantBindingError, TenantIndexKey,
    TenantIndexKeySet, TENANT_BINDING_DOMAIN,
};
use chio_test_support::prelude::*;

const TAG_DOMAIN: &[u8] = b"chio.tenant-tag.v1\0";

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

#[test]
fn index_value_never_verifies_under_another_purpose() {
    let keys = set(1, &[]);
    let preimage = b"issuer\0shared-preimage";
    for derived_purpose in IndexPurpose::ALL {
        let value = keys.derive(derived_purpose, TAG_DOMAIN, preimage);
        for verify_purpose in IndexPurpose::ALL {
            let verdict = keys.verify_value(verify_purpose, TAG_DOMAIN, preimage, &value);
            if verify_purpose == derived_purpose {
                assert_eq!(verdict, Ok(()));
            } else {
                assert_eq!(
                    verdict,
                    Err(TenantBindingError::Mismatch),
                    "{derived_purpose:?} verified under {verify_purpose:?}"
                );
            }
        }
    }
}

#[test]
fn purpose_labels_and_prefixes_are_distinct() {
    for (index, left) in IndexPurpose::ALL.iter().enumerate() {
        for right in IndexPurpose::ALL.iter().skip(index + 1) {
            assert_ne!(left.label(), right.label());
            assert_ne!(left.string_prefix(), right.string_prefix());
        }
    }
}

#[test]
fn index_value_refuses_another_domain_or_preimage() {
    let keys = set(1, &[]);
    let value = keys.derive(IndexPurpose::TenantTag, TAG_DOMAIN, b"acme");
    assert_eq!(
        keys.verify_value(
            IndexPurpose::TenantTag,
            b"chio.subject-tag.v1\0",
            b"acme",
            &value
        ),
        Err(TenantBindingError::Mismatch)
    );
    assert_eq!(
        keys.verify_value(IndexPurpose::TenantTag, TAG_DOMAIN, b"acmf", &value),
        Err(TenantBindingError::Mismatch)
    );
}

#[test]
fn index_value_verifies_across_generations() {
    let before = set(1, &[]);
    let old = before.derive(IndexPurpose::SubjectTag, TAG_DOMAIN, b"user-1");
    let after = set(2, &[1]);
    let new = after.derive(IndexPurpose::SubjectTag, TAG_DOMAIN, b"user-1");
    assert_eq!(old.key_id, key_id(1));
    assert_eq!(new.key_id, key_id(2));
    assert_ne!(old.value, new.value);
    assert_eq!(
        after.verify_value(IndexPurpose::SubjectTag, TAG_DOMAIN, b"user-1", &old),
        Ok(())
    );
    assert_eq!(
        after.verify_value(IndexPurpose::SubjectTag, TAG_DOMAIN, b"user-1", &new),
        Ok(())
    );
    let forged = KeyedIndexValue {
        key_id: new.key_id,
        value: old.value,
    };
    assert_eq!(
        after.verify_value(IndexPurpose::SubjectTag, TAG_DOMAIN, b"user-1", &forged),
        Err(TenantBindingError::Mismatch)
    );
}

#[test]
fn tenant_binding_verifies_after_rotation() {
    let before = set(1, &[]);
    let binding = before.bind("tenant-acme");
    assert_eq!(binding.key_id, key_id(1));
    let after = set(2, &[1]);
    assert_eq!(after.verify("tenant-acme", &binding), Ok(()));
    assert_eq!(
        after.verify("tenant-other", &binding),
        Err(TenantBindingError::Mismatch)
    );
    assert_eq!(after.bind("tenant-acme").key_id, key_id(2));
}

#[test]
fn tenant_binding_is_the_tenant_binding_purpose_value() {
    let keys = set(3, &[]);
    let binding = keys.bind("tenant-acme");
    assert_eq!(
        binding.keyed_value(),
        keys.derive(
            IndexPurpose::TenantBinding,
            TENANT_BINDING_DOMAIN,
            b"tenant-acme"
        )
    );
}

#[test]
fn index_value_unknown_key_id_refuses() {
    let retired_only = set(1, &[]).derive(IndexPurpose::TenantTag, TAG_DOMAIN, b"acme");
    let keys = set(2, &[3]);
    let unknown = TenantBindingError::TenantIndexKeyUnknown { key_id: key_id(1) };
    assert_eq!(
        keys.verify_value(IndexPurpose::TenantTag, TAG_DOMAIN, b"acme", &retired_only),
        Err(unknown)
    );
    assert_eq!(
        keys.derive_in(&key_id(1), IndexPurpose::TenantTag, TAG_DOMAIN, b"acme"),
        Err(unknown)
    );
}

#[test]
fn tenant_binding_unknown_key_id_refuses() {
    let binding = set(1, &[]).bind("tenant-acme");
    assert_eq!(
        set(2, &[]).verify("tenant-acme", &binding),
        Err(TenantBindingError::TenantIndexKeyUnknown { key_id: key_id(1) })
    );
}

#[test]
fn derive_in_uses_a_retired_generation() {
    let old = set(1, &[]).derive(IndexPurpose::TenantTag, TAG_DOMAIN, b"acme");
    let keys = set(2, &[1, 3]);
    assert_eq!(
        keys.derive_in(&key_id(1), IndexPurpose::TenantTag, TAG_DOMAIN, b"acme"),
        Ok(old)
    );
    let candidates: Vec<KeyedIndexValue> = keys
        .key_ids()
        .map(|id| {
            keys.derive_in(id, IndexPurpose::TenantTag, TAG_DOMAIN, b"acme")
                .test_unwrap()
        })
        .collect();
    assert_eq!(candidates.len(), 3);
    assert!(candidates.contains(&old));
}

#[test]
fn key_ids_list_active_first_then_retired_in_key_id_order() {
    let keys = set(9, &[4, 1, 7]);
    let ids: Vec<Sha256Digest> = keys.key_ids().copied().collect();
    let mut retired = vec![key_id(4), key_id(1), key_id(7)];
    retired.sort();
    assert_eq!(ids.first(), Some(&key_id(9)));
    assert_eq!(ids.get(1..), Some(retired.as_slice()));
    assert_eq!(keys.active_key_id(), &key_id(9));
}

#[test]
fn key_set_refuses_duplicate_key_id() {
    assert_eq!(
        TenantIndexKeySet::new(key(1), vec![key(1)]).test_unwrap_err(),
        TenantBindingError::DuplicateKeyId { key_id: key_id(1) }
    );
    assert_eq!(
        TenantIndexKeySet::new(key(1), vec![key(2), key(2)]).test_unwrap_err(),
        TenantBindingError::DuplicateKeyId { key_id: key_id(2) }
    );
}

#[test]
fn index_value_string_form_parses_exactly() {
    let value = set(1, &[]).derive(IndexPurpose::EnterpriseSubject, TAG_DOMAIN, b"alice");
    let text = value.to_string_form(IndexPurpose::EnterpriseSubject);
    let key_hex = value.key_id.to_bare_hex();
    let value_hex = value.value.to_bare_hex();
    assert_eq!(text, format!("esk1.{key_hex}.{value_hex}"));
    assert_eq!(
        KeyedIndexValue::parse_string_form(IndexPurpose::EnterpriseSubject, &text),
        Ok(value)
    );
    for purpose in IndexPurpose::ALL {
        let form = value.to_string_form(purpose);
        assert!(form.starts_with(purpose.string_prefix()));
        assert_eq!(
            KeyedIndexValue::parse_string_form(purpose, &form),
            Ok(value)
        );
    }

    let refused = [
        text.to_uppercase(),
        format!("ESK1.{key_hex}.{value_hex}"),
        format!("esk1.{}.{value_hex}", key_hex.to_uppercase()),
        format!("esk1.{key_hex}.{}", value_hex.to_uppercase()),
        format!("esk1.{key_hex}.{value_hex}."),
        format!(".esk1.{key_hex}.{value_hex}"),
        format!("esk1..{key_hex}.{value_hex}"),
        format!("esk1.{key_hex}.{value_hex}.00"),
        format!("esk1.{key_hex}{value_hex}"),
        format!("esk1.{}.{value_hex}", &key_hex[1..]),
        format!("esk1.{key_hex}0.{value_hex}"),
        format!("esk1.{key_hex}.{}", &value_hex[..62]),
        format!("esk1.{key_hex}.{value_hex}00"),
        format!("esk1.sha256:{key_hex}.{value_hex}"),
        format!("esk1.{key_hex}.{}g", &value_hex[..63]),
        format!("esk1.{key_hex}.{value_hex} "),
        format!("esk.{key_hex}.{value_hex}"),
        format!("esk2.{key_hex}.{value_hex}"),
        format!("tt1.{key_hex}.{value_hex}"),
        format!("tb1.{key_hex}.{value_hex}"),
        String::new(),
        "esk1".to_owned(),
    ];
    for candidate in refused {
        assert_eq!(
            KeyedIndexValue::parse_string_form(IndexPurpose::EnterpriseSubject, &candidate),
            Err(TenantBindingError::MalformedStringForm {
                purpose: IndexPurpose::EnterpriseSubject
            }),
            "accepted {candidate:?}"
        );
    }
}

#[test]
fn tenant_binding_wire_form_is_strict() {
    let binding = set(1, &[]).bind("tenant-acme");
    let encoded = serde_json::to_value(binding).test_unwrap();
    assert_eq!(
        encoded.get("alg").and_then(|alg| alg.as_str()),
        Some("hkdf-hmac-sha256")
    );
    assert_eq!(
        serde_json::from_value::<TenantBinding>(encoded.clone()).test_unwrap(),
        binding
    );

    let mut padded = encoded.clone();
    if let Some(object) = padded.as_object_mut() {
        object.insert("extra".to_owned(), serde_json::Value::Bool(true));
    }
    assert!(serde_json::from_value::<TenantBinding>(padded).is_err());

    let mut other_alg = encoded;
    if let Some(object) = other_alg.as_object_mut() {
        object.insert("alg".to_owned(), "hmac-sha256".into());
    }
    assert!(serde_json::from_value::<TenantBinding>(other_alg).is_err());
}

#[test]
fn key_debug_never_prints_key_material() {
    let rendered = format!("{:?}", set(1, &[2]));
    assert!(rendered.contains("key_id"));
    assert!(!rendered.contains("subkeys"));
}

#[cfg(unix)]
mod load {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    use chio_core_types::tenant_index::{TenantIndexKeyLoadError, TenantIndexKeySet};
    use chio_test_support::prelude::*;

    use super::key_id;

    fn write_key(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).test_unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).test_unwrap();
    }

    fn provision(dir: &Path, active: u8, retired: &[u8]) {
        write_key(&dir.join("active"), &[active; 32]);
        if !retired.is_empty() {
            let retired_dir = dir.join("retired");
            fs::create_dir(&retired_dir).test_unwrap();
            for byte in retired {
                write_key(&retired_dir.join(key_id(*byte).to_bare_hex()), &[*byte; 32]);
            }
        }
    }

    #[test]
    fn tenant_index_keys_load_active_and_retired() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[3, 4]);
        let keys = TenantIndexKeySet::load_dir(dir.path()).test_unwrap();
        let ids: Vec<_> = keys.key_ids().copied().collect();
        let mut expected = vec![key_id(3), key_id(4)];
        expected.sort();
        expected.insert(0, key_id(5));
        assert_eq!(ids, expected);
        let binding = super::set(3, &[]).bind("tenant-acme");
        assert_eq!(keys.verify("tenant-acme", &binding), Ok(()));
    }

    #[test]
    fn tenant_index_keys_load_without_retired_directory() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        let keys = TenantIndexKeySet::load_dir(dir.path()).test_unwrap();
        assert_eq!(keys.key_ids().count(), 1);
    }

    #[test]
    fn tenant_index_keys_refuse_missing_active() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        fs::create_dir(dir.path().join("retired")).test_unwrap();
        assert!(matches!(
            TenantIndexKeySet::load_dir(dir.path()),
            Err(TenantIndexKeyLoadError::MissingActive { .. })
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_wrong_length() {
        for length in [0_usize, 31, 33, 64] {
            let dir = chio_test_support::private_tempdir().test_unwrap();
            write_key(&dir.path().join("active"), &vec![7; length]);
            assert!(
                matches!(
                    TenantIndexKeySet::load_dir(dir.path()),
                    Err(TenantIndexKeyLoadError::WrongLength { .. })
                ),
                "accepted a {length}-byte key"
            );
        }
    }

    #[test]
    fn tenant_index_keys_refuse_loose_permissions() {
        for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o601] {
            let dir = chio_test_support::private_tempdir().test_unwrap();
            provision(dir.path(), 5, &[]);
            let path = dir.path().join("active");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).test_unwrap();
            assert!(
                matches!(
                    TenantIndexKeySet::load_dir(dir.path()),
                    Err(TenantIndexKeyLoadError::LoosePermissions { .. })
                ),
                "accepted mode {mode:o}"
            );
        }
    }

    #[test]
    fn tenant_index_keys_refuse_loose_retired_permissions() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[3]);
        let path = dir.path().join("retired").join(key_id(3).to_bare_hex());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).test_unwrap();
        assert!(matches!(
            TenantIndexKeySet::load_dir(dir.path()),
            Err(TenantIndexKeyLoadError::LoosePermissions { .. })
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_duplicate_key_id() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[5]);
        assert!(matches!(
            TenantIndexKeySet::load_dir(dir.path()),
            Err(TenantIndexKeyLoadError::KeySet(
                chio_core_types::tenant_index::TenantBindingError::DuplicateKeyId { .. }
            ))
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_misnamed_retired_key() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        let retired_dir = dir.path().join("retired");
        fs::create_dir(&retired_dir).test_unwrap();
        write_key(&retired_dir.join(key_id(4).to_bare_hex()), &[3; 32]);
        assert!(matches!(
            TenantIndexKeySet::load_dir(dir.path()),
            Err(TenantIndexKeyLoadError::RetiredNameMismatch { .. })
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_unexpected_entry() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        write_key(&dir.path().join("active.bak"), &[5; 32]);
        assert!(matches!(
            TenantIndexKeySet::load_dir(dir.path()),
            Err(TenantIndexKeyLoadError::UnexpectedEntry { .. })
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_symlinked_key() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        let target = dir.path().join("elsewhere");
        fs::create_dir(&target).test_unwrap();
        write_key(&target.join("key"), &[5; 32]);
        let keys_dir = dir.path().join("keys");
        fs::create_dir(&keys_dir).test_unwrap();
        symlink(target.join("key"), keys_dir.join("active")).test_unwrap();
        assert!(matches!(
            TenantIndexKeySet::load_dir(&keys_dir),
            Err(TenantIndexKeyLoadError::NotRegularFile { .. })
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_a_file_as_the_directory() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        let path = dir.path().join("active");
        write_key(&path, &[5; 32]);
        assert!(matches!(
            TenantIndexKeySet::load_dir(&path),
            Err(TenantIndexKeyLoadError::NotDirectory { .. })
        ));
    }
}
