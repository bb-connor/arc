//! Tenant index key set: domain and purpose isolation, generations, string forms and loading.

use chio_core_types::root_authority::Sha256Digest;
use chio_core_types::tenant_index::{
    IndexDomain, IndexPurpose, KeyedIndexValue, TenantBinding, TenantBindingError, TenantIndexKey,
    TenantIndexKeySet,
};
use chio_test_support::prelude::*;

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
fn every_domain_belongs_to_one_purpose_and_is_nul_terminated_once() {
    let expected = [
        (
            IndexDomain::TenantBinding,
            IndexPurpose::TenantBinding,
            &b"chio.receipt.tenant-binding.v1\0"[..],
        ),
        (
            IndexDomain::TenantTag,
            IndexPurpose::TenantTag,
            &b"chio.tenant-tag.v1\0"[..],
        ),
        (
            IndexDomain::SubjectTag,
            IndexPurpose::SubjectTag,
            &b"chio.subject-tag.v1\0"[..],
        ),
        (
            IndexDomain::EnterpriseSubject,
            IndexPurpose::EnterpriseSubject,
            &b"chio.enterprise-subject.v1\0"[..],
        ),
        (
            IndexDomain::ScimCapability,
            IndexPurpose::EnterpriseSubject,
            &b"chio.scim-capability.v1\0"[..],
        ),
        (
            IndexDomain::ScimPolicy,
            IndexPurpose::EnterpriseSubject,
            &b"chio.scim-policy.v1\0"[..],
        ),
        (
            IndexDomain::ActiveDefenseKeyedDigest,
            IndexPurpose::ActiveDefenseDigest,
            &b"chio.active-defense.keyed-digest.v1\0"[..],
        ),
    ];
    assert_eq!(IndexDomain::ALL.len(), expected.len());
    for (domain, purpose, bytes) in expected {
        assert!(IndexDomain::ALL.contains(&domain));
        assert_eq!(domain.purpose(), purpose);
        assert_eq!(domain.as_bytes(), bytes);
        assert_eq!(bytes.iter().filter(|byte| **byte == 0).count(), 1);
        assert_eq!(bytes.last(), Some(&0));
    }
    for purpose in IndexPurpose::ALL {
        assert!(IndexDomain::ALL
            .iter()
            .any(|domain| domain.purpose() == purpose));
    }
}

#[test]
fn index_value_never_verifies_under_another_purpose() {
    let keys = set(1, &[]);
    let preimage = b"issuer\0shared-preimage";
    for derived_domain in IndexDomain::ALL {
        let value = keys.derive(derived_domain, preimage);
        for verify_domain in IndexDomain::ALL {
            let verdict = keys.verify_value(verify_domain, preimage, &value);
            if verify_domain == derived_domain {
                assert_eq!(verdict, Ok(()));
            } else {
                assert_eq!(
                    verdict,
                    Err(TenantBindingError::Mismatch),
                    "{derived_domain:?} verified under {verify_domain:?}"
                );
            }
        }
    }
}

#[test]
fn a_binding_cannot_be_derived_from_a_caller_shaped_preimage() {
    let keys = set(1, &[]);
    let binding = keys.bind("acme");
    for domain in IndexDomain::ALL {
        let shaped = keys.derive(domain, b"chio.receipt.tenant-binding.v1\0acme");
        assert_ne!(shaped, binding.keyed_value(), "{domain:?}");
        let mut preimage = domain.as_bytes().to_vec();
        preimage.extend_from_slice(b"acme");
        assert_ne!(
            keys.derive(domain, &preimage),
            binding.keyed_value(),
            "{domain:?}"
        );
    }
    assert_eq!(
        keys.derive(IndexDomain::TenantBinding, b"acme"),
        binding.keyed_value()
    );
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
fn index_value_refuses_another_preimage() {
    let keys = set(1, &[]);
    let value = keys.derive(IndexDomain::TenantTag, b"acme");
    assert_eq!(
        keys.verify_value(IndexDomain::TenantTag, b"acmf", &value),
        Err(TenantBindingError::Mismatch)
    );
}

#[test]
fn index_value_verifies_across_generations() {
    let before = set(1, &[]);
    let old = before.derive(IndexDomain::SubjectTag, b"user-1");
    let after = set(2, &[1]);
    let new = after.derive(IndexDomain::SubjectTag, b"user-1");
    assert_eq!(old.key_id, key_id(1));
    assert_eq!(new.key_id, key_id(2));
    assert_ne!(old.value, new.value);
    assert_eq!(
        after.verify_value(IndexDomain::SubjectTag, b"user-1", &old),
        Ok(())
    );
    assert_eq!(
        after.verify_value(IndexDomain::SubjectTag, b"user-1", &new),
        Ok(())
    );
    let forged = KeyedIndexValue {
        key_id: new.key_id,
        value: old.value,
    };
    assert_eq!(
        after.verify_value(IndexDomain::SubjectTag, b"user-1", &forged),
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
fn index_value_unknown_key_id_refuses() {
    let retired_only = set(1, &[]).derive(IndexDomain::TenantTag, b"acme");
    let keys = set(2, &[3]);
    let unknown = TenantBindingError::TenantIndexKeyUnknown { key_id: key_id(1) };
    assert_eq!(
        keys.verify_value(IndexDomain::TenantTag, b"acme", &retired_only),
        Err(unknown)
    );
    assert_eq!(
        keys.derive_in(&key_id(1), IndexDomain::TenantTag, b"acme"),
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
    let old = set(1, &[]).derive(IndexDomain::TenantTag, b"acme");
    let keys = set(2, &[1, 3]);
    assert_eq!(
        keys.derive_in(&key_id(1), IndexDomain::TenantTag, b"acme"),
        Ok(old)
    );
    let candidates: Vec<KeyedIndexValue> = keys
        .key_ids()
        .map(|id| {
            keys.derive_in(id, IndexDomain::TenantTag, b"acme")
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
    let value = set(1, &[]).derive(IndexDomain::EnterpriseSubject, b"alice");
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
    assert_eq!(
        serde_json::from_value::<TenantBinding>(padded)
            .test_unwrap_err()
            .to_string(),
        "unknown field `extra`, expected one of `alg`, `key_id`, `value`"
    );

    let mut other_alg = encoded;
    if let Some(object) = other_alg.as_object_mut() {
        object.insert("alg".to_owned(), "hmac-sha256".into());
    }
    assert_eq!(
        serde_json::from_value::<TenantBinding>(other_alg)
            .test_unwrap_err()
            .to_string(),
        "unknown variant `hmac-sha256`, expected `hkdf-hmac-sha256`"
    );

    let key_id = binding.key_id;
    let value = binding.value;
    let duplicated = format!(
        r#"{{"alg":"hkdf-hmac-sha256","alg":"hkdf-hmac-sha256","key_id":"{key_id}","value":"{value}"}}"#
    );
    assert_eq!(
        serde_json::from_str::<TenantBinding>(&duplicated)
            .test_unwrap_err()
            .to_string(),
        "duplicate field `alg` at line 1 column 31"
    );
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
    use std::path::{Path, PathBuf};

    use chio_core_types::tenant_index::{
        TenantBindingError, TenantIndexKeyLoadError, TenantIndexKeySet,
    };
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

    fn refusal(dir: &Path) -> TenantIndexKeyLoadError {
        TenantIndexKeySet::load_dir(dir).test_unwrap_err()
    }

    fn refused_path(error: &TenantIndexKeyLoadError) -> Option<&PathBuf> {
        match error {
            TenantIndexKeyLoadError::Io { path, .. }
            | TenantIndexKeyLoadError::MissingActive { path }
            | TenantIndexKeyLoadError::NotRegularFile { path }
            | TenantIndexKeyLoadError::NotDirectory { path }
            | TenantIndexKeyLoadError::WrongLength { path }
            | TenantIndexKeyLoadError::LoosePermissions { path }
            | TenantIndexKeyLoadError::NotOwned { path }
            | TenantIndexKeyLoadError::UnexpectedEntry { path }
            | TenantIndexKeyLoadError::RetiredNameMismatch { path } => Some(path),
            TenantIndexKeyLoadError::UnsupportedPlatform | TenantIndexKeyLoadError::KeySet(_) => {
                None
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
        let error = refusal(dir.path());
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::MissingActive { .. }
        ));
        assert_eq!(refused_path(&error), Some(&dir.path().to_path_buf()));
    }

    #[test]
    fn tenant_index_keys_refuse_wrong_length() {
        for length in [0_usize, 31, 33, 64] {
            let dir = chio_test_support::private_tempdir().test_unwrap();
            write_key(&dir.path().join("active"), &vec![7; length]);
            let error = refusal(dir.path());
            assert!(
                matches!(error, TenantIndexKeyLoadError::WrongLength { .. }),
                "accepted a {length}-byte key"
            );
            assert_eq!(refused_path(&error), Some(&dir.path().join("active")));
        }
    }

    #[test]
    fn tenant_index_keys_refuse_loose_permissions() {
        for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o601] {
            let dir = chio_test_support::private_tempdir().test_unwrap();
            provision(dir.path(), 5, &[]);
            let path = dir.path().join("active");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).test_unwrap();
            let error = refusal(dir.path());
            assert!(
                matches!(error, TenantIndexKeyLoadError::LoosePermissions { .. }),
                "accepted mode {mode:o}"
            );
            assert_eq!(refused_path(&error), Some(&path));
        }
    }

    #[test]
    fn tenant_index_keys_refuse_loose_retired_permissions() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[3]);
        let path = dir.path().join("retired").join(key_id(3).to_bare_hex());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).test_unwrap();
        let error = refusal(dir.path());
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::LoosePermissions { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }

    #[test]
    fn tenant_index_keys_refuse_duplicate_key_id() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[5]);
        assert!(matches!(
            refusal(dir.path()),
            TenantIndexKeyLoadError::KeySet(TenantBindingError::DuplicateKeyId { key_id })
                if key_id == super::key_id(5)
        ));
    }

    #[test]
    fn tenant_index_keys_refuse_misnamed_retired_key() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        let retired_dir = dir.path().join("retired");
        fs::create_dir(&retired_dir).test_unwrap();
        let path = retired_dir.join(key_id(4).to_bare_hex());
        write_key(&path, &[3; 32]);
        let error = refusal(dir.path());
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::RetiredNameMismatch { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }

    #[test]
    fn tenant_index_keys_refuse_unexpected_entry() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        let path = dir.path().join("active.bak");
        write_key(&path, &[5; 32]);
        let error = refusal(dir.path());
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::UnexpectedEntry { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
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
        let error = refusal(&keys_dir);
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::NotRegularFile { .. }
        ));
        assert_eq!(refused_path(&error), Some(&keys_dir.join("active")));
    }

    #[test]
    fn tenant_index_keys_refuse_a_file_as_the_directory() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        let path = dir.path().join("active");
        write_key(&path, &[5; 32]);
        let error = refusal(&path);
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::NotDirectory { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }

    #[test]
    fn tenant_index_keys_refuse_retired_as_a_file() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        let path = dir.path().join("retired");
        write_key(&path, &[3; 32]);
        let error = refusal(dir.path());
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::NotDirectory { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }

    #[test]
    fn tenant_index_keys_refuse_a_subdirectory_inside_retired() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[3]);
        let path = dir.path().join("retired").join(key_id(4).to_bare_hex());
        fs::create_dir(&path).test_unwrap();
        let error = refusal(dir.path());
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::NotRegularFile { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }

    #[test]
    fn tenant_index_keys_refuse_a_symlink_inside_retired() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        provision(dir.path(), 5, &[]);
        let target = dir.path().join("elsewhere");
        fs::create_dir(&target).test_unwrap();
        write_key(&target.join("key"), &[3; 32]);
        let keys_dir = dir.path().join("keys");
        fs::create_dir(&keys_dir).test_unwrap();
        write_key(&keys_dir.join("active"), &[5; 32]);
        let retired_dir = keys_dir.join("retired");
        fs::create_dir(&retired_dir).test_unwrap();
        let path = retired_dir.join(key_id(3).to_bare_hex());
        symlink(target.join("key"), &path).test_unwrap();
        let error = refusal(&keys_dir);
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::NotRegularFile { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }

    #[test]
    fn tenant_index_keys_refuse_a_symlinked_retired_directory() {
        let dir = chio_test_support::private_tempdir().test_unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).test_unwrap();
        write_key(&elsewhere.join(key_id(3).to_bare_hex()), &[3; 32]);
        let keys_dir = dir.path().join("keys");
        fs::create_dir(&keys_dir).test_unwrap();
        write_key(&keys_dir.join("active"), &[5; 32]);
        let path = keys_dir.join("retired");
        symlink(&elsewhere, &path).test_unwrap();
        let error = refusal(&keys_dir);
        assert!(matches!(
            error,
            TenantIndexKeyLoadError::NotDirectory { .. }
        ));
        assert_eq!(refused_path(&error), Some(&path));
    }
}
