use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};

use chio_core_types::enterprise_subject::{EnterpriseSubjectError, EnterpriseSubjectKey};
use chio_core_types::rng::{Rng, RngError};
use chio_core_types::root_authority::Sha256Digest;
use chio_core_types::tenant_index::{TenantBindingError, TenantIndexKey, TenantIndexKeySet};
use chio_test_support::prelude::*;
use serde_json::{json, Value};

use super::{
    with_enterprise_identity_index, EnterpriseIdentityId, EnterpriseIdentityIndexError,
    ResolvedIdentity, ENTERPRISE_IDENTITY_INDEX_SCHEMA,
};
use crate::passport_verifier::RegistryUpdateError;

const SCOPE: &str = "https://idp.example";
const DEACTIVATED_AT: u64 = 1_767_225_600;

struct SequenceRng(AtomicU8);

impl SequenceRng {
    fn new() -> Self {
        Self(AtomicU8::new(1))
    }
}

impl Rng for SequenceRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        dest.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("entropy offline"))
    }
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

fn subject(keys: &TenantIndexKeySet, principal: &str) -> EnterpriseSubjectKey {
    EnterpriseSubjectKey::derive(keys, SCOPE, principal).test_unwrap()
}

fn index_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("enterprise-identities.json")
}

fn insert(
    path: &Path,
    keys: &TenantIndexKeySet,
    rng: &dyn Rng,
    principal: &str,
) -> ResolvedIdentity {
    with_enterprise_identity_index(path, keys, |index| {
        index.resolve_or_insert(rng, SCOPE, principal)
    })
    .test_unwrap()
}

fn stored(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).test_unwrap()).test_unwrap()
}

fn unknown(byte: u8) -> TenantBindingError {
    TenantBindingError::TenantIndexKeyUnknown {
        key_id: key_id(byte),
    }
}

fn is_subject_refusal(
    result: &Result<impl std::fmt::Debug, EnterpriseIdentityIndexError>,
    expected: TenantBindingError,
) -> bool {
    matches!(
        result,
        Err(EnterpriseIdentityIndexError::Subject(EnterpriseSubjectError::Index(error)))
            if *error == expected
    )
}

#[test]
fn insert_resolves_by_principal_and_persists_only_the_keyed_subject() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let keys = set(1, &[]);
    let rng = SequenceRng::new();
    let alice = insert(&path, &keys, &rng, "alice");
    assert!(alice.inserted);
    assert_eq!(alice.identity.identity_id.as_str(), "01".repeat(16));
    assert_eq!(alice.identity.subject, subject(&keys, "alice"));
    assert_eq!(alice.identity.deactivated_at, None);

    let again = insert(&path, &keys, &rng, "alice");
    assert_eq!(again.identity, alice.identity);
    assert!(!again.inserted);
    let bob = insert(&path, &keys, &rng, "bob");
    assert_ne!(bob.identity.identity_id, alice.identity.identity_id);

    let document = stored(&path);
    assert_eq!(document["schema"], ENTERPRISE_IDENTITY_INDEX_SCHEMA);
    assert_eq!(document["history"], json!([]));
    let rows = document["identities"].as_array().test_unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let text = row["subject"].as_str().test_unwrap();
        assert!(text.starts_with("esk1."), "unkeyed subject {text}");
    }
}

#[test]
fn rotate_then_login_resolves_same_identity() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let before = set(1, &[]);
    let alice = insert(&path, &before, &SequenceRng::new(), "alice").identity;

    let after = set(2, &[1]);
    let fresh_login = subject(&after, "alice");
    let resolved = with_enterprise_identity_index(&path, &after, |index| {
        let fresh = index.resolve_presented(SCOPE, "alice", &fresh_login)?;
        let stale = index.resolve_presented(SCOPE, "alice", &alice.subject)?;
        Ok((fresh, stale))
    })
    .test_unwrap();
    assert_eq!(resolved.0.identity_id, alice.identity_id);
    assert_eq!(resolved.1.identity_id, alice.identity_id);
    assert_eq!(resolved.0.subject, fresh_login);
    assert_eq!(resolved.0.subject.key_id(), &key_id(2));
}

#[test]
fn rotation_rederives_every_identity_in_one_replace_and_keeps_history() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let before = set(1, &[]);
    let rng = SequenceRng::new();
    let principals = ["alice", "bob", "carol"];
    let ids: Vec<EnterpriseIdentityId> = principals
        .iter()
        .map(|principal| insert(&path, &before, &rng, principal).identity.identity_id)
        .collect();

    let after = set(2, &[1]);
    let refused = with_enterprise_identity_index(&path, &after, |_| {
        Err::<(), _>(EnterpriseIdentityIndexError::UnknownIdentity)
    });
    assert!(matches!(
        refused,
        Err(EnterpriseIdentityIndexError::UnknownIdentity)
    ));

    let document = stored(&path);
    let rows = document["identities"].as_array().test_unwrap();
    let history = document["history"].as_array().test_unwrap();
    assert_eq!(rows.len(), principals.len());
    assert_eq!(history.len(), principals.len());
    for ((principal, id), row) in principals.iter().zip(&ids).zip(rows) {
        assert_eq!(row["identityId"], id.as_str());
        assert_eq!(row["subject"], subject(&after, principal).to_string());
        let prior = subject(&before, principal).to_string();
        assert!(history
            .iter()
            .any(|entry| entry["identityId"] == id.as_str() && entry["subject"] == prior));
    }

    let unchanged = std::fs::read(&path).test_unwrap();
    with_enterprise_identity_index(&path, &after, |index| Ok(index.len())).test_unwrap();
    assert_eq!(std::fs::read(&path).test_unwrap(), unchanged);
}

#[test]
fn history_join_after_rotation() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let before = set(1, &[]);
    let alice = insert(&path, &before, &SequenceRng::new(), "alice").identity;
    let old_receipt_subject = alice.subject;

    let after = set(2, &[1]);
    let new_receipt_subject = subject(&after, "alice");
    let relabeled = EnterpriseSubjectKey::parse(&format!(
        "esk1.{}.{}",
        key_id(2).to_bare_hex(),
        old_receipt_subject.keyed_value().value.to_bare_hex()
    ))
    .test_unwrap();
    let crossed = EnterpriseSubjectKey::parse(&format!(
        "esk1.{}.{}",
        key_id(1).to_bare_hex(),
        new_receipt_subject.keyed_value().value.to_bare_hex()
    ))
    .test_unwrap();
    let joined = with_enterprise_identity_index(&path, &after, |index| {
        assert_eq!(
            index.history_of(&alice.identity_id),
            vec![old_receipt_subject]
        );
        Ok([
            index.resolve_subject(&old_receipt_subject)?,
            index.resolve_subject(&new_receipt_subject)?,
            index.resolve_subject(&relabeled)?,
            index.resolve_subject(&crossed)?,
        ])
    })
    .test_unwrap();
    assert_eq!(
        joined,
        [
            Some(alice.identity_id.clone()),
            Some(alice.identity_id),
            None,
            None
        ]
    );
}

#[test]
fn unknown_generation_refuses_startup_and_lookup() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    insert(&path, &set(1, &[]), &SequenceRng::new(), "alice");

    let current_unloaded =
        with_enterprise_identity_index(&path, &set(2, &[]), |index| Ok(index.len()));
    assert!(is_subject_refusal(&current_unloaded, unknown(1)));

    with_enterprise_identity_index(&path, &set(2, &[1]), |index| Ok(index.len())).test_unwrap();
    let retired_missing =
        with_enterprise_identity_index(&path, &set(3, &[2]), |index| Ok(index.len()));
    assert!(is_subject_refusal(&retired_missing, unknown(1)));

    let keys = set(2, &[1]);
    let foreign = subject(&set(7, &[]), "alice");
    let by_subject =
        with_enterprise_identity_index(&path, &keys, |index| index.resolve_subject(&foreign));
    assert!(is_subject_refusal(&by_subject, unknown(7)));
    let presented = with_enterprise_identity_index(&path, &keys, |index| {
        index.resolve_presented(SCOPE, "alice", &foreign)
    });
    assert!(is_subject_refusal(&presented, unknown(7)));
}

#[test]
fn scim_deactivate_after_rotation_holds() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let before = set(1, &[]);
    let rng = SequenceRng::new();
    let alice = insert(&path, &before, &rng, "alice").identity;
    let deactivated = with_enterprise_identity_index(&path, &before, |index| {
        index.deactivate(&alice.identity_id, DEACTIVATED_AT)
    })
    .test_unwrap();
    assert_eq!(deactivated.deactivated_at, Some(DEACTIVATED_AT));

    let after = set(2, &[1]);
    let recreated = insert(&path, &after, &rng, "alice");
    assert!(!recreated.inserted);
    assert_eq!(recreated.identity.identity_id, alice.identity_id);
    assert_eq!(recreated.identity.deactivated_at, Some(DEACTIVATED_AT));
    let later = with_enterprise_identity_index(&path, &after, |index| {
        index.deactivate(&alice.identity_id, DEACTIVATED_AT + 60)
    })
    .test_unwrap();
    assert_eq!(later.deactivated_at, Some(DEACTIVATED_AT));
}

#[test]
fn no_duplicate_identity_across_rotation() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let rng = SequenceRng::new();
    let first = insert(&path, &set(1, &[]), &rng, "alice").identity;
    let second = insert(&path, &set(2, &[1]), &rng, "alice");
    let third = insert(&path, &set(3, &[1, 2]), &rng, "alice");
    assert!(!second.inserted && !third.inserted);
    assert_eq!(second.identity.identity_id, first.identity_id);
    assert_eq!(third.identity.identity_id, first.identity_id);
    let other_scope = with_enterprise_identity_index(&path, &set(3, &[1, 2]), |index| {
        let other = index.resolve_or_insert(&rng, "https://other-idp.example", "alice")?;
        Ok((
            other,
            index.len(),
            index.history_of(&first.identity_id).len(),
        ))
    })
    .test_unwrap();
    assert!(other_scope.0.inserted);
    assert_ne!(other_scope.0.identity.identity_id, first.identity_id);
    assert_eq!(other_scope.1, 2);
    assert_eq!(other_scope.2, 2);
}

#[test]
fn a_reactivated_generation_moves_its_subject_back_out_of_history() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let alice = insert(&path, &set(1, &[]), &SequenceRng::new(), "alice").identity;
    with_enterprise_identity_index(&path, &set(2, &[1]), |index| Ok(index.len())).test_unwrap();
    let restored = with_enterprise_identity_index(&path, &set(1, &[2]), |index| {
        Ok((
            index.resolve(SCOPE, "alice"),
            index.history_of(&alice.identity_id),
        ))
    })
    .test_unwrap();
    assert_eq!(restored.0, Some(alice.clone()));
    assert_eq!(restored.1, vec![subject(&set(2, &[]), "alice")]);
}

#[test]
fn presented_subject_must_verify_and_be_indexed() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let keys = set(1, &[]);
    insert(&path, &keys, &SequenceRng::new(), "alice");
    let bob = subject(&keys, "bob");
    let as_alice = with_enterprise_identity_index(&path, &keys, |index| {
        index.resolve_presented(SCOPE, "alice", &bob)
    });
    assert!(is_subject_refusal(&as_alice, TenantBindingError::Mismatch));
    let unindexed = with_enterprise_identity_index(&path, &keys, |index| {
        index.resolve_presented(SCOPE, "bob", &bob)
    });
    assert!(matches!(
        unindexed,
        Err(EnterpriseIdentityIndexError::UnknownIdentity)
    ));
}

#[test]
fn entropy_failure_inserts_nothing() {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    let refused = with_enterprise_identity_index(&path, &set(1, &[]), |index| {
        index.resolve_or_insert(&FailingRng, SCOPE, "alice")
    });
    assert!(matches!(
        refused,
        Err(EnterpriseIdentityIndexError::Entropy(RngError(
            "entropy offline"
        )))
    ));
    assert!(!path.exists());
}

fn identity_row(id: &str, principal: &str, subject: &EnterpriseSubjectKey) -> Value {
    json!({
        "identityId": id,
        "providerScope": SCOPE,
        "principal": principal,
        "subject": subject.to_string(),
        "deactivatedAt": null,
    })
}

fn refusal_of(document: &Value, keys: &TenantIndexKeySet) -> EnterpriseIdentityIndexError {
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let path = index_path(&dir);
    std::fs::write(&path, serde_json::to_vec(document).test_unwrap()).test_unwrap();
    with_enterprise_identity_index(&path, keys, |index| Ok(index.len())).test_unwrap_err()
}

#[test]
fn a_tampered_index_refuses_to_load() {
    let keys = set(1, &[]);
    let alice = subject(&keys, "alice");
    let bob = subject(&keys, "bob");
    let id_a = "0a".repeat(16);
    let id_b = "0b".repeat(16);
    let document = |identities: Value, history: Value| {
        json!({
            "schema": ENTERPRISE_IDENTITY_INDEX_SCHEMA,
            "identities": identities,
            "history": history,
        })
    };

    let swapped = refusal_of(
        &document(json!([identity_row(&id_a, "alice", &bob)]), json!([])),
        &keys,
    );
    assert!(is_subject_refusal(
        &Err::<(), _>(swapped),
        TenantBindingError::Mismatch
    ));

    let repeated_principal = refusal_of(
        &document(
            json!([
                identity_row(&id_a, "alice", &alice),
                identity_row(&id_b, "alice", &alice)
            ]),
            json!([]),
        ),
        &keys,
    );
    assert!(matches!(
        repeated_principal,
        EnterpriseIdentityIndexError::DuplicatePrincipal
    ));

    let repeated_id = refusal_of(
        &document(
            json!([
                identity_row(&id_a, "alice", &alice),
                identity_row(&id_a, "bob", &bob)
            ]),
            json!([]),
        ),
        &keys,
    );
    assert!(matches!(
        repeated_id,
        EnterpriseIdentityIndexError::DuplicateIdentityId
    ));

    let orphan = refusal_of(
        &document(
            json!([identity_row(&id_a, "alice", &alice)]),
            json!([{"identityId": id_b, "subject": bob.to_string()}]),
        ),
        &keys,
    );
    assert!(matches!(
        orphan,
        EnterpriseIdentityIndexError::OrphanHistory
    ));

    let history_as_current = refusal_of(
        &document(
            json!([identity_row(&id_a, "alice", &alice)]),
            json!([{"identityId": id_a, "subject": alice.to_string()}]),
        ),
        &keys,
    );
    assert!(matches!(
        history_as_current,
        EnterpriseIdentityIndexError::DuplicateSubject
    ));

    let other_schema = refusal_of(
        &json!({"schema": "chio.enterprise-identity-index.v2", "identities": [], "history": []}),
        &keys,
    );
    assert!(matches!(
        other_schema,
        EnterpriseIdentityIndexError::UnsupportedSchema
    ));
}

#[test]
fn old_unkeyed_shape_refuses() {
    let keys = set(1, &[]);
    let unkeyed = "a1".repeat(32);
    let id = "0a".repeat(16);
    for document in [
        json!({
            "schema": ENTERPRISE_IDENTITY_INDEX_SCHEMA,
            "identities": [{
                "identityId": id,
                "providerScope": SCOPE,
                "principal": "alice",
                "subject": unkeyed,
                "deactivatedAt": null,
            }],
            "history": [],
        }),
        json!({
            "schema": ENTERPRISE_IDENTITY_INDEX_SCHEMA,
            "identities": [{
                "identityId": "scim-0123",
                "providerScope": SCOPE,
                "principal": "alice",
                "subject": subject(&keys, "alice").to_string(),
                "deactivatedAt": null,
            }],
            "history": [],
        }),
        json!({
            "schema": ENTERPRISE_IDENTITY_INDEX_SCHEMA,
            "identities": [],
            "history": [],
            "legacy": [],
        }),
    ] {
        let refused = refusal_of(&document, &keys);
        assert!(
            matches!(
                refused,
                EnterpriseIdentityIndexError::Registry(RegistryUpdateError::Load(_))
            ),
            "loaded {document}: {refused:?}"
        );
    }
}
