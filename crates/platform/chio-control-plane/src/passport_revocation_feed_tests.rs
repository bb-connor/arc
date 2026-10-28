use std::path::PathBuf;

use chio_core::Keypair;
use chio_credentials::{PassportLifecycleRecord, PassportStatusDistribution};
use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, EpochNonce, PassportRevocationLeaf,
    PassportRevocationLeafKind, RevocationKey, RevocationOracleError, SqliteRevocationOracle,
    SubjectId, MAX_REVOCATION_SUBJECT_BYTES,
};

use super::{
    passport_revocation_leaves_page, passport_revocation_root_verifier,
    sign_passport_revocation_root, PassportRevocationFeedError, PassportRevocationLeavesPage,
    PassportRevocationRootDocument, MAX_JSON_SAFE_INTEGER, MAX_PASSPORT_REVOCATION_PAGE_BYTES,
    MAX_PASSPORT_REVOCATION_PAGE_LEAVES, PASSPORT_REVOCATION_LEAVES_SCHEMA,
    PASSPORT_REVOCATION_ROOT_SCHEMA,
};
use crate::passport_revocation::{passport_revocation_oracle_path, revoke_passport_status};
use crate::passport_verifier::test_fixtures::passport_from_issuers;
use crate::passport_verifier::PassportStatusRegistry;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_710_000_000;

fn authority() -> Keypair {
    Keypair::from_seed(&[11; 32])
}

struct Feed {
    _dir: tempfile::TempDir,
    registry: PathBuf,
    oracle: SqliteRevocationOracle,
}

fn feed() -> Fallible<Feed> {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(&registry)?)?;
    Ok(Feed {
        _dir: dir,
        registry,
        oracle,
    })
}

fn revoke_many(oracle: &SqliteRevocationOracle, keys: &[RevocationKey]) -> TestResult {
    oracle.transact(1_000, |txn| {
        for key in keys {
            txn.revoke(key)?;
        }
        Ok(())
    })?;
    Ok(())
}

fn passport_keys(count: usize) -> Vec<RevocationKey> {
    (0..count)
        .map(|index| passport_revocation_key(&format!("passport-{index}")))
        .collect()
}

#[test]
fn the_signed_root_covers_the_oracle_and_carries_the_signing_time() -> TestResult {
    let feed = feed()?;
    let committed = feed
        .oracle
        .revoke(passport_revocation_key("passport-a"), 1_000)?;
    let signed = sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 9_000)?;
    signed.verify(&passport_revocation_root_verifier(
        &authority().public_key(),
    ))?;
    assert_eq!(signed.root.epoch, committed.epoch);
    assert_eq!(signed.root.root_hash, committed.root_hash);
    assert_eq!(signed.root.leaf_count, 1);
    assert_eq!(signed.root.issued_at_unix_ms, 9_000);
    assert_eq!(
        signed.verify(&passport_revocation_root_verifier(
            &Keypair::from_seed(&[12; 32]).public_key()
        )),
        Err(RevocationOracleError::SignatureVerificationFailed)
    );
    Ok(())
}

#[test]
fn a_clock_behind_the_oracle_refuses_to_sign() -> TestResult {
    let feed = feed()?;
    feed.oracle
        .revoke(passport_revocation_key("passport-a"), 8_000)?;
    assert_eq!(
        sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 7_999),
        Err(PassportRevocationFeedError::ClockBehindOracle {
            now_unix_ms: 7_999,
            root_issued_at_unix_ms: 8_000,
        })
    );
    Ok(())
}

#[test]
fn a_signing_time_beyond_json_precision_is_refused() -> TestResult {
    let feed = feed()?;
    assert_eq!(
        sign_passport_revocation_root(
            &feed.oracle,
            &feed.registry,
            authority(),
            MAX_JSON_SAFE_INTEGER + 1
        ),
        Err(PassportRevocationFeedError::BeyondJsonPrecision(
            "issued_at_unix_ms"
        ))
    );
    Ok(())
}

#[test]
fn an_absent_oracle_refuses_the_root_and_the_leaves() -> TestResult {
    let feed = feed()?;
    feed.oracle
        .revoke(passport_revocation_key("passport-a"), 1_000)?;
    std::fs::remove_file(passport_revocation_oracle_path(&feed.registry)?)?;
    assert!(matches!(
        sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 5_000),
        Err(PassportRevocationFeedError::OracleUnavailable(_))
    ));
    assert!(matches!(
        passport_revocation_leaves_page(&feed.oracle, &feed.registry, 0),
        Err(PassportRevocationFeedError::OracleUnavailable(_))
    ));
    Ok(())
}

struct Revoked {
    feed: Feed,
    record: PassportLifecycleRecord,
}

impl Revoked {
    fn keys(&self) -> Vec<RevocationKey> {
        let mut keys = vec![passport_revocation_key(&self.record.passport_id)];
        keys.extend(
            self.record
                .credential_digests
                .iter()
                .map(|digest| credential_revocation_key(digest)),
        );
        keys
    }

    fn restore(&self, keys: &[RevocationKey]) -> Fallible<SqliteRevocationOracle> {
        let path = passport_revocation_oracle_path(&self.feed.registry)?;
        std::fs::rename(&path, self.feed.registry.with_file_name("lost.sqlite3"))?;
        let restored = SqliteRevocationOracle::open(&path)?;
        revoke_many(&restored, keys)?;
        Ok(restored)
    }
}

/// A feed whose registry has revoked one published passport through the
/// oracle.
fn revoked_passport() -> Fallible<Revoked> {
    let feed = feed()?;
    let passport = passport_from_issuers(3, &[4, 5], ISSUED_AT)?;
    let record = PassportStatusRegistry::update(&feed.registry, |registry| {
        registry.publish(&passport, ISSUED_AT, PassportStatusDistribution::default())
    })?;
    let record = revoke_passport_status(
        &feed.registry,
        &record.passport_id,
        None,
        Some(ISSUED_AT + 1),
        ISSUED_AT + 2,
    )?;
    Ok(Revoked { feed, record })
}

const SIGN_AT: u64 = (ISSUED_AT + 3) * 1_000;

#[test]
fn an_oracle_holding_every_registry_revocation_signs_its_own_snapshot() -> TestResult {
    let revoked = revoked_passport()?;
    let mut keys = revoked.keys();
    keys.push(passport_revocation_key("unrelated-passport"));
    let restored = revoked.restore(&keys)?;
    let signed =
        sign_passport_revocation_root(&restored, &revoked.feed.registry, authority(), SIGN_AT)?;
    let current = restored.current_epoch_root()?;
    assert_eq!(signed.root.root_hash, current.root_hash);
    assert_eq!(signed.root.leaf_count, 4);
    assert_eq!(signed.root.issued_at_unix_ms, SIGN_AT);
    Ok(())
}

#[test]
fn a_lost_oracle_refuses_to_sign() -> TestResult {
    let revoked = revoked_passport()?;
    let empty = revoked.restore(&[])?;
    assert_eq!(
        sign_passport_revocation_root(&empty, &revoked.feed.registry, authority(), SIGN_AT),
        Err(PassportRevocationFeedError::OracleMissingRevocation {
            passport_id: revoked.record.passport_id.clone(),
            subject: revoked.record.passport_id.clone(),
        })
    );
    Ok(())
}

#[test]
fn an_equal_count_restore_of_unrelated_revocations_refuses_to_sign() -> TestResult {
    let revoked = revoked_passport()?;
    let unrelated: Vec<RevocationKey> = (0..revoked.keys().len())
        .map(|index| match index {
            0 => passport_revocation_key("unrelated-passport"),
            index => credential_revocation_key(&format!("{index:064x}")),
        })
        .collect();
    let restored = revoked.restore(&unrelated)?;
    assert_eq!(
        sign_passport_revocation_root(&restored, &revoked.feed.registry, authority(), SIGN_AT),
        Err(PassportRevocationFeedError::OracleMissingRevocation {
            passport_id: revoked.record.passport_id.clone(),
            subject: revoked.record.passport_id.clone(),
        })
    );
    Ok(())
}

#[test]
fn a_restore_missing_one_credential_revocation_refuses_to_sign() -> TestResult {
    let revoked = revoked_passport()?;
    let mut keys = revoked.keys();
    let missing = keys
        .pop()
        .ok_or("a revoked passport carries a credential")?;
    keys.push(credential_revocation_key(&"ef".repeat(32)));
    let restored = revoked.restore(&keys)?;
    assert_eq!(
        sign_passport_revocation_root(&restored, &revoked.feed.registry, authority(), SIGN_AT),
        Err(PassportRevocationFeedError::OracleMissingRevocation {
            passport_id: revoked.record.passport_id.clone(),
            subject: missing.subject_id.as_str().to_owned(),
        })
    );
    Ok(())
}

#[test]
fn pages_follow_the_cursor_in_insertion_order_within_the_leaf_bound() -> TestResult {
    let feed = feed()?;
    let total = MAX_PASSPORT_REVOCATION_PAGE_LEAVES + 3;
    revoke_many(&feed.oracle, &passport_keys(total))?;

    let first = passport_revocation_leaves_page(&feed.oracle, &feed.registry, 0)?;
    assert_eq!(first.schema, PASSPORT_REVOCATION_LEAVES_SCHEMA);
    assert_eq!(first.after, 0);
    assert_eq!(first.leaves.len(), MAX_PASSPORT_REVOCATION_PAGE_LEAVES);
    assert_eq!(
        first.leaves.first(),
        Some(&PassportRevocationLeaf {
            seq: 1,
            kind: PassportRevocationLeafKind::Passport,
            subject: "passport-0".to_owned(),
        })
    );
    let last = first.leaves.last().ok_or("empty page")?.seq;
    let second = passport_revocation_leaves_page(&feed.oracle, &feed.registry, last)?;
    assert_eq!(second.after, last);
    assert_eq!(second.leaves.len(), 3);
    assert_eq!(second.leaves.first().map(|leaf| leaf.seq), Some(last + 1));
    assert!(
        passport_revocation_leaves_page(&feed.oracle, &feed.registry, last + 3)?
            .leaves
            .is_empty()
    );
    Ok(())
}

#[test]
fn pages_stay_below_the_byte_bound() -> TestResult {
    let feed = feed()?;
    let keys = (0..MAX_PASSPORT_REVOCATION_PAGE_LEAVES)
        .map(|index| {
            passport_revocation_key(&format!(
                "{index:04}{}",
                "x".repeat(MAX_REVOCATION_SUBJECT_BYTES - 4)
            ))
        })
        .collect::<Vec<_>>();
    revoke_many(&feed.oracle, &keys)?;
    let page = passport_revocation_leaves_page(&feed.oracle, &feed.registry, 0)?;
    assert!(!page.leaves.is_empty());
    assert!(page.leaves.len() < MAX_PASSPORT_REVOCATION_PAGE_LEAVES);
    assert!(serde_json::to_vec(&page)?.len() <= MAX_PASSPORT_REVOCATION_PAGE_BYTES);
    Ok(())
}

#[test]
fn a_cursor_beyond_json_precision_is_refused() -> TestResult {
    let feed = feed()?;
    for cursor in [MAX_JSON_SAFE_INTEGER + 1, u64::MAX] {
        assert_eq!(
            passport_revocation_leaves_page(&feed.oracle, &feed.registry, cursor),
            Err(PassportRevocationFeedError::CursorOutOfRange(cursor))
        );
    }
    Ok(())
}

#[test]
fn a_leaf_with_a_nonce_outside_the_kind_table_is_unpublishable() -> TestResult {
    let feed = feed()?;
    revoke_many(
        &feed.oracle,
        &[
            passport_revocation_key("passport-a"),
            RevocationKey::new(SubjectId::from("foreign"), EpochNonce::new(7)),
        ],
    )?;
    assert_eq!(
        passport_revocation_leaves_page(&feed.oracle, &feed.registry, 0)
            .err()
            .map(|error| matches!(
                error,
                PassportRevocationFeedError::UnpublishableLeaf { seq: 2, .. }
            )),
        Some(true)
    );
    assert_eq!(
        passport_revocation_leaves_page(&feed.oracle, &feed.registry, 2)?
            .leaves
            .len(),
        0
    );
    Ok(())
}

#[test]
fn credential_leaves_publish_with_kind_credential() -> TestResult {
    let feed = feed()?;
    let digest = "cd".repeat(32);
    revoke_many(
        &feed.oracle,
        &[
            passport_revocation_key("passport-a"),
            credential_revocation_key(&digest),
        ],
    )?;
    let page = passport_revocation_leaves_page(&feed.oracle, &feed.registry, 0)?;
    assert_eq!(
        serde_json::to_value(&page)?,
        serde_json::json!({
            "schema": PASSPORT_REVOCATION_LEAVES_SCHEMA,
            "after": 0,
            "leaves": [
                {"seq": 1, "kind": "passport", "subject": "passport-a"},
                {"seq": 2, "kind": "credential", "subject": digest},
            ],
        })
    );
    Ok(())
}

#[test]
fn a_root_document_of_another_schema_is_refused() -> TestResult {
    let feed = feed()?;
    let signed = sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 1_000)?;
    let document = PassportRevocationRootDocument::new(signed.clone());
    assert_eq!(document.schema, PASSPORT_REVOCATION_ROOT_SCHEMA);
    assert_eq!(document.clone().into_signed_root()?, signed);
    let foreign = PassportRevocationRootDocument {
        schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
        ..document
    };
    assert_eq!(
        foreign.into_signed_root(),
        Err(PassportRevocationFeedError::UnsupportedSchema(
            PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned()
        ))
    );
    let page = PassportRevocationLeavesPage {
        schema: PASSPORT_REVOCATION_ROOT_SCHEMA.to_owned(),
        after: 0,
        leaves: Vec::new(),
    };
    assert!(matches!(
        page.into_leaves(),
        Err(PassportRevocationFeedError::UnsupportedSchema(_))
    ));
    Ok(())
}

#[test]
fn a_root_or_page_with_an_unknown_nested_field_is_refused_by_the_decoder() -> TestResult {
    let feed = feed()?;
    feed.oracle
        .revoke(passport_revocation_key("passport-a"), 1_000)?;
    let root = serde_json::to_value(PassportRevocationRootDocument::new(
        sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 2_000)?,
    ))?;
    let page = serde_json::to_value(passport_revocation_leaves_page(
        &feed.oracle,
        &feed.registry,
        0,
    )?)?;
    serde_json::from_value::<PassportRevocationRootDocument>(root.clone())?;
    serde_json::from_value::<PassportRevocationLeavesPage>(page.clone())?;
    for pointer in [
        "",
        "/signedRoot",
        "/signedRoot/root",
        "/signedRoot/signature",
    ] {
        let mut tampered = root.clone();
        tampered
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("root object")?
            .insert("extra".to_owned(), serde_json::json!(0));
        let refused = serde_json::from_value::<PassportRevocationRootDocument>(tampered)
            .err()
            .ok_or("an unknown root field must refuse")?
            .to_string();
        assert!(refused.contains("unknown field"), "{pointer}: {refused}");
    }
    for pointer in ["", "/leaves/0"] {
        let mut tampered = page.clone();
        tampered
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("page object")?
            .insert("epochNonce".to_owned(), serde_json::json!(0));
        let refused = serde_json::from_value::<PassportRevocationLeavesPage>(tampered)
            .err()
            .ok_or("an unknown page field must refuse")?
            .to_string();
        assert!(refused.contains("unknown field"), "{pointer}: {refused}");
    }
    Ok(())
}

#[test]
fn every_published_integer_is_below_json_safe_precision() -> TestResult {
    let feed = feed()?;
    revoke_many(&feed.oracle, &passport_keys(4))?;
    let root = serde_json::to_value(PassportRevocationRootDocument::new(
        sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 9_000)?,
    ))?;
    let page = serde_json::to_value(passport_revocation_leaves_page(
        &feed.oracle,
        &feed.registry,
        0,
    )?)?;
    for document in [root, page] {
        assert_json_safe(&document)?;
    }
    Ok(())
}

fn assert_json_safe(value: &serde_json::Value) -> TestResult {
    match value {
        serde_json::Value::Number(number) => {
            let integer = number
                .as_u64()
                .ok_or("every number is a non-negative integer")?;
            assert!(integer <= MAX_JSON_SAFE_INTEGER, "{integer}");
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_json_safe(item)?;
            }
        }
        serde_json::Value::Object(members) => {
            for member in members.values() {
                assert_json_safe(member)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn published_schema(source: &str) -> Fallible<jsonschema::Validator> {
    Ok(jsonschema::validator_for(&serde_json::from_str(source)?)?)
}

#[test]
fn published_documents_match_their_registered_schemas() -> TestResult {
    let root_schema = published_schema(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/chio-trust/v1/passport-revocation-root.schema.json"
    )))?;
    let leaves_schema = published_schema(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/chio-trust/v1/passport-revocation-leaves.schema.json"
    )))?;
    let feed = feed()?;
    revoke_many(
        &feed.oracle,
        &[
            passport_revocation_key("passport-a"),
            credential_revocation_key(&"ab".repeat(32)),
        ],
    )?;
    let root = serde_json::to_value(PassportRevocationRootDocument::new(
        sign_passport_revocation_root(&feed.oracle, &feed.registry, authority(), 2_000)?,
    ))?;
    let page = serde_json::to_value(passport_revocation_leaves_page(
        &feed.oracle,
        &feed.registry,
        0,
    )?)?;
    root_schema
        .validate(&root)
        .map_err(|error| error.to_string())?;
    leaves_schema
        .validate(&page)
        .map_err(|error| error.to_string())?;

    let mut foreign_root = root.clone();
    foreign_root["signedRoot"]["root"]["extra"] = serde_json::json!(0);
    assert!(!root_schema.is_valid(&foreign_root));
    let mut imprecise_root = root;
    imprecise_root["signedRoot"]["root"]["epoch"] = serde_json::json!(MAX_JSON_SAFE_INTEGER + 1);
    assert!(!root_schema.is_valid(&imprecise_root));
    let mut foreign_leaf = page.clone();
    foreign_leaf["leaves"][0]["kind"] = serde_json::json!("issuer");
    assert!(!leaves_schema.is_valid(&foreign_leaf));
    let mut nonce_leaf = page;
    nonce_leaf["leaves"][0]["epochNonce"] = serde_json::json!(0);
    assert!(!leaves_schema.is_valid(&nonce_leaf));
    Ok(())
}
