use std::path::Path;

use chio_core::Keypair;
use chio_revocation_oracle::{
    passport_revocation_key, EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle,
    SqliteRevocationOracle, SubjectId, MAX_REVOCATION_SUBJECT_BYTES,
};

use super::{
    passport_revocation_leaves_page, passport_revocation_root_verifier,
    sign_passport_revocation_root, PassportRevocationFeedError, PassportRevocationLeaf,
    MAX_PASSPORT_REVOCATION_PAGE_BYTES, MAX_PASSPORT_REVOCATION_PAGE_LEAVES,
    PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::passport_revocation::passport_revocation_oracle_path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn authority() -> Keypair {
    Keypair::from_seed(&[11; 32])
}

fn oracle(registry: &Path) -> Result<SqliteRevocationOracle, Box<dyn std::error::Error>> {
    Ok(SqliteRevocationOracle::open(
        &passport_revocation_oracle_path(registry)?,
    )?)
}

#[test]
fn an_absent_oracle_publishes_the_signed_empty_root_without_creating_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let signed = sign_passport_revocation_root(&registry, authority(), 5_000)?;
    signed.verify(&passport_revocation_root_verifier(
        &authority().public_key(),
    ))?;
    let empty = InMemoryRevocationOracle::new().epoch_root();
    assert_eq!(signed.root.root_hash, empty.root_hash);
    assert_eq!(signed.root.leaf_count, 0);
    assert_eq!(signed.root.issued_at_unix_ms, 5_000);
    assert!(passport_revocation_leaves_page(&registry, 0)?
        .leaves
        .is_empty());
    assert!(!passport_revocation_oracle_path(&registry)?.exists());
    Ok(())
}

#[test]
fn the_signed_root_covers_the_oracle_and_carries_the_signing_time() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let committed = oracle(&registry)?.revoke(passport_revocation_key("passport-a"), 1_000)?;
    let signed = sign_passport_revocation_root(&registry, authority(), 9_000)?;
    assert_eq!(signed.root.epoch, committed.epoch);
    assert_eq!(signed.root.root_hash, committed.root_hash);
    assert_eq!(signed.root.leaf_count, 1);
    assert_eq!(signed.root.issued_at_unix_ms, 9_000);
    assert!(signed
        .verify(&passport_revocation_root_verifier(
            &Keypair::from_seed(&[12; 32]).public_key()
        ))
        .is_err());
    Ok(())
}

#[test]
fn a_clock_behind_the_oracle_refuses_to_sign() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    oracle(&registry)?.revoke(passport_revocation_key("passport-a"), 8_000)?;
    assert_eq!(
        sign_passport_revocation_root(&registry, authority(), 7_999),
        Err(PassportRevocationFeedError::ClockBehindOracle {
            now_unix_ms: 7_999,
            root_issued_at_unix_ms: 8_000,
        })
    );
    Ok(())
}

#[test]
fn pages_follow_the_cursor_in_insertion_order_within_the_leaf_bound() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let oracle = oracle(&registry)?;
    let total = MAX_PASSPORT_REVOCATION_PAGE_LEAVES + 3;
    oracle.transact(1_000, |txn| {
        for index in 0..total {
            txn.revoke(&passport_revocation_key(&format!("passport-{index}")))?;
        }
        Ok(())
    })?;

    let first = passport_revocation_leaves_page(&registry, 0)?;
    assert_eq!(first.schema, PASSPORT_REVOCATION_LEAVES_SCHEMA);
    assert_eq!(first.after, 0);
    assert_eq!(first.leaves.len(), MAX_PASSPORT_REVOCATION_PAGE_LEAVES);
    assert_eq!(
        first.leaves[0],
        PassportRevocationLeaf {
            seq: 1,
            subject: "passport-0".to_owned(),
            epoch_nonce: passport_revocation_key("passport-0").epoch_nonce.get(),
        }
    );
    let last = first.leaves.last().ok_or("empty page")?.seq;
    let second = passport_revocation_leaves_page(&registry, last)?;
    assert_eq!(second.after, last);
    assert_eq!(second.leaves.len(), 3);
    assert_eq!(second.leaves[0].seq, last + 1);
    assert!(passport_revocation_leaves_page(&registry, last + 3)?
        .leaves
        .is_empty());
    Ok(())
}

#[test]
fn pages_stay_below_the_byte_bound() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let oracle = oracle(&registry)?;
    oracle.transact(1_000, |txn| {
        for index in 0..MAX_PASSPORT_REVOCATION_PAGE_LEAVES {
            let subject = format!("{index:04}{}", "x".repeat(MAX_REVOCATION_SUBJECT_BYTES - 4));
            txn.revoke(&RevocationKey::new(
                SubjectId::new(subject),
                EpochNonce::new(1),
            ))?;
        }
        Ok(())
    })?;
    let page = passport_revocation_leaves_page(&registry, 0)?;
    assert!(!page.leaves.is_empty());
    assert!(page.leaves.len() < MAX_PASSPORT_REVOCATION_PAGE_LEAVES);
    assert!(serde_json::to_vec(&page)?.len() <= MAX_PASSPORT_REVOCATION_PAGE_BYTES);
    Ok(())
}

#[test]
fn a_cursor_beyond_i64_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    assert_eq!(
        passport_revocation_leaves_page(&registry, u64::MAX),
        Err(PassportRevocationFeedError::CursorOutOfRange(u64::MAX))
    );
    Ok(())
}
