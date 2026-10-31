use chio_test_support::prelude::*;

use super::*;
use crate::{
    InMemoryRevocationOracle, PassportRevocationLeafKind, RevocationOracle, RootSignature,
    MAX_REVOCATION_SUBJECT_BYTES,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn leaf(seq: u64, subject: &str) -> PassportRevocationLeaf {
    PassportRevocationLeaf {
        seq,
        kind: PassportRevocationLeafKind::Passport,
        subject: subject.to_owned(),
    }
}

fn signed(root: EpochRoot) -> SignedEpochRoot {
    SignedEpochRoot {
        root,
        signature: RootSignature {
            signer_id: "partner".to_owned(),
            signature_bytes: vec![1; 64],
        },
    }
}

fn partner_root(leaves: &[PassportRevocationLeaf], issued_at_unix_ms: u64) -> SignedEpochRoot {
    let mut tree = InMemoryRevocationOracle::new();
    for leaf in leaves {
        tree.insert(leaf.to_revocation_key(), 1_000).test_unwrap();
    }
    let mut root = tree.epoch_root();
    root.issued_at_unix_ms = issued_at_unix_ms;
    signed(root)
}

#[test]
fn a_mirror_stamped_for_another_partner_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mirror.sqlite3");
    SqlitePartnerMirror::open(&path, "alpha")?;
    assert!(matches!(
        SqlitePartnerMirror::open(&path, "bravo"),
        Err(PartnerMirrorError::PartnerMismatch { expected, found })
            if expected == "bravo" && found == "alpha"
    ));
    Ok(())
}

#[test]
fn a_refused_apply_leaves_the_tree_and_the_accepted_root_unchanged() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mirror = SqlitePartnerMirror::open(&dir.path().join("mirror.sqlite3"), "alpha")?;
    let first = [leaf(1, "passport-a")];
    let accepted = partner_root(&first, 2_000);
    mirror.apply(&accepted, &first, 2_000)?;

    let next = [
        leaf(1, "passport-a"),
        leaf(2, "passport-b"),
        leaf(3, "passport-c"),
    ];
    let offered = partner_root(&next, 3_000);
    assert_eq!(
        mirror.apply(&offered, &[leaf(3, "passport-c")], 3_000),
        Err(PartnerMirrorRefusal::OutOfSequence { seq: 3, have: 1 }.into())
    );
    assert_eq!(
        mirror.apply(&offered, &next[1..2], 3_000),
        Err(PartnerMirrorRefusal::RootMismatch {
            epoch: offered.root.epoch
        }
        .into())
    );
    let view = mirror.view(&[leaf(2, "passport-b").to_revocation_key()])?;
    assert_eq!(view.accepted, Some(accepted.clone()));
    assert!(view.tree.same_tree(&accepted.root));
    assert_eq!(view.revoked, None);

    mirror.apply(&offered, &next[1..], 3_000)?;
    assert_eq!(mirror.accepted()?, Some(offered));
    Ok(())
}

#[test]
fn a_conflicting_root_is_recorded_once_with_the_accepted_root() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mirror = SqlitePartnerMirror::open(&dir.path().join("mirror.sqlite3"), "alpha")?;
    let first = [leaf(1, "passport-a")];
    let accepted = partner_root(&first, 2_000);
    mirror.apply(&accepted, &first, 2_000)?;

    let mut rolled_back = accepted.root.clone();
    rolled_back.issued_at_unix_ms = 1_500;
    let offered = signed(rolled_back);
    let refusal = PartnerMirrorRefusal::AttestationRollback {
        accepted: 2_000,
        offered: 1_500,
    };
    assert_eq!(
        mirror.apply(&offered, &[], 3_000),
        Err(refusal.clone().into())
    );
    let reason = refusal.to_string();
    assert_eq!(
        mirror.record_conflict(&reason, &offered, 3_000)?,
        ConflictRecord::Recorded
    );
    assert_eq!(
        mirror.record_conflict(&reason, &offered, 4_000)?,
        ConflictRecord::AlreadyRecorded
    );
    assert_eq!(
        mirror.conflicts()?,
        vec![PartnerMirrorConflict {
            observed_at_unix_ms: 3_000,
            reason,
            accepted_root: Some(accepted),
            offered_root: offered,
        }]
    );
    Ok(())
}

#[test]
fn a_reopened_mirror_keeps_its_accepted_root_tree_and_conflicts() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mirror.sqlite3");
    let first = [leaf(1, "passport-a")];
    let accepted = partner_root(&first, 2_000);
    let mut stale = accepted.root.clone();
    stale.issued_at_unix_ms = 1_500;
    let offered = signed(stale);
    {
        let mirror = SqlitePartnerMirror::open(&path, "alpha")?;
        mirror.apply(&accepted, &first, 2_000)?;
        mirror.record_conflict("rollback", &offered, 3_000)?;
    }

    let reopened = SqlitePartnerMirror::open(&path, "alpha")?;
    let view = reopened.view(&[leaf(1, "passport-a").to_revocation_key()])?;
    assert_eq!(view.accepted, Some(accepted.clone()));
    assert!(view.tree.same_tree(&accepted.root));
    assert_eq!(
        view.revoked,
        Some(leaf(1, "passport-a").to_revocation_key())
    );
    assert_eq!(
        reopened.conflicts()?,
        vec![PartnerMirrorConflict {
            observed_at_unix_ms: 3_000,
            reason: "rollback".to_owned(),
            accepted_root: Some(accepted),
            offered_root: offered,
        }]
    );
    Ok(())
}

#[test]
fn a_tree_written_outside_the_mirror_refuses_every_apply() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mirror.sqlite3");
    let mirror = SqlitePartnerMirror::open(&path, "alpha")?;
    let first = [leaf(1, "passport-a")];
    let accepted = partner_root(&first, 2_000);
    mirror.apply(&accepted, &first, 2_000)?;
    SqliteRevocationOracle::open(&path)?
        .revoke(leaf(2, "passport-b").to_revocation_key(), 2_500)?;

    let next = [leaf(1, "passport-a"), leaf(2, "passport-b")];
    assert_eq!(
        mirror.apply(&partner_root(&next, 3_000), &next[1..], 3_000),
        Err(PartnerMirrorRefusal::Diverged.into())
    );
    assert_eq!(mirror.accepted()?, Some(accepted));
    Ok(())
}

#[test]
fn a_tampered_stored_root_is_refused_as_corrupt() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mirror.sqlite3");
    let mirror = SqlitePartnerMirror::open(&path, "alpha")?;
    let first = [leaf(1, "passport-a")];
    let accepted = partner_root(&first, 2_000);
    mirror.apply(&accepted, &first, 2_000)?;
    let mut stale = accepted.root.clone();
    stale.issued_at_unix_ms = 1_500;
    mirror.record_conflict("rollback", &signed(stale), 3_000)?;

    let raw = rusqlite::Connection::open(&path)?;
    raw.execute(
        "UPDATE chio_partner_revocation_conflicts SET offered_root = '{}'",
        [],
    )?;
    assert!(matches!(
        mirror.conflicts(),
        Err(SqliteRevocationOracleError::CorruptRecord(_))
    ));
    raw.execute(
        "UPDATE chio_partner_revocation_mirror SET signed_root = '{\"root\":null}'",
        [],
    )?;
    assert!(matches!(
        mirror.accepted(),
        Err(SqliteRevocationOracleError::CorruptRecord(_))
    ));
    assert!(matches!(
        mirror.apply(&accepted, &[], 4_000),
        Err(PartnerMirrorError::Store(
            SqliteRevocationOracleError::CorruptRecord(_)
        ))
    ));
    Ok(())
}

#[test]
fn an_apply_against_a_held_write_lock_fails_and_commits_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mirror.sqlite3");
    let mirror = SqlitePartnerMirror::open(&path, "alpha")?;
    let first = [leaf(1, "passport-a")];
    let offered = partner_root(&first, 2_000);

    mirror.oracle.set_busy_timeout(std::time::Duration::ZERO)?;
    let blocker = rusqlite::Connection::open(&path)?;
    blocker.execute_batch("BEGIN IMMEDIATE")?;
    assert!(matches!(
        mirror.apply(&offered, &first, 2_000),
        Err(PartnerMirrorError::Store(
            SqliteRevocationOracleError::Storage(_)
        ))
    ));
    blocker.execute_batch("ROLLBACK")?;

    assert_eq!(mirror.accepted()?, None);
    assert_eq!(mirror.view(&[])?.tree.leaf_count, 0);
    mirror.apply(&offered, &first, 2_000)?;
    assert_eq!(mirror.accepted()?, Some(offered));
    Ok(())
}

#[test]
fn an_oversized_leaf_subject_is_refused_and_commits_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mirror = SqlitePartnerMirror::open(&dir.path().join("mirror.sqlite3"), "alpha")?;
    let oversized = [leaf(1, &"x".repeat(MAX_REVOCATION_SUBJECT_BYTES + 1))];
    let offered = partner_root(&[leaf(1, "passport-a")], 2_000);
    assert_eq!(
        mirror.apply(&offered, &oversized, 2_000),
        Err(PartnerMirrorRefusal::SubjectTooLong { seq: 1 }.into())
    );
    assert_eq!(mirror.accepted()?, None);
    assert_eq!(mirror.view(&[])?.tree.leaf_count, 0);
    Ok(())
}
