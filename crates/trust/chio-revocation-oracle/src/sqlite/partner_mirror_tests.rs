use chio_test_support::prelude::*;

use super::*;
use crate::{
    InMemoryRevocationOracle, PassportRevocationLeafKind, RevocationOracle, RootSignature,
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
