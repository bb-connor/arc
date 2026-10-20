use std::path::{Path, PathBuf};

use chio_core::Keypair;
use chio_revocation_oracle::{
    passport_revocation_key, EpochRoot, SignedEpochRoot, SqliteRevocationOracle,
};
use chio_security_types::clock::FixedClock;

use super::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
    PartnerRevocationSource, MAX_PARTNER_ROOT_FUTURE_SKEW_MS, MAX_PARTNER_SYNC_LEAVES,
};
use crate::passport_revocation::passport_revocation_oracle_path;
use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, passport_revocation_root_signer_id,
    sign_passport_revocation_root, PassportRevocationLeaf, PassportRevocationLeavesPage,
    MAX_PASSPORT_REVOCATION_PAGE_LEAVES, PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::revocation_partner::RevocationPartner;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PARTNER: &str = "acme";
const TTL_SECONDS: u64 = 60;

fn authority() -> Keypair {
    Keypair::from_seed(&[21; 32])
}

fn partner_for(key: &Keypair) -> RevocationPartner {
    RevocationPartner {
        partner_id: PARTNER.to_owned(),
        issuer: "https://trust.acme.example".to_owned(),
        authority_public_key: key.public_key(),
        revocation_freshness_ttl_seconds: TTL_SECONDS,
    }
}

fn partner() -> RevocationPartner {
    partner_for(&authority())
}

/// Partner A: a passport registry path whose revocation oracle it publishes.
struct Publisher {
    _dir: tempfile::TempDir,
    registry: PathBuf,
}

impl Publisher {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let registry = dir.path().join("a-passport-statuses.json");
        Ok(Self {
            _dir: dir,
            registry,
        })
    }

    fn revoke(&self, passport_id: &str, at: u64) -> TestResult {
        SqliteRevocationOracle::open(&passport_revocation_oracle_path(&self.registry)?)?
            .revoke(passport_revocation_key(passport_id), at)?;
        Ok(())
    }

    fn source(&self, now: u64) -> FeedSource<'_> {
        FeedSource {
            registry: &self.registry,
            signer: authority(),
            now,
            root_override: None,
            leaves_override: None,
            pages_served: 0,
        }
    }
}

/// Serves partner A's feed in process, with hooks that replace what it serves.
struct FeedSource<'a> {
    registry: &'a Path,
    signer: Keypair,
    now: u64,
    root_override: Option<SignedEpochRoot>,
    leaves_override: Option<Vec<PassportRevocationLeaf>>,
    pages_served: usize,
}

impl PartnerRevocationSource for FeedSource<'_> {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError> {
        if let Some(root) = self.root_override.clone() {
            return Ok(root);
        }
        sign_passport_revocation_root(self.registry, self.signer.clone(), self.now)
            .map_err(|error| PartnerRevocationError::Fetch(PARTNER.to_owned(), error.to_string()))
    }

    fn leaves_after(
        &mut self,
        after: u64,
    ) -> Result<PassportRevocationLeavesPage, PartnerRevocationError> {
        self.pages_served += 1;
        if let Some(leaves) = self.leaves_override.clone() {
            return Ok(PassportRevocationLeavesPage {
                schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
                after,
                leaves: leaves.into_iter().filter(|leaf| leaf.seq > after).collect(),
            });
        }
        passport_revocation_leaves_page(self.registry, after)
            .map_err(|error| PartnerRevocationError::Fetch(PARTNER.to_owned(), error.to_string()))
    }
}

/// Operator B's mirror of partner A.
fn mirror(dir: &Path) -> Result<PartnerRevocationMirror, Box<dyn std::error::Error>> {
    let path = partner_revocation_mirror_path(&dir.join("b-revocation-partners.json"), PARTNER)?;
    Ok(PartnerRevocationMirror::open(&path, PARTNER)?)
}

fn sign(root: EpochRoot, key: &Keypair) -> Result<SignedEpochRoot, Box<dyn std::error::Error>> {
    let signer = chio_revocation_oracle::Ed25519RootSigner::new(
        passport_revocation_root_signer_id(&key.public_key()),
        key.clone(),
    );
    Ok(SignedEpochRoot::sign(root, &signer)?)
}

#[test]
fn the_mirror_path_sits_beside_the_partner_registry_per_partner() -> TestResult {
    let registry = Path::new("/srv/chio/revocation-partners.json");
    assert_eq!(
        partner_revocation_mirror_path(registry, PARTNER)?,
        PathBuf::from("/srv/chio/revocation-partners.json.partner-acme.revocations.sqlite3")
    );
    Ok(())
}

#[test]
fn a_revocation_at_the_partner_denies_after_the_next_sync_on_the_same_handle() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;

    a.revoke("passport-other", 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    b.check_passport(&partner(), "passport-held", 10_000)?;

    a.revoke("passport-held", 11_000)?;
    b.sync(
        &partner(),
        &mut a.source(12_000),
        &FixedClock::from_millis(12_000),
    )?;
    assert_eq!(
        b.check_passport(&partner(), "passport-held", 12_000),
        Err(PartnerRevocationError::Revoked {
            partner_id: PARTNER.to_owned(),
            passport_id: "passport-held".to_owned(),
        })
    );
    let accepted = b.accepted()?.ok_or("no accepted root")?;
    assert_eq!(accepted.cursor_seq, 2);
    assert_eq!(accepted.signed_root.root.leaf_count, 2);
    assert_eq!(accepted.signed_root.root.issued_at_unix_ms, 12_000);
    Ok(())
}

#[test]
fn a_mirror_with_no_verified_root_denies() -> TestResult {
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    assert_eq!(
        b.check_passport(&partner(), "passport-held", 10_000),
        Err(PartnerRevocationError::NoVerifiedRoot(PARTNER.to_owned()))
    );
    Ok(())
}

#[test]
fn a_root_older_than_the_freshness_ttl_denies() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let ttl_ms = TTL_SECONDS * 1_000;
    b.check_passport(&partner(), "passport-held", 10_000 + ttl_ms)?;
    assert_eq!(
        b.check_passport(&partner(), "passport-held", 10_001 + ttl_ms),
        Err(PartnerRevocationError::StaleRoot {
            partner_id: PARTNER.to_owned(),
            issued_at_unix_ms: 10_000,
            now_unix_ms: 10_001 + ttl_ms,
            ttl_ms,
        })
    );
    Ok(())
}

#[test]
fn a_root_signed_by_another_key_is_refused_and_changes_nothing() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-held", 1_000)?;
    let mut forged = a.source(10_000);
    forged.signer = Keypair::from_seed(&[99; 32]);
    assert_eq!(
        b.sync(&partner(), &mut forged, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::UnverifiableRoot(PARTNER.to_owned()))
    );
    assert_eq!(b.accepted()?, None);
    assert_eq!(forged.pages_served, 0);
    Ok(())
}

#[test]
fn a_tampered_signature_is_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let mut signed = sign_passport_revocation_root(&a.registry, authority(), 10_000)?;
    signed.root.issued_at_unix_ms += 1;
    let mut source = a.source(10_000);
    source.root_override = Some(signed);
    assert_eq!(
        b.sync(&partner(), &mut source, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::UnverifiableRoot(PARTNER.to_owned()))
    );
    Ok(())
}

#[test]
fn a_rotated_partner_key_no_longer_verifies_the_accepted_root() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let rotated = partner_for(&Keypair::from_seed(&[22; 32]));
    assert_eq!(
        b.check_passport(&rotated, "passport-held", 10_000),
        Err(PartnerRevocationError::UnverifiableRoot(PARTNER.to_owned()))
    );
    Ok(())
}

#[test]
fn an_older_epoch_is_refused_as_a_rollback() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-a", 1_000)?;
    let old = sign_passport_revocation_root(&a.registry, authority(), 10_000)?;
    a.revoke("passport-b", 11_000)?;
    b.sync(
        &partner(),
        &mut a.source(12_000),
        &FixedClock::from_millis(12_000),
    )?;

    let mut replay = a.source(13_000);
    replay.root_override = Some(old);
    assert_eq!(
        b.sync(&partner(), &mut replay, &FixedClock::from_millis(13_000)),
        Err(PartnerRevocationError::Rollback {
            partner_id: PARTNER.to_owned(),
            accepted: 2,
            offered: 1,
        })
    );
    assert_eq!(
        b.accepted()?
            .ok_or("no accepted root")?
            .signed_root
            .root
            .epoch,
        2
    );
    Ok(())
}

#[test]
fn an_older_attestation_of_the_same_epoch_is_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let earlier = sign_passport_revocation_root(&a.registry, authority(), 10_000)?;
    b.sync(
        &partner(),
        &mut a.source(12_000),
        &FixedClock::from_millis(12_000),
    )?;
    let mut replay = a.source(13_000);
    replay.root_override = Some(earlier);
    assert_eq!(
        b.sync(&partner(), &mut replay, &FixedClock::from_millis(13_000)),
        Err(PartnerRevocationError::AttestationRollback {
            partner_id: PARTNER.to_owned(),
            accepted: 12_000,
            offered: 10_000,
        })
    );
    Ok(())
}

#[test]
fn a_newer_attestation_of_the_same_root_refreshes_without_leaves() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-a", 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let mut refresh = a.source(70_000);
    b.sync(&partner(), &mut refresh, &FixedClock::from_millis(70_000))?;
    assert_eq!(refresh.pages_served, 0);
    b.check_passport(&partner(), "passport-held", 70_000 + TTL_SECONDS * 1_000)?;
    Ok(())
}

#[test]
fn leaves_that_do_not_rebuild_the_signed_root_are_refused_and_recorded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-held", 1_000)?;
    let mut lying = a.source(10_000);
    lying.leaves_override = Some(vec![PassportRevocationLeaf {
        seq: 1,
        subject: "passport-decoy".to_owned(),
        epoch_nonce: passport_revocation_key("passport-decoy").epoch_nonce.get(),
    }]);
    assert_eq!(
        b.sync(&partner(), &mut lying, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::RootMismatch {
            partner_id: PARTNER.to_owned(),
            epoch: 1,
        })
    );
    assert_eq!(b.accepted()?, None);
    assert_eq!(b.oracle.current_epoch_root()?.leaf_count, 0);
    let conflicts = b.conflicts()?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].accepted_root, None);
    assert_eq!(conflicts[0].offered_root.root.leaf_count, 1);
    assert_eq!(conflicts[0].observed_at_unix_ms, 10_000);
    Ok(())
}

#[test]
fn two_signed_roots_for_one_epoch_are_refused_as_equivocation_and_recorded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-a", 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let accepted = b.accepted()?.ok_or("no accepted root")?.signed_root;

    let mut other = accepted.root.clone();
    other.root_hash = [7; 32];
    other.issued_at_unix_ms = 11_000;
    let mut equivocating = a.source(11_000);
    equivocating.root_override = Some(sign(other, &authority())?);
    assert_eq!(
        b.sync(
            &partner(),
            &mut equivocating,
            &FixedClock::from_millis(11_000)
        ),
        Err(PartnerRevocationError::Equivocation {
            partner_id: PARTNER.to_owned(),
            epoch: 1,
        })
    );
    assert_eq!(
        b.accepted()?.ok_or("no accepted root")?.signed_root,
        accepted
    );
    let conflicts = b.conflicts()?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].accepted_root.as_ref(), Some(&accepted));
    assert_eq!(conflicts[0].offered_root.root.root_hash, [7; 32]);
    Ok(())
}

#[test]
fn a_root_dated_past_the_skew_is_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let ahead = 10_001 + MAX_PARTNER_ROOT_FUTURE_SKEW_MS;
    assert_eq!(
        b.sync(
            &partner(),
            &mut a.source(ahead),
            &FixedClock::from_millis(10_000)
        ),
        Err(PartnerRevocationError::FutureRoot {
            partner_id: PARTNER.to_owned(),
            issued_at_unix_ms: ahead,
            now_unix_ms: 10_000,
        })
    );
    b.sync(
        &partner(),
        &mut a.source(10_000 + MAX_PARTNER_ROOT_FUTURE_SKEW_MS),
        &FixedClock::from_millis(10_000),
    )?;
    b.check_passport(&partner(), "passport-held", 10_000)?;
    Ok(())
}

#[test]
fn leaves_that_end_before_the_signed_count_are_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-a", 1_000)?;
    a.revoke("passport-b", 1_000)?;
    let mut short = a.source(10_000);
    short.leaves_override = Some(vec![PassportRevocationLeaf {
        seq: 1,
        subject: "passport-a".to_owned(),
        epoch_nonce: passport_revocation_key("passport-a").epoch_nonce.get(),
    }]);
    assert_eq!(
        b.sync(&partner(), &mut short, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::TruncatedLeaves(PARTNER.to_owned()))
    );
    assert_eq!(b.accepted()?, None);
    Ok(())
}

#[test]
fn a_page_out_of_sequence_is_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-a", 1_000)?;
    a.revoke("passport-b", 1_000)?;
    let leaf = |seq, subject: &str| PassportRevocationLeaf {
        seq,
        subject: subject.to_owned(),
        epoch_nonce: passport_revocation_key(subject).epoch_nonce.get(),
    };
    let mut reordered = a.source(10_000);
    reordered.leaves_override = Some(vec![leaf(2, "passport-b"), leaf(1, "passport-a")]);
    assert_eq!(
        b.sync(&partner(), &mut reordered, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::MalformedPage(
            PARTNER.to_owned(),
            "leaf sequence is not strictly increasing".to_owned()
        ))
    );
    let mut repeated = a.source(10_000);
    repeated.leaves_override = Some(vec![leaf(1, "passport-a"), leaf(2, "passport-a")]);
    assert_eq!(
        b.sync(&partner(), &mut repeated, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::DuplicateLeaf {
            partner_id: PARTNER.to_owned(),
            seq: 2,
        })
    );
    assert_eq!(b.accepted()?, None);
    Ok(())
}

#[test]
fn a_partner_beyond_the_sync_bound_is_refused_before_any_page() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let behind = MAX_PARTNER_SYNC_LEAVES + 1;
    let root = EpochRoot {
        epoch: behind,
        root_hash: [1; 32],
        leaf_count: usize::try_from(behind)?,
        issued_at_unix_ms: 10_000,
    };
    let mut far = a.source(10_000);
    far.root_override = Some(sign(root, &authority())?);
    assert_eq!(
        b.sync(&partner(), &mut far, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::TooFarBehind {
            partner_id: PARTNER.to_owned(),
            behind,
        })
    );
    assert_eq!(far.pages_served, 0);
    Ok(())
}

#[test]
fn a_sync_spans_pages_and_resumes_from_the_cursor() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    SqliteRevocationOracle::open(&passport_revocation_oracle_path(&a.registry)?)?.transact(
        1_000,
        |txn| {
            for index in 0..MAX_PASSPORT_REVOCATION_PAGE_LEAVES + 10 {
                txn.revoke(&passport_revocation_key(&format!("passport-{index}")))?;
            }
            Ok(())
        },
    )?;
    let mut first = a.source(10_000);
    b.sync(&partner(), &mut first, &FixedClock::from_millis(10_000))?;
    assert_eq!(first.pages_served, 2);

    a.revoke("passport-late", 11_000)?;
    let mut second = a.source(12_000);
    b.sync(&partner(), &mut second, &FixedClock::from_millis(12_000))?;
    assert_eq!(second.pages_served, 1);
    assert_eq!(
        b.check_passport(&partner(), "passport-late", 12_000),
        Err(PartnerRevocationError::Revoked {
            partner_id: PARTNER.to_owned(),
            passport_id: "passport-late".to_owned(),
        })
    );
    assert_eq!(
        b.check_passport(&partner(), "passport-0", 12_000),
        Err(PartnerRevocationError::Revoked {
            partner_id: PARTNER.to_owned(),
            passport_id: "passport-0".to_owned(),
        })
    );
    Ok(())
}

#[test]
fn a_second_handle_on_the_mirror_observes_a_sync_without_reopening() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let syncer = mirror(dir.path())?;
    let door = mirror(dir.path())?;
    a.revoke("passport-held", 1_000)?;
    syncer.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    assert_eq!(
        door.check_passport(&partner(), "passport-held", 10_000),
        Err(PartnerRevocationError::Revoked {
            partner_id: PARTNER.to_owned(),
            passport_id: "passport-held".to_owned(),
        })
    );
    Ok(())
}

#[test]
fn a_mirror_stamped_for_another_partner_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mirror.sqlite3");
    PartnerRevocationMirror::open(&path, PARTNER)?;
    assert!(matches!(
        PartnerRevocationMirror::open(&path, "bravo"),
        Err(PartnerRevocationError::PartnerMismatch { expected, found })
            if expected == "bravo" && found == PARTNER
    ));
    Ok(())
}

#[test]
fn a_repeated_conflicting_root_is_recorded_once_and_the_log_is_bounded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke("passport-a", 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let accepted = b.accepted()?.ok_or("no accepted root")?.signed_root;
    let equivocate = |hash: [u8; 32]| -> Result<SignedEpochRoot, Box<dyn std::error::Error>> {
        let mut other = accepted.root.clone();
        other.root_hash = hash;
        other.issued_at_unix_ms = 11_000;
        sign(other, &authority())
    };
    let equivocation = PartnerRevocationError::Equivocation {
        partner_id: PARTNER.to_owned(),
        epoch: 1,
    };
    let repeated = equivocate([7; 32])?;
    for _ in 0..3 {
        assert_eq!(
            b.apply(&partner(), &repeated, &[], 11_000),
            Err(equivocation.clone())
        );
    }
    assert_eq!(b.conflicts()?.len(), 1);

    let bound = usize::try_from(super::MAX_RECORDED_PARTNER_CONFLICTS)?;
    for index in 1..bound {
        let mut hash = [0_u8; 32];
        hash[..8].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
        assert_eq!(
            b.apply(&partner(), &equivocate(hash)?, &[], 11_000),
            Err(equivocation.clone())
        );
    }
    assert_eq!(b.conflicts()?.len(), bound);
    assert_eq!(
        b.apply(&partner(), &equivocate([9; 32])?, &[], 11_000),
        Err(PartnerRevocationError::ConflictLogFull(PARTNER.to_owned()))
    );
    assert_eq!(
        b.apply(&partner(), &repeated, &[], 11_000),
        Err(equivocation)
    );
    assert_eq!(b.conflicts()?.len(), bound);
    Ok(())
}

#[test]
fn a_mirror_tree_that_diverges_from_its_accepted_root_is_unavailable() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    SqliteRevocationOracle::open(&partner_revocation_mirror_path(
        &dir.path().join("b-revocation-partners.json"),
        PARTNER,
    )?)?
    .revoke(passport_revocation_key("passport-planted"), 10_000)?;
    assert_eq!(
        b.check_passport(&partner(), "passport-held", 10_000),
        Err(PartnerRevocationError::MirrorUnavailable(
            PARTNER.to_owned(),
            "mirror tree does not match its accepted root".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn a_failing_clock_refuses_the_sync_after_the_fetch() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    assert_eq!(
        b.sync(
            &partner(),
            &mut a.source(10_000),
            &FixedClock::new(u64::MAX)
        ),
        Err(PartnerRevocationError::Clock(
            chio_security_types::clock::ClockError::Overflow.to_string()
        ))
    );
    assert_eq!(b.accepted()?, None);
    Ok(())
}
