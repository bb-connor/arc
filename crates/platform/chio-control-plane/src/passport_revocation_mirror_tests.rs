use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core::Keypair;
use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, EpochRoot, PassportRevocationLeaf,
    PassportRevocationLeafKind, RevocationKey, SignedEpochRoot, SqliteRevocationOracle,
    MAX_REVOCATION_SUBJECT_BYTES,
};
use chio_security_types::clock::FixedClock;

use super::{
    partner_revocation_mirror_path, PartnerMirrorCache, PartnerRevocationError,
    PartnerRevocationMirror, PartnerRevocationSource, MAX_PARTNER_ROOT_FUTURE_SKEW_MS,
    MAX_PARTNER_SYNC_LEAVES, MAX_RECORDED_PARTNER_CONFLICTS,
};
use crate::passport_revocation::passport_revocation_oracle_path;
use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, passport_revocation_root_signer_id,
    sign_passport_revocation_root, PassportRevocationLeavesPage,
    MAX_PASSPORT_REVOCATION_PAGE_LEAVES, PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::revocation_partner::{RevocationPartner, RevocationPartnerRegistry};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

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
        issuer_public_keys: vec![key.public_key()],
        revocation_freshness_ttl_seconds: TTL_SECONDS,
    }
}

fn partner() -> RevocationPartner {
    partner_for(&authority())
}

fn passport(passport_id: &str) -> Vec<RevocationKey> {
    vec![passport_revocation_key(passport_id)]
}

fn revoked(subject: &str) -> PartnerRevocationError {
    PartnerRevocationError::Revoked {
        partner_id: PARTNER.to_owned(),
        subject: subject.to_owned(),
    }
}

fn leaf(seq: u64, subject: &str) -> PassportRevocationLeaf {
    PassportRevocationLeaf {
        seq,
        kind: PassportRevocationLeafKind::Passport,
        subject: subject.to_owned(),
    }
}

/// Partner A: the revocation oracle it publishes beside its lifecycle registry.
struct Publisher {
    _dir: tempfile::TempDir,
    registry: PathBuf,
    oracle: SqliteRevocationOracle,
}

impl Publisher {
    fn new() -> Fallible<Self> {
        let dir = tempfile::tempdir()?;
        let registry = dir.path().join("a-passport-statuses.json");
        let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(&registry)?)?;
        Ok(Self {
            _dir: dir,
            registry,
            oracle,
        })
    }

    fn revoke(&self, key: RevocationKey, at: u64) -> TestResult {
        self.oracle.revoke(key, at)?;
        Ok(())
    }

    fn signed(&self, now: u64) -> Fallible<SignedEpochRoot> {
        Ok(sign_passport_revocation_root(
            &self.oracle,
            &self.registry,
            authority(),
            now,
        )?)
    }

    fn source(&self, now: u64) -> FeedSource<'_> {
        FeedSource {
            publisher: self,
            signer: authority(),
            now,
            root_override: None,
            leaves_override: None,
            requested: Vec::new(),
        }
    }
}

/// Serves partner A's feed in process, with hooks that replace what it serves.
struct FeedSource<'a> {
    publisher: &'a Publisher,
    signer: Keypair,
    now: u64,
    root_override: Option<SignedEpochRoot>,
    leaves_override: Option<Vec<PassportRevocationLeaf>>,
    requested: Vec<u64>,
}

impl PartnerRevocationSource for FeedSource<'_> {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError> {
        if let Some(root) = self.root_override.clone() {
            return Ok(root);
        }
        sign_passport_revocation_root(
            &self.publisher.oracle,
            &self.publisher.registry,
            self.signer.clone(),
            self.now,
        )
        .map_err(|error| PartnerRevocationError::Fetch(PARTNER.to_owned(), error.to_string()))
    }

    fn leaves_after(
        &mut self,
        after: u64,
    ) -> Result<PassportRevocationLeavesPage, PartnerRevocationError> {
        self.requested.push(after);
        if let Some(leaves) = self.leaves_override.clone() {
            return Ok(PassportRevocationLeavesPage {
                schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
                after,
                leaves,
            });
        }
        passport_revocation_leaves_page(&self.publisher.oracle, &self.publisher.registry, after)
            .map_err(|error| PartnerRevocationError::Fetch(PARTNER.to_owned(), error.to_string()))
    }
}

fn registry_path(dir: &Path) -> PathBuf {
    dir.join("b-revocation-partners.json")
}

/// Operator B's mirror of partner A.
fn mirror(dir: &Path) -> Fallible<PartnerRevocationMirror> {
    let path = partner_revocation_mirror_path(&registry_path(dir), PARTNER)?;
    Ok(PartnerRevocationMirror::open(&path, PARTNER)?)
}

fn sign(root: EpochRoot, key: &Keypair) -> Fallible<SignedEpochRoot> {
    let signer = chio_revocation_oracle::Ed25519RootSigner::new(
        passport_revocation_root_signer_id(&key.public_key()),
        key.clone(),
    );
    Ok(SignedEpochRoot::sign(root, &signer)?)
}

fn accepted(mirror: &PartnerRevocationMirror) -> Fallible<SignedEpochRoot> {
    Ok(mirror.accepted()?.ok_or("no accepted root")?)
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

    a.revoke(passport_revocation_key("passport-other"), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    b.check_passport(&partner(), &passport("passport-held"), 10_000)?;

    a.revoke(passport_revocation_key("passport-held"), 11_000)?;
    b.sync(
        &partner(),
        &mut a.source(12_000),
        &FixedClock::from_millis(12_000),
    )?;
    assert_eq!(
        b.check_passport(&partner(), &passport("passport-held"), 12_000),
        Err(revoked("passport-held"))
    );
    let root = accepted(&b)?.root;
    assert_eq!(root.leaf_count, 2);
    assert_eq!(root.issued_at_unix_ms, 12_000);
    Ok(())
}

#[test]
fn check_passport_denies_on_a_credential_leaf() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let digest = "cd".repeat(32);
    a.revoke(credential_revocation_key(&digest), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let subjects = [
        passport_revocation_key("passport-held"),
        credential_revocation_key(&"ab".repeat(32)),
    ];
    b.check_passport(&partner(), &subjects, 10_000)?;
    let subjects = [
        passport_revocation_key("passport-held"),
        credential_revocation_key(&digest),
    ];
    assert_eq!(
        b.check_passport(&partner(), &subjects, 10_000),
        Err(revoked(&digest))
    );
    assert_eq!(
        b.check_passport(&partner(), &passport(&digest), 10_000),
        Ok(())
    );
    Ok(())
}

#[test]
fn a_mirror_with_no_verified_root_denies() -> TestResult {
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    assert_eq!(
        b.check_passport(&partner(), &passport("passport-held"), 10_000),
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
    b.check_passport(&partner(), &passport("passport-held"), 10_000 + ttl_ms)?;
    assert_eq!(
        b.check_passport(&partner(), &passport("passport-held"), 10_001 + ttl_ms),
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
    a.revoke(passport_revocation_key("passport-held"), 1_000)?;
    let mut forged = a.source(10_000);
    forged.signer = Keypair::from_seed(&[99; 32]);
    assert_eq!(
        b.sync(&partner(), &mut forged, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::UnverifiableRoot(PARTNER.to_owned()))
    );
    assert_eq!(b.accepted()?, None);
    assert!(forged.requested.is_empty());
    Ok(())
}

#[test]
fn a_tampered_signature_is_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let mut signed = a.signed(10_000)?;
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
        b.check_passport(&rotated, &passport("passport-held"), 10_000),
        Err(PartnerRevocationError::UnverifiableRoot(PARTNER.to_owned()))
    );
    Ok(())
}

#[test]
fn an_older_epoch_is_refused_as_a_rollback_and_recorded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    let old = a.signed(10_000)?;
    a.revoke(passport_revocation_key("passport-b"), 11_000)?;
    b.sync(
        &partner(),
        &mut a.source(12_000),
        &FixedClock::from_millis(12_000),
    )?;
    let current = accepted(&b)?;

    let mut replay = a.source(13_000);
    replay.root_override = Some(old.clone());
    assert_eq!(
        b.sync(&partner(), &mut replay, &FixedClock::from_millis(13_000)),
        Err(PartnerRevocationError::Rollback {
            partner_id: PARTNER.to_owned(),
            accepted: 2,
            offered: 1,
        })
    );
    assert_eq!(accepted(&b)?, current);
    let conflicts = b.conflicts()?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].offered_root, old);
    assert_eq!(conflicts[0].accepted_root.as_ref(), Some(&current));
    Ok(())
}

#[test]
fn an_older_attestation_of_the_same_epoch_is_refused_and_recorded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let earlier = a.signed(10_000)?;
    b.sync(
        &partner(),
        &mut a.source(12_000),
        &FixedClock::from_millis(12_000),
    )?;
    let mut replay = a.source(13_000);
    replay.root_override = Some(earlier.clone());
    assert_eq!(
        b.sync(&partner(), &mut replay, &FixedClock::from_millis(13_000)),
        Err(PartnerRevocationError::AttestationRollback {
            partner_id: PARTNER.to_owned(),
            accepted: 12_000,
            offered: 10_000,
        })
    );
    let conflicts = b.conflicts()?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].offered_root, earlier);
    Ok(())
}

#[test]
fn a_newer_attestation_of_the_same_root_refreshes_without_leaves() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let mut refresh = a.source(70_000);
    b.sync(&partner(), &mut refresh, &FixedClock::from_millis(70_000))?;
    assert!(refresh.requested.is_empty());
    b.check_passport(
        &partner(),
        &passport("passport-held"),
        70_000 + TTL_SECONDS * 1_000,
    )?;
    Ok(())
}

#[test]
fn leaves_that_do_not_rebuild_the_signed_root_are_refused_and_recorded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-held"), 1_000)?;
    let mut lying = a.source(10_000);
    lying.leaves_override = Some(vec![leaf(1, "passport-decoy")]);
    assert_eq!(
        b.sync(&partner(), &mut lying, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::RootMismatch {
            partner_id: PARTNER.to_owned(),
            epoch: 1,
        })
    );
    assert_eq!(b.accepted()?, None);
    assert_eq!(b.store.view(&[])?.tree.leaf_count, 0);
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
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let current = accepted(&b)?;

    let mut other = current.root.clone();
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
    assert_eq!(accepted(&b)?, current);
    let conflicts = b.conflicts()?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].accepted_root.as_ref(), Some(&current));
    assert_eq!(conflicts[0].offered_root.root.root_hash, [7; 32]);
    Ok(())
}

#[test]
fn two_roots_equal_in_epoch_and_hash_but_not_leaf_count_are_both_recorded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let current = accepted(&b)?.root;
    for leaf_count in [2, 3] {
        let offered = sign(
            EpochRoot {
                leaf_count,
                issued_at_unix_ms: 11_000,
                ..current.clone()
            },
            &authority(),
        )?;
        assert_eq!(
            b.apply(&partner(), &offered, &[], 11_000),
            Err(PartnerRevocationError::Equivocation {
                partner_id: PARTNER.to_owned(),
                epoch: current.epoch,
            })
        );
    }
    let recorded = b
        .conflicts()?
        .into_iter()
        .map(|conflict| conflict.offered_root.root.leaf_count)
        .collect::<Vec<_>>();
    assert_eq!(recorded, vec![2, 3]);
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
    b.check_passport(&partner(), &passport("passport-held"), 10_000)?;
    Ok(())
}

#[test]
fn leaves_that_end_before_the_signed_count_are_refused() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    a.revoke(passport_revocation_key("passport-b"), 1_000)?;
    let mut short = a.source(10_000);
    short.leaves_override = Some(Vec::new());
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
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    a.revoke(passport_revocation_key("passport-b"), 1_000)?;
    let mut reordered = a.source(10_000);
    reordered.leaves_override = Some(vec![leaf(2, "passport-b"), leaf(1, "passport-a")]);
    assert_eq!(
        b.sync(&partner(), &mut reordered, &FixedClock::from_millis(10_000)),
        Err(PartnerRevocationError::MalformedPage(
            PARTNER.to_owned(),
            "leaf sequence is not contiguous".to_owned()
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
fn a_page_whose_seq_skips_is_refused_and_the_mirror_is_unchanged() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let before = accepted(&b)?;
    a.revoke(passport_revocation_key("passport-b"), 11_000)?;
    a.revoke(passport_revocation_key("passport-c"), 11_000)?;
    let mut skipping = a.source(12_000);
    skipping.leaves_override = Some(vec![leaf(2, "passport-b"), leaf(4, "passport-c")]);
    assert_eq!(
        b.sync(&partner(), &mut skipping, &FixedClock::from_millis(12_000)),
        Err(PartnerRevocationError::MalformedPage(
            PARTNER.to_owned(),
            "leaf sequence is not contiguous".to_owned()
        ))
    );
    assert_eq!(accepted(&b)?, before);
    assert_eq!(b.store.view(&[])?.tree.leaf_count, 1);
    assert_eq!(
        b.apply(
            &partner(),
            &a.signed(12_000)?,
            &[leaf(3, "passport-b"), leaf(4, "passport-c")],
            12_000
        ),
        Err(PartnerRevocationError::MalformedPage(
            PARTNER.to_owned(),
            "leaf 3 does not follow mirror leaf 1".to_owned()
        ))
    );
    assert_eq!(accepted(&b)?, before);
    Ok(())
}

#[test]
fn a_mirror_keeps_its_cursor_as_its_leaf_count_across_reopen() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    a.revoke(passport_revocation_key("passport-b"), 1_000)?;
    {
        let b = mirror(dir.path())?;
        let mut first = a.source(10_000);
        b.sync(&partner(), &mut first, &FixedClock::from_millis(10_000))?;
        assert_eq!(first.requested, vec![0]);
    }
    a.revoke(passport_revocation_key("passport-c"), 11_000)?;
    let reopened = mirror(dir.path())?;
    assert_eq!(accepted(&reopened)?.root.leaf_count, 2);
    let mut second = a.source(12_000);
    reopened.sync(&partner(), &mut second, &FixedClock::from_millis(12_000))?;
    assert_eq!(second.requested, vec![2]);
    assert_eq!(
        reopened.check_passport(&partner(), &passport("passport-c"), 12_000),
        Err(revoked("passport-c"))
    );
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
    assert!(far.requested.is_empty());
    Ok(())
}

#[test]
fn a_sync_spans_pages_and_resumes_from_the_leaf_count() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let total = MAX_PASSPORT_REVOCATION_PAGE_LEAVES + 10;
    a.oracle.transact(1_000, |txn| {
        for index in 0..total {
            txn.revoke(&passport_revocation_key(&format!("passport-{index}")))?;
        }
        Ok(())
    })?;
    let mut first = a.source(10_000);
    b.sync(&partner(), &mut first, &FixedClock::from_millis(10_000))?;
    assert_eq!(
        first.requested,
        vec![
            0,
            crate::integer::count(MAX_PASSPORT_REVOCATION_PAGE_LEAVES)
        ]
    );

    a.revoke(passport_revocation_key("passport-late"), 11_000)?;
    let mut second = a.source(12_000);
    b.sync(&partner(), &mut second, &FixedClock::from_millis(12_000))?;
    assert_eq!(second.requested, vec![crate::integer::count(total)]);
    for subject in ["passport-late", "passport-0"] {
        assert_eq!(
            b.check_passport(&partner(), &passport(subject), 12_000),
            Err(revoked(subject))
        );
    }
    Ok(())
}

#[test]
fn a_second_handle_on_the_mirror_observes_a_sync_without_reopening() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let syncer = mirror(dir.path())?;
    let door = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-held"), 1_000)?;
    syncer.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    assert_eq!(
        door.check_passport(&partner(), &passport("passport-held"), 10_000),
        Err(revoked("passport-held"))
    );
    Ok(())
}

#[test]
fn a_repeated_conflicting_root_is_recorded_once_and_the_log_is_bounded() -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    a.revoke(passport_revocation_key("passport-a"), 1_000)?;
    b.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let current = accepted(&b)?;
    let equivocate = |hash: [u8; 32]| -> Fallible<SignedEpochRoot> {
        let mut other = current.root.clone();
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

    let bound = usize::try_from(MAX_RECORDED_PARTNER_CONFLICTS)?;
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
        &registry_path(dir.path()),
        PARTNER,
    )?)?
    .revoke(passport_revocation_key("passport-planted"), 10_000)?;
    let diverged = PartnerRevocationError::MirrorUnavailable(
        PARTNER.to_owned(),
        "mirror tree does not match its accepted root".to_owned(),
    );
    assert_eq!(
        b.check_passport(&partner(), &passport("passport-held"), 10_000),
        Err(diverged.clone())
    );
    assert_eq!(
        b.sync(
            &partner(),
            &mut a.source(11_000),
            &FixedClock::from_millis(11_000)
        ),
        Err(diverged)
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

fn registry_listing(partner_ids: &[&str]) -> Fallible<RevocationPartnerRegistry> {
    let partners = partner_ids
        .iter()
        .zip(40_u8..)
        .map(|(partner_id, seed)| {
            let key = Keypair::from_seed(&[seed; 32]).public_key().to_hex();
            (
                (*partner_id).to_owned(),
                serde_json::json!({
                    "partnerId": partner_id,
                    "issuer": format!("https://trust.{partner_id}.example"),
                    "authorityPublicKey": key,
                    "issuerPublicKeys": [key],
                    "revocationFreshnessTtlSeconds": TTL_SECONDS,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": crate::revocation_partner::REVOCATION_PARTNER_REGISTRY_SCHEMA,
        "partners": partners,
    }))?;
    Ok(RevocationPartnerRegistry::from_json(&bytes)?)
}

#[test]
fn a_cached_mirror_handle_is_reused_across_syncs_and_dropped_when_the_registry_forgets_the_partner(
) -> TestResult {
    let a = Publisher::new()?;
    let dir = tempfile::tempdir()?;
    let registry = registry_path(dir.path());
    let cache = PartnerMirrorCache::default();
    let first = cache.mirror(&registry, PARTNER)?;
    first.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let second = cache.mirror(&registry, PARTNER)?;
    assert!(Arc::ptr_eq(&first, &second));
    cache.mirror(&registry, "bravo")?;

    cache.retain(&registry_listing(&[PARTNER])?)?;
    assert_eq!(cache.partner_ids()?, vec![PARTNER.to_owned()]);
    assert!(Arc::ptr_eq(&first, &cache.mirror(&registry, PARTNER)?));
    cache.retain(&registry_listing(&["bravo"])?)?;
    assert!(cache.partner_ids()?.is_empty());

    let reopened = cache.mirror(&registry, PARTNER)?;
    assert!(!Arc::ptr_eq(&first, &reopened));
    assert_eq!(reopened.accepted()?, first.accepted()?);

    let moved = dir.path().join("moved-revocation-partners.json");
    let relocated = cache.mirror(&moved, PARTNER)?;
    assert!(!Arc::ptr_eq(&reopened, &relocated));
    assert_eq!(relocated.accepted()?, None);
    Ok(())
}

/// Serves a fixed signed root and fixed pages keyed by their cursor.
struct FixedPages {
    root: SignedEpochRoot,
    pages: Vec<PassportRevocationLeavesPage>,
}

impl PartnerRevocationSource for FixedPages {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError> {
        Ok(self.root.clone())
    }

    fn leaves_after(
        &mut self,
        after: u64,
    ) -> Result<PassportRevocationLeavesPage, PartnerRevocationError> {
        self.pages
            .iter()
            .find(|page| page.after == after)
            .cloned()
            .ok_or_else(|| PartnerRevocationError::TruncatedLeaves(PARTNER.to_owned()))
    }
}

#[test]
fn a_full_page_past_the_offered_root_stages_only_the_leaves_up_to_it() -> TestResult {
    let a = Publisher::new()?;
    for subject in ["passport-1", "passport-2", "passport-3"] {
        a.revoke(passport_revocation_key(subject), 9_000)?;
    }
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let page = |after: u64, leaves: Vec<PassportRevocationLeaf>| PassportRevocationLeavesPage {
        schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
        after,
        leaves,
    };
    let full_page_after_one = (2..)
        .take(MAX_PASSPORT_REVOCATION_PAGE_LEAVES)
        .map(|seq| leaf(seq, &format!("passport-{seq}")))
        .collect();
    let mut source = FixedPages {
        root: a.signed(10_000)?,
        pages: vec![
            page(0, vec![leaf(1, "passport-1")]),
            page(1, full_page_after_one),
        ],
    };
    let staged = b.stage(&partner(), &mut source)?;
    assert_eq!(
        staged.leaves(),
        &[
            leaf(1, "passport-1"),
            leaf(2, "passport-2"),
            leaf(3, "passport-3")
        ][..]
    );
    b.commit(&partner(), staged, &FixedClock::from_millis(10_000))?;
    assert_eq!(accepted(&b)?.root.leaf_count, 3);
    Ok(())
}

#[test]
fn a_page_with_an_oversized_subject_is_refused_while_staging() -> TestResult {
    let a = Publisher::new()?;
    a.revoke(passport_revocation_key("passport-a"), 9_000)?;
    let dir = tempfile::tempdir()?;
    let b = mirror(dir.path())?;
    let mut oversized = a.source(10_000);
    oversized.leaves_override = Some(vec![leaf(1, &"x".repeat(MAX_REVOCATION_SUBJECT_BYTES + 1))]);
    assert_eq!(
        b.stage(&partner(), &mut oversized)
            .map(|staged| staged.leaves().len()),
        Err(PartnerRevocationError::MalformedPage(
            PARTNER.to_owned(),
            "leaf subject exceeds the revocation subject bound".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn a_check_overlapping_syncs_reads_one_committed_state() -> TestResult {
    const ROUNDS: u64 = 300;
    let a = Publisher::new()?;
    a.revoke(passport_revocation_key("passport-0"), 9_000)?;
    let dir = tempfile::tempdir()?;
    let syncer = mirror(dir.path())?;
    syncer.sync(
        &partner(),
        &mut a.source(10_000),
        &FixedClock::from_millis(10_000),
    )?;
    let checker = mirror(dir.path())?;
    let done = std::sync::atomic::AtomicBool::new(false);
    let checked = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let outcome = (1..=ROUNDS).try_for_each(|round| {
                let at = 10_000 + round;
                a.revoke(passport_revocation_key(&format!("passport-{round}")), at)
                    .map_err(|error| error.to_string())?;
                syncer
                    .sync(&partner(), &mut a.source(at), &FixedClock::from_millis(at))
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            });
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            outcome
        });
        let mut checks = Vec::new();
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            checks.push(checker.check_passport(
                &partner(),
                &passport("passport-unrelated"),
                10_000 + ROUNDS,
            ));
        }
        (writer.join(), checks)
    });
    let (writer, checks) = checked;
    assert_eq!(writer.map_err(|_| "writer panicked")?, Ok(()));
    assert_eq!(checks.iter().find(|check| check.is_err()), None);
    Ok(())
}
