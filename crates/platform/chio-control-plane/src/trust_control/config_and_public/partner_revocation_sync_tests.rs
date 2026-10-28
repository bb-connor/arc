use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core::Keypair;
use chio_revocation_oracle::{
    Ed25519RootSigner, EpochRoot, PassportRevocationLeaf, PassportRevocationLeafKind,
    SignedEpochRoot,
};
use chio_security_types::clock::FixedClock;

use super::super::portable_issuer_fetch::{
    build_portable_fetch_agent, PortableFetchDeadline, PORTABLE_ISSUER_FETCH_TOTAL_TIMEOUT,
};
use super::{sync_partner_revocation_mirror, sync_within, PartnerRevocationFeed};
use crate::bounded_worker_pool::tests::{drain, single_worker_pool};
use crate::passport_revocation::passport_revocation_oracle_path;
use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, sign_passport_revocation_root,
};
use crate::passport_revocation_feed::{
    passport_revocation_root_signer_id, PassportRevocationFeedError, PassportRevocationLeavesPage,
    PassportRevocationRootDocument, PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::passport_revocation_mirror::PartnerRevocationSource;
use crate::passport_revocation_mirror::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::revocation_partner::RevocationPartner;
use chio_revocation_oracle::{passport_revocation_key, SqliteRevocationOracle};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const PARTNER: &str = "acme";
const NOW_MS: u64 = 1_800_000_000_000;

fn authority() -> Keypair {
    Keypair::from_seed(&[31; 32])
}

fn revocation_partner(issuer: &str) -> RevocationPartner {
    RevocationPartner {
        partner_id: PARTNER.to_owned(),
        issuer: issuer.to_owned(),
        authority_public_key: authority().public_key(),
        issuer_public_keys: vec![authority().public_key()],
        revocation_freshness_ttl_seconds: 60,
    }
}

fn signed(root: EpochRoot) -> Fallible<SignedEpochRoot> {
    let key = authority();
    let signer = Ed25519RootSigner::new(passport_revocation_root_signer_id(&key.public_key()), key);
    Ok(SignedEpochRoot::sign(root, &signer)?)
}

struct Mirror {
    _dir: tempfile::TempDir,
    mirror: Arc<PartnerRevocationMirror>,
}

fn mirror() -> Fallible<Mirror> {
    let dir = tempfile::tempdir()?;
    let path =
        partner_revocation_mirror_path(&dir.path().join("b-revocation-partners.json"), PARTNER)?;
    let mirror = Arc::new(PartnerRevocationMirror::open(&path, PARTNER)?);
    Ok(Mirror { _dir: dir, mirror })
}

/// A loopback HTTP peer that answers each request with `respond(path)` after
/// `delay`, one connection at a time, and counts the leaf pages it served.
struct Peer {
    addr: std::net::SocketAddr,
    pages: Arc<AtomicUsize>,
}

fn peer(delay: Duration, respond: impl Fn(&str) -> String + Send + 'static) -> Fallible<Peer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let pages = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&pages);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            let mut request = [0_u8; 2048];
            let Ok(read) = stream.read(&mut request) else {
                continue;
            };
            let head = String::from_utf8_lossy(&request[..read]).into_owned();
            let path = head
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            if path.contains("/leaves") {
                served.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(delay);
            }
            let body = respond(&path);
            let _written = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    Ok(Peer { addr, pages })
}

fn loopback_feed(
    addr: std::net::SocketAddr,
    deadline: PortableFetchDeadline,
) -> Fallible<PartnerRevocationFeed> {
    let agent = build_portable_fetch_agent(vec![addr], false, &deadline)?;
    Ok(PartnerRevocationFeed::new(
        PARTNER,
        &format!("http://{addr}"),
        agent,
        deadline,
    ))
}

fn page_after(path: &str) -> u64 {
    path.split("after=")
        .nth(1)
        .and_then(|after| after.parse().ok())
        .unwrap_or_default()
}

#[test]
fn every_page_request_is_bounded_by_the_remaining_deadline() -> TestResult {
    const LEAVES: u64 = 1_024;
    let root = serde_json::to_string(&PassportRevocationRootDocument::new(signed(EpochRoot {
        epoch: LEAVES,
        root_hash: [1; 32],
        leaf_count: usize::try_from(LEAVES)?,
        issued_at_unix_ms: NOW_MS,
    })?))?;
    let stall = Duration::from_millis(300);
    let peer = peer(stall, move |path| {
        if !path.contains("/leaves") {
            return root.clone();
        }
        let after = page_after(path);
        let leaves = (after + 1..=(after + 256).min(LEAVES))
            .map(|seq| PassportRevocationLeaf {
                seq,
                kind: PassportRevocationLeafKind::Passport,
                subject: format!("passport-{seq}"),
            })
            .collect();
        serde_json::to_string(&PassportRevocationLeavesPage {
            schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
            after,
            leaves,
        })
        .unwrap_or_default()
    })?;
    let budget = Duration::from_millis(500);
    let started = Instant::now();
    let deadline = PortableFetchDeadline::starting_at(
        started
            .checked_sub(PORTABLE_ISSUER_FETCH_TOTAL_TIMEOUT - budget)
            .ok_or("monotonic clock too young for the deadline fixture")?,
    )?;
    let mirror = mirror()?;
    let mut feed = loopback_feed(peer.addr, deadline)?;
    let refused = mirror
        .mirror
        .sync(
            &revocation_partner("https://trust.acme.example"),
            &mut feed,
            &FixedClock::from_millis(NOW_MS),
        )
        .err()
        .ok_or("a sync past its deadline must refuse")?;
    let elapsed = started.elapsed();
    assert!(
        matches!(&refused, PartnerRevocationError::Fetch(partner_id, _) if partner_id == PARTNER),
        "{refused}"
    );
    assert!(elapsed < budget + stall, "{elapsed:?}");
    assert!(peer.pages.load(Ordering::SeqCst) <= 2);
    assert_eq!(mirror.mirror.accepted()?, None);
    Ok(())
}

#[test]
fn a_root_document_of_another_schema_is_refused_by_the_transport() -> TestResult {
    let root = signed(EpochRoot {
        epoch: 0,
        root_hash: [0; 32],
        leaf_count: 0,
        issued_at_unix_ms: NOW_MS,
    })?;
    let body = serde_json::to_string(&serde_json::json!({
        "schema": "chio.trust.passport-revocation-root.v2",
        "signedRoot": root,
    }))?;
    let peer = peer(Duration::ZERO, move |_| body.clone())?;
    let mirror = mirror()?;
    let mut feed = loopback_feed(peer.addr, PortableFetchDeadline::start()?)?;
    assert_eq!(
        mirror.mirror.sync(
            &revocation_partner("https://trust.acme.example"),
            &mut feed,
            &FixedClock::from_millis(NOW_MS),
        ),
        Err(PartnerRevocationError::MalformedRoot(
            PARTNER.to_owned(),
            PassportRevocationFeedError::UnsupportedSchema(
                "chio.trust.passport-revocation-root.v2".to_owned()
            )
            .to_string()
        ))
    );
    assert_eq!(mirror.mirror.accepted()?, None);
    Ok(())
}

#[test]
fn a_page_whose_cursor_differs_from_the_request_is_refused_by_the_mirror() -> TestResult {
    let root = serde_json::to_string(&PassportRevocationRootDocument::new(signed(EpochRoot {
        epoch: 1,
        root_hash: [1; 32],
        leaf_count: 1,
        issued_at_unix_ms: NOW_MS,
    })?))?;
    let page = serde_json::to_string(&PassportRevocationLeavesPage {
        schema: PASSPORT_REVOCATION_LEAVES_SCHEMA.to_owned(),
        after: 7,
        leaves: Vec::new(),
    })?;
    let peer = peer(Duration::ZERO, move |path| {
        if path.contains("/leaves") {
            page.clone()
        } else {
            root.clone()
        }
    })?;
    let mirror = mirror()?;
    let mut feed = loopback_feed(peer.addr, PortableFetchDeadline::start()?)?;
    assert_eq!(
        mirror.mirror.sync(
            &revocation_partner("https://trust.acme.example"),
            &mut feed,
            &FixedClock::from_millis(NOW_MS),
        ),
        Err(PartnerRevocationError::MalformedPage(
            PARTNER.to_owned(),
            "page cursor does not match the request".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn the_strict_transport_refuses_a_loopback_partner_before_any_fetch() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let mirror = mirror()?;
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let refused = sync_partner_revocation_mirror(
        Arc::clone(&mirror.mirror),
        revocation_partner(&format!("https://{addr}")),
        clock,
    )
    .err()
    .ok_or("a loopback partner must refuse")?;
    assert!(
        matches!(&refused, PartnerRevocationError::Fetch(partner_id, reason)
            if partner_id == PARTNER && reason.to_lowercase().contains("loopback")),
        "{refused}"
    );
    assert_eq!(
        listener.accept().map(|_| ()).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(mirror.mirror.accepted()?, None);
    Ok(())
}

/// One partner feed with one revoked passport, served from memory.
#[derive(Clone)]
struct OnePassportFeed {
    root: SignedEpochRoot,
    page: PassportRevocationLeavesPage,
}

impl OnePassportFeed {
    fn new() -> Fallible<Self> {
        let dir = tempfile::tempdir()?;
        let registry = dir.path().join("a-passport-statuses.json");
        let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(&registry)?)?;
        oracle.revoke(passport_revocation_key("passport-1"), NOW_MS)?;
        Ok(Self {
            root: sign_passport_revocation_root(&oracle, &registry, authority(), NOW_MS)?,
            page: passport_revocation_leaves_page(&oracle, &registry, 0)?,
        })
    }
}

impl PartnerRevocationSource for OnePassportFeed {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError> {
        Ok(self.root.clone())
    }

    fn leaves_after(
        &mut self,
        _after: u64,
    ) -> Result<PassportRevocationLeavesPage, PartnerRevocationError> {
        Ok(self.page.clone())
    }
}

fn deadline_in(left: Duration) -> Fallible<PortableFetchDeadline> {
    Ok(PortableFetchDeadline::starting_at(
        Instant::now()
            .checked_sub(PORTABLE_ISSUER_FETCH_TOTAL_TIMEOUT - left)
            .ok_or("monotonic clock too young for the deadline fixture")?,
    )?)
}

#[test]
fn a_sync_abandoned_at_its_deadline_never_commits() -> TestResult {
    let feed = OnePassportFeed::new()?;
    let mirror = mirror()?;
    let partner = revocation_partner("https://trust.acme.example");
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let pool = single_worker_pool();
    let (staged_tx, staged_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let mut late = feed.clone();
    let refused = sync_within(
        &pool,
        deadline_in(Duration::from_millis(200))?,
        Arc::clone(&mirror.mirror),
        partner.clone(),
        Arc::clone(&clock),
        move |mirror, partner, _deadline| {
            let staged = mirror.stage(partner, &mut late)?;
            let _sent = staged_tx.send(());
            let _released = release_rx.recv();
            Ok(staged)
        },
    )
    .err()
    .ok_or("a sync past its deadline must refuse")?;
    assert!(
        matches!(&refused, PartnerRevocationError::Fetch(partner_id, _) if partner_id == PARTNER),
        "{refused}"
    );
    staged_rx.recv()?;
    release_tx.send(())?;
    drain(&pool);
    assert_eq!(mirror.mirror.accepted()?, None);

    let mut timely = feed.clone();
    let root = sync_within(
        &pool,
        PortableFetchDeadline::start()?,
        Arc::clone(&mirror.mirror),
        partner,
        clock,
        move |mirror, partner, _deadline| mirror.stage(partner, &mut timely),
    )?;
    assert_eq!(root, feed.root.root);
    assert_eq!(
        mirror.mirror.accepted()?.map(|accepted| accepted.root),
        Some(feed.root.root)
    );
    Ok(())
}
