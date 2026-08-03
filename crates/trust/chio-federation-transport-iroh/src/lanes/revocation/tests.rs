use super::*;
use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_federation::revocation_gossip::RevocationRootGossip;
use chio_federation::revocation_gossip::REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA;
use chio_revocation_oracle::Ed25519RootSigner;
use chio_revocation_oracle::EpochRoot;
use iroh::SecretKey;
use std::sync::Mutex;

use crate::identity::revocation_signer_endorsement_preimage;
use crate::identity::transport_endorsement_preimage;
use crate::identity::RevocationSignerEntry;
use crate::identity::TransportDirectoryBundleBody;
use crate::identity::TransportDirectoryBundleDocument;
use crate::identity::TransportDirectoryBundleTrust;
use crate::identity::TransportDirectoryDocument;
use crate::identity::TransportDirectoryEntry;
use crate::identity::TrustedTransportDirectoryIssuer;
use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;

const NOW: u64 = 2_000_000;
const SEED_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const SEED_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";

fn endpoint_from_seed(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

fn signer(signer_id: &str, seed: &str) -> Ed25519RootSigner {
    Ed25519RootSigner::from_signing_key(signer_id, seed).expect("valid seed")
}

fn signed_root(signer: &Ed25519RootSigner, epoch: u64) -> SignedEpochRoot {
    let root = EpochRoot {
        epoch,
        root_hash: [epoch as u8; 32],
        leaf_count: epoch as usize,
        issued_at_unix_ms: 1_700_000_000_000 + epoch,
    };
    SignedEpochRoot::sign(root, signer).expect("sign never fails")
}

/// A batch addressed to the test handlers' responder kernel
/// (`did:chio:responder`), so it passes the recipient-address pin. Use
/// [`batch_addressed_to`] to build a MIS-addressed batch.
fn batch(frames: Vec<RevocationRootGossip>) -> RevocationGossipBatch {
    batch_addressed_to("did:chio:responder", frames)
}

fn batch_addressed_to(
    recipient_kernel_id: &str,
    frames: Vec<RevocationRootGossip>,
) -> RevocationGossipBatch {
    RevocationGossipBatch {
        schema: REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: recipient_kernel_id.to_string(),
        frames,
        flushed_at_unix_ms: NOW,
    }
}

/// A peer for the test directory builder: admitted at a transport endpoint,
/// optionally declaring oracle revocation signers via its passport. The
/// derived signer directory is a projection of the verified bundle, so a
/// signer's endpoint is STRUCTURALLY this peer's `transport_seed`.
struct PeerSpec {
    kernel_id: &'static str,
    passport_seed: u8,
    transport_seed: u8,
    /// (signer_id, oracle seed hex) declared by this peer's passport.
    signers: Vec<(&'static str, &'static str)>,
    removed: bool,
}

impl PeerSpec {
    fn admitted(kernel_id: &'static str, passport_seed: u8, transport_seed: u8) -> Self {
        Self {
            kernel_id,
            passport_seed,
            transport_seed,
            signers: Vec::new(),
            removed: false,
        }
    }

    fn with_signer(mut self, signer_id: &'static str, oracle_seed: &'static str) -> Self {
        self.signers.push((signer_id, oracle_seed));
        self
    }
}

fn build_peer_entry(spec: &PeerSpec) -> TransportDirectoryEntry {
    let passport = Keypair::from_seed(&[spec.passport_seed; 32]);
    let transport = endpoint_from_seed(spec.transport_seed);
    let passport_endorsement =
        passport.sign(&transport_endorsement_preimage(spec.kernel_id, &transport));
    let revocation_signers = spec
        .signers
        .iter()
        .map(|(signer_id, seed)| {
            let oracle = signer(signer_id, seed);
            let oracle_public_key = oracle.public_key();
            let oracle_endorsement = passport.sign(&revocation_signer_endorsement_preimage(
                spec.kernel_id,
                signer_id,
                &oracle_public_key,
            ));
            RevocationSignerEntry {
                signer_id: signer_id.to_string(),
                oracle_public_key,
                oracle_endorsement,
            }
        })
        .collect();
    TransportDirectoryEntry {
        kernel_id: spec.kernel_id.to_string(),
        passport_public_key: passport.public_key(),
        transport_endpoint_id: transport,
        passport_endorsement,
        revocation_signers,
        removed: spec.removed,
    }
}

/// Build a load-time-verified directory admitting the given peers; each peer's
/// declared oracle signers are projected into the derived signer directory.
fn verified_directory_of(peers: &[PeerSpec]) -> Arc<VerifiedDirectory> {
    let issuer = Keypair::from_seed(&[240; 32]);
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:local".to_string(),
        peers: peers.iter().map(build_peer_entry).collect(),
        treaties: Vec::new(),
    };
    let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
    let body = TransportDirectoryBundleBody {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        issuer: "did:chio:issuer".to_string(),
        key_id: "issuer-key-1".to_string(),
        directory_sha256,
        version: 1,
        previous_version_sha256: None,
        issued_at_unix_ms: NOW - 1,
        expires_at_unix_ms: NOW + 1,
    };
    let (signature, _) = issuer.sign_canonical(&body).unwrap();
    let bundle = TransportDirectoryBundleDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        body,
        directory,
        signature,
    };
    let trust = TransportDirectoryBundleTrust {
        issuers: vec![TrustedTransportDirectoryIssuer {
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            public_key: issuer.public_key(),
        }],
        version_floor: 0,
        expected_previous_version_sha256: None,
        now_unix_ms: NOW,
    };
    Arc::new(bundle.verify_bundle(&trust).expect("bundle verifies"))
}

/// A single-peer directory admitting `kernel_id` at `transport_seed` and
/// declaring `signer_id` (oracle `seed`) bound to that same endpoint.
fn directory_with_signer(
    kernel_id: &'static str,
    transport_seed: u8,
    signer_id: &'static str,
    seed: &'static str,
) -> Arc<VerifiedDirectory> {
    verified_directory_of(&[
        PeerSpec::admitted(kernel_id, 7, transport_seed).with_signer(signer_id, seed)
    ])
}

/// A recording sink so tests can assert exactly what was merged.
#[derive(Debug, Default)]
struct RecordingSink {
    merged: Mutex<Vec<u64>>,
}

impl RevocationRootSink for RecordingSink {
    fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError> {
        self.merged
            .lock()
            .expect("sink lock")
            .push(signed.root.epoch);
        Ok(())
    }

    // Infallible in-memory sink: record the whole verified batch under one lock
    // acquisition, which is inherently atomic (there is no mid-batch failure to
    // leave a partial apply). Overrides the fail-closed default so a valid push
    // merges; every real sink must likewise provide an atomic merge_batch.
    fn merge_batch(&self, roots: &[SignedEpochRoot]) -> Result<(), RevocationLaneError> {
        self.merged
            .lock()
            .expect("sink lock")
            .extend(roots.iter().map(|root| root.root.epoch));
        Ok(())
    }
}

#[derive(Debug, Default)]
struct EmptyHistory;
impl RevocationCatchupHistory for EmptyHistory {
    fn signed_root_at(&self, _epoch: u64) -> Option<SignedEpochRoot> {
        None
    }
}

fn handler(directory: Arc<VerifiedDirectory>) -> (RevocationHandler, Arc<RecordingSink>) {
    let sink = Arc::new(RecordingSink::default());
    let handler = RevocationHandler::new(
        directory,
        Arc::new(EmptyHistory),
        sink.clone(),
        "did:chio:responder",
    );
    (handler, sink)
}

/// A durable temp [`FsStore`](iroh_blobs::store::fs::FsStore) at a per-process,
/// per-timestamp path, plus its dir for cleanup. Used to back a
/// [`RevocationRootPublisher`] so the served-manifest tests can assert every
/// advertised hash is actually stored (fetchable).
async fn temp_fs_store(tag: &str) -> (iroh_blobs::store::fs::FsStore, std::path::PathBuf) {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "chio-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let store = iroh_blobs::store::fs::FsStore::load(&dir)
        .await
        .expect("load fs store");
    (store, dir)
}

/// A tiny in-memory [`RevocationCatchupHistory`] for the manifest tests.
#[derive(Debug)]
struct MapHistory(HashMap<u64, SignedEpochRoot>);
impl RevocationCatchupHistory for MapHistory {
    fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
        self.0.get(&epoch).cloned()
    }
}

fn history_5_to_7(oracle: &Ed25519RootSigner) -> MapHistory {
    let mut roots = HashMap::new();
    for epoch in 5..=7 {
        roots.insert(epoch, signed_root(oracle, epoch));
    }
    MapHistory(roots)
}

#[test]
fn signed_root_accepted_through_derived_binding() {
    // A real SignedEpochRoot verifies through the DERIVED signer binding: the
    // directory declares oracle-a bound (structurally) to the peer's endpoint.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![frame])),
        NOW,
    );
    match response {
        RevocationLaneResponse::PushAccepted { merged_epochs } => {
            assert_eq!(merged_epochs, vec![5]);
        }
        other => panic!("expected PushAccepted, got {other:?}"),
    }
    assert_eq!(*sink.merged.lock().unwrap(), vec![5]);
}

#[test]
fn push_addressed_to_another_responder_is_rejected_and_not_merged() {
    // A batch whose recipient_kernel_id names a DIFFERENT kernel than this
    // responder must be rejected fail-closed BEFORE any root reaches the sink,
    // even when every frame would otherwise verify. Only the correctly-addressed
    // batch merges.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    // Same crypto-valid frame, but the batch is addressed to another kernel.
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch_addressed_to("did:chio:someone-else", vec![frame])),
        NOW,
    );
    match response {
        RevocationLaneResponse::Rejected { code, .. } => {
            assert_eq!(code, "recipient-mismatch");
        }
        other => panic!("expected Rejected(recipient-mismatch), got {other:?}"),
    }
    assert!(
        sink.merged.lock().unwrap().is_empty(),
        "a mis-addressed batch must merge NOTHING"
    );

    // The SAME frame in a batch addressed to THIS responder still merges.
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![frame])),
        NOW,
    );
    match response {
        RevocationLaneResponse::PushAccepted { merged_epochs } => {
            assert_eq!(merged_epochs, vec![5]);
        }
        other => panic!("expected PushAccepted, got {other:?}"),
    }
    assert_eq!(*sink.merged.lock().unwrap(), vec![5]);
}

#[test]
fn forged_root_bumps_verify_failure_counter_and_is_still_rejected() {
    // OBSERVE-ONLY proof: a forged (tampered) root drives handle_request to a
    // typed Rejected AND bumps verify_failures{revocation,bad-signature}. The
    // response and the empty sink are byte-identical to before instrumentation.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let mut signed = signed_root(&oracle, 5);
    signed.signature.signature_bytes[0] ^= 0x01;
    let frame = RevocationRootGossip::from_signed(signed, NOW);

    let before =
        crate::metrics::verify_failures_total(crate::metrics::SEAM_REVOCATION, "bad-signature");
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![frame])),
        NOW,
    );
    assert!(matches!(response, RevocationLaneResponse::Rejected { .. }));
    assert!(sink.merged.lock().unwrap().is_empty(), "nothing merged");
    assert!(
        crate::metrics::verify_failures_total(crate::metrics::SEAM_REVOCATION, "bad-signature")
            > before,
        "the verify failure must be counted (observe-only)"
    );
}

#[test]
fn tampered_signature_is_rejected_bad_signature() {
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let mut signed = signed_root(&oracle, 5);
    // Flip a signature byte: integrity of the wire object is intact, but the
    // pinned-signer authenticity check must fail closed.
    signed.signature.signature_bytes[0] ^= 0x01;
    let frame = RevocationRootGossip::from_signed(signed, NOW);

    let err = handler
        .verify_batch(transport, &batch(vec![frame]))
        .expect_err("tampered signature must fail closed");
    assert!(matches!(err, RevocationLaneError::BadSignature(ref id) if id == "oracle-a"));
    // Nothing merged (all-or-nothing).
    assert!(sink.merged.lock().unwrap().is_empty());
}

#[test]
fn forged_root_rejected_through_derived_binding() {
    // Pinned "oracle-a" holds SEED_A (declared in the directory); the frame is
    // signed by an impostor that CLAIMS "oracle-a" but holds SEED_B. The
    // derived binding's verifier rejects it fail-closed.
    let transport = endpoint_from_seed(10);
    let impostor = signer("oracle-a", SEED_B);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, _sink) = handler(directory);

    let frame = RevocationRootGossip::from_signed(signed_root(&impostor, 5), NOW);
    let err = handler
        .verify_batch(transport, &batch(vec![frame]))
        .expect_err("wrong signing key must fail closed");
    assert!(matches!(err, RevocationLaneError::BadSignature(_)));
}

#[test]
fn unpinned_signer_id_is_rejected() {
    let transport = endpoint_from_seed(10);
    let oracle_b = signer("oracle-b", SEED_B);
    // Only oracle-a is declared in the directory.
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, _sink) = handler(directory);

    let frame = RevocationRootGossip::from_signed(signed_root(&oracle_b, 5), NOW);
    let err = handler
        .verify_batch(transport, &batch(vec![frame]))
        .expect_err("unpinned signer must fail closed");
    assert!(matches!(err, RevocationLaneError::UnknownSigner(ref id) if id == "oracle-b"));
}

#[test]
fn signer_pinned_to_other_endpoint_is_rejected() {
    // oracle-a is declared by peer-a (structurally bound to endpoint(10)), but
    // the frame arrives authenticated as peer-b's endpoint(11). peer-b is
    // itself admitted, so this exercises the signer/endpoint origin pin, not
    // the admission reject.
    let arriving = endpoint_from_seed(11);
    let oracle = signer("oracle-a", SEED_A);
    let directory = verified_directory_of(&[
        PeerSpec::admitted("did:chio:peer-a", 7, 10).with_signer("oracle-a", SEED_A),
        PeerSpec::admitted("did:chio:peer-b", 8, 11),
    ]);
    let (handler, _sink) = handler(directory);

    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let err = handler
        .verify_batch(arriving, &batch(vec![frame]))
        .expect_err("signer bound to another endpoint must fail closed");
    assert!(matches!(
        err,
        RevocationLaneError::SignerEndpointMismatch { .. }
    ));
}

#[test]
fn unbound_endpoint_is_rejected_at_the_gate() {
    // The connection's endpoint is bound to NO admitted kernel: the handler's
    // defense-in-depth re-resolve rejects before any signer work.
    let intruder = endpoint_from_seed(200);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, _sink) = handler(directory);

    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let err = handler
        .verify_batch(intruder, &batch(vec![frame]))
        .expect_err("unbound endpoint must fail closed at the gate");
    assert!(matches!(err, RevocationLaneError::UnboundEndpoint));
}

#[test]
fn one_bad_frame_rejects_whole_batch_all_or_nothing() {
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let good = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let mut bad_signed = signed_root(&oracle, 6);
    bad_signed.signature.signature_bytes[0] ^= 0x01;
    let bad = RevocationRootGossip::from_signed(bad_signed, NOW);

    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![good, bad])),
        NOW,
    );
    assert!(matches!(response, RevocationLaneResponse::Rejected { .. }));
    // The good frame must NOT have been merged: all-or-nothing.
    assert!(sink.merged.lock().unwrap().is_empty());
}

/// A transactional sink that stages the whole batch and only commits when
/// every root passes: it can reject a configured epoch to simulate a
/// mid-batch storage failure WITHOUT leaving a partial commit. This is the
/// shape a real store-backed sink must implement to honor the all-or-nothing
/// batch contract (`merge_batch`).
#[derive(Debug, Default)]
struct AtomicRecordingSink {
    committed: Mutex<Vec<u64>>,
    fail_on_epoch: Option<u64>,
}

impl RevocationRootSink for AtomicRecordingSink {
    fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError> {
        if self.fail_on_epoch == Some(signed.root.epoch) {
            return Err(RevocationLaneError::SinkRejected(format!(
                "storage rejected epoch {}",
                signed.root.epoch
            )));
        }
        self.committed
            .lock()
            .expect("sink lock")
            .push(signed.root.epoch);
        Ok(())
    }

    fn merge_batch(&self, roots: &[SignedEpochRoot]) -> Result<(), RevocationLaneError> {
        // Stage: validate every root against the configured storage failure
        // BEFORE touching committed state, so a mid-batch failure is atomic.
        let mut staged = Vec::with_capacity(roots.len());
        for root in roots {
            if self.fail_on_epoch == Some(root.root.epoch) {
                return Err(RevocationLaneError::SinkRejected(format!(
                    "storage rejected epoch {}",
                    root.root.epoch
                )));
            }
            staged.push(root.root.epoch);
        }
        // Commit only after the whole batch staged successfully.
        self.committed.lock().expect("sink lock").extend(staged);
        Ok(())
    }
}

#[test]
fn batch_merge_is_atomic_when_a_later_root_fails() {
    // Two crypto-valid roots pass verify_batch, but the sink rejects the 2nd
    // (epoch 6) on storage. The batch merge MUST be all-or-nothing: the first
    // root (epoch 5) must NOT be left partially applied.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let sink = Arc::new(AtomicRecordingSink {
        fail_on_epoch: Some(6),
        ..AtomicRecordingSink::default()
    });
    let handler = RevocationHandler::new(
        directory,
        Arc::new(EmptyHistory),
        sink.clone(),
        "did:chio:responder",
    );

    let good = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let doomed = RevocationRootGossip::from_signed(signed_root(&oracle, 6), NOW);
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![good, doomed])),
        NOW,
    );
    assert!(matches!(response, RevocationLaneResponse::Rejected { .. }));
    // Atomic: the earlier root must NOT have been committed.
    assert!(
        sink.committed.lock().unwrap().is_empty(),
        "a mid-batch sink failure must leave the sink unchanged (no partial apply)"
    );
}

#[test]
fn batch_merge_applies_all_when_every_root_succeeds() {
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let sink = Arc::new(AtomicRecordingSink::default());
    let handler = RevocationHandler::new(
        directory,
        Arc::new(EmptyHistory),
        sink.clone(),
        "did:chio:responder",
    );

    let f5 = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let f6 = RevocationRootGossip::from_signed(signed_root(&oracle, 6), NOW);
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![f5, f6])),
        NOW,
    );
    match response {
        RevocationLaneResponse::PushAccepted { merged_epochs } => {
            assert_eq!(merged_epochs, vec![5, 6]);
        }
        other => panic!("expected PushAccepted, got {other:?}"),
    }
    assert_eq!(*sink.committed.lock().unwrap(), vec![5, 6]);
}

/// A sink that implements ONLY `merge_root` and inherits the trait's fail-closed
/// default `merge_batch`, modelling an implementer who forgot the atomic override.
#[derive(Debug, Default)]
struct DefaultMergeSink {
    merged: Mutex<Vec<u64>>,
}

impl RevocationRootSink for DefaultMergeSink {
    fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError> {
        self.merged
            .lock()
            .expect("sink lock")
            .push(signed.root.epoch);
        Ok(())
    }
    // Intentionally NO merge_batch override: inherits the fail-closed default.
}

#[test]
fn default_merge_batch_fails_closed_with_no_partial_apply() {
    // A sink relying on the trait's default merge_batch must NOT silently apply
    // roots one at a time: the default fails closed (SinkRejected), so a batch
    // that otherwise verifies is rejected and NOTHING reaches the cache. This is
    // the all-or-nothing guarantee - an implementer who forgets an atomic
    // merge_batch gets a loud, total rejection rather than a partial cache advance.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let sink = Arc::new(DefaultMergeSink::default());
    let handler = RevocationHandler::new(
        directory,
        Arc::new(EmptyHistory),
        sink.clone(),
        "did:chio:responder",
    );

    let f5 = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let f6 = RevocationRootGossip::from_signed(signed_root(&oracle, 6), NOW);
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::Push(batch(vec![f5, f6])),
        NOW,
    );
    match response {
        RevocationLaneResponse::Rejected { code, .. } => {
            assert_eq!(code, "sink-rejected");
        }
        other => panic!("expected Rejected(sink-rejected), got {other:?}"),
    }
    assert!(
        sink.merged.lock().unwrap().is_empty(),
        "the fail-closed default must merge NOTHING (no partial apply)"
    );
}

#[test]
fn derived_signer_directory_resolves_binding() {
    // The projection consumed by the handler resolves the declared signer to
    // the peer's endpoint, and rejects an undeclared signer fail-closed.
    let transport = endpoint_from_seed(10);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let binding = directory
        .resolve_signer("oracle-a")
        .expect("oracle-a resolves through the derived projection");
    assert_eq!(binding.endpoint, transport);
    assert_eq!(directory.signer_directory().len(), 1);
    assert!(directory.resolve_signer("oracle-b").is_none());
}

#[test]
fn catchup_request_serves_from_history() {
    // A history holding epochs 5..=7 served through respond_to_catchup.
    #[derive(Debug)]
    struct MapHistory(HashMap<u64, SignedEpochRoot>);
    impl RevocationCatchupHistory for MapHistory {
        fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
            self.0.get(&epoch).cloned()
        }
    }
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let mut roots = HashMap::new();
    for epoch in 5..=7 {
        roots.insert(epoch, signed_root(&oracle, epoch));
    }
    let handler = RevocationHandler::new(
        directory,
        Arc::new(MapHistory(roots)),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    );

    let request = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
    let response = handler.handle_request(transport, RevocationLaneRequest::Catchup(request), NOW);
    match response {
        RevocationLaneResponse::Catchup(catchup) => {
            let epochs: Vec<u64> = catchup.frames.iter().map(|frame| frame.epoch).collect();
            assert_eq!(epochs, vec![5, 6, 7]);
            assert!(catchup.validate_response().is_ok());
        }
        other => panic!("expected Catchup, got {other:?}"),
    }
}

#[tokio::test]
async fn catchup_manifest_request_serves_published_blob_addresses() {
    // The SAME history that catchup_request_serves_from_history inlines as full
    // frames is served as a blob MANIFEST when a publisher is wired: the
    // (epoch -> address) list a follower feeds to BlobCatchupClient::fetch_range,
    // each address exactly the one the follower re-derives + BLAKE3-verifies. AND
    // the handler PUBLISHES every advertised root into the store its BlobsProtocol
    // serves, so every advertised hash is actually fetchable: no hash
    // is advertised that the authority cannot serve.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let history = history_5_to_7(&oracle);
    let expected: Vec<(u64, iroh_blobs::Hash)> = (5..=7)
        .map(|epoch| {
            (
                epoch,
                crate::catchup::signed_root_blob_address(&history.0[&epoch]).unwrap(),
            )
        })
        .collect();

    let (store, dir) = temp_fs_store("revocation-manifest-serve").await;
    let handler = RevocationHandler::new(
        directory,
        Arc::new(history),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    )
    .with_blob_publisher(RevocationRootPublisher::new(store.clone()));

    // The requester is the kernel admitted at this transport endpoint.
    let request = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
    let response = handler
        .handle_catchup_manifest(transport, &request, NOW)
        .await;
    match response {
        RevocationLaneResponse::CatchupManifest(manifest) => {
            manifest.validate().expect("manifest is well-formed");
            assert_eq!(manifest.responder_kernel_id, "did:chio:responder");
            assert_eq!(manifest.fetch_manifest(), expected);
            // Every advertised hash is Complete in the served store, not merely a
            // deterministic address the store never held.
            for entry in &manifest.entries {
                assert!(
                    matches!(
                        store.blobs().status(entry.blob_hash).await.unwrap(),
                        iroh_blobs::api::blobs::BlobStatus::Complete { .. }
                    ),
                    "advertised epoch {} must be published to the served store",
                    entry.epoch
                );
            }
        }
        other => panic!("expected CatchupManifest, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn catchup_manifest_without_publisher_falls_back_to_inline() {
    // Fail-closed: with NO blob publisher wired the handler
    // cannot confirm advertised blobs are stored, so a manifest request is served
    // as an INLINE Catchup response (the follower still catches up over lane-b) and
    // NEVER as a CatchupManifest advertising hashes the authority may not hold.
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    // No .with_blob_publisher(...): the manifest path must fall back to inline.
    let handler = RevocationHandler::new(
        directory,
        Arc::new(history_5_to_7(&oracle)),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    );

    let request = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
    let response = handler
        .handle_catchup_manifest(transport, &request, NOW)
        .await;
    match response {
        RevocationLaneResponse::Catchup(catchup) => {
            let epochs: Vec<u64> = catchup.frames.iter().map(|frame| frame.epoch).collect();
            assert_eq!(epochs, vec![5, 6, 7]);
            assert!(catchup.validate_response().is_ok());
        }
        other => panic!("expected inline Catchup fallback, got {other:?}"),
    }
}

#[tokio::test]
async fn catchup_manifest_async_requester_mismatch_rejected_and_nothing_published() {
    // The async served-manifest path enforces the SAME transport-bound requester
    // auth as the inline path, BEFORE publishing: a spoofed requester is Rejected
    // and NOTHING is written to the store (auth precedes any publish).
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let history = history_5_to_7(&oracle);
    let addresses: Vec<iroh_blobs::Hash> = (5..=7)
        .map(|epoch| crate::catchup::signed_root_blob_address(&history.0[&epoch]).unwrap())
        .collect();

    let (store, dir) = temp_fs_store("revocation-manifest-spoof").await;
    let handler = RevocationHandler::new(
        directory,
        Arc::new(history),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    )
    .with_blob_publisher(RevocationRootPublisher::new(store.clone()));

    // The endpoint is admitted as did:chio:peer, but the request claims another.
    let spoofed = RevocationCatchupRequest::new("did:chio:impostor", 5, 7, NOW).unwrap();
    let response = handler
        .handle_catchup_manifest(transport, &spoofed, NOW)
        .await;
    assert!(
        matches!(response, RevocationLaneResponse::Rejected { ref code, .. } if code == "requester-mismatch"),
        "a spoofed manifest requester must be rejected, got {response:?}"
    );
    // Fail-closed: NOTHING was published for the rejected request.
    for hash in addresses {
        assert!(
            !matches!(
                store.blobs().status(hash).await.unwrap(),
                iroh_blobs::api::blobs::BlobStatus::Complete { .. }
            ),
            "a rejected request must publish nothing"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn catchup_manifest_requester_mismatch_is_rejected_and_not_served() {
    // The manifest path enforces the SAME transport-bound requester
    // authentication as the inline catch-up path: a spoofed requester is
    // Rejected(requester-mismatch) and NO manifest is served.
    #[derive(Debug)]
    struct MapHistory(HashMap<u64, SignedEpochRoot>);
    impl RevocationCatchupHistory for MapHistory {
        fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
            self.0.get(&epoch).cloned()
        }
    }
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let mut roots = HashMap::new();
    for epoch in 5..=7 {
        roots.insert(epoch, signed_root(&oracle, epoch));
    }
    let handler = RevocationHandler::new(
        directory,
        Arc::new(MapHistory(roots)),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    );

    let spoofed = RevocationCatchupRequest::new("did:chio:impostor", 5, 7, NOW).unwrap();
    let response = handler.handle_request(
        transport,
        RevocationLaneRequest::CatchupManifest(spoofed),
        NOW,
    );
    assert!(
        matches!(response, RevocationLaneResponse::Rejected { ref code, .. } if code == "requester-mismatch"),
        "a spoofed manifest requester must be rejected, got {response:?}"
    );
}

#[test]
fn catchup_requester_mismatch_is_rejected_and_not_served() {
    // The connection endpoint is admitted as "did:chio:peer", but the catch-up
    // request CLAIMS a different requester_kernel_id. The requester is now
    // bound to the authenticated transport endpoint, so this is
    // Rejected(requester-mismatch) and the history is never served; a matching
    // claim from the same endpoint is still served.
    #[derive(Debug)]
    struct MapHistory(HashMap<u64, SignedEpochRoot>);
    impl RevocationCatchupHistory for MapHistory {
        fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
            self.0.get(&epoch).cloned()
        }
    }
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
    let mut roots = HashMap::new();
    for epoch in 5..=7 {
        roots.insert(epoch, signed_root(&oracle, epoch));
    }
    let handler = RevocationHandler::new(
        directory,
        Arc::new(MapHistory(roots)),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    );

    // Spoofed requester: claims to be a kernel this endpoint is not admitted as.
    let spoofed = RevocationCatchupRequest::new("did:chio:impostor", 5, 7, NOW).unwrap();
    let response = handler.handle_request(transport, RevocationLaneRequest::Catchup(spoofed), NOW);
    match response {
        RevocationLaneResponse::Rejected { code, .. } => {
            assert_eq!(code, "requester-mismatch");
        }
        other => panic!("expected Rejected(requester-mismatch), got {other:?}"),
    }

    // A matching requester (the endpoint's own admitted kernel) is still served.
    let genuine = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
    let served = handler.handle_request(transport, RevocationLaneRequest::Catchup(genuine), NOW);
    match served {
        RevocationLaneResponse::Catchup(catchup) => {
            let epochs: Vec<u64> = catchup.frames.iter().map(|frame| frame.epoch).collect();
            assert_eq!(epochs, vec![5, 6, 7]);
        }
        other => panic!("expected Catchup, got {other:?}"),
    }
}

#[test]
fn signer_directory_rejects_duplicate_and_key_mismatch() {
    let transport = endpoint_from_seed(10);
    let oracle = signer("oracle-a", SEED_A);
    // Duplicate signer_id.
    let dup = VerifiedSignerDirectory::from_bindings(vec![
        (
            "oracle-a".to_string(),
            SignerBinding {
                endpoint: transport,
                verifier: oracle.verifier(),
            },
        ),
        (
            "oracle-a".to_string(),
            SignerBinding {
                endpoint: transport,
                verifier: oracle.verifier(),
            },
        ),
    ]);
    assert!(matches!(dup, Err(RevocationLaneError::DuplicateSigner(_))));

    // Key/verifier signer_id disagrees with the map key.
    let mismatch = VerifiedSignerDirectory::from_bindings(vec![(
        "oracle-z".to_string(),
        SignerBinding {
            endpoint: transport,
            verifier: oracle.verifier(),
        },
    )]);
    assert!(matches!(
        mismatch,
        Err(RevocationLaneError::SignerIdMismatch { .. })
    ));
}

#[test]
fn lane_request_round_trips_externally_tagged() {
    // The externally-tagged envelope preserves the inner deny_unknown_fields
    // contract types unchanged.
    let oracle = signer("oracle-a", SEED_A);
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let request = RevocationLaneRequest::Push(batch(vec![frame]));
    let encoded = serde_json::to_vec(&request).unwrap();
    let decoded: RevocationLaneRequest = serde_json::from_slice(&encoded).unwrap();
    match decoded {
        RevocationLaneRequest::Push(batch) => assert!(batch.validate_envelope().is_ok()),
        other => panic!("unexpected variant: {other:?}"),
    }
}

// -- End-to-end over real loopback QUIC, driving the REAL RevocationHandler --
//
// The deterministic tests above drive `verify_batch` / `handle_request` in
// isolation. These bind two endpoints over loopback QUIC, mount the REAL
// `RevocationHandler` on its ALPN, and push through the genuine `accept()`
// path: transport auth -> directory `authorize` -> pinned-signer verify ->
// sink merge. A forged-signer root is rejected ON THE WIRE and reaches
// NOTHING (the sink stays empty), proving the real handler fails closed.

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::EndpointAddr;
use iroh::TransportAddr;
use std::time::Duration;

async fn bind_endpoint(seed: u8) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .bind_addr("127.0.0.1:0")
        .expect("loopback bind address parses")
        .bind()
        .await
        .expect("endpoint binds on loopback")
}

fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
    EndpointAddr::from_parts(
        endpoint.id(),
        endpoint.bound_sockets().into_iter().map(TransportAddr::Ip),
    )
}

/// Drive the client half by hand, reusing the lane's own `write_frame` /
/// `read_frame` so the wire codec under test is the real one (the shipped
/// `push_batch_over_iroh` is exercised end to end in
/// [`push_batch_over_iroh_accepts_a_dialable_endpoint_addr`]).
async fn push_batch_over_quic(
    dialer: &Endpoint,
    acceptor: EndpointAddr,
    batch: RevocationGossipBatch,
) -> RevocationLaneResponse {
    let conn = dialer
        .connect(acceptor, ALPN_REVOCATION_ROOT)
        .await
        .expect("dialer connects to acceptor over loopback");
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi stream");
    write_frame(&mut send, &RevocationLaneRequest::Push(batch))
        .await
        .expect("write push request");
    let response: RevocationLaneResponse = read_frame(&mut recv).await.expect("read lane response");
    conn.close(0u32.into(), b"ok");
    response
}

#[tokio::test]
async fn real_handler_accepts_pinned_signer_over_quic() {
    let dialer_seed = 20u8;
    let oracle = signer("oracle-a", SEED_A);
    // The directory declares oracle-a bound (structurally) to the dialer's
    // endpoint (transport_seed == dialer_seed), so the derived binding both
    // admits the dialer and pins oracle-a to it.
    let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let acceptor = bind_endpoint(21).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_REVOCATION_ROOT, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed).await;
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        push_batch_over_quic(&dialer, acceptor_addr, batch(vec![frame])),
    )
    .await
    .expect("push completes before timeout");

    match response {
        RevocationLaneResponse::PushAccepted { merged_epochs } => {
            assert_eq!(merged_epochs, vec![5]);
        }
        other => panic!("expected PushAccepted, got {other:?}"),
    }
    assert_eq!(*sink.merged.lock().unwrap(), vec![5]);
    router.shutdown().await.ok();
}

#[tokio::test]
async fn push_batch_over_iroh_accepts_a_dialable_endpoint_addr() {
    // In a direct-address / relay-disabled deployment the caller knows the peer's
    // full EndpointAddr (id + socket). The shipped push_batch_over_iroh must accept
    // it and dial successfully, not only a bare EndpointId that needs discovery.
    let dialer_seed = 28u8;
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let acceptor = bind_endpoint(29).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_REVOCATION_ROOT, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed).await;
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        // Pass the FULL EndpointAddr (not a bare EndpointId) through the shipped API.
        push_batch_over_iroh(&dialer, acceptor_addr, &batch(vec![frame])),
    )
    .await
    .expect("push completes before timeout")
    .expect("push_batch_over_iroh dials a full EndpointAddr");

    match response {
        RevocationLaneResponse::PushAccepted { merged_epochs } => {
            assert_eq!(merged_epochs, vec![5]);
        }
        other => panic!("expected PushAccepted, got {other:?}"),
    }
    assert_eq!(*sink.merged.lock().unwrap(), vec![5]);
    router.shutdown().await.ok();
}

#[tokio::test]
async fn real_handler_rejects_forged_signer_root_before_merge_over_quic() {
    let dialer_seed = 20u8;
    // Declared "oracle-a" holds SEED_A and is bound to the dialer endpoint, so
    // the admission gate and the transport-origin pin BOTH pass; the batch is
    // signed by an IMPOSTOR that claims "oracle-a" but holds SEED_B.
    // Authenticity must fail closed on the wire, before any merge.
    let impostor = signer("oracle-a", SEED_B);
    let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
    let (handler, sink) = handler(directory);

    let acceptor = bind_endpoint(22).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_REVOCATION_ROOT, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed).await;
    let forged = RevocationRootGossip::from_signed(signed_root(&impostor, 5), NOW);
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        push_batch_over_quic(&dialer, acceptor_addr, batch(vec![forged])),
    )
    .await
    .expect("push completes before timeout");

    match response {
        RevocationLaneResponse::Rejected { code, .. } => {
            assert_eq!(code, "bad-signature");
        }
        other => panic!("expected Rejected(bad-signature), got {other:?}"),
    }
    // Fail-closed: the forged root reached the sink NOWHERE (nothing merged).
    assert!(sink.merged.lock().unwrap().is_empty());
    router.shutdown().await.ok();
}

// -- Client-side slowloris bound: a silent authority must not hang the caller --
//
// An authority that accepts the connection and reads the request but never
// returns the response frame must not hang the dialer forever. This handler is
// that admitted-but-silent authority.

#[derive(Debug, Clone)]
struct SilentAfterReadRevocationHandler;

impl ProtocolHandler for SilentAfterReadRevocationHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut _send, mut recv) = conn.accept_bi().await?;
        // Read the request frame, then deliberately never write a response.
        let _request: RevocationLaneRequest =
            read_frame(&mut recv).await.map_err(AcceptError::from_err)?;
        conn.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn client_read_bound_drops_an_authority_that_never_replies() {
    // No admission gate on the acceptor: this isolates the CLIENT read bound (the
    // authority handshakes and reads the request, then goes silent).
    let acceptor = bind_endpoint(30).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_REVOCATION_ROOT, SilentAfterReadRevocationHandler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(31).await;
    let oracle = signer("oracle-a", SEED_A);
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    // A tight read bound; connect/open/write keep their generous defaults so only
    // the (hung) response read trips.
    let limits = AcceptLimitConfig {
        read_timeout: Duration::from_millis(200),
        ..AcceptLimitConfig::default()
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        push_batch_over_iroh_with_limits(&dialer, acceptor_addr, &batch(vec![frame]), &limits),
    )
    .await
    .expect("the client read bound must fire well before the outer test timeout");
    let error = outcome.expect_err("a silent authority must fail closed at the read bound");
    assert!(
        matches!(
            error,
            RevocationLaneError::AcceptLimit(AcceptLimitError::Timeout {
                phase: AcceptPhase::ReadFrame,
                ..
            })
        ),
        "unexpected error: {error:?}"
    );
    assert_eq!(error.code(), "accept_timeout");

    router.shutdown().await.ok();
}

// -- Client closes the connection after reading the reply (frees accept slots) --
//
// The shipped client must close the QUIC connection once it has read the reply,
// so the accept side's linger (which waits for the dialer to close) resolves at
// once instead of pinning its accept slot until the idle timeout.

/// An acceptor that replies, then waits for the DIALER to close: `conn.closed()`
/// resolves only when the client closes its half, so it fires a `Notify` proving
/// the shipped client closed.
#[derive(Clone, Debug)]
struct NotifyOnDialerClose {
    notify: Arc<tokio::sync::Notify>,
}

impl ProtocolHandler for NotifyOnDialerClose {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let _request: RevocationLaneRequest =
            read_frame(&mut recv).await.map_err(AcceptError::from_err)?;
        write_frame(
            &mut send,
            &RevocationLaneResponse::PushAccepted {
                merged_epochs: Vec::new(),
            },
        )
        .await
        .map_err(AcceptError::from_err)?;
        // Resolves when the dialer closes its half. If the shipped client closes
        // after reading, this returns promptly; otherwise it would only
        // resolve at the far-longer QUIC idle timeout.
        conn.closed().await;
        self.notify.notify_one();
        Ok(())
    }
}

#[tokio::test]
async fn shipped_client_closes_connection_after_reading_reply() {
    // No admission gate: this isolates the CLIENT close behavior of the shipped
    // push_batch_over_iroh path. The acceptor replies and then waits for the
    // dialer to close; the client MUST close after reading the reply so the
    // accept-side wait resolves promptly (freeing the slot).
    let acceptor = bind_endpoint(34).await;
    let notify = Arc::new(tokio::sync::Notify::new());
    let router = Router::builder(acceptor)
        .accept(
            ALPN_REVOCATION_ROOT,
            NotifyOnDialerClose {
                notify: notify.clone(),
            },
        )
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(35).await;
    let oracle = signer("oracle-a", SEED_A);
    let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        push_batch_over_iroh(&dialer, acceptor_addr, &batch(vec![frame])),
    )
    .await
    .expect("push completes before timeout")
    .expect("push_batch_over_iroh returns a response");
    assert!(matches!(
        response,
        RevocationLaneResponse::PushAccepted { .. }
    ));

    // The accept side observes the dialer's close well within this bound only
    // because the shipped client closes after reading; without the close it would
    // hang until the QUIC idle timeout (far longer than this bound).
    tokio::time::timeout(Duration::from_secs(5), notify.notified())
        .await
        .expect("the shipped client must close the connection after reading the reply");

    router.shutdown().await.ok();
}

// -- Public manifest client helper end to end over real loopback QUIC --
//
// The shipped `request_manifest_catchup_over_iroh` is the PUBLIC entry point for
// blob catch-up. These bind two endpoints over loopback, mount the
// REAL `RevocationHandler`, and drive the genuine `serve` -> `handle_catchup_manifest`
// path. With a publisher wired the client receives a manifest whose every hash is
// fetchable from the authority store; without one it receives the
// fail-closed inline fallback (never an unfetchable manifest).

#[tokio::test]
async fn request_manifest_catchup_over_iroh_returns_published_manifest() {
    let dialer_seed = 24u8;
    let oracle = signer("oracle-a", SEED_A);
    // Admit did:chio:peer at the dialer endpoint; the requester claims that kernel.
    let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
    let (store, dir) = temp_fs_store("revocation-manifest-quic").await;
    let handler = RevocationHandler::new(
        directory,
        Arc::new(history_5_to_7(&oracle)),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    )
    .with_blob_publisher(RevocationRootPublisher::new(store.clone()));

    let acceptor = bind_endpoint(25).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_REVOCATION_ROOT, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed).await;
    let request = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        // The shipped PUBLIC manifest client helper.
        request_manifest_catchup_over_iroh(&dialer, acceptor_addr, &request),
    )
    .await
    .expect("manifest request completes before timeout")
    .expect("request_manifest_catchup_over_iroh returns a response");
    match response {
        RevocationLaneResponse::CatchupManifest(manifest) => {
            manifest.validate().expect("manifest is well-formed");
            assert_eq!(
                manifest.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
                vec![5, 6, 7]
            );
            // Every advertised hash is fetchable from the authority's served store.
            for entry in &manifest.entries {
                assert!(
                    matches!(
                        store.blobs().status(entry.blob_hash).await.unwrap(),
                        iroh_blobs::api::blobs::BlobStatus::Complete { .. }
                    ),
                    "advertised epoch {} must be fetchable from the authority store",
                    entry.epoch
                );
            }
        }
        other => panic!("expected CatchupManifest, got {other:?}"),
    }
    router.shutdown().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn request_manifest_catchup_over_iroh_falls_back_to_inline_without_publisher() {
    let dialer_seed = 26u8;
    let oracle = signer("oracle-a", SEED_A);
    let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
    // No publisher: the authority must fall back to inline rather than advertise
    // hashes it cannot serve.
    let handler = RevocationHandler::new(
        directory,
        Arc::new(history_5_to_7(&oracle)),
        Arc::new(RecordingSink::default()),
        "did:chio:responder",
    );

    let acceptor = bind_endpoint(27).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_REVOCATION_ROOT, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed).await;
    let request = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        request_manifest_catchup_over_iroh(&dialer, acceptor_addr, &request),
    )
    .await
    .expect("completes before timeout")
    .expect("returns a response");
    match response {
        RevocationLaneResponse::Catchup(catchup) => {
            let epochs: Vec<u64> = catchup.frames.iter().map(|frame| frame.epoch).collect();
            assert_eq!(epochs, vec![5, 6, 7]);
        }
        other => panic!("expected inline Catchup fallback, got {other:?}"),
    }
    router.shutdown().await.ok();
}
