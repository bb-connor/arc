#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::identity::transport_endorsement_preimage;
use crate::identity::TransportDirectoryBundleBody;
use crate::identity::TransportDirectoryBundleDocument;
use crate::identity::TransportDirectoryBundleTrust;
use crate::identity::TransportDirectoryDocument;
use crate::identity::TransportDirectoryEntry;
use crate::identity::TrustedTransportDirectoryIssuer;
use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex as core_sha256_hex;
use chio_core_types::Keypair;
use chio_federation::pheromone_gossip::verify_pheromone_gossip_batch;
use chio_federation::pheromone_gossip::PheromoneDepositGossip;
use chio_federation::pheromone_gossip::PheromoneGossipBatchVerificationContext;
use chio_federation::pheromone_gossip::PheromoneGossipError;
use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA;
use chio_federation::pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA;
use iroh::SecretKey;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

const NOW: u64 = 1_766_000_000_500;
const RECIPIENT: &str = "did:chio:buyer-kernel";
const TREATY: &str = "treaty:buyer-llamaworks:support-ops";
const NAMESPACE: &str = "dev.chio.support";

/// Serializes every test that records a pheromone-lane ACCEPT so the double-count
/// tests can assert an EXACT delta on the process-global metric
/// statics. Without it, the ~8 parallel accept-counting tests in this module would
/// perturb the shared counter between a test's before/after reads. Any NEW test that
/// drives a successful delivery (a lane ACCEPT) MUST acquire this guard.
static COUNTED_ACCEPT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Read the pheromone-lane ACCEPT counter once it stops advancing. The acceptor
/// records the metric in `accept()` AFTER `handle` returns - i.e. after the dialer has
/// already read the report and `deliver_batch_over_iroh` returned - so a naive read
/// right after delivery can miss it. Serialized by [`COUNTED_ACCEPT_SERIAL`], only
/// this test's own delivery can advance the counter, so waiting for it to reach
/// `at_least` and then hold steady is deterministic.
async fn settled_pheromone_accept_total(before: u64, at_least: u64) -> u64 {
    let read = || {
        crate::metrics::lane_total(
            crate::metrics::LANE_PHEROMONE,
            crate::metrics::LANE_OUTCOME_ACCEPT,
        )
    };
    let mut last = read();
    let mut stable = 0u32;
    for _ in 0..400 {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let now = read();
        if now == last && now >= before + at_least {
            stable += 1;
            if stable >= 4 {
                return now;
            }
        } else if now != last {
            stable = 0;
            last = now;
        }
    }
    last
}

fn endpoint_from_seed(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// Build a load-time-verified directory admitting `kernel_id` at the
/// transport endpoint derived from `transport_seed`; `removed` tombstones it.
/// Mirrors the admission-module fixture.
fn verified_gate(
    kernel_id: &str,
    passport_seed: u8,
    transport_seed: u8,
    removed: bool,
) -> DirectoryGate {
    let passport = Keypair::from_seed(&[passport_seed; 32]);
    let issuer = Keypair::from_seed(&[240; 32]);
    let transport = endpoint_from_seed(transport_seed);
    let entry = TransportDirectoryEntry {
        kernel_id: kernel_id.to_string(),
        passport_public_key: passport.public_key(),
        transport_endpoint_id: transport,
        passport_endorsement: passport.sign(&transport_endorsement_preimage(kernel_id, &transport)),
        revocation_signers: Vec::new(),
        removed,
    };
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:local".to_string(),
        peers: vec![entry],
        treaties: Vec::new(),
    };
    let directory_sha256 = core_sha256_hex(&canonical_json_bytes(&directory).unwrap());
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
    DirectoryGate::new(Arc::new(bundle.verify_bundle(&trust).unwrap()))
}

/// A parseable `chio_core_types::Signature` (as its hex JSON form). The
/// direct-frame verifier does not check the deposit signature, so any
/// well-formed signature suffices to exercise the sender-equality checks.
fn signature_value() -> serde_json::Value {
    let sig = Keypair::from_seed(&[9; 32]).sign(b"pheromone-lane-fixture");
    serde_json::to_value(sig).unwrap()
}

/// A single-frame direct batch authored by `author` (both `origin` and
/// `gossiping_peer`), scoped to `TREATY`. The nested `PheromoneDeposit` is
/// built by deserialization so this crate need not depend on chio-pheromone.
fn direct_batch(author: &str) -> PheromoneGossipBatch {
    let frame = serde_json::json!({
        "schema": PHEROMONE_GOSSIP_SCHEMA,
        "deposit": {
            "schema": "chio.pheromone-deposit.v1",
            "kernel_id": author,
            "agent_passport_key_hash": "a".repeat(64),
            "agent_passport_jwk_thumbprint": "b".repeat(43),
            "subject_class": "support.prompt_injection",
            "subject_class_namespace": NAMESPACE,
            "indicator": {"digest": "c".repeat(64)},
            "severity": "high",
            "confidence": 0.8,
            "timestamp_unix_ms": NOW,
            "decay_half_life_secs": 3_600.0,
            "nonce": "nonce-live-relay-001",
            "treaty_scope": [TREATY],
            "signature": signature_value(),
        },
        "origin_kernel_id": author,
        "gossiping_peer_kernel_id": author,
        "treaty_id": TREATY,
        "ts_unix_ms": NOW,
    });
    let frame: PheromoneDepositGossip =
        serde_json::from_value(frame).expect("frame fixture deserializes");
    PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: RECIPIENT.to_string(),
        treaty_id: TREATY.to_string(),
        frames: vec![frame],
        flushed_at_unix_ms: NOW,
    }
}

fn live_policy() -> PheromoneTransitPolicy {
    PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: Vec::new(),
        allowed_ingress_treaties: vec![TREATY.to_string()],
        allowed_egress_treaties: vec![TREATY.to_string()],
        allowed_subject_class_namespaces: vec![NAMESPACE.to_string()],
        valid_from_unix_ms: NOW - 1_000,
        valid_until_unix_ms: NOW + 1_000,
        max_hops: 4,
        required_action_class_id: "action:demo".to_string(),
        pinned_ladder_refs: Vec::new(),
    }
}

#[test]
fn admitted_endpoint_resolves_to_its_kernel_id() {
    let gate = verified_gate("did:chio:llamaworks", 1, 10, false);
    assert_eq!(
        resolve_authenticated_sender(&gate, &endpoint_from_seed(10)).unwrap(),
        "did:chio:llamaworks"
    );
}

/// A complete receive report round-trips through the dial-side validation shape
/// and yields its `accepted` verdict.
#[test]
fn full_receive_report_validates_and_carries_accepted() {
    let report = serde_json::json!({
        "schema": "chio.pheromone.receive-report.v1",
        "accepted": true,
        "batchOutcome": "accepted",
        "acceptedFrameCount": 2,
        "rejectedFrameCount": 0,
        "batchSha256": "a".repeat(64),
        "recipientKernelId": "did:chio:relay",
        "authenticatedSenderKernelId": "did:chio:origin",
        "receivedAtUnixMs": NOW,
        "frames": [],
    });
    let bytes = serde_json::to_vec(&report).unwrap();
    let shape: ReceiveReportShape =
        serde_json::from_slice(&bytes).expect("a complete report must validate");
    assert!(shape.accepted, "the validated report carries accepted=true");
}

/// Fail-closed: a response that merely asserts `{"accepted":true}` (a buggy or
/// misrouted ALPN handler) is NOT a full receive report and MUST be rejected so a
/// batch is never marked durably delivered on it.
#[test]
fn partial_accepted_response_is_rejected_before_delivery() {
    let rejected = serde_json::from_slice::<ReceiveReportShape>(br#"{"accepted":true}"#);
    assert!(
        rejected.is_err(),
        "a partial report carrying only accepted:true must fail validation"
    );
    // An otherwise-complete report with an unknown batchOutcome is also rejected.
    let bad_outcome = serde_json::json!({
        "schema": "chio.pheromone.receive-report.v1",
        "accepted": true,
        "batchOutcome": "totally-unknown",
        "acceptedFrameCount": 0,
        "rejectedFrameCount": 0,
        "batchSha256": "a".repeat(64),
        "recipientKernelId": "did:chio:relay",
        "authenticatedSenderKernelId": "did:chio:origin",
        "receivedAtUnixMs": NOW,
        "frames": [],
    });
    let bytes = serde_json::to_vec(&bad_outcome).unwrap();
    assert!(
        serde_json::from_slice::<ReceiveReportShape>(&bytes).is_err(),
        "an unknown batchOutcome must fail validation fail-closed"
    );
}

#[test]
fn unbound_endpoint_is_rejected_fail_closed() {
    let gate = verified_gate("did:chio:llamaworks", 1, 10, false);
    let error = resolve_authenticated_sender(&gate, &endpoint_from_seed(200)).unwrap_err();
    assert!(matches!(error, IrohLaneError::Unadmitted(_)));
    assert_eq!(error.code(), "unadmitted");
}

#[test]
fn removed_endpoint_is_rejected_fail_closed() {
    let gate = verified_gate("did:chio:ghost", 3, 12, true);
    let error = resolve_authenticated_sender(&gate, &endpoint_from_seed(12)).unwrap_err();
    assert!(matches!(error, IrohLaneError::Unadmitted(_)));
}

#[test]
fn resolved_sender_feeds_verifier_and_batch_is_accepted() {
    // The transport resolves the admitted endpoint to its kernel_id; that
    // exact string, used as authenticated_sender_kernel_id, makes the
    // unchanged per-frame verifier accept the peer-authored batch.
    let gate = verified_gate("did:chio:llamaworks", 1, 10, false);
    let authenticated_sender =
        resolve_authenticated_sender(&gate, &endpoint_from_seed(10)).unwrap();
    let batch = direct_batch(&authenticated_sender);
    let context = PheromoneGossipBatchVerificationContext {
        now_unix_ms: NOW,
        recipient_kernel_id: RECIPIENT.to_string(),
        authenticated_sender_kernel_id: authenticated_sender.clone(),
    };
    verify_pheromone_gossip_batch(&batch, &live_policy(), &context)
        .expect("resolved sender's batch verifies (pheromone_gossip.rs:236/244)");
    assert_eq!(authenticated_sender, "did:chio:llamaworks");
}

#[test]
fn verifier_rejects_when_authenticated_sender_differs() {
    // Same peer-authored batch, but the transport-sourced sender does not
    // match the frame author: the :236 check fails (fail-closed). This is
    // the load-bearing binding the whole lane exists to populate.
    let batch = direct_batch("did:chio:llamaworks");
    let context = PheromoneGossipBatchVerificationContext {
        now_unix_ms: NOW,
        recipient_kernel_id: RECIPIENT.to_string(),
        authenticated_sender_kernel_id: "did:chio:mallory".to_string(),
    };
    let error = verify_pheromone_gossip_batch(&batch, &live_policy(), &context).unwrap_err();
    assert!(matches!(
        error,
        PheromoneGossipError::AuthenticatedSenderMismatch(_)
    ));
}

#[tokio::test]
async fn len_delimited_frame_round_trips() {
    let batch = direct_batch("did:chio:llamaworks");
    let bytes = canonical_json_bytes(&batch).unwrap();

    let mut out: Vec<u8> = Vec::new();
    write_len_delimited(&mut out, &bytes).await.unwrap();

    let mut reader: &[u8] = &out;
    let read = read_len_delimited(&mut reader, MAX_PHEROMONE_BATCH_BYTES)
        .await
        .unwrap();
    let decoded: PheromoneGossipBatch = serde_json::from_slice(&read).unwrap();
    assert_eq!(decoded, batch);
}

#[tokio::test]
async fn over_cap_frame_is_rejected_before_allocation() {
    let mut framed: Vec<u8> = Vec::new();
    let oversized = (MAX_PHEROMONE_BATCH_BYTES as u32).saturating_add(1);
    framed.extend_from_slice(&oversized.to_be_bytes());
    let mut reader: &[u8] = &framed;
    let error = read_len_delimited(&mut reader, MAX_PHEROMONE_BATCH_BYTES)
        .await
        .unwrap_err();
    assert!(matches!(error, IrohLaneError::FrameTooLarge(_)));
    assert_eq!(error.code(), "frame_too_large");
}

#[tokio::test]
async fn read_len_delimited_enforces_the_configured_ingress_cap() {
    // A frame WITHIN the transport hard cap but OVER the configured body limit is
    // rejected before allocation, so the iroh ingress is no laxer than the HTTP
    // relay's DefaultBodyLimit.
    let configured = 256_000usize; // production relay max_body_bytes
    let mut framed: Vec<u8> = Vec::new();
    let over_configured = (configured as u32).saturating_add(1);
    framed.extend_from_slice(&over_configured.to_be_bytes());
    let mut reader: &[u8] = &framed;
    let error = read_len_delimited(&mut reader, configured)
        .await
        .unwrap_err();
    match error {
        IrohLaneError::FrameTooLarge(len) => assert_eq!(len as u32, over_configured),
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn incremental_read_holds_only_delivered_bytes() {
    // A frame that declares a large length but is fully delivered still reads
    // back byte-for-byte, and the buffer never pre-commits the declared length.
    let payload = vec![7u8; 200 * 1024];
    let mut framed = Vec::new();
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    let mut reader = std::io::Cursor::new(framed);
    let out = read_len_delimited(&mut reader, 8 * 1024 * 1024)
        .await
        .expect("a fully-delivered frame reads back");
    assert_eq!(out, payload);

    // A truncated body (declares more than it delivers) fails with an EOF Io
    // error after consuming only the delivered bytes, never allocating `len`.
    let mut short = Vec::new();
    short.extend_from_slice(&(64u32 * 1024).to_be_bytes());
    short.extend_from_slice(&[1u8; 10]); // only 10 of 65536 bytes delivered
    let mut reader = std::io::Cursor::new(short);
    let err = read_len_delimited(&mut reader, 8 * 1024 * 1024)
        .await
        .expect_err("a truncated frame is rejected");
    assert!(matches!(err, IrohLaneError::Io(_)), "unexpected: {err:?}");
}

// -- Inbox-reservation lifecycle (InboxSlotGuard) --
//
// The winner's slot lifecycle is: reserve -> receive (self-commits) -> record.
// These drive the guard's state machine directly (the real receiver's report
// type is not nameable here, so the store seam is exercised through the guard,
// observing outcomes via reserve/lookup).

const GUARD_SENDER: &str = "did:chio:llamaworks";

#[test]
fn receive_fail_releases_slot_for_reclaim() {
    // Winner reserves, then models a FAILED receive: the guard stays ARMED and
    // drops (the `?`-return / cancel / panic path). Nothing committed, so the
    // slot must be released and a redelivery re-wins and re-receives.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let nonce = "iroh-pheromone-batch:receive-fail";
    assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
    {
        let _slot = InboxSlotGuard::new(
            Arc::clone(&store),
            GUARD_SENDER.to_string(),
            nonce.to_string(),
        );
        // receive fails -> guard drops ARMED -> RELEASE.
    }
    assert!(
        store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
        "a failed receive must release so a redelivery can re-receive"
    );
    assert!(
        store
            .lookup_inbox_report(GUARD_SENDER, nonce)
            .unwrap()
            .is_none(),
        "no durable verdict is recorded when nothing committed"
    );
}

#[test]
fn record_fail_leaves_slot_held_so_redelivery_never_re_receives() {
    // Winner reserves, the receive COMMITS (disarm), then record FAILS: the slot
    // must stay HELD so a redelivery loses the reservation and takes the loser /
    // fail-closed path, NEVER re-receiving the already-admitted batch (defect a).
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let nonce = "iroh-pheromone-batch:record-fail";
    assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
    {
        let mut slot = InboxSlotGuard::new(
            Arc::clone(&store),
            GUARD_SENDER.to_string(),
            nonce.to_string(),
        );
        slot.commit().unwrap(); // deposits committed (disarm + durable marker)
                                // record_inbox fails -> do NOT release -> guard drops DISARMED.
    }
    assert!(
        !store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
        "a committed-but-unrecorded batch must leave the slot held, fail-closed"
    );
    assert!(
        store
            .lookup_inbox_report(GUARD_SENDER, nonce)
            .unwrap()
            .is_none(),
        "with no durable verdict the loser waits then fails closed, never re-receiving"
    );
}

#[test]
fn record_ok_release_frees_slot_and_bounds_growth() {
    // Winner reserves, the receive COMMITS (disarm), record succeeds, then the
    // now-redundant reservation is released explicitly (bounds table growth). In
    // production the durable verdict recorded before release short-circuits any
    // redelivery at lookup_inbox_report BEFORE the reservation, so re-winning the
    // freed slot here is harmless.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let nonce = "iroh-pheromone-batch:record-ok";
    assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
    {
        let mut slot = InboxSlotGuard::new(
            Arc::clone(&store),
            GUARD_SENDER.to_string(),
            nonce.to_string(),
        );
        slot.commit().unwrap(); // deposits committed (disarm + durable marker)
        slot.release().unwrap(); // durable verdict recorded -> release the redundant row
                                 // guard drops already-disarmed -> no double release.
    }
    assert!(
        store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
        "a recorded success must release the redundant reservation"
    );
}

#[test]
fn winning_the_reservation_does_not_prove_the_batch_is_unreceived() {
    // Premise of handle()'s post-win RE-READ (the "reservation won after
    // another handler recorded+released" race): because the winner RELEASES its slot
    // after recording the durable verdict (to bound reservation-table growth), a later
    // redelivery can WIN the SAME (sender, nonce) reservation AGAIN even though the
    // batch is already admitted. Winning therefore does NOT prove un-receipt, so
    // handle() must re-read lookup_inbox_report AFTER winning and return the recorded
    // verdict instead of re-running the receiver (which would re-enter the runtime
    // replay window and reject the already-accepted deposits).
    //
    // This asserts the store-level premise only. The end-to-end Some-branch of the
    // re-read (winning, then finding a recorded verdict) cannot be exercised in this
    // crate: seeding a durable verdict needs `record_inbox(.., &PheromoneReceiveReport)`
    // and chio-pheromone-runtime is not a (dev-)dependency here, so that report type is
    // not nameable (the same limitation the loopback-QUIC tests document). The recorded-
    // verdict short-circuit itself is covered by chio-pheromone-relay's store tests.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let nonce = "iroh-pheromone-batch:win-after-release";
    // Winner: reserve -> commit -> release, exactly as handle()'s record-Ok path does.
    assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
    {
        let mut slot = InboxSlotGuard::new(
            Arc::clone(&store),
            GUARD_SENDER.to_string(),
            nonce.to_string(),
        );
        slot.commit().unwrap();
        slot.release().unwrap();
    }
    // A redelivery re-WINS the freed slot: winning cannot be treated as proof of
    // un-receipt, which is precisely why handle() re-reads the durable inbox here.
    assert!(
        store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
        "a released slot is re-won by a redelivery, so a post-win re-read is required \
             to avoid re-receiving an already-admitted batch"
    );
}

#[test]
fn outbox_reuse_enqueues_leases_and_dead_letters() {
    let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = direct_batch("did:chio:llamaworks");
    let outbox_id = enqueue_batch_for_delivery(
        &store,
        "did:chio:llamaworks",
        RECIPIENT,
        TREATY,
        &batch,
        NOW,
    )
    .unwrap();

    let due = store.lease_due_batches(NOW, 10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].outbox_id, outbox_id);

    // Enqueue is idempotent on the canonical batch hash.
    let again = enqueue_batch_for_delivery(
        &store,
        "did:chio:llamaworks",
        RECIPIENT,
        TREATY,
        &batch,
        NOW,
    )
    .unwrap();
    assert_eq!(again, outbox_id);

    // Three failures retry twice then dead-letter, matching
    // mark_delivery_failure's attempt cap.
    let mut entry = due.into_iter().next().unwrap();
    let mut report = OutboxDrainReport::default();
    for attempts in 0..3u64 {
        entry.attempts = attempts;
        record_delivery_failure(&store, &entry, "transport", NOW, &mut report).unwrap();
    }
    assert_eq!(report.retried, 2);
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(report.failures.len(), 3);
}

#[test]
fn outbox_retry_and_dead_letter_bump_outbox_counters() {
    // OBSERVE-ONLY proof: the retry/dead-letter accounting is unchanged AND now
    // emits the outbox family the shipped HTTP relay already meters.
    let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = direct_batch("did:chio:llamaworks");
    enqueue_batch_for_delivery(
        &store,
        "did:chio:llamaworks",
        RECIPIENT,
        TREATY,
        &batch,
        NOW,
    )
    .unwrap();
    let mut entry = store
        .lease_due_batches(NOW, 10)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let before_retry = crate::metrics::outbox_total(crate::metrics::OUTBOX_RETRIED);
    let before_dead = crate::metrics::outbox_total(crate::metrics::OUTBOX_DEAD_LETTERED);
    let mut report = OutboxDrainReport::default();
    for attempts in 0..3u64 {
        entry.attempts = attempts;
        record_delivery_failure(&store, &entry, "transport", NOW, &mut report).unwrap();
    }
    assert_eq!(report.retried, 2);
    assert_eq!(report.dead_lettered, 1);
    assert!(
        crate::metrics::outbox_total(crate::metrics::OUTBOX_RETRIED) > before_retry,
        "retries must be counted (observe-only)"
    );
    assert!(
        crate::metrics::outbox_total(crate::metrics::OUTBOX_DEAD_LETTERED) > before_dead,
        "dead-letters must be counted (observe-only)"
    );
}

// -- End-to-end over real loopback QUIC (mirrors the validated PoC shape) --
//
// The real receiver seam (RelayBatchReceiver, whose report type is not
// nameable here) is represented by a canned-report handler that still exercises
// the genuine transport path: the admission gate on the endpoint, the
// handler's re-resolution of conn.remote_id(), the ALPN, and the
// length-delimited bidi codec. The deterministic tests above prove the
// verifier seam; these prove the wire path and the accept-time gate.

use iroh::endpoint::presets;
use iroh::TransportAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
struct CannedReportHandler {
    gate: DirectoryGate,
}

impl ProtocolHandler for CannedReportHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let sender = resolve_authenticated_sender(&self.gate, &conn.remote_id())
            .map_err(AcceptError::from_err)?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let raw = read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES)
            .await
            .map_err(AcceptError::from_err)?;
        // Prove the received bytes decode to the real wire type.
        let batch: PheromoneGossipBatch =
            serde_json::from_slice(&raw).map_err(AcceptError::from_err)?;
        // Emit a COMPLETE receive report, faithfully mirroring the runtime
        // `PheromoneReceiveReport` the production handler serializes. A partial
        // report (for example only `accepted`) is rejected on the dial side before
        // a batch is marked delivered, so the double must carry every field.
        let report = serde_json::json!({
            "schema": "chio.pheromone-receive-report.v1",
            "accepted": true,
            "batchOutcome": "accepted",
            "acceptedFrameCount": batch.frames.len() as u64,
            "rejectedFrameCount": 0,
            "batchSha256": "0".repeat(64),
            "recipientKernelId": batch.recipient_kernel_id,
            "authenticatedSenderKernelId": sender,
            "receivedAtUnixMs": 0u64,
            "frames": [],
        });
        let bytes = serde_json::to_vec(&report).map_err(AcceptError::from_err)?;
        write_len_delimited(&mut send, &bytes)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

async fn bind_endpoint(seed: u8, gate: Option<DirectoryGate>) -> Endpoint {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .bind_addr("127.0.0.1:0")
        .expect("loopback bind address parses");
    if let Some(gate) = gate {
        builder = builder.hooks(gate);
    }
    builder.bind().await.expect("endpoint binds on loopback")
}

fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
    EndpointAddr::from_parts(
        endpoint.id(),
        endpoint.bound_sockets().into_iter().map(TransportAddr::Ip),
    )
}

#[tokio::test]
async fn admitted_dialer_batch_accepted_over_quic() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    let dialer_seed = 20u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
    let acceptor = bind_endpoint(21, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, CannedReportHandler { gate })
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let batch = direct_batch("did:chio:bob");
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("admitted dialer delivers its batch");
    assert!(outcome.accepted, "admitted dialer's batch is accepted");

    router.shutdown().await.ok();
}

/// A receiver double that records whether `receive_batch` ever ran, so a deny-all
/// swap between admission and receive can be proven to admit nothing.
struct ReceiveProbe {
    received: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl RelayBatchReceiver for ReceiveProbe {
    async fn receive_batch(
        &self,
        _batch: PheromoneGossipBatch,
        _authenticated_sender_kernel_id: String,
        _received_at_unix_ms: u64,
    ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
        self.received.store(true, Ordering::SeqCst);
        Err(PheromoneRelayError::Json(
            "receiver must not run after a deny-all swap".to_string(),
        ))
    }
}

#[tokio::test]
async fn deny_all_swap_between_admission_and_receive_admits_nothing() {
    // A peer admitted at the handshake must not deliver a batch once the directory has
    // swapped to deny-all. The swap is published mid-handle - after the connection was
    // admitted and the request frame read, but before any receiver state is touched -
    // modeling the reloader publishing deny-all while a peer is already in flight. The
    // handler must re-resolve against the live directory and refuse to receive, so the
    // batch never reaches the receiver.
    let dialer_seed = 60u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

    let received = Arc::new(AtomicBool::new(false));
    let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(ReceiveProbe {
        received: Arc::clone(&received),
    });

    // Swap the shared directory to deny-all at the exact instant the batch is scoped.
    let swap_gate = gate.clone();
    let scope_check: InboundBatchScopeCheck = Arc::new(
        move |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
            swap_gate.swap(Arc::new(
                crate::identity::VerifiedDirectory::empty_deny_all(),
            ));
            Ok(())
        },
    );

    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let handler =
        PheromoneBatchHandler::new(gate.clone(), receiver, Arc::clone(&store), now, scope_check);

    let acceptor = bind_endpoint(61, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let batch = direct_batch("did:chio:bob");
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery attempt completes before timeout");

    assert!(
        outcome.is_err(),
        "a batch delivered after the directory swapped to deny-all must fail closed"
    );
    assert!(
        !received.load(Ordering::SeqCst),
        "the receiver must never run once the directory has swapped to deny-all"
    );

    router.shutdown().await.ok();
}

/// A receiver double shared by BOTH recovery tests (loser and winner path):
/// its `receive_batch` must never run (neither recovery path re-receives an
/// already-admitted batch), and its `recorded_report_for_batch` surfaces the
/// durably-committed runtime verdict. The panic is the teeth: any recovery path
/// that re-runs the receiver trips it.
struct RecoveringReceiver {
    report: chio_pheromone_runtime::PheromoneReceiveReport,
}

#[async_trait::async_trait]
impl RelayBatchReceiver for RecoveringReceiver {
    async fn receive_batch(
        &self,
        _batch: PheromoneGossipBatch,
        _authenticated_sender_kernel_id: String,
        _received_at_unix_ms: u64,
    ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
        panic!("recovery path must not re-run receive_batch");
    }

    async fn recorded_report_for_batch(
        &self,
        _batch_sha256: &str,
        _authenticated_sender_kernel_id: &str,
    ) -> Result<Option<chio_pheromone_runtime::PheromoneReceiveReport>, PheromoneRelayError> {
        Ok(Some(self.report.clone()))
    }
}

#[tokio::test]
async fn verdict_recovery_converges_after_commit_before_record_crash() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    // A crash after receive_batch self-commits its deposits but before record_inbox
    // writes the durable verdict leaves the reservation committed=1. A redelivery
    // loses the slot and reaches the loser path; it must recover the durable verdict
    // (via recorded_report_for_batch) and converge, never dead-letter the accepted
    // batch.
    let dialer_seed = 40u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

    // The batch the dialer delivers, and the (sender, nonce) it keys on.
    let batch = direct_batch("did:chio:bob");
    let batch_bytes = canonical_json_bytes(&batch).unwrap();
    let nonce = inbox_nonce(&batch_bytes);
    let sender = "did:chio:bob";

    // Seed the crash-after-commit-before-record state: a COMMITTED residual
    // reservation for (sender, nonce) with NO recorded verdict, so the handler's
    // reserve_inbox_slot loses and the redelivery takes the loser path.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    assert!(store.reserve_inbox_slot(sender, &nonce).unwrap().won);
    store
        .mark_inbox_reservation_committed(sender, &nonce)
        .unwrap();
    assert!(store.lookup_inbox_report(sender, &nonce).unwrap().is_none());

    // The durable verdict the runtime store committed before the crash, surfaced
    // by the receiver double. Its batch_sha256 matches the handler's lookup key
    // (canonical_sha256 of the batch), though the double returns it regardless.
    let canned = chio_pheromone_runtime::PheromoneReceiveReport {
        schema: "chio.pheromone-receive-report.v1".to_string(),
        accepted: true,
        batch_outcome: chio_pheromone_runtime::PheromoneBatchOutcome::Accepted,
        accepted_frame_count: batch.frames.len() as u64,
        rejected_frame_count: 0,
        batch_sha256: core_sha256_hex(&batch_bytes),
        recipient_kernel_id: RECIPIENT.to_string(),
        authenticated_sender_kernel_id: sender.to_string(),
        received_at_unix_ms: NOW,
        frames: Vec::new(),
    };

    let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RecoveringReceiver { report: canned });
    let scope_check: InboundBatchScopeCheck = Arc::new(
        |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
            Ok(())
        },
    );
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let handler =
        PheromoneBatchHandler::new(gate.clone(), receiver, Arc::clone(&store), now, scope_check);

    let before = crate::metrics::lane_total(
        crate::metrics::LANE_PHEROMONE,
        crate::metrics::LANE_OUTCOME_ACCEPT,
    );

    let acceptor = bind_endpoint(41, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("loser path recovers the durable verdict and returns it");

    // Convergence: the dialer reads the recovered accepted verdict, and the
    // durable inbox now records it so a further redelivery short-circuits.
    assert!(
        outcome.accepted,
        "the recovered verdict is the accepted one"
    );
    assert!(
        store.lookup_inbox_report(sender, &nonce).unwrap().is_some(),
        "recovery adopts the durable verdict as the inbox record"
    );
    // Metric dedupe: a recovered redelivery must count EXACTLY ONE accept, like a
    // fresh delivery or an inbox hit. `accept` counts one accept for every Ok(()); a
    // stray inner count in handle's loser-path recovery would emit a SECOND sample
    // (delta == 2 instead of 1).
    let after = settled_pheromone_accept_total(before, 1).await;
    assert_eq!(
        after - before,
        1,
        "loser-path recovery counts exactly one accept, not two"
    );

    router.shutdown().await.ok();
}

#[tokio::test]
async fn winner_path_adopts_durable_verdict_after_commit_before_mark_crash() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    // WINNER path, symmetric with the loser-path recovery above.
    // The winner and loser paths cover two DIFFERENT crash windows, distinguished
    // solely by the reservation's committed flag at open:
    //  - LOSER window (test above): a crash AFTER slot.commit() leaves a
    //    committed = 1 reservation that SURVIVES clear-at-open, so a redelivery
    //    LOSES reserve_inbox_slot and takes the loser path.
    //  - WINNER window (this test): a crash BETWEEN receive_batch self-committing
    //    its runtime deposits (in the RUNTIME store) and slot.commit() marking the
    //    RELAY reservation committed leaves committed = 0, which the store reclaims
    //    at open. A redelivery therefore WINS reserve_inbox_slot, re-reads the RELAY
    //    inbox (still None), and, absent the runtime-store consult, would re-run
    //    receive_batch on an already-admitted batch. The runtime replay-nonce
    //    idempotency then turns every frame into ReplayWindowExceeded, recording +
    //    returning a spurious REJECTED verdict that dead-letters an accepted batch.
    //    The winner path instead consults the RUNTIME store by batch_sha256 first and
    //    ADOPTS the durable verdict, never re-running receive_batch.
    //
    // The shared RecoveringReceiver double PANICS if receive_batch is called: a winner
    // path that re-ran the receiver would trip the panic (the delivery fails / never
    // returns the accepted report). The recovery path instead adopts the durable
    // verdict without touching the receiver.
    let dialer_seed = 44u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

    // The batch the dialer redelivers, and the (sender, nonce) it keys on.
    let batch = direct_batch("did:chio:bob");
    let batch_bytes = canonical_json_bytes(&batch).unwrap();
    let nonce = inbox_nonce(&batch_bytes);
    let sender = "did:chio:bob";

    // Reproduce the crash-before-mark residual: an EMPTY relay reservation table
    // (the committed = 0 reservation was reclaimed at open) and NO recorded inbox
    // verdict, so the handler's own reserve_inbox_slot WINS and the post-win re-read
    // finds None - the winner path. Only the RUNTIME store (via the receiver double)
    // holds the durable verdict.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    assert!(
        store.lookup_inbox_report(sender, &nonce).unwrap().is_none(),
        "no relay inbox verdict is recorded before recovery (winner-path premise)"
    );

    // The durable verdict the runtime store committed before the crash, surfaced by
    // the receiver double. Its batch_sha256 matches the handler's lookup key
    // (canonical sha256 of the batch), though the double returns it regardless.
    let canned = chio_pheromone_runtime::PheromoneReceiveReport {
        schema: "chio.pheromone-receive-report.v1".to_string(),
        accepted: true,
        batch_outcome: chio_pheromone_runtime::PheromoneBatchOutcome::Accepted,
        accepted_frame_count: batch.frames.len() as u64,
        rejected_frame_count: 0,
        batch_sha256: core_sha256_hex(&batch_bytes),
        recipient_kernel_id: RECIPIENT.to_string(),
        authenticated_sender_kernel_id: sender.to_string(),
        received_at_unix_ms: NOW,
        frames: Vec::new(),
    };

    // The SHARED double: receive_batch PANICS (teeth), recorded_report_for_batch
    // returns the durable verdict. A winner path that re-ran the receiver would panic
    // here; the recovery path adopts the durable verdict instead.
    let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RecoveringReceiver { report: canned });
    let scope_check: InboundBatchScopeCheck = Arc::new(
        |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
            Ok(())
        },
    );
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let handler =
        PheromoneBatchHandler::new(gate.clone(), receiver, Arc::clone(&store), now, scope_check);

    let before = crate::metrics::lane_total(
        crate::metrics::LANE_PHEROMONE,
        crate::metrics::LANE_OUTCOME_ACCEPT,
    );

    let acceptor = bind_endpoint(45, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("the winner path adopts the durable verdict (never re-runs receive_batch)");

    // Convergence: the dialer reads the recovered ACCEPTED verdict (not a spurious
    // ReplayWindowExceeded REJECTED), the durable inbox now records it so a further
    // redelivery short-circuits, and the recovery counts an accept, never a
    // dead-letter.
    assert!(
        outcome.accepted,
        "the winner path returns the recovered accepted verdict, not a spurious rejection"
    );
    assert!(
        store.lookup_inbox_report(sender, &nonce).unwrap().is_some(),
        "winner-path recovery adopts the durable verdict as the inbox record"
    );
    // Metric dedupe: a recovered redelivery must count EXACTLY ONE accept. A stray
    // winner-path inner count would make delta == 2 instead of 1.
    let after = settled_pheromone_accept_total(before, 1).await;
    assert_eq!(
        after - before,
        1,
        "winner-path recovery counts exactly one accept, not two"
    );

    router.shutdown().await.ok();
}

/// A receiver double for the sender-scoping tests: its
/// `recorded_report_for_batch` returns a durable verdict recorded under a
/// DIFFERENT authenticated sender, and its `receive_batch` records that it ran
/// (via `received`) and returns a distinguishable FRESH verdict. A recovery
/// path that (wrongly) adopts the cross-sender verdict never runs receive_batch;
/// the SCOPED path discards it and either falls through to receive_batch (winner)
/// or denies (loser).
struct WrongSenderRecoveringReceiver {
    recovered: chio_pheromone_runtime::PheromoneReceiveReport,
    fresh: chio_pheromone_runtime::PheromoneReceiveReport,
    received: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl RelayBatchReceiver for WrongSenderRecoveringReceiver {
    async fn receive_batch(
        &self,
        _batch: PheromoneGossipBatch,
        _authenticated_sender_kernel_id: String,
        _received_at_unix_ms: u64,
    ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
        self.received
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(self.fresh.clone())
    }

    async fn recorded_report_for_batch(
        &self,
        _batch_sha256: &str,
        _authenticated_sender_kernel_id: &str,
    ) -> Result<Option<chio_pheromone_runtime::PheromoneReceiveReport>, PheromoneRelayError> {
        Ok(Some(self.recovered.clone()))
    }
}

/// Build a `PheromoneReceiveReport` for these `batch` bytes under `sender` with
/// the given `accepted` outcome, for the sender-scoping tests.
fn scoping_report(
    batch: &PheromoneGossipBatch,
    batch_bytes: &[u8],
    sender: &str,
    accepted: bool,
) -> chio_pheromone_runtime::PheromoneReceiveReport {
    let frame_count = batch.frames.len() as u64;
    chio_pheromone_runtime::PheromoneReceiveReport {
        schema: "chio.pheromone-receive-report.v1".to_string(),
        accepted,
        batch_outcome: if accepted {
            chio_pheromone_runtime::PheromoneBatchOutcome::Accepted
        } else {
            chio_pheromone_runtime::PheromoneBatchOutcome::Rejected
        },
        accepted_frame_count: if accepted { frame_count } else { 0 },
        rejected_frame_count: if accepted { 0 } else { frame_count },
        batch_sha256: core_sha256_hex(batch_bytes),
        recipient_kernel_id: RECIPIENT.to_string(),
        authenticated_sender_kernel_id: sender.to_string(),
        received_at_unix_ms: NOW,
        frames: Vec::new(),
    }
}

#[tokio::test]
async fn winner_path_rejects_recovered_verdict_from_a_different_sender() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    // Sender-scoping (SECURITY). The runtime store keys receive reports by
    // batch_sha256 ALONE, so a verdict it holds for these batch bytes may have been
    // recorded under a DIFFERENT authenticated sender. The winner path must NOT adopt
    // such a verdict verbatim: that would attribute another sender's accept/reject to
    // THIS (sender, nonce), bypassing the per-frame gossiping_peer_kernel_id ==
    // authenticated_sender binding. It must discard the cross-sender verdict and fall
    // through to receive_batch, re-verifying under THIS sender.
    //
    // recorded_report_for_batch returns an ACCEPTED verdict recorded under
    // "did:chio:alice"; the authenticated sender is "did:chio:bob"; the fresh
    // receive_batch verdict for bob is a distinguishable REJECTED one. An unscoped
    // winner path would adopt alice's accepted verdict (the dialer reads accepted ==
    // true and receive_batch never runs); the scoped winner path discards alice's
    // verdict, runs receive_batch under bob, and returns bob's rejected verdict.
    let dialer_seed = 46u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

    let batch = direct_batch("did:chio:bob");
    let batch_bytes = canonical_json_bytes(&batch).unwrap();
    let nonce = inbox_nonce(&batch_bytes);
    let sender = "did:chio:bob";

    // Empty reservation table + no recorded inbox verdict => the handler wins its
    // own reserve_inbox_slot and the post-win re-read finds None: the winner path.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    assert!(store.lookup_inbox_report(sender, &nonce).unwrap().is_none());

    // The runtime store holds an ACCEPTED verdict for these bytes recorded under a
    // DIFFERENT authenticated sender (alice); the fresh receive_batch verdict for
    // bob is a distinguishable REJECTED one.
    let recovered = scoping_report(&batch, &batch_bytes, "did:chio:alice", true);
    let fresh = scoping_report(&batch, &batch_bytes, sender, false);
    let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(WrongSenderRecoveringReceiver {
        recovered,
        fresh,
        received: Arc::clone(&received),
    });
    let scope_check: InboundBatchScopeCheck = Arc::new(
        |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
            Ok(())
        },
    );
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let handler =
        PheromoneBatchHandler::new(gate.clone(), receiver, Arc::clone(&store), now, scope_check);

    let acceptor = bind_endpoint(47, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("the scoped winner path returns the fresh verdict, not the cross-sender one");

    assert!(
            !outcome.accepted,
            "a verdict recorded under a DIFFERENT sender is NOT adopted; the fresh receive_batch verdict (rejected) is returned"
        );
    assert!(
        received.load(std::sync::atomic::Ordering::SeqCst),
        "the scoped winner path falls through to receive_batch under THIS sender"
    );
    let stored = store.lookup_inbox_report(sender, &nonce).unwrap().unwrap();
    assert_eq!(
        stored.authenticated_sender_kernel_id, sender,
        "the recorded inbox verdict is scoped to THIS authenticated sender, not the recovered one"
    );

    router.shutdown().await.ok();
}

#[tokio::test]
async fn loser_path_rejects_recovered_verdict_from_a_different_sender() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    // Sender-scoping (SECURITY), loser path. Symmetric with the winner-path test: a
    // committed residual reservation with no recorded inbox verdict sends the
    // redelivery down the loser path, where the runtime store holds a verdict for
    // these bytes recorded under a DIFFERENT sender. The loser path must NOT adopt it
    // (that would hand THIS sender another sender's accepted verdict); it must deny
    // (fail-closed DedupInFlight).
    //
    // recorded_report_for_batch returns an ACCEPTED verdict recorded under
    // "did:chio:alice"; the authenticated sender is "did:chio:bob". The loser path
    // never calls receive_batch, so `received` stays false either way. An unscoped
    // loser path would adopt alice's accepted verdict (the dialer reads accepted ==
    // true); the scoped loser path denies and the delivery fails closed.
    let dialer_seed = 48u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

    let batch = direct_batch("did:chio:bob");
    let batch_bytes = canonical_json_bytes(&batch).unwrap();
    let nonce = inbox_nonce(&batch_bytes);
    let sender = "did:chio:bob";

    // Seed the crash-after-commit residual: a COMMITTED reservation for
    // (sender, nonce) with NO recorded verdict, so reserve_inbox_slot LOSES and
    // the redelivery takes the loser path.
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    assert!(store.reserve_inbox_slot(sender, &nonce).unwrap().won);
    store
        .mark_inbox_reservation_committed(sender, &nonce)
        .unwrap();
    assert!(store.lookup_inbox_report(sender, &nonce).unwrap().is_none());

    let recovered = scoping_report(&batch, &batch_bytes, "did:chio:alice", true);
    let fresh = scoping_report(&batch, &batch_bytes, sender, false);
    let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(WrongSenderRecoveringReceiver {
        recovered,
        fresh,
        received: Arc::clone(&received),
    });
    let scope_check: InboundBatchScopeCheck = Arc::new(
        |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
            Ok(())
        },
    );
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let handler =
        PheromoneBatchHandler::new(gate.clone(), receiver, Arc::clone(&store), now, scope_check);

    let acceptor = bind_endpoint(49, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout");

    assert!(
            result.is_err(),
            "the scoped loser path denies a cross-sender recovered verdict (fail-closed), never adopts it"
        );
    assert!(
        !received.load(std::sync::atomic::Ordering::SeqCst),
        "the loser path never re-runs receive_batch"
    );
    assert!(
        store.lookup_inbox_report(sender, &nonce).unwrap().is_none(),
        "no cross-sender verdict is recorded as THIS sender's inbox record"
    );

    router.shutdown().await.ok();
}

/// A receiver double that always accepts, for the per-peer-cap wiring test.
struct AcceptingReceiver {
    report: chio_pheromone_runtime::PheromoneReceiveReport,
}

#[async_trait::async_trait]
impl RelayBatchReceiver for AcceptingReceiver {
    async fn receive_batch(
        &self,
        _batch: PheromoneGossipBatch,
        _authenticated_sender_kernel_id: String,
        _received_at_unix_ms: u64,
    ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
        Ok(self.report.clone())
    }
}

#[tokio::test]
async fn per_peer_cap_one_still_admits_a_single_dialer() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    // A per-peer cap of 1 must not break a single, sequential dialer: the guard
    // releases when the handler task ends, so the exchange completes (the accept site
    // calls admit_peer, not admit).
    let dialer_seed = 42u8;
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
    let batch = direct_batch("did:chio:bob");
    let batch_bytes = canonical_json_bytes(&batch).unwrap();
    let report = chio_pheromone_runtime::PheromoneReceiveReport {
        schema: "chio.pheromone-receive-report.v1".to_string(),
        accepted: true,
        batch_outcome: chio_pheromone_runtime::PheromoneBatchOutcome::Accepted,
        accepted_frame_count: batch.frames.len() as u64,
        rejected_frame_count: 0,
        batch_sha256: core_sha256_hex(&batch_bytes),
        recipient_kernel_id: RECIPIENT.to_string(),
        authenticated_sender_kernel_id: "did:chio:bob".to_string(),
        received_at_unix_ms: NOW,
        frames: Vec::new(),
    };

    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(AcceptingReceiver { report });
    let scope_check: InboundBatchScopeCheck = Arc::new(
        |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
            Ok(())
        },
    );
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let handler = PheromoneBatchHandler::new(gate.clone(), receiver, store, now, scope_check)
        .with_accept_limits(AcceptLimitConfig {
            max_in_flight_per_peer: 1,
            ..AcceptLimitConfig::default()
        });

    let acceptor = bind_endpoint(43, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("a per-peer cap of 1 still admits a single dialer");
    assert!(
        outcome.accepted,
        "single dialer under per-peer cap 1 is accepted"
    );

    router.shutdown().await.ok();
}

#[tokio::test]
async fn unbound_dialer_is_rejected_at_handshake() {
    // Directory admits only the endpoint derived from seed 20.
    let gate = verified_gate("did:chio:bob", 1, 20, false);
    let acceptor = bind_endpoint(21, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, CannedReportHandler { gate })
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    // Seed 99 is not bound in the directory: the accept-time gate rejects it.
    let unbound = bind_endpoint(99, None).await;
    let batch = direct_batch("did:chio:bob");
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh(&unbound, acceptor_addr, &batch),
    )
    .await
    .expect("dial resolves before timeout");
    assert!(
        result.is_err(),
        "unbound endpoint must be rejected, got {result:?}"
    );

    router.shutdown().await.ok();
}

// -- Driving the REAL per-frame verifier over loopback QUIC --
//
// The `CannedReportHandler` above proves the wire path and the accept-time
// gate, but the canned handler never runs the verifier. Wiring the actual
// `PheromoneBatchHandler` is not possible here without a Cargo.toml change:
// `RelayBatchReceiver::receive_batch` returns
// `chio_pheromone_runtime::PheromoneReceiveReport`, and chio-pheromone-runtime
// is neither a (dev-)dependency of this crate nor re-exported by any current
// dependency, so no `RelayBatchReceiver` double (real OR recording) can even
// name its return type. So instead this handler resolves the sender through
// the REAL admission gate (exactly as `PheromoneBatchHandler::handle` does)
// and feeds that gate-resolved kernel_id - never an attacker value - into the
// REAL `verify_pheromone_gossip_batch` (pheromone_gossip.rs:236/244), the same
// per-frame verifier the production handler runs behind the receiver seam.
// This drives the verifier the canned handler skips, over genuine QUIC.

#[derive(Debug, Clone)]
struct VerifyingBatchHandler {
    gate: DirectoryGate,
    policy: Arc<PheromoneTransitPolicy>,
    recipient_kernel_id: String,
    now_unix_ms: u64,
}

impl ProtocolHandler for VerifyingBatchHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // The one transport-sourced value, resolved exactly as the real
        // handler does. Everything else feeds the unchanged verifier.
        let sender = resolve_authenticated_sender(&self.gate, &conn.remote_id())
            .map_err(AcceptError::from_err)?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let raw = read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES)
            .await
            .map_err(AcceptError::from_err)?;
        let batch: PheromoneGossipBatch =
            serde_json::from_slice(&raw).map_err(AcceptError::from_err)?;

        let context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: self.now_unix_ms,
            recipient_kernel_id: self.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: sender.clone(),
        };
        let accepted = verify_pheromone_gossip_batch(&batch, &self.policy, &context).is_ok();

        // A COMPLETE receive report, faithfully mirroring the runtime type; a
        // partial report is rejected on the dial side before a batch is marked
        // delivered (see [`ReceiveReportShape`]).
        let frame_count = batch.frames.len() as u64;
        let report = serde_json::json!({
            "schema": "chio.pheromone-receive-report.v1",
            "accepted": accepted,
            "batchOutcome": if accepted { "accepted" } else { "rejected" },
            "acceptedFrameCount": if accepted { frame_count } else { 0 },
            "rejectedFrameCount": if accepted { 0 } else { frame_count },
            "batchSha256": "0".repeat(64),
            "recipientKernelId": batch.recipient_kernel_id,
            "authenticatedSenderKernelId": sender,
            "receivedAtUnixMs": self.now_unix_ms,
            "frames": [],
        });
        let bytes = serde_json::to_vec(&report).map_err(AcceptError::from_err)?;
        write_len_delimited(&mut send, &bytes)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

fn verifying_handler(gate: DirectoryGate) -> VerifyingBatchHandler {
    VerifyingBatchHandler {
        gate,
        policy: Arc::new(live_policy()),
        recipient_kernel_id: RECIPIENT.to_string(),
        now_unix_ms: NOW,
    }
}

#[tokio::test]
async fn real_verifier_accepts_admitted_senders_own_batch_over_quic() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    let dialer_seed = 24u8;
    // The gate resolves the dialer endpoint to did:chio:bob.
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
    let acceptor = bind_endpoint(25, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, verifying_handler(gate))
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    // Batch authored by did:chio:bob == the gate-resolved authenticated sender.
    let batch = direct_batch("did:chio:bob");
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("delivery round-trips");
    assert!(
        outcome.accepted,
        "the real verifier, fed the gate-resolved sender, accepts the admitted sender's own batch"
    );

    router.shutdown().await.ok();
}

#[tokio::test]
async fn real_verifier_rejects_batch_whose_author_is_not_the_authenticated_sender_over_quic() {
    let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
    let dialer_seed = 26u8;
    // The dialer endpoint is admitted, resolving to did:chio:bob...
    let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
    let acceptor = bind_endpoint(27, Some(gate.clone())).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, verifying_handler(gate))
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(dialer_seed, None).await;
    // ...but the batch's gossiping_peer_kernel_id is did:chio:mallory, not the
    // gate-resolved did:chio:bob. The REAL verifier's :236 check fails closed,
    // so the transport CANNOT launder an attacker-chosen author.
    let batch = direct_batch("did:chio:mallory");
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
    )
    .await
    .expect("delivery completes before timeout")
    .expect("delivery round-trips");
    assert!(
            !outcome.accepted,
            "a batch whose gossiping_peer != the authenticated sender must be rejected by the real verifier"
        );

    router.shutdown().await.ok();
}

// -- Client-side slowloris bound --
//
// A recipient that completes the handshake and reads the batch but never
// returns the report frame must not hang the dialer forever (which would
// block the sequential outbox drain of every later batch). This handler is
// that hostile-but-admitted recipient.

#[derive(Debug, Clone)]
struct SilentAfterReadHandler;

impl ProtocolHandler for SilentAfterReadHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut _send, mut recv) = conn.accept_bi().await?;
        // Read the request frame, then deliberately never write the report:
        // exactly the "recipient never returns the report" hang the client
        // read bound defends against.
        let _raw = read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES)
            .await
            .map_err(AcceptError::from_err)?;
        conn.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn client_read_bound_drops_a_recipient_that_never_returns_the_report() {
    // No admission gate on the acceptor: this isolates the CLIENT read bound
    // (the recipient handshakes and reads the batch, then goes silent).
    let acceptor = bind_endpoint(40, None).await;
    let router = Router::builder(acceptor)
        .accept(ALPN_PHEROMONE_BATCH, SilentAfterReadHandler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint());

    let dialer = bind_endpoint(41, None).await;
    let batch = direct_batch("did:chio:llamaworks");
    // A tight read bound; connect/open/write keep their generous defaults so
    // only the (hung) report read trips.
    let limits = AcceptLimitConfig {
        read_timeout: Duration::from_millis(200),
        ..AcceptLimitConfig::default()
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh_with_limits(&dialer, acceptor_addr, &batch, &limits),
    )
    .await
    .expect("the client read bound must fire well before the outer test timeout");
    let error = outcome.expect_err("a silent recipient must fail closed at the read bound");
    assert!(
        matches!(
            error,
            IrohLaneError::AcceptLimit(AcceptLimitError::Timeout {
                phase: AcceptPhase::ReadFrame,
                ..
            })
        ),
        "unexpected error: {error:?}"
    );
    assert_eq!(error.code(), "accept_timeout");

    router.shutdown().await.ok();
}

// -- Sender-mismatch rows are re-queued, never dead-lettered --

#[tokio::test]
async fn sender_mismatch_row_is_requeued_not_dead_lettered() {
    // A leased outbox row whose sender_kernel_id != the sender being drained
    // belongs to a DIFFERENT sender's drain. It must be re-queued (mirroring the
    // HTTP tick), never routed through the dead-letter path: draining it
    // repeatedly must NEVER dead-letter another sender's batch.
    let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = direct_batch("did:chio:other");
    enqueue_batch_for_delivery(&store, "did:chio:other", RECIPIENT, TREATY, &batch, NOW).unwrap();

    // The mismatch is caught before any dial, so resolve_addr / scope_check must
    // never run; the endpoint is likewise never used.
    let endpoint = bind_endpoint(43, None).await;
    let mut now = NOW;
    for _ in 0..4 {
        let report = drain_outbox_over_iroh(
            &store,
            &endpoint,
            |_recipient: &str| -> Option<EndpointAddr> {
                panic!("a sender-mismatched row must never be resolved or dialed")
            },
            |_recipient: &str, _batch: &PheromoneGossipBatch| {
                panic!("a sender-mismatched row must never be scope-checked")
            },
            // Draining for a DIFFERENT sender than the queued row.
            "did:chio:llamaworks",
            now,
            10,
        )
        .await
        .unwrap();
        assert_eq!(report.delivered, 0);
        assert_eq!(
            report.dead_lettered, 0,
            "a mismatched-sender row must never be dead-lettered"
        );
        assert_eq!(
            report.retried, 1,
            "the row is re-queued so its correct sender can drain it"
        );
        assert!(
            report.failures[0].contains("sender_mismatch"),
            "unexpected failures: {:?}",
            report.failures
        );
        // Advance past the fixed 60s re-queue backoff so the row leases again.
        now = now.saturating_add(60_001);
    }
}

// -- Outbound directory-scope enforcement on the drain --

#[tokio::test]
async fn outbound_scope_rejection_skips_dial_and_folds_into_retry() {
    let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = direct_batch("did:chio:llamaworks");
    enqueue_batch_for_delivery(
        &store,
        "did:chio:llamaworks",
        RECIPIENT,
        TREATY,
        &batch,
        NOW,
    )
    .unwrap();

    // A real endpoint satisfies the signature, but the scope check rejects
    // BEFORE any dial, so resolve_addr (and the endpoint) are never used.
    let endpoint = bind_endpoint(42, None).await;

    let report = drain_outbox_over_iroh(
        &store,
        &endpoint,
        |_recipient: &str| -> Option<EndpointAddr> {
            panic!("a scope-rejected batch must never be resolved or dialed")
        },
        |recipient: &str, _batch: &PheromoneGossipBatch| {
            // Mirror a recipient removed from the current directory scope.
            Err(PheromoneRelayError::PeerRemoved(recipient.to_string()))
        },
        "did:chio:llamaworks",
        NOW,
        10,
    )
    .await
    .unwrap();

    assert_eq!(
        report.delivered, 0,
        "a scope-rejected batch is never delivered"
    );
    assert_eq!(report.retried, 1, "it folds into the durable retry path");
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(report.failures.len(), 1);
    assert!(
        report.failures[0].contains("peer_removed"),
        "the mirrored scope code must be recorded, got {:?}",
        report.failures
    );
}
