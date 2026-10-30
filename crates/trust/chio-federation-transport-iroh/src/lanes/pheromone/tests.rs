#![allow(clippy::unwrap_used, clippy::expect_used)]
use chio_pheromone_runtime::PheromoneReceiveReport as ReceiveReportShape;

use super::*;
fn fixture_frame_reports(
    batch: &PheromoneGossipBatch,
    accepted: bool,
) -> Vec<chio_pheromone_runtime::PheromoneFrameReport> {
    batch
        .frames
        .iter()
        .enumerate()
        .map(
            |(frame_index, _)| chio_pheromone_runtime::PheromoneFrameReport {
                frame_index,
                accepted,
                code: if accepted { "accepted" } else { "rejected" }.into(),
                detail: "fixture".into(),
                deposit_nonce: None,
            },
        )
        .collect()
}

use crate::identity::sign_transport_endorsement;
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
        passport_endorsement: sign_transport_endorsement(&passport, kernel_id, &transport).unwrap(),
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
    let signature = issuer
        .sign_wrapped(
            crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA,
            &chio_core_types::canonical::CanonicalBytes::from_serializable(&body).unwrap(),
        )
        .unwrap();
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
    let sig = Keypair::from_seed(&[9; 32]).sign_exempt(
        chio_core_types::crypto::ExemptFormat::JwsSigningInput,
        b"pheromone-lane-fixture",
    );
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
    // This isolates the store-level premise. The end-to-end winner-path re-read and
    // durable verdict adoption are covered by
    // `winner_path_adopts_durable_verdict_after_commit_before_mark_crash` below.
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

mod over_quic;
