#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn lagged_event_is_metered_and_surfaced() {
    // The variant exists, is fieldless, and has a stable code.
    assert_eq!(FanoutError::Lagged.code(), "lagged");
    // The lagged outcome has a real metrics slot that advances (observe-only,
    // monotone lower bound: other tests only ever add).
    let before = crate::metrics::lane_total(
        crate::metrics::LANE_FANOUT,
        crate::metrics::LANE_OUTCOME_LAGGED,
    );
    crate::metrics::record_lane_frame(
        crate::metrics::LANE_FANOUT,
        crate::metrics::LANE_OUTCOME_LAGGED,
    );
    assert!(
        crate::metrics::lane_total(
            crate::metrics::LANE_FANOUT,
            crate::metrics::LANE_OUTCOME_LAGGED,
        ) > before,
        "a lagged event must be counted, never silently dropped"
    );
}
use chio_core_types::Keypair;
use chio_federation::pheromone_gossip::PheromoneDepositGossip;
use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA;
use chio_federation::pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA;
use chio_pheromone::sign_deposit;
use chio_pheromone::PheromoneDeposit;
use chio_pheromone::PheromoneDepositBody;
use chio_pheromone::Severity;
use chio_pheromone::PHEROMONE_DEPOSIT_SCHEMA;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::RelayMode;
use iroh::SecretKey;
use iroh_gossip::api::Message;
use iroh_gossip::proto::DeliveryScope;
use std::net::Ipv4Addr;

// Build a real issuer-signed VerifiedDirectory as the membership oracle to pin
// the production treaty-party gate.
use crate::identity::transport_endorsement_preimage;
use crate::identity::TransportDirectoryBundleBody;
use crate::identity::TransportDirectoryBundleDocument;
use crate::identity::TransportDirectoryBundleTrust;
use crate::identity::TransportDirectoryDocument;
use crate::identity::TransportDirectoryEntry;
use crate::identity::TransportTreatyEntry;
use crate::identity::TrustedTransportDirectoryIssuer;
use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;

const NOW: u64 = 1_700_000_000_000;
const NAMESPACE: &str = "chio/agents";
const TREATY_ALPHA: &str = "treaty-alpha";
const AUTHOR: &str = "did:chio:author";

fn endpoint_from_seed(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

fn deposit_body(kernel_id: &str, treaty: &str, namespace: &str) -> PheromoneDepositBody {
    PheromoneDepositBody {
        schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
        kernel_id: kernel_id.to_string(),
        agent_passport_key_hash: "passport-key-hash".to_string(),
        agent_passport_jwk_thumbprint: "passport-thumbprint".to_string(),
        subject_class: "malicious-tool".to_string(),
        subject_class_namespace: namespace.to_string(),
        indicator: serde_json::json!({ "kind": "observation" }),
        severity: Severity::High,
        confidence: 0.8,
        timestamp_unix_ms: NOW,
        decay_half_life_secs: 3600.0,
        evaporation_floor: None,
        nonce: "nonce-1".to_string(),
        treaty_scope: vec![treaty.to_string()],
        cost_commitment: None,
        workflow_context: None,
    }
}

/// A direct (non-relay) frame authored + self-signed by `author`.
fn signed_direct_frame(
    author: &Keypair,
    author_kernel: &str,
    gossiping_peer: &str,
    treaty: &str,
    namespace: &str,
) -> PheromoneDepositGossip {
    let deposit = sign_deposit(deposit_body(author_kernel, treaty, namespace), author).unwrap();
    frame_over(deposit, author_kernel, gossiping_peer, treaty)
}

fn frame_over(
    deposit: PheromoneDeposit,
    origin: &str,
    gossiping_peer: &str,
    treaty: &str,
) -> PheromoneDepositGossip {
    PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit,
        origin_kernel_id: origin.to_string(),
        gossiping_peer_kernel_id: gossiping_peer.to_string(),
        treaty_id: treaty.to_string(),
        ts_unix_ms: NOW,
        transit_chain: None,
    }
}

/// A membership admitting `AUTHOR` to both treaties the tests exercise, so the
/// treaty-party gate is a no-op for the pre-existing authenticity tests (which
/// isolate signature / origin / binding failures). The dedicated membership
/// tests below use a membership that does NOT admit the author.
fn party_membership() -> StaticTreatyMembership {
    StaticTreatyMembership::new()
        .with(TREATY_ALPHA, [AUTHOR])
        .with("treaty-beta", [AUTHOR])
}

fn live_policy(namespace: &str) -> PheromoneTransitPolicy {
    PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: Vec::new(),
        allowed_ingress_treaties: Vec::new(),
        allowed_egress_treaties: Vec::new(),
        allowed_subject_class_namespaces: vec![namespace.to_string()],
        valid_from_unix_ms: NOW - 1,
        valid_until_unix_ms: NOW + 1_000_000,
        max_hops: 4,
        required_action_class_id: "action".to_string(),
        pinned_ladder_refs: Vec::new(),
    }
}

/// An issuer-signed, load-time-verified directory whose treaty `TREATY_ALPHA`
/// party set is exactly {did:chio:alice}. This is the PRODUCTION membership
/// oracle (a `VerifiedDirectory`), so it pins the real treaty-party gate rather
/// than a `StaticTreatyMembership` stand-in.
fn party_verified_directory() -> crate::identity::VerifiedDirectory {
    let passport = Keypair::from_seed(&[50; 32]);
    let issuer = Keypair::from_seed(&[240; 32]);
    let transport = endpoint_from_seed(60);
    let entry = TransportDirectoryEntry {
        kernel_id: "did:chio:alice".to_string(),
        passport_public_key: passport.public_key(),
        transport_endpoint_id: transport,
        passport_endorsement: passport.sign(&transport_endorsement_preimage(
            "did:chio:alice",
            &transport,
        )),
        revocation_signers: Vec::new(),
        removed: false,
    };
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:local".to_string(),
        peers: vec![entry],
        treaties: vec![TransportTreatyEntry {
            treaty_id: TREATY_ALPHA.to_string(),
            party_kernel_ids: vec!["did:chio:alice".to_string()],
        }],
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
    bundle
        .verify_bundle(&trust)
        .expect("treaty bundle verifies")
}

#[test]
fn fanout_membership_gate_rejects_non_party_at_join_and_receive() {
    // Regression pin: the per-treaty membership gate is enforced against the
    // issuer-signed VerifiedDirectory party set.
    let directory = party_verified_directory();

    // JOIN precondition the swarm-join gate reads: is_treaty_party is fail-closed
    // for a non-party (and true for a party).
    assert!(directory.is_treaty_party(TREATY_ALPHA, "did:chio:alice"));
    assert!(!directory.is_treaty_party(TREATY_ALPHA, "did:chio:eve"));

    // RECEIVE: a validly self-signed frame whose origin (eve) is NOT a party to
    // TREATY_ALPHA is rejected with TreatyMembershipDenied, using the
    // VerifiedDirectory as the membership oracle. Eve is not directory-bound, so
    // her key resolves via the caller resolver; the directory still denies the
    // treaty membership AFTER the self-signature verifies (fail-closed).
    let eve = Keypair::from_seed(&[71; 32]);
    let frame = signed_direct_frame(
        &eve,
        "did:chio:eve",
        "did:chio:hub",
        TREATY_ALPHA,
        NAMESPACE,
    );
    let keys = StaticOriginKeys::new().with("did:chio:eve", eve.public_key());
    let policy = live_policy(NAMESPACE);
    let error = verify_fanout_frame(&frame, &keys, &directory, &policy, NOW)
        .expect_err("a non-party origin is denied on receive");
    assert!(
        matches!(error, FanoutError::TreatyMembershipDenied { .. }),
        "unexpected: {error:?}"
    );
}

#[test]
fn valid_self_signed_frame_is_accepted() {
    let author = Keypair::from_seed(&[7; 32]);
    // gossiping_peer is deliberately a re-gossiping HUB, not the author: the
    // fan-out lane does not require gossiping_peer == author (unlike lanes a/b).
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = party_membership();

    verify_fanout_frame(&frame, &keys, &membership, &policy, NOW)
        .expect("valid self-signed frame accepted");

    // And through the full receive shape (mirrors the gossip PoC loop): the
    // frame arrives forwarded by some neighbor, then decode + verify accepts.
    let content = encode_fanout_frame(&frame).expect("encodes under cap");
    let neighbor = endpoint_from_seed(42);
    let event = Event::Received(Message {
        content,
        scope: DeliveryScope::Neighbors,
        delivered_from: neighbor,
    });
    match event {
        Event::Received(message) => {
            let verified = decode_and_verify_fanout_frame(
                &message.content,
                TREATY_ALPHA,
                &keys,
                &membership,
                &policy,
                NOW,
            )
            .expect("received frame verifies");
            assert_eq!(verified.origin_kernel_id, AUTHOR);
        }
        other => panic!("expected Received, got {other:?}"),
    }
}

#[test]
fn bad_deposit_signature_rejected_even_from_admitted_neighbor() {
    let author = Keypair::from_seed(&[7; 32]);
    // A fully-trusted, admitted neighbor: it has its own passport key in the
    // resolver and its own admitted transport endpoint. It forwards A's frame.
    let neighbor = Keypair::from_seed(&[8; 32]);
    let neighbor_endpoint = endpoint_from_seed(43);

    let mut frame = signed_direct_frame(
        &author,
        AUTHOR,
        "did:chio:neighbor",
        TREATY_ALPHA,
        NAMESPACE,
    );
    // Tamper a signed-but-frame-irrelevant field AFTER signing: the frame-level
    // checks still pass, but the deposit self-signature no longer matches.
    frame.deposit.body.confidence = 0.123_456;

    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new()
        .with(AUTHOR, author.public_key())
        .with("did:chio:neighbor", neighbor.public_key());
    let membership = party_membership();

    // Delivered by the admitted neighbor. `delivered_from` is a genuine,
    // trusted swarm member, yet it does NOT launder the tampered payload.
    let content = encode_fanout_frame(&frame).expect("encodes under cap");
    let event = Event::Received(Message {
        content,
        scope: DeliveryScope::Neighbors,
        delivered_from: neighbor_endpoint,
    });
    match event {
        Event::Received(message) => {
            let result = decode_and_verify_fanout_frame(
                &message.content,
                TREATY_ALPHA,
                &keys,
                &membership,
                &policy,
                NOW,
            );
            assert!(
                    matches!(result, Err(FanoutError::DepositSignatureInvalid)),
                    "tampered payload must be rejected regardless of the admitted forwarder, got {result:?}"
                );
        }
        other => panic!("expected Received, got {other:?}"),
    }
}

#[test]
fn unknown_origin_is_rejected() {
    let author = Keypair::from_seed(&[7; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    // Empty resolver: the origin has no bound key, so authorship is unresolvable.
    let keys = StaticOriginKeys::new();
    let membership = party_membership();

    let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
    assert!(matches!(result, Err(FanoutError::UnknownOrigin(_))));
}

#[test]
fn unknown_origin_bumps_verify_failure_counter_and_is_still_rejected() {
    // OBSERVE-ONLY proof: an unresolvable author still fails closed AND bumps
    // verify_failures{fanout,unknown-origin}; the returned Err is unchanged.
    let author = Keypair::from_seed(&[7; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new();
    let membership = party_membership();

    let before =
        crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "unknown-origin");
    let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
    assert!(matches!(result, Err(FanoutError::UnknownOrigin(_))));
    assert!(
        crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "unknown-origin")
            > before,
        "the fan-out verify failure must be counted (observe-only)"
    );
}

#[test]
fn treaty_mismatch_bumps_verify_failure_counter_and_is_still_rejected() {
    // OBSERVE-ONLY proof for the cross-treaty injection signal: a valid-signature
    // frame minted for a foreign treaty is still rejected on this swarm AND is
    // counted (verify_failures{fanout,treaty-mismatch}).
    let author = Keypair::from_seed(&[7; 32]);
    let beta_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = party_membership();
    let content = encode_fanout_frame(&beta_frame).expect("encodes under cap");

    let before =
        crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "treaty-mismatch");
    let result =
        decode_bind_treaty_and_verify(&content, TREATY_ALPHA, &keys, &membership, &policy, NOW);
    assert!(matches!(result, Err(FanoutError::TreatyMismatch { .. })));
    assert!(
        crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "treaty-mismatch")
            > before,
        "the cross-treaty injection must be counted (observe-only)"
    );
}

#[test]
fn topic_derivation_is_deterministic_and_distinct_per_treaty() {
    let alpha_1 = pheromone_topic_for_treaty(TREATY_ALPHA);
    let alpha_2 = pheromone_topic_for_treaty(TREATY_ALPHA);
    let beta = pheromone_topic_for_treaty("treaty-beta");

    // Deterministic for the same treaty, distinct across treaties.
    assert_eq!(alpha_1, alpha_2);
    assert_ne!(alpha_1, beta);

    // A different domain-separation label yields a different topic for the same
    // treaty (no cross-surface collision).
    let other_surface = topic_for_treaty("chio-trust-fanout/v1", TREATY_ALPHA);
    assert_ne!(alpha_1, other_surface);

    // Exact digest: blake3(label || 0x00 || treaty) used verbatim.
    let mut hasher = blake3::Hasher::new();
    hasher.update(PHEROMONE_FANOUT_TOPIC_LABEL.as_bytes());
    hasher.update(b"\x00");
    hasher.update(TREATY_ALPHA.as_bytes());
    let expected = TopicId::from_bytes(*hasher.finalize().as_bytes());
    assert_eq!(alpha_1, expected);
}

#[test]
fn oversized_frame_is_rejected_before_broadcast() {
    let author = Keypair::from_seed(&[7; 32]);
    let mut body = deposit_body(AUTHOR, TREATY_ALPHA, NAMESPACE);
    // A large indicator pushes the serialized frame past the ~4 KiB cap.
    body.indicator = serde_json::json!({ "blob": "x".repeat(5_000) });
    let deposit = sign_deposit(body, &author).unwrap();
    let frame = frame_over(deposit, AUTHOR, "did:chio:hub", TREATY_ALPHA);

    let result = encode_fanout_frame(&frame);
    assert!(matches!(result, Err(FanoutError::MessageTooLarge { .. })));
}

#[test]
fn frame_from_a_foreign_treaty_is_rejected_on_this_swarm() {
    // F2 (fail-open fix): a frame minted for treaty-beta, carrying a fully
    // VALID deposit self-signature, is injected onto the alpha swarm. Routing
    // separation alone does not stop this (a globally-admitted operator can
    // compute the non-secret beta TopicId), so the RECEIVE side must bind the
    // swarm to its treaty and reject the foreign frame.
    let author = Keypair::from_seed(&[7; 32]);
    let beta_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = party_membership();
    let content = encode_fanout_frame(&beta_frame).expect("encodes under cap");

    // Sanity: bound to its OWN treaty (beta), the frame's signature, origin, and
    // treaty-party membership all verify, so the rejection below is purely the
    // swarm/treaty binding to a DIFFERENT treaty, not a bad sig or a non-party.
    decode_bind_treaty_and_verify(&content, "treaty-beta", &keys, &membership, &policy, NOW)
        .expect("beta frame verifies when bound to the beta swarm");

    // Received on the alpha swarm (self.treaty_id = TREATY_ALPHA): rejected.
    let result =
        decode_bind_treaty_and_verify(&content, TREATY_ALPHA, &keys, &membership, &policy, NOW);
    assert!(
            matches!(
                result,
                Err(FanoutError::TreatyMismatch { ref expected, ref got })
                    if expected == TREATY_ALPHA && got == "treaty-beta"
            ),
            "a valid-signature frame bound to treaty-beta must be rejected on the alpha swarm, got {result:?}"
        );

    // And a matching-treaty frame on the same swarm still passes the binding.
    let alpha_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let alpha_content = encode_fanout_frame(&alpha_frame).expect("encodes under cap");
    decode_bind_treaty_and_verify(
        &alpha_content,
        TREATY_ALPHA,
        &keys,
        &membership,
        &policy,
        NOW,
    )
    .expect("an alpha-treaty frame is accepted on the alpha swarm");
}

#[test]
fn lane_verifies_a_real_chio_pheromone_deposit_signature() {
    // F3 guard: pin this lane's hand-copied signing preimage (clear
    // cost_commitment + canonical JSON) to the NORMATIVE signer. We build a
    // real deposit with chio_pheromone::sign_deposit and assert this lane's
    // verify_deposit_self_signature accepts it. If chio_pheromone changes its
    // canonicalization (deposit_signature_body / canonical_json), this test
    // fails loudly here instead of the copy silently diverging and rejecting
    // otherwise-valid deposits.
    let author = Keypair::from_seed(&[7; 32]);
    let deposit = sign_deposit(deposit_body(AUTHOR, TREATY_ALPHA, NAMESPACE), &author).unwrap();
    let frame = frame_over(deposit, AUTHOR, "did:chio:hub", TREATY_ALPHA);

    verify_deposit_self_signature(&frame, &author.public_key())
        .expect("lane preimage matches chio_pheromone::sign_deposit canonicalization");

    // A one-byte tamper of a signed field must then fail closed, proving the
    // acceptance above is the real signature check and not a no-op.
    let mut tampered = frame;
    tampered.deposit.body.confidence = 0.123_456;
    assert!(matches!(
        verify_deposit_self_signature(&tampered, &author.public_key()),
        Err(FanoutError::DepositSignatureInvalid)
    ));
}

#[test]
fn small_frame_encodes_under_cap() {
    let author = Keypair::from_seed(&[7; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let payload = encode_fanout_frame(&frame).expect("encodes");
    assert!(payload.len() <= MAX_GOSSIP_MESSAGE_SIZE);
    // Round-trips back to an equal frame.
    let decoded: PheromoneDepositGossip = serde_json::from_slice(&payload).unwrap();
    assert_eq!(decoded, frame);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_join_fails_closed_on_timeout() {
    // An empty bootstrap has no neighbor to join, so subscribe_and_join would
    // block forever; the client join bound fails it closed rather than hanging.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[73u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let local_id = endpoint.id();
    let gossip = Gossip::builder().spawn(endpoint.clone());
    // The lane derives its local endpoint id from &endpoint, so it
    // must be built before the endpoint is moved into the router.
    let lane = FanoutLane::new(gossip.clone(), &endpoint);
    let _router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip)
        .spawn();
    // Local operator IS a party AND its authenticated endpoint resolves to
    // AUTHOR, so it passes the membership gate and reaches the (empty-bootstrap)
    // join, which then fails closed on the client bound.
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, [AUTHOR])
        .with_endpoint(local_id, AUTHOR);
    let result = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            AUTHOR,
            &membership,
            vec![],
            Duration::from_millis(50),
        )
        .await;
    assert!(
        matches!(result, Err(FanoutError::Gossip(ref msg)) if msg.contains("timed out")),
        "empty-bootstrap join must fail closed on the client bound, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_rejects_wrong_treaty_frame_before_send() {
    // Send-side treaty binding (mirrors the receive-side check): a fully
    // valid, self-signed frame minted for treaty-beta is rejected BEFORE it
    // reaches the wire when broadcast on the alpha swarm, so a mis-addressed
    // frame cannot leak onto another treaty's swarm members.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[71u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();

    // subscribe (NOT join): returns immediately without a neighbor, which is
    // enough to exercise broadcast's pre-send treaty check on a single node
    // (the check returns before the sender is ever used).
    let topic_id = pheromone_topic_for_treaty(TREATY_ALPHA);
    let (sender, receiver) = gossip
        .subscribe(topic_id, vec![])
        .await
        .expect("subscribe to the alpha topic")
        .split();
    let alpha_topic = FanoutTopic {
        treaty_id: TREATY_ALPHA.to_string(),
        topic_id,
        sender,
        receiver,
    };

    // A frame with a fully VALID deposit self-signature, but minted for a
    // DIFFERENT treaty than this swarm carries.
    let author = Keypair::from_seed(&[7; 32]);
    let beta_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);

    let result = alpha_topic.broadcast(&beta_frame).await;
    assert!(
        matches!(
            result,
            Err(FanoutError::TreatyMismatch { ref expected, ref got })
                if expected == TREATY_ALPHA && got == "treaty-beta"
        ),
        "a treaty-beta frame must be rejected before the alpha swarm broadcast, got {result:?}"
    );

    drop(alpha_topic);
    router.shutdown().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_sender_enforces_treaty_and_size_checks() {
    // The advertised concurrent sender (for broadcasting alongside a `&mut self`
    // receive loop) must run the SAME send-side checks as `FanoutTopic::broadcast`:
    // there is no raw-`GossipSender` escape hatch. Both a wrong-treaty frame and an
    // oversized frame are rejected BEFORE they reach the wire.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[74u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();

    // subscribe (NOT join): returns immediately without a neighbor, enough to
    // exercise the pre-send checks (they return before the sender is ever used).
    let topic_id = pheromone_topic_for_treaty(TREATY_ALPHA);
    let (sender, receiver) = gossip
        .subscribe(topic_id, vec![])
        .await
        .expect("subscribe to the alpha topic")
        .split();
    let alpha_topic = FanoutTopic {
        treaty_id: TREATY_ALPHA.to_string(),
        topic_id,
        sender,
        receiver,
    };

    let concurrent = alpha_topic.concurrent_sender();
    assert_eq!(concurrent.treaty_id(), TREATY_ALPHA);

    // Wrong treaty: a fully valid, self-signed treaty-beta frame is rejected on
    // the alpha concurrent sender before any broadcast.
    let author = Keypair::from_seed(&[7; 32]);
    let beta_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
    let wrong_treaty = concurrent.broadcast(&beta_frame).await;
    assert!(
        matches!(
            wrong_treaty,
            Err(FanoutError::TreatyMismatch { ref expected, ref got })
                if expected == TREATY_ALPHA && got == "treaty-beta"
        ),
        "the concurrent sender must reject a wrong-treaty frame, got {wrong_treaty:?}"
    );

    // Oversized: a correctly-addressed alpha frame past the ~4 KiB cap is rejected
    // too (the size check the raw sender would have skipped).
    let mut body = deposit_body(AUTHOR, TREATY_ALPHA, NAMESPACE);
    body.indicator = serde_json::json!({ "blob": "x".repeat(5_000) });
    let deposit = sign_deposit(body, &author).unwrap();
    let oversized = frame_over(deposit, AUTHOR, "did:chio:hub", TREATY_ALPHA);
    let too_large = concurrent.broadcast(&oversized).await;
    assert!(
        matches!(too_large, Err(FanoutError::MessageTooLarge { .. })),
        "the concurrent sender must reject an oversized frame, got {too_large:?}"
    );

    drop(alpha_topic);
    router.shutdown().await.ok();
}

#[test]
fn receive_rejects_a_non_party_origin_frame() {
    // ITEM 1 receive side: a frame with a fully VALID deposit self-signature and
    // a resolvable origin key is still rejected if the origin kernel is NOT a
    // party to the frame's treaty, so a non-party that joined the swarm anyway
    // cannot inject an accepted frame.
    let author = Keypair::from_seed(&[7; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    // Membership admits a DIFFERENT kernel to alpha, so AUTHOR is a non-party.
    let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, ["did:chio:other"]);

    let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
    assert!(
        matches!(
            result,
            Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                if treaty_id == TREATY_ALPHA && kernel_id == AUTHOR
        ),
        "a non-party origin frame must be rejected on receive, got {result:?}"
    );

    // Same rejection through the raw decode entry (bound to the alpha treaty).
    let content = encode_fanout_frame(&frame).expect("encodes under cap");
    let decoded =
        decode_and_verify_fanout_frame(&content, TREATY_ALPHA, &keys, &membership, &policy, NOW);
    assert!(matches!(
        decoded,
        Err(FanoutError::TreatyMembershipDenied { .. })
    ));
}

#[test]
fn receive_accepts_a_party_origin_frame() {
    // Control: with the origin admitted as a party to alpha, the same frame
    // verifies. The membership gate is the ONLY difference from the reject above.
    let author = Keypair::from_seed(&[7; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, [AUTHOR]);

    verify_fanout_frame(&frame, &keys, &membership, &policy, NOW)
        .expect("a party origin frame verifies");
}

#[test]
fn raw_decode_rejects_a_foreign_treaty_frame() {
    // ITEM 2: the raw next_payload decode path is now BOUND to the joined
    // treaty. A frame minted for treaty-beta - with a fully VALID deposit
    // self-signature AND an origin that is a party to beta - is still rejected
    // when decoded on the alpha swarm (expected_treaty = TREATY_ALPHA), so a raw
    // receive loop can no longer accept a foreign-treaty payload.
    let author = Keypair::from_seed(&[7; 32]);
    let beta_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = party_membership(); // admits AUTHOR to both alpha and beta
    let content = encode_fanout_frame(&beta_frame).expect("encodes under cap");

    // Bound to beta (its own treaty) it verifies - isolating the binding below.
    decode_and_verify_fanout_frame(&content, "treaty-beta", &keys, &membership, &policy, NOW)
        .expect("the beta frame verifies when the raw decode is bound to beta");

    // Bound to alpha, the raw decode rejects it before any signature work.
    let result =
        decode_and_verify_fanout_frame(&content, TREATY_ALPHA, &keys, &membership, &policy, NOW);
    assert!(
        matches!(
            result,
            Err(FanoutError::TreatyMismatch { ref expected, ref got })
                if expected == TREATY_ALPHA && got == "treaty-beta"
        ),
        "the raw decode must bind to the joined treaty, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn topic_bound_decoder_rejects_a_foreign_treaty_frame() {
    // The exposed checked decoder (FanoutTopic::decode_and_verify) supplies the
    // topic's OWN treaty, so a raw receive loop cannot forget the binding: a
    // beta frame is rejected on an alpha topic though its signature is valid.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[77u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();
    let topic_id = pheromone_topic_for_treaty(TREATY_ALPHA);
    let (sender, receiver) = gossip
        .subscribe(topic_id, vec![])
        .await
        .expect("subscribe to the alpha topic")
        .split();
    let alpha_topic = FanoutTopic {
        treaty_id: TREATY_ALPHA.to_string(),
        topic_id,
        sender,
        receiver,
    };

    let author = Keypair::from_seed(&[7; 32]);
    let beta_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = party_membership();
    let content = encode_fanout_frame(&beta_frame).expect("encodes under cap");

    let result = alpha_topic.decode_and_verify(&content, &keys, &membership, &policy, NOW);
    assert!(
        matches!(
            result,
            Err(FanoutError::TreatyMismatch { ref expected, ref got })
                if expected == TREATY_ALPHA && got == "treaty-beta"
        ),
        "the topic-bound decoder must bind to self.treaty_id, got {result:?}"
    );

    // Control: an alpha frame decodes cleanly through the same bound decoder.
    let alpha_frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let alpha_content = encode_fanout_frame(&alpha_frame).expect("encodes under cap");
    alpha_topic
        .decode_and_verify(&alpha_content, &keys, &membership, &policy, NOW)
        .expect("an alpha frame verifies on the alpha topic");

    drop(alpha_topic);
    router.shutdown().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_rejects_a_non_party_local_operator() {
    // ITEM 1 join side: a globally-admitted operator that is NOT a party to the
    // treaty is rejected BEFORE the swarm is joined, so treaty traffic never
    // reaches a non-party even though it can compute the (non-secret) topic id.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[75u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let local_id = endpoint.id();
    let gossip = Gossip::builder().spawn(endpoint.clone());
    // The lane derives its local endpoint id from &endpoint, so it
    // must be built before the endpoint is moved into the router.
    let lane = FanoutLane::new(gossip.clone(), &endpoint);
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip)
        .spawn();

    // Membership admits a DIFFERENT operator to alpha; the local endpoint
    // authenticates (honestly) as "did:chio:non-party", which is NOT a party, so
    // the join is rejected before any neighbor dial. (The caller's claimed id
    // equals the authenticated id here, so this exercises the party-denial path,
    // not the spoof path.)
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, ["did:chio:party"])
        .with_endpoint(local_id, "did:chio:non-party");
    let result = lane
        .subscribe_treaty(TREATY_ALPHA, "did:chio:non-party", &membership, vec![])
        .await;
    assert!(
        matches!(
            result,
            Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                if treaty_id == TREATY_ALPHA && kernel_id == "did:chio:non-party"
        ),
        "a non-party local operator must be rejected at join, got {result:?}"
    );

    // The gate fires BEFORE any neighbor dial: even with a NON-empty bootstrap
    // (an unreachable fabricated endpoint) and a short join bound, a non-party is
    // still denied with TreatyMembershipDenied rather than attempting the dial and
    // timing out. This confirms the gate fires before any neighbor is dialed, and
    // with the raw gossip handle private, no path reaches subscribe_and_join
    // without this check.
    let denied_with_bootstrap = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            "did:chio:non-party",
            &membership,
            vec![endpoint_from_seed(99)],
            Duration::from_millis(50),
        )
        .await;
    assert!(
            matches!(
                denied_with_bootstrap,
                Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                    if treaty_id == TREATY_ALPHA && kernel_id == "did:chio:non-party"
            ),
            "the membership gate must short-circuit before dialing bootstrap, got {denied_with_bootstrap:?}"
        );
    router.shutdown().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_admits_a_party_past_the_membership_gate() {
    // A genuine party passes the membership gate and proceeds to the join; with
    // an empty bootstrap the join then times out, proving the gate let it
    // through (the error is the client join bound, NOT a membership denial).
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[76u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let local_id = endpoint.id();
    let gossip = Gossip::builder().spawn(endpoint.clone());
    // The lane derives its local endpoint id from &endpoint, so it
    // must be built before the endpoint is moved into the router.
    let lane = FanoutLane::new(gossip.clone(), &endpoint);
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip)
        .spawn();

    // The local endpoint AUTHENTICATES as the genuine party, and the caller's
    // claimed id matches it, so the gate lets it through to the join.
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, ["did:chio:party"])
        .with_endpoint(local_id, "did:chio:party");
    let result = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            "did:chio:party",
            &membership,
            vec![],
            Duration::from_millis(50),
        )
        .await;
    assert!(
        matches!(result, Err(FanoutError::Gossip(ref msg)) if msg.contains("timed out")),
        "a party must pass the membership gate and reach the empty-bootstrap join, got {result:?}"
    );
    router.shutdown().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_rejects_a_non_party_spoofing_a_real_party_kernel_id() {
    // The JOIN gate must bind to the node's AUTHENTICATED endpoint identity, not
    // the caller-supplied `local_kernel_id` string, to prevent spoofing. A
    // globally-admitted operator that is NOT a party to the treaty calls
    // subscribe_treaty passing a REAL party's kernel id as the argument; because
    // that string is a genuine party, binding on `is_party(treaty, arg)` alone
    // would admit it and leak the treaty's traffic. The gate instead resolves the
    // LOCAL endpoint to its admitted kernel id and rejects the spoof.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[78u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let local_id = endpoint.id();
    let gossip = Gossip::builder().spawn(endpoint.clone());
    // The lane derives its local endpoint id from &endpoint, so it
    // must be built before the endpoint is moved into the router.
    let lane = FanoutLane::new(gossip.clone(), &endpoint);
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip)
        .spawn();

    // The directory authenticates THIS node's endpoint as the NON-party
    // "did:chio:intruder". "did:chio:party" is a real party, but a DIFFERENT
    // node - the intruder does not authenticate as it.
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, ["did:chio:party"])
        .with_endpoint(local_id, "did:chio:intruder");

    // Spoof: the intruder passes the real party's kernel id as the arg. Even
    // with a non-empty bootstrap and a short bound, it is denied (not dialed and
    // timed out), because the arg does not match the authenticated id.
    let spoofed = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            "did:chio:party",
            &membership,
            vec![endpoint_from_seed(99)],
            Duration::from_millis(50),
        )
        .await;
    assert!(
        matches!(
            spoofed,
            Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                if treaty_id == TREATY_ALPHA && kernel_id == "did:chio:party"
        ),
        "a non-party spoofing a real party's kernel id must be rejected, got {spoofed:?}"
    );

    // And the intruder gets no join even under its OWN authenticated id: it is
    // simply not a party to the treaty (the honest party-denial path).
    let honest = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            "did:chio:intruder",
            &membership,
            vec![endpoint_from_seed(99)],
            Duration::from_millis(50),
        )
        .await;
    assert!(
        matches!(
            honest,
            Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                if treaty_id == TREATY_ALPHA && kernel_id == "did:chio:intruder"
        ),
        "the intruder is a non-party even under its own id, got {honest:?}"
    );
    router.shutdown().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_derives_local_identity_from_the_spawned_endpoint() {
    // The constructor DERIVES local_endpoint_id from the passed Endpoint
    // (endpoint.id()) rather than a raw caller-supplied EndpointId. Proof: the
    // directory binds a DIFFERENT (foreign) endpoint to
    // the party and admits that party to the treaty, but does NOT bind THIS
    // node's endpoint.id(). Because the JOIN gate resolves the lane's OWN derived
    // endpoint id, it finds it unbound and fails closed - a caller cannot make
    // the lane authenticate under an endpoint id it does not actually hold.
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[79u8; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("endpoint binds on loopback");
    let real_id = endpoint.id();
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let lane = FanoutLane::new(gossip.clone(), &endpoint);
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip)
        .spawn();

    // The directory binds a FOREIGN endpoint (seed 200, NOT this node's real_id)
    // to the genuine party, and admits that party to the treaty.
    let foreign = endpoint_from_seed(200);
    assert_ne!(
        foreign, real_id,
        "the foreign endpoint must differ from this node's derived id"
    );
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, ["did:chio:party"])
        .with_endpoint(foreign, "did:chio:party");

    // Even claiming the genuine party's kernel id, the lane's DERIVED endpoint id
    // (real_id) is unbound in the directory, so the gate denies the join before
    // any dial: the lane used endpoint.id(), not a caller value.
    let result = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            "did:chio:party",
            &membership,
            vec![endpoint_from_seed(99)],
            Duration::from_millis(50),
        )
        .await;
    assert!(
            matches!(result, Err(FanoutError::TreatyMembershipDenied { .. })),
            "the lane derives its id from the spawned endpoint; an id it does not own is unbound and denied, got {result:?}"
        );

    // Control: bind THIS node's real (derived) endpoint id to the party, and the
    // same call passes the gate and reaches the (empty-bootstrap) join timeout,
    // proving the lane authenticates as endpoint.id().
    let membership_ok = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, ["did:chio:party"])
        .with_endpoint(real_id, "did:chio:party");
    let admitted = lane
        .subscribe_treaty_with_timeout(
            TREATY_ALPHA,
            "did:chio:party",
            &membership_ok,
            vec![],
            Duration::from_millis(50),
        )
        .await;
    assert!(
        matches!(admitted, Err(FanoutError::Gossip(ref msg)) if msg.contains("timed out")),
        "binding the DERIVED endpoint id admits the party past the gate, got {admitted:?}"
    );
    router.shutdown().await.ok();
}

#[test]
fn receive_rejects_a_resolver_key_that_lags_the_directory() {
    // Origin-key resolution is bound to the SAME verified directory
    // snapshot membership authorizes against. A caller resolver that still lists
    // a rotated-away key (disagreeing with the directory's CURRENT binding) is
    // refused BEFORE any signature work, so a stale key cannot launder a frame
    // (mirrors the bilateral co-signing stale-key refusal).
    let author = Keypair::from_seed(&[7; 32]); // the CURRENT directory key
    let stale = Keypair::from_seed(&[9; 32]); // a rotated-away key the resolver still lists
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    // Resolver LAGS: it binds the stale key.
    let keys = StaticOriginKeys::new().with(AUTHOR, stale.public_key());
    // Directory binds AUTHOR's CURRENT key and admits it as a party.
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, [AUTHOR])
        .with_origin_key(AUTHOR, author.public_key());

    let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
    assert!(
        matches!(
            result,
            Err(FanoutError::OriginKeyMismatch { ref origin_kernel_id })
                if origin_kernel_id == AUTHOR
        ),
        "a resolver key that lags the directory must be refused, got {result:?}"
    );
}

#[test]
fn receive_binds_origin_key_to_the_directory_even_with_an_empty_resolver() {
    // The directory-bound key is authoritative on its own: with an EMPTY resolver
    // (no mismatch to trip), the frame is verified against the directory key. A
    // frame signed by the CURRENT key is accepted; a frame signed by a
    // rotated-away key the directory no longer binds fails on signature - so an
    // OLD frame minted under a compromised/rotated key can never be replayed.
    let current = Keypair::from_seed(&[7; 32]);
    let rotated_away = Keypair::from_seed(&[9; 32]);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new(); // empty: forces reliance on the directory
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, [AUTHOR])
        .with_origin_key(AUTHOR, current.public_key());

    // A frame signed by the CURRENT directory key verifies against the binding.
    let ok_frame = signed_direct_frame(&current, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    verify_fanout_frame(&ok_frame, &keys, &membership, &policy, NOW)
        .expect("the current directory key is authoritative even with an empty resolver");

    // A frame signed by the ROTATED-AWAY key is rejected: verification uses the
    // directory's CURRENT key, so the old signature no longer matches.
    let stale_frame = signed_direct_frame(
        &rotated_away,
        AUTHOR,
        "did:chio:hub",
        TREATY_ALPHA,
        NAMESPACE,
    );
    let result = verify_fanout_frame(&stale_frame, &keys, &membership, &policy, NOW);
    assert!(
            matches!(result, Err(FanoutError::DepositSignatureInvalid)),
            "a frame signed by a rotated-away key must fail against the current directory key, got {result:?}"
        );
}

#[test]
fn receive_accepts_when_resolver_matches_the_directory() {
    // Control: when the resolver AGREES with the directory binding, resolution
    // succeeds and a valid frame verifies (no false-positive mismatch).
    let author = Keypair::from_seed(&[7; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, [AUTHOR])
        .with_origin_key(AUTHOR, author.public_key());
    verify_fanout_frame(&frame, &keys, &membership, &policy, NOW)
        .expect("a resolver key matching the directory binding verifies");
}

#[test]
fn origin_key_mismatch_bumps_verify_failure_counter_and_is_still_rejected() {
    // OBSERVE-ONLY proof: a lagging resolver key still fails closed AND bumps
    // verify_failures{fanout,origin-key-mismatch}; the returned Err is unchanged.
    let author = Keypair::from_seed(&[7; 32]);
    let stale = Keypair::from_seed(&[9; 32]);
    let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
    let policy = live_policy(NAMESPACE);
    let keys = StaticOriginKeys::new().with(AUTHOR, stale.public_key());
    let membership = StaticTreatyMembership::new()
        .with(TREATY_ALPHA, [AUTHOR])
        .with_origin_key(AUTHOR, author.public_key());

    let before =
        crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "origin-key-mismatch");
    let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
    assert!(matches!(result, Err(FanoutError::OriginKeyMismatch { .. })));
    assert!(
        crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "origin-key-mismatch")
            > before,
        "the origin-key mismatch must be counted (observe-only)"
    );
}
