#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::identity::transport_endorsement_preimage;
use crate::identity::TransportDirectoryBundleBody;
use crate::identity::TransportDirectoryBundleDocument;
use crate::identity::TransportDirectoryBundleTrust;
use crate::identity::TransportDirectoryDocument;
use crate::identity::TransportDirectoryEntry;
use crate::identity::TrustedTransportDirectoryIssuer;
use crate::identity::VerifiedDirectory;
use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_core_types::canonical_json_bytes;
use chio_core_types::receipt::body::prepare_receipt_body_for_signing;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::body::ChioReceiptBody;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::BoundaryClass;
use chio_core_types::receipt::kinds::ReceiptKind;
use chio_core_types::receipt::kinds::RedactionMode;
use chio_core_types::receipt::kinds::ToolOrigin;
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::metadata::ActorRef;
use chio_core_types::receipt::signing::ChioReceiptSigningBody;
use chio_core_types::sha256_hex;
use chio_federation::bilateral_dsse::build_predicate;
use chio_federation::bilateral_dsse::build_statement;
use chio_federation::bilateral_dsse::pae;
use chio_federation::bilateral_dsse::KernelIdentity;
use chio_federation::bilateral_dsse::Keyid;
use chio_federation::bilateral_dsse::PAYLOAD_TYPE_IN_TOTO;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::RelayMode;
use iroh::SecretKey;
use std::net::Ipv4Addr;

const NOW: u64 = 2_000_000;
const TOOL_HOST_KERNEL: &str = "did:chio:org-b";
const ORIGIN_KERNEL: &str = "did:chio:org-a";
const ISSUER: &str = "did:chio:issuer";
const KEY_ID: &str = "issuer-key-1";

/// A federation participant: an ed25519 transport identity plus a long-term
/// passport keypair (the co-signing key material).
struct Peer {
    kernel_id: String,
    transport_secret: SecretKey,
    transport_id: EndpointId,
    passport: Keypair,
}

impl Peer {
    fn new(kernel_id: &str, transport_seed: u8, passport_seed: u8) -> Self {
        let transport_secret = SecretKey::from_bytes(&[transport_seed; 32]);
        let transport_id = transport_secret.public();
        Self {
            kernel_id: kernel_id.to_string(),
            transport_secret,
            transport_id,
            passport: Keypair::from_seed(&[passport_seed; 32]),
        }
    }

    fn entry(&self) -> TransportDirectoryEntry {
        TransportDirectoryEntry {
            kernel_id: self.kernel_id.clone(),
            passport_public_key: self.passport.public_key(),
            transport_endpoint_id: self.transport_id,
            passport_endorsement: self.passport.sign(&transport_endorsement_preimage(
                &self.kernel_id,
                &self.transport_id,
            )),
            revocation_signers: Vec::new(),
            removed: false,
        }
    }
}

/// Build a load-time-verified directory admitting the given peers.
fn verified_directory(peers: &[&Peer]) -> Arc<VerifiedDirectory> {
    let issuer = Keypair::from_seed(&[240; 32]);
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: ORIGIN_KERNEL.to_string(),
        peers: peers.iter().map(|peer| peer.entry()).collect(),
        treaties: Vec::new(),
    };
    let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
    let body = TransportDirectoryBundleBody {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        issuer: ISSUER.to_string(),
        key_id: KEY_ID.to_string(),
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
            issuer: ISSUER.to_string(),
            key_id: KEY_ID.to_string(),
            public_key: issuer.public_key(),
        }],
        version_floor: 0,
        expected_previous_version_sha256: None,
        now_unix_ms: NOW,
    };
    Arc::new(bundle.verify_bundle(&trust).expect("bundle verifies"))
}

/// Spin up Org A: a loopback endpoint with the gate hook installed and the
/// bilateral handler mounted on a `Router`. Returns the endpoint address, the
/// live router (kept alive by the caller), and the gate.
async fn spawn_org_a(
    org_a: &Peer,
    gate: DirectoryGate,
    passport_keys: Arc<dyn PinnedPassportKeys>,
) -> (EndpointAddr, Router) {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_a.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .hooks(gate.clone())
        .bind()
        .await
        .expect("org a endpoint binds");

    let socket = endpoint.bound_sockets()[0];
    let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);

    let handler = BilateralCoSignHandler::new(
        gate,
        org_a.kernel_id.clone(),
        org_a.passport.clone(),
        passport_keys,
    );
    let router = Router::builder(endpoint)
        .accept(ALPN_BILATERAL, handler)
        .spawn();
    (addr, router)
}

/// Build Org B: a loopback client endpoint plus a co-signer that dials `addr`
/// for `org_a_kernel_id`.
async fn spawn_org_b(
    org_b: &Peer,
    org_a_kernel_id: &str,
    addr: EndpointAddr,
) -> IrohBilateralCoSigner {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_b.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("org b endpoint binds");
    let mut book: HashMap<String, EndpointAddr> = HashMap::new();
    book.insert(org_a_kernel_id.to_string(), addr);
    IrohBilateralCoSigner::new(endpoint, Arc::new(book))
}

/// Org B signs the PAE bytes with its passport key and assembles the request.
fn org_b_request(org_b: &Peer, org_a_kernel_id: &str, pae_bytes: &[u8]) -> DsseCoSigningRequest {
    let org_b_signature = org_b.passport.sign(pae_bytes);
    DsseCoSigningRequest::new(
        org_a_kernel_id.to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.to_vec(),
        org_b_signature,
    )
}

/// The DSSE pre-authentication encoding the producer path signs: the PAE of
/// the in-toto statement `sign_dsse_envelope_with_cosigner` builds for these
/// two kernels over a receipt the tool host signed. The accept side
/// reconstructs this statement before it will co-sign, so a legitimate
/// exchange carries one.
fn dsse_pae_preimage(org_a: &Peer, org_b: &Peer) -> Vec<u8> {
    let receipt = host_signed_receipt(&org_b.passport);
    let identity = |peer: &Peer| KernelIdentity {
        kernel_id: peer.kernel_id.clone(),
        passport_key_fingerprint: Keyid::from_public_key(&peer.passport.public_key()),
        alg: "ed25519".to_string(),
    };
    let predicate = build_predicate(
        &receipt,
        identity(org_a),
        identity(org_b),
        &receipt.tool_name,
        NOW,
    )
    .expect("bilateral predicate");
    let statement = build_statement(&receipt, predicate).expect("in-toto statement");
    pae(
        PAYLOAD_TYPE_IN_TOTO,
        &statement.canonical_bytes().expect("canonical statement"),
    )
}

fn pinned_org_b(org_b: &Peer) -> Arc<dyn PinnedPassportKeys> {
    let mut keys: HashMap<String, PublicKey> = HashMap::new();
    keys.insert(org_b.kernel_id.clone(), org_b.passport.public_key());
    Arc::new(keys)
}

#[tokio::test]
async fn full_cosign_succeeds_and_response_verifies_over_pae_bytes() {
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

    let response = cosigner
        .request_dsse_cosignature_over_iroh(&request)
        .await
        .expect("co-sign succeeds");

    assert_eq!(response.schema, BILATERAL_DSSE_COSIGNING_SCHEMA);
    // The contract: Org A's signature verifies over the exact pae_bytes
    // against Org A's pinned passport key.
    assert!(org_a
        .passport
        .public_key()
        .verify(&pae_bytes, &response.org_a_signature));
    // And it does NOT verify over different bytes (sanity).
    assert!(!org_a
        .passport
        .public_key()
        .verify(b"other bytes", &response.org_a_signature));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cosign_over_the_sync_protocol_trait_contract() {
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

    // Drive the SYNC BilateralCoSigningProtocol contract (block_in_place path).
    let cosigner_for_call = cosigner.clone();
    let request_for_call = request.clone();
    let response =
        tokio::task::spawn(
            async move { cosigner_for_call.request_dsse_cosignature(&request_for_call) },
        )
        .await
        .expect("join")
        .expect("trait co-sign succeeds");

    assert!(org_a
        .passport
        .public_key()
        .verify(&pae_bytes, &response.org_a_signature));
}

#[tokio::test(flavor = "current_thread")]
async fn sync_cosign_on_current_thread_runtime_fails_closed_without_panicking() {
    // On a CURRENT-THREAD tokio runtime `block_in_place` would panic. The sync
    // BilateralCoSigningProtocol entry point must instead fail closed with a
    // TransportFailure (mirrors the multi-thread sync-trait test, which
    // succeeds via `block_in_place`). No live server is needed: the
    // current-thread guard trips before any dial.
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_b.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("org b endpoint binds");
    // An empty address book is fine: the guard returns before resolving Org A.
    let book: HashMap<String, EndpointAddr> = HashMap::new();
    let cosigner = IrohBilateralCoSigner::new(endpoint, Arc::new(book));

    let pae_bytes = b"pae on a current-thread runtime".to_vec();
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

    // Must NOT panic; must return a typed TransportFailure fail-closed.
    let result = cosigner.request_dsse_cosignature(&request);
    assert!(
        matches!(result, Err(BilateralCoSigningError::TransportFailure(_))),
        "sync co-sign on a current-thread runtime must fail closed, got {result:?}"
    );
}

#[tokio::test]
async fn mismatched_org_b_kernel_id_is_rejected_without_signing() {
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    // Org B is admitted as `did:chio:org-b`, but CLAIMS to be someone else.
    let pae_bytes = b"pae for a spoofed org_b".to_vec();
    let org_b_signature = org_b.passport.sign(&pae_bytes);
    let request = DsseCoSigningRequest::new(
        ORIGIN_KERNEL.to_string(),
        "did:chio:evil-impersonator".to_string(),
        pae_bytes,
        org_b_signature,
    );

    let result = cosigner.request_dsse_cosignature_over_iroh(&request).await;
    assert_eq!(
        result,
        Err(BilateralCoSigningError::UnknownPeer(
            "did:chio:evil-impersonator".to_string()
        )),
        "the authenticated endpoint must match the claimed org_b_kernel_id"
    );
}

#[tokio::test]
async fn bad_org_b_signature_is_rejected_without_signing() {
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    // The signature is over DIFFERENT bytes than the pae_bytes carried, so the
    // server's verify(pae_bytes, org_b_signature) fails.
    let pae_bytes = b"the bytes org a is asked to co-sign".to_vec();
    let wrong_signature = org_b.passport.sign(b"a different message entirely");
    let request = DsseCoSigningRequest::new(
        ORIGIN_KERNEL.to_string(),
        org_b.kernel_id.clone(),
        pae_bytes,
        wrong_signature,
    );

    let result = cosigner.request_dsse_cosignature_over_iroh(&request).await;
    assert_eq!(
        result,
        Err(BilateralCoSigningError::OrgBSignatureInvalid),
        "a bad org_b signature must be refused without producing org_a's signature"
    );
}

#[tokio::test]
async fn unbound_endpoint_is_rejected_at_the_gate() {
    // The server's directory admits only org_a; the client (org_b) is NOT in
    // it, so the accept-time gate 403-rejects at handshake and no handler runs.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    let pae_bytes = b"pae from an unadmitted peer".to_vec();
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

    let result = cosigner.request_dsse_cosignature_over_iroh(&request).await;
    assert!(
        matches!(result, Err(BilateralCoSigningError::TransportFailure(_))),
        "an unadmitted endpoint is rejected by the gate; got {result:?}"
    );
}

#[test]
fn cosign_unit_rejects_wrong_origin_without_signing() {
    // Pure (no-network) proof of the fail-closed origin check: a request
    // addressed to a different Org A yields UnknownPeer and no signature.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let handler = BilateralCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        pinned_org_b(&org_b),
    );

    let pae_bytes = b"pae".to_vec();
    let request = DsseCoSigningRequest::new(
        "did:chio:some-other-origin".to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.clone(),
        org_b.passport.sign(&pae_bytes),
    );
    assert_eq!(
        handler.cosign(&org_b.transport_id, &request),
        Err(BilateralCoSigningError::UnknownPeer(
            "did:chio:some-other-origin".to_string()
        ))
    );
}

#[test]
fn wrong_origin_bumps_verify_failure_counter_and_is_still_rejected() {
    // OBSERVE-ONLY proof: a request addressed to a different Org A is refused
    // WITHOUT signing (byte-identical Err) AND bumps verify_failures{bilateral}.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let handler = BilateralCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        pinned_org_b(&org_b),
    );

    let pae_bytes = b"pae".to_vec();
    let request = DsseCoSigningRequest::new(
        "did:chio:some-other-origin".to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.clone(),
        org_b.passport.sign(&pae_bytes),
    );

    let before =
        crate::metrics::verify_failures_total(crate::metrics::SEAM_BILATERAL, "unknown-peer");
    let result = handler.cosign(&org_b.transport_id, &request);
    assert_eq!(
        result,
        Err(BilateralCoSigningError::UnknownPeer(
            "did:chio:some-other-origin".to_string()
        ))
    );
    assert!(
        crate::metrics::verify_failures_total(crate::metrics::SEAM_BILATERAL, "unknown-peer")
            > before,
        "the co-sign rejection must be counted (observe-only)"
    );
}

#[test]
fn cosign_unit_verifies_against_the_directory_bound_passport_key() {
    // The happy path of the directory-bound key: when the pinned map AGREES
    // with the verified directory's current binding for Org B, a request
    // signed with that key is co-signed. Pure (no network) proof that
    // verification now flows through the directory snapshot.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let handler = BilateralCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        pinned_org_b(&org_b),
    );

    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    let request = DsseCoSigningRequest::new(
        ORIGIN_KERNEL.to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.clone(),
        org_b.passport.sign(&pae_bytes),
    );
    let response = handler
        .cosign(&org_b.transport_id, &request)
        .expect("a request signed with the directory-bound passport co-signs");
    assert!(org_a
        .passport
        .public_key()
        .verify(&pae_bytes, &response.org_a_signature));
}

#[test]
fn cosign_unit_rejects_endpoint_absent_from_the_current_directory_snapshot() {
    // Single-snapshot verification. Endpoint authorization AND the passport-key
    // lookup are read from ONE `directory()` snapshot, so a directory
    // reload can never authorize the endpoint against one directory while reading the key
    // from another. This locks in that authorization is sourced from the CURRENT
    // directory snapshot: if that snapshot no longer binds the remote endpoint (rotated
    // away / removed), cosign fails closed even for an otherwise-valid, correctly-signed
    // request whose key is still pinned - the key is looked up from the SAME snapshot that
    // failed to authorize the endpoint, so a rotated-away peer can never co-sign.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    // The CURRENT directory admits only org_a; org_b's endpoint is NOT bound here.
    let gate = DirectoryGate::new(verified_directory(&[&org_a]));
    let handler = BilateralCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        // org_b's key is still pinned, so the rejection is due ONLY to the current
        // snapshot not authorizing the endpoint, not a pinned-map miss.
        pinned_org_b(&org_b),
    );
    let pae_bytes = b"pae from a rotated-away peer".to_vec();
    let request = DsseCoSigningRequest::new(
        ORIGIN_KERNEL.to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.clone(),
        org_b.passport.sign(&pae_bytes),
    );
    assert_eq!(
        handler.cosign(&org_b.transport_id, &request),
        Err(BilateralCoSigningError::UnknownPeer(
            org_b.kernel_id.clone()
        )),
        "a peer the current directory snapshot does not authorize cannot co-sign"
    );
}

#[test]
fn lagging_pinned_passport_key_is_rejected_without_signing() {
    // The DSSE-verification key must be bound to the same verified
    // directory the gate admitted on. If an out-of-band pinned map LAGS the
    // signed directory (pins a different passport key than the directory's
    // current binding for Org B), Org A must refuse to co-sign - otherwise an
    // authenticated peer could obtain a co-signature under a passport the
    // current directory no longer pins. Fail-closed, before signing.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    // The directory binds org_b's CURRENT passport (seed 2 via `Peer::new`).
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    // The pinned map lags: it still pins a STALE/rotated-away key (seed 99),
    // not the key the verified directory currently binds for org_b.
    let stale_passport = Keypair::from_seed(&[99u8; 32]);
    assert_ne!(stale_passport.public_key(), org_b.passport.public_key());
    let mut stale: HashMap<String, PublicKey> = HashMap::new();
    stale.insert(org_b.kernel_id.clone(), stale_passport.public_key());
    let handler =
        BilateralCoSignHandler::new(gate, ORIGIN_KERNEL, org_a.passport.clone(), Arc::new(stale));

    // Org B signs with its CURRENT (directory-bound) passport. Even a
    // perfectly valid signature is refused because the pinned map disagrees
    // with the signed directory: the lag is caught before any co-signature.
    let pae_bytes = b"pae under a lagging pinned map".to_vec();
    let request = DsseCoSigningRequest::new(
        ORIGIN_KERNEL.to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.clone(),
        org_b.passport.sign(&pae_bytes),
    );
    assert_eq!(
        handler.cosign(&org_b.transport_id, &request),
        Err(BilateralCoSigningError::OrgBSignatureInvalid),
        "a pinned passport key that lags the signed directory must be refused without signing"
    );
}

// -- Production-robustness: bounded accept over real loopback QUIC --
//
// These drive the REAL `BilateralCoSignHandler::accept` (through its bounded
// `serve` + concurrency cap) against deliberately misbehaving dialers. The
// bounds only limit WAITING; a slow/stalled/never-closing peer is dropped
// fail-closed, and a legitimate exchange within the bounds is still fully
// verified and co-signed (timeouts never weaken the trust path).

use std::time::Duration;

/// Spin up Org A exactly like [`spawn_org_a`] but with explicit accept bounds.
async fn spawn_org_a_with_limits(
    org_a: &Peer,
    gate: DirectoryGate,
    passport_keys: Arc<dyn PinnedPassportKeys>,
    limits: AcceptLimitConfig,
) -> (EndpointAddr, Router) {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_a.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .hooks(gate.clone())
        .bind()
        .await
        .expect("org a endpoint binds");
    let socket = endpoint.bound_sockets()[0];
    let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);
    let handler = BilateralCoSignHandler::new(
        gate,
        org_a.kernel_id.clone(),
        org_a.passport.clone(),
        passport_keys,
    )
    .with_accept_limits(limits);
    let router = Router::builder(endpoint)
        .accept(ALPN_BILATERAL, handler)
        .spawn();
    (addr, router)
}

/// A raw admitted dialer endpoint (for hand-driven, misbehaving clients).
async fn bind_peer(peer: &Peer) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(peer.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("peer endpoint binds")
}

/// Small per-phase bounds so an INFINITE stall trips promptly; the concurrency
/// cap stays at the generous default (not exercised by the slowloris tests).
fn stall_bounds() -> AcceptLimitConfig {
    AcceptLimitConfig {
        accept_stream_timeout: Duration::from_millis(300),
        read_timeout: Duration::from_millis(300),
        write_timeout: Duration::from_millis(300),
        linger_timeout: Duration::from_millis(300),
        ..AcceptLimitConfig::default()
    }
}

#[tokio::test]
async fn legit_cosign_within_tight_bounds_is_still_fully_verified_and_accepted() {
    // The CRITICAL trust-path test: with real (tight but sufficient) bounds
    // active, a valid request is still fully verified and co-signed, and the
    // response verifies over the exact pae_bytes. Timeouts bound waiting only.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let limits = AcceptLimitConfig {
        accept_stream_timeout: Duration::from_secs(4),
        read_timeout: Duration::from_secs(4),
        write_timeout: Duration::from_secs(4),
        linger_timeout: Duration::from_secs(4),
        ..AcceptLimitConfig::default()
    };

    let (addr, _router) = spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), limits).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

    let response = cosigner
        .request_dsse_cosignature_over_iroh(&request)
        .await
        .expect("a legitimate exchange within the bounds still co-signs");
    assert_eq!(response.schema, BILATERAL_DSSE_COSIGNING_SCHEMA);
    assert!(
        org_a
            .passport
            .public_key()
            .verify(&pae_bytes, &response.org_a_signature),
        "the co-signature verifies over the exact pae_bytes: verification was not weakened"
    );
}

#[tokio::test]
async fn peer_that_never_opens_a_stream_is_dropped_within_accept_bi_bound() {
    // An admitted peer connects (handshake completes, handler runs) but never
    // opens its bidi stream. The bounded accept_bi drops it fail-closed.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let (addr, _router) =
        spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), stall_bounds()).await;

    let dialer = bind_peer(&org_b).await;
    let conn = dialer
        .connect(addr, ALPN_BILATERAL)
        .await
        .expect("admitted dialer connects");
    // Never open_bi. The server must close within the accept_bi bound; give a
    // wide outer window so only a genuine hang (not scheduling jitter) fails.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "server must drop a peer that never opens a stream, not hang on accept_bi"
    );
}

#[tokio::test]
async fn slowloris_length_prefix_without_body_is_dropped_within_read_bound() {
    // THE key slowloris test: the peer opens its stream and sends a length
    // prefix declaring a body it never sends. The bounded frame read drops it
    // fail-closed rather than blocking the handler task on read_exact forever.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let (addr, _router) =
        spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), stall_bounds()).await;

    let dialer = bind_peer(&org_b).await;
    let conn = dialer
        .connect(addr, ALPN_BILATERAL)
        .await
        .expect("admitted dialer connects");
    let (mut send, _recv) = conn.open_bi().await.expect("dialer opens bi stream");
    // Declare a 4096-byte frame, then send NOTHING more and never finish.
    send.write_all(&4096u32.to_be_bytes())
        .await
        .expect("dialer writes only the length prefix");
    // Deliberately no body, no finish(): the classic slowloris dribble.

    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "server must drop a peer that sends a length prefix then withholds the body"
    );
}

#[tokio::test]
async fn peer_that_completes_exchange_but_never_closes_does_not_hang_past_linger() {
    // The peer runs a full, valid exchange (and gets a real co-signature) but
    // then never closes the connection. The bounded linger releases the
    // handler task instead of pinning it on conn.closed() forever.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let (addr, _router) =
        spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), stall_bounds()).await;

    let dialer = bind_peer(&org_b).await;
    let conn = dialer
        .connect(addr, ALPN_BILATERAL)
        .await
        .expect("admitted dialer connects");
    let (mut send, mut recv) = conn.open_bi().await.expect("dialer opens bi stream");

    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);
    let request_bytes =
        serde_json::to_vec(&WireDsseCoSigningRequest::from_request(&request)).unwrap();
    write_frame(&mut send, &request_bytes)
        .await
        .expect("write request frame");
    send.finish().expect("half-close the request stream");

    let reply_bytes = read_frame(&mut recv).await.expect("read the reply frame");
    let reply: WireReply = serde_json::from_slice(&reply_bytes).unwrap();
    let response = reply
        .into_result()
        .expect("the full exchange yields a real co-signature");
    assert!(
        org_a
            .passport
            .public_key()
            .verify(&pae_bytes, &response.org_a_signature),
        "the co-signature is valid: the exchange genuinely completed"
    );

    // Now hold the connection open (never close). The server must stop
    // lingering within its linger bound and drop the connection, which the
    // dialer observes as `closed()` resolving. A hang would time out here.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "server must not hang past the linger bound waiting for a peer that never closes"
    );
}

#[tokio::test]
async fn saturated_concurrency_cap_sheds_an_additional_dialer_over_quic() {
    // Cap = 1. Dialer A opens a stream and stalls the read, holding the sole
    // in-flight permit. While it is held, dialer C is shed after the bounded
    // wait: one peer cannot starve the lane, and back-pressure is bounded.
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let org_c = Peer::new("did:chio:org-c", 12, 3);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b, &org_c]));
    let limits = AcceptLimitConfig {
        max_in_flight: 1,
        accept_stream_timeout: Duration::from_secs(3),
        read_timeout: Duration::from_secs(3),
        shed_wait: Duration::from_millis(150),
        ..AcceptLimitConfig::default()
    };
    let (addr, _router) = spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), limits).await;

    // A holds the single permit by stalling in the bounded read.
    let dialer_a = bind_peer(&org_b).await;
    let conn_a = dialer_a
        .connect(addr.clone(), ALPN_BILATERAL)
        .await
        .expect("dialer A connects");
    let (mut send_a, _recv_a) = conn_a.open_bi().await.expect("A opens bi stream");
    send_a
        .write_all(&512u32.to_be_bytes())
        .await
        .expect("A sends a length prefix then stalls");
    // Let A's accept task acquire the sole permit and enter the bounded read.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // C dials for a full co-sign, but the cap is saturated: it is shed.
    let cosigner_c = spawn_org_b(&org_c, ORIGIN_KERNEL, addr).await;
    let request_c = org_b_request(&org_c, ORIGIN_KERNEL, b"pae from a shed dialer");
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        cosigner_c.request_dsse_cosignature_over_iroh(&request_c),
    )
    .await
    .expect("the shed dialer resolves quickly (bounded wait, not unbounded)");
    assert!(
        result.is_err(),
        "a dialer must be shed while the single in-flight permit is held, got {result:?}"
    );

    drop(conn_a);
}

// -- Client-side slowloris bound: a silent Org A must not hang the caller --
//
// An Org A that accepts the connection and reads the request but never returns
// the reply frame must not hang the dialer forever. This handler is that
// admitted-but-silent Org A.

#[derive(Debug, Clone)]
struct SilentAfterReadBilateralHandler;

impl ProtocolHandler for SilentAfterReadBilateralHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut _send, mut recv) = connection.accept_bi().await?;
        // Read the request frame, then deliberately never write the reply.
        let _request = read_frame(&mut recv).await.map_err(AcceptError::from_err)?;
        connection.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn client_read_bound_drops_an_org_a_that_never_replies() {
    // No admission gate installed: this isolates the CLIENT read bound (Org A
    // handshakes and reads the request, then goes silent).
    let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_a.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("org a endpoint binds");
    let socket = endpoint.bound_sockets()[0];
    let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);
    let router = Router::builder(endpoint)
        .accept(ALPN_BILATERAL, SilentAfterReadBilateralHandler)
        .spawn();

    // A tight read bound; connect/open/write keep their generous defaults so only
    // the (hung) reply read trips.
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr)
        .await
        .with_accept_limits(AcceptLimitConfig {
            read_timeout: Duration::from_millis(200),
            ..AcceptLimitConfig::default()
        });

    let pae_bytes = b"pae for a silent org a".to_vec();
    let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        cosigner.request_dsse_cosignature_over_iroh(&request),
    )
    .await
    .expect("the client read bound must fire well before the outer test timeout");
    assert!(
        matches!(result, Err(BilateralCoSigningError::TransportFailure(_))),
        "a silent org a must fail closed at the client read bound, got {result:?}"
    );

    router.shutdown().await.ok();
}

/// A receipt shaped like the one a receiver kernel signs before it asks the
/// origin to co-sign: the body the `CoSigningBody` preimage wraps.
fn host_signed_receipt(host: &Keypair) -> ChioReceipt {
    let arguments = serde_json::json!({ "record": "ledger-7" });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "invoke-receipt-cosign".to_string(),
            timestamp: NOW / 1_000,
            capability_id: "cap-receipt-cosign".to_string(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: ToolCallAction::from_parameters(arguments).expect("action"),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "agent:test/receipt-cosign".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: "4".repeat(64),
            policy_hash: "policy-receipt-cosign".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: host.public_key(),
            bbs_projection_version: None,
        },
        host,
    )
    .expect("receipt signs")
}

/// Stand up Org A with the RECEIPT co-sign handler mounted instead of the DSSE
/// one. Mirrors [`spawn_org_a`] so the two profiles differ only in the lane.
async fn spawn_org_a_receipt_profile(
    org_a: &Peer,
    gate: DirectoryGate,
    passport_keys: Arc<dyn PinnedPassportKeys>,
) -> (EndpointAddr, Router) {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_a.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind addr")
        .hooks(gate.clone())
        .bind()
        .await
        .expect("org a endpoint binds");

    let socket = endpoint.bound_sockets()[0];
    let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);

    let handler = BilateralReceiptCoSignHandler::new(
        gate,
        org_a.kernel_id.clone(),
        org_a.passport.clone(),
        passport_keys,
    );
    let router = Router::builder(endpoint)
        .accept(ALPN_BILATERAL_RECEIPT_COSIGN, handler)
        .spawn();
    (addr, router)
}

/// Org B signs the canonical co-signing body and assembles the request the
/// kernel's `co_sign_with_origin` would assemble.
fn org_b_receipt_request(org_b: &Peer, org_a_kernel_id: &str) -> CoSigningRequest {
    let receipt = host_signed_receipt(&org_b.passport);
    let body = CoSigningBody::from_receipt(&receipt, org_a_kernel_id, &org_b.kernel_id)
        .expect("co-signing body");
    let bytes = body.canonical_bytes().expect("canonical bytes");
    CoSigningRequest::new(
        receipt,
        org_a_kernel_id.to_string(),
        org_b.kernel_id.clone(),
        org_b.passport.sign(&bytes),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_cosign_completes_the_kernel_contract_over_the_lane() {
    let org_a = Peer::new(ORIGIN_KERNEL, 30, 3);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 31, 4);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a_receipt_profile(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;
    assert_eq!(cosigner.connections_opened(), 0);

    // The exact contract `ChioKernel::apply_federation_cosign` drives: Org B
    // signs its own receipt body, the origin co-signs the same bytes across the
    // network, and the assembled dual-signed receipt verifies under both keys.
    let receipt = host_signed_receipt(&org_b.passport);
    let dual = tokio::task::spawn_blocking({
        let cosigner = cosigner.clone();
        let org_a_public = org_a.passport.public_key();
        let org_b_passport = org_b.passport.clone();
        move || {
            chio_federation::bilateral::co_sign_with_origin(
                ORIGIN_KERNEL,
                &org_a_public,
                TOOL_HOST_KERNEL,
                &org_b_passport,
                receipt,
                &cosigner,
            )
        }
    })
    .await
    .expect("join")
    .expect("the kernel's co-sign hop completes over iroh");

    assert_eq!(dual.org_a_kernel_id, ORIGIN_KERNEL);
    assert_eq!(dual.org_b_kernel_id, TOOL_HOST_KERNEL);
    dual.verify(&org_a.passport.public_key(), &org_b.passport.public_key())
        .expect("the dual-signed receipt verifies under both passports");
    // One QUIC connection per receipt co-sign hop, counted at the co-signer:
    // the hop count an experiment reports is an observation, not an assumption.
    assert_eq!(cosigner.connections_opened(), 1);
}

#[tokio::test]
async fn receipt_cosign_refuses_a_tampered_org_b_signature_without_signing() {
    let org_a = Peer::new(ORIGIN_KERNEL, 32, 5);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 33, 6);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a_receipt_profile(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    // Org B signs bytes that are not the canonical body of the receipt it sends,
    // so the origin's re-verification over the transmitted bytes must fail.
    let mut request = org_b_receipt_request(&org_b, ORIGIN_KERNEL);
    request.org_b_signature = org_b.passport.sign(b"not the canonical co-signing body");

    let result = cosigner.request_cosignature_over_iroh(&request).await;
    assert_eq!(
        result.err(),
        Some(BilateralCoSigningError::OrgBSignatureInvalid),
        "a signature over other bytes must never obtain the origin's co-signature"
    );
}

#[tokio::test]
async fn receipt_cosign_rejects_an_org_b_that_claims_another_kernel_id() {
    let org_a = Peer::new(ORIGIN_KERNEL, 34, 7);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 35, 8);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a_receipt_profile(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    // Org B is admitted as `did:chio:org-b` but claims to be someone else; the
    // transport-origin binding refuses before any key lookup.
    let impersonated = "did:chio:evil-impersonator";
    let receipt = host_signed_receipt(&org_b.passport);
    let body = CoSigningBody::from_receipt(&receipt, ORIGIN_KERNEL, impersonated)
        .expect("co-signing body");
    let bytes = body.canonical_bytes().expect("canonical bytes");
    let request = CoSigningRequest::new(
        receipt,
        ORIGIN_KERNEL.to_string(),
        impersonated.to_string(),
        org_b.passport.sign(&bytes),
    );

    let result = cosigner.request_cosignature_over_iroh(&request).await;
    assert_eq!(
        result.err(),
        Some(BilateralCoSigningError::UnknownPeer(
            impersonated.to_string()
        ))
    );
}

#[tokio::test]
async fn receipt_cosign_fails_closed_on_a_schema_mismatch() {
    let org_a = Peer::new(ORIGIN_KERNEL, 36, 9);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 37, 10);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) =
        spawn_org_a_receipt_profile(&org_a, gate.clone(), pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

    // Client side: the DSSE schema tag never rides the receipt lane, and the
    // caller is refused before a connection is dialed.
    let mut request = org_b_receipt_request(&org_b, ORIGIN_KERNEL);
    request.schema = BILATERAL_DSSE_COSIGNING_SCHEMA.to_string();
    let result = cosigner.request_cosignature_over_iroh(&request).await;
    assert_eq!(
        result.err(),
        Some(BilateralCoSigningError::UnsupportedSchema(
            BILATERAL_DSSE_COSIGNING_SCHEMA.to_string()
        ))
    );

    // Accept side: a frame that reaches the handler under the wrong schema tag
    // is refused without signing, whatever the client did.
    let handler = BilateralReceiptCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        pinned_org_b(&org_b),
    );
    let wire = WireReceiptCoSigningRequest {
        schema: BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
        org_a_kernel_id: ORIGIN_KERNEL.to_string(),
        org_b_kernel_id: org_b.kernel_id.clone(),
        body_bytes: b"canonical co-signing body".to_vec(),
        org_b_signature: org_b.passport.sign(b"canonical co-signing body"),
    };
    assert_eq!(
        handler.cosign(&org_b.transport_id, &wire).err(),
        Some(BilateralCoSigningError::UnsupportedSchema(
            BILATERAL_DSSE_COSIGNING_SCHEMA.to_string()
        ))
    );
}

#[tokio::test]
async fn connection_counter_counts_each_dial_and_ignores_a_refusal() {
    let org_a = Peer::new(ORIGIN_KERNEL, 38, 11);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 39, 12);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;
    assert_eq!(cosigner.connections_opened(), 0);

    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    for expected in 1..=2 {
        cosigner
            .request_dsse_cosignature_over_iroh(&org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes))
            .await
            .expect("the dsse hop completes");
        assert_eq!(cosigner.connections_opened(), expected);
    }

    // Clones share the counter, so a kernel holding one handle and an observer
    // holding another read the same number of hops.
    assert_eq!(cosigner.clone().connections_opened(), 2);

    // A refusal that never reaches a dial is not a connection.
    let mut wrong_schema = org_b_receipt_request(&org_b, ORIGIN_KERNEL);
    wrong_schema.schema = BILATERAL_DSSE_COSIGNING_SCHEMA.to_string();
    assert!(cosigner
        .request_cosignature_over_iroh(&wrong_schema)
        .await
        .is_err());
    assert_eq!(cosigner.connections_opened(), 2);
}

#[tokio::test]
async fn hop_timers_split_the_handshake_from_the_exchange() {
    let org_a = Peer::new(ORIGIN_KERNEL, 40, 13);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 41, 14);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

    let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
    let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;
    assert_eq!(cosigner.connect_nanos(), 0);
    assert_eq!(cosigner.exchange_nanos(), 0);

    // Both halves are cumulative across hops and shared by every clone, which
    // is what lets a caller take a before/after difference around one
    // operation and read it as that operation's share.
    let pae_bytes = dsse_pae_preimage(&org_a, &org_b);
    let mut connect = 0_u64;
    let mut exchange = 0_u64;
    for hop in 1..=2_u64 {
        cosigner
            .request_dsse_cosignature_over_iroh(&org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes))
            .await
            .expect("the dsse hop completes");
        assert_eq!(cosigner.connections_opened(), hop);
        let next_connect = cosigner.clone().connect_nanos();
        let next_exchange = cosigner.clone().exchange_nanos();
        assert!(next_connect > connect, "hop {hop} dialed in no time at all");
        assert!(
            next_exchange > exchange,
            "hop {hop} exchanged in no time at all"
        );
        connect = next_connect;
        exchange = next_exchange;
    }

    // A refusal that never dials moves neither half.
    let mut wrong_schema = org_b_receipt_request(&org_b, ORIGIN_KERNEL);
    wrong_schema.schema = BILATERAL_DSSE_COSIGNING_SCHEMA.to_string();
    assert!(cosigner
        .request_cosignature_over_iroh(&wrong_schema)
        .await
        .is_err());
    assert_eq!(cosigner.connect_nanos(), connect);
    assert_eq!(cosigner.exchange_nanos(), exchange);
}

/// A receipt body attributed to `kernel_key`, prepared exactly as the
/// receipt signer prepares it, together with the canonical signing
/// preimage a kernel's receipt signature covers.
fn attributed_receipt_preimage(kernel_key: &PublicKey) -> (ChioReceiptBody, Vec<u8>) {
    let arguments = serde_json::json!({ "record": "ledger-forged" });
    let body = prepare_receipt_body_for_signing(ChioReceiptBody {
        id: "invoke-forged".to_string(),
        timestamp: NOW / 1_000,
        capability_id: "cap-forged".to_string(),
        tool_server: "vendor-ledger".to_string(),
        tool_name: "wire_transfer".to_string(),
        action: ToolCallAction::from_parameters(arguments).expect("action"),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![ActorRef {
            actor_id: "agent:test/forged".to_string(),
            actor_kind: Some("agent".to_string()),
        }],
        content_hash: "7".repeat(64),
        policy_hash: "policy-forged".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.clone(),
        bbs_projection_version: None,
    })
    .expect("body prepares for signing");
    let preimage =
        canonical_json_bytes(&ChioReceiptSigningBody::from(&body)).expect("signing preimage");
    (body, preimage)
}

/// Assemble the receipt a holder of a signature over
/// [`attributed_receipt_preimage`]'s preimage can publish.
fn receipt_from_signature(body: ChioReceiptBody, signature: Signature) -> ChioReceipt {
    ChioReceipt {
        id: body.id,
        timestamp: body.timestamp,
        capability_id: body.capability_id,
        tool_server: body.tool_server,
        tool_name: body.tool_name,
        action: body.action,
        decision: body.decision,
        receipt_kind: body.receipt_kind,
        boundary_class: body.boundary_class,
        observation_outcome: body.observation_outcome,
        tool_origin: body.tool_origin,
        redaction_mode: body.redaction_mode,
        actor_chain: body.actor_chain,
        content_hash: body.content_hash,
        policy_hash: body.policy_hash,
        evidence: body.evidence,
        metadata: body.metadata,
        trust_level: body.trust_level,
        tenant_id: body.tenant_id,
        bbs_projection_version: body.bbs_projection_version,
        kernel_key: body.kernel_key,
        bbs_signature: None,
        algorithm: None,
        signature,
    }
}

#[test]
fn receipt_cosign_refuses_a_receipt_signing_preimage() {
    let org_a = Peer::new(ORIGIN_KERNEL, 46, 21);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 47, 22);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let handler = BilateralReceiptCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        pinned_org_b(&org_b),
    );

    // A receipt the peer invented, attributed to the co-signing kernel.
    let (body, preimage) = attributed_receipt_preimage(&org_a.passport.public_key());

    // These bytes are a live forgery vector: the co-signing kernel's own
    // signature over them is a receipt that passes ordinary receipt
    // verification while naming that kernel as its signer.
    let harvested = Ed25519Backend::new(org_a.passport.clone())
        .sign_bytes(&preimage)
        .expect("origin signs");
    let forged = receipt_from_signature(body, harvested);
    assert!(
        forged.verify_signature().expect("verification runs"),
        "the preimage must be a real receipt preimage for this proof to mean anything"
    );

    // The peer is pinned, directory-bound, and signs the exact bytes it
    // sends, so every admission check passes: only the preimage discipline
    // stands between it and the signature above.
    let request = WireReceiptCoSigningRequest {
        schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
        org_a_kernel_id: ORIGIN_KERNEL.to_string(),
        org_b_kernel_id: org_b.kernel_id.clone(),
        body_bytes: preimage.clone(),
        org_b_signature: org_b.passport.sign(&preimage),
    };
    let refusal = handler.cosign(&org_b.transport_id, &request).err();
    assert!(
        matches!(refusal, Some(BilateralCoSigningError::CanonicalJson(_))),
        "a receipt signing preimage is not a co-signing body and must never be \
         signed, got {refusal:?}"
    );
}

#[test]
fn dsse_cosign_refuses_a_receipt_signing_preimage() {
    let org_a = Peer::new(ORIGIN_KERNEL, 48, 23);
    let org_b = Peer::new(TOOL_HOST_KERNEL, 49, 24);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
    let handler = BilateralCoSignHandler::new(
        gate,
        ORIGIN_KERNEL,
        org_a.passport.clone(),
        pinned_org_b(&org_b),
    );

    let (body, preimage) = attributed_receipt_preimage(&org_a.passport.public_key());
    let harvested = Ed25519Backend::new(org_a.passport.clone())
        .sign_bytes(&preimage)
        .expect("origin signs");
    assert!(
        receipt_from_signature(body, harvested)
            .verify_signature()
            .expect("verification runs"),
        "the preimage must be a real receipt preimage for this proof to mean anything"
    );

    let request = org_b_request(&org_b, ORIGIN_KERNEL, &preimage);
    let refusal = handler.cosign(&org_b.transport_id, &request).err();
    assert!(
        matches!(refusal, Some(BilateralCoSigningError::CanonicalJson(_))),
        "a receipt signing preimage is not a DSSE pre-authentication encoding and \
         must never be signed, got {refusal:?}"
    );
}
