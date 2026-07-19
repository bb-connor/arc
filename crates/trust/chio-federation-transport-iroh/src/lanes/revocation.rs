//! Lane b: revocation epoch roots over a direct per-peer QUIC stream.
//! ADAPTER-SPEC section 4 row (b) + IROH-LANES-BLUEPRINT "LANE B".
//!
//! This lane carries two message kinds over one direct, admission-gated,
//! per-peer QUIC stream (`open_bi` / `accept_bi`):
//!
//! - a pushed [`RevocationGossipBatch`] of signed epoch roots, and
//! - a [`RevocationCatchupRequest`] whose [`RevocationCatchupResponse`] rides the
//!   same stream (the CONTROL envelope for the catch-up lane; the bulk root bytes
//!   ride iroh-blobs in [`crate::catchup`], ADAPTER-SPEC 4 lane e).
//!
//! ## Authenticity model (different from lane a)
//!
//! Revocation has NO `authenticated_sender_kernel_id` seam. The receiver verifies
//! each [`chio_revocation_oracle::SignedEpochRoot`] against a PINNED signer key it
//! already holds (revocation carries no directory in its wire types). The
//! transport contributes origin + ordering + reliability only (ADAPTER-SPEC 4
//! row b; blueprint B.3).
//!
//! ## The net-new binding this lane introduces
//!
//! Revocation wire types carry only an opaque `signer_id`
//! ([`revocation_gossip.rs:65`](chio_federation::revocation_gossip)); there is no
//! endpoint or public key on the wire. So this lane needs a
//! [`VerifiedSignerDirectory`] mapping `signer_id -> (EndpointId, verifying-key)`.
//! In production that directory is a DERIVED PROJECTION of the one issuer-signed
//! [`VerifiedDirectory`]: each [`crate::identity::RevocationSignerEntry`] binds
//! `signer_id -> oracle_public_key` to an operator via a domain-separated passport
//! endorsement, and the transport `EndpointId` that may originate the signer's
//! roots IS that operator's `transport_endpoint_id`. So the origin pin is
//! STRUCTURAL: signer and endpoint come from one issuer-signed entry, inheriting
//! the body-hash pin, issuer signature, validity window, and rollback machinery.
//!
//! At accept time the handler (1) REJECTS at the admission gate any transport
//! `EndpointId` not bound to an admitted kernel (defense in depth), (2) asserts
//! each frame's `signer_id` is pinned to the SAME authenticated `EndpointId`
//! (transport origin pin, now structurally guaranteed by the derived directory),
//! and (3) signature-verifies the [`SignedEpochRoot`] against the bound verifying
//! key (authenticity). All three are mandatory and independent (ADAPTER-SPEC 5
//! "feeds the verifier, not replaces it"; blueprint B.4).

use std::collections::HashMap;
use std::sync::Arc;

use chio_federation::revocation_gossip::respond_to_catchup;
use chio_federation::revocation_gossip::RevocationCatchupHistory;
use chio_federation::revocation_gossip::RevocationCatchupRequest;
use chio_federation::revocation_gossip::RevocationCatchupResponse;
use chio_federation::revocation_gossip::RevocationGossipBatch;
use chio_federation::revocation_gossip::RevocationGossipError;
use chio_revocation_oracle::Ed25519RootVerifier;
use chio_revocation_oracle::EpochRootVerifier;
use chio_revocation_oracle::SignedEpochRoot;
use iroh::endpoint::Connection;
use iroh::endpoint::RecvStream;
use iroh::endpoint::SendStream;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use serde::Deserialize;
use serde::Serialize;

use crate::catchup::build_catchup_manifest;
use crate::catchup::publish_and_build_catchup_manifest;
use crate::catchup::CatchupError;
use crate::catchup::RevocationCatchupManifest;
use crate::catchup::RevocationRootPublisher;
use crate::identity::VerifiedDirectory;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptLimitError;
use crate::lanes::limits::AcceptLimiter;
use crate::lanes::limits::AcceptPhase;
use crate::lanes::limits::LANE_RESET_CLOSE_CODE;

/// ALPN for the revocation-root lane. Distinct, versioned, mounted on its own
/// `Router` accept (blueprint B.2).
pub const ALPN_REVOCATION_ROOT: &[u8] = b"chio/federation/revocation-root/1";

/// Hard cap on a single length-delimited lane frame. Revocation batches and
/// catch-up responses are small (bounded by
/// [`chio_federation::revocation_gossip::REVOCATION_CATCHUP_MAX_EPOCHS`]); this
/// bounds a hostile peer's per-message allocation fail-closed.
pub const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;

/// QUIC application close code the CLIENT sends once it has read a clean reply, so
/// the accept side's bounded linger (which waits for the dialer to close) resolves
/// promptly and its accept slot is released instead of being pinned until the idle
/// timeout. Mirrors the pheromone (`LANE_OK_CODE`) and bilateral (`CLOSE_OK`)
/// clients, which likewise close after reading; `0` matches this lane's own
/// loopback test helper. Distinct from [`LANE_RESET_CLOSE_CODE`] (a fail-closed
/// reset) so a clean client close is diagnosable on the wire.
const LANE_OK_CLOSE_CODE: u32 = 0;

/// A single pinned signer binding: an opaque `signer_id` cross-linked to the
/// transport `EndpointId` that is allowed to originate its roots AND to the
/// pinned verifying key that authenticates those roots.
///
/// The verifier already carries the `signer_id` and the public key; the
/// `endpoint` is the transport-origin pin the wire types lack.
#[derive(Debug, Clone)]
pub struct SignerBinding {
    /// Transport `EndpointId` allowed to originate this signer's roots.
    pub endpoint: EndpointId,
    /// Pinned verify-only counterpart of the signer's oracle key. Holds no
    /// private material, so it can never forge a root.
    pub verifier: Ed25519RootVerifier,
}

/// The `signer_id -> (EndpointId, verifying-key)` directory this lane requires
/// (blueprint B.4), keyed on the opaque revocation `signer_id` since revocation
/// wire types carry no endpoint or public key.
///
/// In production this is a DERIVED PROJECTION of the issuer-signed
/// [`VerifiedDirectory`], built by
/// [`TransportDirectoryBundleDocument::verify_bundle`](crate::identity::TransportDirectoryBundleDocument::verify_bundle)
/// and read back via
/// [`VerifiedDirectory::signer_directory`](crate::identity::VerifiedDirectory::signer_directory).
/// The duplicate-`signer_id` and `signer_id`-vs-key consistency rules are enforced
/// during bundle verification (consistent by construction, since the verifier is
/// built from the same `signer_id`). The `from_bindings` constructor is
/// crate-internal (test / explicit construction only) and re-checks both rules
/// fail-closed; production directories come solely from `verify_bundle`.
#[derive(Debug, Clone, Default)]
pub struct VerifiedSignerDirectory {
    by_signer: HashMap<String, SignerBinding>,
}

impl VerifiedSignerDirectory {
    /// Build a pinned signer directory from `(signer_id, binding)` pairs.
    ///
    /// Rejects a duplicate `signer_id` fail-closed and rejects a binding whose
    /// pinned verifier `signer_id` disagrees with its map key (the two identify
    /// the same signer and must not drift).
    // Retained as a crate-internal explicit/test constructor (used by the unit
    // tests below). Production directories come solely from `verify_bundle` via
    // `from_verified_map`, so this has no non-test caller: allow dead_code rather
    // than expose it publicly again.
    #[allow(dead_code)]
    pub(crate) fn from_bindings(
        bindings: impl IntoIterator<Item = (String, SignerBinding)>,
    ) -> Result<Self, RevocationLaneError> {
        let mut by_signer: HashMap<String, SignerBinding> = HashMap::new();
        for (signer_id, binding) in bindings {
            if binding.verifier.signer_id() != signer_id {
                return Err(RevocationLaneError::SignerIdMismatch {
                    key: signer_id,
                    pinned: binding.verifier.signer_id().to_string(),
                });
            }
            if by_signer.insert(signer_id.clone(), binding).is_some() {
                return Err(RevocationLaneError::DuplicateSigner(signer_id));
            }
        }
        Ok(Self { by_signer })
    }

    /// Wrap an already-validated `signer_id -> binding` map produced by the
    /// issuer-signed directory verifier (`verify_bundle`), where duplicate
    /// detection and `signer_id`-vs-key consistency are enforced during bundle
    /// verification. This is the production constructor; the map's provenance is
    /// the one issuer-signed transport directory.
    pub(crate) fn from_verified_map(by_signer: HashMap<String, SignerBinding>) -> Self {
        Self { by_signer }
    }

    /// Resolve an opaque `signer_id` to its pinned binding, or `None`
    /// (fail-closed) when the signer is not pinned.
    #[must_use]
    pub fn resolve(&self, signer_id: &str) -> Option<&SignerBinding> {
        self.by_signer.get(signer_id)
    }

    /// Number of pinned signer bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_signer.len()
    }

    /// Whether no signer is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_signer.is_empty()
    }
}

/// Errors surfaced by the revocation lane. Every variant is fail-closed: the
/// receiver merges nothing and either resets the stream or writes back a typed
/// [`RevocationLaneResponse::Rejected`] (blueprint B.7).
#[derive(Debug, thiserror::Error)]
pub enum RevocationLaneError {
    /// A structural / ordering error from the `chio-federation` envelope layer.
    #[error("revocation gossip error: {0}")]
    Gossip(#[from] RevocationGossipError),
    /// The authenticated transport `EndpointId` resolves to no admitted kernel.
    /// Should be unreachable past the admission gate; treated as a hard reset.
    #[error("unbound transport endpoint reached revocation handler")]
    UnboundEndpoint,
    /// A frame's `signer_id` is not present in the pinned signer directory.
    #[error("no pinned signer binding for signer_id `{0}`")]
    UnknownSigner(String),
    /// A frame's `signer_id` is pinned, but to a DIFFERENT transport endpoint
    /// than the one that authenticated this connection (origin-pin violation).
    #[error("signer `{signer_id}` is not pinned to transport endpoint {endpoint}")]
    SignerEndpointMismatch {
        /// The opaque signer identity carried by the frame.
        signer_id: String,
        /// The authenticated transport endpoint (short form) that presented it.
        endpoint: String,
    },
    /// A catch-up request's claimed `requester_kernel_id` is not the kernel
    /// admitted at the authenticated transport `EndpointId`. Binding the claimed
    /// requester to the connection endpoint closes a requester-spoofing gap.
    /// Fail-closed: nothing is served.
    #[error("catch-up requester `{claimed}` is not admitted at transport endpoint {endpoint}")]
    RequesterMismatch {
        /// The authenticated transport endpoint (short form) that presented it.
        endpoint: String,
        /// The `requester_kernel_id` claimed by the catch-up request.
        claimed: String,
    },
    /// A Push batch named a `recipient_kernel_id` other than this responder's
    /// kernel. Fail-closed: the batch is addressed to a DIFFERENT kernel, so
    /// NOTHING is merged (a misrouted or cross-recipient-replayed batch cannot
    /// mutate this responder's revocation cache).
    #[error("push batch addressed to `{claimed}` but this responder is `{expected}`")]
    RecipientMismatch {
        /// This responder's kernel id (the only recipient it will merge for).
        expected: String,
        /// The `recipient_kernel_id` the batch claimed.
        claimed: String,
    },
    /// The pinned-signer signature check over a [`SignedEpochRoot`] failed
    /// (BLAKE3/transport integrity is NOT authenticity, ADAPTER-SPEC 2.2).
    #[error("epoch root signature failed pinned-signer verification (signer_id `{0}`)")]
    BadSignature(String),
    /// A pinned binding's verifier `signer_id` disagrees with its directory key.
    #[error("pinned signer key `{key}` disagrees with verifier signer_id `{pinned}`")]
    SignerIdMismatch {
        /// The directory map key.
        key: String,
        /// The `signer_id` carried by the pinned verifier.
        pinned: String,
    },
    /// The same `signer_id` was pinned more than once.
    #[error("duplicate signer binding for signer_id `{0}`")]
    DuplicateSigner(String),
    /// The caller's revocation-root sink rejected a verified root.
    #[error("revocation sink rejected merge: {0}")]
    SinkRejected(String),
    /// A JSON (de)serialization failure on the wire.
    #[error("wire codec error: {0}")]
    Codec(String),
    /// A QUIC stream read/write/finish failure.
    #[error("transport error: {0}")]
    Transport(String),
    /// A peer-dependent accept step exceeded its bound (slowloris) or the
    /// in-flight cap shed the connection. Fail-closed: the connection is reset
    /// and NOTHING is merged or served.
    #[error(transparent)]
    AcceptLimit(#[from] AcceptLimitError),
}

/// Caller-provided sink for verified epoch roots (blueprint B.6
/// `RevocationRootSink`). Called only AFTER a root has passed pinned-signer
/// verification and the transport-origin pin. The merge is all-or-nothing at the
/// batch level: a batch with any unverifiable frame merges nothing.
pub trait RevocationRootSink: std::fmt::Debug + Send + Sync {
    /// Merge one verified signed root into the caller's `RevocationView` cache.
    /// Fail-closed: an `Err` aborts the batch.
    fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError>;

    /// Atomically merge a batch of verified roots. Fail-closed and
    /// all-or-nothing: if ANY root fails, the sink MUST be left exactly as it was
    /// before the call (no partial application). The lane calls THIS method (never
    /// `merge_root` directly), so the all-or-nothing batch contract is honored end
    /// to end.
    ///
    /// # Fail-closed default (no partial cache advance)
    ///
    /// The default here deliberately does NOT loop [`merge_root`]. A per-root loop
    /// would leave earlier roots applied when a later root fails, advancing the
    /// revocation cache partially while [`RevocationHandler::handle_request`]
    /// reports the whole batch rejected - the exact all-or-nothing violation this
    /// contract forbids. A generic default cannot roll back an arbitrary sink, so
    /// instead of risking a silent partial apply it FAILS CLOSED: it merges nothing
    /// and returns [`RevocationLaneError::SinkRejected`]. Every sink therefore MUST
    /// provide its own atomic `merge_batch` that stages all roots and commits only
    /// after every root is accepted (see the `AtomicRecordingSink` test for the
    /// stage-then-commit shape); a sink that forgets the override gets a loud, total
    /// rejection rather than a corrupting partial advance. Verification (signature +
    /// origin pin) already ran on every root in [`RevocationHandler::verify_batch`]
    /// before this is ever called.
    fn merge_batch(&self, _roots: &[SignedEpochRoot]) -> Result<(), RevocationLaneError> {
        Err(RevocationLaneError::SinkRejected(
            "RevocationRootSink::merge_batch has no safe generic default: a sink MUST \
             implement an atomic (stage-then-commit) batch merge so a mid-batch failure \
             advances the revocation cache by nothing (all-or-nothing). The fail-closed \
             default merged nothing."
                .to_string(),
        ))
    }
}

/// One lane request. Externally tagged so the inner `deny_unknown_fields`
/// contract types keep their own object shape (an internally-tagged enum would
/// inject the discriminant key into the batch object and break the contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RevocationLaneRequest {
    /// A pushed batch of signed roots (per-peer FIFO drain).
    Push(RevocationGossipBatch),
    /// A catch-up gap-fill request; its response inlines full signed-root frames
    /// over this same stream (best for small ranges).
    Catchup(RevocationCatchupRequest),
    /// A catch-up request that asks for a blob MANIFEST instead of inline frames,
    /// so a large history can ride iroh-blobs (lane e) rather than overrunning the
    /// bounded lane-b response. Same range + requester-authentication as `Catchup`.
    CatchupManifest(RevocationCatchupRequest),
}

/// One lane response, correlated to the request by stream identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RevocationLaneResponse {
    /// A push batch verified and merged; carries the merged epochs for audit.
    PushAccepted {
        /// The epochs merged into the receiver cache, in wire order.
        merged_epochs: Vec<u64>,
    },
    /// A catch-up response (may be a partial suffix; see `validate_response`).
    Catchup(RevocationCatchupResponse),
    /// A blob catch-up MANIFEST: the `(epoch -> content-address)` list a follower
    /// feeds to `BlobCatchupClient::fetch_range` to pull the history over blobs.
    CatchupManifest(RevocationCatchupManifest),
    /// A typed rejection. Fail-closed: NOTHING was merged and no root was served.
    Rejected {
        /// Stable machine code for the deny reason.
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

impl RevocationLaneError {
    /// Stable machine code for a typed [`RevocationLaneResponse::Rejected`].
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            RevocationLaneError::Gossip(inner) => match inner {
                RevocationGossipError::UnsupportedSchema(_) => "unsupported-schema",
                RevocationGossipError::EpochMismatch { .. } => "epoch-mismatch",
                RevocationGossipError::SignerIdMismatch { .. } => "signer-id-mismatch",
                RevocationGossipError::UnknownPeer(_) => "unknown-peer",
                RevocationGossipError::InvalidConfiguration(_) => "invalid-configuration",
                RevocationGossipError::QueuePoisoned => "queue-poisoned",
                RevocationGossipError::CatchupRangeInverted { .. } => "catchup-range-inverted",
                RevocationGossipError::CatchupRangeTooWide { .. } => "catchup-range-too-wide",
                RevocationGossipError::CatchupGap { .. } => "catchup-gap",
            },
            RevocationLaneError::UnboundEndpoint => "unbound-endpoint",
            RevocationLaneError::UnknownSigner(_) => "unknown-signer",
            RevocationLaneError::SignerEndpointMismatch { .. } => "signer-endpoint-mismatch",
            RevocationLaneError::RequesterMismatch { .. } => "requester-mismatch",
            RevocationLaneError::RecipientMismatch { .. } => "recipient-mismatch",
            RevocationLaneError::BadSignature(_) => "bad-signature",
            RevocationLaneError::SignerIdMismatch { .. } => "signer-id-mismatch",
            RevocationLaneError::DuplicateSigner(_) => "duplicate-signer",
            RevocationLaneError::SinkRejected(_) => "sink-rejected",
            RevocationLaneError::Codec(_) => "codec",
            RevocationLaneError::Transport(_) => "transport",
            RevocationLaneError::AcceptLimit(error) => error.code(),
        }
    }

    /// QUIC application close code for a fail-closed reset. Accept-limit outcomes
    /// (slowloris timeout / saturation shed) carry their own distinct codes; every
    /// other lane error is a generic reset.
    fn close_code(&self) -> u32 {
        match self {
            RevocationLaneError::AcceptLimit(error) => error.close_code(),
            _ => LANE_RESET_CLOSE_CODE,
        }
    }

    fn as_rejected(&self) -> RevocationLaneResponse {
        RevocationLaneResponse::Rejected {
            code: self.code().to_string(),
            message: self.to_string(),
        }
    }

    /// Map a [`CatchupError`] from the manifest builder onto a lane error: a range /
    /// gap ordering fault surfaces as [`RevocationLaneError::Gossip`] (so its stable
    /// `code()` matches the inline catch-up path), everything else as
    /// [`RevocationLaneError::Codec`]. Fail-closed either way (the manifest is not
    /// served on error).
    fn from_catchup(error: CatchupError) -> Self {
        match error {
            CatchupError::Ordering(inner) => RevocationLaneError::Gossip(inner),
            other => RevocationLaneError::Codec(other.to_string()),
        }
    }
}

/// The revocation-root [`ProtocolHandler`]. Mount on
/// `Router::builder(ep).accept(ALPN_REVOCATION_ROOT, handler)`.
#[derive(Clone)]
pub struct RevocationHandler {
    /// The one issuer-signed directory. It resolves the admission re-check
    /// (`EndpointId -> kernel_id`, defense in depth above the accept-time gate)
    /// AND carries the derived `signer_id -> (EndpointId, verifying-key)` pinning,
    /// so both originate from the same issuer-signed material.
    directory: Arc<VerifiedDirectory>,
    /// Catch-up history the responder serves via `respond_to_catchup`.
    history: Arc<dyn RevocationCatchupHistory + Send + Sync>,
    /// Caller cache updater for verified push roots.
    sink: Arc<dyn RevocationRootSink>,
    /// This responder's kernel id, echoed into catch-up responses.
    responder_kernel_id: String,
    /// Optional AUTHORITY-side blob publisher backed by the SAME [`FsStore`](iroh_blobs::store::fs::FsStore)
    /// the authority serves over
    /// [`BlobsProtocol`](iroh_blobs::BlobsProtocol). When present, a
    /// [`CatchupManifest`](RevocationLaneRequest::CatchupManifest) request PUBLISHES
    /// every advertised root into that store before advertising its hash, so every
    /// advertised hash is fetchable (blob catch-up, lane e). When absent, the manifest
    /// path FAILS CLOSED and falls back to inline catch-up rather than advertise a hash
    /// the authority may not have stored. Wire it via
    /// [`with_blob_publisher`](Self::with_blob_publisher).
    blob_publisher: Option<RevocationRootPublisher>,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
}

impl std::fmt::Debug for RevocationHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationHandler")
            .field("responder_kernel_id", &self.responder_kernel_id)
            .field("directory_version", &self.directory.version())
            .field("pinned_signers", &self.directory.signer_directory().len())
            .field("blob_publisher", &self.blob_publisher.is_some())
            .finish_non_exhaustive()
    }
}

/// Adapts an `Arc<dyn RevocationCatchupHistory>` to the sized `H:
/// RevocationCatchupHistory` bound `respond_to_catchup` requires.
struct DynHistory(Arc<dyn RevocationCatchupHistory + Send + Sync>);

impl RevocationCatchupHistory for DynHistory {
    fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
        self.0.signed_root_at(epoch)
    }
}

impl RevocationHandler {
    /// Build a revocation-root handler. The signer pinning is DERIVED from the
    /// issuer-signed `directory` ([`VerifiedDirectory::signer_directory`]), so the
    /// handler can never be fed a signer map that disagrees with the admitted
    /// endpoints: the transport-origin pin is structural, not conventional.
    #[must_use]
    pub fn new(
        directory: Arc<VerifiedDirectory>,
        history: Arc<dyn RevocationCatchupHistory + Send + Sync>,
        sink: Arc<dyn RevocationRootSink>,
        responder_kernel_id: impl Into<String>,
    ) -> Self {
        Self {
            directory,
            history,
            sink,
            responder_kernel_id: responder_kernel_id.into(),
            blob_publisher: None,
            limiter: AcceptLimiter::default(),
        }
    }

    /// Override the default accept-hardening bounds (per-phase timeouts + the
    /// in-flight concurrency cap). The [`Default`] preserves the historical
    /// (generous) behavior; the wiring can tune it in one place.
    #[must_use]
    pub fn with_accept_limits(mut self, config: AcceptLimitConfig) -> Self {
        self.limiter = AcceptLimiter::new(config);
        self
    }

    /// Wire an AUTHORITY-side blob publisher so the blob-manifest catch-up path
    /// (lane e) actually serves fetchable hashes. The `publisher` MUST wrap the SAME
    /// [`FsStore`](iroh_blobs::store::fs::FsStore) the authority mounts as its
    /// [`BlobsProtocol`](iroh_blobs::BlobsProtocol) (build it with
    /// [`BlobCatchupClient::publisher`](crate::catchup::BlobCatchupClient::publisher)).
    ///
    /// With a publisher, a
    /// [`CatchupManifest`](RevocationLaneRequest::CatchupManifest) request PUBLISHES
    /// every advertised root into that store before putting its hash in the manifest,
    /// so a follower can fetch every advertised hash. WITHOUT a publisher the handler
    /// cannot confirm the advertised blobs are stored, so it fails closed: it never
    /// advertises a blob manifest and instead falls back to inline catch-up on the same
    /// request. This is the seam that keeps the manifest path from advertising a hash
    /// the authority cannot serve.
    #[must_use]
    pub fn with_blob_publisher(mut self, publisher: RevocationRootPublisher) -> Self {
        self.blob_publisher = Some(publisher);
        self
    }

    /// Verify EVERY frame of a pushed batch against the pinned signer directory
    /// and the transport-origin pin, returning the verified roots WITHOUT
    /// merging. All-or-nothing: any unverifiable frame fails the whole batch so
    /// the cache/history is left untouched (blueprint B.5).
    ///
    /// `endpoint` is the authenticated transport `EndpointId` of the connection
    /// carrying the batch.
    pub fn verify_batch(
        &self,
        endpoint: EndpointId,
        batch: &RevocationGossipBatch,
    ) -> Result<Vec<SignedEpochRoot>, RevocationLaneError> {
        // Defense in depth: the admission gate already rejected unbound
        // endpoints before any accept ran. Re-resolve fail-closed anyway.
        if self.directory.authorize(&endpoint).is_none() {
            return Err(RevocationLaneError::UnboundEndpoint);
        }
        // Cheap structural gate: schema + per-frame envelope consistency.
        batch.validate_envelope()?;

        // Address pin: a bilateral Push batch MUST name THIS responder as its
        // recipient. A batch addressed to a DIFFERENT kernel (misrouted, or replayed
        // cross-recipient) is rejected fail-closed BEFORE any root is merged, mirroring
        // the pheromone verifier's recipient check and the catch-up requester pin.
        if batch.recipient_kernel_id != self.responder_kernel_id {
            return Err(RevocationLaneError::RecipientMismatch {
                expected: self.responder_kernel_id.clone(),
                claimed: batch.recipient_kernel_id.clone(),
            });
        }

        let mut verified: Vec<SignedEpochRoot> = Vec::with_capacity(batch.frames.len());
        for frame in &batch.frames {
            // (a) resolve the opaque signer_id to its pinned binding in the
            // directory's derived signer projection.
            let binding = self
                .directory
                .resolve_signer(&frame.signer_id)
                .ok_or_else(|| RevocationLaneError::UnknownSigner(frame.signer_id.clone()))?;
            // (b) transport-origin pin: the signer must be bound to the SAME
            // authenticated endpoint that presented this frame. Structurally
            // guaranteed by the derived directory, re-checked fail-closed.
            if binding.endpoint != endpoint {
                return Err(RevocationLaneError::SignerEndpointMismatch {
                    signer_id: frame.signer_id.clone(),
                    endpoint: endpoint.fmt_short().to_string(),
                });
            }
            // (c) envelope consistency (epoch/signer agreement) BEFORE crypto.
            frame.validate_envelope()?;
            // (d) authenticity: pinned-signer signature over the root. BLAKE3 /
            // transport integrity is not authenticity.
            frame
                .signed_root
                .verify(&binding.verifier)
                .map_err(|_| RevocationLaneError::BadSignature(frame.signer_id.clone()))?;
            verified.push(frame.signed_root.clone());
        }
        Ok(verified)
    }

    /// Serve a catch-up request from the pinned history via the contract's
    /// `respond_to_catchup` (strict monotone, gap-truncating, never fabricating).
    pub fn respond_catchup(
        &self,
        request: &RevocationCatchupRequest,
        responded_at_unix_ms: u64,
    ) -> Result<RevocationCatchupResponse, RevocationLaneError> {
        let history = DynHistory(self.history.clone());
        let response = respond_to_catchup(
            request,
            &self.responder_kernel_id,
            &history,
            responded_at_unix_ms,
        )?;
        Ok(response)
    }

    /// Build a blob MANIFEST (the `(epoch -> content-address)` list) for a catch-up
    /// request, computing each entry's address deterministically. Walks the SAME
    /// contiguous suffix as [`respond_catchup`](Self::respond_catchup).
    ///
    /// ADDRESS-ONLY: this does NOT publish the roots. It must not be advertised over
    /// the wire unless the caller has ALREADY published every advertised root into the
    /// store the authority's `BlobsProtocol` serves; otherwise a follower fetches a
    /// hash the authority never stored and catch-up fails. The lane's served manifest
    /// path uses [`respond_catchup_manifest_published`](Self::respond_catchup_manifest_published)
    /// (which publishes as it advertises) and this remains a lower-level builder for
    /// callers that manage publishing themselves.
    pub fn respond_catchup_manifest(
        &self,
        request: &RevocationCatchupRequest,
        responded_at_unix_ms: u64,
    ) -> Result<RevocationCatchupManifest, RevocationLaneError> {
        let history = DynHistory(self.history.clone());
        build_catchup_manifest(
            request,
            &self.responder_kernel_id,
            &history,
            responded_at_unix_ms,
        )
        .map_err(RevocationLaneError::from_catchup)
    }

    /// Serve a catch-up request as a blob MANIFEST, PUBLISHING every advertised root
    /// into `publisher`'s store (the same store the authority's `BlobsProtocol` serves)
    /// before advertising its hash. This is the safe served-manifest path: every
    /// advertised hash is confirmed-stored, so a follower can never be pointed at a
    /// hash the authority cannot serve (closes the "advertise an unpublished root" gap).
    /// The follower still fetches and pinned-signer-verifies every blob.
    async fn respond_catchup_manifest_published(
        &self,
        request: &RevocationCatchupRequest,
        responded_at_unix_ms: u64,
        publisher: &RevocationRootPublisher,
    ) -> Result<RevocationCatchupManifest, RevocationLaneError> {
        let history = DynHistory(self.history.clone());
        publish_and_build_catchup_manifest(
            request,
            &self.responder_kernel_id,
            &history,
            responded_at_unix_ms,
            publisher,
        )
        .await
        .map_err(RevocationLaneError::from_catchup)
    }

    /// Authenticate a catch-up requester against the connection: the claimed
    /// `requester_kernel_id` MUST be the kernel this authenticated transport
    /// `EndpointId` is admitted as. Fail-closed: an unadmitted endpoint
    /// (`authorize -> None`) or a mismatched claim is rejected and NOTHING is
    /// served. Shared by the inline-frame and manifest catch-up paths so both bind
    /// the requester field to the transport identity rather than trusting the
    /// self-asserted claim.
    fn authenticate_catchup_requester(
        &self,
        endpoint: EndpointId,
        requester_kernel_id: &str,
    ) -> Result<(), RevocationLaneError> {
        if self.directory.authorize(&endpoint) != Some(requester_kernel_id) {
            return Err(RevocationLaneError::RequesterMismatch {
                endpoint: endpoint.fmt_short().to_string(),
                claimed: requester_kernel_id.to_string(),
            });
        }
        Ok(())
    }

    /// Handle one decoded lane request, producing the response to write back.
    /// Verification failures become a typed [`RevocationLaneResponse::Rejected`]
    /// (never a silent drop) and NOTHING is merged / served (fail-closed).
    fn handle_request(
        &self,
        endpoint: EndpointId,
        request: RevocationLaneRequest,
        now_unix_ms: u64,
    ) -> RevocationLaneResponse {
        match request {
            RevocationLaneRequest::Push(batch) => match self.verify_batch(endpoint, &batch) {
                Ok(roots) => {
                    // Only now merge, all-or-nothing having verified every root.
                    // `merge_batch` carries the atomic (no-partial-application)
                    // contract: a mid-batch sink failure leaves the sink untouched.
                    match self.sink.merge_batch(&roots) {
                        Ok(()) => RevocationLaneResponse::PushAccepted {
                            merged_epochs: roots.iter().map(|root| root.root.epoch).collect(),
                        },
                        Err(error) => {
                            note_revocation_failure(&error);
                            error.as_rejected()
                        }
                    }
                }
                Err(error) => {
                    note_revocation_failure(&error);
                    error.as_rejected()
                }
            },
            RevocationLaneRequest::Catchup(request) => {
                // Bind the self-asserted `requester_kernel_id` to the authenticated
                // transport identity, closing a requester-spoofing gap.
                if let Err(error) =
                    self.authenticate_catchup_requester(endpoint, &request.requester_kernel_id)
                {
                    note_revocation_failure(&error);
                    return error.as_rejected();
                }
                match self.respond_catchup(&request, now_unix_ms) {
                    Ok(response) => RevocationLaneResponse::Catchup(response),
                    Err(error) => {
                        note_revocation_failure(&error);
                        error.as_rejected()
                    }
                }
            }
            RevocationLaneRequest::CatchupManifest(request) => {
                // A blob manifest is only safe to advertise when the authority has a
                // publisher wired, so it can publish each advertised root and every
                // hash is fetchable. That path is async and served by
                // `serve` -> `handle_catchup_manifest`. Reaching this SYNC arm means no
                // publisher is available (or a direct caller bypassed `serve`), so fail
                // closed: authenticate the requester, then fall back to inline catch-up
                // rather than advertise a hash the authority may not have stored.
                if let Err(error) =
                    self.authenticate_catchup_requester(endpoint, &request.requester_kernel_id)
                {
                    note_revocation_failure(&error);
                    return error.as_rejected();
                }
                match self.respond_catchup(&request, now_unix_ms) {
                    Ok(response) => RevocationLaneResponse::Catchup(response),
                    Err(error) => {
                        note_revocation_failure(&error);
                        error.as_rejected()
                    }
                }
            }
        }
    }

    /// Serve a [`CatchupManifest`](RevocationLaneRequest::CatchupManifest) request,
    /// binding the requester to the transport identity exactly as the inline catch-up
    /// path, then:
    ///
    /// - with a blob publisher wired ([`with_blob_publisher`](Self::with_blob_publisher)),
    ///   PUBLISH every advertised root into the store the authority's `BlobsProtocol`
    ///   serves and return a [`CatchupManifest`](RevocationLaneResponse::CatchupManifest)
    ///   whose every hash is therefore fetchable;
    /// - WITHOUT a publisher, fail closed and fall back to an inline
    ///   [`Catchup`](RevocationLaneResponse::Catchup) response on the same request, so
    ///   the follower still catches up over lane-b and the authority NEVER advertises a
    ///   hash it cannot serve.
    ///
    /// A spoofed requester is [`Rejected`](RevocationLaneResponse::Rejected) and nothing
    /// is published or served, in either mode.
    async fn handle_catchup_manifest(
        &self,
        endpoint: EndpointId,
        request: &RevocationCatchupRequest,
        now_unix_ms: u64,
    ) -> RevocationLaneResponse {
        if let Err(error) =
            self.authenticate_catchup_requester(endpoint, &request.requester_kernel_id)
        {
            note_revocation_failure(&error);
            return error.as_rejected();
        }
        // With a publisher: publish-then-advertise, so every advertised hash is
        // fetchable. Without one: fail closed to an inline catch-up response, never
        // advertising a hash the authority may not have stored. Both branches yield
        // a lane response or a fail-closed error.
        let result = match &self.blob_publisher {
            Some(publisher) => self
                .respond_catchup_manifest_published(request, now_unix_ms, publisher)
                .await
                .map(RevocationLaneResponse::CatchupManifest),
            None => self
                .respond_catchup(request, now_unix_ms)
                .map(RevocationLaneResponse::Catchup),
        };
        match result {
            Ok(response) => response,
            Err(error) => {
                note_revocation_failure(&error);
                error.as_rejected()
            }
        }
    }
}

/// OBSERVE-ONLY: count + log a revocation-lane rejection alongside the unchanged
/// fail-closed response. Reads the error's bounded `code()`; a `catchup-gap` also
/// bumps the epoch-gap family (a core revocation-freshness health signal that was
/// entirely dark before). Never alters the response the caller returns.
fn note_revocation_failure(error: &RevocationLaneError) {
    let reason = error.code();
    crate::metrics::record_verify_failure(crate::metrics::SEAM_REVOCATION, reason);
    if reason == "catchup-gap" {
        crate::metrics::record_catchup_epoch_gap(crate::metrics::CATCHUP_SOURCE_REVOCATION);
    }
    tracing::warn!(
        target: crate::observability::TARGET_VERIFY,
        seam = crate::metrics::SEAM_REVOCATION,
        reason = reason,
        "revocation lane rejected request"
    );
}

impl RevocationHandler {
    /// One bounded request/response exchange over the accepted connection. Every
    /// peer-dependent await is bounded (accept_bi, the request-frame read, the
    /// response write); a verification failure is still delivered IN-BAND as a
    /// typed [`RevocationLaneResponse::Rejected`] (produced by `handle_request`,
    /// so this returns `Ok`), and only transport / codec / timeout failures reset.
    async fn serve(&self, conn: &Connection) -> Result<(), RevocationLaneError> {
        let endpoint = conn.remote_id();
        // Defense in depth: unreachable past the admission gate. Reset closed.
        if self.directory.authorize(&endpoint).is_none() {
            return Err(RevocationLaneError::UnboundEndpoint);
        }
        // Bound accept_bi: a connected-but-silent peer is dropped here.
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, conn.accept_bi())
            .await?
            .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
        // Bound the request-frame read: the primary slowloris surface.
        let request: RevocationLaneRequest = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        // Verification runs on the fully received frame; timeouts never weaken it.
        // The blob-manifest path is served asynchronously (it may PUBLISH each
        // advertised root so every advertised hash is fetchable) and is the only lane
        // response produced outside the sync `handle_request`; everything else is
        // synchronous, pure verification.
        let now = now_unix_ms();
        let response = match request {
            RevocationLaneRequest::CatchupManifest(catchup) => {
                self.handle_catchup_manifest(endpoint, &catchup, now).await
            }
            other => self.handle_request(endpoint, other, now),
        };
        // Bound the response write: a peer that stops reading is dropped here.
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &response),
            )
            .await??;
        Ok(())
    }
}

impl ProtocolHandler for RevocationHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        use tracing::Instrument;
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code.
        let _permit = match self.limiter.admit_peer(&conn.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                // OBSERVE-ONLY: the slowloris saturation shed is now countable.
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_REVOCATION,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "revocation lane shed accept (saturated)"
                );
                conn.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        // OBSERVE-ONLY: the in-flight gauge (slowloris detector) and accept span.
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_REVOCATION);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_REVOCATION);
        let started = std::time::Instant::now();
        let result = self.serve(&conn).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_REVOCATION,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_REVOCATION,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                // Bounded linger: keep the connection open until the dialer has
                // read the finished response and closed (so the finished stream
                // is not reset on drop; without this the response can be lost as
                // "connection lost" on real QUIC), but never past the linger bound.
                self.limiter.linger(&conn).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_REVOCATION, outcome);
                crate::observability::record_outcome(&span, outcome);
                tracing::warn!(code = error.code(), error = %error, "revocation lane reset");
                conn.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

/// Client half: dial an authority and push a batch of signed roots, returning
/// the authority's typed response. The admission gate on the authority endpoint
/// rejects an unadmitted dialer before this stream is accepted.
///
/// `authority` is anything that resolves to a dialable [`EndpointAddr`]: a bare
/// [`EndpointId`] (resolved via discovery/relay) OR a full [`EndpointAddr`] carrying
/// the socket address(es), so a direct-address / relay-disabled deployment can dial
/// a known peer without discovery.
///
/// Uses the generous default client bounds ([`AcceptLimitConfig::default`]); see
/// [`push_batch_over_iroh_with_limits`] to tune them.
pub async fn push_batch_over_iroh(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    batch: &RevocationGossipBatch,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    push_batch_over_iroh_with_limits(endpoint, authority, batch, &AcceptLimitConfig::default())
        .await
}

/// Same as [`push_batch_over_iroh`], with explicit client-side bounds on every
/// peer-dependent await (connect, open, write, read).
pub async fn push_batch_over_iroh_with_limits(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    batch: &RevocationGossipBatch,
    limits: &AcceptLimitConfig,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_over_iroh(
        endpoint,
        authority,
        &RevocationLaneRequest::Push(batch.clone()),
        limits,
    )
    .await
}

/// Client half: dial an authority and request a catch-up range; the response
/// (control envelope) rides this lane-b stream while the bulk root bytes are
/// available over iroh-blobs ([`crate::catchup`]).
///
/// `authority` accepts a bare [`EndpointId`] or a full [`EndpointAddr`] (see
/// [`push_batch_over_iroh`]). Uses the generous default client bounds; see
/// [`request_catchup_over_iroh_with_limits`] to tune them.
pub async fn request_catchup_over_iroh(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    request: &RevocationCatchupRequest,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_catchup_over_iroh_with_limits(
        endpoint,
        authority,
        request,
        &AcceptLimitConfig::default(),
    )
    .await
}

/// Same as [`request_catchup_over_iroh`], with explicit client-side bounds.
pub async fn request_catchup_over_iroh_with_limits(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    request: &RevocationCatchupRequest,
    limits: &AcceptLimitConfig,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_over_iroh(
        endpoint,
        authority,
        &RevocationLaneRequest::Catchup(request.clone()),
        limits,
    )
    .await
}

/// Client half: dial an authority and request a BLOB-MANIFEST catch-up (lane e),
/// sending [`RevocationLaneRequest::CatchupManifest`] instead of the inline
/// [`Catchup`](RevocationLaneRequest::Catchup) so a large history rides iroh-blobs
/// rather than overrunning the bounded lane-b response. This is the PUBLIC entry point
/// that was missing: [`request_catchup_over_iroh`] only ever asks for inline frames, so
/// without this an external caller could never drive the advertised blob path.
///
/// The returned [`RevocationLaneResponse`] is one of:
/// - [`CatchupManifest`](RevocationLaneResponse::CatchupManifest): feed it to
///   [`BlobCatchupClient::fetch_from_manifest`](crate::catchup::BlobCatchupClient::fetch_from_manifest)
///   to pull + verify the history over blobs (every advertised hash is fetchable
///   because the authority publishes each root before advertising it);
/// - [`Catchup`](RevocationLaneResponse::Catchup): a fail-closed INLINE fallback the
///   authority serves when it has no blob publisher wired (it will not advertise a hash
///   it cannot serve) - merge the inline frames directly;
/// - [`Rejected`](RevocationLaneResponse::Rejected): a typed deny (e.g. a spoofed
///   requester); nothing was served.
///
/// The caller therefore MUST handle both the manifest and the inline-fallback response.
/// Mirrors [`request_catchup_over_iroh`]'s auth-gated connect, close-after-read, and
/// per-phase timeout handling. `authority` accepts a bare [`EndpointId`] or a full
/// [`EndpointAddr`] (see [`push_batch_over_iroh`]). Uses the generous default client
/// bounds; see [`request_manifest_catchup_over_iroh_with_limits`] to tune them.
pub async fn request_manifest_catchup_over_iroh(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    request: &RevocationCatchupRequest,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_manifest_catchup_over_iroh_with_limits(
        endpoint,
        authority,
        request,
        &AcceptLimitConfig::default(),
    )
    .await
}

/// Same as [`request_manifest_catchup_over_iroh`], with explicit client-side bounds.
pub async fn request_manifest_catchup_over_iroh_with_limits(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    request: &RevocationCatchupRequest,
    limits: &AcceptLimitConfig,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_over_iroh(
        endpoint,
        authority,
        &RevocationLaneRequest::CatchupManifest(request.clone()),
        limits,
    )
    .await
}

/// Bound one peer-dependent client await by the phase's timeout, mirroring the
/// accept-side [`AcceptLimiter::bounded`] and the pheromone client. On timeout this
/// fails closed with [`RevocationLaneError::AcceptLimit`] (`accept_timeout`) so a
/// peer that accepts but never replies can no longer hang the caller forever.
async fn client_bounded<T, F>(
    limits: &AcceptLimitConfig,
    phase: AcceptPhase,
    fut: F,
) -> Result<T, RevocationLaneError>
where
    F: std::future::Future<Output = T>,
{
    let bound = limits.phase_timeout(phase);
    match tokio::time::timeout(bound, fut).await {
        Ok(output) => Ok(output),
        Err(_elapsed) => Err(RevocationLaneError::AcceptLimit(
            AcceptLimitError::Timeout {
                phase,
                timeout_ms: u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
            },
        )),
    }
}

async fn request_over_iroh(
    endpoint: &Endpoint,
    authority: impl Into<EndpointAddr>,
    request: &RevocationLaneRequest,
    limits: &AcceptLimitConfig,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    let conn = client_bounded(
        limits,
        AcceptPhase::AcceptStream,
        endpoint.connect(authority, ALPN_REVOCATION_ROOT),
    )
    .await?
    .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    // Run the open/write/read exchange, then ALWAYS close the connection before
    // returning (mirrors the bilateral `request_dsse_cosignature_over_iroh` and the
    // pheromone client, which both close after reading). On success the accept side
    // is lingering purely to let the dialer close its half; closing here resolves
    // that linger at once so the accept slot is freed instead of pinned until the
    // QUIC idle timeout. Factored out so the connection is closed exactly once on
    // every path (success, timeout, transport, or codec failure).
    let result = request_exchange(limits, &conn, request).await;
    conn.close(LANE_OK_CLOSE_CODE.into(), b"ok");
    result
}

/// The open-bi / write-request / read-reply half of [`request_over_iroh`], factored
/// out so the caller can close the connection exactly once regardless of outcome.
async fn request_exchange(
    limits: &AcceptLimitConfig,
    conn: &Connection,
    request: &RevocationLaneRequest,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    let (mut send, mut recv) = client_bounded(limits, AcceptPhase::AcceptStream, conn.open_bi())
        .await?
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    client_bounded(
        limits,
        AcceptPhase::WriteResponse,
        write_frame(&mut send, request),
    )
    .await??;
    // The primary client-side hang surface: a peer that accepts the request but
    // never returns the response frame is dropped here at the read bound.
    let response = client_bounded(limits, AcceptPhase::ReadFrame, read_frame(&mut recv)).await??;
    Ok(response)
}

/// Write a length-delimited canonical-JSON frame and half-close the send half so
/// the reader's `read_to_end` terminates.
async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    value: &T,
) -> Result<(), RevocationLaneError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| RevocationLaneError::Codec(error.to_string()))?;
    send.write_all(&bytes)
        .await
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    send.finish()
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    Ok(())
}

/// Read a single frame written by [`write_frame`] (the peer half-closes after
/// one message), capped at [`MAX_WIRE_BYTES`] fail-closed.
async fn read_frame<T: for<'de> Deserialize<'de>>(
    recv: &mut RecvStream,
) -> Result<T, RevocationLaneError> {
    let bytes = recv
        .read_to_end(MAX_WIRE_BYTES)
        .await
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| RevocationLaneError::Codec(error.to_string()))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "revocation/tests.rs"]
mod tests;
