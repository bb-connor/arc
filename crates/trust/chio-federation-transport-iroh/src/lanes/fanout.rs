//! Lane c: cross-operator fan-out over iroh-gossip per-treaty topics.
//!
//! ADAPTER-SPEC section 4 row (c) + 4.1. This is the one genuinely many-to-many
//! surface (reputation clearing, transit-hub re-gossip). It carries
//! [`PheromoneDepositGossip`] frames over an iroh-gossip swarm, one swarm per
//! treaty.
//!
//! ## Topic derivation (one-topic-per-treaty gives ROUTING separation)
//!
//! `TopicId = blake3("chio-pheromone-gossip/v1\x00" || treaty_id_bytes)`, where
//! `treaty_id_bytes` is the canonical UTF-8 of the existing `String` treaty id
//! (ADAPTER-SPEC 4.1). A gossip topic is one swarm where every member sees every
//! other member's wire traffic. Binding `TopicId` one-to-one to a treaty means
//! each treaty's traffic rides its OWN swarm: this is ROUTING separation
//! (different treaty, different swarm, different `TopicId`), which keeps one
//! treaty's frames off another treaty's wire by default.
//!
//! Topic-per-treaty ROUTING separation is one layer; ACCESS CONTROL is the other
//! and is now ENFORCED (below). The `TopicId` is deterministic and therefore NOT a
//! secret; it grants no access on its own. The accept-time
//! [`DirectoryGate`](crate::admission::DirectoryGate) is FEDERATION-GLOBAL: it
//! admits an operator to the federation, not to a specific treaty. So a
//! globally-admitted operator that is NOT a party to a treaty could still compute
//! that treaty's (non-secret) `TopicId`. That gap is closed by a PER-TREATY
//! membership gate layered on top of federation admission.
//!
//! ## Treaty-party membership gate (federation admission + treaty party set)
//!
//! Membership is sourced from the SAME issuer-signed, anti-rollback substrate the
//! transport keys use: the per-treaty PARTY SET carried in the
//! [`VerifiedDirectory`](crate::identity::VerifiedDirectory) (an issuer-signed
//! `treaty_id -> {party kernel_ids}` map, body-hash-pinned, validity-windowed,
//! monotone-versioned). The gate is enforced FAIL-CLOSED in two places (defense in
//! depth), so this is no longer routing separation alone but enforced
//! treaty-scoped access control:
//!
//! 1. JOIN side: [`FanoutLane::subscribe_treaty`] /
//!    [`subscribe_treaty_with_timeout`](FanoutLane::subscribe_treaty_with_timeout)
//!    reject with [`FanoutError::TreatyMembershipDenied`] BEFORE joining the swarm
//!    if the LOCAL operator is not a party to `treaty_id`. The local operator's
//!    kernel id is resolved from the node's OWN AUTHENTICATED endpoint identity (the
//!    `EndpointId` the swarm authenticates as on the wire), NOT from a
//!    caller-supplied string, so a non-party cannot pass a real party's kernel id to
//!    slip past the gate.
//! 2. RECEIVE side: the frame-verification path
//!    ([`verify_fanout_frame`] / [`FanoutTopic::recv_verified`]) additionally
//!    rejects (same variant) a frame whose ORIGIN kernel is not a party to the
//!    frame's `treaty_id`, so a non-party that joins the swarm anyway cannot inject
//!    an accepted frame.
//!
//! The DELIVERED guarantee is therefore: (1) routing separation (above), (2) the
//! treaty-party membership gate at JOIN and RECEIVE (this section), and (3) a
//! receive-side swarm/treaty binding, so a frame carrying a foreign `treaty_id` is
//! rejected on this swarm even if its deposit self-signature is valid (see
//! [`FanoutTopic::recv_verified`] and [`FanoutError::TreatyMismatch`]). This is
//! federation admission AND treaty-party membership, not one standing in for the
//! other.
//!
//! ## Residual exposure: inbound gossip joins are NOT gated at admission (iroh_gossip 0.101)
//!
//! The JOIN-side gate above guards THIS node's OWN subscription: it stops a local
//! non-party from calling [`FanoutLane::subscribe_treaty`] and joining a swarm it is
//! not a party to. It does NOT gate INBOUND joins by OTHER peers. A custom client
//! that BYPASSES the local helper (dials a party's endpoint directly and computes
//! the deterministic, non-secret `TopicId`) can still be admitted as a gossip
//! neighbor and PASSIVELY OBSERVE frames the honest swarm members forward. This is a
//! CONFIDENTIALITY residual, and it is NOT closed here because iroh_gossip 0.101
//! exposes no inbound-admission hook. Verified against iroh-gossip 0.101:
//!
//! - The membership protocol admits inbound joins UNCONDITIONALLY:
//!   `hyparview::HyparView::on_join` adds the joining peer with `Priority::High`, and
//!   `add_active` ALWAYS succeeds for a high-priority join (evicting a random slot if
//!   full). There is no application predicate consulted.
//! - `JoinOptions` (the only per-subscription config) carries just `bootstrap` and
//!   `subscription_capacity`: no per-peer/per-topic admission callback or ACL.
//! - There is no pre-acceptance event: `iroh_gossip::api::Event` is only
//!   `NeighborUp` / `NeighborDown` / `Received` / `Lagged`; `NeighborUp` fires AFTER
//!   the peer is already in the active view, and a neighbor cannot be rejected then.
//! - The mounted `ProtocolHandler::accept` for `iroh_gossip::ALPN` admits ALL
//!   connections; the federation-wide accept-time
//!   [`DirectoryGate`](crate::admission::DirectoryGate) is the only connection-level
//!   filter, and it is per-FEDERATION not per-TREATY (one gossip connection
//!   multiplexes every topic, so it cannot be gated per treaty at the connection
//!   layer either).
//!
//! What IS enforced despite this: a bypassing joiner cannot INJECT an accepted frame
//! (the RECEIVE-side treaty-party gate drops a non-party origin, and the
//! swarm/treaty binding drops a foreign-treaty frame), and topic-per-treaty routing
//! separation keeps other treaties' traffic off this swarm. What is NOT enforceable
//! with this gossip version is preventing a federation-admitted non-party from
//! JOINING a treaty swarm and OBSERVING its forwarded traffic. Closing that requires
//! an upstream iroh_gossip capability this lane would then gate on treaty membership:
//! a per-topic/per-peer inbound admission predicate in `JoinOptions`, or a
//! pre-acceptance `NeighborJoinRequested` event with the ability to deny the join.
//! Until then treaty confidentiality against a passive federation-admitted observer
//! rests on federation admission plus routing separation, not join-time treaty
//! enforcement. This is a documented API limitation, NOT a closed gap.
//!
//! ## The load-bearing correctness property: `delivered_from` is NOT the author
//!
//! In gossip, [`Message::delivered_from`](iroh_gossip::api::Message) is the
//! forwarding NEIGHBOR that relayed the frame, NOT the original author
//! (empirically observed: node C reports `delivered_from = B` for a message A
//! authored, ADAPTER-SPEC 4 row (c)). Therefore this lane MUST NOT reuse the
//! `authenticated_sender == author` equality the direct lanes (a/b) rely on, and
//! MUST NOT call
//! [`verify_pheromone_gossip_frame_for_batch`](chio_federation::pheromone_gossip)
//! (which would demand `gossiping_peer_kernel_id == authenticated_sender`, false
//! over any relay hop).
//!
//! Instead, every received payload is origin-verified FROM THE PAYLOAD ALONE:
//! 1. the transport-independent
//!    [`verify_pheromone_gossip_frame`] (namespace, policy liveness, origin ==
//!    deposit author, transit-chain integrity), and
//! 2. the embedded deposit's OWN self-signature, verified against the origin
//!    operator's passport key resolved from a trusted directory (NEVER from
//!    `delivered_from`).
//!
//! Neither step consults the transport sender. `delivered_from` is never an input
//! to verification (see [`verify_fanout_frame`] and
//! [`decode_and_verify_fanout_frame`], whose signatures do not even accept it).

use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use chio_core_types::canonical_json_bytes;
use chio_core_types::PublicKey;
use chio_federation::pheromone_gossip::verify_pheromone_gossip_frame;
use chio_federation::pheromone_gossip::PheromoneDepositGossip;
use chio_federation::pheromone_gossip::PheromoneGossipError;
use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
use iroh::EndpointId;
use iroh_gossip::api::Event;
use iroh_gossip::api::GossipReceiver;
use iroh_gossip::api::GossipSender;
use iroh_gossip::api::Message;
use iroh_gossip::Gossip;
use iroh_gossip::TopicId;
use n0_future::StreamExt;

/// Domain-separation label for the pheromone fan-out gossip surface (ADAPTER-SPEC
/// 4.1). Versioned `/v1`; distinct from other gossip surfaces so lanes never
/// collide on the same `TopicId`.
pub const PHEROMONE_FANOUT_TOPIC_LABEL: &str = "chio-pheromone-gossip/v1";

/// Working cap on a single gossip payload. Mirrors iroh-gossip's
/// `DEFAULT_MAX_MESSAGE_SIZE` (ADAPTER-SPEC 7). A [`PheromoneDepositGossip`] with
/// a long transit chain can exceed this; such payloads must be referenced
/// out-of-band (bulk over the blob lane), never squeezed past the cap.
pub const MAX_GOSSIP_MESSAGE_SIZE: usize = 4096;

/// Client-side liveness bound on a swarm JOIN. `subscribe_and_join` blocks until a
/// neighbor is up, so an empty, unreachable, or hostile bootstrap set would hang the
/// join forever. After this bound the join fails closed (mirrors the direct lanes'
/// `client_bounded` and the blob catch-up client bounds). Generous for cross-continent
/// neighbor discovery; tune via [`FanoutLane::subscribe_treaty_with_timeout`].
pub const FANOUT_JOIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Derive the per-surface gossip topic for a treaty (ADAPTER-SPEC 4.1):
/// `TopicId = blake3(label || 0x00 || treaty_id_bytes)`. Deterministic and
/// coordination-free; the 32-byte BLAKE3 digest is used verbatim as the
/// `TopicId`.
#[must_use]
pub fn topic_for_treaty(label: &str, treaty_id: &str) -> TopicId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(b"\x00");
    hasher.update(treaty_id.as_bytes());
    TopicId::from_bytes(*hasher.finalize().as_bytes())
}

/// The pheromone fan-out topic for a treaty, under
/// [`PHEROMONE_FANOUT_TOPIC_LABEL`]. This is the one-topic-per-treaty binding that
/// is the confidentiality boundary.
#[must_use]
pub fn pheromone_topic_for_treaty(treaty_id: &str) -> TopicId {
    topic_for_treaty(PHEROMONE_FANOUT_TOPIC_LABEL, treaty_id)
}

/// Errors raised by the fan-out lane. Every payload-verification variant is a hard
/// reject; over best-effort gossip a rejected frame is DROPPED, not answered
/// (ADAPTER-SPEC 4 row (c)). Fail-closed: verification yields the frame only when
/// every check passes.
#[derive(Debug, thiserror::Error)]
pub enum FanoutError {
    /// A serialized frame exceeded [`MAX_GOSSIP_MESSAGE_SIZE`]; caught BEFORE
    /// broadcast so an oversized frame never hits the wire.
    #[error("gossip payload of {size} bytes exceeds the {max}-byte max_message_size")]
    MessageTooLarge {
        /// Serialized size of the offending payload.
        size: usize,
        /// The enforced cap.
        max: usize,
    },
    /// JSON encode/decode of a gossip frame failed.
    #[error("gossip frame json codec error: {0}")]
    Codec(String),
    /// No verifying key is bound to the payload's origin kernel id in the trusted
    /// resolver. Fail-closed: an unresolvable author is rejected, never trusted.
    #[error("no verifying key is bound to origin kernel {0}")]
    UnknownOrigin(String),
    /// The caller-provided [`OriginKeyResolver`] bound a key for the frame's origin
    /// that DISAGREES with the CURRENT directory-bound passport key for that origin
    /// (the resolver LAGS a key rotation/removal in the issuer-signed directory).
    /// Fail-closed: a lagging resolver key is refused BEFORE the frame is accepted,
    /// so a rotated-away/revoked key can never launder a frame even while the
    /// resolver still lists it. This mirrors the bilateral co-signing stale-key
    /// refusal ([`crate::identity::VerifiedDirectory::resolve_passport_key`] being
    /// authoritative over a separately-fed pinned map that can lag it).
    #[error(
        "origin `{origin_kernel_id}` resolver key disagrees with the current directory binding"
    )]
    OriginKeyMismatch {
        /// The origin kernel whose resolver key lags the current directory binding.
        origin_kernel_id: String,
    },
    /// The embedded deposit's OWN self-signature did not verify against the
    /// origin operator's resolved passport key. This is the check that makes
    /// `delivered_from` irrelevant to authorship.
    #[error("deposit self-signature is invalid")]
    DepositSignatureInvalid,
    /// A received frame's `treaty_id` did not match the treaty this swarm
    /// carries. Fail-closed: a frame minted for a different treaty is rejected on
    /// this swarm even if its deposit self-signature is valid, binding swarm
    /// delivery to the treaty the topic promises (the routing-separation property
    /// in the module docs).
    #[error("frame treaty_id `{got}` does not match this swarm's treaty `{expected}`")]
    TreatyMismatch {
        /// The treaty this swarm (topic) is bound to.
        expected: String,
        /// The `treaty_id` carried by the received frame.
        got: String,
    },
    /// The local operator (at JOIN) or a frame's origin kernel (at RECEIVE) is
    /// NOT a party to `treaty_id` per the issuer-signed per-treaty party set.
    /// Fail-closed: federation admission alone does not admit a non-party to a
    /// treaty's swarm, and a non-party origin frame is rejected on receive.
    #[error("kernel `{kernel_id}` is not a party to treaty `{treaty_id}`")]
    TreatyMembershipDenied {
        /// The treaty whose party set was consulted.
        treaty_id: String,
        /// The kernel id that is not a party (the local operator at join, or the
        /// frame origin at receive).
        kernel_id: String,
    },
    /// Canonical JSON serialization failed while reconstructing the deposit
    /// signing preimage.
    #[error("canonical json error: {0}")]
    Canonical(String),
    /// Transport-independent frame verification failed
    /// ([`verify_pheromone_gossip_frame`]).
    #[error(transparent)]
    Frame(PheromoneGossipError),
    /// The underlying iroh-gossip subscribe/join/broadcast/receive failed.
    #[error("gossip transport error: {0}")]
    Gossip(String),
    /// The gossip receiver fell behind and iroh-gossip dropped messages
    /// (Event::Lagged). Fieldless: iroh-gossip 0.101 reports no drop count, so
    /// the number of dropped messages is unknowable at this layer. A dropped
    /// message is a lost-frame signal, never an accepted frame.
    #[error("gossip receiver lagged: an unknown number of messages were dropped")]
    Lagged,
}

impl FanoutError {
    /// Stable, bounded metric/log reason for this fan-out failure. Feeds the
    /// `reason` label on `chio_federation_transport_verify_failures_total`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::Codec(_) => "codec",
            Self::UnknownOrigin(_) => "unknown-origin",
            Self::OriginKeyMismatch { .. } => "origin-key-mismatch",
            Self::DepositSignatureInvalid => "deposit-signature-invalid",
            Self::TreatyMismatch { .. } => "treaty-mismatch",
            Self::TreatyMembershipDenied { .. } => "treaty-membership-denied",
            Self::Canonical(_) => "canonical-json",
            Self::Frame(_) => "frame-invalid",
            Self::Gossip(_) => "gossip-transport",
            Self::Lagged => "lagged",
        }
    }
}

/// Observe-only: count and log a fan-out frame rejection alongside the fail-closed
/// drop. The receive path drops an invalid frame without emitting any local signal
/// of its own, so a `TreatyMismatch` cross-treaty injection campaign or a
/// `DepositSignatureInvalid` flood would otherwise go unobserved.
fn note_fanout_failure(error: &FanoutError) {
    let reason = error.code();
    crate::metrics::record_verify_failure(crate::metrics::SEAM_FANOUT, reason);
    tracing::warn!(
        target: crate::observability::TARGET_VERIFY,
        seam = crate::metrics::SEAM_FANOUT,
        reason = reason,
        "fan-out frame rejected"
    );
}

/// Resolves an origin operator's passport verifying key from its `kernel_id`.
///
/// The fan-out lane verifies the embedded deposit's OWN signature against this
/// key. The key MUST come from a trusted directory (the passport admission set,
/// mirroring `PheromoneValidationContext.passports`), and is resolved by the
/// payload's `origin_kernel_id`. It is NEVER derived from the gossip transport:
/// `Message::delivered_from` is the forwarding neighbor, not the author.
///
/// This resolver is NOT authoritative on its own. When the receive path's
/// `membership` oracle binds a current key for the origin
/// ([`TreatyMembership::directory_origin_key`], the production
/// [`crate::identity::VerifiedDirectory`]), THAT directory key is authoritative and
/// a resolver key that lags it (a rotated-away/revoked key) is refused with
/// [`FanoutError::OriginKeyMismatch`]. The resolver stands alone only for a
/// non-directory membership backend that binds no origin keys (see the private
/// `resolve_origin_key` helper).
pub trait OriginKeyResolver {
    /// The origin operator's passport verifying key, or `None` (fail-closed) when
    /// no admitted operator is bound to `origin_kernel_id`.
    fn verifying_key(&self, origin_kernel_id: &str) -> Option<PublicKey>;
}

/// A simple in-memory [`OriginKeyResolver`] backed by a `kernel_id -> PublicKey`
/// map. Callers populate it from the trusted passport admission set for the
/// treaty's swarm.
#[derive(Debug, Clone, Default)]
pub struct StaticOriginKeys {
    keys: HashMap<String, PublicKey>,
}

impl StaticOriginKeys {
    /// An empty resolver (resolves nothing; every origin is unknown/rejected).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `kernel_id` to its passport verifying key (builder style).
    #[must_use]
    pub fn with(mut self, kernel_id: impl Into<String>, key: PublicKey) -> Self {
        self.keys.insert(kernel_id.into(), key);
        self
    }

    /// Bind `kernel_id` to its passport verifying key.
    pub fn insert(&mut self, kernel_id: impl Into<String>, key: PublicKey) {
        self.keys.insert(kernel_id.into(), key);
    }
}

impl OriginKeyResolver for StaticOriginKeys {
    fn verifying_key(&self, origin_kernel_id: &str) -> Option<PublicKey> {
        self.keys.get(origin_kernel_id).cloned()
    }
}

/// Decides whether a `kernel_id` is a party to a `treaty_id`.
///
/// This is the treaty-scoped ACCESS-CONTROL oracle the fan-out lane consults at
/// JOIN (is the LOCAL operator a party?) and at RECEIVE (is the frame ORIGIN a
/// party?). It MUST be backed by trusted, anti-rollback data: the production
/// implementation is [`crate::identity::VerifiedDirectory`] (the issuer-signed
/// per-treaty party set), never the (non-secret) topic id or the gossip transport.
/// Fail-closed: an unknown treaty or a non-party kernel returns `false`.
pub trait TreatyMembership {
    /// Whether `kernel_id` is a party to `treaty_id` (fail-closed on unknown).
    fn is_party(&self, treaty_id: &str, kernel_id: &str) -> bool;

    /// Resolve an AUTHENTICATED transport `EndpointId` to the admitted `kernel_id`
    /// bound to it, or `None` (fail-closed) when the endpoint is not
    /// directory-bound. This is the seam the JOIN gate uses to bind the party
    /// check to the LOCAL node's real endpoint identity (the same `EndpointId` the
    /// gossip swarm authenticates as on the wire) rather than a caller-supplied
    /// string: the production [`crate::identity::VerifiedDirectory`] resolves it
    /// from its issuer-signed `EndpointId -> kernel_id` admission map (the same map
    /// the accept-time [`DirectoryGate`](crate::admission::DirectoryGate) uses).
    ///
    /// The default returns `None`, so any membership backend that does NOT bind
    /// endpoints to kernel ids fails closed (the JOIN gate denies rather than
    /// trusting the caller's claimed id).
    fn kernel_id_for_endpoint(&self, _endpoint: &EndpointId) -> Option<String> {
        None
    }

    /// The origin operator's CURRENT directory-bound passport key for
    /// `origin_kernel_id`, resolved from the SAME issuer-signed, anti-rollback
    /// snapshot this oracle authorizes treaty membership against.
    ///
    /// The receive path binds origin-key resolution to THIS key so a
    /// caller-provided [`OriginKeyResolver`] cannot lag the directory: the
    /// production [`crate::identity::VerifiedDirectory`] returns
    /// [`resolve_passport_key`](crate::identity::VerifiedDirectory::resolve_passport_key)
    /// (the algorithm-agnostic long-term key of a NON-removed operator, rebuilt in
    /// the same verified pass as the party set), so a rotated-away/revoked passport
    /// (one the current directory no longer binds) is authoritative here and a
    /// resolver still listing the stale key is refused (see
    /// [`verify_fanout_frame`] and [`FanoutError::OriginKeyMismatch`]).
    ///
    /// The default returns `None`: a membership backend that binds no origin keys
    /// (a non-directory test oracle) falls back to the caller's resolver, preserving
    /// the pre-directory behavior. Because the party set and passport bindings are
    /// built in the SAME verified pass, a party with no directory-bound key is not a
    /// reachable state for [`crate::identity::VerifiedDirectory`] (a removed operator
    /// is absent from BOTH), so the fallback never re-opens the stale-key gap for the
    /// production oracle.
    fn directory_origin_key(&self, _origin_kernel_id: &str) -> Option<PublicKey> {
        None
    }
}

impl TreatyMembership for crate::identity::VerifiedDirectory {
    fn is_party(&self, treaty_id: &str, kernel_id: &str) -> bool {
        self.is_treaty_party(treaty_id, kernel_id)
    }

    fn kernel_id_for_endpoint(&self, endpoint: &EndpointId) -> Option<String> {
        // The SAME issuer-signed EndpointId -> kernel_id admission map the
        // accept-time DirectoryGate consults (VerifiedDirectory::authorize),
        // fail-closed on an unbound or removed endpoint.
        self.authorize(endpoint).map(str::to_owned)
    }

    fn directory_origin_key(&self, origin_kernel_id: &str) -> Option<PublicKey> {
        // The origin's CURRENT issuer-signed passport key from the SAME verified
        // snapshot the party set is built in: a rotated-away/removed operator is
        // absent here (fail-closed), so the receive path never accepts a frame
        // against a key the current directory no longer binds.
        self.resolve_passport_key(origin_kernel_id).cloned()
    }
}

/// A simple in-memory [`TreatyMembership`] backed by a `treaty_id -> {kernel_id}`
/// map. Callers populate it from the trusted per-treaty party set (mirroring
/// [`StaticOriginKeys`] for the origin-key resolver); production wiring should
/// prefer the issuer-signed [`crate::identity::VerifiedDirectory`].
#[derive(Debug, Clone, Default)]
pub struct StaticTreatyMembership {
    parties: HashMap<String, HashSet<String>>,
    /// The authenticated `EndpointId -> kernel_id` binding the JOIN gate resolves
    /// the LOCAL node's identity through (mirroring the issuer-signed admission map
    /// [`crate::identity::VerifiedDirectory`] carries). Empty by default, so an
    /// unbound endpoint fails closed at the gate.
    endpoints: HashMap<EndpointId, String>,
    /// The CURRENT directory-bound `kernel_id -> passport key` binding the receive
    /// path resolves origin keys through (mirroring
    /// [`crate::identity::VerifiedDirectory::resolve_passport_key`]). Empty by
    /// default, so a backend that binds no origin keys falls back to the caller's
    /// [`OriginKeyResolver`] exactly as before.
    origin_keys: HashMap<String, PublicKey>,
}

impl StaticTreatyMembership {
    /// An empty membership set (every kernel is a non-party; fail-closed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind an authenticated transport `EndpointId` to its `kernel_id` (builder
    /// style), so the JOIN gate can resolve the LOCAL node's identity from its
    /// endpoint the way [`crate::identity::VerifiedDirectory`] does in production.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: EndpointId, kernel_id: impl Into<String>) -> Self {
        self.endpoints.insert(endpoint, kernel_id.into());
        self
    }

    /// Bind `kernel_id` to its CURRENT directory-bound passport key (builder style),
    /// so the receive path resolves the origin key from this snapshot the way
    /// [`crate::identity::VerifiedDirectory::resolve_passport_key`] does in
    /// production. A resolver key that lags this binding is refused
    /// ([`FanoutError::OriginKeyMismatch`]).
    #[must_use]
    pub fn with_origin_key(mut self, kernel_id: impl Into<String>, key: PublicKey) -> Self {
        self.origin_keys.insert(kernel_id.into(), key);
        self
    }

    /// Bind `treaty_id` to a party set (builder style).
    #[must_use]
    pub fn with(
        mut self,
        treaty_id: impl Into<String>,
        party_kernel_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let entry = self.parties.entry(treaty_id.into()).or_default();
        for kernel_id in party_kernel_ids {
            entry.insert(kernel_id.into());
        }
        self
    }

    /// Add a single `kernel_id` to a treaty's party set.
    pub fn insert_party(&mut self, treaty_id: impl Into<String>, kernel_id: impl Into<String>) {
        self.parties
            .entry(treaty_id.into())
            .or_default()
            .insert(kernel_id.into());
    }
}

impl TreatyMembership for StaticTreatyMembership {
    fn is_party(&self, treaty_id: &str, kernel_id: &str) -> bool {
        self.parties
            .get(treaty_id)
            .is_some_and(|parties| parties.contains(kernel_id))
    }

    fn kernel_id_for_endpoint(&self, endpoint: &EndpointId) -> Option<String> {
        self.endpoints.get(endpoint).cloned()
    }

    fn directory_origin_key(&self, origin_kernel_id: &str) -> Option<PublicKey> {
        self.origin_keys.get(origin_kernel_id).cloned()
    }
}

/// Origin-verify a fan-out frame FROM THE PAYLOAD ALONE. This is the whole point
/// of the lane: it never consults the gossip transport sender.
///
/// Order (fail-closed; authenticate, THEN authorize):
/// 1. [`verify_pheromone_gossip_frame`]: schema, `origin_kernel_id ==
///    deposit.body.kernel_id`, subject namespace, policy liveness, and
///    transit-chain integrity. It takes NO transport-sender identity. Running it
///    first also PINS the origin to the deposit author, so the key resolved next
///    is bound to the deposit's own signer.
/// 2. Resolve the AUTHOR key from `frame.origin_kernel_id` (the signed payload),
///    NEVER from `delivered_from`, BOUND to the same verified directory snapshot
///    `membership` uses: when the directory binds a current key for the origin it
///    is AUTHORITATIVE, and a caller-resolver key that lags it is refused (see the
///    private `resolve_origin_key` helper).
/// 3. Verify the deposit's OWN self-signature against that key.
/// 4. TREATY-PARTY AUTHORIZATION: the (now-authenticated) origin kernel MUST be a
///    party to the frame's own `treaty_id` per `membership`. A non-party origin is
///    rejected even with a valid self-signature, so a non-party that joins a swarm
///    anyway cannot inject an accepted frame.
///
/// # Errors
/// Returns [`FanoutError::Frame`] on frame verification failure,
/// [`FanoutError::UnknownOrigin`] when the origin has no bound key,
/// [`FanoutError::OriginKeyMismatch`] when the caller resolver key lags the current
/// directory binding, [`FanoutError::DepositSignatureInvalid`] when the
/// self-signature does not verify, and [`FanoutError::TreatyMembershipDenied`] when
/// the origin is not a party to the frame's treaty.
pub fn verify_fanout_frame<R, M>(
    frame: &PheromoneDepositGossip,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    // OBSERVE-ONLY wrapper: the origin-verification logic is unchanged in
    // `verify_fanout_frame_inner`; here we count + log a rejection and return the
    // SAME `Result`.
    let result = verify_fanout_frame_inner(frame, origin_keys, membership, policy, now_unix_ms);
    if let Err(error) = &result {
        note_fanout_failure(error);
    }
    result
}

fn verify_fanout_frame_inner<R, M>(
    frame: &PheromoneDepositGossip,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    // (1) Transport-independent frame verification. Pins origin == deposit author.
    verify_pheromone_gossip_frame(frame, policy, now_unix_ms).map_err(FanoutError::Frame)?;

    // (2) Resolve the author key from the PAYLOAD origin, never `delivered_from`,
    // and BIND it to the SAME verified directory snapshot `membership` authorizes
    // against. When the directory binds a CURRENT key for this origin that key is
    // AUTHORITATIVE, so a rotated-away/removed key can never be accepted just
    // because the caller's `origin_keys` resolver still lists it: a resolver key
    // that disagrees with the directory binding is refused with
    // `OriginKeyMismatch` BEFORE any signature work (mirroring the bilateral
    // co-signing stale-key refusal). Only when the membership backend binds no key
    // for the origin (a non-directory test oracle) do we fall back to the resolver.
    let origin_key = resolve_origin_key(frame, origin_keys, membership)?;

    // (3) Verify the deposit's OWN self-signature against that key.
    verify_deposit_self_signature(frame, &origin_key)?;

    // (4) Authorize the authenticated origin against the frame's treaty party set.
    // Fail-closed: a non-party origin is rejected even with a valid self-signature.
    if !membership.is_party(&frame.treaty_id, &frame.origin_kernel_id) {
        return Err(FanoutError::TreatyMembershipDenied {
            treaty_id: frame.treaty_id.clone(),
            kernel_id: frame.origin_kernel_id.clone(),
        });
    }
    Ok(())
}

/// Resolve the origin author key to verify the deposit self-signature against,
/// BOUND to the SAME verified directory snapshot `membership` authorizes against.
///
/// Fail-closed resolution order (mirrors the bilateral co-signing key resolution):
/// - If `membership` binds a CURRENT directory key for the origin
///   ([`TreatyMembership::directory_origin_key`], the production
///   [`crate::identity::VerifiedDirectory::resolve_passport_key`]), that key is
///   AUTHORITATIVE. A caller `origin_keys` resolver key that DISAGREES with it (a
///   key that lags a rotation/removal) is refused with
///   [`FanoutError::OriginKeyMismatch`] before any signature work, so a
///   rotated-away/revoked key can never launder a frame even while the resolver
///   still lists it. A missing resolver key is fine here: the directory binding
///   stands on its own (an old frame signed by a rotated-away key then fails the
///   self-signature check against the current directory key).
/// - Only when the membership backend binds NO directory key for the origin (a
///   non-directory oracle) do we fall back to the caller's resolver, rejecting an
///   unresolvable origin with [`FanoutError::UnknownOrigin`].
fn resolve_origin_key<R, M>(
    frame: &PheromoneDepositGossip,
    origin_keys: &R,
    membership: &M,
) -> Result<PublicKey, FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    let resolver_key = origin_keys.verifying_key(&frame.origin_kernel_id);
    match membership.directory_origin_key(&frame.origin_kernel_id) {
        // The directory binds a current key: it is AUTHORITATIVE. A resolver key
        // that disagrees with it (lags a rotation/removal) is refused; a matching or
        // absent resolver key defers to the directory binding.
        Some(directory_key) => match resolver_key {
            Some(resolver_key) if resolver_key != directory_key => {
                Err(FanoutError::OriginKeyMismatch {
                    origin_kernel_id: frame.origin_kernel_id.clone(),
                })
            }
            _ => Ok(directory_key),
        },
        // No directory binding for this origin: fall back to the caller's resolver.
        None => {
            resolver_key.ok_or_else(|| FanoutError::UnknownOrigin(frame.origin_kernel_id.clone()))
        }
    }
}

/// Decode a raw gossip payload from `Message::content`, BIND it to the joined
/// treaty, then origin-verify it. This is what a raw receive loop calls after
/// [`FanoutTopic::next_payload`]; `expected_treaty` MUST be the treaty of the swarm
/// the payload arrived on (use [`FanoutTopic::treaty_id`] or the topic-bound
/// [`FanoutTopic::decode_and_verify`]).
///
/// Fail-closed: a frame whose `treaty_id` is not `expected_treaty` is rejected with
/// [`FanoutError::TreatyMismatch`] BEFORE any signature work, so a raw receive loop
/// can no longer accept a foreign-treaty frame that a caller forgot to bind (a
/// valid self-signed frame for a DIFFERENT treaty does not pass here). Note the
/// signature takes only the payload bytes: `delivered_from` is structurally absent,
/// so it cannot leak into the authorship decision.
///
/// # Errors
/// Returns [`FanoutError::Codec`] on malformed JSON, [`FanoutError::TreatyMismatch`]
/// when the frame is bound to a different treaty, else any error from
/// [`verify_fanout_frame`] (including [`FanoutError::TreatyMembershipDenied`] when
/// the frame origin is not a party to the treaty).
pub fn decode_and_verify_fanout_frame<R, M>(
    content: &[u8],
    expected_treaty: &str,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<PheromoneDepositGossip, FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    decode_bind_treaty_and_verify(
        content,
        expected_treaty,
        origin_keys,
        membership,
        policy,
        now_unix_ms,
    )
}

/// Decode a raw gossip payload, ENFORCE the swarm/treaty binding against
/// `expected_treaty`, then origin-verify it. This is the single core shared by
/// [`FanoutTopic::recv_verified`] and the public treaty-bound
/// [`decode_and_verify_fanout_frame`], so both the streaming and raw receive paths
/// enforce the SAME binding; factored out so it is unit-testable without a live
/// swarm.
///
/// Fail-closed order: decode, then reject with [`FanoutError::TreatyMismatch`]
/// BEFORE any signature work if the frame's `treaty_id` is not `expected_treaty`
/// (a frame minted for a different treaty is rejected on this swarm even if its
/// deposit self-signature is valid), then run [`verify_fanout_frame`].
///
/// # Errors
/// [`FanoutError::Codec`] on malformed JSON, [`FanoutError::TreatyMismatch`]
/// when the frame is bound to a different treaty, else any error from
/// [`verify_fanout_frame`].
fn decode_bind_treaty_and_verify<R, M>(
    content: &[u8],
    expected_treaty: &str,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<PheromoneDepositGossip, FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    let frame: PheromoneDepositGossip =
        serde_json::from_slice(content).map_err(|error| FanoutError::Codec(error.to_string()))?;
    if frame.treaty_id != expected_treaty {
        // OBSERVE-ONLY: the cross-treaty injection signal (a foreign-treaty frame
        // on this swarm) is counted before the unchanged fail-closed reject. The
        // verify_fanout_frame call below already self-counts its own failures.
        let error = FanoutError::TreatyMismatch {
            expected: expected_treaty.to_string(),
            got: frame.treaty_id,
        };
        note_fanout_failure(&error);
        return Err(error);
    }
    verify_fanout_frame(&frame, origin_keys, membership, policy, now_unix_ms)?;
    Ok(frame)
}

/// Serialize a frame for broadcast, enforcing the [`MAX_GOSSIP_MESSAGE_SIZE`] cap
/// BEFORE it reaches the wire.
///
/// # Errors
/// Returns [`FanoutError::Codec`] on serialization failure and
/// [`FanoutError::MessageTooLarge`] when the serialized frame exceeds the cap.
pub fn encode_fanout_frame(frame: &PheromoneDepositGossip) -> Result<Bytes, FanoutError> {
    let bytes = serde_json::to_vec(frame).map_err(|error| FanoutError::Codec(error.to_string()))?;
    if bytes.len() > MAX_GOSSIP_MESSAGE_SIZE {
        return Err(FanoutError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_GOSSIP_MESSAGE_SIZE,
        });
    }
    Ok(Bytes::from(bytes))
}

/// Reconstruct the exact preimage `chio-pheromone` signs and verify the deposit's
/// own signature against `origin_key`.
///
/// The normative signing/verification lives in
/// `chio_pheromone::validation::{verify_deposit_signature, deposit_signature_body}`
/// (validation.rs:154-171), which are `pub(crate)` and so cannot be called from
/// here. The preimage is the deposit body with `cost_commitment` cleared, encoded
/// as canonical JSON; this reproduces that byte-for-byte. It MUST stay in step
/// with the canonical functions. The guard test
/// `lane_verifies_a_real_chio_pheromone_deposit_signature` pins this copy to the
/// normative signer: it signs a real deposit with `chio_pheromone::sign_deposit`
/// and asserts this function accepts it, so a canonicalization change in
/// `chio_pheromone` fails loudly here instead of silently diverging.
fn verify_deposit_self_signature(
    frame: &PheromoneDepositGossip,
    origin_key: &PublicKey,
) -> Result<(), FanoutError> {
    let mut signed_body = frame.deposit.body.clone();
    signed_body.cost_commitment = None;
    let canonical = canonical_json_bytes(&signed_body)
        .map_err(|error| FanoutError::Canonical(error.to_string()))?;
    if origin_key.verify(&canonical, &frame.deposit.signature) {
        Ok(())
    } else {
        Err(FanoutError::DepositSignatureInvalid)
    }
}

/// The fan-out lane: a handle to the shared iroh-gossip protocol.
///
/// The gossip protocol is spawned once
/// (`Gossip::builder().spawn(endpoint.clone())`, which implements
/// `ProtocolHandler`) and mounted on the router under `iroh_gossip::ALPN`
/// (`Router::builder(ep).accept(iroh_gossip::ALPN, gossip.clone()).spawn()`);
/// gossip owns its ALPN, so this lane does not invent one. Membership of every
/// topic swarm is gated UPSTREAM by the accept-time
/// [`DirectoryGate`](crate::admission::DirectoryGate) installed via
/// `Endpoint::builder(..).hooks(gate)`.
///
/// That accept-time gate is FEDERATION-GLOBAL; the PER-TREATY party gate is layered
/// on top at [`subscribe_treaty`](FanoutLane::subscribe_treaty). To keep that gate
/// unbypassable, the underlying [`Gossip`] handle is held PRIVATELY and NOT exposed
/// by any accessor: the only way to join a treaty swarm is through the
/// membership-checked `subscribe_treaty` /
/// [`subscribe_treaty_with_timeout`](FanoutLane::subscribe_treaty_with_timeout),
/// so a caller cannot reach
/// `subscribe_and_join(pheromone_topic_for_treaty(..), ..)` directly and join a
/// treaty it is not a party to.
///
/// ## The JOIN gate binds to the AUTHENTICATED local endpoint, not a caller string
///
/// The lane also captures its own `local_endpoint_id`: the `EndpointId` of the
/// endpoint the [`Gossip`] handle was spawned on, i.e. the identity this node
/// AUTHENTICATES as on the wire when it joins a swarm. The JOIN gate resolves THAT
/// endpoint to a kernel id through the issuer-signed directory
/// ([`TreatyMembership::kernel_id_for_endpoint`]) and authorizes against the
/// resolved id, so a caller cannot pass an arbitrary party's `kernel_id` string to
/// slip past the party check. The id is DERIVED INTERNALLY from the
/// [`iroh::Endpoint`] handed to [`FanoutLane::new`] (`endpoint.id()`), NOT accepted
/// as a raw caller value: a caller can only pass an endpoint whose id is
/// cryptographically its own, never a real party's `EndpointId` it does not hold the
/// secret key for. See [`FanoutLane::new`] for the residual iroh_gossip 0.101
/// contract (`Gossip` exposes no accessor to recover its own endpoint, so the caller
/// must pass the SAME endpoint it spawned `gossip` on).
#[derive(Debug, Clone)]
pub struct FanoutLane {
    gossip: Gossip,
    /// The AUTHENTICATED local endpoint identity, DERIVED from the `Endpoint` passed
    /// to [`FanoutLane::new`] (`endpoint.id()`) - never a raw caller-supplied id. The
    /// `gossip` swarm authenticates as this endpoint on the wire; the JOIN gate
    /// resolves it to the local kernel id it authorizes.
    local_endpoint_id: EndpointId,
}

impl FanoutLane {
    /// Wrap an already-spawned, router-mounted [`Gossip`] handle together with the
    /// AUTHENTICATED local endpoint the JOIN gate binds to.
    ///
    /// `endpoint` MUST be the SAME [`iroh::Endpoint`] the `gossip` handle was spawned
    /// on (`Gossip::builder().spawn(endpoint.clone())`). The lane DERIVES
    /// `local_endpoint_id = endpoint.id()` INTERNALLY, so a caller cannot supply an
    /// id that differs from an endpoint it actually holds: it can only pass an
    /// `Endpoint` whose id is cryptographically its own (derived from a secret key it
    /// possesses), never a real party's `EndpointId` it does not control. This closes
    /// the join-spoof where a non-party passed a real party's `EndpointId` while its
    /// gossip endpoint authenticated as someone else.
    ///
    /// Residual contract (iroh_gossip 0.101 limitation): `iroh_gossip::Gossip`
    /// exposes NO accessor to recover the endpoint it was spawned on (verified
    /// against iroh-gossip 0.101 - the endpoint is consumed by `GossipBuilder::spawn`
    /// into a private actor task and never surfaced), so the lane cannot itself
    /// confirm `endpoint` is the one `gossip` actually runs on. The caller MUST pass
    /// that same endpoint; passing a DIFFERENT endpoint it also owns would bind the
    /// gate to an identity other than the one the swarm authenticates as on the wire.
    /// Taking the `Endpoint` and deriving the id internally is nonetheless strictly
    /// stronger than accepting a raw `EndpointId` (which a non-party could set to any
    /// real party's id): here the id is always tied to an endpoint the caller holds.
    #[must_use]
    pub fn new(gossip: Gossip, endpoint: &iroh::Endpoint) -> Self {
        Self {
            gossip,
            local_endpoint_id: endpoint.id(),
        }
    }

    // NO raw gossip accessor is exposed (deliberate, fail-closed). Handing out the
    // underlying `Gossip` handle would let a caller run
    // `subscribe_and_join(pheromone_topic_for_treaty(treaty_id), bootstrap)` directly
    // and join a treaty swarm WITHOUT the treaty-party membership check enforced in
    // `subscribe_treaty` / `subscribe_treaty_with_timeout` below - reopening exactly
    // the leak the JOIN gate closes (a globally-admitted non-party computing the
    // non-secret topic id and joining anyway). The handle stays private so EVERY join
    // routes through the membership gate; there is no membership-bypass escape hatch.

    /// Subscribe to and join the per-treaty topic swarm, returning the split
    /// sender/receiver handle.
    ///
    /// `bootstrap` are already-admitted `EndpointId`s to dial into the swarm (the
    /// directory gate rejects any unadmitted endpoint at handshake, so bootstraps
    /// that are not directory-bound simply fail to connect). The topic is derived
    /// deterministically from `treaty_id` via [`pheromone_topic_for_treaty`].
    ///
    /// TREATY-PARTY JOIN GATE (fail-closed), bound to the AUTHENTICATED local
    /// identity: the swarm is joined ONLY if the LOCAL node's OWN endpoint
    /// (`local_endpoint_id`, resolved to a kernel id through `membership` the way
    /// [`crate::identity::VerifiedDirectory`] does) is a party to `treaty_id`. The
    /// caller-supplied `local_kernel_id` is NOT trusted on its own: it is rejected
    /// unless it EQUALS the id resolved from the authenticated endpoint, so a
    /// globally-admitted non-party cannot pass a real party's `kernel_id` string to
    /// slip past the check. A non-party is rejected with
    /// [`FanoutError::TreatyMembershipDenied`] BEFORE the (non-secret,
    /// deterministic) topic is computed or any neighbor is dialed, so federation
    /// admission alone never leaks a treaty's traffic to a non-party.
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMembershipDenied`] when the local endpoint does
    /// not resolve to a kernel id, when `local_kernel_id` does not match that
    /// resolved id, or when the resolved id is not a party to `treaty_id`; or
    /// [`FanoutError::Gossip`] if the subscribe/join fails.
    pub async fn subscribe_treaty<M>(
        &self,
        treaty_id: &str,
        local_kernel_id: &str,
        membership: &M,
        bootstrap: Vec<EndpointId>,
    ) -> Result<FanoutTopic, FanoutError>
    where
        M: TreatyMembership + ?Sized,
    {
        self.subscribe_treaty_with_timeout(
            treaty_id,
            local_kernel_id,
            membership,
            bootstrap,
            FANOUT_JOIN_TIMEOUT,
        )
        .await
    }

    /// Same as [`subscribe_treaty`](Self::subscribe_treaty), with an explicit join
    /// bound. `subscribe_and_join` blocks until a neighbor is up; an empty or
    /// unreachable `bootstrap` would otherwise hang the join forever, so it fails
    /// closed to [`FanoutError::Gossip`] after `join_timeout` (client-side liveness
    /// defense, mirroring the direct lanes' `client_bounded`). `next_payload`'s wait
    /// is deliberately NOT bounded: a receive loop is meant to block until the next
    /// gossip message.
    ///
    /// The treaty-party JOIN gate (see [`subscribe_treaty`](Self::subscribe_treaty)),
    /// bound to the AUTHENTICATED local endpoint identity, is enforced here,
    /// fail-closed, BEFORE the topic is derived or joined.
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMembershipDenied`] when the local endpoint does
    /// not resolve to a kernel id, when `local_kernel_id` does not match that
    /// resolved id, or when the resolved id is not a party to `treaty_id`; or
    /// [`FanoutError::Gossip`] if the join times out or the subscribe/join fails.
    pub async fn subscribe_treaty_with_timeout<M>(
        &self,
        treaty_id: &str,
        local_kernel_id: &str,
        membership: &M,
        bootstrap: Vec<EndpointId>,
        join_timeout: Duration,
    ) -> Result<FanoutTopic, FanoutError>
    where
        M: TreatyMembership + ?Sized,
    {
        // TREATY-PARTY JOIN GATE (fail-closed), bound to the AUTHENTICATED local
        // identity. The gate MUST NOT authorize on the caller-supplied
        // `local_kernel_id` string alone: a globally-admitted operator that is not a
        // party to `treaty_id` could otherwise pass ANY real party's kernel id here,
        // satisfy `is_party`, join the deterministic gossip topic, and observe that
        // treaty's traffic. Instead we resolve the LOCAL node's OWN endpoint
        // (`local_endpoint_id`, the same identity the swarm authenticates as on the
        // wire, captured at construction) to its admitted kernel id through the
        // issuer-signed directory, then (1) reject unless the caller's claimed id
        // equals that authenticated id, and (2) authorize the authenticated id
        // against the treaty party set. All three failure modes reject BEFORE the
        // (non-secret) topic is computed, so a non-party never joins the swarm.
        let Some(authenticated_kernel_id) =
            membership.kernel_id_for_endpoint(&self.local_endpoint_id)
        else {
            // The local endpoint is not directory-bound: fail closed rather than
            // trust the caller's claimed id.
            let error = FanoutError::TreatyMembershipDenied {
                treaty_id: treaty_id.to_string(),
                kernel_id: local_kernel_id.to_string(),
            };
            note_fanout_failure(&error);
            return Err(error);
        };
        if authenticated_kernel_id != local_kernel_id {
            // The caller claimed an identity that is NOT the one this node
            // authenticates as: reject the spoof, whether or not the claimed id is a
            // genuine party.
            let error = FanoutError::TreatyMembershipDenied {
                treaty_id: treaty_id.to_string(),
                kernel_id: local_kernel_id.to_string(),
            };
            note_fanout_failure(&error);
            return Err(error);
        }
        if !membership.is_party(treaty_id, &authenticated_kernel_id) {
            let error = FanoutError::TreatyMembershipDenied {
                treaty_id: treaty_id.to_string(),
                kernel_id: authenticated_kernel_id,
            };
            note_fanout_failure(&error);
            return Err(error);
        }
        let topic_id = pheromone_topic_for_treaty(treaty_id);
        let joined = tokio::time::timeout(
            join_timeout,
            self.gossip.subscribe_and_join(topic_id, bootstrap),
        )
        .await
        .map_err(|_elapsed| {
            FanoutError::Gossip(format!(
                "swarm join timed out after {}ms (no neighbor from bootstrap)",
                u64::try_from(join_timeout.as_millis()).unwrap_or(u64::MAX)
            ))
        })?
        .map_err(|error| FanoutError::Gossip(error.to_string()))?;
        let (sender, receiver) = joined.split();
        Ok(FanoutTopic {
            treaty_id: treaty_id.to_string(),
            topic_id,
            sender,
            receiver,
        })
    }
}

/// A joined per-treaty gossip topic: one swarm = one treaty = the confidentiality
/// boundary (ADAPTER-SPEC 4.1).
#[derive(Debug)]
pub struct FanoutTopic {
    treaty_id: String,
    topic_id: TopicId,
    sender: GossipSender,
    receiver: GossipReceiver,
}

impl FanoutTopic {
    /// The treaty this swarm carries.
    #[must_use]
    pub fn treaty_id(&self) -> &str {
        &self.treaty_id
    }

    /// The deterministic topic id for this swarm.
    #[must_use]
    pub fn topic_id(&self) -> TopicId {
        self.topic_id
    }

    /// A cheap-clone CHECKED concurrent sender, for broadcasting concurrently with a
    /// receive loop (the receiver borrows `&mut self`).
    ///
    /// Unlike a raw [`GossipSender`], every [`CheckedFanoutSender::broadcast`] runs the
    /// SAME send-side treaty binding and [`MAX_GOSSIP_MESSAGE_SIZE`] cap that
    /// [`FanoutTopic::broadcast`] enforces, so a concurrent send path cannot bypass the
    /// treaty pin or inject an oversized frame onto the swarm.
    #[must_use]
    pub fn concurrent_sender(&self) -> CheckedFanoutSender {
        CheckedFanoutSender {
            treaty_id: self.treaty_id.clone(),
            sender: self.sender.clone(),
        }
    }

    /// Broadcast a self-signed frame to the treaty swarm, enforcing the
    /// [`MAX_GOSSIP_MESSAGE_SIZE`] cap first.
    ///
    /// The frame MUST already carry a valid deposit self-signature: peers verify
    /// it origin-only on receive and DROP anything that fails.
    ///
    /// Fail-closed: a frame whose `treaty_id` does not match this swarm's treaty is
    /// REJECTED before it reaches the wire (send-side treaty binding, mirroring the
    /// receive-side check), so a mis-addressed frame cannot leak to another treaty's
    /// swarm members.
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMismatch`] for a wrong-treaty frame,
    /// [`FanoutError::MessageTooLarge`] / [`FanoutError::Codec`] from encoding, or
    /// [`FanoutError::Gossip`] if the broadcast fails.
    pub async fn broadcast(&self, frame: &PheromoneDepositGossip) -> Result<(), FanoutError> {
        checked_broadcast(&self.sender, &self.treaty_id, frame).await
    }

    /// Await the next gossip PAYLOAD from the swarm, mapping the membership
    /// (`NeighborUp`/`NeighborDown`) and `Lagged` events away.
    ///
    /// Returns the raw [`Message`]. The caller MUST verify it with the
    /// treaty-BOUND [`decode_and_verify`](Self::decode_and_verify) (or the free
    /// [`decode_and_verify_fanout_frame`] passing this topic's
    /// [`treaty_id`](Self::treaty_id)) so a foreign-treaty frame cannot be accepted
    /// on this swarm, and MUST NOT treat [`Message::delivered_from`] (the forwarding
    /// NEIGHBOR) as the author. Returns `None` when the topic stream is closed.
    pub async fn next_payload(&mut self) -> Option<Result<Message, FanoutError>> {
        loop {
            match self.receiver.next().await {
                Some(Ok(Event::Received(message))) => return Some(Ok(message)),
                Some(Ok(Event::Lagged)) => {
                    // The receiver fell behind and iroh-gossip dropped messages.
                    // Meter, log, and surface it as a dropped-message signal (never
                    // an accepted frame) so a subscriber that fell behind cannot
                    // silently lose frames.
                    crate::metrics::record_lane_frame(
                        crate::metrics::LANE_FANOUT,
                        crate::metrics::LANE_OUTCOME_LAGGED,
                    );
                    tracing::warn!(
                        target: crate::observability::TARGET_VERIFY,
                        treaty = %self.treaty_id,
                        "fan-out gossip receiver lagged; messages dropped"
                    );
                    return Some(Err(FanoutError::Lagged));
                }
                // NeighborUp / NeighborDown are not payloads.
                Some(Ok(_)) => continue,
                Some(Err(error)) => return Some(Err(FanoutError::Gossip(error.to_string()))),
                None => return None,
            }
        }
    }

    /// Decode + fully verify a raw payload (from [`next_payload`](Self::next_payload))
    /// BOUND to THIS swarm's treaty. This is the checked decoder a raw receive loop
    /// uses so it cannot forget the treaty binding: it supplies `self.treaty_id`
    /// to [`decode_and_verify_fanout_frame`], so a foreign-treaty frame is rejected
    /// with [`FanoutError::TreatyMismatch`] even if its deposit self-signature is
    /// valid. `delivered_from` is never consulted.
    ///
    /// # Errors
    /// Any error from [`decode_and_verify_fanout_frame`] (codec, treaty mismatch,
    /// origin/signature failure, or non-party origin).
    pub fn decode_and_verify<R, M>(
        &self,
        content: &[u8],
        origin_keys: &R,
        membership: &M,
        policy: &PheromoneTransitPolicy,
        now_unix_ms: u64,
    ) -> Result<PheromoneDepositGossip, FanoutError>
    where
        R: OriginKeyResolver + ?Sized,
        M: TreatyMembership + ?Sized,
    {
        decode_and_verify_fanout_frame(
            content,
            &self.treaty_id,
            origin_keys,
            membership,
            policy,
            now_unix_ms,
        )
    }

    /// Await the next payload AND verify it end-to-end: decode, ENFORCE the
    /// swarm/treaty binding (reject a frame whose `treaty_id` is not this swarm's
    /// treaty, even if its deposit self-signature is valid), run the
    /// transport-independent frame verifier, verify the deposit's OWN
    /// self-signature against the origin's resolved key, and ENFORCE the
    /// treaty-party gate (reject a frame whose ORIGIN kernel is not a party to the
    /// treaty per `membership`, so a non-party that joined the swarm anyway cannot
    /// inject an accepted frame). `delivered_from` is never consulted. `now_unix_ms`
    /// is supplied by the caller per receive.
    ///
    /// The swarm/treaty binding is what turns topic-per-treaty ROUTING separation
    /// into a hard receive-side check: a globally-admitted operator can compute a
    /// foreign treaty's (non-secret) `TopicId` and inject frames onto this swarm,
    /// but any frame carrying a different `treaty_id` is rejected here with
    /// [`FanoutError::TreatyMismatch`] (see the module docs).
    ///
    /// Returns `None` when the topic stream is closed; otherwise the verified
    /// frame or the verification error (a rejected frame over best-effort gossip
    /// is surfaced so the caller can log-and-drop it).
    pub async fn recv_verified<R, M>(
        &mut self,
        origin_keys: &R,
        membership: &M,
        policy: &PheromoneTransitPolicy,
        now_unix_ms: u64,
    ) -> Option<Result<PheromoneDepositGossip, FanoutError>>
    where
        R: OriginKeyResolver + ?Sized,
        M: TreatyMembership + ?Sized,
    {
        let message = match self.next_payload().await? {
            Ok(message) => message,
            Err(error) => return Some(Err(error)),
        };
        Some(decode_bind_treaty_and_verify(
            &message.content,
            &self.treaty_id,
            origin_keys,
            membership,
            policy,
            now_unix_ms,
        ))
    }
}

/// Broadcast `frame` on `sender` after enforcing the send-side treaty binding and the
/// [`MAX_GOSSIP_MESSAGE_SIZE`] cap. Shared by [`FanoutTopic::broadcast`] and
/// [`CheckedFanoutSender::broadcast`] so NO broadcast path (including a concurrent one)
/// can reach the raw [`GossipSender`] and skip the checks. Fail-closed: a wrong-treaty
/// frame is [`FanoutError::TreatyMismatch`] and an oversized/unencodable frame is
/// [`FanoutError::MessageTooLarge`] / [`FanoutError::Codec`], both BEFORE the frame
/// reaches the wire.
async fn checked_broadcast(
    sender: &GossipSender,
    expected_treaty_id: &str,
    frame: &PheromoneDepositGossip,
) -> Result<(), FanoutError> {
    if frame.treaty_id != expected_treaty_id {
        return Err(FanoutError::TreatyMismatch {
            expected: expected_treaty_id.to_string(),
            got: frame.treaty_id.clone(),
        });
    }
    let payload = encode_fanout_frame(frame)?;
    sender
        .broadcast(payload)
        .await
        .map_err(|error| FanoutError::Gossip(error.to_string()))
}

/// A cheap-clone concurrent broadcast handle for one treaty swarm that ENFORCES the
/// same send-side checks as [`FanoutTopic::broadcast`].
///
/// Returned by [`FanoutTopic::concurrent_sender`] so a broadcast path running
/// alongside a `&mut self` receive loop cannot reach the raw [`GossipSender`] and
/// bypass the treaty binding or the [`MAX_GOSSIP_MESSAGE_SIZE`] cap. This closes the
/// send-side treaty-pin bypass: there is no accessor that hands out the unchecked
/// sender.
#[derive(Debug, Clone)]
pub struct CheckedFanoutSender {
    treaty_id: String,
    sender: GossipSender,
}

impl CheckedFanoutSender {
    /// The treaty this sender is pinned to.
    #[must_use]
    pub fn treaty_id(&self) -> &str {
        &self.treaty_id
    }

    /// Broadcast a self-signed frame to the pinned treaty swarm, enforcing the treaty
    /// binding and the [`MAX_GOSSIP_MESSAGE_SIZE`] cap first (identical semantics to
    /// [`FanoutTopic::broadcast`]).
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMismatch`] for a wrong-treaty frame,
    /// [`FanoutError::MessageTooLarge`] / [`FanoutError::Codec`] from encoding, or
    /// [`FanoutError::Gossip`] if the broadcast fails.
    pub async fn broadcast(&self, frame: &PheromoneDepositGossip) -> Result<(), FanoutError> {
        checked_broadcast(&self.sender, &self.treaty_id, frame).await
    }
}

#[cfg(test)]
#[path = "fanout/tests.rs"]
mod tests;
