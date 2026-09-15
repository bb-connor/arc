//! Lane d: bilateral DSSE co-sign over a dedicated-ALPN bidirectional QUIC RPC.
//!
//! ADAPTER-SPEC section 4 row (d) + 4.2. This lane is an interactive
//! request/response exchange, categorically NOT gossip: broadcasting an in-flight
//! DSSE statement would leak it to non-parties. It is the transport implementation
//! of [`chio_federation::bilateral::BilateralCoSigningProtocol`], dialing over iroh
//! instead of running in-process; the request/response CONTRACT above the transport
//! is unchanged (it replaces [`chio_federation::bilateral::InProcessCoSigner`]).
//!
//! ## The five-step flow (ADAPTER-SPEC 4.2)
//!
//! 1. Org B ([`IrohBilateralCoSigner`]) resolves Org A's [`EndpointAddr`] from
//!    `request.org_a_kernel_id` and dials [`ALPN_BILATERAL`]; QUIC/TLS
//!    authenticates both `EndpointId`s.
//! 2. Org A's `after_handshake` admission gate ([`crate::admission::DirectoryGate`])
//!    Rejects (403) any Org B `EndpointId` not bound to an admitted, non-removed
//!    `kernel_id` BEFORE any [`ProtocolHandler::accept`] runs (DoS rejection /
//!    defense in depth, NOT a replacement for the signature check).
//! 3. Org B `open_bi()`, writes one length-delimited canonical
//!    [`WireDsseCoSigningRequest`], then half-closes its send half (`finish()`).
//! 4. Org A ([`BilateralCoSignHandler`]) asserts its directory-resolved
//!    `EndpointId == request.org_b_kernel_id`, verifies `org_b_signature` over the
//!    exact `pae_bytes` against Org B's DIRECTORY-BOUND passport key (the key the
//!    same verified directory snapshot binds for that peer; a separately-pinned
//!    map must AGREE with it or the co-sign is refused, so a rotated-away key is
//!    never accepted), algorithm-agnostic, above iroh, via
//!    [`chio_core_types::PublicKey::verify`], and re-checks trust / rotation-window
//!    through the same directory resolution. On ANY failure it writes a typed error
//!    mirroring [`BilateralCoSigningError`] and terminates WITHOUT signing.
//! 5. On success Org A reconstructs `pae_bytes` as the DSSE pre-authentication
//!    encoding of an in-toto bilateral statement naming both kernels (mirroring
//!    `InProcessCoSigner::request_dsse_cosignature`), signs those same bytes,
//!    and writes the response frame on the same stream. Bytes that do not
//!    reconstruct are refused without signing.
//!
//! ## Wire mirror (the KNOWN GOTCHA)
//!
//! [`DsseCoSigningRequest`] and [`DsseCoSigningResponse`] are deliberately NOT
//! `Serialize`/`Deserialize` in the contracts crate. Rather than modify
//! `chio-federation`, this lane defines ADAPTER-LOCAL serde mirror types that map
//! field-for-field:
//!
//! | contracts type ([`chio_federation::bilateral`]) | adapter wire mirror |
//! | --- | --- |
//! | `DsseCoSigningRequest { schema, org_a_kernel_id, org_b_kernel_id, pae_bytes, org_b_signature }` | [`WireDsseCoSigningRequest`] with the identical five fields |
//! | `DsseCoSigningResponse { schema, org_a_signature }` | [`WireReply::Ok`] `{ schema, org_a_signature }` |
//! | `BilateralCoSigningError` (server-produced subset) | [`WireReply::Err`] `{ code, detail }` tagged by [`WireErrorCode`] |
//!
//! [`chio_core_types::Signature`] already implements serde (algorithm-tagged hex
//! via `to_hex`/`from_hex`), so the mirror carries it verbatim and every passport
//! algorithm (Ed25519, P-256, P-384, ML-DSA-65, Hybrid) round-trips. NOTE:
//! `Signature::to_bytes()` is Ed25519-only (it returns zeros for other algorithms),
//! so the wire path MUST use the serde/hex encoding, never `to_bytes`. `pae_bytes`
//! maps 1:1 on the wire and is signed and verified exactly as received
//! (ADAPTER-SPEC 4.2), but the accept side reconstructs it from the statement it
//! decodes to before signing and refuses any byte disagreement.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use chio_core_types::Ed25519Backend;
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use chio_core_types::SigningBackend;
use chio_federation::bilateral::reconstruct_cosigning_body;
use chio_federation::bilateral::BilateralCoSigningError;
use chio_federation::bilateral::BilateralCoSigningProtocol;
use chio_federation::bilateral::CoSigningBody;
use chio_federation::bilateral::CoSigningRequest;
use chio_federation::bilateral::CoSigningResponse;
use chio_federation::bilateral::DsseCoSigningRequest;
use chio_federation::bilateral::DsseCoSigningResponse;
use chio_federation::bilateral::BILATERAL_COSIGNING_SCHEMA;
use chio_federation::bilateral::BILATERAL_DSSE_COSIGNING_SCHEMA;
use chio_federation::bilateral_dsse::reconstruct_dsse_pae;
use chio_federation::bilateral_dsse::DssePreimageBinding;
use iroh::endpoint::Connection;
use iroh::endpoint::RecvStream;
use iroh::endpoint::SendStream;
use iroh::endpoint::VarInt;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use serde::Deserialize;
use serde::Serialize;

use crate::admission::DirectoryGate;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptLimitError;
use crate::lanes::limits::AcceptLimiter;
use crate::lanes::limits::AcceptPhase;
use crate::lanes::limits::LANE_RESET_CLOSE_CODE;

/// SPEC-FIXED ALPN for the bilateral DSSE co-sign lane (ADAPTER-SPEC 4.2).
pub const ALPN_BILATERAL: &[u8] = b"chio/federation/bilateral-dsse-cosign/1";

/// Hard cap on a single length-delimited frame. A DSSE PAE preimage wraps an
/// in-toto Statement (with an embedded receipt), so a few KiB is typical; the cap
/// is a fail-closed anti-DoS bound, not a tuning knob.
const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// QUIC application close code used when the exchange completes normally.
const CLOSE_OK: u32 = 0;

// ---------------------------------------------------------------------------
// Directory-facing seams (kept above iroh, algorithm-agnostic)
// ---------------------------------------------------------------------------

/// Client-side (Org B) resolver from an Org A `kernel_id` to a dialable
/// [`EndpointAddr`].
///
/// In production this is backed by discovery (an `EndpointId` alone is dialable
/// once discovery/relay is configured); in relay-disabled / loopback deployments
/// it carries the direct socket addresses. It is intentionally distinct from the
/// server's [`crate::identity::VerifiedDirectory`] (which resolves the reverse
/// direction, `EndpointId -> kernel_id`).
pub trait OrgAddressBook: Send + Sync {
    /// The dialable address for a peer `kernel_id`, or `None` when unknown.
    fn address_of(&self, kernel_id: &str) -> Option<EndpointAddr>;
}

impl OrgAddressBook for HashMap<String, EndpointAddr> {
    fn address_of(&self, kernel_id: &str) -> Option<EndpointAddr> {
        self.get(kernel_id).cloned()
    }
}

/// Server-side (Org A) pinned passport keys for the counterparties it may
/// co-sign for, keyed by `kernel_id`.
///
/// This mirrors `InProcessCoSigner`'s single `tool_host_public_key` and serves as
/// Org A's co-signing ALLOWLIST (which admitted peers it will co-sign for). It is
/// NO LONGER the authoritative verification key: Org A verifies Org B's signature
/// over `pae_bytes` against the DIRECTORY-BOUND passport key
/// ([`crate::identity::VerifiedDirectory::resolve_passport_key`]) so verification
/// is pinned to the same issuer-signed snapshot the admission gate authorized on.
/// The key pinned here MUST agree with that binding; a pinned key that lags the
/// signed directory is refused before signing (fail-closed on mismatch/lag). The
/// passport key is deliberately NOT the ed25519 transport `EndpointId` (Option B:
/// a non-ed25519 passport cannot be an `EndpointId`).
pub trait PinnedPassportKeys: Send + Sync {
    /// The pinned passport public key for a peer `kernel_id`, or `None` when the
    /// peer is not a co-signing counterparty.
    fn passport_key(&self, kernel_id: &str) -> Option<PublicKey>;
}

impl PinnedPassportKeys for HashMap<String, PublicKey> {
    fn passport_key(&self, kernel_id: &str) -> Option<PublicKey> {
        self.get(kernel_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Wire mirror types (serde; adapter-local, contracts crate untouched)
// ---------------------------------------------------------------------------

/// Serde mirror of [`DsseCoSigningRequest`] (see module docs). Field-for-field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDsseCoSigningRequest {
    schema: String,
    org_a_kernel_id: String,
    org_b_kernel_id: String,
    /// DSSE PAE preimage; signed and verified verbatim, and reconstructed from
    /// the statement it decodes to before the accept side will sign it.
    pae_bytes: Vec<u8>,
    /// Algorithm-tagged (serde hex); round-trips every passport algorithm.
    org_b_signature: Signature,
}

impl WireDsseCoSigningRequest {
    fn from_request(request: &DsseCoSigningRequest) -> Self {
        Self {
            schema: request.schema.clone(),
            org_a_kernel_id: request.org_a_kernel_id.clone(),
            org_b_kernel_id: request.org_b_kernel_id.clone(),
            pae_bytes: request.pae_bytes.clone(),
            org_b_signature: request.org_b_signature.clone(),
        }
    }

    fn into_request(self) -> DsseCoSigningRequest {
        DsseCoSigningRequest {
            schema: self.schema,
            org_a_kernel_id: self.org_a_kernel_id,
            org_b_kernel_id: self.org_b_kernel_id,
            pae_bytes: self.pae_bytes,
            org_b_signature: self.org_b_signature,
        }
    }
}

/// The single reply frame Org A writes back: either the co-signature or a typed
/// error mirroring [`BilateralCoSigningError`]. A typed error is a valid reply
/// (the peer is reachable and answered), NOT a transport failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum WireReply {
    /// Org A co-signed the exact `pae_bytes`. Mirrors [`DsseCoSigningResponse`].
    Ok {
        schema: String,
        org_a_signature: Signature,
    },
    /// Org A refused (WITHOUT signing). `detail` carries the offending id / reason.
    Err { code: WireErrorCode, detail: String },
}

/// Wire tag mirroring the server-producible [`BilateralCoSigningError`] variants.
/// Every variant is fail-closed; there is no "accepted" error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireErrorCode {
    UnsupportedSchema,
    UnknownPeer,
    PeerExpired,
    OrgBSignatureInvalid,
    /// Any other server-side rejection (folds `TransportFailure`, `PeerRejected`).
    PeerRejected,
}

impl WireErrorCode {
    /// Stable, bounded metric/log reason for this wire error code. Feeds the
    /// `reason` label on `chio_federation_transport_verify_failures_total`.
    fn as_reason(self) -> &'static str {
        match self {
            WireErrorCode::UnsupportedSchema => "unsupported-schema",
            WireErrorCode::UnknownPeer => "unknown-peer",
            WireErrorCode::PeerExpired => "peer-expired",
            WireErrorCode::OrgBSignatureInvalid => "org-b-signature-invalid",
            WireErrorCode::PeerRejected => "peer-rejected",
        }
    }
}

/// OBSERVE-ONLY reason for a co-sign rejection, reusing the exhaustive
/// [`WireReply::err`] mapping so any [`BilateralCoSigningError`] variant folds to
/// one bounded code (never a high-cardinality label).
fn bilateral_reason(error: &BilateralCoSigningError) -> &'static str {
    if let WireReply::Err { code, .. } = WireReply::err(error) {
        code.as_reason()
    } else {
        "peer-rejected"
    }
}

impl WireReply {
    /// Encode a successful co-signature.
    fn ok(response: &DsseCoSigningResponse) -> Self {
        Self::Ok {
            schema: response.schema.clone(),
            org_a_signature: response.org_a_signature.clone(),
        }
    }

    /// Encode a server-side rejection as a typed error frame (no signature).
    fn err(error: &BilateralCoSigningError) -> Self {
        let (code, detail) = match error {
            BilateralCoSigningError::UnsupportedSchema(schema) => {
                (WireErrorCode::UnsupportedSchema, schema.clone())
            }
            BilateralCoSigningError::UnknownPeer(peer) => {
                (WireErrorCode::UnknownPeer, peer.clone())
            }
            BilateralCoSigningError::PeerExpired(peer) => {
                (WireErrorCode::PeerExpired, peer.clone())
            }
            BilateralCoSigningError::OrgBSignatureInvalid => {
                (WireErrorCode::OrgBSignatureInvalid, String::new())
            }
            // Everything else is surfaced to the peer as a rejection with context.
            other => (WireErrorCode::PeerRejected, other.to_string()),
        };
        Self::Err { code, detail }
    }

    /// Client-side: fold a receipt-profile reply frame back into the contract's
    /// Result. Identical to [`Self::into_result`] except that an `Ok` frame must
    /// carry the receipt profile's schema tag, so a reply minted under the DSSE
    /// profile can never be accepted here.
    fn into_receipt_result(self) -> Result<CoSigningResponse, BilateralCoSigningError> {
        match self {
            Self::Ok {
                schema,
                org_a_signature,
            } => {
                if schema != BILATERAL_COSIGNING_SCHEMA {
                    return Err(BilateralCoSigningError::UnsupportedSchema(schema));
                }
                Ok(CoSigningResponse {
                    schema,
                    org_a_signature,
                })
            }
            Self::Err { code, detail } => Err(match code {
                WireErrorCode::UnsupportedSchema => {
                    BilateralCoSigningError::UnsupportedSchema(detail)
                }
                WireErrorCode::UnknownPeer => BilateralCoSigningError::UnknownPeer(detail),
                WireErrorCode::PeerExpired => BilateralCoSigningError::PeerExpired(detail),
                WireErrorCode::OrgBSignatureInvalid => {
                    BilateralCoSigningError::OrgBSignatureInvalid
                }
                WireErrorCode::PeerRejected => BilateralCoSigningError::PeerRejected(detail),
            }),
        }
    }

    /// Client-side: fold the reply frame back into the contract's Result.
    fn into_result(self) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        match self {
            Self::Ok {
                schema,
                org_a_signature,
            } => {
                if schema != BILATERAL_DSSE_COSIGNING_SCHEMA {
                    return Err(BilateralCoSigningError::UnsupportedSchema(schema));
                }
                Ok(DsseCoSigningResponse {
                    schema,
                    org_a_signature,
                })
            }
            Self::Err { code, detail } => Err(match code {
                WireErrorCode::UnsupportedSchema => {
                    BilateralCoSigningError::UnsupportedSchema(detail)
                }
                WireErrorCode::UnknownPeer => BilateralCoSigningError::UnknownPeer(detail),
                WireErrorCode::PeerExpired => BilateralCoSigningError::PeerExpired(detail),
                WireErrorCode::OrgBSignatureInvalid => {
                    BilateralCoSigningError::OrgBSignatureInvalid
                }
                WireErrorCode::PeerRejected => BilateralCoSigningError::PeerRejected(detail),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Length-delimited framing over one bidi stream
// ---------------------------------------------------------------------------

/// Transport/codec failures on the raw stream. Kept separate from
/// [`BilateralCoSigningError`] so it can bridge to both an [`AcceptError`]
/// (server) and `TransportFailure` (client).
#[derive(Debug, thiserror::Error)]
enum WireError {
    #[error("bilateral stream io failed: {0}")]
    Io(String),
    #[error("bilateral frame length {0} exceeds the {max}-byte cap", max = MAX_WIRE_BYTES)]
    FrameTooLarge(usize),
}

/// Fail-closed accept-side failures that RESET the bilateral stream (as opposed
/// to a co-sign rejection, which is delivered in-band as a typed [`WireReply::Err`]
/// and is NOT an error here). Groups the raw framing, codec, transport, and
/// accept-limit (slowloris timeout / saturation shed) failures so the accept
/// handler can close with the right code in one place.
#[derive(Debug, thiserror::Error)]
enum BilateralAcceptError {
    /// A raw length-delimited framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A request could not be decoded / a reply could not be encoded.
    #[error("bilateral codec error: {0}")]
    Codec(#[from] serde_json::Error),
    /// A QUIC accept/finish transport failure.
    #[error("bilateral transport error: {0}")]
    Transport(String),
    /// A peer-dependent accept step exceeded its bound (slowloris) or the
    /// in-flight cap shed the connection.
    #[error(transparent)]
    AcceptLimit(#[from] AcceptLimitError),
}

impl BilateralAcceptError {
    /// Stable, log- and reason-string-friendly code.
    fn code(&self) -> &'static str {
        match self {
            BilateralAcceptError::Wire(_) => "wire",
            BilateralAcceptError::Codec(_) => "codec",
            BilateralAcceptError::Transport(_) => "transport",
            BilateralAcceptError::AcceptLimit(error) => error.code(),
        }
    }

    /// QUIC application close code. Accept-limit outcomes carry their own distinct
    /// codes; every other failure is a generic reset.
    fn close_code(&self) -> u32 {
        match self {
            BilateralAcceptError::AcceptLimit(error) => error.close_code(),
            _ => LANE_RESET_CLOSE_CODE,
        }
    }
}

/// Write one length-delimited frame: a 4-byte big-endian length prefix followed
/// by the payload bytes. The caller `finish()`es the send half afterwards.
async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> Result<(), WireError> {
    let len = u32::try_from(bytes.len()).map_err(|_| WireError::FrameTooLarge(bytes.len()))?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(WireError::FrameTooLarge(bytes.len()));
    }
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
    send.write_all(bytes)
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
    Ok(())
}

/// Read exactly one length-delimited frame written by [`write_frame`].
/// Fail-closed on an over-cap length before allocating.
async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_WIRE_BYTES {
        return Err(WireError::FrameTooLarge(len));
    }
    // Incremental read: grow as bytes arrive, never pre-commit the declared len.
    // `recv` is an iroh (noq) RecvStream, whose inherent `read` yields
    // `Option<usize>` (None == stream finished / EOF).
    const READ_CHUNK: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK));
    let mut remaining = len;
    let mut chunk = [0u8; READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK);
        match recv
            .read(&mut chunk[..want])
            .await
            .map_err(|error| WireError::Io(error.to_string()))?
        {
            Some(0) | None => {
                return Err(WireError::Io(
                    "unexpected eof reading frame body".to_string(),
                ));
            }
            Some(n) => {
                buf.extend_from_slice(&chunk[..n]);
                remaining -= n;
            }
        }
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Client side (Org B): the transport impl of the federation trait
// ---------------------------------------------------------------------------

/// Org B's transport implementation of
/// [`chio_federation::bilateral::BilateralCoSigningProtocol`]. Dials Org A over
/// iroh on [`ALPN_BILATERAL`] and runs the one-shot request/response exchange.
#[derive(Clone)]
pub struct IrohBilateralCoSigner {
    endpoint: Endpoint,
    address_book: Arc<dyn OrgAddressBook>,
    /// Client-side slowloris bounds: every peer-dependent await (connect, open,
    /// write, the reply read) is bounded by the matching phase timeout so an Org A
    /// that accepts but never replies cannot hang the caller forever. Generous by
    /// default; tune via [`IrohBilateralCoSigner::with_accept_limits`].
    limits: AcceptLimitConfig,
    /// QUIC connections this co-signer has opened to Org A, counted across both
    /// profiles and shared by every clone. Read it through
    /// [`IrohBilateralCoSigner::connections_opened`] to observe how many co-sign
    /// hops a workload actually cost instead of inferring the number from the
    /// protocol.
    connections: Arc<AtomicU64>,
    /// Cumulative nanoseconds this co-signer has spent inside
    /// [`Endpoint::connect`] for Org A, across both profiles and shared by every
    /// clone. Read through [`IrohBilateralCoSigner::connect_nanos`]. Paired with
    /// `exchange_nanos` it splits a co-sign hop into the QUIC handshake and the
    /// request/reply that follows it, so a caller can attribute the hop's share
    /// of a latency budget to connection setup rather than infer it.
    connect_nanos: Arc<AtomicU64>,
    /// Cumulative nanoseconds spent in the request/reply exchange on an already
    /// established connection: stream open, request write, reply read and decode.
    /// Excludes the connect above and the connection close that follows.
    exchange_nanos: Arc<AtomicU64>,
}

impl core::fmt::Debug for IrohBilateralCoSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrohBilateralCoSigner")
            .field("endpoint", &self.endpoint.id().fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

impl IrohBilateralCoSigner {
    /// Build the co-signer over a bound iroh [`Endpoint`] and an Org A address
    /// resolver. The client-side waits use the generous [`AcceptLimitConfig::default`]
    /// bounds; tune them via [`Self::with_accept_limits`].
    #[must_use]
    pub fn new(endpoint: Endpoint, address_book: Arc<dyn OrgAddressBook>) -> Self {
        Self {
            endpoint,
            address_book,
            limits: AcceptLimitConfig::default(),
            connections: Arc::new(AtomicU64::new(0)),
            connect_nanos: Arc::new(AtomicU64::new(0)),
            exchange_nanos: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many QUIC connections this co-signer has opened to Org A since it was
    /// built, across the DSSE and receipt profiles. Clones share the counter, so
    /// one handle reports every hop the kernel made through it. Monotone and
    /// saturating.
    #[must_use]
    pub fn connections_opened(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    /// Cumulative nanoseconds spent establishing QUIC connections to Org A,
    /// across both profiles and every clone. Monotone and saturating.
    ///
    /// A co-sign hop is a connect followed by one request/reply exchange. This
    /// counter holds the first half and [`Self::exchange_nanos`] the second, so
    /// the cost of a hop can be split between the handshake and the round trip
    /// instead of being reported as one opaque number.
    #[must_use]
    pub fn connect_nanos(&self) -> u64 {
        self.connect_nanos.load(Ordering::SeqCst)
    }

    /// Cumulative nanoseconds spent in the request/reply exchange on an already
    /// established connection, across both profiles and every clone. Monotone
    /// and saturating. See [`Self::connect_nanos`].
    #[must_use]
    pub fn exchange_nanos(&self) -> u64 {
        self.exchange_nanos.load(Ordering::SeqCst)
    }

    /// Count one opened connection and the time its handshake took.
    fn record_connect(&self, elapsed: core::time::Duration) {
        self.connections.fetch_add(1, Ordering::SeqCst);
        self.connect_nanos.fetch_add(
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Record the time one request/reply exchange took on an open connection.
    fn record_exchange(&self, elapsed: core::time::Duration) {
        self.exchange_nanos.fetch_add(
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Override the default client-side slowloris bounds (per-phase timeouts on
    /// connect / open / write / the reply read). The [`Default`] preserves the
    /// generous behavior; a caller can tighten them in one place.
    #[must_use]
    pub fn with_accept_limits(mut self, limits: AcceptLimitConfig) -> Self {
        self.limits = limits;
        self
    }

    /// Async transport of the co-signing exchange (the recommended entry point).
    ///
    /// Dials Org A, writes the length-delimited request, half-closes, and reads
    /// the reply. Transport/codec failures fold into
    /// [`BilateralCoSigningError::TransportFailure`]; a typed error frame folds
    /// into the mirrored [`BilateralCoSigningError`] variant. The caller verifies
    /// `org_a_signature` over `pae_bytes` (as `sign_dsse_envelope_with_cosigner`
    /// already does), consistent with the in-process contract.
    pub async fn request_dsse_cosignature_over_iroh(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        let addr = self
            .address_book
            .address_of(&request.org_a_kernel_id)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_a_kernel_id.clone()))?;

        let dialed = std::time::Instant::now();
        let connection = client_bounded(
            &self.limits,
            AcceptPhase::AcceptStream,
            self.endpoint.connect(addr, ALPN_BILATERAL),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        self.record_connect(dialed.elapsed());

        let exchanged = std::time::Instant::now();
        let result = self.exchange(&connection, request).await;
        self.record_exchange(exchanged.elapsed());
        connection.close(VarInt::from_u32(CLOSE_OK), b"done");
        result
    }

    /// Async transport of the RECEIPT co-signing exchange (profile 2).
    ///
    /// This is the hop `ChioKernel::apply_federation_cosign` makes first, through
    /// `chio_federation::bilateral::co_sign_with_origin`, before the DSSE hop. Org B
    /// re-derives the canonical [`CoSigningBody`] bytes from the receipt it is
    /// holding and sends those bytes verbatim, so Org A signs exactly what Org B
    /// signed. The caller verifies `org_a_signature` over the same bytes, which
    /// `co_sign_with_origin` already does.
    pub async fn request_cosignature_over_iroh(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        if request.schema != BILATERAL_COSIGNING_SCHEMA {
            return Err(BilateralCoSigningError::UnsupportedSchema(
                request.schema.clone(),
            ));
        }
        let body = CoSigningBody::from_receipt(
            &request.body,
            &request.org_a_kernel_id,
            &request.org_b_kernel_id,
        )?;
        let body_bytes = body.canonical_bytes()?;

        let addr = self
            .address_book
            .address_of(&request.org_a_kernel_id)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_a_kernel_id.clone()))?;

        let dialed = std::time::Instant::now();
        let connection = client_bounded(
            &self.limits,
            AcceptPhase::AcceptStream,
            self.endpoint.connect(addr, ALPN_BILATERAL_RECEIPT_COSIGN),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        self.record_connect(dialed.elapsed());

        let exchanged = std::time::Instant::now();
        let result = self
            .receipt_exchange(&connection, request, body_bytes)
            .await;
        self.record_exchange(exchanged.elapsed());
        connection.close(VarInt::from_u32(CLOSE_OK), b"done");
        result
    }

    /// The receipt-profile bidi write-request / read-reply half, factored out so
    /// the connection is always closed exactly once by the caller.
    async fn receipt_exchange(
        &self,
        connection: &Connection,
        request: &CoSigningRequest,
        body_bytes: Vec<u8>,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        let (mut send, mut recv) = client_bounded(
            &self.limits,
            AcceptPhase::AcceptStream,
            connection.open_bi(),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let wire = WireReceiptCoSigningRequest {
            schema: request.schema.clone(),
            org_a_kernel_id: request.org_a_kernel_id.clone(),
            org_b_kernel_id: request.org_b_kernel_id.clone(),
            body_bytes,
            org_b_signature: request.org_b_signature.clone(),
        };
        let request_bytes = serde_json::to_vec(&wire)
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        client_bounded(
            &self.limits,
            AcceptPhase::WriteResponse,
            write_frame(&mut send, &request_bytes),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        send.finish()
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let reply_bytes =
            client_bounded(&self.limits, AcceptPhase::ReadFrame, read_frame(&mut recv))
                .await?
                .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        let reply: WireReply = serde_json::from_slice(&reply_bytes)
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        reply.into_receipt_result()
    }

    /// The bidi write-request / read-reply half, factored out so the connection
    /// is always closed exactly once by the caller regardless of outcome.
    async fn exchange(
        &self,
        connection: &Connection,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        let (mut send, mut recv) = client_bounded(
            &self.limits,
            AcceptPhase::AcceptStream,
            connection.open_bi(),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let request_bytes = serde_json::to_vec(&WireDsseCoSigningRequest::from_request(request))
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        client_bounded(
            &self.limits,
            AcceptPhase::WriteResponse,
            write_frame(&mut send, &request_bytes),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        send.finish()
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        // The primary client-side hang surface: an Org A that accepts the request but
        // never returns the reply frame is dropped here at the read bound.
        let reply_bytes =
            client_bounded(&self.limits, AcceptPhase::ReadFrame, read_frame(&mut recv))
                .await?
                .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        let reply: WireReply = serde_json::from_slice(&reply_bytes)
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        reply.into_result()
    }
}

/// Bound one peer-dependent client await by the phase's timeout, mirroring the
/// accept-side [`AcceptLimiter::bounded`]. On timeout this fails closed with a
/// [`BilateralCoSigningError::TransportFailure`] so an Org A that accepts but never
/// replies can no longer hang the caller forever.
async fn client_bounded<T, F>(
    limits: &AcceptLimitConfig,
    phase: AcceptPhase,
    fut: F,
) -> Result<T, BilateralCoSigningError>
where
    F: std::future::Future<Output = T>,
{
    let bound = limits.phase_timeout(phase);
    match tokio::time::timeout(bound, fut).await {
        Ok(output) => Ok(output),
        Err(_elapsed) => Err(BilateralCoSigningError::TransportFailure(format!(
            "bilateral co-sign {phase} exceeded its {}ms client bound",
            bound.as_millis()
        ))),
    }
}

/// Drive one async lane exchange from the synchronous
/// [`BilateralCoSigningProtocol`] contract. On a multi-threaded tokio runtime the
/// blocking wait moves off the async worker with `block_in_place`; off a runtime
/// entirely a private current-thread runtime is spun up for the call. On a
/// CURRENT-THREAD runtime `block_in_place` would panic, so the bridge fails closed
/// with a typed error naming the async method the caller should have used.
fn block_on_lane<T, F>(
    exchange: impl FnOnce() -> F,
    method: &str,
) -> Result<T, BilateralCoSigningError>
where
    F: std::future::Future<Output = Result<T, BilateralCoSigningError>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(exchange()))
            }
            _ => Err(BilateralCoSigningError::TransportFailure(format!(
                "{method} invoked on a current-thread tokio runtime; call \
                 {method}_over_iroh (async) instead of blocking"
            ))),
        },
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
            runtime.block_on(exchange())
        }
    }
}

impl BilateralCoSigningProtocol for IrohBilateralCoSigner {
    /// Synchronous contract entry point for the receipt profile. Bridges to
    /// [`Self::request_cosignature_over_iroh`] under the same runtime rules as
    /// [`Self::request_dsse_cosignature`]: `block_in_place` on a multi-threaded
    /// runtime, a private runtime off-runtime, and a typed `TransportFailure` on a
    /// current-thread runtime rather than the panic `block_in_place` would raise.
    fn request_cosignature(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        block_on_lane(
            || self.request_cosignature_over_iroh(request),
            "request_cosignature",
        )
    }

    /// Synchronous contract entry point. Bridges to
    /// [`Self::request_dsse_cosignature_over_iroh`]. Works from a multi-threaded
    /// tokio runtime (uses `block_in_place`) or from a plain non-async thread
    /// (spins a private current-thread runtime). On a CURRENT-THREAD tokio runtime
    /// it returns a `TransportFailure` error instead of panicking (`block_in_place`
    /// is unsupported there). Prefer the async method inside async code.
    fn request_dsse_cosignature(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        block_on_lane(
            || self.request_dsse_cosignature_over_iroh(request),
            "request_dsse_cosignature",
        )
    }
}

// ---------------------------------------------------------------------------
// Server side (Org A): the ProtocolHandler behind the admission gate
// ---------------------------------------------------------------------------

/// Org A's accept-side handler. Mounted on a `Router` at [`ALPN_BILATERAL`]
/// behind the [`DirectoryGate`] hook. Performs exactly the verification
/// `InProcessCoSigner::request_dsse_cosignature` does, plus the transport-origin
/// binding (the authenticated `EndpointId` must resolve to the claimed
/// `org_b_kernel_id`).
pub struct BilateralCoSignHandler {
    /// Resolves the authenticated `EndpointId` to its admitted `kernel_id`
    /// (shares the exact resolution the accept-time gate admitted on).
    gate: DirectoryGate,
    /// This server's own (Org A) `kernel_id`.
    origin_kernel_id: String,
    /// Org A's co-signing keypair. Mirrors `InProcessCoSigner::origin_keypair`;
    /// Org A signs `pae_bytes` with `Ed25519Backend`.
    origin_keypair: Keypair,
    /// Pinned Org B passport keys (algorithm-agnostic), keyed by `kernel_id`.
    passport_keys: Arc<dyn PinnedPassportKeys>,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
}

impl core::fmt::Debug for BilateralCoSignHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material.
        f.debug_struct("BilateralCoSignHandler")
            .field("origin_kernel_id", &self.origin_kernel_id)
            .finish_non_exhaustive()
    }
}

impl BilateralCoSignHandler {
    /// Build the handler from the shared admission gate, Org A's identity + signing
    /// key, and the pinned Org B passport keys.
    #[must_use]
    pub fn new(
        gate: DirectoryGate,
        origin_kernel_id: impl Into<String>,
        origin_keypair: Keypair,
        passport_keys: Arc<dyn PinnedPassportKeys>,
    ) -> Self {
        Self {
            gate,
            origin_kernel_id: origin_kernel_id.into(),
            origin_keypair,
            passport_keys,
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

    /// Pure verification + co-signature, decoupled from the stream so the
    /// fail-closed no-signature paths are unit-testable without a live handshake.
    ///
    /// Mirrors `InProcessCoSigner::request_dsse_cosignature` (schema, origin,
    /// Org B signature, sign the same bytes) and adds step-4's transport-origin
    /// binding: the authenticated `remote` `EndpointId` must resolve, through the
    /// verified directory, to the request's declared `org_b_kernel_id`.
    fn cosign(
        &self,
        remote: &EndpointId,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        // OBSERVE-ONLY wrapper: the verification + co-signature logic is unchanged
        // in `cosign_inner`; here we count + log a rejection (OrgBSignatureInvalid,
        // UnknownPeer origin/endpoint mismatch, PeerExpired) ALONGSIDE it and
        // return the SAME `Result` the caller folds into a typed WireReply::Err.
        let result = self.cosign_inner(remote, request);
        if let Err(error) = &result {
            let reason = bilateral_reason(error);
            crate::metrics::record_verify_failure(crate::metrics::SEAM_BILATERAL, reason);
            tracing::warn!(
                target: crate::observability::TARGET_VERIFY,
                seam = crate::metrics::SEAM_BILATERAL,
                reason = reason,
                "bilateral co-sign refused without signing"
            );
        }
        result
    }

    fn cosign_inner(
        &self,
        remote: &EndpointId,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        if request.schema != BILATERAL_DSSE_COSIGNING_SCHEMA {
            return Err(BilateralCoSigningError::UnsupportedSchema(
                request.schema.clone(),
            ));
        }
        // Sign the exact pae_bytes the peer sent, once the shared accept-side
        // decision has bound the transport origin to the claimed peer, verified Org
        // B's signature over those exact bytes, and reconstructed them as this
        // profile's preimage.
        let org_a_signature = cosign_bytes(
            CoSignAuthority {
                gate: &self.gate,
                origin_kernel_id: &self.origin_kernel_id,
                origin_keypair: &self.origin_keypair,
                passport_keys: self.passport_keys.as_ref(),
            },
            CoSignSubject {
                remote,
                org_a_kernel_id: &request.org_a_kernel_id,
                org_b_kernel_id: &request.org_b_kernel_id,
                signed_bytes: &request.pae_bytes,
                org_b_signature: &request.org_b_signature,
                profile: CoSignProfile::DssePreAuthentication,
            },
        )?;
        Ok(DsseCoSigningResponse {
            schema: BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
            org_a_signature,
        })
    }
}

impl BilateralCoSignHandler {
    /// One bounded request/response exchange. Every peer-dependent await is
    /// bounded (accept_bi, the request-frame read, the reply write). A co-sign
    /// REJECTION is delivered IN-BAND as a typed [`WireReply::Err`] (never a
    /// signature) and returns `Ok`; only genuine transport / codec / timeout
    /// failures return `Err` and reset the stream.
    async fn serve(&self, connection: &Connection) -> Result<(), BilateralAcceptError> {
        // Infallible after the handshake; the gate hook has already run.
        let remote = connection.remote_id();
        // Bound accept_bi: a connected-but-silent peer is dropped here.
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, connection.accept_bi())
            .await?
            .map_err(|error| BilateralAcceptError::Transport(error.to_string()))?;

        // Step 3: read the single length-delimited request (bounded: the primary
        // slowloris surface).
        let request_bytes = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        let wire_request: WireDsseCoSigningRequest = serde_json::from_slice(&request_bytes)?;
        let request = wire_request.into_request();

        // Step 4/5: verify + co-sign (or a typed error mirroring the contract).
        // Verification runs on the fully received request; timeouts never weaken it.
        let reply = match self.cosign(&remote, &request) {
            Ok(response) => WireReply::ok(&response),
            Err(error) => WireReply::err(&error),
        };
        let reply_bytes = serde_json::to_vec(&reply)?;
        // Bound the reply write: a peer that stops reading is dropped here.
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &reply_bytes),
            )
            .await??;
        send.finish()
            .map_err(|error| BilateralAcceptError::Transport(error.to_string()))?;
        Ok(())
    }
}

impl ProtocolHandler for BilateralCoSignHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        use tracing::Instrument;
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code.
        let _permit = match self.limiter.admit_peer(&connection.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_BILATERAL,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "bilateral lane shed accept (saturated)"
                );
                connection.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_BILATERAL);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_BILATERAL);
        let started = std::time::Instant::now();
        let result = self.serve(&connection).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_BILATERAL,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_BILATERAL,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                // Bounded linger: keep the connection until the client has read
                // the reply and closed (so the framed response is not truncated
                // by an early drop), but never past the linger bound.
                self.limiter.linger(&connection).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_BILATERAL, outcome);
                crate::observability::record_outcome(&span, outcome);
                tracing::warn!(code = error.code(), error = %error, "bilateral lane reset");
                connection.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Profile 2 (receipt co-sign): the kernel's detached `CoSigningBody` hop
// ---------------------------------------------------------------------------

/// SPEC-FIXED ALPN for the receipt co-sign profile of lane d.
///
/// An admitted federated call makes TWO co-signing round trips: the kernel first
/// asks Org A to sign the canonical [`chio_federation::bilateral::CoSigningBody`]
/// of the receipt it just signed (`request_cosignature`), and only then asks for
/// the DSSE PAE signature (`request_dsse_cosignature`). The two profiles sign
/// different preimages under different schema tags, so they ride separate ALPNs
/// and separate handlers; neither can be replayed as the other.
pub const ALPN_BILATERAL_RECEIPT_COSIGN: &[u8] = b"chio/federation/bilateral-receipt-cosign/1";

/// Serde wire frame for the receipt co-sign profile.
///
/// The frame carries the canonical [`chio_federation::bilateral::CoSigningBody`]
/// bytes rather than the receipt, so Org A signs the exact bytes Org B signed. Org
/// B derives the bytes from the receipt it is holding, and Org A re-derives them
/// from the receipt those bytes carry before it will sign: a byte-level
/// disagreement between the two sides fails closed without a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireReceiptCoSigningRequest {
    schema: String,
    org_a_kernel_id: String,
    org_b_kernel_id: String,
    /// Canonical JSON of the `CoSigningBody`; signed and verified verbatim, and
    /// re-derived from the receipt it carries before the accept side will sign it.
    body_bytes: Vec<u8>,
    /// Algorithm-tagged (serde hex); round-trips every passport algorithm.
    org_b_signature: Signature,
}

/// Everything the accept side needs to decide whether it will co-sign at all.
struct CoSignAuthority<'a> {
    gate: &'a DirectoryGate,
    origin_kernel_id: &'a str,
    origin_keypair: &'a Keypair,
    passport_keys: &'a dyn PinnedPassportKeys,
}

/// Which preimage family the bytes of an exchange must reconstruct as.
///
/// The co-signing key also signs receipts, so the profile is what keeps this
/// endpoint from being a signing oracle for the other preimage families the
/// key covers. Every profile of the lane names one here; there is no variant
/// that signs bytes without reconstructing them.
#[derive(Debug, Clone, Copy)]
enum CoSignProfile {
    /// Canonical `chio_federation::bilateral::CoSigningBody`.
    ReceiptCoSigningBody,
    /// DSSE v1 pre-authentication encoding of an in-toto bilateral statement.
    DssePreAuthentication,
}

/// The one exchange being decided: who is asking, for whom, over which bytes,
/// under which preimage profile.
struct CoSignSubject<'a> {
    remote: &'a EndpointId,
    org_a_kernel_id: &'a str,
    org_b_kernel_id: &'a str,
    signed_bytes: &'a [u8],
    org_b_signature: &'a Signature,
    profile: CoSignProfile,
}

/// Shared accept-side decision for both profiles of lane d: bind the
/// authenticated transport origin to the claimed peer, verify Org B's signature
/// over the exact bytes it sent under the directory-bound passport key,
/// reconstruct those bytes as the preimage the profile expects, and return Org
/// A's signature over them.
///
/// The bytes are never opaque here. Who is allowed to obtain a signature and
/// what a signature may cover are both decided in this one function, because
/// either one alone is insufficient: the same key signs receipts and DSSE
/// statements, so an admitted peer that can choose the bytes can choose which
/// preimage family it walks away with a signature over.
fn cosign_bytes(
    authority: CoSignAuthority<'_>,
    subject: CoSignSubject<'_>,
) -> Result<Signature, BilateralCoSigningError> {
    // This server must be the origin (Org A) the request is addressed to.
    if subject.org_a_kernel_id != authority.origin_kernel_id {
        return Err(BilateralCoSigningError::UnknownPeer(
            subject.org_a_kernel_id.to_string(),
        ));
    }
    // ONE directory snapshot for the WHOLE verification. Load the current verified
    // directory ONCE and use it for BOTH the transport-origin
    // authorization AND the passport-key lookup. Consulting the gate twice (a
    // `resolve` for the endpoint, then a separate `directory()` for the key) could
    // straddle a live directory reload: the endpoint might authorize against the OLD
    // directory while the key is read from the NEW one. In the endpoint-rotation case
    // where the new directory keeps the same passport key for that kernel but no longer
    // binds its `EndpointId`, the co-signature would verify even though the CURRENT
    // directory no longer authorizes the remote endpoint. Holding one owned snapshot Arc
    // (ArcSwap `load_full`) also keeps the backing directory alive for the borrowed key.
    let directory = authority.gate.directory();
    // Transport-origin binding: the authenticated EndpointId must resolve to the claimed
    // Org B kernel id IN THIS SNAPSHOT. `authorize` returns None for unbound/removed
    // peers (trust + rotation window at the directory layer); the gate should already
    // have rejected those at handshake, so None here is defense in depth. A
    // resolved-but-mismatched id means the caller claimed to be a different peer than it
    // authenticated as: fail closed.
    let resolved = directory
        .authorize(subject.remote)
        .ok_or_else(|| BilateralCoSigningError::UnknownPeer(subject.org_b_kernel_id.to_string()))?;
    if resolved != subject.org_b_kernel_id {
        return Err(BilateralCoSigningError::UnknownPeer(
            subject.org_b_kernel_id.to_string(),
        ));
    }
    // Org B's passport key (any algorithm), read from the SAME issuer-signed snapshot
    // the endpoint was just authorized against. Sourcing the verification key from
    // the verified directory (not only a separately-fed pinned map that can lag it) means
    // a rotated-away / revoked passport - one the current directory no longer binds - can
    // never be used to obtain Org A's co-signature. Fail-closed: an unknown or removed
    // peer has no directory-bound passport key.
    let directory_key = directory
        .resolve_passport_key(subject.org_b_kernel_id)
        .ok_or_else(|| BilateralCoSigningError::UnknownPeer(subject.org_b_kernel_id.to_string()))?;
    // The pinned map is Org A's co-signing allowlist (which admitted peers it
    // will co-sign for): the peer MUST be pinned. Defense in depth: the pinned
    // key MUST also agree with the directory's current binding. A pinned key
    // that lags the signed directory (differs from the current binding) is
    // refused BEFORE signing rather than silently overriding the verified
    // snapshot - fail-closed on mismatch/lag.
    let pinned_key = authority
        .passport_keys
        .passport_key(subject.org_b_kernel_id)
        .ok_or_else(|| BilateralCoSigningError::UnknownPeer(subject.org_b_kernel_id.to_string()))?;
    if pinned_key != *directory_key {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    // Verify Org B's signature over the exact bytes against the directory-bound
    // key (above iroh; the pinned map having been proven to match it).
    if !directory_key.verify(subject.signed_bytes, subject.org_b_signature) {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    // Recompute and refuse, immediately above the signature and on every
    // profile: parse the bytes as the content this profile signs, re-derive
    // their canonical encoding from that content, and refuse unless the two
    // agree byte for byte. An admitted peer authenticating bytes of its own
    // choosing is otherwise enough to obtain this kernel's signature over any
    // preimage its key covers, including the canonical signing preimage of a
    // receipt the peer invented and attributed to this kernel.
    let origin_public_key = authority.origin_keypair.public_key();
    match subject.profile {
        CoSignProfile::ReceiptCoSigningBody => {
            reconstruct_cosigning_body(
                subject.signed_bytes,
                subject.org_a_kernel_id,
                subject.org_b_kernel_id,
            )?;
        }
        CoSignProfile::DssePreAuthentication => {
            reconstruct_dsse_pae(
                subject.signed_bytes,
                DssePreimageBinding {
                    org_a_kernel_id: subject.org_a_kernel_id,
                    org_a_public_key: &origin_public_key,
                    org_b_kernel_id: subject.org_b_kernel_id,
                    org_b_public_key: directory_key,
                },
            )?;
        }
    }

    // Success: sign the reconstructed bytes.
    let backend = Ed25519Backend::new(authority.origin_keypair.clone());
    backend
        .sign_bytes(subject.signed_bytes)
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))
}

/// Org A's accept-side handler for the receipt co-sign profile. Mounted on
/// `Router::builder(ep).accept(ALPN_BILATERAL_RECEIPT_COSIGN, handler)` behind the
/// same [`DirectoryGate`] as the DSSE profile.
///
/// Performs exactly the verification `InProcessCoSigner::request_cosignature`
/// does, plus the transport-origin binding. It signs the canonical
/// `CoSigningBody` bytes the peer sent, but only after re-deriving them from the
/// receipt those bytes carry, so the signature covers content this kernel
/// reconstructed rather than bytes it was handed.
pub struct BilateralReceiptCoSignHandler {
    gate: DirectoryGate,
    origin_kernel_id: String,
    origin_keypair: Keypair,
    passport_keys: Arc<dyn PinnedPassportKeys>,
    limiter: AcceptLimiter,
}

impl core::fmt::Debug for BilateralReceiptCoSignHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material.
        f.debug_struct("BilateralReceiptCoSignHandler")
            .field("origin_kernel_id", &self.origin_kernel_id)
            .finish_non_exhaustive()
    }
}

impl BilateralReceiptCoSignHandler {
    /// Build the handler from the shared admission gate, Org A's identity and
    /// signing key, and the pinned Org B passport keys.
    #[must_use]
    pub fn new(
        gate: DirectoryGate,
        origin_kernel_id: impl Into<String>,
        origin_keypair: Keypair,
        passport_keys: Arc<dyn PinnedPassportKeys>,
    ) -> Self {
        Self {
            gate,
            origin_kernel_id: origin_kernel_id.into(),
            origin_keypair,
            passport_keys,
            limiter: AcceptLimiter::default(),
        }
    }

    /// Override the default accept-hardening bounds (per-phase timeouts + the
    /// in-flight concurrency cap).
    #[must_use]
    pub fn with_accept_limits(mut self, config: AcceptLimitConfig) -> Self {
        self.limiter = AcceptLimiter::new(config);
        self
    }

    /// Pure verification + co-signature, decoupled from the stream so the
    /// fail-closed no-signature paths are unit-testable without a live handshake.
    fn cosign(
        &self,
        remote: &EndpointId,
        request: &WireReceiptCoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        let result = self.cosign_inner(remote, request);
        if let Err(error) = &result {
            let reason = bilateral_reason(error);
            crate::metrics::record_verify_failure(crate::metrics::SEAM_BILATERAL, reason);
            tracing::warn!(
                target: crate::observability::TARGET_VERIFY,
                seam = crate::metrics::SEAM_BILATERAL,
                reason = reason,
                "bilateral receipt co-sign refused without signing"
            );
        }
        result
    }

    fn cosign_inner(
        &self,
        remote: &EndpointId,
        request: &WireReceiptCoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        if request.schema != BILATERAL_COSIGNING_SCHEMA {
            return Err(BilateralCoSigningError::UnsupportedSchema(
                request.schema.clone(),
            ));
        }
        let org_a_signature = cosign_bytes(
            CoSignAuthority {
                gate: &self.gate,
                origin_kernel_id: &self.origin_kernel_id,
                origin_keypair: &self.origin_keypair,
                passport_keys: self.passport_keys.as_ref(),
            },
            CoSignSubject {
                remote,
                org_a_kernel_id: &request.org_a_kernel_id,
                org_b_kernel_id: &request.org_b_kernel_id,
                signed_bytes: &request.body_bytes,
                org_b_signature: &request.org_b_signature,
                profile: CoSignProfile::ReceiptCoSigningBody,
            },
        )?;
        Ok(CoSigningResponse {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            org_a_signature,
        })
    }

    /// One bounded request/response exchange. A co-sign REJECTION is delivered
    /// IN-BAND as a typed [`WireReply::Err`] (never a signature) and returns `Ok`;
    /// only genuine transport / codec / timeout failures reset the stream.
    async fn serve(&self, connection: &Connection) -> Result<(), BilateralAcceptError> {
        let remote = connection.remote_id();
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, connection.accept_bi())
            .await?
            .map_err(|error| BilateralAcceptError::Transport(error.to_string()))?;

        let request_bytes = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        let request: WireReceiptCoSigningRequest = serde_json::from_slice(&request_bytes)?;

        let reply = match self.cosign(&remote, &request) {
            Ok(response) => WireReply::Ok {
                schema: response.schema,
                org_a_signature: response.org_a_signature,
            },
            Err(error) => WireReply::err(&error),
        };
        let reply_bytes = serde_json::to_vec(&reply)?;
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &reply_bytes),
            )
            .await??;
        send.finish()
            .map_err(|error| BilateralAcceptError::Transport(error.to_string()))?;
        Ok(())
    }
}

impl ProtocolHandler for BilateralReceiptCoSignHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        use tracing::Instrument;
        let _permit = match self.limiter.admit_peer(&connection.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_BILATERAL,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "bilateral receipt lane shed accept (saturated)"
                );
                connection.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_BILATERAL);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_BILATERAL);
        let started = std::time::Instant::now();
        let result = self.serve(&connection).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_BILATERAL,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_BILATERAL,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                self.limiter.linger(&connection).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_BILATERAL, outcome);
                crate::observability::record_outcome(&span, outcome);
                tracing::warn!(code = error.code(), error = %error, "bilateral receipt lane reset");
                connection.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests;
