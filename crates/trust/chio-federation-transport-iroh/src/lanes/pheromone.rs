//! Lane a: pheromone directed batches over a direct per-peer QUIC stream.
//! ADAPTER-SPEC section 4 row (a) + section 3.3; blueprint LANE A.
//!
//! This is the iroh migration of the shipped `chio-pheromone-relay` HTTP
//! transport. It swaps exactly one hop: on the shipped HTTP path the
//! `authenticated_sender_kernel_id` handed to
//! [`RelayBatchReceiver::receive_batch`] comes from HTTP-signature verification;
//! here it comes from the admission-resolved `kernel_id` bound to the
//! cryptographically authenticated iroh `EndpointId` (`conn.remote_id()`).
//! Everything below that seam (`receive_batch` -> receiver config -> per-frame
//! `chio-federation` verifier) is REUSED byte-for-byte, so the per-frame checks
//! at `pheromone_gossip.rs:236` (`gossiping_peer_kernel_id == authenticated
//! sender`) and `:244` (direct `origin_kernel_id == authenticated sender`) run
//! ABOVE the transport, unchanged.
//!
//! Defense in depth (ADAPTER-SPEC section 5, ADR-0014 Drop-In Seam step 3): the
//! accept-time [`DirectoryGate`](crate::admission::DirectoryGate) rejects
//! unbound endpoints at `after_handshake` BEFORE any handler runs, AND the
//! handler re-resolves `conn.remote_id()` (fail-closed) before feeding the
//! per-frame verifier. Both layers are kept.
//!
//! Store-and-forward reuses the shipped `SqlitePheromoneRelayStore` outbox/inbox
//! verbatim (blueprint LANE A.3): [`enqueue_batch_for_delivery`] enqueues on
//! flush, [`drain_outbox_over_iroh`] mirrors `deliver_due_batches`
//! (`service.rs:609`) with the ONLY substitution being an iroh `open_bi` write
//! in place of the HTTP `post_batch`, and the handler records the inbox for
//! idempotent dedup.
//!
//! Note on the seam boundary: `PheromoneReceiveReport` lives in
//! `chio-pheromone-runtime`, which is not a direct dependency of this adapter
//! (only `chio-pheromone-relay` is). The handler therefore never names that type
//! (it flows through by inference from [`RelayBatchReceiver::receive_batch`]),
//! and the dial side exposes the peer's report as raw canonical bytes plus the
//! parsed `accepted` flag ([`BatchDeliveryOutcome`]).

use std::fmt;
use std::sync::Arc;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_pheromone_relay::PheromoneRelayError;
use chio_pheromone_relay::RelayBatchReceiver;
use chio_pheromone_relay::RelayOutboxBatch;
use chio_pheromone_relay::SqlitePheromoneRelayStore;
use iroh::endpoint::Connection;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use crate::admission::DirectoryGate;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptLimitError;
use crate::lanes::limits::AcceptLimiter;
use crate::lanes::limits::AcceptPhase;

/// ALPN for the pheromone directed-batch lane. Distinct, versioned, mounted on
/// its own `Router` accept (ADAPTER-SPEC 4 lane a, blueprint A.2).
pub const ALPN_PHEROMONE_BATCH: &[u8] = b"chio/federation/pheromone-batch/1";

/// Hard cap on a single length-delimited frame (request batch or response
/// report). Fail-closed: a larger declared length is rejected before any
/// allocation, so a peer cannot force an unbounded buffer.
pub const MAX_PHEROMONE_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// QUIC application close code used when the handler resets a stream after a
/// fail-closed lane error (distinct from the admission gate's 403).
pub const LANE_RESET_ERROR_CODE: u32 = 1;

/// QUIC application close code used on a clean dial-side teardown.
const LANE_OK_CODE: u32 = 0;

/// Bounded wait, on the LOSER of a concurrent receive-slot reservation, for the
/// winner to record its durable verdict. The loser never re-runs the receiver; it
/// polls the inbox this many times, sleeping [`DEDUP_WAIT_BACKOFF`] between tries,
/// then fails closed (the peer retries and hits the recorded verdict). The product
/// (a few seconds) comfortably covers one `receive_batch` + `record_inbox`.
const DEDUP_WAIT_ATTEMPTS: u32 = 150;

/// Backoff between inbox polls while the loser waits for the winner's verdict.
const DEDUP_WAIT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

/// Inbound directory-scope gate applied on the iroh ingress path BEFORE
/// [`RelayBatchReceiver::receive_batch`], mirroring the HTTP relay's
/// `enforce_peer_batch_directory_scope` (`service.rs`). Supplied by the wiring so
/// this crate never names `PeerDirectory`; it MUST be evaluated against the CURRENT
/// peer directory and fail closed on any out-of-scope sender (not an `Origin`/`Hub`,
/// over its per-peer frame cap, unsubscribed from the batch treaty, or carrying an
/// unpinned transit ladder). Its `Err` folds into [`IrohLaneError::Relay`] and
/// resets the stream, exactly as the HTTP path rejects the same peer.
pub type InboundBatchScopeCheck =
    Arc<dyn Fn(&str, &PheromoneGossipBatch) -> Result<(), PheromoneRelayError> + Send + Sync>;

/// Errors raised inside the pheromone lane. Every variant is fail-closed: an
/// error denies the batch (handler side resets the stream; sender side folds
/// into the durable outbox retry/dead-letter path via [`IrohLaneError::code`]).
#[derive(Debug, thiserror::Error)]
pub enum IrohLaneError {
    /// An endpoint that the admission gate should already have rejected reached
    /// the handler and did not resolve to an admitted, non-removed `kernel_id`.
    /// Unreachable past the gate; treated as a defense-in-depth reset.
    #[error("unadmitted endpoint reached pheromone lane handler: {0}")]
    Unadmitted(String),
    /// A length-delimited frame declared or carried more than
    /// [`MAX_PHEROMONE_BATCH_BYTES`] bytes.
    #[error("pheromone batch frame of {0} bytes exceeds the transport cap")]
    FrameTooLarge(usize),
    /// A stream read/write (framing) io error.
    #[error("pheromone lane io error: {0}")]
    Io(#[from] std::io::Error),
    /// A batch or report failed JSON (de)serialization.
    #[error("pheromone lane codec error: {0}")]
    Codec(#[from] serde_json::Error),
    /// Canonical-JSON encoding of an outbound value failed.
    #[error("pheromone lane canonical-json error: {0}")]
    CanonicalJson(String),
    /// An iroh transport failure (connect, open/accept stream, finish, reset).
    #[error("pheromone lane transport error: {0}")]
    Transport(String),
    /// The reused relay receiver / store rejected the batch (the per-frame
    /// verifier and inbox dedup live behind this seam).
    #[error("pheromone relay error: {0}")]
    Relay(#[from] PheromoneRelayError),
    /// A concurrent connection holds the receive slot for this exact batch and had
    /// not yet recorded its verdict within the bounded dedup wait. Fail-closed: the
    /// stream is reset WITHOUT re-running the receiver (re-running would double-
    /// mutate the runtime replay window); the peer retries and hits the recorded
    /// verdict via the durable inbox.
    #[error("pheromone batch dedup in-flight: {0}")]
    DedupInFlight(String),
    /// A peer-dependent accept step exceeded its bound (slowloris) or the
    /// in-flight cap shed the connection. Fail-closed: the connection is reset
    /// and NOTHING is verified or accepted.
    #[error(transparent)]
    AcceptLimit(#[from] AcceptLimitError),
}

impl IrohLaneError {
    /// Stable, log- and outbox-friendly code for this error. Relay failures
    /// delegate to [`PheromoneRelayError::code`] so the durable queue records
    /// the same code the shipped HTTP path would.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unadmitted(_) => "unadmitted",
            Self::FrameTooLarge(_) => "frame_too_large",
            Self::Io(_) => "io",
            Self::Codec(_) => "codec",
            Self::CanonicalJson(_) => "canonical_json",
            Self::Transport(_) => "transport",
            Self::Relay(error) => error.code(),
            Self::DedupInFlight(_) => "dedup_in_flight",
            Self::AcceptLimit(error) => error.code(),
        }
    }

    /// QUIC application close code for a fail-closed reset. Accept-limit outcomes
    /// (slowloris timeout / saturation shed) carry their own distinct codes so a
    /// stalled or shed peer is diagnosable on the wire; every other lane error is
    /// a generic reset.
    #[must_use]
    pub fn close_code(&self) -> u32 {
        match self {
            Self::AcceptLimit(error) => error.close_code(),
            _ => LANE_RESET_ERROR_CODE,
        }
    }
}

/// Re-resolve the authenticated `EndpointId` to its admitted `kernel_id`.
///
/// The admission gate has already guaranteed (fail-closed, at `after_handshake`)
/// that only bound, non-removed endpoints reach a handler, so this normally
/// yields `Some`; a `None` here is an unreachable defense-in-depth reset. The
/// returned string is the ONLY value the transport contributes to the per-frame
/// verifier's `authenticated_sender_kernel_id`.
fn resolve_authenticated_sender(
    gate: &DirectoryGate,
    remote: &EndpointId,
) -> Result<String, IrohLaneError> {
    gate.resolve(remote)
        .ok_or_else(|| IrohLaneError::Unadmitted(remote.fmt_short().to_string()))
}

/// Deterministic inbox nonce for a batch, so redelivery of the same batch dedups
/// idempotently at `record_inbox` (keyed on `(sender_kernel_id, nonce)`). Uses
/// the canonical batch hash, matching the store's own `batch_sha256`.
fn inbox_nonce(batch_bytes: &[u8]) -> String {
    format!("iroh-pheromone-batch:{}", sha256_hex(batch_bytes))
}

/// RAII holder for an inbox receive-slot reservation (`reserve_inbox_slot`).
///
/// The reservation is the dedup primitive that makes concurrent delivery of the
/// SAME batch receive it exactly once. Its lifecycle is subtle because
/// [`RelayBatchReceiver::receive_batch`] SELF-COMMITS its runtime mutation
/// (admitting the deposits) internally, so the instant of commit sits BETWEEN the
/// reservation and the durable inbox record:
///
/// - While ARMED (before the receive commits), dropping this guard RELEASES the
///   slot. This covers the receive-failed `?`-return AND an accept-task
///   cancel/panic (a `Router` shutdown or connection close cancels the accept
///   future): nothing was committed, so a redelivery may re-claim and re-receive.
///   Without this, a cancelled/panicked pre-commit accept would LEAK the row and
///   make that `(sender, nonce)` un-receivable (losers fail closed as
///   [`IrohLaneError::DedupInFlight`]) until a restart's DELETE-at-open.
/// - Once the receive commits, the caller [`commit`](Self::commit)s. That disarms the
///   guard (a drop/cancel/panic must NOT release: re-receiving an already-admitted
///   batch would re-enter the runtime replay window and reject its already-accepted
///   deposits, a spurious "rejected" durable verdict) AND persists a durable
///   `committed` marker on the reservation so that a PROCESS crash in this window
///   leaves a row that SURVIVES the store's clear-at-open (which reclaims only
///   provably-pre-commit rows); a redelivery then loses the reservation and takes the
///   fail-closed loser path instead of re-receiving.
/// - On a recorded durable verdict the caller [`release`](Self::release)s
///   explicitly: the verdict now short-circuits redelivery at `lookup_inbox_report`
///   BEFORE the reservation is consulted, so the row is redundant and releasing it
///   bounds reservation-table growth.
struct InboxSlotGuard {
    store: Arc<SqlitePheromoneRelayStore>,
    sender_kernel_id: String,
    nonce: String,
    armed: bool,
}

impl InboxSlotGuard {
    /// Arm a guard over a freshly-won reservation.
    fn new(store: Arc<SqlitePheromoneRelayStore>, sender_kernel_id: String, nonce: String) -> Self {
        Self {
            store,
            sender_kernel_id,
            nonce,
            armed: true,
        }
    }

    /// Commit the slot after the receive has self-committed its runtime deposits, the
    /// instant BEFORE the durable verdict is recorded.
    ///
    /// Two effects, both fail-closed:
    /// - Disarms the guard so a subsequent drop/cancel/panic does NOT release (see the
    ///   type docs); done FIRST so that even if the durable marker write below errors,
    ///   the slot stays HELD rather than being released. Re-receiving an
    ///   already-committed batch must never happen.
    /// - Persists the durable `committed` marker so a PROCESS crash in the
    ///   committed-but-unrecorded window leaves a reservation that survives the store's
    ///   clear-at-open reclaim (which clears only provably-pre-commit `committed = 0`
    ///   rows); a redelivery then loses the reservation and takes the fail-closed loser
    ///   path instead of re-receiving.
    fn commit(&mut self) -> Result<(), IrohLaneError> {
        self.armed = false;
        self.store
            .mark_inbox_reservation_committed(&self.sender_kernel_id, &self.nonce)?;
        Ok(())
    }

    /// Explicitly release the (now redundant) reservation after the durable verdict
    /// is recorded, disarming so a later drop does not release again. Fail-closed:
    /// propagates the store error.
    fn release(&mut self) -> Result<(), IrohLaneError> {
        self.armed = false;
        self.store
            .release_inbox_slot(&self.sender_kernel_id, &self.nonce)?;
        Ok(())
    }
}

impl Drop for InboxSlotGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Pre-commit exit (receive failed, or the accept future was cancelled /
        // panicked before commit): release so a redelivery can re-claim and
        // re-receive. Best-effort - Drop cannot propagate - so a store error is
        // logged, leaving the slot HELD (fail-closed) until a restart's
        // DELETE-at-open reclaims it.
        if let Err(error) = self
            .store
            .release_inbox_slot(&self.sender_kernel_id, &self.nonce)
        {
            tracing::warn!(
                sender = %self.sender_kernel_id,
                nonce = %self.nonce,
                error = %error,
                "failed to release inbox receive slot on drop (slot held fail-closed)"
            );
        }
    }
}

/// Read a `u32` big-endian length prefix followed by exactly that many bytes,
/// rejecting an over-cap declared length before allocating (fail-closed).
///
/// `max_bytes` is the caller's effective cap and MUST never exceed the transport
/// hard cap [`MAX_PHEROMONE_BATCH_BYTES`]. The ingress handler passes the configured
/// relay body-size limit (256 KiB production / 1 MiB local-dev) so the iroh path is
/// no laxer than the HTTP relay's `DefaultBodyLimit`; internal reads (the dialer's
/// own response) pass the transport cap.
async fn read_len_delimited<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, IrohLaneError>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > max_bytes {
        return Err(IrohLaneError::FrameTooLarge(len));
    }
    // Grow the buffer as bytes actually arrive instead of committing `len` up
    // front: a peer that declares a large length then dribbles holds only what it
    // has sent (the per-phase ReadFrame timeout still bounds the dribble).
    const READ_CHUNK: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK));
    let mut remaining = len;
    let mut chunk = [0u8; READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK);
        let n = reader.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Err(IrohLaneError::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        remaining -= n;
    }
    Ok(buf)
}

/// Write a `u32` big-endian length prefix followed by the bytes. Does not
/// `finish()` the stream: the caller half-closes when appropriate.
async fn write_len_delimited<W>(writer: &mut W, bytes: &[u8]) -> Result<(), IrohLaneError>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(bytes.len()).map_err(|_| IrohLaneError::FrameTooLarge(bytes.len()))?;
    if bytes.len() > MAX_PHEROMONE_BATCH_BYTES {
        return Err(IrohLaneError::FrameTooLarge(bytes.len()));
    }
    writer.write_u32(len).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Receiver side of lane a: a [`ProtocolHandler`] mounted on
/// [`ALPN_PHEROMONE_BATCH`].
///
/// On accept it re-resolves the authenticated sender from `conn.remote_id()`,
/// reads one length-delimited canonical [`PheromoneGossipBatch`], feeds the
/// reused [`RelayBatchReceiver::receive_batch`] with that resolved `kernel_id`
/// as the `authenticated_sender_kernel_id` (so the unchanged per-frame verifier
/// runs above the transport), records the inbox for idempotent dedup, and writes
/// the peer's report back on the same bidi stream.
#[derive(Clone)]
pub struct PheromoneBatchHandler {
    gate: DirectoryGate,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Inbound per-peer directory-scope gate (the SAME `enforce_peer_batch_directory_scope`
    /// the HTTP relay runs before receiving). Evaluated fail-closed BEFORE the batch
    /// reaches the receiver, so an out-of-scope sender is rejected on the iroh path
    /// exactly as it is over HTTP.
    scope_check: InboundBatchScopeCheck,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
    /// Effective ingress body-size cap. Defaults to the transport hard cap
    /// [`MAX_PHEROMONE_BATCH_BYTES`]; the wiring lowers it to the relay profile's
    /// configured body limit (mirroring the HTTP relay's `DefaultBodyLimit`) so the
    /// iroh ingress is never a laxer surface than HTTP. Applied to the request-frame
    /// read BEFORE deserialization, fail-closed to [`IrohLaneError::FrameTooLarge`].
    max_batch_bytes: usize,
}

impl fmt::Debug for PheromoneBatchHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PheromoneBatchHandler")
            .field("gate", &self.gate)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl PheromoneBatchHandler {
    /// Build the handler from the admission gate (for re-resolution), the reused
    /// relay receiver seam, the shipped SQLite store (inbox dedup), a clock, and the
    /// inbound directory-scope gate (the SAME `enforce_peer_batch_directory_scope`
    /// the HTTP relay runs before receiving, supplied by the wiring against the
    /// current peer directory).
    #[must_use]
    pub fn new(
        gate: DirectoryGate,
        receiver: Arc<dyn RelayBatchReceiver>,
        store: Arc<SqlitePheromoneRelayStore>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
        scope_check: InboundBatchScopeCheck,
    ) -> Self {
        Self {
            gate,
            receiver,
            store,
            now,
            scope_check,
            limiter: AcceptLimiter::default(),
            max_batch_bytes: MAX_PHEROMONE_BATCH_BYTES,
        }
    }

    /// Override the default accept-hardening bounds (per-phase timeouts + the
    /// in-flight concurrency cap). The [`Default`] preserves the historical
    /// (generous) behavior; the wiring can tighten or loosen it in one place.
    #[must_use]
    pub fn with_accept_limits(mut self, config: AcceptLimitConfig) -> Self {
        self.limiter = AcceptLimiter::new(config);
        self
    }

    /// Lower the ingress body-size cap to the relay profile's configured body limit
    /// so the iroh ingress path is no laxer than the HTTP relay's `DefaultBodyLimit`
    /// (256 KiB production / 1 MiB local-dev). Fail-closed: the effective cap is the
    /// MIN of the requested limit and the transport hard cap
    /// [`MAX_PHEROMONE_BATCH_BYTES`], so this can only tighten, never widen, the
    /// ceiling. A batch declaring more than the effective cap is rejected before any
    /// allocation or deserialization.
    #[must_use]
    pub fn with_max_batch_bytes(mut self, max_batch_bytes: usize) -> Self {
        self.max_batch_bytes = max_batch_bytes.min(MAX_PHEROMONE_BATCH_BYTES);
        self
    }

    async fn handle(&self, conn: &Connection) -> Result<(), IrohLaneError> {
        // The ONE hop that replaces the HTTP-signed sender: the authenticated
        // EndpointId, resolved through the load-time-verified directory.
        let authenticated_sender = resolve_authenticated_sender(&self.gate, &conn.remote_id())?;

        // Bound accept_bi: a connected-but-silent peer is dropped here.
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, conn.accept_bi())
            .await?
            .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

        // Bound the request-frame read: the primary slowloris surface (a large
        // declared length then a dribble of bytes is dropped here). Timeouts only
        // bound waiting; the verifier below runs on the fully received frame.
        let raw = self
            .limiter
            .bounded(
                AcceptPhase::ReadFrame,
                read_len_delimited(&mut recv, self.max_batch_bytes),
            )
            .await??;
        let batch: PheromoneGossipBatch = serde_json::from_slice(&raw)?;

        // ENFORCE INBOUND PEER SCOPE (fail-closed): mirror the HTTP handle_batch_relay,
        // which runs enforce_peer_batch_directory_scope BEFORE receive_batch. A sender
        // that is not an Origin/Hub, exceeds its per-peer frame cap, is unsubscribed
        // from the batch treaty, or carries an unpinned transit ladder is rejected here
        // on the iroh path exactly as over HTTP, BEFORE any receiver/inbox state is
        // consulted or mutated. Runs on EVERY batch (even a dedup redelivery), matching
        // the HTTP path, so a sender that has since fallen out of scope cannot replay.
        (self.scope_check)(&authenticated_sender, &batch)?;

        // RE-RESOLVE AGAINST THE CURRENT DIRECTORY BEFORE TOUCHING RECEIVER STATE
        // (fail-closed). The admission gate authorized this endpoint at `after_handshake`,
        // but the directory reloader can publish a deny-all (expiry, revoked local binding,
        // below-minVersion, or an untrusted signing issuer) - or a successor that tombstones
        // this sender - DURING the accept_bi + request-frame read this handler just awaited.
        // Resolving the sender only once at accept would let a peer that connected just
        // before that swap still deliver a batch under a directory that is no longer valid.
        // Resolve again now, immediately before any receiver/inbox mutation: an endpoint the
        // current directory no longer admits (or now binds to a different kernel) is reset
        // here rather than received under a stale directory.
        let remote = conn.remote_id();
        if resolve_authenticated_sender(&self.gate, &remote)? != authenticated_sender {
            return Err(IrohLaneError::Unadmitted(remote.fmt_short().to_string()));
        }

        // DEDUP BEFORE RECEIVE (fail-closed idempotency): compute the deterministic
        // inbox nonce and consult the store BEFORE mutating receiver state. On a
        // retry of an already-admitted batch, re-running receive_batch would re-enter
        // the runtime replay window and reject the already-accepted deposits, dead-
        // lettering a batch the peer already holds. Returning the stored report keeps
        // redelivery idempotent, exactly as the shipped HTTP inbox does.
        let batch_bytes = canonical_json_bytes(&batch)
            .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;
        let nonce = inbox_nonce(&batch_bytes);
        let report = match self
            .store
            .lookup_inbox_report(&authenticated_sender, &nonce)?
        {
            // Already fully admitted: return the durable verdict verbatim.
            Some(stored) => stored,
            None => {
                // RESERVE BEFORE RECEIVE (fail-closed concurrency): the lookup ->
                // receive -> record sequence is NOT atomic, so two connections
                // delivering the SAME batch could both read None and both re-run
                // receive_batch, double-mutating the runtime replay window. Atomically
                // claim the (sender, nonce) receive slot first; only the sole winner
                // receives.
                if self
                    .store
                    .reserve_inbox_slot(&authenticated_sender, &nonce)?
                    .won
                {
                    // Hold the freshly-won reservation via an RAII guard, ARMED. While
                    // armed, ANY early exit - the receive `?`-return below, an
                    // accept-task cancel (Router shutdown / connection close cancels the
                    // accept future), or a panic - drops the guard and RELEASES the slot,
                    // so a batch that committed NOTHING never leaks its reservation (a
                    // leaked row would make that (sender, nonce) un-receivable until a
                    // restart's DELETE-at-open). Once the receive COMMITS we DISARM, so
                    // from there a drop/cancel/panic leaves the slot HELD (fail-closed):
                    // re-receiving an already-admitted batch would re-enter the runtime
                    // replay window and reject its already-accepted deposits.
                    let mut slot = InboxSlotGuard::new(
                        Arc::clone(&self.store),
                        authenticated_sender.clone(),
                        nonce.clone(),
                    );
                    // RE-READ AFTER WINNING THE RESERVATION (fail-closed): our first
                    // lookup_inbox_report returned None, but winning the slot does NOT
                    // prove the batch is unreceived. A concurrent handler can record its
                    // durable verdict AND release its reservation (release_inbox_slot runs
                    // only AFTER record_inbox, to bound table growth) in the window between
                    // our None-read and our winning here, so we may have re-claimed a slot
                    // for an ALREADY-admitted batch. Re-read the durable inbox now, holding
                    // the freshly-won slot: if the verdict is already recorded, return it
                    // verbatim and RELEASE the (now redundant) slot - NEVER re-run
                    // receive_batch, which would re-enter the runtime replay window and
                    // reject the already-accepted deposits (a spurious "rejected" verdict).
                    // This closes the "reservation won after another handler recorded+
                    // released" race and mirrors the HTTP path's nonce-before-receive
                    // idempotency. Only a still-absent verdict proceeds to receive.
                    if let Some(stored) = self
                        .store
                        .lookup_inbox_report(&authenticated_sender, &nonce)?
                    {
                        slot.release()?;
                        stored
                    } else {
                        // WINNER-PATH DURABLE-VERDICT RECOVERY (symmetric with the loser
                        // path below). Winning the reservation and finding no
                        // recorded inbox verdict does NOT prove the batch is unreceived across
                        // the two-store boundary. receive_batch self-commits its runtime
                        // mutation (deposits + receive-report) in the RUNTIME store; slot.commit()
                        // marks the RELAY reservation committed in a SEPARATE durable write, with
                        // a cross-store fsync between the two. A hard crash (SIGKILL / OOM /
                        // power) in that window leaves the batch ADMITTED in the runtime store
                        // but the relay reservation committed = 0, which the store reclaims at
                        // open; a redelivery then re-wins the reservation and reaches HERE.
                        // Consult the runtime store by batch hash BEFORE re-running
                        // receive_batch: if it already holds a committed receive-report, ADOPT
                        // that durable verdict rather than re-running the receiver (which would
                        // re-enter the runtime replay window and reject the already-admitted
                        // deposits - a spurious "rejected" verdict that dead-letters an accepted
                        // batch). The hash is sha256_hex over the same canonical batch bytes the
                        // runtime store keys on (batch_sha256 == sha256_hex(canonical_json_bytes)),
                        // identical to the loser path.
                        let batch_sha256 = sha256_hex(&batch_bytes);
                        // SCOPE THE RECOVERED VERDICT TO THE AUTHENTICATED SENDER
                        // (fail-closed): a batch hash is NOT sender-unique. A DIFFERENT
                        // authenticated sender can durably record a verdict for these exact
                        // batch bytes - either an envelope-rejected report (any peer that
                        // replays the bytes with the WRONG identity trips
                        // gossiping_peer_kernel_id != authenticated_sender), or, for a batch
                        // whose gossiping_peer_kernel_id it legitimately owns, an accepted
                        // one. Adopting it verbatim would attribute that sender's verdict to
                        // OUR (authenticated_sender, nonce) inbox key, bypassing the
                        // per-frame verifier's gossiping_peer_kernel_id == authenticated_sender
                        // binding: a wrong sender could POISON this batch hash with a rejected
                        // verdict before the real sender arrives, or RECEIVE an accepted verdict
                        // for another sender's batch. The runtime-store lookup is now itself
                        // sender-scoped at the query level, so it returns THIS sender's row (or
                        // None); the `.filter` re-checks the deserialized sender as
                        // belt-and-suspenders. Any non-matching (or absent) report falls through
                        // to receive_batch, which re-runs that verifier under THIS sender.
                        if let Some(recovered) = self
                            .receiver
                            .recorded_report_for_batch(&batch_sha256, &authenticated_sender)
                            .await?
                            .filter(|recovered| {
                                recovered.authenticated_sender_kernel_id == authenticated_sender
                            })
                        {
                            // Adopt the durable verdict as the inbox record so both peers
                            // converge. record_inbox is idempotent (ON CONFLICT), so a
                            // concurrent handler recording first is harmless. RELEASE the
                            // committed residual reservation via the guard (disarming it so the
                            // Drop does not release again) now that the durable inbox row
                            // short-circuits any later redelivery at lookup_inbox_report before
                            // the reservation is consulted. NEVER re-run receive_batch. The lane
                            // accept counter is NOT incremented here: `handle` returns Ok on this
                            // recovery, and `accept` counts LANE_OUTCOME_ACCEPT once for every
                            // Ok(()), exactly as it does for a fresh delivery or an inbox hit.
                            // Counting here too would emit TWO accept samples for one recovered
                            // redelivery (metric dedupe).
                            let _ = self.store.record_inbox(
                                &authenticated_sender,
                                &nonce,
                                &batch,
                                &recovered,
                            )?;
                            slot.release()?;
                            recovered
                        } else {
                            let now = (self.now)();
                            // The report type (chio-pheromone-runtime PheromoneReceiveReport)
                            // is not nameable here; it flows through by inference. The per-frame
                            // verifier (pheromone_gossip.rs:236/244) runs inside this call,
                            // unchanged, and only ever on a batch neither already in the inbox
                            // nor durably committed in the runtime store.
                            let fresh = match self
                                .receiver
                                .receive_batch(batch.clone(), authenticated_sender.clone(), now)
                                .await
                            {
                                // receive_batch self-commits its runtime mutation only on Ok; an
                                // Err admitted nothing. The still-ARMED guard drops on this
                                // `?`-return and RELEASES the slot so a redelivery can re-claim
                                // and re-receive. Fail-closed.
                                Err(error) => return Err(error.into()),
                                Ok(fresh) => fresh,
                            };
                            // Deposits are now committed. COMMIT the slot: disarm (a cancel/panic
                            // in the committed-but-unrecorded window below must NOT release, or a
                            // redelivery would re-receive an already-admitted batch, yielding a
                            // spurious "rejected" durable verdict for deposits that were in fact
                            // admitted) AND persist the durable commit marker so a PROCESS crash
                            // in this window leaves a reservation that survives the store's
                            // clear-at-open, forcing redelivery down the fail-closed loser path.
                            slot.commit()?;
                            match self.store.record_inbox(
                                &authenticated_sender,
                                &nonce,
                                &batch,
                                &fresh,
                            ) {
                                // Durable verdict recorded: it now short-circuits any redelivery
                                // at lookup_inbox_report BEFORE the reservation is consulted, so
                                // the reservation is redundant. Release it to bound
                                // reservation-table growth (fail-closed on the store error; the
                                // recorded verdict still short-circuits the peer's retry).
                                Ok(_) => slot.release()?,
                                // A committed batch whose verdict failed to record must NOT be
                                // re-received. Leave the slot HELD (already disarmed): a
                                // redelivery loses the reservation and takes the loser /
                                // fail-closed path, never re-running the receiver. The peer retry
                                // fail-closes pending operational recovery.
                                Err(error) => return Err(error.into()),
                            }
                            fresh
                        }
                    }
                } else {
                    // Loser: a concurrent handler is receiving this exact batch. Do
                    // NOT receive (that is the double-mutation this dedup closes); wait,
                    // bounded, for the winner's durable verdict and return it. The
                    // report type is unnameable in this crate (see the module note), so
                    // the wait is inlined and flows the verdict through by inference.
                    let mut verdict = None;
                    for _ in 0..DEDUP_WAIT_ATTEMPTS {
                        if let Some(stored) = self
                            .store
                            .lookup_inbox_report(&authenticated_sender, &nonce)?
                        {
                            verdict = Some(stored);
                            break;
                        }
                        tokio::time::sleep(DEDUP_WAIT_BACKOFF).await;
                    }
                    match verdict {
                        Some(stored) => stored,
                        None => {
                            // Durable-verdict recovery: the bounded poll found no recorded
                            // inbox verdict, but the runtime store may
                            // have durably committed this batch before a crash in the
                            // commit-to-record window (receive_batch self-committed the
                            // deposits; the process died before record_inbox wrote the
                            // durable verdict, leaving the reservation committed=1). A
                            // redelivery then lost the slot and reached this loser path.
                            // Consult the runtime store by batch hash: the hash is
                            // sha256_hex over the same canonical batch bytes the runtime
                            // store keys on (batch_sha256 == sha256_hex(canonical_json_bytes)).
                            let batch_sha256 = sha256_hex(&batch_bytes);
                            // SCOPE THE RECOVERED VERDICT TO THE AUTHENTICATED SENDER
                            // (fail-closed), identically to the winner path above: a batch hash
                            // is NOT sender-unique, so a report the store holds for these bytes
                            // may belong to a DIFFERENT authenticated sender. Adopting it would
                            // attribute another sender's verdict to OUR (authenticated_sender,
                            // nonce), bypassing the per-frame gossiping_peer_kernel_id ==
                            // authenticated_sender binding. The runtime-store lookup is now itself
                            // sender-scoped at the query level; the `.filter` re-checks the
                            // deserialized sender as belt-and-suspenders. A wrong-sender (or
                            // absent) report denies here so the peer retries and the durable inbox
                            // short-circuits once THIS sender's own verdict is recorded.
                            if let Some(recovered) = self
                                .receiver
                                .recorded_report_for_batch(&batch_sha256, &authenticated_sender)
                                .await?
                                .filter(|recovered| {
                                    recovered.authenticated_sender_kernel_id == authenticated_sender
                                })
                            {
                                // Adopt the durable verdict as the inbox record so both
                                // peers converge. record_inbox is idempotent (ON CONFLICT),
                                // so a concurrent winner recording first is harmless.
                                let _ = self.store.record_inbox(
                                    &authenticated_sender,
                                    &nonce,
                                    &batch,
                                    &recovered,
                                )?;
                                // Release the committed residual reservation now that the
                                // durable inbox row short-circuits any later redelivery at
                                // lookup_inbox_report before the reservation is consulted.
                                // The lane accept counter is NOT incremented here: `handle`
                                // returns Ok on this recovery and `accept` counts
                                // LANE_OUTCOME_ACCEPT once for every Ok(()), so counting here too
                                // would double-count one recovered redelivery (metric dedupe).
                                self.store
                                    .release_inbox_slot(&authenticated_sender, &nonce)?;
                                recovered
                            } else {
                                // Fail-closed if there is no durable verdict FOR THIS SENDER
                                // to recover: the peer retries and the durable inbox
                                // short-circuits the retry once the winner records.
                                return Err(IrohLaneError::DedupInFlight(format!(
                                    "sender {authenticated_sender} nonce {nonce} still receiving"
                                )));
                            }
                        }
                    }
                }
            }
        };

        let report_bytes = canonical_json_bytes(&report)
            .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;
        // Bound the response write: a peer that stops reading is dropped here.
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_len_delimited(&mut send, &report_bytes),
            )
            .await??;
        send.finish()
            .map_err(|error| IrohLaneError::Transport(error.to_string()))?;
        Ok(())
    }
}

impl ProtocolHandler for PheromoneBatchHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        use tracing::Instrument;
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code, so one
        // hostile peer cannot spawn unbounded accept tasks.
        let _permit = match self.limiter.admit_peer(&conn.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_PHEROMONE,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "pheromone lane shed accept (saturated)"
                );
                conn.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_PHEROMONE);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_PHEROMONE);
        let started = std::time::Instant::now();
        let result = self.handle(&conn).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_PHEROMONE,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_PHEROMONE,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                // Bounded linger: keep the connection open until the dialer has
                // read the report and closed (so the finished stream is not reset
                // on drop), but never past the linger bound.
                self.limiter.linger(&conn).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_PHEROMONE, outcome);
                crate::observability::record_outcome(&span, outcome);
                tracing::warn!(code = error.code(), error = %error, "pheromone lane reset batch");
                conn.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

/// Mount the pheromone lane on its own ALPN. The admission
/// [`DirectoryGate`](crate::admission::DirectoryGate) must already be installed
/// on `endpoint` via `Endpoint::builder(..).hooks(gate)` so unbound endpoints
/// are rejected at `after_handshake` before this handler runs.
#[must_use]
pub fn mount_pheromone_lane(endpoint: Endpoint, handler: PheromoneBatchHandler) -> Router {
    Router::builder(endpoint)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn()
}

/// Outcome of a single dial-side delivery: the peer's `accepted` verdict (read from
/// a fully validated receive report; a partial/malformed report is rejected before
/// this is ever produced) plus the raw canonical report bytes for callers that hold
/// the runtime report type.
#[derive(Debug, Clone)]
pub struct BatchDeliveryOutcome {
    /// Whether the receiving peer accepted the whole batch.
    pub accepted: bool,
    /// Canonical JSON bytes of the peer's `PheromoneReceiveReport`.
    pub report_json: Vec<u8>,
}

/// The batch-level verdict enum mirrored from the runtime `PheromoneReceiveReport`,
/// so an unknown or absent outcome string is rejected fail-closed alongside a missing
/// field when a receive report is validated.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiveReportOutcome {
    Accepted,
    Partial,
    Rejected,
}

/// The set of fields a COMPLETE `PheromoneReceiveReport` (the runtime relay's receive
/// verdict) carries on the wire, deserialized on the dial side to REJECT a partial or
/// malformed report BEFORE a batch is marked durably delivered (see
/// [`deliver_batch_over_iroh_with_limits`]). Every field is required, so serde rejects
/// a report that omits any of them (for example a buggy or misrouted ALPN handler
/// answering `{"accepted":true}`); it is deliberately NOT `deny_unknown_fields` so a
/// forward-compatible report that ADDS fields still verifies. This crate mirrors the
/// runtime report's shape rather than depending on the runtime type (the same reason
/// the batch itself is exchanged as canonical bytes).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ReceiveReportShape {
    schema: String,
    accepted: bool,
    batch_outcome: ReceiveReportOutcome,
    accepted_frame_count: u64,
    rejected_frame_count: u64,
    batch_sha256: String,
    recipient_kernel_id: String,
    authenticated_sender_kernel_id: String,
    received_at_unix_ms: u64,
    frames: Vec<serde_json::Value>,
}

/// Bound one peer-dependent client await by the phase's timeout, mirroring the
/// accept-side [`AcceptLimiter::bounded`]. On timeout this fails closed with the
/// same [`AcceptLimitError::Timeout`] the accept side raises, so a stalled dial
/// folds into the durable outbox retry/dead-letter path via [`IrohLaneError::code`]
/// (`accept_timeout`) rather than hanging the sequential drain forever.
async fn client_bounded<T, F>(
    limits: &AcceptLimitConfig,
    phase: AcceptPhase,
    fut: F,
) -> Result<T, IrohLaneError>
where
    F: std::future::Future<Output = T>,
{
    let bound = limits.phase_timeout(phase);
    match tokio::time::timeout(bound, fut).await {
        Ok(output) => Ok(output),
        Err(_elapsed) => Err(IrohLaneError::AcceptLimit(AcceptLimitError::Timeout {
            phase,
            timeout_ms: u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
        })),
    }
}

/// Sender side of lane a: dial a peer over [`ALPN_PHEROMONE_BATCH`], write one
/// length-delimited canonical [`PheromoneGossipBatch`], and read back the report.
///
/// The iroh replacement for `PheromoneRelayClient::post_batch`
/// (`service.rs:652`). `recipient_addr` is the peer resolved from its
/// `kernel_id` via the directory (an [`EndpointId`] in production with
/// discovery, or a full [`EndpointAddr`] for direct addressing).
///
/// Uses the generous default client bounds
/// ([`AcceptLimitConfig::default`]); see [`deliver_batch_over_iroh_with_limits`]
/// to tune them.
pub async fn deliver_batch_over_iroh(
    endpoint: &Endpoint,
    recipient_addr: impl Into<EndpointAddr>,
    batch: &PheromoneGossipBatch,
) -> Result<BatchDeliveryOutcome, IrohLaneError> {
    deliver_batch_over_iroh_with_limits(
        endpoint,
        recipient_addr,
        batch,
        &AcceptLimitConfig::default(),
    )
    .await
}

/// Same as [`deliver_batch_over_iroh`], with explicit client-side bounds.
///
/// Client-side slowloris defense (mirrors the accept-side [`AcceptLimiter`]):
/// every peer-dependent await (connect, open, write, and the report read) is
/// bounded by the corresponding [`AcceptLimitConfig`] phase timeout. A recipient
/// that connects but never returns the report frame no longer hangs the caller
/// forever; the dial fails closed (`accept_timeout`) and the durable outbox lease
/// retries or dead-letters normally, so one stalled peer cannot block the
/// sequential drain of later batches.
pub async fn deliver_batch_over_iroh_with_limits(
    endpoint: &Endpoint,
    recipient_addr: impl Into<EndpointAddr>,
    batch: &PheromoneGossipBatch,
    limits: &AcceptLimitConfig,
) -> Result<BatchDeliveryOutcome, IrohLaneError> {
    let batch_bytes = canonical_json_bytes(batch)
        .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;

    let conn = client_bounded(
        limits,
        AcceptPhase::AcceptStream,
        endpoint.connect(recipient_addr, ALPN_PHEROMONE_BATCH),
    )
    .await?
    .map_err(|error| IrohLaneError::Transport(error.to_string()))?;
    let (mut send, mut recv) = client_bounded(limits, AcceptPhase::AcceptStream, conn.open_bi())
        .await?
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

    client_bounded(
        limits,
        AcceptPhase::WriteResponse,
        write_len_delimited(&mut send, &batch_bytes),
    )
    .await??;
    send.finish()
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

    // The primary client-side hang surface: a peer that accepts the batch but
    // never returns the report frame is dropped here at the read bound. The report
    // is our own peer's response, so it is bounded by the transport hard cap.
    let report_json = client_bounded(
        limits,
        AcceptPhase::ReadFrame,
        read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES),
    )
    .await??;
    conn.close(LANE_OK_CODE.into(), b"ok");

    // Fail-closed durable-delivery gate: a batch is only ever marked delivered (and
    // its durable outbox row discarded by `drain_outbox_over_iroh`) once the recipient
    // returns a COMPLETE, well-typed receive report - not merely any JSON carrying
    // `accepted: true`. A buggy or misrouted ALPN handler answering `{"accepted":true}`
    // deserializes here as a PARTIAL report (missing the required fields) and is
    // REJECTED with a typed [`IrohLaneError::Codec`], so the drain retries or
    // dead-letters the batch rather than dropping it. This mirrors the HTTP relay tick,
    // which deserializes the full `PheromoneReceiveReport` type before trusting
    // `accepted`. `report_json` is still surfaced verbatim for callers that hold the
    // runtime report type.
    let report: ReceiveReportShape = serde_json::from_slice(&report_json)?;

    Ok(BatchDeliveryOutcome {
        accepted: report.accepted,
        report_json,
    })
}

/// Enqueue a batch into the shipped SQLite outbox for durable store-and-forward
/// (blueprint A.3, "enqueue on flush"). Idempotent on the canonical batch hash.
pub fn enqueue_batch_for_delivery(
    store: &SqlitePheromoneRelayStore,
    sender_kernel_id: &str,
    recipient_kernel_id: &str,
    treaty_id: &str,
    batch: &PheromoneGossipBatch,
    queued_at_unix_ms: u64,
) -> Result<String, IrohLaneError> {
    store
        .enqueue_batch(
            sender_kernel_id,
            recipient_kernel_id,
            treaty_id,
            batch,
            queued_at_unix_ms,
        )
        .map_err(IrohLaneError::from)
}

/// Counts from one [`drain_outbox_over_iroh`] tick, mirroring the shape of the
/// shipped `RelayTickReport`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboxDrainReport {
    /// Batches accepted by their recipient and marked delivered.
    pub delivered: u64,
    /// Batches that failed and were scheduled for a later retry.
    pub retried: u64,
    /// Batches that exhausted their attempts and were dead-lettered.
    pub dead_lettered: u64,
    /// Per-entry `outbox_id: code` failure lines.
    pub failures: Vec<String>,
}

/// Drain due outbox batches and deliver each over iroh, mirroring
/// `deliver_due_batches` (`service.rs:609`) with the single substitution of an
/// iroh `open_bi` write for the HTTP `post_batch`. Leasing, retry/backoff, and
/// dead-lettering all reuse the shipped `SqlitePheromoneRelayStore`.
///
/// `resolve_addr` maps a recipient `kernel_id` to its dialable
/// [`EndpointAddr`]; an unresolvable recipient folds into the retry path rather
/// than aborting the tick (fail-closed).
///
/// `scope_check` mirrors the HTTP tick's `enforce_outbound_peer_batch_directory_scope`
/// and MUST be applied against the CURRENT directory: a queued row whose recipient
/// was removed or is otherwise outside the recipient's directory scope is rejected
/// BEFORE it is dialed, so stale-or-unauthorized queued work is never leaked over
/// the new transport. Its `Err` folds into the durable retry/dead-letter path with
/// the mirrored scope code (fail-closed); the wiring supplies the shipped check so
/// the two transports enforce the same scope.
pub async fn drain_outbox_over_iroh<F, S>(
    store: &SqlitePheromoneRelayStore,
    endpoint: &Endpoint,
    resolve_addr: F,
    scope_check: S,
    sender_kernel_id: &str,
    now_unix_ms: u64,
    max_batches: usize,
) -> Result<OutboxDrainReport, IrohLaneError>
where
    F: Fn(&str) -> Option<EndpointAddr>,
    S: Fn(&str, &PheromoneGossipBatch) -> Result<(), PheromoneRelayError>,
{
    let due = store.lease_due_batches(now_unix_ms, max_batches)?;
    let mut report = OutboxDrainReport::default();
    for entry in due {
        if entry.sender_kernel_id != sender_kernel_id {
            // A row leased for a DIFFERENT sender is re-queued, NOT routed through
            // record_delivery_failure (which dead-letters after 3 attempts). Mirror
            // the HTTP deliver tick (service.rs deliver_due_batches): the row belongs
            // to another sender's drain, so it must stay available for that sender
            // rather than being permanently dead-lettered here.
            store.mark_retry(
                &entry.outbox_id,
                "sender_mismatch",
                now_unix_ms.saturating_add(60_000),
            )?;
            report.retried = report.retried.saturating_add(1);
            report
                .failures
                .push(format!("{}: sender_mismatch", entry.outbox_id));
            continue;
        }
        // ENFORCE OUTBOUND PEER SCOPE (fail-closed): mirror the HTTP deliver tick.
        // A recipient removed from / outside the current directory scope must not be
        // dialed over iroh even if `resolve_addr` still yields an address; the row
        // folds into the durable retry/dead-letter path with the scope code.
        if let Err(error) = scope_check(&entry.recipient_kernel_id, &entry.batch) {
            record_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
            continue;
        }
        let Some(addr) = resolve_addr(&entry.recipient_kernel_id) else {
            record_delivery_failure(store, &entry, "unknown_peer", now_unix_ms, &mut report)?;
            continue;
        };
        match deliver_batch_over_iroh(endpoint, addr, &entry.batch).await {
            Ok(outcome) if outcome.accepted => {
                store.mark_delivered(&entry.outbox_id)?;
                report.delivered = report.delivered.saturating_add(1);
                // Observe-only: the iroh outbox drain emits the delivery outcome the
                // shipped HTTP relay already meters.
                crate::metrics::record_outbox(crate::metrics::OUTBOX_DELIVERED);
            }
            Ok(_) => {
                record_delivery_failure(
                    store,
                    &entry,
                    "receiver_rejected",
                    now_unix_ms,
                    &mut report,
                )?;
            }
            Err(error) => {
                record_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
            }
        }
    }
    Ok(report)
}

/// Fold a delivery failure into the durable outbox: retry with linear backoff
/// until the attempt cap, then dead-letter. Mirrors `mark_delivery_failure`
/// (`service.rs:751`): 3 attempts, `60_000 * (attempts + 1)` ms backoff.
fn record_delivery_failure(
    store: &SqlitePheromoneRelayStore,
    entry: &RelayOutboxBatch,
    code: &str,
    now_unix_ms: u64,
    report: &mut OutboxDrainReport,
) -> Result<(), IrohLaneError> {
    report.failures.push(format!("{}: {code}", entry.outbox_id));
    if entry.attempts.saturating_add(1) >= 3 {
        store.mark_dead_letter(&entry.outbox_id, code)?;
        report.dead_lettered = report.dead_lettered.saturating_add(1);
        // OBSERVE-ONLY: a dead-lettered batch is an operator-actionable signal
        // (delivery has permanently failed for this batch). Counted + logged with
        // the durable outbox `code`; the retry/dead-letter decision is unchanged.
        crate::metrics::record_outbox(crate::metrics::OUTBOX_DEAD_LETTERED);
        tracing::warn!(
            target: crate::observability::TARGET_OUTBOX,
            outbox_id = %entry.outbox_id,
            code = code,
            "pheromone outbox batch dead-lettered"
        );
    } else {
        let backoff_ms = 60_000u64.saturating_mul(entry.attempts.saturating_add(1));
        store.mark_retry(
            &entry.outbox_id,
            code,
            now_unix_ms.saturating_add(backoff_ms),
        )?;
        report.retried = report.retried.saturating_add(1);
        crate::metrics::record_outbox(crate::metrics::OUTBOX_RETRIED);
    }
    Ok(())
}

#[cfg(test)]
#[path = "pheromone/tests.rs"]
mod tests;
