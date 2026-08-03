//! DEPLOYABILITY: mount the iroh federation-transport lanes on the pheromone
//! relay serve binary so the transport is actually runnable.
//!
//! # Safety invariant (DUAL, opt-in, default OFF)
//!
//! This module is only ever reached when the operator passes `--iroh-enable`
//! (which defaults to `false`). With the flag off, [`load_iroh_serve_inputs`]
//! returns `Ok(None)` BEFORE touching any file or constructing anything iroh, so
//! the serve path is byte-for-byte unchanged and the HTTP relay behaves exactly as
//! today. With the flag on, the iroh endpoint runs ALONGSIDE the axum HTTP relay
//! (DUAL migration): the HTTP relay always keeps running and stays authoritative;
//! iroh is a second ingress/egress behind the same trust logic.
//!
//! # What is wired here
//!
//! The pheromone directed-batch lane is the lane that genuinely reuses the
//! shipped relay seam: [`build_iroh_router`] mounts
//! [`chio_federation_transport_iroh::lanes::pheromone::mount_pheromone_lane`]
//! with the SAME `Arc<dyn RelayBatchReceiver>` and `Arc<SqlitePheromoneRelayStore>`
//! the HTTP `PheromoneRelayService` holds (one receiver, one store, two
//! transports). The per-frame verifier runs ABOVE both transports, unchanged.
//!
//! The revocation and bilateral lanes are NOT wired on this hook: the current
//! crate constructors need collaborators the relay-serve process does not host
//! (`RevocationHandler::new` requires a `RevocationRootSink` backed by a live
//! revocation-view cache plus a `RevocationCatchupHistory`;
//! `BilateralCoSignHandler::new` requires a dedicated DSSE co-sign `Keypair` and a
//! pinned-passport-key map). Stubbing those with no-op collaborators would be
//! fail-OPEN for revocation (a no-op sink silently discards verified revocation
//! roots), which the house rules forbid, so requesting them fails closed at load
//! time (see [`parse_iroh_lanes`]).
//!
//! # Fail-closed
//!
//! Every load/verify step ([`load_iroh_serve_inputs`]) and every endpoint-build
//! step ([`build_iroh_router`]) returns `Err` on any problem, and the caller
//! aborts serve startup. `--iroh-enable` never silently continues without the
//! transport.
//!
//! # Relay/discovery default
//!
//! With no `--iroh-relay-url`, the endpoint uses `RelayMode::Disabled` (direct
//! addressing). The n0 free relays end 2026-12-31, so this NEVER defaults to n0.

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chio_federation_transport_iroh::admission::DirectoryGate;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
use chio_federation_transport_iroh::identity::VerifiedDirectory;
use chio_federation_transport_iroh::lanes::limits::RECOMMENDED_MAX_IDLE_TIMEOUT;
use chio_federation_transport_iroh::lanes::pheromone::mount_pheromone_lane;
use chio_federation_transport_iroh::lanes::pheromone::InboundBatchScopeCheck;
use chio_federation_transport_iroh::lanes::pheromone::PheromoneBatchHandler;
use chio_pheromone_relay::enforce_peer_batch_directory_scope;
use chio_pheromone_relay::PeerDirectory;
use chio_pheromone_relay::RelayBatchReceiver;
use chio_pheromone_relay::SqlitePheromoneRelayStore;
use iroh::endpoint::presets;
use iroh::endpoint::IdleTimeout;
use iroh::endpoint::QuicTransportConfig;
use iroh::endpoint::VarInt;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::RelayUrl;
use iroh::SecretKey;

use super::read_utf8_json_file;
use super::unix_now_ms;
use super::RelayTrustedIssuersDocument;
use crate::CliError;

/// A dedicated, rotatable ed25519 transport key file (Option B), SEPARATE from the
/// long-term passport / relay signing key. `seedHex` is the 32-byte ed25519 seed as
/// hex. Kept minimal on purpose: the passport key (loaded elsewhere) endorses this
/// transport `EndpointId` inside the issuer-signed directory bundle.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IrohTransportKeyDocument {
    pub(crate) seed_hex: String,
}

/// Optional rotation-state input for the transport-directory bundle, mirroring the
/// relay's signed peer-directory state. It pins the rollback FLOOR and the expected
/// predecessor bundle hash a ROTATED successor bundle must chain onto, so a
/// post-genesis bundle (version > 1 carrying a `previousVersionSha256`) is accepted
/// at startup. Without it the wiring can only promote a GENESIS bundle (floor 0, no
/// predecessor). The bundle it pins is itself issuer-signed and verified against
/// `--trusted-issuers`; this document only carries the operator's local rollback pin.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IrohTransportDirectoryStateDocument {
    /// Rollback floor: the loaded bundle's `version` MUST be strictly greater.
    pub(crate) version_floor: u64,
    /// The expected predecessor bundle hash the successor must chain onto (its
    /// `previousVersionSha256`); `None` only when pinning a genesis bundle.
    pub(crate) expected_previous_version_sha256: Option<String>,
}

/// The iroh federation-transport lanes an operator may request via `--iroh-lanes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IrohLane {
    /// Directed pheromone batches (lane a). Reuses the relay receiver + store.
    Pheromone,
    /// Revocation epoch roots (lane b). Needs a sink + history not hosted here.
    Revocation,
    /// Bilateral DSSE co-sign (lane d). Needs a co-sign key + passport-key map.
    Bilateral,
}

impl IrohLane {
    fn label(self) -> &'static str {
        match self {
            IrohLane::Pheromone => "pheromone",
            IrohLane::Revocation => "revocation",
            IrohLane::Bilateral => "bilateral",
        }
    }
}

/// Endpoint + router construction knobs, derived from the CLI flags.
#[derive(Debug, Clone)]
pub(crate) struct IrohMountConfig {
    /// Relay mode. `Disabled` by default (never n0).
    pub(crate) relay_mode: RelayMode,
    /// Socket address the iroh endpoint binds.
    pub(crate) bind_addr: SocketAddr,
    /// The lanes to mount (pheromone only, on this hook).
    pub(crate) lanes: Vec<IrohLane>,
    /// QUIC transport idle-timeout backstop.
    pub(crate) max_idle_timeout: Duration,
}

/// Everything needed to build the iroh router, produced by
/// [`load_iroh_serve_inputs`] (all fail-closed file loads + the load-time bundle
/// verification), and consumed by [`build_iroh_router`] (the async endpoint bind).
/// Deliberately does NOT hold the relay receiver/store: those are attached at build
/// time so the loading + verification is unit-testable without them.
pub(crate) struct IrohServeInputs {
    /// The load-time-verified transport directory the admission gate is built from.
    pub(crate) directory: Arc<VerifiedDirectory>,
    /// The rotatable ed25519 transport key this endpoint authenticates as.
    pub(crate) transport_key: SecretKey,
    /// The transport directory's own `localKernelId` (the issuer-signed, body-hash-pinned
    /// identity this node authenticates AS over the transport). Captured at load time
    /// from the verified bundle so [`build_iroh_router`] can fail closed when it does NOT
    /// match the relay's configured local identity (`peer_directory.local_kernel_id()`):
    /// otherwise the endpoint would authenticate as a DIFFERENT kernel than the relay's
    /// receiver verifies inbound batches as, and valid deliveries would be
    /// rejected/dead-lettered. `VerifiedDirectory` does not surface this id, so it is
    /// carried here rather than re-derived.
    pub(crate) transport_local_kernel_id: String,
    /// Endpoint + router construction knobs.
    pub(crate) config: IrohMountConfig,
}

/// A live iroh mount: the spawned router (kept alive for the process lifetime) plus
/// startup metadata for the log line.
pub(crate) struct IrohMount {
    /// The spawned protocol router. Call [`Router::shutdown`] on teardown.
    pub(crate) router: Router,
    /// This endpoint's authenticated id (for the startup log line).
    pub(crate) endpoint_id: EndpointId,
    /// The socket address(es) the endpoint actually bound. With the default
    /// `--iroh-bind-addr 0.0.0.0:0` the OS assigns an ephemeral port, so this is
    /// the ONLY place the operator can learn the reachable port; it is logged at
    /// startup and returned here so it is observable + assertable in tests.
    pub(crate) bound_sockets: Vec<SocketAddr>,
    /// The lane labels actually mounted (for the startup log line).
    pub(crate) enabled_lanes: Vec<&'static str>,
    /// The admission gate installed on the endpoint (shares one Arc<ArcSwap> with
    /// the installed hook), so the directory reloader can publish re-verified
    /// directories that every lane observes immediately.
    pub(crate) gate: DirectoryGate,
    /// This node's `localKernelId` (the identity the bound endpoint authenticates AS).
    /// Threaded into the reloader's `DirectoryReloadConfig` so the live binding recheck
    /// mirrors the startup check EXACTLY (`resolve_transport_endpoint(local_kernel_id)
    /// == endpoint_id`) rather than merely confirming the endpoint resolves to some
    /// kernel.
    pub(crate) transport_local_kernel_id: String,
}

/// Render the iroh federation-transport Prometheus metric families.
///
/// The relay's own `/metrics` route lives in `chio-pheromone-relay`
/// (`service.rs`), a separate crate this `-p chio-cli` change does not touch. The
/// clean hook is a one-line concatenation of this string onto that exporter's
/// body; this accessor makes the render reachable from the serving binary in the
/// meantime. All families are process-global statics, so any `/metrics` handler
/// that calls this observes the live counters.
#[must_use]
pub(crate) fn iroh_transport_metrics_prometheus() -> String {
    chio_federation_transport_iroh::metrics::render_iroh_transport_metrics_prometheus()
}

/// Parse the comma-separated `--iroh-lanes` value.
///
/// Fail-closed: an empty set, an unknown token, or a lane that is not wireable on
/// the relay-serve hook (revocation / bilateral, see the module docs) is rejected
/// rather than silently dropped.
pub(crate) fn parse_iroh_lanes(raw: &str) -> Result<Vec<IrohLane>, CliError> {
    let mut lanes = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let lane = match token {
            "pheromone" => IrohLane::Pheromone,
            "revocation" => IrohLane::Revocation,
            "bilateral" => IrohLane::Bilateral,
            other => {
                return Err(CliError::cli_other_error(format!(
                    "Chio iroh transport: unknown lane '{other}' (expected pheromone, revocation, or bilateral)"
                )));
            }
        };
        if !matches!(lane, IrohLane::Pheromone) {
            return Err(CliError::cli_other_error(format!(
                "Chio iroh transport: lane '{}' is not yet wired on the pheromone relay serve hook \
                 (it needs collaborators the relay does not host); only 'pheromone' is supported here",
                lane.label()
            )));
        }
        if !lanes.contains(&lane) {
            lanes.push(lane);
        }
    }
    if lanes.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: --iroh-lanes selected no lanes".to_string(),
        ));
    }
    Ok(lanes)
}

/// Build `RelayMode` from the repeated `--iroh-relay-url` flag.
///
/// No URLs -> `RelayMode::Disabled` (direct addressing). This NEVER returns the n0
/// default map (free relays end 2026-12-31); a self-hosted relay is opt-in.
fn relay_mode_from_urls(urls: &[String]) -> Result<RelayMode, CliError> {
    if urls.is_empty() {
        return Ok(RelayMode::Disabled);
    }
    let mut parsed = Vec::with_capacity(urls.len());
    for url in urls {
        let relay_url: RelayUrl = url.parse().map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport relay url '{url}': {error}"))
        })?;
        parsed.push(relay_url);
    }
    Ok(RelayMode::custom(parsed))
}

/// Load the transport ed25519 secret key from a `{ "seedHex": ".." }` file.
fn load_transport_secret_key(path: &Path) -> Result<SecretKey, CliError> {
    let json = read_utf8_json_file(path, "Chio iroh transport key")?;
    let document: IrohTransportKeyDocument = serde_json::from_str(&json)
        .map_err(|error| CliError::cli_other_error(format!("Chio iroh transport key: {error}")))?;
    let bytes = hex::decode(document.seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport key seedHex: {error}"))
    })?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        CliError::cli_other_error(
            "Chio iroh transport key seedHex: must decode to exactly 32 bytes".to_string(),
        )
    })?;
    Ok(SecretKey::from_bytes(&seed))
}

/// Build the load-time trust for the transport-directory bundle from the SAME
/// `--trusted-issuers` config the HTTP peer directory uses. The validity window is
/// checked against `now`.
///
/// Rollback pin: the trusted-issuer file's `minVersion` (the SAME field the HTTP
/// peer-directory loader reads as its trusted floor) is the rollback floor when no
/// explicit `transport_directory_state` pin is supplied, so a bundle below the
/// issuer-configured minimum is rejected fail-closed even without a state file
/// (defaulting to `0` only when `minVersion` is absent). Without a state pin the
/// expected predecessor is `None`, so a ROTATED successor bundle (carrying a
/// `previousVersionSha256`) still needs the state input to pin the predecessor hash;
/// a supplied state floor can never sit BELOW the issuer `minVersion` (a local pin
/// must not silently lower the issuer-configured floor). See
/// [`IrohTransportDirectoryStateDocument`].
fn transport_bundle_trust(
    trusted_issuers: Option<&Path>,
    transport_directory_state: Option<&Path>,
    now_unix_ms: u64,
) -> Result<TransportDirectoryBundleTrust, CliError> {
    let path = trusted_issuers.ok_or_else(|| {
        CliError::cli_other_error(
            "Chio iroh transport: --trusted-issuers is required with --iroh-enable".to_string(),
        )
    })?;
    let json = read_utf8_json_file(path, "Chio iroh transport trusted issuers")?;
    let document: RelayTrustedIssuersDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport trusted issuers: {error}"))
    })?;
    // The SAME minVersion the HTTP peer-directory loader enforces as its trusted
    // rollback floor (absent -> 0). Read before `issuers` is consumed below.
    let trusted_min_version = document.min_version.unwrap_or(0);
    let issuers = document
        .issuers
        .into_iter()
        .map(|issuer| TrustedTransportDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect::<Vec<_>>();
    if issuers.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio iroh transport trusted issuers: no issuers configured".to_string(),
        ));
    }
    // Honor the trusted-issuer minVersion as the rollback floor. Without a rotation
    // state the expected predecessor is None (genesis chaining); with one, the
    // explicit floor takes precedence but can never fall below the issuer minVersion.
    //
    // minVersion is INCLUSIVE (the HTTP peer-directory loader accepts version ==
    // minVersion via `version < min_version`), but `verify_bundle` treats
    // `version_floor` as EXCLUSIVE (`version <= version_floor` rejects). Map the
    // inclusive minimum onto the exclusive floor with `saturating_sub(1)` so a
    // bundle exactly AT minVersion is accepted and one below it is rejected, in
    // lockstep with the HTTP loader.
    let inclusive_min_as_floor = trusted_min_version.saturating_sub(1);
    let (version_floor, expected_previous_version_sha256) = match transport_directory_state {
        Some(state_path) => {
            let state_json =
                read_utf8_json_file(state_path, "Chio iroh transport directory state")?;
            let state: IrohTransportDirectoryStateDocument = serde_json::from_str(&state_json)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chio iroh transport directory state: {error}"
                    ))
                })?;
            (
                state.version_floor.max(inclusive_min_as_floor),
                state.expected_previous_version_sha256,
            )
        }
        None => (inclusive_min_as_floor, None),
    };
    Ok(TransportDirectoryBundleTrust {
        issuers,
        version_floor,
        expected_previous_version_sha256,
        now_unix_ms,
    })
}

/// Load + verify all iroh serve inputs, fail-closed.
///
/// Returns `Ok(None)` immediately (touching NO files, constructing NOTHING) when
/// `iroh_enable` is false: this is the opt-in-default-off / byte-unchanged
/// guarantee. When enabled, every missing/invalid input aborts with `Err`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_iroh_serve_inputs(
    iroh_enable: bool,
    iroh_transport_directory: Option<&Path>,
    iroh_transport_directory_state: Option<&Path>,
    trusted_issuers: Option<&Path>,
    iroh_transport_key: Option<&Path>,
    iroh_bind_addr: &str,
    iroh_relay_url: &[String],
    iroh_lanes: &str,
    now_unix_ms: u64,
) -> Result<Option<IrohServeInputs>, CliError> {
    if !iroh_enable {
        return Ok(None);
    }

    let lanes = parse_iroh_lanes(iroh_lanes)?;

    let directory_path = iroh_transport_directory.ok_or_else(|| {
        CliError::cli_other_error(
            "Chio iroh transport: --iroh-transport-directory is required with --iroh-enable"
                .to_string(),
        )
    })?;
    let directory_json =
        read_utf8_json_file(directory_path, "Chio iroh transport directory bundle")?;
    let bundle: TransportDirectoryBundleDocument =
        serde_json::from_str(&directory_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport directory bundle: {error}"))
        })?;
    let trust =
        transport_bundle_trust(trusted_issuers, iroh_transport_directory_state, now_unix_ms)?;
    let directory = bundle.verify_bundle(&trust).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio iroh transport directory bundle verification: {error}"
        ))
    })?;

    let key_path = iroh_transport_key.ok_or_else(|| {
        CliError::cli_other_error(
            "Chio iroh transport: --iroh-transport-key is required with --iroh-enable".to_string(),
        )
    })?;
    let transport_key = load_transport_secret_key(key_path)?;

    // Validate the LOCAL transport-key binding (fail-closed). The key this node
    // authenticates as MUST be exactly the transport `EndpointId` the verified
    // directory endorses for THIS node's `localKernelId`. Otherwise the endpoint
    // binds under an `EndpointId` no peer endorses: peers enforcing the same transport
    // directory would dial a DIFFERENT endpoint, or reject this one at the
    // `DirectoryGate` (`after_handshake`), so the opt-in iroh transport is silently
    // unusable. The `localKernelId` is carried by the body-hash-pinned directory
    // document, so it is trusted once `verify_bundle` succeeds; `resolve_transport_endpoint`
    // returns the non-removed binding (or `None` for an unknown/removed local entry).
    let local_kernel_id = bundle.directory.local_kernel_id.as_str();
    let endorsed_endpoint = directory
        .resolve_transport_endpoint(local_kernel_id)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "Chio iroh transport: the verified directory binds no non-removed transport \
                 endpoint for this node's local kernel id '{local_kernel_id}', so the \
                 --iroh-transport-key cannot be a directory-endorsed endpoint"
            ))
        })?;
    let bound_endpoint = transport_key.public();
    if bound_endpoint != endorsed_endpoint {
        return Err(CliError::cli_other_error(format!(
            "Chio iroh transport: --iroh-transport-key public endpoint {} does not match the \
             directory-endorsed transport endpoint {} for local kernel id '{local_kernel_id}'; \
             peers enforcing this directory would reject or bypass this node",
            bound_endpoint.fmt_short(),
            endorsed_endpoint.fmt_short()
        )));
    }

    let bind_addr = iroh_bind_addr.parse::<SocketAddr>().map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport bind address: {error}"))
    })?;
    let relay_mode = relay_mode_from_urls(iroh_relay_url)?;

    Ok(Some(IrohServeInputs {
        directory: Arc::new(directory),
        transport_key,
        // The issuer-signed, body-hash-pinned local identity this node authenticates
        // AS over the transport. Compared against the relay's configured local identity
        // at build time (fail-closed) so the endpoint can never authenticate as a
        // different kernel than the relay's receiver verifies inbound batches as.
        transport_local_kernel_id: bundle.directory.local_kernel_id.clone(),
        config: IrohMountConfig {
            relay_mode,
            bind_addr,
            lanes,
            max_idle_timeout: RECOMMENDED_MAX_IDLE_TIMEOUT,
        },
    }))
}

// -- Live directory reload ---------------------------------------------------

/// A directory-reload failure. Never crosses the trust boundary as an admit: the
/// reloader keeps last-good on a transient error and fails closed on expiry.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DirectoryReloadError {
    #[error("directory reload read error: {0}")]
    Read(String),
    #[error("directory reload verify error: {0}")]
    Verify(String),
    #[error("directory reload rollback: on-disk version {found} is not above current {current}")]
    Rollback { found: u64, current: u64 },
}

/// The outcome of one reload evaluation.
#[derive(Debug)]
pub(crate) enum ReloadOutcome {
    /// A strictly-newer, in-window bundle re-verified; swap it in.
    Updated(VerifiedDirectory),
    /// The on-disk bundle is unchanged and still in-window; no swap.
    Unchanged,
    /// The running bundle expired with no valid successor; swap to deny-all.
    ExpiredWhileRunning,
    /// A strictly-newer, in-window successor re-verified but no longer binds THIS
    /// node's local transport endpoint (it tombstoned or rotated this node). The
    /// already-bound endpoint would keep serving with the old key, so the swap must
    /// NOT proceed as an admit; fail closed to deny-all (local-binding recheck,
    /// mirroring the startup binding check). Carries the (validly-signed,
    /// in-window, monotone) revoking directory so the reloader ADVANCES its last-good
    /// chain onto it: the revoker is now the federation's canonical directory, so a
    /// later successor that rebinds this node chains onto THIS revoker (not the
    /// pre-revoke version) and must be able to self-heal admission.
    LocalBindingRevoked(VerifiedDirectory),
    /// The directory is below a trusted `minVersion` operators raised above it, so it can
    /// never be admitted (a restart would reject it via `transport_bundle_trust`); fail
    /// closed to deny-all. `Some(successor)` is a strictly-newer, validly-signed, in-window
    /// successor that is itself below the raised floor: it cannot admit, but the reloader
    /// ADVANCES its last-good chain onto it (like [`ReloadOutcome::LocalBindingRevoked`]) so
    /// a later at-or-above-floor bundle - which chains onto THIS successor - self-heals
    /// rather than being stranded against a dropped chain. `None` is the running directory
    /// itself below the floor (the unchanged fast path, or a below-floor running directory
    /// whose on-disk successor did not verify): deny-all, chain KEPT.
    BelowMinVersionFloor(Option<VerifiedDirectory>),
    /// The on-disk bundle is UNCHANGED and still in-window, but it no longer verifies
    /// against the CURRENT trusted-issuer set: operators rotated or removed the issuer
    /// that signed it (or rotated its key) since the last verification. A restart would
    /// reject it via `transport_bundle_trust` (unknown issuer / invalid signature); the
    /// unchanged fast path must fail closed to deny-all identically rather than keep
    /// admitting under a signer the federation no longer trusts until expiry.
    TrustRootsChanged,
    /// The on-disk bundle carries the running version but a DIFFERENT canonical body: the
    /// file was replaced without a version bump (a tampered or out-of-band rotated body).
    /// It cannot be a monotone successor at the same version, and treating it as Unchanged
    /// would keep the loaded directory admitting peers the replacement dropped. Fail closed
    /// to deny-all; a proper versioned successor chained onto last-good self-heals.
    CurrentBodyReplaced,
    /// The trusted-issuers file parsed but pins NO issuer (operators removed every issuer).
    /// Trusting no signer must admit nothing, and startup rejects the same empty
    /// configuration; the reload must fail closed to deny-all rather than fold it into the
    /// transient keep-last-good read-error path (which would keep the previous signer active
    /// until expiry). Chain is KEPT so a successor under a restored issuer self-heals.
    TrustRootsEmpty,
}

/// Inputs for the bounded poll reloader. The reloader deliberately advances its
/// version floor + previous-hash chain from the LIVE directory (current_version /
/// current_body_sha256), not from a rotation-state file, so a downgrade can never
/// be re-accepted; hence no state-file path is carried here.
pub(crate) struct DirectoryReloadConfig {
    pub interval: Duration,
    pub bundle_path: PathBuf,
    pub trusted_issuers_path: PathBuf,
    /// This node's LOCAL transport binding: the `EndpointId` the running endpoint is
    /// actually bound to (the public half of the configured `--iroh-transport-key`).
    /// Rechecked against every re-verified successor BEFORE the swap:
    /// the startup path rejects a directory that does not endorse this binding, and a
    /// live successor that tombstones or rotates this node must not be swapped in while
    /// the endpoint keeps serving with the old key. The recheck fails closed to deny-all.
    pub local_transport_endpoint: EndpointId,
    /// This node's `localKernelId` (the identity the running endpoint authenticates AS,
    /// carried by the body-hash-pinned directory document and matched at startup). The
    /// binding recheck mirrors the startup check EXACTLY: it requires the successor to
    /// bind THIS kernel id to THIS endpoint (`resolve_transport_endpoint(local_kernel_id)
    /// == local_transport_endpoint`). Checking only that the endpoint resolves to SOME
    /// kernel is insufficient: a successor that reassigns this endpoint to a DIFFERENT
    /// kernel id would still `authorize` it, yet the relay would keep serving under the
    /// old secret for an identity the directory no longer binds to this node.
    pub local_kernel_id: String,
}

/// Read + parse the on-disk transport directory bundle (no verification).
fn read_bundle_document(path: &Path) -> Result<TransportDirectoryBundleDocument, String> {
    let json = read_utf8_json_file(path, "Chio iroh transport directory bundle")
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&json).map_err(|error| error.to_string())
}

/// The canonical sha256 of a parsed bundle document. This matches the value the gate
/// reports as `current_body_sha256` and that a successor pins as `previousVersionSha256`
/// (`VerifiedDirectory::body_sha256` hashes the same whole document), so the reloader can
/// tell a byte-unchanged bundle from a same-version replacement without re-verifying.
fn bundle_body_sha256(bundle: &TransportDirectoryBundleDocument) -> Result<String, String> {
    let bytes = chio_core_types::canonical_json_bytes(bundle).map_err(|error| error.to_string())?;
    Ok(chio_core_types::sha256_hex(&bytes))
}

/// A trusted-issuers reload failure. `Empty` is a DISTINCT fail-closed condition (the
/// file parsed but pins no issuer, so no signer is trusted) kept apart from a transient
/// `Read`/parse error that keeps last-good.
enum TrustedIssuersReloadError {
    /// The file could not be read or parsed (transient); keep last-good.
    Read(String),
    /// The file parsed but pins NO issuer. Trusting no signer must admit nothing, so this
    /// fails closed to deny-all rather than keeping the previous signer active until expiry.
    Empty,
}

/// Read + parse the trusted-issuers file into the verifier's issuer list PLUS the
/// trusted `minVersion` (absent -> 0). The reload path honors this floor identically
/// to the startup loader: operators that raise `minVersion` on a running relay
/// must have it enforced on the NEXT reload, not only at restart. An empty issuer set is
/// surfaced as [`TrustedIssuersReloadError::Empty`] so callers fail closed rather than
/// folding it into the transient keep-last-good read-error path.
fn read_trusted_issuers(
    path: &Path,
) -> Result<(Vec<TrustedTransportDirectoryIssuer>, u64), TrustedIssuersReloadError> {
    let json = read_utf8_json_file(path, "Chio iroh transport trusted issuers")
        .map_err(|error| TrustedIssuersReloadError::Read(error.to_string()))?;
    let document: super::relay::RelayTrustedIssuersDocument = serde_json::from_str(&json)
        .map_err(|error| TrustedIssuersReloadError::Read(error.to_string()))?;
    let trusted_min_version = document.min_version.unwrap_or(0);
    let issuers: Vec<TrustedTransportDirectoryIssuer> = document
        .issuers
        .into_iter()
        .map(|issuer| TrustedTransportDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect();
    if issuers.is_empty() {
        return Err(TrustedIssuersReloadError::Empty);
    }
    Ok((issuers, trusted_min_version))
}

/// Re-verify the directory bundle, fail-closed. EXPIRY IS CHECKED BEFORE THE
/// UNCHANGED FAST PATH: an unchanged-but-expired bundle must not be treated as
/// valid; with no strictly-newer in-window successor it fails closed as
/// `ExpiredWhileRunning`.
pub(crate) fn reload_verified_directory(
    config: &DirectoryReloadConfig,
    now: u64,
    current_version: u64,
    current_expires_at_unix_ms: u64,
    current_body_sha256: &str,
) -> Result<ReloadOutcome, DirectoryReloadError> {
    let expired = current_expires_at_unix_ms <= now;

    // Read the on-disk bundle. If it cannot be read and the running bundle is
    // expired, we cannot keep serving it -> fail closed; else keep last-good.
    let bundle = match read_bundle_document(&config.bundle_path) {
        Ok(bundle) => bundle,
        Err(error) => {
            if expired {
                return Ok(ReloadOutcome::ExpiredWhileRunning);
            }
            return Err(DirectoryReloadError::Read(error));
        }
    };

    // Fast path ONLY when still in-window: a genuinely unchanged, still-valid
    // bundle needs no re-verify. Guarded by `!expired` so an expired bundle can
    // never be short-circuited as Unchanged.
    if !expired && bundle.body.version == current_version {
        // The unchanged fast path is only sound when the on-disk body is BYTE-identical to
        // the loaded one. A same-version file whose canonical body differs (a tampered or
        // out-of-band rotated body, possibly re-signed by rotated trust roots) is a
        // substitution, not the running directory: it cannot be a monotone successor at the
        // same version, and reporting it Unchanged would keep the loaded directory admitting
        // peers the replacement dropped. Fail closed to deny-all instead; a proper versioned
        // successor chained onto last-good self-heals. Compare hashes BEFORE the fast path.
        match bundle_body_sha256(&bundle) {
            Ok(on_disk) if on_disk != current_body_sha256 => {
                return Ok(ReloadOutcome::CurrentBodyReplaced);
            }
            Ok(_) => {}
            Err(error) => return Err(DirectoryReloadError::Verify(error)),
        }
        // The unchanged fast path must be exactly as strict as a restart: an operator can
        // change the trusted-issuer set (raise `minVersion`, or rotate/remove the signing
        // issuer) while the on-disk bundle is byte-unchanged. Re-read the current trust so
        // the fast path enforces it rather than serving a stale-but-now-untrusted directory
        // until expiry. A transient read error must NOT tear down a still-in-window
        // directory, so keep last-good (`Err(Read)`) exactly as the strictly-newer path.
        let (issuers, trusted_min_version) =
            match read_trusted_issuers(&config.trusted_issuers_path) {
                Ok(parsed) => parsed,
                Err(TrustedIssuersReloadError::Empty) => return Ok(ReloadOutcome::TrustRootsEmpty),
                Err(TrustedIssuersReloadError::Read(error)) => {
                    return Err(DirectoryReloadError::Read(error))
                }
            };
        // minVersion is INCLUSIVE: a directory at `current_version` is admissible only
        // when `current_version >= trusted_min_version`. Below that floor, fail closed. The
        // running directory is unchanged (no successor to advance the chain onto), so keep
        // last-good (`None`) and let a successor at or above the floor self-heal.
        if current_version < trusted_min_version {
            return Ok(ReloadOutcome::BelowMinVersionFloor(None));
        }
        // RE-VERIFY THE UNCHANGED BUNDLE AGAINST THE CURRENT TRUST ROOTS (fail-closed).
        // The gate authorized this bundle against the issuer set that was trusted when it
        // was last verified; that set can shrink underneath a running relay (an operator
        // rotates or removes the issuer that signed it). A bundle signed by an issuer the
        // federation no longer trusts must stop admitting immediately, exactly as a restart
        // would reject it via `transport_bundle_trust`. Chain onto the bundle's own recorded
        // predecessor (its identity is unchanged, so this re-check is a pure signature/issuer
        // re-validation, not a rollback re-evaluation) and floor just below the running
        // version so the current version is still admissible. Any verification failure
        // (unknown issuer, invalid signature) fails closed to deny-all.
        let trust = TransportDirectoryBundleTrust {
            issuers,
            version_floor: current_version.saturating_sub(1),
            expected_previous_version_sha256: bundle.body.previous_version_sha256.clone(),
            now_unix_ms: now,
        };
        return match bundle.verify_bundle(&trust) {
            Ok(_verified) => Ok(ReloadOutcome::Unchanged),
            Err(_error) => Ok(ReloadOutcome::TrustRootsChanged),
        };
    }

    if bundle.body.version > current_version {
        // Strictly newer: verify against a floor of the current version, chaining
        // onto the current body hash, with a FRESH now. verify_bundle's validity
        // window rejects an already-expired successor, so an expired bundle cannot
        // be swapped in.
        let (issuers, trusted_min_version) =
            match read_trusted_issuers(&config.trusted_issuers_path) {
                Ok(parsed) => parsed,
                Err(TrustedIssuersReloadError::Empty) => return Ok(ReloadOutcome::TrustRootsEmpty),
                Err(TrustedIssuersReloadError::Read(error)) => {
                    if expired {
                        return Ok(ReloadOutcome::ExpiredWhileRunning);
                    }
                    return Err(DirectoryReloadError::Read(error));
                }
            };
        // minVersion is INCLUSIVE: a successor is admissible only when its version is at or
        // above the trusted floor. A successor newer than the running version but STILL
        // BELOW that floor (operators raised minVersion past this staged version) can never
        // be admitted. It is still VERIFIED against the preserved chain so a valid one
        // ADVANCES last-good onto it (deny-all, like `LocalBindingRevoked`): a below-floor
        // successor is the immediate predecessor a later at-or-above-floor bundle chains
        // onto, so dropping it here would strand that recovery bundle (predecessor mismatch)
        // in deny-all until restart. A below-floor successor implies the running directory
        // is below the floor too, so a successor that does NOT verify still fails closed to
        // deny-all rather than keeping the below-floor directory admitting.
        if bundle.body.version < trusted_min_version {
            let trust = TransportDirectoryBundleTrust {
                issuers,
                version_floor: current_version,
                expected_previous_version_sha256: Some(current_body_sha256.to_string()),
                now_unix_ms: now,
            };
            return Ok(match bundle.verify_bundle(&trust) {
                Ok(verified) => ReloadOutcome::BelowMinVersionFloor(Some(verified)),
                Err(_error) => ReloadOutcome::BelowMinVersionFloor(None),
            });
        }
        let trust = TransportDirectoryBundleTrust {
            issuers,
            version_floor: current_version,
            expected_previous_version_sha256: Some(current_body_sha256.to_string()),
            now_unix_ms: now,
        };
        return match bundle.verify_bundle(&trust) {
            Ok(verified) => {
                // RECHECK THE LOCAL IDENTITY BINDING BEFORE SWAPPING (fail-closed).
                // The successor verified as a valid, in-window, monotone directory, but that
                // does NOT prove it still binds THIS node's local identity the way the startup
                // path (`load_iroh_serve_inputs` + `build_iroh_router`) requires. Mirror BOTH
                // startup checks EXACTLY, or a successor a restart would reject could be swapped
                // in live:
                //   - `resolve_transport_endpoint(local_kernel_id) == local_transport_endpoint`
                //     denies a successor that TOMBSTONES this node (resolve None), ROTATES its
                //     endpoint to a different `EndpointId` (resolve returns the new endpoint), or
                //     REASSIGNS the bound endpoint to a DIFFERENT kernel id (resolving THIS kernel
                //     yields a different or no endpoint); and
                //   - `directory.localKernelId == local_kernel_id` denies a successor that keeps
                //     this node's endpoint binding but REASSIGNS the directory's declared local
                //     identity: `build_iroh_router` requires the bundle's own `localKernelId` to
                //     equal the relay's configured local kernel id, so a restart would reject
                //     such a bundle even though the endpoint binding survives.
                // In every case the already-bound endpoint would keep serving iroh ingress under
                // the OLD `SecretKey` for a local identity the successor no longer binds to this
                // node. Fail closed to deny-all rather than admit under a revoked local identity.
                let binds_local_endpoint = verified
                    .resolve_transport_endpoint(&config.local_kernel_id)
                    == Some(config.local_transport_endpoint);
                let declares_local_kernel =
                    bundle.directory.local_kernel_id == config.local_kernel_id;
                if binds_local_endpoint && declares_local_kernel {
                    Ok(ReloadOutcome::Updated(verified))
                } else {
                    Ok(ReloadOutcome::LocalBindingRevoked(verified))
                }
            }
            Err(error) => {
                // A successor at or above the floor that fails verification (partially
                // written or bad) must NOT mask a running directory that is ITSELF below the
                // raised floor: a restart would reject the running directory via
                // `transport_bundle_trust`, so fail closed to deny-all rather than keep the
                // below-floor directory admitting until expiry. Order this ahead of the
                // transient paths so a bad successor cannot leave a below-floor directory
                // live. last-good is KEPT so a valid successor chained onto it self-heals.
                if current_version < trusted_min_version {
                    Ok(ReloadOutcome::BelowMinVersionFloor(None))
                } else if expired {
                    Ok(ReloadOutcome::ExpiredWhileRunning)
                } else {
                    Err(DirectoryReloadError::Verify(error.to_string()))
                }
            }
        };
    }

    // version <= current and not the in-window-unchanged case: either a rollback
    // attempt or an expired bundle with no newer successor. Fail closed if
    // expired; else reject the rollback and keep last-good.
    if expired {
        Ok(ReloadOutcome::ExpiredWhileRunning)
    } else {
        Err(DirectoryReloadError::Rollback {
            found: bundle.body.version,
            current: current_version,
        })
    }
}

/// The reloader's LAST-GOOD directory identity, tracked SEPARATELY from the admission
/// gate. A fail-closed deny-all swap (expiry / binding revoked) must NOT erase the
/// version + hash chain the next successor verifies against: if the reloader re-read
/// these from the gate, an expiry swap would leave the gate at the deny-all sentinel
/// (version 0, empty hash), and a later successor chained onto the last good bundle
/// would then fail verification (predecessor version/hash mismatch), stranding the
/// relay in deny-all until a restart. Holding last-good here lets the reloader SELF-HEAL
/// back to admission when a valid in-window successor appears.
struct ReloadState {
    version: u64,
    body_sha256: String,
    expires_at_unix_ms: u64,
}

impl ReloadState {
    /// Seed from the load-time-verified gate.
    fn from_gate(gate: &DirectoryGate) -> Self {
        Self {
            version: gate.current_version(),
            body_sha256: gate.current_body_sha256(),
            expires_at_unix_ms: gate.current_expires_at_unix_ms(),
        }
    }
}

/// One reload evaluation: re-verify against the preserved last-good chain and either
/// swap in a successor (advancing last-good), alarm + deny-all on expiry / binding
/// revocation (WITHOUT touching last-good, so a later successor can self-heal), or keep
/// last-good on a transient error. Extracted from the poll loop so the last-good
/// preservation + self-heal is unit-testable without the async timer.
fn directory_reload_step(
    gate: &DirectoryGate,
    config: &DirectoryReloadConfig,
    now: u64,
    state: &mut ReloadState,
    alive: &std::sync::atomic::AtomicBool,
) {
    use std::sync::atomic::Ordering;
    match reload_verified_directory(
        config,
        now,
        state.version,
        state.expires_at_unix_ms,
        &state.body_sha256,
    ) {
        Ok(ReloadOutcome::Updated(next)) => {
            // Advance the last-good chain to the newly-verified successor BEFORE the swap,
            // so a subsequent reload (and any recovery from a later lapse) chains onto it.
            // This is also the self-heal path back from a deny-all lapse: a valid in-window
            // successor verified against the preserved last-good chain restores admission
            // without a restart.
            state.version = next.version();
            state.body_sha256 = next.body_sha256().to_string();
            state.expires_at_unix_ms = next.expires_at_unix_ms();
            gate.swap(Arc::new(next));
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_UPDATED,
            );
        }
        Ok(ReloadOutcome::Unchanged) => {
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_UNCHANGED,
            );
        }
        Ok(ReloadOutcome::ExpiredWhileRunning) => {
            // Fail closed to deny-all but KEEP last-good (state untouched): a later valid
            // in-window successor chained onto it re-verifies and self-heals admission.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_EXPIRED_FAILCLOSED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory expired with no valid successor; admitting nothing until a \
                 valid in-window successor is published"
            );
        }
        Ok(ReloadOutcome::LocalBindingRevoked(revoking)) => {
            // The successor verified but no longer binds this node's local identity the way
            // startup requires: it tombstoned this node, rotated or reassigned its bound
            // transport endpoint, or reassigned the directory's declared `localKernelId` away
            // from this node. The endpoint is still bound with the old key, so admitting peers
            // from the successor would serve ingress under a revoked identity. Fail closed to
            // deny-all and raise the same alarm as expiry.
            //
            // ADVANCE the last-good chain onto the revoking directory FIRST. The revoker is
            // a validly-signed, in-window, monotone directory: it is now the federation's
            // canonical successor, so a later directory that rebinds this node chains onto
            // THIS revoker's hash/version, not the pre-revoke version. Leaving the chain
            // pinned to the pre-revoke version would reject that correctly-chained rebinding
            // successor (predecessor mismatch) and strand the relay in deny-all until a
            // restart. The gate stays deny-all (we do NOT swap the revoker in, since it does
            // not bind this node); only the chain reference advances, so the documented
            // self-heal path works after a rebind.
            state.version = revoking.version();
            state.body_sha256 = revoking.body_sha256().to_string();
            state.expires_at_unix_ms = revoking.expires_at_unix_ms();
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_BINDING_REVOKED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory successor no longer binds this node's local identity \
                 (tombstoned, endpoint rotated or reassigned, or declared local kernel id \
                 changed); admitting nothing until a successor rebinds this node"
            );
        }
        Ok(ReloadOutcome::BelowMinVersionFloor(maybe_successor)) => {
            // The directory is below a trusted minVersion operators raised above it. A
            // restart would reject it, so fail closed to deny-all rather than keep admitting
            // until expiry.
            //
            // If a strictly-newer, validly-signed successor is present, it is itself below
            // the raised floor: it cannot admit, but ADVANCE the last-good chain onto it (as
            // `LocalBindingRevoked` does) so a later at-or-above-floor bundle chained onto
            // THIS successor self-heals instead of being stranded against a dropped chain.
            // Absent a successor (the unchanged running directory, or a below-floor running
            // directory whose successor did not verify), last-good is KEPT.
            if let Some(successor) = maybe_successor {
                state.version = successor.version();
                state.body_sha256 = successor.body_sha256().to_string();
                state.expires_at_unix_ms = successor.expires_at_unix_ms();
            }
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_BELOW_MIN_VERSION,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory version is below the trusted minVersion floor operators \
                 raised; admitting nothing until a successor at or above the floor is published"
            );
        }
        Ok(ReloadOutcome::TrustRootsChanged) => {
            // The running directory is unchanged and in-window but its signing issuer is no
            // longer trusted (operators rotated or removed it). A restart would reject it, so
            // fail closed to deny-all rather than keep admitting under an untrusted signer.
            // last-good is KEPT (state untouched): a later successor signed by a currently
            // trusted issuer, chained onto the running directory, self-heals admission without
            // a restart.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_TRUST_ROOTS_CHANGED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory signing issuer is no longer trusted; admitting nothing \
                 until a successor signed by a currently trusted issuer is published"
            );
        }
        Ok(ReloadOutcome::CurrentBodyReplaced) => {
            // The on-disk bundle carries the running version but a different body: the file
            // was replaced without a version bump, so it cannot be trusted as a monotone
            // successor. Fail closed to deny-all rather than keep the loaded directory
            // admitting. last-good is KEPT (state untouched): a properly versioned successor
            // chained onto the running directory self-heals admission without a restart.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_CURRENT_BODY_REPLACED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory file was replaced at the running version with a different \
                 body; admitting nothing until a properly versioned successor is published"
            );
        }
        Ok(ReloadOutcome::TrustRootsEmpty) => {
            // The trusted-issuers file now pins no issuer: operators removed every issuer.
            // Trusting no signer must admit nothing, and startup rejects the same empty
            // configuration, so fail closed to deny-all rather than keep the previous signer
            // active until expiry. last-good is KEPT (state untouched): a successor under a
            // restored trusted issuer, chained onto the running directory, self-heals.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_TRUST_ROOTS_EMPTY,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory trusted-issuer set is empty; admitting nothing until a \
                 trusted issuer is restored and a successor it signs is published"
            );
        }
        Err(error) => {
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_ERROR,
            );
            tracing::warn!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                error = %error,
                "transport directory reload failed; keeping last-good"
            );
        }
    }
}

/// The reloader's next wake delay, driven by the LIVE admission gate's directory rather
/// than the reloader's last-good chain (which can point past a deny-all gate at an
/// already-advanced successor). `live_directory_expires_at_unix_ms` is
/// `DirectoryGate::current_expires_at_unix_ms`: `0` is the deny-all sentinel (admits
/// nothing), and any positive value is a live directory's validity-window end.
///
/// - Deny-all gate: poll on the fixed `interval` for a valid successor. No live directory
///   is admitting, so there is no expiry to enforce and never a zero-delay busy-loop.
/// - Live directory still in-window: wake at whichever comes first, the next fixed poll or
///   the expiry deadline, so a bundle that expires between two fixed polls fails closed AT
///   the deadline (`DirectoryGate::decide` is not itself time-aware).
/// - Live directory whose deadline elapsed mid-cycle (the step ran while it was in-window,
///   so the gate is still admitting it): recheck IMMEDIATELY so the next step fails it
///   closed at the deadline rather than after another full interval.
fn next_reload_delay(
    interval: Duration,
    now: u64,
    live_directory_expires_at_unix_ms: u64,
) -> Duration {
    if live_directory_expires_at_unix_ms == 0 {
        interval
    } else if live_directory_expires_at_unix_ms > now {
        std::cmp::min(
            interval,
            Duration::from_millis(live_directory_expires_at_unix_ms - now),
        )
    } else {
        Duration::ZERO
    }
}

/// Bounded poll loop: re-verify the directory and either swap in a successor, alarm +
/// deny-all on expiry, or keep last-good. Wakes at most every `interval`, but also
/// exactly at the running directory's expiry deadline (see [`next_reload_delay`]) so an
/// expired directory fails closed promptly instead of admitting until the next fixed
/// poll. A dedicated task feeds shared state (the admission gate and the alive flag)
/// and is joined on shutdown.
pub(crate) async fn run_directory_reloader(
    gate: DirectoryGate,
    config: DirectoryReloadConfig,
    now_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut state = ReloadState::from_gate(&gate);
    loop {
        let now = now_fn();
        directory_reload_step(&gate, &config, now, &mut state, &alive);
        // Schedule off the LIVE gate's expiry (re-read after the step and with a fresh
        // clock): if the directory was still admitting at the step but its deadline elapsed
        // before this delay is computed, the gate expiry is now in the past and the reloader
        // rechecks immediately to fail it closed, rather than admitting for another interval.
        let delay = next_reload_delay(config.interval, now_fn(), gate.current_expires_at_unix_ms());
        tokio::time::sleep(delay).await;
    }
}

/// Per-tick router-liveness step, testable without a live router: flip the
/// `chio_iroh_router_alive` gauge and, on the transition to dead, log an alarm so a
/// panicked accept task that silently kills the router (while HTTP keeps serving)
/// becomes loud. Returns the liveness it was given.
pub(crate) fn note_router_liveness(alive: bool) -> bool {
    chio_federation_transport_iroh::metrics::set_router_alive(alive);
    if !alive {
        tracing::error!(
            target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
            "iroh router is down; federation ingress frozen while HTTP keeps serving"
        );
    }
    alive
}

/// Build and spawn the iroh router, sharing the relay's receiver + store.
///
/// One `Endpoint` with the [`DirectoryGate`] installed via `.hooks(gate)` (so
/// unadmitted endpoints are 403'd at `after_handshake` before any handler runs),
/// the configured `RelayMode`, the configured bind address, and the recommended
/// QUIC idle-timeout backstop. The pheromone lane is mounted with the SAME
/// `Arc<dyn RelayBatchReceiver>` + `Arc<SqlitePheromoneRelayStore>` the HTTP relay
/// holds. Fail-closed: any bind/verify error returns `Err`.
///
/// `peer_directory` is the SAME issuer-verified peer directory the HTTP relay holds;
/// the iroh ingress handler enforces `enforce_peer_batch_directory_scope` against it
/// before every `receive_batch`, so both transports apply one identical inbound scope
/// gate (an out-of-scope sender is rejected on the iroh path exactly as over HTTP).
///
/// `max_batch_bytes` is the relay profile's configured body-size limit (the HTTP
/// relay's `DefaultBodyLimit`); the ingress handler rejects any frame over it before
/// deserialization, so the iroh path is never a laxer ingress than HTTP.
pub(crate) async fn build_iroh_router(
    inputs: IrohServeInputs,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
    peer_directory: PeerDirectory,
    max_batch_bytes: usize,
) -> Result<IrohMount, CliError> {
    let IrohServeInputs {
        directory,
        transport_key,
        transport_local_kernel_id,
        config,
    } = inputs;

    // FAIL-CLOSED WIRING GUARD: only the pheromone lane is wireable on this serve
    // hook. Enabling lane c (fan-out) here is a fail-closed error and MUST stay so
    // until BOTH are satisfied: (1) the gossip Lagged handling has an anti-entropy
    // path or an explicit accepted-loss decision, and (2) any lane-c
    // mount passes the issuer-signed VerifiedDirectory (never a StaticTreatyMembership
    // and never the raw topic id) as the TreatyMembership oracle and derives origin
    // keys from the same trusted admission set. The per-treaty membership gate is
    // enforced at JOIN (subscribe_treaty_with_timeout) and RECEIVE
    // (verify_fanout_frame); this guard keeps it that way. parse_iroh_lanes already
    // rejected anything else, so this is a defense-in-depth re-check.
    if config
        .lanes
        .iter()
        .any(|lane| !matches!(lane, IrohLane::Pheromone))
    {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: only the pheromone lane is wireable on the relay serve hook"
                .to_string(),
        ));
    }

    // Fail-closed relay/transport identity binding. The transport directory's own
    // `localKernelId` (the identity this endpoint authenticates AS, verified at load time
    // to match the endorsed transport key) MUST equal the relay's configured local
    // identity, which is `peer_directory.local_kernel_id()` (the SAME value the HTTP relay
    // sets as `PheromoneRelayConfig.local_kernel_id` and its receiver verifies every
    // inbound batch against). If they differ, the iroh endpoint authenticates as a
    // DIFFERENT kernel than the receiver expects, so valid deliveries are
    // rejected/dead-lettered while startup silently "succeeds". Reject BEFORE binding the
    // endpoint so the mount never comes up authenticating as the wrong kernel.
    let relay_local_kernel_id = peer_directory.local_kernel_id();
    if transport_local_kernel_id != relay_local_kernel_id {
        return Err(CliError::cli_other_error(format!(
            "Chio iroh transport: the transport directory's local kernel id '{transport_local_kernel_id}' \
             does not match the relay's configured local kernel id '{relay_local_kernel_id}'; the iroh \
             endpoint would authenticate as a different kernel than the relay's receiver verifies inbound \
             batches as, so valid deliveries would be rejected/dead-lettered"
        )));
    }

    let gate = DirectoryGate::new(directory);

    let idle_timeout: IdleTimeout = config.max_idle_timeout.try_into().map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport idle timeout: {error}"))
    })?;
    // Each direct lane uses exactly one bidi stream per connection; bound the
    // per-connection window to the batch cap with headroom.
    let bidi_streams =
        VarInt::from(chio_federation_transport_iroh::lanes::limits::RECOMMENDED_MAX_BIDI_STREAMS);
    let receive_window = VarInt::from_u64(
        chio_federation_transport_iroh::lanes::limits::recommended_receive_window_bytes(
            max_batch_bytes,
        ),
    )
    .unwrap_or(VarInt::MAX);
    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidi_streams)
        .receive_window(receive_window)
        .build();

    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(transport_key)
        .relay_mode(config.relay_mode)
        .transport_config(transport_config)
        // iroh's Endpoint builder is pre-seeded with BOTH default IP transports
        // (0.0.0.0 AND [::]); `bind_addr` only replaces the default for the address
        // FAMILY it names, so a single-family bind (e.g. 127.0.0.1:4433) would still
        // open an IPv6 wildcard ([::]) socket and expose the lane on an unintended
        // interface. Clear all default IP transports FIRST, then bind exactly the one
        // operator-intended address (`clear_ip_transports` removes every IP transport,
        // so it MUST precede `bind_addr` or it would drop the address just added).
        .clear_ip_transports()
        .bind_addr(config.bind_addr)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport bind address: {error}"))
        })?
        .hooks(gate.clone())
        .bind()
        .await
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport endpoint bind: {error}"))
        })?;
    let endpoint_id = endpoint.id();
    // Capture the ACTUAL bound socket(s) before the endpoint is moved into the
    // router. With the default ephemeral port this is the operator's only way to
    // learn the reachable address to configure on peers.
    let bound_sockets = endpoint.bound_sockets();

    // The shared clock the handler stamps received batches with.
    let now_fn: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(unix_now_ms);
    // Inbound directory-scope gate: reuse the shipped enforce_peer_batch_directory_scope
    // against the SAME peer directory the HTTP relay holds, so the iroh ingress path
    // applies the identical Origin/Hub + frame-cap + treaty-subscription + ladder-pin
    // check the HTTP handle_batch_relay runs before receive_batch (fail-closed).
    let scope_check: InboundBatchScopeCheck = Arc::new(move |sender, batch| {
        enforce_peer_batch_directory_scope(&peer_directory, sender, batch)
    });
    // Enforce the SAME body-size limit the HTTP relay applies (the relay profile's
    // max_body_bytes: 256 KiB production / 1 MiB local-dev) on the iroh ingress, so
    // the new transport is no laxer than the HTTP `DefaultBodyLimit` (fail-closed;
    // clamped to the transport hard cap inside the handler).
    // Clone the gate for the handler (it also feeds the installed .hooks(gate)):
    // the mount keeps a clone so the reloader can swap the shared directory.
    let handler = PheromoneBatchHandler::new(gate.clone(), receiver, store, now_fn, scope_check)
        .with_max_batch_bytes(max_batch_bytes);
    let router = mount_pheromone_lane(endpoint, handler);

    let enabled_lanes = config.lanes.iter().map(|lane| lane.label()).collect();
    Ok(IrohMount {
        router,
        endpoint_id,
        bound_sockets,
        enabled_lanes,
        gate,
        transport_local_kernel_id,
    })
}

/// Bind an OUTBOUND-only iroh endpoint for the relay tick's outbound drain
/// (`drain_outbox_over_iroh`).
///
/// This is the SAME gated endpoint [`build_iroh_router`] binds (the `DirectoryGate`
/// hooks, the configured relay mode, QUIC idle timeout, and rotatable transport key),
/// but on an EPHEMERAL outbound bind (the configured `--iroh-bind-addr`'s local
/// interface with the port zeroed) rather than the stable serving bind address, and
/// WITHOUT mounting an accept handler: the tick only DIALS recipients to deliver
/// queued batches, it does not accept inbound streams, so it needs no stable inbound
/// port and must NOT contend for the port a running serve process already holds.
/// Returns
/// the bound endpoint plus the issuer-verified transport directory the recipient
/// address resolver is derived from (kernel_id -> transport `EndpointId`). Fail-closed:
/// any bind error returns `Err`.
///
/// # Reachability
///
/// The verified transport directory binds `(kernel_id -> transport EndpointId)`; it
/// does NOT carry per-peer dialable socket addresses. So the tick resolves a recipient
/// to an EndpointId and then threads any direct socket(s) from the out-of-band
/// `--iroh-peer-addr` book onto it (the direct-address deployment). Where the
/// deployment instead provides path discovery (a configured `--iroh-relay-url` plus
/// discovery, mirroring how the serve mount logs its bound socket for operators to
/// configure on peers) the id-only address resolves without a book entry. Either way,
/// a recipient with no dialable path folds into the durable retry/dead-letter path
/// fail-closed (it never drops the batch).
pub(crate) async fn build_iroh_outbound_endpoint(
    inputs: IrohServeInputs,
    relay_local_kernel_id: &str,
) -> Result<(Endpoint, Arc<VerifiedDirectory>), CliError> {
    let IrohServeInputs {
        directory,
        transport_key,
        transport_local_kernel_id,
        config,
    } = inputs;

    // Fail-closed relay/transport identity binding, mirroring the serve path in
    // [`build_iroh_router`]: the transport directory's `localKernelId` (verified at load
    // time to match the endorsed transport key) MUST equal the relay's configured local
    // identity. If they differ, this outbound tick endpoint dials as a different kernel
    // than the relay's peers expect, so deliveries are rejected/dead-lettered. Reject
    // before binding the endpoint.
    if transport_local_kernel_id != relay_local_kernel_id {
        return Err(CliError::cli_other_error(format!(
            "Chio iroh transport: the transport directory's local kernel id '{transport_local_kernel_id}' \
             does not match the relay's configured local kernel id '{relay_local_kernel_id}'; the iroh tick \
             endpoint would dial as a different kernel than the relay's peers expect"
        )));
    }

    // Only the pheromone lane is drainable here; parse_iroh_lanes already rejected
    // anything else, so this is a defense-in-depth re-check.
    if config
        .lanes
        .iter()
        .any(|lane| !matches!(lane, IrohLane::Pheromone))
    {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: only the pheromone lane is drainable on the relay tick hook"
                .to_string(),
        ));
    }

    // Install the admission gate even though this endpoint only dials: it is harmless
    // for an outbound-only endpoint and keeps the identity + relay setup byte-identical
    // to the serve mount. The directory is cloned so the caller keeps it for address
    // resolution.
    let gate = DirectoryGate::new(directory.clone());
    let idle_timeout: IdleTimeout = config.max_idle_timeout.try_into().map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport idle timeout: {error}"))
    })?;
    // Drain endpoint: one bidi stream, batch-cap-bounded window. `max_batch_bytes`
    // is not in scope on this outbound-only path, so derive the window from the
    // transport hard cap.
    let bidi_streams =
        VarInt::from(chio_federation_transport_iroh::lanes::limits::RECOMMENDED_MAX_BIDI_STREAMS);
    let receive_window = VarInt::from_u64(
        chio_federation_transport_iroh::lanes::limits::recommended_receive_window_bytes(
            chio_federation_transport_iroh::lanes::pheromone::MAX_PHEROMONE_BATCH_BYTES,
        ),
    )
    .unwrap_or(VarInt::MAX);
    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidi_streams)
        .receive_window(receive_window)
        .build();
    // An outbound-only TICK endpoint must NOT reuse the stable serving
    // `--iroh-bind-addr`. When a durable relay-serve process is already listening on
    // that addr:port (the deployment the serve log recommends), a second (tick)
    // process that reused the exact addr:port would fail to bind the already-in-use
    // UDP port, so iroh delivery would be unusable. Keep the configured local
    // interface (IP family) but zero the port so the OS assigns a free EPHEMERAL port:
    // the tick only DIALS, so it needs no stable inbound port. This is the one place
    // the tick (outbound, ephemeral) path diverges from the serve (inbound, stable
    // addr) path [`build_iroh_router`] takes.
    let mut outbound_bind_addr = config.bind_addr;
    outbound_bind_addr.set_port(0);
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(transport_key)
        .relay_mode(config.relay_mode)
        .transport_config(transport_config)
        // Clear both default IP transports (0.0.0.0 AND [::]) before binding, so the
        // ephemeral outbound socket lives on ONLY the operator-intended address family/
        // interface and never opens an unintended IPv6 wildcard socket. Must precede
        // `bind_addr` (see the serve-path bind for the full rationale).
        .clear_ip_transports()
        .bind_addr(outbound_bind_addr)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport bind address: {error}"))
        })?
        .hooks(gate)
        .bind()
        .await
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport endpoint bind: {error}"))
        })?;
    Ok((endpoint, directory))
}

#[cfg(test)]
#[path = "iroh_mount/tests.rs"]
mod tests;
