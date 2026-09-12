//! Example: a cross-organization tool call between two separately administered
//! kernels running as two OS processes.
//!
//! Everything the in-tree treaty benchmarks do inside one process is split here
//! across a process boundary: Org A (`origin`) holds only Org A's keys, Org B
//! (`receiver`) holds only Org B's keys and its own SQLite receipt and revocation
//! stores, and the two never share a heap. What crosses the network is the
//! request, the receiver's verdict, the co-signing hops the receiver's kernel
//! makes back to Org A, and Org A's signed revocation clock. An admitted call
//! costs three of those hops, measured rather than assumed: one for the evidence
//! the receiver mints before the call, two inside the admission decision.
//!
//! ```text
//!   send ----- tool call (experiment ALPN) -----> receiver (Org B kernel)
//!                                                    |
//!     origin <--- receipt co-sign (lane d, profile 2) |
//!     origin <--- DSSE co-sign     (lane d, profile 1) |
//!     origin ---> signed epoch roots (lane b) ---------+
//! ```
//!
//! Two hosts is the same command with different addresses: every socket comes
//! from `--bind` and `--peer KERNEL_ID=HOST:PORT`, and relays are disabled, so
//! the only change is which host names appear in the flags. The benchmark script
//! makes that split explicit: it is run once per machine with disjoint roles and
//! records the host count from the roles it actually started.
//!
//! ## Subcommands
//!
//! * `keygen --kernel-id ID --dir DIR` writes one organization's secrets and the
//!   public half the directory issuer needs. Every key is freshly generated.
//! * `directory --issuer-dir DIR --public FILE ... --out-dir DIR` acts as the
//!   third-party issuer: it signs the transport directory bundle that binds both
//!   kernels and writes the shared treaty both organizations agreed to.
//! * `origin` runs Org A: the two co-sign handlers and the revocation epoch
//!   ticker.
//! * `receiver` runs Org B: a `ChioKernel` behind the runtime admission hook,
//!   with the iroh co-signers and the revocation bridge installed, plus the
//!   experiment-only tool-call ALPN.
//! * `send --scenario S --calls N` drives calls and records round-trip latency
//!   together with the receiver's decomposition of each evaluation window.
//! * `baseline --calls N` makes the same tool call with the kernel out of the
//!   path, over the same lane, so admission has a denominator.
//! * `load --workers N --calls M` holds N admissions in flight at once and
//!   reports throughput against the wall clock rather than one over the latency.
//! * `race --workers N [--repeats R]` puts N calls that present the SAME
//!   single-use continuation in flight at once and asserts that exactly one is
//!   admitted, that the rest carry the replay code, and that the receiver
//!   dispatched exactly once.
//! * `preflight --target ID` probes reachability and the clock offset between
//!   this host and another and refuses a split run whose clocks disagree by more
//!   than the bound.
//! * `revoke --capability-id ID [--repeats N]` advances Org A's epoch with a
//!   revoked capability and measures calls until the receiver's first denial.
//! * `cut [--repeats N]` stops Org A's ticker and measures time to the first
//!   freshness denial. Both report every repeat, because each observation costs
//!   one control-file poll period and one call of polling resolution.
//!
//! ## What the receiver measures about itself
//!
//! The receiver's evaluation window is not reported as one number. Each
//! dependency the kernel calls keeps its own cumulative stopwatch: the co-signer
//! separates the QUIC handshake of a co-sign hop from the exchange that follows
//! it, the admission store times every resolution, continuation, lease and trust
//! floor operation, the tool server times its own invocation, and the durable
//! receipt store times every append. A call reads all of them before and after
//! `evaluate_tool_call`, and the differences are that call's parts. The
//! remainder of the window, reported rather than modelled, is the work that has
//! no such dependency: guards, the binding comparisons, the two DSSE signature
//! verifications, canonicalization, the durable pre-dispatch record and receipt
//! signing. The counters are process-wide, so a run that has more than one call
//! in flight does not report a decomposition, and a sequential run that ever
//! attributes more than the window it decomposes stops rather than report it.
//!
//! The tool-call ALPN is EXPERIMENT-ONLY: no shipped Chio lane carries a
//! `ToolCallRequest`, so the request hop is not a claim about the deployed
//! protocol. The unmediated baseline and the clock probe ride the same
//! experiment-only ground and are not Chio interfaces either: the baseline
//! exists to be the denominator of the mediated call, and nothing in the shipped
//! crates reaches it. It is bound the way the shipped lanes are all the same: the
//! authenticated endpoint is re-resolved through the verified directory and must
//! be the treaty role entitled to send that frame, and every peer-dependent await
//! on it is bounded. The co-sign hops and the revocation lane are the shipped
//! lanes, unchanged.
//!
//! Run: see `docs/papers/programmable-sovereignty/bench/run-federated-pair.sh`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::governance::GovernedTransactionIntent;
use chio_core_types::capability::scope::ChioScope;
use chio_core_types::capability::scope::Operation;
use chio_core_types::capability::scope::ToolGrant;
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::capability::token::CapabilityTokenBody;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::body::ChioReceiptBody;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::BoundaryClass;
use chio_core_types::receipt::kinds::ReceiptKind;
use chio_core_types::receipt::kinds::RedactionMode;
use chio_core_types::receipt::kinds::ToolOrigin;
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::metadata::ActorRef;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope_with_cosigner;
use chio_federation::bilateral_dsse::BilateralPredicateExtensions;
use chio_federation::bilateral_dsse::CapabilityLeaseRef;
use chio_federation::bilateral_dsse::DsseEnvelope;
use chio_federation::bilateral_dsse::GovernanceReceiptRef;
use chio_federation::bilateral_dsse::HashRecord;
use chio_federation::bilateral_dsse::PolicyEvaluationSummary;
use chio_federation::bilateral_dsse::PolicyVerdict;
use chio_federation::bilateral_dsse::TreatyBindingRef;
use chio_federation::revocation_gossip::RevocationGossipBatch;
use chio_federation::revocation_gossip::RevocationRootGossip;
use chio_federation::revocation_gossip::REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA;
use chio_federation::trust_establishment::KernelTrustExchange;
use chio_federation::trust_establishment::PeerHandshakeEnvelope;
use chio_federation_transport_iroh::admission::DirectoryGate;
use chio_federation_transport_iroh::identity::revocation_signer_endorsement_preimage;
use chio_federation_transport_iroh::identity::transport_endorsement_preimage;
use chio_federation_transport_iroh::identity::RevocationSignerEntry;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
use chio_federation_transport_iroh::identity::VerifiedDirectory;
use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_federation_transport_iroh::lanes::bilateral::BilateralCoSignHandler;
use chio_federation_transport_iroh::lanes::bilateral::BilateralReceiptCoSignHandler;
use chio_federation_transport_iroh::lanes::bilateral::IrohBilateralCoSigner;
use chio_federation_transport_iroh::lanes::bilateral::PinnedPassportKeys;
use chio_federation_transport_iroh::lanes::bilateral::ALPN_BILATERAL;
use chio_federation_transport_iroh::lanes::bilateral::ALPN_BILATERAL_RECEIPT_COSIGN;
use chio_federation_transport_iroh::lanes::limits::AcceptLimitConfig;
use chio_federation_transport_iroh::lanes::limits::AcceptLimiter;
use chio_federation_transport_iroh::lanes::limits::AcceptPhase;
use chio_federation_transport_iroh::lanes::revocation::push_batch_over_iroh;
use chio_federation_transport_iroh::lanes::revocation::RevocationHandler;
use chio_federation_transport_iroh::lanes::revocation::RevocationViewSink;
use chio_federation_transport_iroh::lanes::revocation::RevokedSubjectSource;
use chio_federation_transport_iroh::lanes::revocation::ALPN_REVOCATION_ROOT;
use chio_kernel::ChioKernel;
use chio_kernel::KernelConfig;
use chio_kernel::KernelError;
use chio_kernel::NestedFlowBridge;
use chio_kernel::ToolCallRequest;
use chio_kernel::ToolServerConnection;
use chio_kernel::Verdict;
use chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE;
use chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS;
use chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES;
use chio_kernel_core::RevocationView;
use chio_kernel_core::RevocationViewSubject;
use chio_revocation_oracle::Ed25519RootSigner;
use chio_revocation_oracle::EpochNonce;
use chio_revocation_oracle::EpochRoot;
use chio_revocation_oracle::InMemoryRevocationOracle;
use chio_revocation_oracle::RevocationKey;
use chio_revocation_oracle::RevocationOracle;
use chio_revocation_oracle::SignedEpochRoot;
use chio_revocation_oracle::DEFAULT_EPOCH_TICK_MS;
use chio_runtime_core::bilateral_dsse_consistency_model;
use chio_runtime_core::bilateral_invocation_binding_sha256;
use chio_runtime_core::compute_ladder_intersection;
use chio_runtime_core::governance_ladder_manifest_sha256;
use chio_runtime_core::ladder_intersection_sha256;
use chio_runtime_core::runtime_admission_bundle_sha256;
use chio_runtime_core::runtime_peer_weights_sha256;
use chio_runtime_core::tool_args_sha256;
use chio_runtime_core::treaty_scope_sha256;
use chio_runtime_core::BilateralInvocation;
use chio_runtime_core::ChioRuntimeAdmissionHook;
use chio_runtime_core::CrossKernelContinuation;
use chio_runtime_core::GovernanceLadderActionClass;
use chio_runtime_core::GovernanceLadderManifest;
use chio_runtime_core::InMemoryRuntimeAdmissionStore;
use chio_runtime_core::LadderIntersection;
use chio_runtime_core::ReceiptLineageBundle;
use chio_runtime_core::ReceiptLineageStatement;
use chio_runtime_core::RuntimeAdmissionBundle;
use chio_runtime_core::RuntimeAdmissionProfile;
use chio_runtime_core::RuntimePeerWeight;
use chio_runtime_core::RuntimePeerWeights;
use chio_runtime_core::RuntimePheromonePolicy;
use chio_runtime_core::RuntimePheromonePolicyRule;
use chio_runtime_core::RuntimeRequestBinding;
use chio_runtime_core::RuntimeTrustedVerifierKey;
use chio_runtime_core::RuntimeVerifierTrustBundleV4;
use chio_runtime_core::SignedRuntimePeerWeights;
use chio_runtime_core::SignedRuntimePheromonePolicy;
use chio_runtime_core::SignedRuntimePheromoneQueryReport;
use chio_runtime_core::SignedRuntimeVerifierTrustBundle;
use chio_runtime_core::TreatyScope;
use chio_runtime_core::CHIO_BILATERAL_INVOCATION_SCHEMA;
use chio_runtime_core::CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA;
use chio_runtime_core::CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA;
use chio_runtime_core::CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA;
use chio_runtime_core::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA;
use chio_runtime_core::CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA;
use chio_runtime_core::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA;
use chio_runtime_core::CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA;
use chio_runtime_core::CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA;
use chio_runtime_core::CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA;
use chio_runtime_core::CHIO_TREATY_SCOPE_SCHEMA;
use chio_runtime_core::{
    ChioRuntimeError, RuntimeAdmissionStore, RuntimeTrustFloorEntry,
    SqliteRuntimeOrchestrationStore, TreatyRuntimeArtifactRecord,
};
use chio_store_sqlite::SqliteAuthorityStore;
use chio_store_sqlite::SqliteReceiptStore;
use chio_store_sqlite::SqliteRevocationStore;
use chio_swarm_authority::SwarmAuthorityBundle;
use iroh::endpoint::presets;
use iroh::endpoint::Connection;
use iroh::endpoint::RecvStream;
use iroh::endpoint::SendStream;
use iroh::endpoint::VarInt;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::RelayMode;
use iroh::SecretKey;
use serde::Deserialize;
use serde::Serialize;

type BoxError = Box<dyn Error + Send + Sync>;

/// Experiment-only ALPN carrying a `ToolCallRequest` and the receiver's verdict.
/// No shipped Chio lane does this; it exists so the request hop can be measured.
const ALPN_EXPERIMENT: &[u8] = b"chio/experiment/federated-tool-call/1";

/// Experiment-only ALPN carrying nothing but a reading of the answering host's
/// clock. Both long-lived roles mount it so a run split across two machines can
/// be refused before it measures anything when the two clocks disagree by more
/// than the run's bound.
const ALPN_CLOCK: &[u8] = b"chio/experiment/federated-pair-clock/1";

const SECRETS_SCHEMA: &str = "chio.experiment.federated-pair-secrets.v1";
const PUBLIC_SCHEMA: &str = "chio.experiment.federated-pair-public.v1";
const TREATY_SCHEMA: &str = "chio.experiment.federated-pair-treaty.v1";
const TRUST_SCHEMA: &str = "chio.experiment.federated-pair-directory-trust.v1";
const CONTROL_SCHEMA: &str = "chio.experiment.federated-pair-control.v1";
const REVOKED_SUBJECTS_SCHEMA: &str = "chio.experiment.federated-pair-revoked-subjects.v1";
const EPOCH_RATE_SCHEMA: &str = "chio.experiment.federated-pair-epoch-rate.v1";
const CLOCK_SCHEMA: &str = "chio.experiment.federated-pair-clock.v1";

/// The most concurrent calls one driver may have in flight against the receiver.
/// It is the experiment lane's per-peer accept cap as well, so a driver that asks
/// for more is refused by the driver rather than shed by the limiter, which would
/// measure the limiter instead of the kernel.
const MAX_CONCURRENT_CALLS: u64 = 64;

/// How far apart two hosts' clocks may be before a split run refuses to measure.
/// The receiving kernel reads its clock in whole seconds and holds its revocation
/// snapshot to a sub-second freshness bound, so an offset of this size already
/// changes which calls are admitted.
const DEFAULT_MAX_CLOCK_OFFSET_MS: u64 = 250;

/// How much of an admitted call's evaluation window may go unaccounted for in
/// the other direction: the attributed parts are measured independently of the
/// whole, so an attributed total that EXCEEDS the whole means the parts are not
/// describing this call and the run must not report the decomposition.
const BUDGET_TOLERANCE_NANOS: u64 = 50_000;

/// Frame cap for the experiment lane. A prepared treaty bundle with an embedded
/// DSSE envelope is tens of kilobytes; the cap is a fail-closed bound.
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const CLOSE_OK: u32 = 0;

/// Validity window the issuer stamps on the treaty and the directory bundle.
const TREATY_BACKDATE_MS: u64 = 3_600_000;
const TREATY_WINDOW_MS: u64 = 86_400_000;

// ---------------------------------------------------------------------------
// Command-line arguments
// ---------------------------------------------------------------------------

/// Repeatable `--key value` flags. Every address in this example comes from
/// here, which is what makes the one-host and two-host runs the same binary.
#[derive(Debug, Default)]
struct Args {
    flags: BTreeMap<String, Vec<String>>,
}

impl Args {
    fn parse(raw: impl Iterator<Item = String>) -> Result<Self, BoxError> {
        let mut flags: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut raw = raw.peekable();
        while let Some(token) = raw.next() {
            let Some(key) = token.strip_prefix("--") else {
                return Err(format!("expected a --flag, got {token}").into());
            };
            let value = raw
                .next()
                .ok_or_else(|| format!("--{key} expects a value"))?;
            flags.entry(key.to_string()).or_default().push(value);
        }
        Ok(Self { flags })
    }

    fn value(&self, key: &str) -> Result<&str, BoxError> {
        self.optional(key)
            .ok_or_else(|| format!("--{key} is required").into())
    }

    fn optional(&self, key: &str) -> Option<&str> {
        self.flags
            .get(key)
            .and_then(|values| values.last())
            .map(String::as_str)
    }

    fn values(&self, key: &str) -> &[String] {
        self.flags.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    fn path(&self, key: &str) -> Result<PathBuf, BoxError> {
        Ok(PathBuf::from(self.value(key)?))
    }

    fn count(&self, key: &str, default: u64) -> Result<u64, BoxError> {
        match self.optional(key) {
            None => Ok(default),
            Some(raw) => raw
                .parse::<u64>()
                .map_err(|error| format!("--{key} must be a whole number: {error}").into()),
        }
    }
}

/// `KERNEL_ID=HOST:PORT`, the same shape the CLI's `--iroh-peer-addr` uses.
fn parse_peer(raw: &str) -> Result<(String, SocketAddr), BoxError> {
    let (kernel_id, socket) = raw
        .split_once('=')
        .ok_or_else(|| format!("--peer expects KERNEL_ID=HOST:PORT, got {raw}"))?;
    if kernel_id.trim().is_empty() {
        return Err(format!("--peer carries an empty kernel id: {raw}").into());
    }
    let socket: SocketAddr = socket
        .parse()
        .map_err(|error| format!("--peer address {socket} is not HOST:PORT: {error}"))?;
    Ok((kernel_id.to_string(), socket))
}

fn peer_map(args: &Args) -> Result<BTreeMap<String, SocketAddr>, BoxError> {
    let mut peers = BTreeMap::new();
    for raw in args.values("peer") {
        let (kernel_id, socket) = parse_peer(raw)?;
        peers.insert(kernel_id, socket);
    }
    Ok(peers)
}

// ---------------------------------------------------------------------------
// On-disk material
// ---------------------------------------------------------------------------

/// One organization's private key material. Written by `keygen` with owner-only
/// permissions and never copied to another organization's directory.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Secrets {
    schema: String,
    kernel_id: String,
    /// ed25519 seed for the rotatable iroh transport identity.
    transport_seed_hex: String,
    /// Long-term operator passport seed; the kernel signs receipts with it.
    passport_seed_hex: String,
    /// Revocation-oracle root signing seed (Org A only in this experiment).
    oracle_seed_hex: String,
    /// Runtime-policy verifier seed (the directory issuer only).
    verifier_seed_hex: String,
    /// Capability-issuing authority seed (the directory issuer only).
    ca_seed_hex: String,
}

/// The half of an identity an organization publishes to the directory issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicIdentity {
    schema: String,
    kernel_id: String,
    transport_endpoint_id: iroh::EndpointId,
    passport_public_key: PublicKey,
    passport_endorsement: Signature,
    oracle_signer_id: String,
    oracle_public_key: PublicKey,
    oracle_endorsement: Signature,
    verifier_public_key: PublicKey,
    ca_public_key: PublicKey,
}

/// Pinned trust for the transport directory bundle, published beside it so both
/// processes verify the same issuer.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DirectoryTrustDocument {
    schema: String,
    issuer: String,
    key_id: String,
    public_key: PublicKey,
    version_floor: u64,
}

/// The treaty both organizations agreed to, issued by the third party. It holds
/// no private material, so the same file ships to both hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TreatyDocument {
    schema: String,
    origin_kernel_id: String,
    receiver_kernel_id: String,
    sender_kernel_id: String,
    capability_id: String,
    action_class_id: String,
    server_id: String,
    tool_name: String,
    governance_receipt_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    arguments: serde_json::Value,
    capability: CapabilityToken,
    treaty_scope: TreatyScope,
    ladder_manifests: Vec<GovernanceLadderManifest>,
    admission_profile: RuntimeAdmissionProfile,
    trust_bundle_sha256: String,
    verification_context_sha256: String,
    signed_trust_bundle: SignedRuntimeVerifierTrustBundle,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    signed_query_report: SignedRuntimePheromoneQueryReport,
    signed_pheromone_policy: SignedRuntimePheromonePolicy,
    signed_peer_weights: SignedRuntimePeerWeights,
    origin_oracle_signer_id: String,
    ca_public_key: PublicKey,
}

/// What `revoke` and `cut` tell the running origin to do. The origin reads it on
/// every tick, so the control surface is one file rather than a signal.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlDocument {
    #[serde(default)]
    schema: String,
    /// Stop publishing epoch roots. The receiver's freshness bound then denies.
    #[serde(default)]
    cut: bool,
    /// Capability ids Org A has revoked.
    #[serde(default)]
    revoked_capability_ids: Vec<String>,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, BoxError> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()).into())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), BoxError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

/// Write a document that must never be readable by anyone but its owner. The
/// temporary carries owner-only permissions from the moment it is created, so a
/// private key is never on disk under the process umask, not even briefly.
fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<(), BoxError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let temporary = path.with_extension("tmp");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", temporary.display()).into()),
    }
    {
        let mut file = create_private(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    restrict_to_owner(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private(path: &Path) -> Result<fs::File, BoxError> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> Result<fs::File, BoxError> {
    Ok(fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?)
}

fn decode_seed(hex: &str) -> Result<[u8; 32], BoxError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(format!("expected a 32-byte hex seed, got {} characters", hex.len()).into());
    }
    let mut seed = [0_u8; 32];
    for (index, slot) in seed.iter_mut().enumerate() {
        let byte = hex
            .get(index * 2..index * 2 + 2)
            .ok_or("seed hex is truncated")?;
        *slot = u8::from_str_radix(byte, 16)
            .map_err(|error| format!("seed hex is not hexadecimal: {error}"))?;
    }
    Ok(seed)
}

fn now_unix_ms() -> Result<u64, BoxError> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

// ---------------------------------------------------------------------------
// Experiment lane wire format
// ---------------------------------------------------------------------------

/// What the sender asks the receiver to do. `Prepare` is untimed setup; `Call`
/// is the measured admission decision.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum ExperimentRequest {
    /// Mint the per-call treaty evidence in the receiver's own store and report
    /// the identifiers and digests the request must cite. `sequence` is `None`
    /// when the sender lets the receiver number the call.
    ///
    /// `continuation_sequence` numbers the single-use continuation separately
    /// from the call. Leaving it `None` gives every call its own continuation,
    /// which is what an ordinary run wants; setting it to a sequence already
    /// prepared mints a second call that names the SAME continuation, which is
    /// what the contention run needs to make several calls race for one.
    Prepare {
        sequence: Option<u64>,
        #[serde(default)]
        continuation_sequence: Option<u64>,
    },
    /// Evaluate one tool call. The sender authored every byte of `request`.
    Call { request: Box<ToolCallRequest> },
    /// Invoke the same tool with the kernel taken out of the path: no capability
    /// check, no admission, no receipt. It is the denominator the admitted call
    /// is measured against and exists for no other purpose; it is reachable only
    /// over this experiment-only ALPN, from the one peer the treaty names as the
    /// driver, and it is not a Chio interface.
    DirectCall { request: Box<ToolCallRequest> },
    /// Report the receiver's dispatch and call counters.
    Stats,
    /// Install Org A's signed revoked-subject set for an epoch.
    RevokedSubjects(SignedRevokedSubjects),
}

/// The receiver's reply.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum ExperimentReply {
    Prepared(Box<PreparedCall>),
    Decision(Box<CallDecision>),
    Stats(ReceiverStats),
    Accepted,
    Refused { detail: String },
}

/// What a clock probe asks for and what it gets back. The reply carries the
/// answering kernel's identity so a probe cannot be satisfied by whichever host
/// happens to answer the address.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClockProbe {
    schema: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClockReply {
    schema: String,
    kernel_id: String,
    unix_ms: u64,
}

/// The evidence the receiver holds for one call, named so the sender can cite it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedCall {
    sequence: u64,
    request_id: String,
    admission_id: String,
    admission_bundle_sha256: String,
    treaty_scope_id: String,
    treaty_scope_sha256: String,
    ladder_intersection_id: String,
    ladder_intersection_sha256: String,
    action_class_id: String,
    /// The sequence the continuation was minted under. Equal to `sequence` for an
    /// ordinary call; shared by every call of one contention round.
    continuation_sequence: u64,
    continuation_id: String,
    continuation_sha256: String,
    lineage_bundle_id: String,
    lineage_bundle_sha256: String,
    bilateral_invocation_id: String,
    bilateral_invocation_sha256: String,
    bilateral_dsse_id: String,
    bilateral_dsse_sha256: String,
    /// Wall-clock the receiver spent minting the evidence, including the DSSE
    /// co-sign hop to Org A. Reported separately so it never enters the
    /// admission latency.
    prepare_micros: u64,
    /// Co-sign connections the receiver had opened to Org A when it began this
    /// preparation. Subtracted from the count the decision reports, it gives the
    /// number of co-sign hops this one call cost as an observation.
    cosign_connections_before: u64,
}

/// One admission decision, as the receiver saw it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallDecision {
    request_id: String,
    /// `allow`, `deny`, or `pending_approval`.
    verdict: String,
    failure_code: String,
    receipt_id: String,
    /// Wall-clock inside `evaluate_tool_call`, including both co-sign hops back
    /// to Org A on the admitted path.
    evaluate_micros: u64,
    /// Tool-server invocations after this call. A denial must not move it.
    dispatches: u64,
    /// Epoch of the revocation snapshot the receiver held when it answered.
    revocation_epoch: u64,
    /// Co-sign connections the receiver had opened to Org A once it had answered.
    cosign_connections: u64,
    /// Where the evaluation window went, measured at the dependencies the kernel
    /// called rather than inferred from the protocol.
    budget: ReceiverBudget,
}

/// One admitted or denied call's evaluation window, decomposed.
///
/// Every field but `evaluate_nanos` is a before/after difference of a counter
/// kept by a real dependency of the kernel: the co-signer's own connect and
/// exchange timers, the admission store's per-method stopwatch, the tool server,
/// and the durable receipt store. Nothing is a model of the protocol, and
/// nothing is sampled.
///
/// `attributed_nanos` is the sum of the measured parts and `unattributed_nanos`
/// the remainder of the window: the guard pipeline, the binding comparisons, the
/// two DSSE signature verifications, canonicalization, and receipt construction
/// and signing. Those run inside the admission hook, where this example has no
/// dependency to put a stopwatch on, so the remainder is reported whole rather
/// than split further.
///
/// The parts and that remainder are the window exactly, by construction, so
/// their sum is not a check. [`ReceiverBudget::check`] is one-sided:
/// `overattributed_nanos` is the reverse remainder and must be zero within
/// [`BUDGET_TOLERANCE_NANOS`], because a positive value means the counters
/// picked up work from another call. Nothing bounds how large
/// `unattributed_nanos` may be.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiverBudget {
    evaluate_nanos: u64,
    cosign_connect_nanos: u64,
    cosign_exchange_nanos: u64,
    cosign_hops: u64,
    store_resolve_nanos: u64,
    store_resolve_ops: u64,
    continuation_nanos: u64,
    continuation_ops: u64,
    lease_nanos: u64,
    lease_ops: u64,
    trust_floor_nanos: u64,
    trust_floor_ops: u64,
    dispatch_nanos: u64,
    dispatch_ops: u64,
    receipt_append_nanos: u64,
    receipt_append_ops: u64,
    receipt_other_nanos: u64,
    receipt_other_ops: u64,
    revocation_nanos: u64,
    revocation_ops: u64,
    admission_durable_nanos: u64,
    admission_durable_ops: u64,
    tool_outcome_durable_nanos: u64,
    tool_outcome_durable_ops: u64,
    attributed_nanos: u64,
    unattributed_nanos: u64,
    overattributed_nanos: u64,
}

/// The co-signer's three counters, read at one instant.
#[derive(Debug, Clone, Copy, Default)]
struct CoSignSnapshot {
    connect_nanos: u64,
    exchange_nanos: u64,
    hops: u64,
}

impl ReceiverBudget {
    /// The window between two readings of every counter.
    fn between(
        evaluate: Duration,
        ledger: (LedgerSnapshot, LedgerSnapshot),
        cosign: (CoSignSnapshot, CoSignSnapshot),
    ) -> Self {
        let (before, after) = ledger;
        let (cosign_before, cosign_after) = cosign;
        let evaluate_nanos = as_nanos(evaluate);
        let mut budget = Self {
            evaluate_nanos,
            cosign_connect_nanos: cosign_after
                .connect_nanos
                .saturating_sub(cosign_before.connect_nanos),
            cosign_exchange_nanos: cosign_after
                .exchange_nanos
                .saturating_sub(cosign_before.exchange_nanos),
            cosign_hops: cosign_after.hops.saturating_sub(cosign_before.hops),
            store_resolve_nanos: after
                .store_resolve_nanos
                .saturating_sub(before.store_resolve_nanos),
            store_resolve_ops: after
                .store_resolve_ops
                .saturating_sub(before.store_resolve_ops),
            continuation_nanos: after
                .continuation_nanos
                .saturating_sub(before.continuation_nanos),
            continuation_ops: after
                .continuation_ops
                .saturating_sub(before.continuation_ops),
            lease_nanos: after.lease_nanos.saturating_sub(before.lease_nanos),
            lease_ops: after.lease_ops.saturating_sub(before.lease_ops),
            trust_floor_nanos: after
                .trust_floor_nanos
                .saturating_sub(before.trust_floor_nanos),
            trust_floor_ops: after.trust_floor_ops.saturating_sub(before.trust_floor_ops),
            dispatch_nanos: after.dispatch_nanos.saturating_sub(before.dispatch_nanos),
            dispatch_ops: after.dispatch_ops.saturating_sub(before.dispatch_ops),
            receipt_append_nanos: after
                .receipt_append_nanos
                .saturating_sub(before.receipt_append_nanos),
            receipt_append_ops: after
                .receipt_append_ops
                .saturating_sub(before.receipt_append_ops),
            receipt_other_nanos: after
                .receipt_other_nanos
                .saturating_sub(before.receipt_other_nanos),
            receipt_other_ops: after
                .receipt_other_ops
                .saturating_sub(before.receipt_other_ops),
            revocation_nanos: after
                .revocation_nanos
                .saturating_sub(before.revocation_nanos),
            revocation_ops: after.revocation_ops.saturating_sub(before.revocation_ops),
            admission_durable_nanos: after
                .admission_durable_nanos
                .saturating_sub(before.admission_durable_nanos),
            admission_durable_ops: after
                .admission_durable_ops
                .saturating_sub(before.admission_durable_ops),
            tool_outcome_durable_nanos: after
                .tool_outcome_durable_nanos
                .saturating_sub(before.tool_outcome_durable_nanos),
            tool_outcome_durable_ops: after
                .tool_outcome_durable_ops
                .saturating_sub(before.tool_outcome_durable_ops),
            ..Self::default()
        };
        budget.attributed_nanos = budget
            .cosign_connect_nanos
            .saturating_add(budget.cosign_exchange_nanos)
            .saturating_add(budget.store_resolve_nanos)
            .saturating_add(budget.continuation_nanos)
            .saturating_add(budget.lease_nanos)
            .saturating_add(budget.trust_floor_nanos)
            .saturating_add(budget.dispatch_nanos)
            .saturating_add(budget.receipt_append_nanos)
            .saturating_add(budget.receipt_other_nanos)
            .saturating_add(budget.revocation_nanos)
            .saturating_add(budget.admission_durable_nanos)
            .saturating_add(budget.tool_outcome_durable_nanos);
        budget.unattributed_nanos = evaluate_nanos.saturating_sub(budget.attributed_nanos);
        budget.overattributed_nanos = budget.attributed_nanos.saturating_sub(evaluate_nanos);
        budget
    }

    /// Refuse a decomposition whose parts cannot have come from this call.
    ///
    /// Only over-attribution is refused. Under-attribution is the ordinary case:
    /// it is the share of the window that has no dependency to attribute it to.
    fn check(&self, request_id: &str) -> Result<(), BoxError> {
        if self.overattributed_nanos > BUDGET_TOLERANCE_NANOS {
            return Err(format!(
                "call {request_id} attributed {} ns of an evaluation window of {} ns, \
                 which exceeds the {BUDGET_TOLERANCE_NANOS} ns tolerance; the receiver's \
                 counters were not describing this call alone",
                self.attributed_nanos, self.evaluate_nanos
            )
            .into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiverStats {
    calls: u64,
    dispatches: u64,
    /// Tool invocations made with the kernel out of the path, counted apart from
    /// `dispatches` so a baseline run never moves the mediated counter.
    baseline_dispatches: u64,
    /// Which store holds the treaty evidence and the consumed continuations.
    admission_store: String,
    revocation_epoch: u64,
    /// QUIC connections the receiver's kernel has opened to Org A to co-sign,
    /// read from the co-signer itself rather than assumed from the protocol.
    cosign_connections: u64,
}

/// Org A's revoked-subject set for one epoch, signed with Org A's passport key.
///
/// `SignedEpochRoot` carries a root hash and a leaf count, never the leaves, so
/// the revocation lane alone cannot tell the receiver WHICH capability an epoch
/// revoked. This frame is the experiment's stand-in for the inclusion proofs a
/// deployment would pull: it is origin-signed and epoch-bound, but it rides the
/// experiment lane, not a shipped one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedRevokedSubjects {
    body: RevokedSubjectsBody,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokedSubjectsBody {
    schema: String,
    origin_kernel_id: String,
    /// The first epoch at which `subjects` is the revoked set.
    epoch: u64,
    subjects: Vec<String>,
}

// ---------------------------------------------------------------------------
// Length-delimited framing (the same 4-byte prefix the shipped lanes use)
// ---------------------------------------------------------------------------

async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> Result<(), BoxError> {
    let length = u32::try_from(bytes.len()).map_err(|_| "frame exceeds the 4 GiB length prefix")?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(format!("frame of {} bytes exceeds the cap", bytes.len()).into());
    }
    send.write_all(&length.to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, BoxError> {
    let mut length_bytes = [0_u8; 4];
    recv.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(format!("declared frame of {length} bytes exceeds the cap").into());
    }
    const CHUNK: usize = 64 * 1024;
    let mut buffer = Vec::with_capacity(length.min(CHUNK));
    let mut remaining = length;
    let mut chunk = [0_u8; CHUNK];
    while remaining > 0 {
        let want = remaining.min(CHUNK);
        match recv.read(&mut chunk[..want]).await? {
            Some(0) | None => return Err("unexpected end of stream reading a frame".into()),
            Some(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                remaining -= read;
            }
        }
    }
    Ok(buffer)
}

/// The bounds the experiment lane applies to both halves of every exchange, the
/// same discipline the shipped lanes use: no peer-dependent await is unbounded,
/// so a stalled peer fails the call closed instead of hanging the run.
fn experiment_limits() -> AcceptLimitConfig {
    AcceptLimitConfig {
        // The driver dials this lane once per call in a tight sequence and closes
        // as soon as it has the reply, so the teardown grace window is short: a
        // lingering handler holds one of the lane's per-peer permits.
        linger_timeout: Duration::from_secs(5),
        // The concurrency stages present many calls at once from the one driver
        // peer. The shipped default admits 16 per peer, which would shed the rest
        // and measure the limiter instead of the kernel.
        max_in_flight_per_peer: usize::try_from(MAX_CONCURRENT_CALLS).unwrap_or(usize::MAX),
        // A call waiting behind others for a permit must wait, not be shed: the
        // run counts every call it sent.
        shed_wait: Duration::from_secs(30),
        ..AcceptLimitConfig::default()
    }
}

/// Bound one peer-dependent client await by its phase's timeout.
async fn client_bounded<F>(phase: AcceptPhase, future: F) -> Result<F::Output, BoxError>
where
    F: std::future::Future,
{
    let bound = experiment_limits().phase_timeout(phase);
    tokio::time::timeout(bound, future).await.map_err(|_| {
        format!(
            "the experiment lane's {phase} exceeded its {}ms bound",
            bound.as_millis()
        )
        .into()
    })
}

/// One request/reply exchange on the experiment lane.
async fn experiment_exchange(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    request: &ExperimentRequest,
) -> Result<ExperimentReply, BoxError> {
    let connection = client_bounded(
        AcceptPhase::AcceptStream,
        endpoint.connect(peer, ALPN_EXPERIMENT),
    )
    .await?
    .map_err(|error| format!("the experiment lane did not connect: {error}"))?;
    let result = experiment_exchange_inner(&connection, request).await;
    connection.close(VarInt::from_u32(CLOSE_OK), b"done");
    result
}

async fn experiment_exchange_inner(
    connection: &Connection,
    request: &ExperimentRequest,
) -> Result<ExperimentReply, BoxError> {
    let (mut send, mut recv) = client_bounded(AcceptPhase::AcceptStream, connection.open_bi())
        .await?
        .map_err(|error| format!("the experiment lane did not open a stream: {error}"))?;
    client_bounded(
        AcceptPhase::WriteResponse,
        write_frame(&mut send, &serde_json::to_vec(request)?),
    )
    .await??;
    send.finish()?;
    let reply = client_bounded(AcceptPhase::ReadFrame, read_frame(&mut recv)).await??;
    Ok(serde_json::from_slice(&reply)?)
}

// ---------------------------------------------------------------------------
// Shared wiring
// ---------------------------------------------------------------------------

/// The pieces every long-lived role loads from disk before it binds a socket.
struct Loaded {
    secrets: Secrets,
    treaty: TreatyDocument,
    directory: Arc<VerifiedDirectory>,
}

fn load_role(args: &Args) -> Result<Loaded, BoxError> {
    let secrets: Secrets = read_json(&args.path("dir")?.join("secrets.json"))?;
    if secrets.schema != SECRETS_SCHEMA {
        return Err(format!("unexpected secrets schema {}", secrets.schema).into());
    }
    let treaty: TreatyDocument = read_json(&args.path("treaty")?)?;
    if treaty.schema != TREATY_SCHEMA {
        return Err(format!("unexpected treaty schema {}", treaty.schema).into());
    }
    let bundle: TransportDirectoryBundleDocument = read_json(&args.path("directory")?)?;
    let trust_document: DirectoryTrustDocument = read_json(&args.path("trust")?)?;
    if trust_document.schema != TRUST_SCHEMA {
        return Err(format!("unexpected trust schema {}", trust_document.schema).into());
    }
    let trust = TransportDirectoryBundleTrust {
        issuers: vec![TrustedTransportDirectoryIssuer {
            issuer: trust_document.issuer,
            key_id: trust_document.key_id,
            public_key: trust_document.public_key,
        }],
        version_floor: trust_document.version_floor,
        expected_previous_version_sha256: None,
        now_unix_ms: now_unix_ms()?,
    };
    let directory = Arc::new(bundle.verify_bundle(&trust)?);
    Ok(Loaded {
        secrets,
        treaty,
        directory,
    })
}

/// Bind a gated iroh endpoint on the address `--bind` names. A stable address is
/// mandatory: with relays disabled a peer can only be reached at the socket the
/// other side was told about.
async fn bind_endpoint(
    args: &Args,
    transport_seed_hex: &str,
    gate: Option<DirectoryGate>,
) -> Result<Endpoint, BoxError> {
    let bind: SocketAddr = args
        .value("bind")?
        .parse()
        .map_err(|error| format!("--bind must be HOST:PORT: {error}"))?;
    let secret = SecretKey::from_bytes(&decode_seed(transport_seed_hex)?);
    let builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::Disabled)
        .bind_addr(bind)?;
    let endpoint = match gate {
        Some(gate) => builder.hooks(gate).bind().await?,
        None => builder.bind().await?,
    };
    Ok(endpoint)
}

/// Resolve a `--peer` entry into a dialable address: the directory binds the
/// kernel id to its transport identity, the flag supplies the socket.
fn peer_address(
    directory: &VerifiedDirectory,
    peers: &BTreeMap<String, SocketAddr>,
    kernel_id: &str,
) -> Result<EndpointAddr, BoxError> {
    let endpoint_id = directory
        .resolve_transport_endpoint(kernel_id)
        .ok_or_else(|| format!("the transport directory does not bind {kernel_id}"))?;
    let socket = peers
        .get(kernel_id)
        .ok_or_else(|| format!("--peer {kernel_id}=HOST:PORT is required"))?;
    Ok(EndpointAddr::new(endpoint_id).with_ip_addr(*socket))
}

fn pinned_passport(kernel_id: &str, key: PublicKey) -> Arc<dyn PinnedPassportKeys> {
    let mut keys: HashMap<String, PublicKey> = HashMap::new();
    keys.insert(kernel_id.to_string(), key);
    Arc::new(keys)
}

fn address_book(kernel_id: &str, address: EndpointAddr) -> Arc<HashMap<String, EndpointAddr>> {
    let mut book = HashMap::new();
    book.insert(kernel_id.to_string(), address);
    Arc::new(book)
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

/// Generate one organization's keys. Every seed is fresh, so no two runs and no
/// two organizations share key material; nothing here is derived from a fixture
/// constant.
fn run_keygen(args: &Args) -> Result<(), BoxError> {
    let kernel_id = args.value("kernel-id")?.to_string();
    let dir = args.path("dir")?;
    fs::create_dir_all(&dir)?;

    let transport = Keypair::generate();
    let passport = Keypair::generate();
    let oracle = Keypair::generate();
    let verifier = Keypair::generate();
    let ca = Keypair::generate();

    let secrets = Secrets {
        schema: SECRETS_SCHEMA.to_string(),
        kernel_id: kernel_id.clone(),
        transport_seed_hex: transport.seed_hex(),
        passport_seed_hex: passport.seed_hex(),
        oracle_seed_hex: oracle.seed_hex(),
        verifier_seed_hex: verifier.seed_hex(),
        ca_seed_hex: ca.seed_hex(),
    };
    write_json_private(&dir.join("secrets.json"), &secrets)?;

    let transport_id = SecretKey::from_bytes(&decode_seed(&secrets.transport_seed_hex)?).public();
    let oracle_signer_id = format!("{kernel_id}/revocation-signer-1");
    let public = PublicIdentity {
        schema: PUBLIC_SCHEMA.to_string(),
        kernel_id: kernel_id.clone(),
        transport_endpoint_id: transport_id,
        passport_public_key: passport.public_key(),
        passport_endorsement: passport
            .sign(&transport_endorsement_preimage(&kernel_id, &transport_id)),
        oracle_signer_id: oracle_signer_id.clone(),
        oracle_public_key: oracle.public_key(),
        oracle_endorsement: passport.sign(&revocation_signer_endorsement_preimage(
            &kernel_id,
            &oracle_signer_id,
            &oracle.public_key(),
        )),
        verifier_public_key: verifier.public_key(),
        ca_public_key: ca.public_key(),
    };
    write_json(&dir.join("public.json"), &public)?;
    println!("{kernel_id} keys written to {}", dir.display());
    Ok(())
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<(), BoxError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_directory_to_owner(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory_to_owner(_path: &Path) -> Result<(), BoxError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// directory (the third-party issuer)
// ---------------------------------------------------------------------------

/// Sign the transport directory that binds both kernels, and issue the treaty
/// they operate under. The issuer holds neither organization's passport key: it
/// only signs over the public halves they published.
fn run_directory(args: &Args) -> Result<(), BoxError> {
    let issuer_secrets: Secrets = read_json(&args.path("issuer-dir")?.join("secrets.json"))?;
    let issuer_id = issuer_secrets.kernel_id.clone();
    let issuer_key = Keypair::from_seed(&decode_seed(&issuer_secrets.passport_seed_hex)?);
    let verifier_key = Keypair::from_seed(&decode_seed(&issuer_secrets.verifier_seed_hex)?);
    let ca_key = Keypair::from_seed(&decode_seed(&issuer_secrets.ca_seed_hex)?);
    let issuer_key_id = args.optional("issuer-key-id").unwrap_or("issuer-key-1");

    let mut identities: BTreeMap<String, PublicIdentity> = BTreeMap::new();
    for path in args.values("public") {
        let identity: PublicIdentity = read_json(Path::new(path))?;
        if identity.schema != PUBLIC_SCHEMA {
            return Err(format!("unexpected public identity schema {}", identity.schema).into());
        }
        identities.insert(identity.kernel_id.clone(), identity);
    }
    let origin_id = args.value("origin-kernel-id")?.to_string();
    let receiver_id = args.value("receiver-kernel-id")?.to_string();
    let sender_id = args.value("sender-kernel-id")?.to_string();
    for required in [&origin_id, &receiver_id, &sender_id] {
        if !identities.contains_key(required) {
            return Err(format!("no --public identity was supplied for {required}").into());
        }
    }
    let origin = &identities[&origin_id];
    let receiver = &identities[&receiver_id];

    let now = now_unix_ms()?;
    let issued_at = now.saturating_sub(TREATY_BACKDATE_MS);
    let expires_at = now.saturating_add(TREATY_WINDOW_MS);

    // Only Org A runs a revocation oracle in this experiment, so only its entry
    // carries a signer binding; the receiver pins that binding through the same
    // issuer-signed directory it authorizes endpoints with.
    let peers: Vec<TransportDirectoryEntry> = identities
        .values()
        .map(|identity| TransportDirectoryEntry {
            kernel_id: identity.kernel_id.clone(),
            passport_public_key: identity.passport_public_key.clone(),
            transport_endpoint_id: identity.transport_endpoint_id,
            passport_endorsement: identity.passport_endorsement.clone(),
            revocation_signers: if identity.kernel_id == origin_id {
                vec![RevocationSignerEntry {
                    signer_id: identity.oracle_signer_id.clone(),
                    oracle_public_key: identity.oracle_public_key.clone(),
                    oracle_endorsement: identity.oracle_endorsement.clone(),
                }]
            } else {
                Vec::new()
            },
            removed: false,
        })
        .collect();
    let document = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: issuer_id.clone(),
        peers,
        treaties: Vec::new(),
    };
    let body = TransportDirectoryBundleBody {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        issuer: issuer_id.clone(),
        key_id: issuer_key_id.to_string(),
        directory_sha256: sha256_hex(&canonical_json_bytes(&document)?),
        version: 1,
        previous_version_sha256: None,
        issued_at_unix_ms: issued_at,
        expires_at_unix_ms: expires_at,
    };
    let (signature, _) = issuer_key.sign_canonical(&body)?;
    let bundle = TransportDirectoryBundleDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        body,
        directory: document,
        signature,
    };
    let out_dir = args.path("out-dir")?;
    fs::create_dir_all(&out_dir)?;
    write_json(&out_dir.join("transport-directory.json"), &bundle)?;
    write_json(
        &out_dir.join("transport-directory-trust.json"),
        &DirectoryTrustDocument {
            schema: TRUST_SCHEMA.to_string(),
            issuer: issuer_id.clone(),
            key_id: issuer_key_id.to_string(),
            public_key: issuer_key.public_key(),
            version_floor: 0,
        },
    )?;

    let treaty = build_treaty(
        TreatyInputs {
            origin,
            receiver,
            sender_kernel_id: &sender_id,
            issuer_kernel_id: &issuer_id,
            verifier_key: &verifier_key,
            ca_key: &ca_key,
            issued_at,
            expires_at,
        },
        args,
    )?;
    write_json(&out_dir.join("treaty.json"), &treaty)?;
    println!(
        "transport directory and treaty written to {}",
        out_dir.display()
    );
    Ok(())
}

struct TreatyInputs<'a> {
    origin: &'a PublicIdentity,
    receiver: &'a PublicIdentity,
    sender_kernel_id: &'a str,
    /// The third party that signs the directory. It also holds the runtime-policy
    /// verifier key and the capability-issuing key in this experiment, so the
    /// verifier is named after it rather than after either organization.
    issuer_kernel_id: &'a str,
    verifier_key: &'a Keypair,
    ca_key: &'a Keypair,
    issued_at: u64,
    expires_at: u64,
}

/// Assemble the static half of the admission material: the treaty scope, both
/// governance ladder manifests, the runtime admission profile, and the verifier-
/// signed policy inputs a destructive action class requires. None of it is
/// per-call, so both organizations hold the identical file.
fn build_treaty(inputs: TreatyInputs<'_>, args: &Args) -> Result<TreatyDocument, BoxError> {
    let origin_id = inputs.origin.kernel_id.clone();
    let receiver_id = inputs.receiver.kernel_id.clone();
    let capability_id = args
        .optional("capability-id")
        .unwrap_or("cap-federated-pair")
        .to_string();
    let action_class_id = args
        .optional("action-class-id")
        .unwrap_or("workflow.destructive.vendor_call")
        .to_string();
    let server_id = args
        .optional("server-id")
        .unwrap_or("vendor-ledger")
        .to_string();
    let tool_name = args
        .optional("tool-name")
        .unwrap_or("close_account")
        .to_string();
    let governance_receipt_id = format!("gov-{capability_id}");
    let verifier_id = format!("{}/runtime-verifier", inputs.issuer_kernel_id);
    let verifier_key_id = "runtime-verifier-key-1".to_string();

    let arguments = serde_json::json!({
        "record": "vendor-ledger-7",
        "value": "closed"
    });
    let trust_bundle_sha256 = sha256_hex(
        format!("chio.federated-pair.trust-bundle:{origin_id}:{receiver_id}").as_bytes(),
    );
    let verification_context_sha256 = sha256_hex(
        format!("chio.federated-pair.verification-context:{origin_id}:{receiver_id}").as_bytes(),
    );
    let revocation_checkpoint_sha256 =
        sha256_hex(format!("chio.federated-pair.revocation-checkpoint:{origin_id}").as_bytes());

    let origin_manifest = ladder_manifest(
        &origin_id,
        &action_class_id,
        inputs.issued_at,
        inputs.expires_at,
    );
    let receiver_manifest = ladder_manifest(
        &receiver_id,
        &action_class_id,
        inputs.issued_at,
        inputs.expires_at,
    );
    let treaty_scope = TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: format!("treaty:{origin_id}:{receiver_id}"),
        participant_kernel_ids: vec![origin_id.clone(), receiver_id.clone()],
        participant_public_keys: vec![
            inputs.origin.passport_public_key.clone(),
            inputs.receiver.passport_public_key.clone(),
        ],
        ladder_manifest_sha256s: vec![
            governance_ladder_manifest_sha256(&origin_manifest)?,
            governance_ladder_manifest_sha256(&receiver_manifest)?,
        ],
        allowed_action_classes: vec![action_class_id.clone()],
        issued_at_unix_ms: inputs.issued_at,
        expires_at_unix_ms: inputs.expires_at,
        revocation_epoch_sha256: revocation_checkpoint_sha256.clone(),
        trust_bundle_sha256: trust_bundle_sha256.clone(),
    };

    let admission_profile = RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: format!("profile:{receiver_id}"),
        local_kernel_id: receiver_id.clone(),
        verifier_id: verifier_id.clone(),
        issued_at_unix_ms: inputs.issued_at,
        expires_at_unix_ms: inputs.expires_at,
    };

    let trusted_verifier_keys = vec![RuntimeTrustedVerifierKey {
        verifier_id: verifier_id.clone(),
        key_id: verifier_key_id.clone(),
        public_key: inputs.verifier_key.public_key(),
        valid_from_unix_ms: inputs.issued_at,
        valid_until_unix_ms: inputs.expires_at,
        status: "active".to_string(),
    }];
    let signed_trust_bundle = SignedExportEnvelope::sign(
        RuntimeVerifierTrustBundleV4 {
            schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
            verifier_id: verifier_id.clone(),
            key_id: verifier_key_id.clone(),
            version: 1,
            previous_hash_sha256: None,
            trust_bundle_sha256: trust_bundle_sha256.clone(),
            verification_context_sha256: verification_context_sha256.clone(),
            revocation_checkpoint_sha256,
            revocation_authority_roots: vec![inputs.origin.oracle_signer_id.clone()],
            issued_at_unix_ms: inputs.issued_at,
            expires_at_unix_ms: inputs.expires_at,
        },
        inputs.verifier_key,
    )?;

    let peer_weights = RuntimePeerWeights {
        schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
        verifier_id: verifier_id.clone(),
        key_id: verifier_key_id.clone(),
        reputation_epoch: 1,
        issued_at_unix_ms: inputs.issued_at,
        expires_at_unix_ms: inputs.expires_at,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: receiver_id.clone(),
            weight: 1.0,
        }],
    };
    // The query-report age bound spans the treaty window rather than the
    // fixture's sixty seconds: a process that stays up for a whole measurement
    // run must not start denying because a static policy input aged out.
    let pheromone_policy = RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
        policy_id: format!("policy:{receiver_id}"),
        verifier_id: verifier_id.clone(),
        key_id: verifier_key_id.clone(),
        policy_version: 1,
        mode: "enforce".to_string(),
        issued_at_unix_ms: inputs.issued_at,
        expires_at_unix_ms: inputs.expires_at,
        allowed_reputation_epochs: vec![1],
        max_query_report_age_ms: TREATY_WINDOW_MS,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: trust_bundle_sha256.clone(),
        peer_weights_sha256: runtime_peer_weights_sha256(&peer_weights)?,
        rules: vec![RuntimePheromonePolicyRule {
            rule_id: "deny-high-runtime-risk".to_string(),
            subject_class: "workflow.destructive_step".to_string(),
            subject_class_namespace: "chio.runtime".to_string(),
            action_class_id: "*".to_string(),
            direction: "deny_if_at_or_above".to_string(),
            threshold_total_strength: 0.75,
            effect: "deny".to_string(),
        }],
    };
    let signed_query_report = SignedExportEnvelope::sign(
        serde_json::json!({
            "schema": "chio.pheromone.query-report.v1",
            "accepted": true,
            "concentration": {
                "subjectClass": "workflow.destructive_step",
                "subjectClassNamespace": "chio.runtime",
                "totalStrength": 0.10,
                "distinctOriginPairs": 1,
                "reputationEpoch": 1,
                "evaluatedAtUnixMs": inputs.issued_at
            }
        }),
        inputs.verifier_key,
    )?;

    let subject = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.clone(),
            issuer: inputs.ca_key.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.clone(),
                    tool_name: tool_name.clone(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: inputs.issued_at / 1_000,
            expires_at: inputs.expires_at / 1_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        inputs.ca_key,
    )?;

    Ok(TreatyDocument {
        schema: TREATY_SCHEMA.to_string(),
        origin_kernel_id: origin_id,
        receiver_kernel_id: receiver_id,
        sender_kernel_id: inputs.sender_kernel_id.to_string(),
        capability_id,
        action_class_id,
        server_id,
        tool_name,
        governance_receipt_id,
        issued_at_unix_ms: inputs.issued_at,
        expires_at_unix_ms: inputs.expires_at,
        arguments,
        capability,
        treaty_scope,
        ladder_manifests: vec![origin_manifest, receiver_manifest],
        admission_profile,
        trust_bundle_sha256,
        verification_context_sha256,
        signed_trust_bundle,
        trusted_verifier_keys,
        signed_query_report,
        signed_pheromone_policy: SignedExportEnvelope::sign(pheromone_policy, inputs.verifier_key)?,
        signed_peer_weights: SignedExportEnvelope::sign(peer_weights, inputs.verifier_key)?,
        origin_oracle_signer_id: inputs.origin.oracle_signer_id.clone(),
        ca_public_key: inputs.ca_key.public_key(),
    })
}

fn ladder_manifest(
    kernel_id: &str,
    action_class_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder:{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: kernel_id.to_string(),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: issued_at,
        expires_at_unix_ms: expires_at,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![GovernanceLadderActionClass {
            action_class_id: action_class_id.to_string(),
            mode: "receipt_backed".to_string(),
            destructive: true,
            consistency_model: "totally_ordered".to_string(),
            co_sign: "bilateral_required".to_string(),
            co_sign_quorum: None,
            evidence_required: vec![
                "bilateral_dsse".to_string(),
                "bilateral_invocation".to_string(),
                "receipt_lineage".to_string(),
            ],
            aliases: Vec::new(),
        }],
    }
}

// ---------------------------------------------------------------------------
// origin (Org A)
// ---------------------------------------------------------------------------

/// Sleep to the next wall-clock multiple of `tick`, and return the arrival time.
///
/// Alignment matters: a root is only fresh to the consuming kernel for the whole
/// second it is stamped with, so one tick has to land immediately after each
/// second boundary rather than at an arbitrary offset. A wake that lands just
/// short of a boundary waits out the remainder instead of stamping the second
/// that is about to end.
async fn sleep_to_next_tick(tick: Duration) -> Result<u64, BoxError> {
    let tick_ms = u64::try_from(tick.as_millis())?.max(1);
    let now = now_unix_ms()?;
    tokio::time::sleep(Duration::from_millis(tick_ms - (now % tick_ms))).await;
    let now = now_unix_ms()?;
    let into_second = now % 1_000;
    if into_second >= 990 {
        tokio::time::sleep(Duration::from_millis(1_000 - into_second)).await;
        return now_unix_ms();
    }
    Ok(now)
}

/// Run Org A: the two co-sign handlers the receiver's kernel calls back into,
/// and the revocation clock the receiver's freshness bound depends on.
///
/// Org A holds only Org A's keys. It never sees the receiver's passport key, the
/// receiver's stores, or the bytes behind the digests it co-signs.
async fn run_origin(args: &Args) -> Result<(), BoxError> {
    let loaded = load_role(args)?;
    let treaty = &loaded.treaty;
    let origin_id = treaty.origin_kernel_id.clone();
    let receiver_id = treaty.receiver_kernel_id.clone();
    if loaded.secrets.kernel_id != origin_id {
        return Err(format!(
            "--dir holds keys for {} but the treaty names {origin_id} as the origin",
            loaded.secrets.kernel_id
        )
        .into());
    }
    let passport = Keypair::from_seed(&decode_seed(&loaded.secrets.passport_seed_hex)?);
    let receiver_passport = loaded
        .directory
        .resolve_passport_key(&receiver_id)
        .ok_or_else(|| format!("the directory does not bind a passport key for {receiver_id}"))?
        .clone();

    let gate = DirectoryGate::new(Arc::clone(&loaded.directory));
    let endpoint =
        bind_endpoint(args, &loaded.secrets.transport_seed_hex, Some(gate.clone())).await?;
    let pinned = pinned_passport(&receiver_id, receiver_passport);
    // Held for the life of the process: dropping the router unmounts both lanes.
    let _router = Router::builder(endpoint.clone())
        .accept(
            ALPN_BILATERAL,
            BilateralCoSignHandler::new(
                gate.clone(),
                origin_id.clone(),
                passport.clone(),
                Arc::clone(&pinned),
            ),
        )
        .accept(
            ALPN_BILATERAL_RECEIPT_COSIGN,
            BilateralReceiptCoSignHandler::new(
                gate.clone(),
                origin_id.clone(),
                passport.clone(),
                pinned,
            ),
        )
        .accept(
            ALPN_CLOCK,
            ClockHandler {
                gate,
                kernel_id: origin_id.clone(),
                peers: BTreeSet::from([receiver_id.clone(), treaty.sender_kernel_id.clone()]),
                limiter: AcceptLimiter::new(experiment_limits()),
            },
        )
        .spawn();

    // The handshake envelope Org B pins Org A with. Org B verifies the signature
    // against the passport key the issuer-signed directory already binds, so the
    // envelope carries no trust of its own.
    let handshake = PeerHandshakeEnvelope::sign(
        &origin_id,
        &receiver_id,
        &format!("federated-pair-{}", now_unix_ms()?),
        now_unix_ms()? / 1_000,
        &passport,
    )?;
    write_json(&args.path("handshake-out")?, &handshake)?;

    let peers = peer_map(args)?;
    let receiver_addr = peer_address(&loaded.directory, &peers, &receiver_id)?;
    let receiver_experiment = receiver_addr.clone();
    let control_path = args.path("control")?;
    let tick = Duration::from_millis(args.count("tick-ms", DEFAULT_EPOCH_TICK_MS)?);
    let signer = Ed25519RootSigner::new(
        treaty.origin_oracle_signer_id.clone(),
        Keypair::from_seed(&decode_seed(&loaded.secrets.oracle_seed_hex)?),
    );

    println!(
        "origin {origin_id} listening on {}; co-signing for {receiver_id}",
        args.value("bind")?
    );

    let epoch_rate_path = args.optional("epoch-rate-out").map(PathBuf::from);
    let mut oracle = InMemoryRevocationOracle::new();
    let mut epoch: u64 = 0;
    let mut published: BTreeSet<String> = BTreeSet::new();
    let mut cut_logged = false;
    // The control document the origin is currently acting on. A control file that
    // cannot be read, or that carries a schema this binary does not know, leaves it
    // untouched: a malformed file must not silently unrevoke a capability or
    // restart a cut clock.
    let mut control = ControlDocument::default();
    let mut clock = EpochClock::default();
    loop {
        let published_at = sleep_to_next_tick(tick).await?;
        if control_path.exists() {
            match read_json::<ControlDocument>(&control_path) {
                Ok(next) if next.schema == CONTROL_SCHEMA => control = next,
                Ok(next) => println!(
                    "control document carries schema {}, not {CONTROL_SCHEMA}; keeping the previous control state",
                    next.schema
                ),
                Err(error) => {
                    println!("control document unreadable ({error}); keeping the previous control state")
                }
            }
        }

        // A newly revoked capability enters the oracle (changing the root it
        // publishes) and is announced to the receiver before the epoch that
        // carries it, so the receiver never holds a root it cannot interpret.
        let revoked: BTreeSet<String> = control.revoked_capability_ids.iter().cloned().collect();
        if revoked != published {
            for capability_id in revoked.difference(&published) {
                // A capability revoked in an earlier cycle is already a leaf; the
                // oracle keeps it forever, so re-revoking it is a no-op rather than
                // an error.
                let key = RevocationKey::new(capability_id.clone(), EpochNonce::new(0));
                if !oracle.contains(&key) {
                    oracle.insert(key, now_unix_ms()?)?;
                }
            }
            let body = RevokedSubjectsBody {
                schema: REVOKED_SUBJECTS_SCHEMA.to_string(),
                origin_kernel_id: origin_id.clone(),
                epoch: epoch.saturating_add(1),
                subjects: revoked.iter().cloned().collect(),
            };
            let (signature, _) = passport.sign_canonical(&body)?;
            let announcement =
                ExperimentRequest::RevokedSubjects(SignedRevokedSubjects { body, signature });
            // Bounded by the tick: the epoch clock is Org A's own and must not be
            // serialized behind a slow or absent receiver. An announcement that does
            // not land inside one tick is retried on the next one.
            match tokio::time::timeout(
                tick,
                experiment_exchange(&endpoint, receiver_experiment.clone(), &announcement),
            )
            .await
            {
                Ok(Ok(ExperimentReply::Accepted)) => published = revoked,
                Ok(Ok(other)) => println!("receiver refused the revoked-subject frame: {other:?}"),
                Ok(Err(error)) => {
                    println!("revoked-subject frame did not reach the receiver: {error}")
                }
                Err(_elapsed) => println!(
                    "revoked-subject frame did not reach the receiver within one {}ms tick",
                    tick.as_millis()
                ),
            }
        }

        if control.cut {
            if !cut_logged {
                println!("origin stopped publishing epoch roots at epoch {epoch}");
                cut_logged = true;
            }
            clock.interrupt();
            continue;
        }
        cut_logged = false;

        // A heartbeat root: the epoch advances on every tick so the receiver's
        // snapshot stays inside its freshness window, and the root hash is
        // whatever the oracle currently commits to.
        epoch = epoch.saturating_add(1);
        let current = oracle.epoch_root();
        // The consuming kernel reads its clock in whole seconds and rejects a
        // snapshot issued in its future, so a root is stamped at the second it is
        // published in rather than at the millisecond. See the example README.
        let issued_at_unix_ms = published_at - (published_at % 1_000);
        let root = EpochRoot {
            epoch,
            root_hash: current.root_hash,
            leaf_count: current.leaf_count,
            issued_at_unix_ms,
        };
        let signed = SignedEpochRoot::sign(root, &signer)?;
        let batch = RevocationGossipBatch {
            schema: REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA.to_string(),
            recipient_kernel_id: receiver_id.clone(),
            frames: vec![RevocationRootGossip::from_signed(signed, published_at)],
            flushed_at_unix_ms: published_at,
        };
        // A receiver that is not up yet, or a cut link, is the normal case here:
        // the point of the lane is that its silence denies. The delivery is bounded
        // by the tick for the same reason the announcement is: a peer that stops
        // reading must cost one tick of delivery, never the clock itself. A path
        // whose round trip does not fit inside a tick shows up as a gap in the
        // achieved-interval report rather than as a stalled clock.
        let delivered = match tokio::time::timeout(
            tick,
            push_batch_over_iroh(&endpoint, receiver_addr.clone(), &batch),
        )
        .await
        {
            Ok(Ok(_response)) => true,
            Ok(Err(error)) => {
                if epoch.is_multiple_of(40) {
                    println!("epoch {epoch} did not reach {receiver_id}: {error}");
                }
                false
            }
            Err(_elapsed) => {
                if epoch.is_multiple_of(40) {
                    println!(
                        "epoch {epoch} did not reach {receiver_id} within one {}ms tick",
                        tick.as_millis()
                    );
                }
                false
            }
        };
        if delivered {
            clock.delivered(published_at);
        } else {
            clock.interrupt();
        }
        if let Some(path) = epoch_rate_path.as_deref() {
            clock.publish_report(path, epoch, tick)?;
        }
    }
}

/// The rate Org A's revocation clock actually achieved, as opposed to the rate it
/// was asked for.
///
/// The nominal tick is a configuration value; what the receiver's freshness bound
/// sees is the interval between the roots that reached it. This records those
/// intervals so the artifact can report the achieved rate beside the nominal one.
/// A tick that did not deliver (an absent receiver, a cut) breaks the chain rather
/// than folding the gap into the distribution.
#[derive(Debug, Default)]
struct EpochClock {
    last_delivered_at: Option<u64>,
    intervals: Vec<u64>,
    delivered: u64,
    interrupted: u64,
    written_at: u64,
}

impl EpochClock {
    /// Cap on the retained interval history: a long run reports its most recent
    /// window rather than growing without bound.
    const HISTORY: usize = 4096;
    /// Roots between rewrites of the report file.
    const REPORT_EVERY: u64 = 4;

    fn delivered(&mut self, published_at: u64) {
        if let Some(previous) = self.last_delivered_at {
            if self.intervals.len() == Self::HISTORY {
                self.intervals.remove(0);
            }
            self.intervals.push(published_at.saturating_sub(previous));
        }
        self.last_delivered_at = Some(published_at);
        self.delivered = self.delivered.saturating_add(1);
    }

    fn interrupt(&mut self) {
        if self.last_delivered_at.take().is_some() {
            self.interrupted = self.interrupted.saturating_add(1);
        }
    }

    fn publish_report(&mut self, path: &Path, epoch: u64, tick: Duration) -> Result<(), BoxError> {
        if self.delivered < self.written_at.saturating_add(Self::REPORT_EVERY) {
            return Ok(());
        }
        self.written_at = self.delivered;
        let mut ordered = self.intervals.clone();
        ordered.sort_unstable();
        let median = ordered.get(ordered.len() / 2).copied();
        write_json(
            path,
            &serde_json::json!({
                "schema": EPOCH_RATE_SCHEMA,
                "nominalTickMs": u64::try_from(tick.as_millis())?,
                "epoch": epoch,
                "deliveredRoots": self.delivered,
                "deliveryInterruptions": self.interrupted,
                "intervalSamples": ordered.len(),
                "intervalMinMs": ordered.first().copied(),
                "intervalP50Ms": median,
                "intervalMaxMs": ordered.last().copied(),
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// receiver (Org B)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Receiver-side latency decomposition
// ---------------------------------------------------------------------------

/// Cumulative time the receiver's own stores and tool server have spent serving
/// the kernel, in nanoseconds, counted from the moment the process started.
///
/// Nothing here is sampled. Each decorator below wraps a real dependency the
/// kernel calls and adds the wall clock it observed; a caller reads the whole
/// ledger before an operation and again after it, and the difference is that
/// operation's share. The counters are process-wide, so a difference describes
/// one operation only while that operation is the only one running: the
/// sequential drivers take budgets, the concurrent ones do not.
#[derive(Debug, Default)]
struct PhaseLedger {
    store_resolve_nanos: AtomicU64,
    store_resolve_ops: AtomicU64,
    continuation_nanos: AtomicU64,
    continuation_ops: AtomicU64,
    lease_nanos: AtomicU64,
    lease_ops: AtomicU64,
    trust_floor_nanos: AtomicU64,
    trust_floor_ops: AtomicU64,
    dispatch_nanos: AtomicU64,
    dispatch_ops: AtomicU64,
    receipt_append_nanos: AtomicU64,
    receipt_append_ops: AtomicU64,
    receipt_other_nanos: AtomicU64,
    receipt_other_ops: AtomicU64,
    revocation_nanos: AtomicU64,
    revocation_ops: AtomicU64,
    admission_durable_nanos: AtomicU64,
    admission_durable_ops: AtomicU64,
    tool_outcome_durable_nanos: AtomicU64,
    tool_outcome_durable_ops: AtomicU64,
}

/// One read of every counter in [`PhaseLedger`].
#[derive(Debug, Clone, Copy, Default)]
struct LedgerSnapshot {
    store_resolve_nanos: u64,
    store_resolve_ops: u64,
    continuation_nanos: u64,
    continuation_ops: u64,
    lease_nanos: u64,
    lease_ops: u64,
    trust_floor_nanos: u64,
    trust_floor_ops: u64,
    dispatch_nanos: u64,
    dispatch_ops: u64,
    receipt_append_nanos: u64,
    receipt_append_ops: u64,
    receipt_other_nanos: u64,
    receipt_other_ops: u64,
    revocation_nanos: u64,
    revocation_ops: u64,
    admission_durable_nanos: u64,
    admission_durable_ops: u64,
    tool_outcome_durable_nanos: u64,
    tool_outcome_durable_ops: u64,
}

fn as_nanos(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

impl PhaseLedger {
    fn record(counter: &AtomicU64, ops: &AtomicU64, elapsed: Duration) {
        counter.fetch_add(as_nanos(elapsed), Ordering::SeqCst);
        ops.fetch_add(1, Ordering::SeqCst);
    }

    /// Resolving one named object against a receiver-owned store: the admission
    /// bundle and the six treaty artifacts the request cites by id and digest.
    fn record_store_resolve(&self, elapsed: Duration) {
        Self::record(&self.store_resolve_nanos, &self.store_resolve_ops, elapsed);
    }

    /// Consuming or releasing the single-use cross-kernel continuation.
    fn record_continuation(&self, elapsed: Duration) {
        Self::record(&self.continuation_nanos, &self.continuation_ops, elapsed);
    }

    /// Consuming or releasing the destructive lease the admission bundle names.
    fn record_lease(&self, elapsed: Duration) {
        Self::record(&self.lease_nanos, &self.lease_ops, elapsed);
    }

    /// Reading or advancing the monotone runtime trust floor.
    fn record_trust_floor(&self, elapsed: Duration) {
        Self::record(&self.trust_floor_nanos, &self.trust_floor_ops, elapsed);
    }

    /// The tool server invocation itself, after the kernel has committed to it.
    fn record_dispatch(&self, elapsed: Duration) {
        Self::record(&self.dispatch_nanos, &self.dispatch_ops, elapsed);
    }

    /// One durable receipt append, including the commit round trip.
    fn record_receipt_append(&self, elapsed: Duration) {
        Self::record(
            &self.receipt_append_nanos,
            &self.receipt_append_ops,
            elapsed,
        );
    }

    /// Everything else the receipt store serves during an admission: capability
    /// snapshots and delegation chains, session anchors, request and receipt
    /// lineage rows, point lookups and checkpoint work.
    fn record_receipt_other(&self, elapsed: Duration) {
        Self::record(&self.receipt_other_nanos, &self.receipt_other_ops, elapsed);
    }

    /// One revocation-store read or write on the capability chain.
    fn record_revocation(&self, elapsed: Duration) {
        Self::record(&self.revocation_nanos, &self.revocation_ops, elapsed);
    }

    /// One durable admission-operation store call: the fenced pre-dispatch
    /// record, the budget hold, the dispatch commit, the terminal projection.
    fn record_admission_durable(&self, elapsed: Duration) {
        Self::record(
            &self.admission_durable_nanos,
            &self.admission_durable_ops,
            elapsed,
        );
    }

    /// One durable record of what the tool returned.
    fn record_tool_outcome_durable(&self, elapsed: Duration) {
        Self::record(
            &self.tool_outcome_durable_nanos,
            &self.tool_outcome_durable_ops,
            elapsed,
        );
    }

    fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            store_resolve_nanos: self.store_resolve_nanos.load(Ordering::SeqCst),
            store_resolve_ops: self.store_resolve_ops.load(Ordering::SeqCst),
            continuation_nanos: self.continuation_nanos.load(Ordering::SeqCst),
            continuation_ops: self.continuation_ops.load(Ordering::SeqCst),
            lease_nanos: self.lease_nanos.load(Ordering::SeqCst),
            lease_ops: self.lease_ops.load(Ordering::SeqCst),
            trust_floor_nanos: self.trust_floor_nanos.load(Ordering::SeqCst),
            trust_floor_ops: self.trust_floor_ops.load(Ordering::SeqCst),
            dispatch_nanos: self.dispatch_nanos.load(Ordering::SeqCst),
            dispatch_ops: self.dispatch_ops.load(Ordering::SeqCst),
            receipt_append_nanos: self.receipt_append_nanos.load(Ordering::SeqCst),
            receipt_append_ops: self.receipt_append_ops.load(Ordering::SeqCst),
            receipt_other_nanos: self.receipt_other_nanos.load(Ordering::SeqCst),
            receipt_other_ops: self.receipt_other_ops.load(Ordering::SeqCst),
            revocation_nanos: self.revocation_nanos.load(Ordering::SeqCst),
            revocation_ops: self.revocation_ops.load(Ordering::SeqCst),
            admission_durable_nanos: self.admission_durable_nanos.load(Ordering::SeqCst),
            admission_durable_ops: self.admission_durable_ops.load(Ordering::SeqCst),
            tool_outcome_durable_nanos: self.tool_outcome_durable_nanos.load(Ordering::SeqCst),
            tool_outcome_durable_ops: self.tool_outcome_durable_ops.load(Ordering::SeqCst),
        }
    }
}

/// Where the receiver keeps the treaty evidence a request may cite.
///
/// `sqlite` is the default because the single-use property the experiment tests
/// rests on a primary-key insert: an in-memory set would test a different
/// mechanism. `memory` stays available so a run can separate the cost of the
/// durable store from the cost of the decision.
enum AdmissionBackend {
    Memory(InMemoryRuntimeAdmissionStore),
    Sqlite(SqliteRuntimeOrchestrationStore),
}

impl AdmissionBackend {
    fn label(&self) -> &'static str {
        match self {
            Self::Memory(_) => "memory",
            Self::Sqlite(_) => "sqlite",
        }
    }

    fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        match self {
            Self::Memory(store) => store.insert_bundle(bundle),
            Self::Sqlite(store) => store.insert_bundle(bundle),
        }
    }

    fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        match self {
            Self::Memory(store) => {
                store.insert_treaty_runtime_artifact(evidence_kind, evidence_id, artifact)
            }
            Self::Sqlite(store) => {
                store.insert_treaty_runtime_artifact(evidence_kind, evidence_id, artifact)
            }
        }
    }

    fn as_store(&self) -> &dyn RuntimeAdmissionStore {
        match self {
            Self::Memory(store) => store,
            Self::Sqlite(store) => store,
        }
    }
}

/// The receiver's admission store with a stopwatch on every method the kernel
/// calls. The decisions are the backend's; only the clock is added here.
#[derive(Clone)]
struct TimingAdmissionStore {
    backend: Arc<AdmissionBackend>,
    ledger: Arc<PhaseLedger>,
}

impl TimingAdmissionStore {
    fn new(backend: Arc<AdmissionBackend>, ledger: Arc<PhaseLedger>) -> Self {
        Self { backend, ledger }
    }

    fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        self.backend.insert_bundle(bundle)
    }

    fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        self.backend
            .insert_treaty_runtime_artifact(evidence_kind, evidence_id, artifact)
    }

    fn timed<T>(
        &self,
        record: impl Fn(&PhaseLedger, Duration),
        call: impl FnOnce(&dyn RuntimeAdmissionStore) -> T,
    ) -> T {
        let started = Instant::now();
        let outcome = call(self.backend.as_store());
        record(self.ledger.as_ref(), started.elapsed());
        outcome
    }
}

impl RuntimeAdmissionStore for TimingAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.timed(PhaseLedger::record_store_resolve, |store| {
            store.bundle(admission_id)
        })
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        self.timed(PhaseLedger::record_store_resolve, |store| {
            store.treaty_runtime_artifact(evidence_kind, evidence_id)
        })
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        self.timed(PhaseLedger::record_store_resolve, |store| {
            store.swarm_authority_bundle(task_graph_id)
        })
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_lease, |store| {
            store.consume_destructive_lease(lease_id, admission_id)
        })
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_lease, |store| {
            store.release_destructive_lease(lease_id, admission_id)
        })
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_continuation, |store| {
            store.consume_treaty_continuation(continuation_id, admission_id)
        })
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_continuation, |store| {
            store.release_treaty_continuation(continuation_id, admission_id)
        })
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_continuation, |store| {
            store.consume_swarm_continuation(continuation_id, admission_id)
        })
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_continuation, |store| {
            store.release_swarm_continuation(continuation_id, admission_id)
        })
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.timed(PhaseLedger::record_trust_floor, |store| {
            store.runtime_trust_floor(verifier_id, key_id)
        })
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.timed(PhaseLedger::record_trust_floor, |store| {
            store.record_runtime_trust_floor(entry)
        })
    }
}

/// The receiver's durable receipt store with a stopwatch on every append. Every
/// other method forwards unchanged, so the kernel sees the SQLite store's own
/// capabilities rather than a reduced trait default.
struct TimingReceiptStore {
    inner: SqliteReceiptStore,
    ledger: Arc<PhaseLedger>,
}

/// The trait the wrapper forwards through. `SqliteReceiptStore` has inherent
/// methods that share names with the trait's, so every forward names the trait
/// explicitly rather than letting method resolution choose.
use chio_kernel::receipt_store::ReceiptStore as Forwarded;
/// Every method below forwards to the SQLite store through the trait rather
/// than through its inherent surface, so the kernel sees exactly the store it
/// would have seen without the wrapper. The appends are timed apart from the
/// rest: the receipt the caller waits on is one line of the budget, and the
/// capability snapshots, lineage rows and point lookups the same store serves
/// during admission are another.
impl chio_kernel::receipt_store::ReceiptStore for TimingReceiptStore {
    fn append_chio_receipt(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_chio_receipt(&self.inner, receipt);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn durable_sink_id(&self) -> Option<&str> {
        Forwarded::durable_sink_id(&self.inner)
    }
    fn settlement_store_binding(&self) -> Option<chio_settle::SettlementStoreBinding> {
        Forwarded::settlement_store_binding(&self.inner)
    }
    fn atomic_receipt_projection(&self) -> chio_kernel::receipt_store::AtomicReceiptProjection {
        Forwarded::atomic_receipt_projection(&self.inner)
    }
    fn supports_atomic_receipt_projection_with_timeout(&self) -> bool {
        Forwarded::supports_atomic_receipt_projection_with_timeout(&self.inner)
    }
    fn append_chio_receipt_with_pending_observation(
        &self,
        receipt: &ChioReceipt,
        pending: &chio_kernel::receipt_store::PendingSettlementObservation,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome =
            Forwarded::append_chio_receipt_with_pending_observation(&self.inner, receipt, pending);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn append_chio_receipt_with_pending_observation_and_timeout(
        &self,
        receipt: &ChioReceipt,
        pending: &chio_kernel::receipt_store::PendingSettlementObservation,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_chio_receipt_with_pending_observation_and_timeout(
            &self.inner,
            receipt,
            pending,
            budget,
        );
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::load_chio_receipt(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_retained_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::load_retained_chio_receipt(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_retained_chio_receipt_commitment(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<chio_kernel::receipt_store::RetainedReceiptCommitment>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::load_retained_chio_receipt_commitment(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_child_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<chio_core::receipt::lineage::ChildRequestReceipt>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::load_child_receipt(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn append_chio_receipt_canonical(
        &self,
        receipt: &ChioReceipt,
        canonical: &chio_core::canonical::CanonicalBytes,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_chio_receipt_canonical(&self.inner, receipt, canonical);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_chio_receipt_returning_seq(&self.inner, receipt);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn append_chio_receipt_with_timeout(
        &self,
        receipt: &ChioReceipt,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_chio_receipt_with_timeout(&self.inner, receipt, budget);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn writer_liveness(
        &self,
        stall_threshold: std::time::Duration,
    ) -> chio_kernel::ReceiptWriterLiveness {
        let started = Instant::now();
        let outcome = Forwarded::writer_liveness(&self.inner, stall_threshold);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &chio_kernel::receipt_store::AuthorizationReceiptConsumption,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_chio_receipt_consuming_authorization(
            &self.inner,
            receipt,
            consumption,
        );
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::receipts_canonical_bytes_range(&self.inner, start_seq, end_seq);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn flush_receipt_writes(
        &self,
    ) -> Result<
        chio_kernel::receipt_store::ReceiptFlushReport,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::flush_receipt_writes(&self.inner);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn flush_receipt_writes_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<
        chio_kernel::receipt_store::ReceiptFlushReport,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::flush_receipt_writes_with_timeout(&self.inner, timeout);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn receipt_store_health(
        &self,
    ) -> Result<
        chio_kernel::receipt_store::ReceiptStoreHealthReport,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::receipt_store_health(&self.inner);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn writer_serving_closed(&self) -> bool {
        Forwarded::writer_serving_closed(&self.inner)
    }
    fn latest_committed_entry_seq(
        &self,
    ) -> Result<u64, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::latest_committed_entry_seq(&self.inner);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn latest_checkpointed_entry_seq(
        &self,
    ) -> Result<u64, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::latest_checkpointed_entry_seq(&self.inner);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn next_checkpoint_range(
        &self,
        max_batch: u64,
    ) -> Result<
        Option<chio_kernel::receipt_store::ReceiptCheckpointRange>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::next_checkpoint_range(&self.inner, max_batch);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn receipt_checkpoint_status(
        &self,
        max_batch: Option<u64>,
    ) -> Result<
        chio_kernel::receipt_store::ReceiptCheckpointStatusReport,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::receipt_checkpoint_status(&self.inner, max_batch);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn store_checkpoint(
        &self,
        checkpoint: &chio_kernel::KernelCheckpoint,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::store_checkpoint(&self.inner, checkpoint);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<
        chio_kernel::receipt_store::ReceiptCheckpointCreateReport,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::create_next_receipt_checkpoint(&self.inner, max_batch, keypair);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<chio_kernel::KernelCheckpoint>, chio_kernel::receipt_store::ReceiptStoreError>
    {
        let started = Instant::now();
        let outcome = Forwarded::load_checkpoint_by_seq(&self.inner, checkpoint_seq);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_latest_checkpoint(
        &self,
    ) -> Result<Option<chio_kernel::KernelCheckpoint>, chio_kernel::receipt_store::ReceiptStoreError>
    {
        let started = Instant::now();
        let outcome = Forwarded::load_latest_checkpoint(&self.inner);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn supports_kernel_signed_checkpoints(&self) -> bool {
        Forwarded::supports_kernel_signed_checkpoints(&self.inner)
    }
    fn enable_background_checkpoints(
        &self,
        keypair: Keypair,
        max_batch: u64,
    ) -> Result<bool, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::enable_background_checkpoints(&self.inner, keypair, max_batch);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn supports_retention(&self) -> bool {
        Forwarded::supports_retention(&self.inner)
    }
    fn rotate_receipts(
        &self,
        config: &chio_kernel::receipt_store::RetentionConfig,
    ) -> Result<u64, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::rotate_receipts(&self.inner, config);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn record_retention_rotation_outcome(&self, failure: Option<&str>) {
        let started = Instant::now();
        Forwarded::record_retention_rotation_outcome(&self.inner, failure);
        self.ledger.record_receipt_other(started.elapsed());
    }
    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome =
            Forwarded::record_capability_snapshot(&self.inner, token, parent_capability_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn record_capability_snapshot_with_timeout(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
        budget: std::time::Duration,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::record_capability_snapshot_with_timeout(
            &self.inner,
            token,
            parent_capability_id,
            budget,
        );
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<
        Option<chio_kernel::CapabilitySnapshot>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::get_capability_snapshot(&self.inner, capability_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn get_capability_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<chio_kernel::CapabilitySnapshot>, chio_kernel::receipt_store::ReceiptStoreError>
    {
        let started = Instant::now();
        let outcome = Forwarded::get_capability_delegation_chain(&self.inner, capability_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn record_session_anchor(
        &self,
        session_id: &str,
        anchor_id: &str,
        auth_context_fingerprint: &str,
        issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::record_session_anchor(
            &self.inner,
            session_id,
            anchor_id,
            auth_context_fingerprint,
            issued_at,
            supersedes_anchor_id,
            anchor_json,
        );
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn record_request_lineage(
        &self,
        session_id: &str,
        request_id: &str,
        parent_request_id: Option<&str>,
        session_anchor_id: Option<&str>,
        recorded_at: u64,
        request_fingerprint: Option<&str>,
        lineage_json: &serde_json::Value,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::record_request_lineage(
            &self.inner,
            session_id,
            request_id,
            parent_request_id,
            session_anchor_id,
            recorded_at,
            request_fingerprint,
            lineage_json,
        );
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn record_receipt_lineage_statement(
        &self,
        child_receipt_id: &str,
        request_id: Option<&str>,
        session_id: Option<&str>,
        session_anchor_id: Option<&str>,
        parent_request_id: Option<&str>,
        parent_receipt_id: Option<&str>,
        chain_id: Option<&str>,
        recorded_at: u64,
        statement_json: &serde_json::Value,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::record_receipt_lineage_statement(
            &self.inner,
            child_receipt_id,
            request_id,
            session_id,
            session_anchor_id,
            parent_request_id,
            parent_receipt_id,
            chain_id,
            recorded_at,
            statement_json,
        );
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn get_receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<chio_kernel::receipt_store::ReceiptLineageVerification>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::get_receipt_lineage_verification(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn get_retained_receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<chio_kernel::receipt_store::ReceiptLineageVerification>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::get_retained_receipt_lineage_verification(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn list_receipt_lineage_statement_links(
        &self,
        receipt_id: &str,
    ) -> Result<
        Vec<chio_kernel::receipt_store::ReceiptLineageStatementLink>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::list_receipt_lineage_statement_links(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_receipt_lineage_statement(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<chio_core::receipt::lineage::ReceiptLineageStatement>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::load_receipt_lineage_statement(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn load_retained_receipt_lineage_statement(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<chio_core::receipt::lineage::ReceiptLineageStatement>,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = Forwarded::load_retained_receipt_lineage_statement(&self.inner, receipt_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn as_any_mut(&self) -> Option<&dyn std::any::Any> {
        Forwarded::as_any_mut(&self.inner)
    }
    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<chio_kernel::CreditBondRow>, chio_kernel::receipt_store::ReceiptStoreError>
    {
        let started = Instant::now();
        let outcome = Forwarded::resolve_credit_bond(&self.inner, bond_id);
        self.ledger.record_receipt_other(started.elapsed());
        outcome
    }
    fn append_child_receipt(
        &self,
        receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_child_receipt(&self.inner, receipt);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn append_child_receipt_returning_seq(
        &self,
        receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<Option<u64>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_child_receipt_returning_seq(&self.inner, receipt);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
    fn append_child_receipt_with_timeout(
        &self,
        receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = Forwarded::append_child_receipt_with_timeout(&self.inner, receipt, budget);
        self.ledger.record_receipt_append(started.elapsed());
        outcome
    }
}
impl TimingReceiptStore {
    fn new(inner: SqliteReceiptStore, ledger: Arc<PhaseLedger>) -> Self {
        Self { inner, ledger }
    }
}

/// The receiver's durable admission-operation store with a stopwatch on every
/// method. This is the store the kernel opens the fenced pre-dispatch record in,
/// takes the budget hold through, and commits the terminal projection to, so it
/// is where an admission's durability cost lives.
struct TimingAuthorityStore {
    inner: chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore,
    ledger: Arc<PhaseLedger>,
}

/// The durable record of what the tool returned, on the same clock.
struct TimingToolOutcomeStore {
    inner: chio_store_sqlite::tool_outcome_store::SqliteToolOutcomeStore,
    ledger: Arc<PhaseLedger>,
}

impl chio_kernel::receipt_store::ReceiptStore for TimingAuthorityStore {
    fn append_chio_receipt(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome =
            chio_kernel::receipt_store::ReceiptStore::append_chio_receipt(&self.inner, receipt);
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn admission_projection_capabilities(
        &self,
    ) -> chio_kernel::admission_operation::AdmissionProjectionCapabilities {
        let started = Instant::now();
        let outcome = chio_kernel::receipt_store::ReceiptStore::admission_projection_capabilities(
            &self.inner,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn commit_admission_projection(
        &self,
        projection: &chio_kernel::admission_operation::AdmissionTerminalProjection,
    ) -> Result<
        chio_kernel::admission_operation::AdmissionTerminal,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::receipt_store::ReceiptStore::commit_admission_projection(
            &self.inner,
            projection,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome =
            chio_kernel::receipt_store::ReceiptStore::load_chio_receipt(&self.inner, receipt_id);
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn append_child_receipt(
        &self,
        receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), chio_kernel::receipt_store::ReceiptStoreError> {
        let started = Instant::now();
        let outcome =
            chio_kernel::receipt_store::ReceiptStore::append_child_receipt(&self.inner, receipt);
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
}

impl chio_kernel::admission_operation::AdmissionOperationStore for TimingAuthorityStore {
    fn begin(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::admission_operation::AdmissionBeginResult,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::admission_operation::AdmissionOperationStore::begin(
            &self.inner,
            operation,
            fence,
            trusted_now_unix_ms,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn load_by_operation_id(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<
        Option<chio_kernel::admission_operation::AdmissionOperationV1>,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome =
            chio_kernel::admission_operation::AdmissionOperationStore::load_by_operation_id(
                &self.inner,
                operation_id,
            );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn load_by_replay_key(
        &self,
        replay_key: &chio_kernel::admission_operation::AdmissionReplayKey,
    ) -> Result<
        Option<chio_kernel::admission_operation::AdmissionOperationV1>,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::admission_operation::AdmissionOperationStore::load_by_replay_key(
            &self.inner,
            replay_key,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn compare_and_swap(
        &self,
        command: &chio_kernel::admission_operation::AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::admission_operation::AdmissionCommandResult,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::admission_operation::AdmissionOperationStore::compare_and_swap(
            &self.inner,
            command,
            trusted_now_unix_ms,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn claim_recovery_untrusted(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_version: u64,
        claimant_id: &chio_kernel::admission_operation::AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<
        chio_kernel::admission_operation::UntrustedAdmissionRecoveryClaim,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome =
            chio_kernel::admission_operation::AdmissionOperationStore::claim_recovery_untrusted(
                &self.inner,
                operation_id,
                expected_version,
                claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                fence,
            );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn revalidate_recovery_claim(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        claim: &chio_kernel::admission_operation::UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError> {
        let started = Instant::now();
        let outcome =
            chio_kernel::admission_operation::AdmissionOperationStore::revalidate_recovery_claim(
                &self.inner,
                operation,
                claim,
                trusted_now_unix_ms,
                current_store_fence,
            );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<
        Vec<chio_kernel::admission_operation::AdmissionOperationV1>,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::admission_operation::AdmissionOperationStore::list_recoverable(
            &self.inner,
            not_after_unix_ms,
            limit,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn load_terminal_replay(
        &self,
        replay_key: &chio_kernel::admission_operation::AdmissionReplayKey,
    ) -> Result<
        Option<chio_kernel::admission_operation::AdmissionTerminalReplay>,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome =
            chio_kernel::admission_operation::AdmissionOperationStore::load_terminal_replay(
                &self.inner,
                replay_key,
            );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
}

impl chio_kernel::admission_operation::QualifiedAdmissionOperationStore for TimingAuthorityStore {}

impl chio_kernel::QualifiedAdmissionProjectionStore for TimingAuthorityStore {
    fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<
        Option<chio_kernel::payment::PaymentJournalRecord>,
        chio_kernel::AdmissionPaymentJournalError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::QualifiedAdmissionProjectionStore::load_payment_journal(
            &self.inner,
            operation_id,
            active_fence,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn advance_payment_journal(
        &self,
        advance: chio_kernel::AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<chio_kernel::payment::PaymentJournalRecord, chio_kernel::AdmissionPaymentJournalError>
    {
        let started = Instant::now();
        let outcome = chio_kernel::QualifiedAdmissionProjectionStore::advance_payment_journal(
            &self.inner,
            advance,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn begin_payment_settlement(
        &self,
        begin: chio_kernel::AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<chio_kernel::AdmissionPaymentSettlement, chio_kernel::AdmissionPaymentJournalError>
    {
        let started = Instant::now();
        let outcome = chio_kernel::QualifiedAdmissionProjectionStore::begin_payment_settlement(
            &self.inner,
            begin,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn authorize_budget_and_commit_admission(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        request: chio_kernel::budget_store::BudgetAuthorizeHoldRequest,
        payment_journal: Option<chio_kernel::payment::PaymentJournalRecord>,
        credit_exposure: Option<chio_kernel::CreditExposureReservationRequest>,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::AdmissionBudgetAuthorization,
        chio_kernel::AdmissionBudgetAuthorizationError,
    > {
        let started = Instant::now();
        let outcome =
            chio_kernel::QualifiedAdmissionProjectionStore::authorize_budget_and_commit_admission(
                &self.inner,
                operation,
                recovery_lease,
                request,
                payment_journal,
                credit_exposure,
                active_fence,
                trusted_now_unix_ms,
            );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        request: chio_kernel::budget_store::BudgetCaptureInvocationRequest,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::AdmissionBudgetCapture,
        chio_kernel::admission_operation::AdmissionCaptureError,
    > {
        let started = Instant::now();
        let outcome =
            chio_kernel::QualifiedAdmissionProjectionStore::capture_invocation_and_commit_dispatch(
                &self.inner,
                operation,
                recovery_lease,
                request,
                active_fence,
                trusted_now_unix_ms,
            );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn reserve_threshold_approval_and_commit_admission(
        &self,
        command: &chio_kernel::admission_operation::AdmissionOperationCommand,
        reservation: &chio_kernel::ThresholdApprovalReplayReservationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::admission_operation::AdmissionCommandResult,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::QualifiedAdmissionProjectionStore::reserve_threshold_approval_and_commit_admission(&self.inner, command, reservation, trusted_now_unix_ms);
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
    fn list_admission_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<chio_core::receipt::body::ChioReceipt>, chio_kernel::ReceiptStoreError> {
        let started = Instant::now();
        let outcome = chio_kernel::QualifiedAdmissionProjectionStore::list_admission_receipts_after(
            &self.inner,
            after_receipt_id,
            limit,
        );
        self.ledger.record_admission_durable(started.elapsed());
        outcome
    }
}

impl chio_kernel::tool_outcome::ToolOutcomeStore for TimingToolOutcomeStore {
    fn record_tool_returned(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        blob: &chio_kernel::tool_outcome::CanonicalInvocationBlobV1,
        record: &chio_kernel::tool_outcome::ToolOutcomeRecordV1,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::tool_outcome::ToolOutcomeInsertResultV1,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::record_tool_returned(
            &self.inner,
            operation,
            recovery_lease,
            blob,
            record,
            active_fence,
            trusted_now_unix_ms,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn lookup_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<
        Option<chio_kernel::tool_outcome::ToolOutcomeRecordV1>,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::lookup_by_operation(
            &self.inner,
            operation_id,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<
        Option<chio_kernel::tool_outcome::RawInvocationOutcomeV1>,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::load_raw_invocation_by_operation(
            &self.inner,
            operation_id,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn lookup_post_return_evaluation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<
        Option<chio_kernel::tool_outcome::PostReturnEvaluationRecordV1>,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::lookup_post_return_evaluation(
            &self.inner,
            operation_id,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        record: &chio_kernel::tool_outcome::PostReturnEvaluationRecordV1,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::tool_outcome::PostReturnEvaluationRecordV1,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::begin_post_return_evaluation(
            &self.inner,
            recovery_lease,
            record,
            active_fence,
            trusted_now_unix_ms,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn stage_post_return_evaluation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        next: &chio_kernel::tool_outcome::PostReturnEvaluationRecordV1,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::tool_outcome::PostReturnEvaluationRecordV1,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::stage_post_return_evaluation(
            &self.inner,
            operation_id,
            expected_version,
            recovery_lease,
            next,
            active_fence,
            trusted_now_unix_ms,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn finalize_post_return(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        terminal_evaluation: &chio_kernel::tool_outcome::PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &chio_kernel::tool_outcome::ToolOutcomeRecordV1,
        resolved_output: Option<&chio_kernel::tool_outcome::CanonicalResolvedOutputBlobV1>,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        (
            chio_kernel::tool_outcome::PostReturnEvaluationRecordV1,
            chio_kernel::tool_outcome::ToolOutcomeRecordV1,
        ),
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome = chio_kernel::tool_outcome::ToolOutcomeStore::finalize_post_return(
            &self.inner,
            operation_id,
            expected_evaluation_version,
            recovery_lease,
            terminal_evaluation,
            expected_outcome_version,
            terminal_outcome,
            resolved_output,
            active_fence,
            trusted_now_unix_ms,
        );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
    fn load_resolved_output_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<
        Option<chio_kernel::tool_outcome::CanonicalResolvedOutputBlobV1>,
        chio_kernel::tool_outcome::ToolOutcomeStoreError,
    > {
        let started = Instant::now();
        let outcome =
            chio_kernel::tool_outcome::ToolOutcomeStore::load_resolved_output_by_operation(
                &self.inner,
                operation_id,
            );
        self.ledger.record_tool_outcome_durable(started.elapsed());
        outcome
    }
}

impl chio_kernel::tool_outcome::QualifiedToolOutcomeStore for TimingToolOutcomeStore {}

/// The receiver's durable revocation store with a stopwatch on every lookup.
/// The kernel consults it once per capability in the delegation chain.
struct TimingRevocationStore {
    inner: SqliteRevocationStore,
    ledger: Arc<PhaseLedger>,
}

impl chio_kernel::RevocationStore for TimingRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, chio_kernel::RevocationStoreError> {
        let started = Instant::now();
        let outcome = chio_kernel::RevocationStore::is_revoked(&self.inner, capability_id);
        self.ledger.record_revocation(started.elapsed());
        outcome
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, chio_kernel::RevocationStoreError> {
        let started = Instant::now();
        let outcome = chio_kernel::RevocationStore::revoke(&self.inner, capability_id);
        self.ledger.record_revocation(started.elapsed());
        outcome
    }

    fn observe_revocation(
        &self,
        capability_id: &str,
    ) -> Result<chio_kernel::RevocationObservation, chio_kernel::RevocationStoreError> {
        let started = Instant::now();
        let outcome = chio_kernel::RevocationStore::observe_revocation(&self.inner, capability_id);
        self.ledger.record_revocation(started.elapsed());
        outcome
    }

    fn is_ephemeral(&self) -> bool {
        chio_kernel::RevocationStore::is_ephemeral(&self.inner)
    }
}

/// The tool the admitted call reaches. Its counter is the fail-closed gate every
/// denial scenario asserts: a denied call must never move it.
#[derive(Debug)]
struct CountingToolServer {
    server_id: String,
    tool_name: String,
    invocations: Arc<AtomicU64>,
    ledger: Arc<PhaseLedger>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let started = Instant::now();
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let output = serde_json::json!({ "tool": tool_name, "arguments": arguments });
        self.ledger.record_dispatch(started.elapsed());
        Ok(output)
    }
}

/// The revoked leaf set Org A announced, gated on the epoch that carries it.
#[derive(Debug, Default)]
struct OriginPublishedSubjects {
    inner: Mutex<(u64, BTreeSet<RevocationViewSubject>)>,
}

impl OriginPublishedSubjects {
    /// Monotone install: a replayed or older announcement is ignored.
    fn install(&self, epoch: u64, subjects: BTreeSet<RevocationViewSubject>) {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if epoch >= guard.0 {
            *guard = (epoch, subjects);
        }
    }
}

impl RevokedSubjectSource for OriginPublishedSubjects {
    fn revoked_at(&self, root: &EpochRoot) -> BTreeSet<RevocationViewSubject> {
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if root.epoch >= guard.0 {
            guard.1.clone()
        } else {
            BTreeSet::new()
        }
    }
}

/// Catch-up is out of scope for this experiment: Org A publishes a fresh root
/// every tick, so a receiver that misses one denies until the next arrives
/// rather than asking for the gap.
#[derive(Debug, Default)]
struct NoCatchupHistory;

impl chio_federation::revocation_gossip::RevocationCatchupHistory for NoCatchupHistory {
    fn signed_root_at(&self, _epoch: u64) -> Option<SignedEpochRoot> {
        None
    }
}

/// Per-call treaty evidence the receiver mints in its own store.
struct PreparedArtifacts {
    prepared: PreparedCall,
}

/// Everything the receiver owns: its kernel, its evidence store, and the treaty
/// it holds. Nothing here is reachable from Org A's process.
struct Receiver {
    kernel: Arc<ChioKernel>,
    store: TimingAdmissionStore,
    ledger: Arc<PhaseLedger>,
    /// The same tool server the kernel dispatches to, reachable without it. Only
    /// the baseline stage uses it, and it counts into its own counter.
    unmediated_server: CountingToolServer,
    baseline_invocations: Arc<AtomicU64>,
    admission_store: &'static str,
    treaty: TreatyDocument,
    base_receipt: ChioReceipt,
    remote_receipt_sha256: String,
    request_sha256: String,
    scope_sha256: String,
    intersection_id: String,
    intersection_sha256: String,
    dsse_consistency_model: String,
    origin_passport: PublicKey,
    local_keypair: Keypair,
    cosigner: Arc<IrohBilateralCoSigner>,
    view: Arc<RevocationView>,
    subjects: Arc<OriginPublishedSubjects>,
    invocations: Arc<AtomicU64>,
    calls: AtomicU64,
    sequence: AtomicU64,
}

/// The per-call digests the bilateral DSSE predicate binds. Passed as one value
/// so the binding and the artifacts it names cannot drift apart.
struct DsseInputs<'a> {
    lineage_sha256: &'a str,
    continuation_sha256: &'a str,
    local_receipt_sha256: &'a str,
    lease_id: &'a str,
    now: u64,
}

impl Receiver {
    fn stats(&self) -> ReceiverStats {
        ReceiverStats {
            calls: self.calls.load(Ordering::SeqCst),
            dispatches: self.invocations.load(Ordering::SeqCst),
            baseline_dispatches: self.baseline_invocations.load(Ordering::SeqCst),
            admission_store: self.admission_store.to_string(),
            revocation_epoch: self.view.current_epoch(),
            cosign_connections: self.cosigner.connections_opened(),
        }
    }

    fn cosign_snapshot(&self) -> CoSignSnapshot {
        CoSignSnapshot {
            connect_nanos: self.cosigner.connect_nanos(),
            exchange_nanos: self.cosigner.exchange_nanos(),
            hops: self.cosigner.connections_opened(),
        }
    }

    /// Mint the per-call evidence and obtain Org A's DSSE signature across the
    /// network. Untimed relative to the admission decision: this is the treaty
    /// paperwork, not the syscall.
    fn prepare(
        &self,
        sequence: Option<u64>,
        continuation_sequence: Option<u64>,
    ) -> Result<PreparedArtifacts, BoxError> {
        let started = Instant::now();
        let cosign_connections_before = self.cosigner.connections_opened();
        let sequence = sequence.unwrap_or_else(|| self.sequence.fetch_add(1, Ordering::SeqCst));
        // The continuation is numbered separately so several calls can be minted
        // against one of them. Every other artifact stays keyed to the call.
        let continuation_sequence = continuation_sequence.unwrap_or(sequence);
        let treaty = &self.treaty;
        let request_id = format!("req-federated-pair-{sequence}");
        let admission_id = format!("adm-federated-pair-{sequence}");
        let lease_id = format!("lease-federated-pair-{sequence}");
        let now = now_unix_ms()?;

        let bundle = RuntimeAdmissionBundle {
            schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
            admission_id: admission_id.clone(),
            binding: RuntimeRequestBinding {
                request_id: request_id.clone(),
                capability_id: treaty.capability_id.clone(),
                server_id: treaty.server_id.clone(),
                tool_name: treaty.tool_name.clone(),
                tool_args_sha256: self.request_sha256.clone(),
                origin_kernel_id: Some(treaty.origin_kernel_id.clone()),
                host_kernel_id: treaty.receiver_kernel_id.clone(),
            },
            workflow_id: format!("wf-federated-pair-{sequence}"),
            workflow_grant_id: format!("grant-federated-pair-{sequence}"),
            step_index: 1,
            destructive: true,
            lease_id: Some(lease_id.clone()),
            governance_receipt_id: Some(treaty.governance_receipt_id.clone()),
            trust_bundle_sha256: treaty.trust_bundle_sha256.clone(),
            verification_context_sha256: treaty.verification_context_sha256.clone(),
        };
        let admission_bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        self.store.insert_bundle(bundle)?;

        let continuation = CrossKernelContinuation {
            schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
            continuation_id: format!("continue-federated-pair-{continuation_sequence}"),
            source_kernel_id: treaty.origin_kernel_id.clone(),
            target_kernel_id: treaty.receiver_kernel_id.clone(),
            parent_receipt_sha256: sha256_hex(
                format!("federated-pair:parent-receipt:{continuation_sequence}").as_bytes(),
            ),
            parent_session_anchor_sha256: sha256_hex(
                format!("federated-pair:session-anchor:{continuation_sequence}").as_bytes(),
            ),
            capability_id: treaty.capability_id.clone(),
            action_class_id: treaty.action_class_id.clone(),
            audience_tool: format!("{}.{}", treaty.server_id, treaty.tool_name),
            nonce: format!("nonce-federated-pair-{continuation_sequence}"),
            issued_at_unix_ms: treaty.issued_at_unix_ms,
            expires_at_unix_ms: treaty.expires_at_unix_ms,
        };
        let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);

        let mut invocation = BilateralInvocation {
            schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: format!("invoke-federated-pair-{sequence}"),
            treaty_id: treaty.treaty_scope.treaty_id.clone(),
            ladder_intersection_sha256: self.intersection_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: treaty.action_class_id.clone(),
            consistency_model: "totally_ordered".to_string(),
            capability_id: treaty.capability_id.clone(),
            request_sha256: self.request_sha256.clone(),
            outcome_sha256: self.base_receipt.content_hash.clone(),
            local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
            remote_receipt_sha256: self.remote_receipt_sha256.clone(),
            signer_kernel_ids: treaty.treaty_scope.participant_kernel_ids.clone(),
        };
        let invocation_sha256 = bilateral_invocation_binding_sha256(&invocation)?;
        let lineage_statement = ReceiptLineageStatement {
            schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: format!("lineage-federated-pair-{sequence}"),
            parent_receipt_sha256: invocation.local_receipt_sha256.clone(),
            child_receipt_sha256: invocation.remote_receipt_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            bilateral_invocation_sha256: invocation_sha256.clone(),
            evidence_class: "verified".to_string(),
            source_kernel_id: continuation.source_kernel_id.clone(),
            target_kernel_id: continuation.target_kernel_id.clone(),
        };
        invocation.lineage_statement_sha256 =
            sha256_hex(&canonical_json_bytes(&lineage_statement)?);
        if bilateral_invocation_binding_sha256(&invocation)? != invocation_sha256 {
            return Err("the bilateral invocation binding moved after lineage completion".into());
        }
        let lineage = ReceiptLineageBundle {
            schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: format!("lineage-bundle-federated-pair-{sequence}"),
            root_receipt_sha256: lineage_statement.parent_receipt_sha256.clone(),
            leaf_receipt_sha256: lineage_statement.child_receipt_sha256.clone(),
            statements: vec![lineage_statement],
        };
        let lineage_sha256 = sha256_hex(&canonical_json_bytes(&lineage)?);

        // The co-sign hop that crosses the organization boundary: Org B signs the
        // DSSE preimage with its own passport key and asks Org A, over lane d, for
        // the second signature. Org A never holds Org B's key and never parses the
        // preimage.
        let dsse = self.sign_dsse(DsseInputs {
            lineage_sha256: &lineage_sha256,
            continuation_sha256: &continuation_sha256,
            local_receipt_sha256: &invocation.local_receipt_sha256,
            lease_id: &lease_id,
            now,
        })?;
        let dsse_sha256 = sha256_hex(&canonical_json_bytes(&dsse)?);
        let dsse_id = format!("bilateral-dsse-federated-pair-{sequence}");

        self.store.insert_treaty_runtime_artifact(
            "cross_kernel_continuation",
            &continuation.continuation_id,
            &continuation,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "receipt_lineage_bundle",
            &lineage.bundle_id,
            &lineage,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "bilateral_invocation",
            &invocation.invocation_id,
            &invocation,
        )?;
        self.store
            .insert_treaty_runtime_artifact("bilateral_dsse_envelope", &dsse_id, &dsse)?;

        Ok(PreparedArtifacts {
            prepared: PreparedCall {
                sequence,
                request_id,
                admission_id,
                admission_bundle_sha256,
                treaty_scope_id: treaty.treaty_scope.treaty_id.clone(),
                treaty_scope_sha256: self.scope_sha256.clone(),
                ladder_intersection_id: self.intersection_id.clone(),
                ladder_intersection_sha256: self.intersection_sha256.clone(),
                action_class_id: treaty.action_class_id.clone(),
                continuation_sequence,
                continuation_id: continuation.continuation_id,
                continuation_sha256,
                lineage_bundle_id: lineage.bundle_id,
                lineage_bundle_sha256: lineage_sha256,
                bilateral_invocation_id: invocation.invocation_id,
                bilateral_invocation_sha256: invocation_sha256,
                bilateral_dsse_id: dsse_id,
                bilateral_dsse_sha256: dsse_sha256,
                prepare_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                cosign_connections_before,
            },
        })
    }

    fn sign_dsse(&self, inputs: DsseInputs<'_>) -> Result<DsseEnvelope, BoxError> {
        let DsseInputs {
            lineage_sha256,
            continuation_sha256,
            local_receipt_sha256,
            lease_id,
            now,
        } = inputs;
        let treaty = &self.treaty;
        let extensions = BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: lease_id.to_string(),
                issuer: treaty.origin_kernel_id.clone(),
                expires_at_unix_ms: treaty.expires_at_unix_ms,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: format!("policy:{}", treaty.origin_kernel_id),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: format!("policy:{}", treaty.receiver_kernel_id),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: treaty.governance_receipt_id.clone(),
                kernel_id: treaty.receiver_kernel_id.clone(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: sha256_hex(
                        format!("federated-pair:governance:{}", treaty.governance_receipt_id)
                            .as_bytes(),
                    ),
                },
            }),
            consistency_anchor: Some(format!("anchor:{}", treaty.treaty_scope.treaty_id)),
            consistency_model: Some(self.dsse_consistency_model.clone()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: treaty.treaty_scope.treaty_id.clone(),
                treaty_scope_sha256: self.scope_sha256.clone(),
                ladder_intersection_sha256: self.intersection_sha256.clone(),
                admission_report_sha256: sha256_hex(
                    format!("federated-pair:admission-report:{continuation_sha256}").as_bytes(),
                ),

                continuation_sha256: continuation_sha256.to_string(),
                lineage_bundle_sha256: lineage_sha256.to_string(),
                action_class_id: treaty.action_class_id.clone(),
                consistency_model: self.dsse_consistency_model.clone(),
                request_sha256: self.request_sha256.clone(),
                outcome_sha256: self.base_receipt.content_hash.clone(),
                local_receipt_sha256: local_receipt_sha256.to_string(),
                remote_receipt_sha256: self.remote_receipt_sha256.clone(),
                lease_refs: vec![lease_id.to_string()],
                governance_refs: vec![treaty.governance_receipt_id.clone()],
                signer_kernel_ids: treaty.treaty_scope.participant_kernel_ids.clone(),
            }),
        };
        Ok(sign_chio_bilateral_dsse_envelope_with_cosigner(
            &self.base_receipt,
            &self.origin_passport,
            &self.local_keypair,
            &self.treaty.origin_kernel_id,
            &self.treaty.receiver_kernel_id,
            &self.treaty.tool_name,
            now,
            extensions,
            self.cosigner.as_ref(),
        )?)
    }

    /// The measured operation: one receiver-owned admission decision.
    ///
    /// The window is bracketed by a reading of every counter the receiver's own
    /// dependencies keep, so the decision's cost can be attributed to its parts
    /// instead of reported as one number. Those counters are process-wide: the
    /// attribution describes this call only while it is the only call running,
    /// which the budget's own consistency check enforces.
    async fn call(&self, request: &ToolCallRequest) -> CallDecision {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ledger_before = self.ledger.snapshot();
        let cosign_before = self.cosign_snapshot();
        let started = Instant::now();
        let outcome = self.kernel.evaluate_tool_call(request).await;
        let elapsed = started.elapsed();
        let budget = ReceiverBudget::between(
            elapsed,
            (ledger_before, self.ledger.snapshot()),
            (cosign_before, self.cosign_snapshot()),
        );
        let evaluate_micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let (verdict, failure_code, receipt_id) = match outcome {
            Ok(response) => {
                let verdict = match response.verdict {
                    Verdict::Allow => "allow",
                    Verdict::Deny => "deny",
                    Verdict::PendingApproval => "pending_approval",
                };
                let failure_code = response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata["chio_runtime"]["failure_code"].as_str())
                    .map(str::to_string)
                    .or(response.reason)
                    .unwrap_or_default();
                (verdict.to_string(), failure_code, response.receipt.id)
            }
            // A kernel error is a denial for this experiment's purposes: nothing
            // dispatched, and the failure is reported rather than retried.
            Err(error) => ("deny".to_string(), error.to_string(), String::new()),
        };
        CallDecision {
            request_id: request.request_id.clone(),
            verdict,
            failure_code,
            receipt_id,
            evaluate_micros,
            dispatches: self.invocations.load(Ordering::SeqCst),
            revocation_epoch: self.view.current_epoch(),
            cosign_connections: self.cosigner.connections_opened(),
            budget,
        }
    }

    /// The same tool, invoked with the kernel taken out of the path.
    ///
    /// This is the denominator: the transport, the frame, the tool server and
    /// nothing else. No capability is checked, no evidence is resolved, no
    /// continuation is consumed, nothing is dispatched through an admission, and
    /// no receipt is written, so the difference between this and `call` is what
    /// mediating the call costs. It counts into its own invocation counter, so
    /// the admitted run's dispatch assertions are unaffected.
    async fn direct_call(&self, request: &ToolCallRequest) -> CallDecision {
        let ledger_before = self.ledger.snapshot();
        let cosign_before = self.cosign_snapshot();
        let started = Instant::now();
        let outcome = self
            .unmediated_server
            .invoke(&request.tool_name, request.arguments.clone(), None)
            .await;
        let elapsed = started.elapsed();
        let budget = ReceiverBudget::between(
            elapsed,
            (ledger_before, self.ledger.snapshot()),
            (cosign_before, self.cosign_snapshot()),
        );
        let (verdict, failure_code) = match outcome {
            Ok(_) => ("allow".to_string(), String::new()),
            Err(error) => ("deny".to_string(), error.to_string()),
        };
        CallDecision {
            request_id: request.request_id.clone(),
            verdict,
            failure_code,
            receipt_id: String::new(),
            evaluate_micros: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            dispatches: self.baseline_invocations.load(Ordering::SeqCst),
            revocation_epoch: self.view.current_epoch(),
            cosign_connections: self.cosigner.connections_opened(),
            budget,
        }
    }

    /// Accept Org A's signed revoked-subject announcement. The signature is
    /// checked against the passport key the issuer-signed directory binds for Org
    /// A, so an unsigned or foreign frame changes nothing.
    fn install_revoked_subjects(&self, frame: &SignedRevokedSubjects) -> Result<(), BoxError> {
        if frame.body.schema != REVOKED_SUBJECTS_SCHEMA {
            return Err(format!("unexpected schema {}", frame.body.schema).into());
        }
        if frame.body.origin_kernel_id != self.treaty.origin_kernel_id {
            return Err(format!("{} is not the treaty origin", frame.body.origin_kernel_id).into());
        }
        let bytes = canonical_json_bytes(&frame.body)?;
        if !self.origin_passport.verify(&bytes, &frame.signature) {
            return Err("the revoked-subject frame is not signed by the origin passport".into());
        }
        self.subjects.install(
            frame.body.epoch,
            frame
                .body
                .subjects
                .iter()
                .map(|subject| RevocationViewSubject::new(subject.clone()))
                .collect(),
        );
        Ok(())
    }
}

/// The experiment-only tool-call lane. It exists because no shipped Chio lane
/// carries a `ToolCallRequest`.
///
/// It carries no trust of its own: like every shipped lane it re-resolves the
/// authenticated `EndpointId` through the verified directory and requires the
/// resolved kernel id to be the party the treaty names for that frame. The
/// request body is still only a claim; what the receiver believes about it comes
/// from its own store and from Org A's live co-signature.
struct ExperimentHandler {
    receiver: Arc<Receiver>,
    gate: DirectoryGate,
    limiter: AcceptLimiter,
}

impl std::fmt::Debug for ExperimentHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExperimentHandler")
            .field("kernel_id", &self.receiver.treaty.receiver_kernel_id)
            .finish_non_exhaustive()
    }
}

impl ExperimentHandler {
    /// The kernel id the verified directory binds to the authenticated endpoint,
    /// or a refusal. An endpoint the directory no longer binds is refused even
    /// though the accept-time gate admitted it, so a directory that moved between
    /// handshake and frame is honoured.
    fn authenticated_peer(&self, connection: &Connection) -> Result<String, String> {
        let remote = connection.remote_id();
        self.gate.resolve(&remote).ok_or_else(|| {
            format!(
                "endpoint {} is not bound by the current directory snapshot",
                remote.fmt_short()
            )
        })
    }

    /// Every frame names the role the treaty expects to send it. The sender drives
    /// calls; only Org A announces what it revoked.
    fn require_peer(peer: &str, expected: &str, frame: &str) -> Result<(), String> {
        if peer == expected {
            return Ok(());
        }
        Err(format!(
            "{frame} must come from {expected}, not from {peer}"
        ))
    }

    async fn decide(&self, peer: &str, request: ExperimentRequest) -> ExperimentReply {
        let treaty = &self.receiver.treaty;
        let refused = |detail: String| ExperimentReply::Refused { detail };
        match request {
            ExperimentRequest::Call { request } => {
                if let Err(detail) =
                    Self::require_peer(peer, &treaty.sender_kernel_id, "a tool call")
                {
                    return refused(detail);
                }
                // The request claims an origin; the claim must at least name the
                // treaty's origin before the kernel spends an admission on it.
                if request.federated_origin_kernel_id.as_deref()
                    != Some(treaty.origin_kernel_id.as_str())
                {
                    return refused(format!(
                        "a tool call must declare {} as its federated origin",
                        treaty.origin_kernel_id
                    ));
                }
                ExperimentReply::Decision(Box::new(self.receiver.call(&request).await))
            }
            ExperimentRequest::DirectCall { request } => {
                if let Err(detail) =
                    Self::require_peer(peer, &treaty.sender_kernel_id, "an unmediated tool call")
                {
                    return refused(detail);
                }
                if request.server_id != treaty.server_id || request.tool_name != treaty.tool_name {
                    return refused(format!(
                        "the baseline serves only {}.{}",
                        treaty.server_id, treaty.tool_name
                    ));
                }
                ExperimentReply::Decision(Box::new(self.receiver.direct_call(&request).await))
            }
            ExperimentRequest::Prepare {
                sequence,
                continuation_sequence,
            } => {
                if let Err(detail) =
                    Self::require_peer(peer, &treaty.sender_kernel_id, "a preparation request")
                {
                    return refused(detail);
                }
                match self.receiver.prepare(sequence, continuation_sequence) {
                    Ok(artifacts) => ExperimentReply::Prepared(Box::new(artifacts.prepared)),
                    Err(error) => refused(error.to_string()),
                }
            }
            ExperimentRequest::Stats => {
                if let Err(detail) =
                    Self::require_peer(peer, &treaty.sender_kernel_id, "a stats request")
                {
                    return refused(detail);
                }
                ExperimentReply::Stats(self.receiver.stats())
            }
            ExperimentRequest::RevokedSubjects(frame) => {
                if let Err(detail) = Self::require_peer(
                    peer,
                    &treaty.origin_kernel_id,
                    "a revoked-subject announcement",
                ) {
                    return refused(detail);
                }
                match self.receiver.install_revoked_subjects(&frame) {
                    Ok(()) => ExperimentReply::Accepted,
                    Err(error) => refused(error.to_string()),
                }
            }
        }
    }

    async fn serve(&self, connection: &Connection) -> Result<(), BoxError> {
        let peer = self.authenticated_peer(connection);
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, connection.accept_bi())
            .await??;
        let frame = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        let request: ExperimentRequest = serde_json::from_slice(&frame)?;
        let reply = match peer {
            Ok(peer) => self.decide(&peer, request).await,
            Err(detail) => ExperimentReply::Refused { detail },
        };
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &serde_json::to_vec(&reply)?),
            )
            .await??;
        send.finish()?;
        Ok(())
    }
}

impl ProtocolHandler for ExperimentHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // One in-flight permit per peer, held for the whole handler, so a peer
        // that opens connections without finishing them is shed rather than
        // accumulating tasks.
        let _permit = match self.limiter.admit_peer(&connection.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                connection.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        let result = self.serve(&connection).await;
        match result {
            Ok(()) => {
                // Let the client read the reply and close first, within the bound.
                self.limiter.linger(&connection).await;
                Ok(())
            }
            Err(error) => {
                connection.close(VarInt::from_u32(1), b"experiment");
                Err(AcceptError::from_err(std::io::Error::other(
                    error.to_string(),
                )))
            }
        }
    }
}

/// The clock lane. It answers one question, with the answering kernel's own
/// identity attached: what time does this host think it is?
///
/// It carries no trust and decides nothing. It exists so a run split across two
/// machines can refuse to measure before it starts when the two clocks disagree
/// by more than the run's bound, which would otherwise show up as revocation
/// freshness denials attributed to the treaty.
struct ClockHandler {
    gate: DirectoryGate,
    kernel_id: String,
    peers: BTreeSet<String>,
    limiter: AcceptLimiter,
}

impl std::fmt::Debug for ClockHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockHandler")
            .field("kernel_id", &self.kernel_id)
            .finish_non_exhaustive()
    }
}

impl ClockHandler {
    async fn serve(&self, connection: &Connection) -> Result<(), BoxError> {
        let remote = connection.remote_id();
        let peer = self.gate.resolve(&remote);
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, connection.accept_bi())
            .await??;
        let frame = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        let probe: ClockProbe = serde_json::from_slice(&frame)?;
        // Same discipline as every other lane: the authenticated endpoint must
        // still resolve through the verified directory to a party this role
        // exchanges frames with, and the frame must carry the expected schema.
        let reply = match peer {
            Some(peer) if self.peers.contains(&peer) && probe.schema == CLOCK_SCHEMA => {
                Some(ClockReply {
                    schema: CLOCK_SCHEMA.to_string(),
                    kernel_id: self.kernel_id.clone(),
                    unix_ms: now_unix_ms()?,
                })
            }
            _ => None,
        };
        let Some(reply) = reply else {
            return Err("a clock probe arrived from an endpoint this role does not serve".into());
        };
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &serde_json::to_vec(&reply)?),
            )
            .await??;
        send.finish()?;
        Ok(())
    }
}

impl ProtocolHandler for ClockHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let _permit = match self.limiter.admit_peer(&connection.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                connection.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        match self.serve(&connection).await {
            Ok(()) => {
                self.limiter.linger(&connection).await;
                Ok(())
            }
            Err(error) => {
                connection.close(VarInt::from_u32(1), b"clock");
                Err(AcceptError::from_err(std::io::Error::other(
                    error.to_string(),
                )))
            }
        }
    }
}

/// One clock probe against a peer that mounts [`ALPN_CLOCK`].
///
/// The reading is the usual three-timestamp estimate: the local clock before the
/// request, the peer's clock in the reply, the local clock after. The offset is
/// the peer's reading minus the midpoint of the two local ones, and half the
/// round trip bounds the error in that estimate.
async fn probe_clock(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    expect_kernel_id: &str,
) -> Result<(i64, u64), BoxError> {
    let connection = client_bounded(
        AcceptPhase::AcceptStream,
        endpoint.connect(peer, ALPN_CLOCK),
    )
    .await?
    .map_err(|error| format!("the clock lane did not connect: {error}"))?;
    let result = probe_clock_inner(&connection, expect_kernel_id).await;
    connection.close(VarInt::from_u32(CLOSE_OK), b"done");
    result
}

async fn probe_clock_inner(
    connection: &Connection,
    expect_kernel_id: &str,
) -> Result<(i64, u64), BoxError> {
    let (mut send, mut recv) = client_bounded(AcceptPhase::AcceptStream, connection.open_bi())
        .await?
        .map_err(|error| format!("the clock lane did not open a stream: {error}"))?;
    let probe = ClockProbe {
        schema: CLOCK_SCHEMA.to_string(),
    };
    let before = now_unix_ms()?;
    client_bounded(
        AcceptPhase::WriteResponse,
        write_frame(&mut send, &serde_json::to_vec(&probe)?),
    )
    .await??;
    send.finish()?;
    let frame = client_bounded(AcceptPhase::ReadFrame, read_frame(&mut recv)).await??;
    let after = now_unix_ms()?;
    let reply: ClockReply = serde_json::from_slice(&frame)?;
    if reply.schema != CLOCK_SCHEMA {
        return Err(format!("a clock reply carried schema {}", reply.schema).into());
    }
    if reply.kernel_id != expect_kernel_id {
        return Err(format!(
            "the clock reply came from {}, not from {expect_kernel_id}",
            reply.kernel_id
        )
        .into());
    }
    let round_trip = after.saturating_sub(before);
    let midpoint = before.saturating_add(round_trip / 2);
    let offset_ms = i64::try_from(reply.unix_ms).unwrap_or(i64::MAX)
        - i64::try_from(midpoint).unwrap_or(i64::MAX);
    Ok((offset_ms, round_trip))
}

/// Stand up Org B and serve until the process is stopped.
async fn run_receiver(args: &Args) -> Result<(), BoxError> {
    let loaded = load_role(args)?;
    let treaty = loaded.treaty.clone();
    let receiver_id = treaty.receiver_kernel_id.clone();
    let origin_id = treaty.origin_kernel_id.clone();
    if loaded.secrets.kernel_id != receiver_id {
        return Err(format!(
            "--dir holds keys for {} but the treaty names {receiver_id} as the receiver",
            loaded.secrets.kernel_id
        )
        .into());
    }
    let local_keypair = Keypair::from_seed(&decode_seed(&loaded.secrets.passport_seed_hex)?);
    let origin_passport = loaded
        .directory
        .resolve_passport_key(&origin_id)
        .ok_or_else(|| format!("the directory does not bind a passport key for {origin_id}"))?
        .clone();

    let gate = DirectoryGate::new(Arc::clone(&loaded.directory));
    let endpoint =
        bind_endpoint(args, &loaded.secrets.transport_seed_hex, Some(gate.clone())).await?;
    let peers = peer_map(args)?;
    let origin_addr = peer_address(&loaded.directory, &peers, &origin_id)?;

    let store_dir = args.path("store-dir")?;
    fs::create_dir_all(&store_dir)?;
    restrict_directory_to_owner(&store_dir)?;
    // Durable admission operations live beside the receipts: the receiver commits
    // an admission before it dispatches, and it is the only party that can read
    // back what it committed.
    SqliteAuthorityStore::ensure_serving_supported()?;
    let authority_path = store_dir.join("kernel-authority.sqlite3");
    let authority_locks = store_dir.join("kernel-authority-locks");
    fs::create_dir_all(&authority_locks)?;
    restrict_directory_to_owner(&authority_locks)?;
    SqliteAuthorityStore::provision(&authority_path, &authority_locks)?;
    let authority = SqliteAuthorityStore::open_serving(&authority_path, &authority_locks)?;

    // Org A is pinned from the handshake envelope it published, verified against
    // the passport key the directory already binds. Request-borne trust is never
    // consulted: the envelope only proves possession of a key Org B already pins.
    let handshake: PeerHandshakeEnvelope = read_json(&args.path("handshake")?)?;
    let now_secs = now_unix_ms()? / 1_000;
    let exchange = KernelTrustExchange::new(receiver_id.clone(), local_keypair.clone())
        .with_trusted_peer(origin_id.clone(), origin_passport.clone());
    let peer = exchange.accept_envelope(&handshake, &origin_id, now_secs)?;

    // The single-use property this experiment races rests on a primary-key
    // insert, so the durable store is the default: an in-memory set would be a
    // different mechanism under the same name. `memory` stays available so a run
    // can separate the store's cost from the decision's.
    let ledger = Arc::new(PhaseLedger::default());
    let admission_store = args.optional("admission-store").unwrap_or("sqlite");
    let backend = match admission_store {
        "sqlite" => AdmissionBackend::Sqlite(SqliteRuntimeOrchestrationStore::open(
            store_dir.join("runtime-admission.sqlite3"),
        )?),
        "memory" => AdmissionBackend::Memory(InMemoryRuntimeAdmissionStore::new()),
        other => {
            return Err(format!("--admission-store expects sqlite or memory, got {other}").into())
        }
    };
    let admission_store = backend.label();
    let store = TimingAdmissionStore::new(Arc::new(backend), Arc::clone(&ledger));
    let intersection: LadderIntersection = compute_ladder_intersection(
        &treaty.treaty_scope,
        &treaty.ladder_manifests,
        now_unix_ms()?,
    )?;
    let scope_sha256 = treaty_scope_sha256(&treaty.treaty_scope)?;
    let intersection_sha256 = ladder_intersection_sha256(&intersection)?;
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &treaty.treaty_scope.treaty_id,
        &treaty.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &intersection.intersection_id,
        &intersection,
    )?;

    let invocations = Arc::new(AtomicU64::new(0));
    let view = Arc::new(RevocationView::new());
    let subjects = Arc::new(OriginPublishedSubjects::default());
    let cosigner = Arc::new(IrohBilateralCoSigner::new(
        endpoint.clone(),
        address_book(&origin_id, origin_addr),
    ));

    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: local_keypair.clone(),
        ca_public_keys: vec![treaty.ca_public_key.clone()],
        max_delegation_depth: 5,
        // Durable admission requires a canonical SHA-256 policy hash, not a label.
        policy_hash: sha256_hex(format!("policy:{receiver_id}").as_bytes()),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    })
    .with_federation_peers(vec![peer]);
    kernel.set_federation_local_kernel_id(&receiver_id);
    kernel.set_federation_cosigner(Arc::clone(&cosigner) as Arc<_>);
    kernel.set_receipt_store(Box::new(TimingReceiptStore::new(
        SqliteReceiptStore::open(store_dir.join("kernel-receipts.sqlite3"))?,
        Arc::clone(&ledger),
    )))?;
    kernel.set_durable_admission_store(
        Arc::new(TimingAuthorityStore {
            inner: authority.admission_operation_store(),
            ledger: Arc::clone(&ledger),
        }),
        Arc::new(TimingToolOutcomeStore {
            inner: authority.tool_outcome_store(),
            ledger: Arc::clone(&ledger),
        }),
        authority.mutation_fence(),
    )?;
    kernel.reconcile_durable_admission_receipt_projections()?;
    kernel.set_revocation_store(Box::new(TimingRevocationStore {
        inner: SqliteRevocationStore::open(store_dir.join("kernel-revocations.sqlite3"))?,
        ledger: Arc::clone(&ledger),
    }));
    kernel.register_tool_server(Box::new(CountingToolServer {
        server_id: treaty.server_id.clone(),
        tool_name: treaty.tool_name.clone(),
        invocations: Arc::clone(&invocations),
        ledger: Arc::clone(&ledger),
    }));
    kernel.set_runtime_admission_hook(Arc::new(
        ChioRuntimeAdmissionHook::new(treaty.admission_profile.clone(), store.clone())
            .with_runtime_trust_input(
                treaty.signed_trust_bundle.clone(),
                treaty.trusted_verifier_keys.clone(),
            )
            .with_pheromone_query_report(treaty.signed_query_report.clone())
            .with_runtime_pheromone_policy(
                treaty.signed_pheromone_policy.clone(),
                treaty.signed_peer_weights.clone(),
            ),
    ));
    kernel.set_revocation_view(Arc::clone(&view));

    let base_receipt = base_receipt(&treaty, &local_keypair)?;
    let baseline_invocations = Arc::new(AtomicU64::new(0));
    let receiver = Arc::new(Receiver {
        kernel: Arc::new(kernel),
        store,
        unmediated_server: CountingToolServer {
            server_id: treaty.server_id.clone(),
            tool_name: treaty.tool_name.clone(),
            invocations: Arc::clone(&baseline_invocations),
            ledger: Arc::clone(&ledger),
        },
        baseline_invocations,
        admission_store,
        ledger,
        remote_receipt_sha256: sha256_hex(&canonical_json_bytes(&base_receipt)?),
        request_sha256: tool_args_sha256(&treaty.arguments)?,
        scope_sha256,
        intersection_id: intersection.intersection_id.clone(),
        intersection_sha256,
        dsse_consistency_model: bilateral_dsse_consistency_model("totally_ordered")?.to_string(),
        origin_passport,
        local_keypair,
        cosigner,
        view: Arc::clone(&view),
        subjects: Arc::clone(&subjects),
        invocations,
        calls: AtomicU64::new(0),
        sequence: AtomicU64::new(1),
        base_receipt,
        treaty,
    });

    let sink = Arc::new(
        RevocationViewSink::new(Arc::clone(&view))
            .with_subject_source(Arc::clone(&subjects) as Arc<dyn RevokedSubjectSource>),
    );
    let _router = Router::builder(endpoint)
        .accept(
            ALPN_REVOCATION_ROOT,
            RevocationHandler::new(
                Arc::clone(&loaded.directory),
                Arc::new(NoCatchupHistory),
                sink,
                receiver_id.clone(),
            ),
        )
        .accept(
            ALPN_EXPERIMENT,
            ExperimentHandler {
                receiver: Arc::clone(&receiver),
                gate: gate.clone(),
                limiter: AcceptLimiter::new(experiment_limits()),
            },
        )
        .accept(
            ALPN_CLOCK,
            ClockHandler {
                gate,
                kernel_id: receiver_id.clone(),
                peers: BTreeSet::from([
                    receiver.treaty.origin_kernel_id.clone(),
                    receiver.treaty.sender_kernel_id.clone(),
                ]),
                limiter: AcceptLimiter::new(experiment_limits()),
            },
        )
        .spawn();

    println!(
        "receiver {receiver_id} listening on {}; origin {origin_id} pinned",
        args.value("bind")?
    );

    // Readiness is the first epoch root, not the first bound socket: until Org
    // A's revocation clock has been installed the receiver denies everything its
    // freshness bound covers, and a driver that starts sending would measure that.
    let ready_path = args.path("ready-out")?;
    let deadline = Instant::now() + Duration::from_secs(args.count("ready-timeout-secs", 30)?);
    loop {
        if view.current_epoch() > 0 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(
                "no epoch root arrived from the origin before the readiness timeout".into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_json(
        &ready_path,
        &serde_json::json!({
            "kernelId": receiver_id,
            "revocationEpoch": view.current_epoch(),
        }),
    )?;
    println!("receiver ready at epoch {}", view.current_epoch());

    loop {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
    }
}

/// The receiver-signed receipt the bilateral DSSE subject names. It is Org B's
/// own record of the action, which is why Org B signs it and Org A only ever
/// sees its digest.
fn base_receipt(treaty: &TreatyDocument, local: &Keypair) -> Result<ChioReceipt, BoxError> {
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("invoke-federated-pair-base-{}", treaty.capability_id),
            timestamp: treaty.issued_at_unix_ms / 1_000,
            capability_id: treaty.capability_id.clone(),
            tool_server: treaty.server_id.clone(),
            tool_name: treaty.tool_name.clone(),
            action: ToolCallAction::from_parameters(treaty.arguments.clone())?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: format!("agent:{}/federated-pair", treaty.origin_kernel_id),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: sha256_hex(
                format!("federated-pair:outcome:{}", treaty.capability_id).as_bytes(),
            ),
            policy_hash: sha256_hex(format!("policy:{}", treaty.receiver_kernel_id).as_bytes()),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: local.public_key(),
            bbs_projection_version: None,
        },
        local,
    )?)
}

// ---------------------------------------------------------------------------
// send, revoke, cut (Org A's agent-side driver)
// ---------------------------------------------------------------------------

/// What the sender does to the request it authors, and what the receiver must
/// answer. Each denial is something a remote sender can actually reach: it
/// mutates the request, never the receiver's store.
#[derive(Debug, Clone, Copy)]
struct Scenario {
    name: &'static str,
    verdict: &'static str,
    failure_code: &'static str,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "allow",
        verdict: "allow",
        failure_code: "",
    },
    Scenario {
        name: "scope_hash_mismatch",
        verdict: "deny",
        failure_code: "chio_treaty_scope_hash_mismatch",
    },
    Scenario {
        name: "missing_required_evidence",
        verdict: "deny",
        failure_code: "chio_treaty_missing_required_evidence",
    },
    Scenario {
        name: "smuggled_trust_root",
        verdict: "deny",
        failure_code: "request_smuggled_trust_root",
    },
    Scenario {
        name: "smuggled_dynamic_trust",
        verdict: "deny",
        failure_code: "request_smuggled_dynamic_trust",
    },
    Scenario {
        name: "intersection_hash_mismatch",
        verdict: "deny",
        failure_code: "chio_treaty_intersection_mismatch",
    },
    Scenario {
        name: "unknown_treaty_scope",
        verdict: "deny",
        failure_code: "chio_treaty_missing_scope",
    },
    Scenario {
        name: "unknown_ladder_intersection",
        verdict: "deny",
        failure_code: "chio_treaty_missing_intersection",
    },
];

fn scenario_named(name: &str) -> Result<Scenario, BoxError> {
    SCENARIOS
        .iter()
        .copied()
        .find(|scenario| scenario.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = SCENARIOS.iter().map(|scenario| scenario.name).collect();
            format!(
                "unknown scenario {name}; expected one of {}",
                names.join(", ")
            )
            .into()
        })
}

/// Why the receiver said no. The three kinds are distinguished because two of
/// them are the measurement and one of them is an artefact of the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenialKind {
    /// The revocation snapshot did not satisfy the kernel's freshness window.
    ///
    /// The consuming kernel reads its clock in whole seconds while its staleness
    /// bound is half a second, so an installed revocation view necessarily denies
    /// for the short prefix of each second before that second's root lands. These
    /// denials are counted and retried, never measured.
    Freshness,
    /// The capability, or an ancestor of it, is revoked.
    Revoked,
    /// A treaty-admission denial: what the negative scenarios are measuring.
    Admission,
}

/// What the receiver answers a call whose continuation another call already
/// consumed. Named here so the contention run asserts the code rather than
/// accepting any denial as proof of single use.
const CONTINUATION_REPLAY_CODE: &str = "chio_treaty_continuation_replay";

fn classify(failure_code: &str) -> DenialKind {
    if failure_code.contains("revocation view snapshot") {
        DenialKind::Freshness
    } else if failure_code.contains("has been revoked") || failure_code.contains("chain revoked") {
        DenialKind::Revoked
    } else {
        DenialKind::Admission
    }
}

/// The sender's side of the boundary: its own transport identity, the treaty it
/// was given, and the receiver's address. It holds no kernel and no passport.
struct Sender {
    endpoint: Endpoint,
    receiver_addr: EndpointAddr,
    treaty: TreatyDocument,
}

impl Sender {
    async fn connect(args: &Args) -> Result<Self, BoxError> {
        let loaded = load_role(args)?;
        let peers = peer_map(args)?;
        let receiver_addr =
            peer_address(&loaded.directory, &peers, &loaded.treaty.receiver_kernel_id)?;
        let endpoint = bind_endpoint(args, &loaded.secrets.transport_seed_hex, None).await?;
        Ok(Self {
            endpoint,
            receiver_addr,
            treaty: loaded.treaty,
        })
    }

    async fn exchange(&self, request: &ExperimentRequest) -> Result<ExperimentReply, BoxError> {
        experiment_exchange(&self.endpoint, self.receiver_addr.clone(), request).await
    }

    async fn prepare(&self) -> Result<PreparedCall, BoxError> {
        self.prepare_sharing(None).await
    }

    /// Mint one call's evidence. `continuation_sequence` names a continuation an
    /// earlier preparation already minted, which is how several calls come to
    /// present the same single-use identifier.
    async fn prepare_sharing(
        &self,
        continuation_sequence: Option<u64>,
    ) -> Result<PreparedCall, BoxError> {
        match self
            .exchange(&ExperimentRequest::Prepare {
                sequence: None,
                continuation_sequence,
            })
            .await?
        {
            ExperimentReply::Prepared(prepared) => Ok(*prepared),
            ExperimentReply::Refused { detail } => {
                Err(format!("the receiver refused to prepare a call: {detail}").into())
            }
            other => Err(format!("unexpected reply to prepare: {other:?}").into()),
        }
    }

    async fn stats(&self) -> Result<ReceiverStats, BoxError> {
        match self.exchange(&ExperimentRequest::Stats).await? {
            ExperimentReply::Stats(stats) => Ok(stats),
            other => Err(format!("unexpected reply to stats: {other:?}").into()),
        }
    }

    /// One measured call: the round trip is the request hop plus the receiver's
    /// whole admission decision, including the two co-sign hops it makes back to
    /// Org A on the admitted path.
    async fn call(&self, request: ToolCallRequest) -> Result<(CallDecision, f64), BoxError> {
        let started = Instant::now();
        let reply = self
            .exchange(&ExperimentRequest::Call {
                request: Box::new(request),
            })
            .await?;
        let round_trip_ms = started.elapsed().as_secs_f64() * 1_000.0;
        match reply {
            ExperimentReply::Decision(decision) => Ok((*decision, round_trip_ms)),
            ExperimentReply::Refused { detail } => {
                Err(format!("the receiver refused the call: {detail}").into())
            }
            other => Err(format!("unexpected reply to call: {other:?}").into()),
        }
    }

    /// The same request, dispatched by the receiver with the kernel out of the
    /// path. Same lane, same frame size, same tool: only the mediation is absent.
    async fn direct_call(&self, request: ToolCallRequest) -> Result<CallDecision, BoxError> {
        match self
            .exchange(&ExperimentRequest::DirectCall {
                request: Box::new(request),
            })
            .await?
        {
            ExperimentReply::Decision(decision) => Ok(*decision),
            ExperimentReply::Refused { detail } => {
                Err(format!("the receiver refused the unmediated call: {detail}").into())
            }
            other => Err(format!("unexpected reply to an unmediated call: {other:?}").into()),
        }
    }

    /// Author one request against the evidence the receiver says it holds. The
    /// scenario decides what the sender claims; the receiver decides what it
    /// believes.
    fn build_request(&self, prepared: &PreparedCall, scenario: Scenario) -> ToolCallRequest {
        let treaty = &self.treaty;
        let mut chio_treaty = serde_json::json!({
            "treatyScopeId": prepared.treaty_scope_id,
            "treatyScopeSha256": prepared.treaty_scope_sha256,
            "ladderIntersectionId": prepared.ladder_intersection_id,
            "ladderIntersectionSha256": prepared.ladder_intersection_sha256,
            "actionClassId": prepared.action_class_id,
            "crossKernelContinuation": {
                "id": prepared.continuation_id,
                "sha256": prepared.continuation_sha256
            },
            "receiptLineageBundle": {
                "id": prepared.lineage_bundle_id,
                "sha256": prepared.lineage_bundle_sha256
            },
            "bilateralInvocation": {
                "id": prepared.bilateral_invocation_id,
                "sha256": prepared.bilateral_invocation_sha256
            },
            "bilateralDsse": {
                "id": prepared.bilateral_dsse_id,
                "sha256": prepared.bilateral_dsse_sha256
            }
        });
        if let Some(object) = chio_treaty.as_object_mut() {
            match scenario.name {
                // A well-formed digest that names a scope the receiver does not
                // hold: the receiver resolves its own copy and refuses.
                "scope_hash_mismatch" => {
                    object.insert(
                        "treatyScopeSha256".to_string(),
                        serde_json::Value::String(sha256_hex(b"a treaty scope nobody issued")),
                    );
                }
                // The action class requires receipt lineage; a sender that omits
                // the reference does not get to skip the requirement.
                "missing_required_evidence" => {
                    object.remove("receiptLineageBundle");
                }
                // Trust carried in the request is not trust.
                "smuggled_trust_root" => {
                    object.insert(
                        "trustRoot".to_string(),
                        serde_json::json!({ "kernelId": treaty.origin_kernel_id }),
                    );
                }
                "smuggled_dynamic_trust" => {
                    object.insert(
                        "dynamicTrust".to_string(),
                        serde_json::json!({ "peerDiscovery": "https://example.invalid" }),
                    );
                }
                // The intersection the receiver holds under this id hashes to
                // something else, so the digest the sender cites is refused.
                "intersection_hash_mismatch" => {
                    object.insert(
                        "ladderIntersectionSha256".to_string(),
                        serde_json::Value::String(sha256_hex(
                            b"a ladder intersection nobody issued",
                        )),
                    );
                }
                // A scope id the receiver does not hold: there is nothing to
                // resolve, and a request cannot supply the scope itself.
                "unknown_treaty_scope" => {
                    object.insert(
                        "treatyScopeId".to_string(),
                        serde_json::Value::String("treaty:unissued:unissued".to_string()),
                    );
                }
                // The same for the ladder intersection the action class is
                // evaluated against.
                "unknown_ladder_intersection" => {
                    object.insert(
                        "ladderIntersectionId".to_string(),
                        serde_json::Value::String("intersection:unissued".to_string()),
                    );
                }
                _ => {}
            }
        }
        ToolCallRequest {
            request_id: prepared.request_id.clone(),
            capability: treaty.capability.clone(),
            tool_name: treaty.tool_name.clone(),
            server_id: treaty.server_id.clone(),
            agent_id: treaty.capability.subject.to_hex(),
            arguments: treaty.arguments.clone(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: format!("intent-{}", prepared.request_id),
                server_id: treaty.server_id.clone(),
                tool_name: treaty.tool_name.clone(),
                purpose: "cross-organization tool call over the federation lanes".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    "chioAdmission": {
                        "admissionId": prepared.admission_id,
                        "bundleSha256": prepared.admission_bundle_sha256
                    },
                    "chioTreaty": chio_treaty
                })),
                body: Default::default(),
            }),
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: Some(treaty.origin_kernel_id.clone()),
        }
    }

    /// One call end to end, including the untimed preparation.
    async fn drive_once(&self, scenario: Scenario) -> Result<CallSample, BoxError> {
        let prepared = self.prepare().await?;
        let request = self.build_request(&prepared, scenario);
        let (decision, round_trip_ms) = self.call(request).await?;
        Ok(CallSample {
            sequence: prepared.sequence,
            round_trip_ms,
            prepare_ms: prepared.prepare_micros as f64 / 1_000.0,
            // The hops this one call cost, measured at the co-signer rather than
            // read off the protocol: the preparation's DSSE hop plus whatever the
            // admission decision itself dialed.
            cosign_connections: decision
                .cosign_connections
                .saturating_sub(prepared.cosign_connections_before),
            decision,
        })
    }
}

struct CallSample {
    sequence: u64,
    round_trip_ms: f64,
    prepare_ms: f64,
    cosign_connections: u64,
    decision: CallDecision,
}

/// Drive `--calls` calls in `--scenario` and fail closed on any counter that
/// disagrees with the scenario: an admitted run must dispatch exactly once per
/// call, a denied run must not dispatch at all.
async fn run_send(args: &Args) -> Result<(), BoxError> {
    let scenario = scenario_named(args.value("scenario")?)?;
    let calls = args.count("calls", 30)?;
    if calls == 0 {
        return Err("--calls must be at least one".into());
    }
    let sender = Sender::connect(args).await?;
    let before = sender.stats().await?;

    let mut samples = Vec::new();
    let mut freshness_denials = 0_u64;
    let freshness_budget = calls.saturating_mul(4).max(20);
    while samples.len() < calls as usize {
        let sample = sender.drive_once(scenario).await?;
        // A freshness-window denial is the clock, not the treaty. Absorb it,
        // count it, and take the sample from the next call. It can arrive under
        // either verdict expectation, so it is classified before either is checked.
        if sample.decision.verdict == "deny"
            && classify(&sample.decision.failure_code) == DenialKind::Freshness
            && scenario.failure_code != sample.decision.failure_code
        {
            freshness_denials = freshness_denials.saturating_add(1);
            if freshness_denials > freshness_budget {
                return Err(format!(
                    "scenario {} absorbed {freshness_denials} revocation-freshness denials, \
                     which is more than the run allows",
                    scenario.name
                )
                .into());
            }
            continue;
        }
        if sample.decision.verdict != scenario.verdict {
            return Err(format!(
                "scenario {} expected a {} verdict, got {} ({})",
                scenario.name,
                scenario.verdict,
                sample.decision.verdict,
                sample.decision.failure_code
            )
            .into());
        }
        if !scenario.failure_code.is_empty()
            && sample.decision.failure_code != scenario.failure_code
        {
            return Err(format!(
                "scenario {} expected failure code {}, got {}",
                scenario.name, scenario.failure_code, sample.decision.failure_code
            )
            .into());
        }
        // This driver sends one call at a time, so the receiver's counters
        // describe this call alone. A decomposition that claims more time than
        // the window it decomposes is not describing this call, and the run stops
        // rather than report it.
        sample.decision.budget.check(&sample.decision.request_id)?;
        samples.push(sample);
    }
    let after = sender.stats().await?;

    let dispatched = after.dispatches.saturating_sub(before.dispatches);
    let expected_dispatched = if scenario.name == "allow" { calls } else { 0 };
    if dispatched != expected_dispatched {
        return Err(format!(
            "scenario {} moved the receiver's dispatch counter by {dispatched}, expected {expected_dispatched}",
            scenario.name
        )
        .into());
    }

    // Every call of one scenario costs the same co-sign hops, so a run in which
    // they differ is not measuring what it claims to and fails closed rather than
    // reporting an average.
    let cosign_connections: BTreeSet<u64> = samples
        .iter()
        .map(|sample| sample.cosign_connections)
        .collect();
    let cosign_connections_per_call = match (cosign_connections.first(), cosign_connections.last())
    {
        (Some(low), Some(high)) if low == high => *low,
        (Some(low), Some(high)) => {
            return Err(format!(
                "scenario {} cost between {low} and {high} co-sign connections per call; \
                 the per-call hop count is not a single observation",
                scenario.name
            )
            .into())
        }
        _ => return Err("no samples were collected".into()),
    };

    if let Some(path) = args.optional("csv") {
        let mut csv = format!(
            "scenario,sequence,request_id,round_trip_ms,evaluate_ms,prepare_ms,verdict,\
             failure_code,cosign_connections,{BUDGET_CSV_FIELDS}\n"
        );
        for sample in &samples {
            csv.push_str(&format!(
                "{},{},{},{:.6},{:.6},{:.6},{},{},{},{}\n",
                scenario.name,
                sample.sequence,
                sample.decision.request_id,
                sample.round_trip_ms,
                sample.decision.evaluate_micros as f64 / 1_000.0,
                sample.prepare_ms,
                sample.decision.verdict,
                sample.decision.failure_code,
                sample.cosign_connections,
                budget_csv_row(&sample.decision.budget),
            ));
        }
        fs::write(path, csv)?;
    }
    if let Some(path) = args.optional("out") {
        write_json(
            Path::new(path),
            &serde_json::json!({
                "scenario": scenario.name,
                "expectedVerdict": scenario.verdict,
                "expectedFailureCode": scenario.failure_code,
                "calls": calls,
                "dispatchesBefore": before.dispatches,
                "dispatchesAfter": after.dispatches,
                "dispatched": dispatched,
                "expectedDispatched": expected_dispatched,
                "freshnessDenialsAbsorbed": freshness_denials,
                "revocationEpochBefore": before.revocation_epoch,
                "revocationEpochAfter": after.revocation_epoch,
                "cosignConnectionsPerCall": cosign_connections_per_call,
                "cosignConnectionsBefore": before.cosign_connections,
                "cosignConnectionsAfter": after.cosign_connections,
                "admissionStore": after.admission_store,
                "budgetToleranceNanos": BUDGET_TOLERANCE_NANOS,
            }),
        )?;
    }
    println!(
        "scenario {} completed {calls} calls; receiver dispatched {dispatched}",
        scenario.name
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// baseline, load, race, preflight
// ---------------------------------------------------------------------------

/// The per-call decomposition columns, in the order [`budget_csv_row`] writes
/// them. Held in one place so the samples file and the aggregator cannot drift.
const BUDGET_CSV_FIELDS: &str = "cosign_connect_ms,cosign_exchange_ms,cosign_hops,\
store_resolve_ms,store_resolve_ops,continuation_ms,continuation_ops,lease_ms,lease_ops,\
trust_floor_ms,trust_floor_ops,dispatch_ms,dispatch_ops,receipt_append_ms,receipt_append_ops,\
receipt_other_ms,receipt_other_ops,revocation_ms,revocation_ops,admission_durable_ms,\
admission_durable_ops,tool_outcome_durable_ms,tool_outcome_durable_ops,attributed_ms,\
unattributed_ms";

fn millis(nanos: u64) -> f64 {
    nanos as f64 / 1_000_000.0
}

fn budget_csv_row(budget: &ReceiverBudget) -> String {
    format!(
        "{:.6},{:.6},{},{:.6},{},{:.6},{},{:.6},{},{:.6},{},{:.6},{},{:.6},{},{:.6},{},{:.6},{},\
         {:.6},{},{:.6},{},{:.6},{:.6}",
        millis(budget.cosign_connect_nanos),
        millis(budget.cosign_exchange_nanos),
        budget.cosign_hops,
        millis(budget.store_resolve_nanos),
        budget.store_resolve_ops,
        millis(budget.continuation_nanos),
        budget.continuation_ops,
        millis(budget.lease_nanos),
        budget.lease_ops,
        millis(budget.trust_floor_nanos),
        budget.trust_floor_ops,
        millis(budget.dispatch_nanos),
        budget.dispatch_ops,
        millis(budget.receipt_append_nanos),
        budget.receipt_append_ops,
        millis(budget.receipt_other_nanos),
        budget.receipt_other_ops,
        millis(budget.revocation_nanos),
        budget.revocation_ops,
        millis(budget.admission_durable_nanos),
        budget.admission_durable_ops,
        millis(budget.tool_outcome_durable_nanos),
        budget.tool_outcome_durable_ops,
        millis(budget.attributed_nanos),
        millis(budget.unattributed_nanos),
    )
}

/// The unmediated denominator: the same tool, over the same lane, with no kernel
/// in the path. Reported so the paper can state what mediation costs rather than
/// only what admission costs.
async fn run_baseline(args: &Args) -> Result<(), BoxError> {
    let calls = args.count("calls", 30)?;
    if calls < 2 {
        return Err("--calls must be at least two: a single call is not a distribution".into());
    }
    let sender = Sender::connect(args).await?;
    let before = sender.stats().await?;

    let mut samples = Vec::new();
    while samples.len() < calls as usize {
        let prepared = sender.prepare().await?;
        let request = sender.build_request(&prepared, scenario_named("allow")?);
        let started = Instant::now();
        let decision = sender.direct_call(request).await?;
        let round_trip_ms = started.elapsed().as_secs_f64() * 1_000.0;
        if decision.verdict != "allow" {
            return Err(
                format!("the unmediated tool call failed: {}", decision.failure_code).into(),
            );
        }
        decision.budget.check(&decision.request_id)?;
        samples.push((prepared.sequence, round_trip_ms, decision));
    }
    let after = sender.stats().await?;

    // The point of the baseline is that the kernel is not in the path, so the
    // mediated dispatch counter must not have moved at all.
    let mediated = after.dispatches.saturating_sub(before.dispatches);
    if mediated != 0 {
        return Err(format!(
            "the unmediated run moved the kernel's dispatch counter by {mediated}"
        )
        .into());
    }
    let unmediated = after
        .baseline_dispatches
        .saturating_sub(before.baseline_dispatches);
    if unmediated != calls {
        return Err(format!(
            "the unmediated run invoked the tool {unmediated} times, expected {calls}"
        )
        .into());
    }

    if let Some(path) = args.optional("csv") {
        let mut csv = format!(
            "scenario,sequence,request_id,round_trip_ms,evaluate_ms,prepare_ms,verdict,\
             failure_code,cosign_connections,{BUDGET_CSV_FIELDS}\n"
        );
        for (sequence, round_trip_ms, decision) in &samples {
            csv.push_str(&format!(
                "baseline,{sequence},{},{round_trip_ms:.6},{:.6},0.000000,{},{},0,{}\n",
                decision.request_id,
                decision.evaluate_micros as f64 / 1_000.0,
                decision.verdict,
                decision.failure_code,
                budget_csv_row(&decision.budget),
            ));
        }
        fs::write(path, csv)?;
    }
    if let Some(path) = args.optional("out") {
        write_json(
            Path::new(path),
            &serde_json::json!({
                "scenario": "baseline",
                "calls": calls,
                "mediatedDispatchDelta": mediated,
                "unmediatedDispatchDelta": unmediated,
                "admissionStore": after.admission_store,
            }),
        )?;
    }
    println!("baseline completed {calls} calls with the kernel out of the path");
    Ok(())
}

/// One completed call of a concurrent run.
struct ConcurrentSample {
    worker: u64,
    sequence: u64,
    round_trip_ms: f64,
    decision: CallDecision,
}

fn worker_count(args: &Args) -> Result<u64, BoxError> {
    let workers = args.count("workers", 8)?;
    if workers < 2 {
        return Err("--workers must be at least two: one worker is not concurrency".into());
    }
    if workers > MAX_CONCURRENT_CALLS {
        return Err(format!(
            "--workers is {workers}, above the experiment lane's per-peer accept cap of \
             {MAX_CONCURRENT_CALLS}; a larger run would measure the limiter shedding calls"
        )
        .into());
    }
    Ok(workers)
}

/// Sustained concurrent admitted calls.
///
/// Each worker drives its own calls end to end, so the receiver is evaluating
/// `--workers` admissions at once for the whole run. Throughput here is measured
/// against the wall clock of the whole run rather than derived from a latency,
/// which is the only way it can differ from one over the latency.
async fn run_load(args: &Args) -> Result<(), BoxError> {
    let workers = worker_count(args)?;
    let calls_per_worker = args.count("calls", 10)?;
    if calls_per_worker == 0 {
        return Err("--calls must be at least one".into());
    }
    let total = workers.saturating_mul(calls_per_worker);
    let sender = Arc::new(Sender::connect(args).await?);
    let before = sender.stats().await?;
    let freshness = Arc::new(AtomicU64::new(0));
    // Calls whose decomposition claims more time than the window it decomposes.
    // Under concurrency the receiver's counters serve several calls at once, so
    // this is expected to be nonzero: it is the reason no decomposition is
    // reported here, recorded rather than assumed.
    let contaminated = Arc::new(AtomicU64::new(0));
    let budget = total.saturating_mul(4).max(20);

    let started = Instant::now();
    let mut tasks = Vec::new();
    for worker in 0..workers {
        let sender = Arc::clone(&sender);
        let freshness = Arc::clone(&freshness);
        let contaminated = Arc::clone(&contaminated);
        tasks.push(tokio::spawn(async move {
            let mut mine = Vec::new();
            while (mine.len() as u64) < calls_per_worker {
                let sample = sender.drive_once(scenario_named("allow")?).await?;
                if sample.decision.verdict == "deny"
                    && classify(&sample.decision.failure_code) == DenialKind::Freshness
                {
                    if freshness.fetch_add(1, Ordering::SeqCst) >= budget {
                        return Err::<Vec<ConcurrentSample>, BoxError>(
                            format!(
                                "the concurrent run absorbed more than {budget} \
                                 revocation-freshness denials"
                            )
                            .into(),
                        );
                    }
                    continue;
                }
                if sample.decision.verdict != "allow" {
                    return Err(format!(
                        "a concurrent call was denied: {}",
                        sample.decision.failure_code
                    )
                    .into());
                }
                if sample
                    .decision
                    .budget
                    .check(&sample.decision.request_id)
                    .is_err()
                {
                    contaminated.fetch_add(1, Ordering::SeqCst);
                }
                mine.push(ConcurrentSample {
                    worker,
                    sequence: sample.sequence,
                    round_trip_ms: sample.round_trip_ms,
                    decision: sample.decision,
                });
            }
            Ok(mine)
        }));
    }
    let mut samples = Vec::new();
    for task in tasks {
        samples.extend(task.await??);
    }
    let wall_clock_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let after = sender.stats().await?;

    let dispatched = after.dispatches.saturating_sub(before.dispatches);
    if dispatched != total {
        return Err(format!(
            "the concurrent run dispatched {dispatched} times for {total} admitted calls"
        )
        .into());
    }
    samples.sort_by_key(|sample| sample.sequence);

    if let Some(path) = args.optional("csv") {
        let mut csv = String::from(
            "worker,sequence,request_id,round_trip_ms,evaluate_ms,verdict,failure_code\n",
        );
        for sample in &samples {
            csv.push_str(&format!(
                "{},{},{},{:.6},{:.6},{},{}\n",
                sample.worker,
                sample.sequence,
                sample.decision.request_id,
                sample.round_trip_ms,
                sample.decision.evaluate_micros as f64 / 1_000.0,
                sample.decision.verdict,
                sample.decision.failure_code,
            ));
        }
        fs::write(path, csv)?;
    }
    if let Some(path) = args.optional("out") {
        write_json(
            Path::new(path),
            &serde_json::json!({
                "workers": workers,
                "callsPerWorker": calls_per_worker,
                "calls": total,
                "wallClockMs": wall_clock_ms,
                "throughputCallsPerSecond": total as f64 / (wall_clock_ms / 1_000.0),
                "dispatched": dispatched,
                "freshnessDenialsAbsorbed": freshness.load(Ordering::SeqCst),
                "admissionStore": after.admission_store,
                // The decomposition is not reported here: the receiver's counters
                // are process-wide, so with several calls in flight a per-call
                // difference would attribute another call's work to this one.
                "budgetReported": false,
                "budgetContaminatedCalls": contaminated.load(Ordering::SeqCst),
            }),
        )?;
    }
    println!(
        "concurrent load completed {total} admitted calls at {workers} in flight in {wall_clock_ms:.1} ms"
    );
    Ok(())
}

/// One round of the continuation race.
struct RaceRound {
    admitted: Vec<u64>,
    denied: BTreeMap<u64, String>,
    latencies: Vec<(u64, f64)>,
}

/// N calls presenting the SAME single-use continuation, all in flight at once.
///
/// Each racer carries its own admission bundle, lease, lineage bundle, bilateral
/// invocation and DSSE envelope; the one thing they share is the continuation
/// identifier. Exactly one may be admitted, and the receiver's dispatch counter
/// must move by exactly one per round.
async fn run_race(args: &Args) -> Result<(), BoxError> {
    let workers = worker_count(args)?;
    let repeats = args.count("repeats", 10)?;
    if repeats < 2 {
        return Err("--repeats must be at least two: one round is not a distribution".into());
    }
    let sender = Arc::new(Sender::connect(args).await?);
    let before = sender.stats().await?;
    let mut rounds = Vec::new();
    let mut freshness_denials = 0_u64;
    // Rounds thrown away whole because a racer hit a revocation-freshness denial.
    // A discarded round is one whose latencies are not in the reported
    // distributions, so the count is reported beside them: the distributions are
    // conditioned on rounds that saw no freshness denial.
    let mut discarded_rounds = 0_u64;
    let freshness_budget = repeats.saturating_mul(4).max(20);

    while (rounds.len() as u64) < repeats {
        // One continuation, and one prepared call per racer that names it.
        let first = sender.prepare().await?;
        let shared = first.continuation_sequence;
        let mut prepared = vec![first];
        while (prepared.len() as u64) < workers {
            prepared.push(sender.prepare_sharing(Some(shared)).await?);
        }

        // The dispatch counter is read around each round rather than around the
        // whole run. A round the freshness rule discards still dispatched for
        // whichever racer won it, so a delta taken across the run counts those
        // dispatches while the round itself is not kept, and the two disagree by
        // exactly the number of rounds discarded.
        let round_before = sender.stats().await?;
        let mut tasks = Vec::new();
        for (worker, prepared) in prepared.into_iter().enumerate() {
            let sender = Arc::clone(&sender);
            let worker = worker as u64;
            tasks.push(tokio::spawn(async move {
                let request = sender.build_request(&prepared, scenario_named("allow")?);
                let started = Instant::now();
                let (decision, round_trip_ms) = sender.call(request).await?;
                let _ = started;
                Ok::<_, BoxError>((worker, decision, round_trip_ms))
            }));
        }
        let mut round = RaceRound {
            admitted: Vec::new(),
            denied: BTreeMap::new(),
            latencies: Vec::new(),
        };
        let mut freshness_in_round = 0_u64;
        for task in tasks {
            let (worker, decision, round_trip_ms) = task.await??;
            round.latencies.push((worker, round_trip_ms));
            if decision.verdict == "allow" {
                round.admitted.push(worker);
            } else {
                if classify(&decision.failure_code) == DenialKind::Freshness {
                    freshness_in_round = freshness_in_round.saturating_add(1);
                }
                round.denied.insert(worker, decision.failure_code);
            }
        }
        let round_dispatched = sender
            .stats()
            .await?
            .dispatches
            .saturating_sub(round_before.dispatches);

        // A revocation-freshness denial is the clock rather than the continuation:
        // it would take a racer out of the race for a reason the round is not
        // about, so the whole round is discarded and run again. The single-use
        // property still holds over a discarded round: the clock can deny the
        // racer that would have won, never admit a second one.
        if freshness_in_round > 0 {
            if round_dispatched > 1 {
                return Err(format!(
                    "a discarded round dispatched {round_dispatched} times; one                      continuation admits at most once whether or not the round counts"
                )
                .into());
            }
            freshness_denials = freshness_denials.saturating_add(freshness_in_round);
            discarded_rounds = discarded_rounds.saturating_add(1);
            if freshness_denials > freshness_budget {
                return Err(format!(
                    "the contention run absorbed {freshness_denials} revocation-freshness \
                     denials, which is more than it allows"
                )
                .into());
            }
            continue;
        }
        if round.admitted.len() != 1 {
            return Err(format!(
                "{} of {workers} calls presenting one continuation were admitted; \
                 exactly one may be",
                round.admitted.len()
            )
            .into());
        }
        if round_dispatched != 1 {
            return Err(format!(
                "a round of {workers} racers on one continuation dispatched                  {round_dispatched} times; exactly one dispatch per round is the                  whole property"
            )
            .into());
        }
        for (worker, failure_code) in &round.denied {
            if failure_code != CONTINUATION_REPLAY_CODE {
                return Err(format!(
                    "racer {worker} lost the continuation race with failure code \
                     {failure_code}, not {CONTINUATION_REPLAY_CODE}"
                )
                .into());
            }
        }
        rounds.push(round);
    }
    let after = sender.stats().await?;

    // Every round is asserted above to have dispatched exactly once when it is
    // kept and at most once when it is discarded, so the run's own total may
    // only sit between the rounds kept and the rounds attempted.
    let dispatched = after.dispatches.saturating_sub(before.dispatches);
    let attempted = repeats.saturating_add(discarded_rounds);
    if dispatched < repeats || dispatched > attempted {
        return Err(format!(
            "{workers} racers over {repeats} kept rounds and {discarded_rounds} \
             discarded dispatched {dispatched} times, which is outside \
             {repeats} to {attempted}"
        )
        .into());
    }

    let mut winners: BTreeMap<u64, u64> = BTreeMap::new();
    let mut winner_latencies = Vec::new();
    let mut loser_latencies = Vec::new();
    for round in &rounds {
        let Some(winner) = round.admitted.first().copied() else {
            return Err("a recorded round has no winner".into());
        };
        *winners.entry(winner).or_default() += 1;
        for (worker, latency) in &round.latencies {
            if *worker == winner {
                winner_latencies.push(*latency);
            } else {
                loser_latencies.push(*latency);
            }
        }
    }

    if let Some(path) = args.optional("csv") {
        let mut csv = String::from("round,worker,outcome,round_trip_ms\n");
        for (index, round) in rounds.iter().enumerate() {
            for (worker, latency) in &round.latencies {
                let outcome = if round.admitted.contains(worker) {
                    "admitted"
                } else {
                    "replayed"
                };
                csv.push_str(&format!("{index},{worker},{outcome},{latency:.6}\n"));
            }
        }
        fs::write(path, csv)?;
    }
    if let Some(path) = args.optional("out") {
        write_json(
            Path::new(path),
            &serde_json::json!({
                "workers": workers,
                "rounds": rounds.len(),
                "dispatched": dispatched,
                "expectedDispatched": repeats,
                "replayFailureCode": CONTINUATION_REPLAY_CODE,
                "winnersByWorker": winners,
                "winnerLatenciesMs": winner_latencies,
                "loserLatenciesMs": loser_latencies,
                "freshnessDenialsAbsorbed": freshness_denials,
                "roundsDiscarded": discarded_rounds,
                "roundsAttempted": rounds.len() as u64 + discarded_rounds,
                "admissionStore": after.admission_store,
            }),
        )?;
    }
    println!(
        "continuation race: {workers} racers over {} rounds admitted exactly one each \
         ({discarded_rounds} rounds discarded)",
        rounds.len()
    );
    Ok(())
}

/// What one probed host's clock looked like from here.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClockReading {
    kernel_id: String,
    address: String,
    samples: u64,
    offset_ms: i64,
    /// Half the round trip of the sample the offset was read from: the estimate
    /// cannot be tighter than this.
    uncertainty_ms: u64,
    min_round_trip_ms: u64,
}

/// Refuse to measure a split run whose two hosts disagree about the time.
///
/// Reachability and clock agreement are the two things a one-host run never has
/// to establish and a two-host run always does. The receiving kernel reads its
/// clock in whole seconds and holds its revocation snapshot to a sub-second
/// freshness bound, so a clock offset above the bound does not degrade the
/// measurement, it changes which calls are admitted.
async fn run_preflight(args: &Args) -> Result<(), BoxError> {
    let loaded = load_role(args)?;
    let peers = peer_map(args)?;
    let targets = args.values("target");
    if targets.is_empty() {
        return Err("--target names the kernel id of a host to probe; give at least one".into());
    }
    let samples = args.count("samples", 8)?;
    if samples == 0 {
        return Err("--samples must be at least one".into());
    }
    let max_offset_ms = args.count("max-offset-ms", DEFAULT_MAX_CLOCK_OFFSET_MS)?;
    let endpoint = bind_endpoint(args, &loaded.secrets.transport_seed_hex, None).await?;

    let mut readings = Vec::new();
    let mut refusals = Vec::new();
    for target in targets {
        let address = peer_address(&loaded.directory, &peers, target)?;
        let mut best: Option<(i64, u64)> = None;
        for _ in 0..samples {
            // A probe that cannot connect is a reachability failure, which is the
            // first thing preflight is for.
            let (offset_ms, round_trip) = probe_clock(&endpoint, address.clone(), target)
                .await
                .map_err(|error| format!("{target} did not answer a clock probe: {error}"))?;
            // The tightest estimate is the one from the fastest exchange: the
            // error in the midpoint is bounded by half the round trip.
            if best.is_none_or(|(_, best_round_trip)| round_trip < best_round_trip) {
                best = Some((offset_ms, round_trip));
            }
        }
        let Some((offset_ms, round_trip)) = best else {
            return Err(format!("no clock probe of {target} completed").into());
        };
        let uncertainty_ms = round_trip / 2;
        readings.push(ClockReading {
            kernel_id: target.clone(),
            address: address
                .ip_addrs()
                .map(|socket| socket.to_string())
                .collect::<Vec<_>>()
                .join(","),
            samples,
            offset_ms,
            uncertainty_ms,
            min_round_trip_ms: round_trip,
        });
        if offset_ms.unsigned_abs() > max_offset_ms {
            refusals.push(format!(
                "{target}'s clock is {offset_ms} ms from this host's, beyond the \
                 {max_offset_ms} ms bound"
            ));
        }
        if uncertainty_ms > max_offset_ms {
            refusals.push(format!(
                "the path to {target} has a {round_trip} ms round trip, so a \
                 {max_offset_ms} ms offset bound cannot be established over it"
            ));
        }
    }

    if let Some(path) = args.optional("out") {
        write_json(
            Path::new(path),
            &serde_json::json!({
                "schema": "chio.experiment.federated-pair-preflight.v1",
                "maxOffsetMs": max_offset_ms,
                "samplesPerTarget": samples,
                "readings": readings,
                "refusals": refusals,
                "admitted": refusals.is_empty(),
            }),
        )?;
    }
    if !refusals.is_empty() {
        return Err(refusals.join("; ").into());
    }
    for reading in &readings {
        println!(
            "preflight: {} answered {} probes, clock offset {} ms (+/- {} ms)",
            reading.kernel_id, reading.samples, reading.offset_ms, reading.uncertainty_ms
        );
    }
    Ok(())
}

/// One flip of the receiver's answer, and what it cost to observe.
struct Flip {
    elapsed_ms: f64,
    calls: u64,
    failure_code: String,
    freshness_denials: u64,
}

/// Poll the receiver with allow-shaped calls until it denies for `want`, and
/// report how long the flip took. A freshness-window denial is the clock rather
/// than the answer being waited for, so it is counted and polled past.
async fn poll_until_denial(
    sender: &Sender,
    want: DenialKind,
    started: Instant,
    timeout: Duration,
) -> Result<Flip, BoxError> {
    let allow = scenario_named("allow")?;
    let mut calls = 0_u64;
    let mut freshness_denials = 0_u64;
    loop {
        calls = calls.saturating_add(1);
        let sample = sender.drive_once(allow).await?;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
        if sample.decision.verdict == "deny" {
            let kind = classify(&sample.decision.failure_code);
            if kind == want {
                return Ok(Flip {
                    elapsed_ms,
                    calls,
                    failure_code: sample.decision.failure_code,
                    freshness_denials,
                });
            }
            if kind == DenialKind::Freshness {
                freshness_denials = freshness_denials.saturating_add(1);
            } else {
                return Err(format!(
                    "the receiver denied with an unexpected reason while waiting: {}",
                    sample.decision.failure_code
                )
                .into());
            }
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "the receiver never produced the expected denial within {} ms",
                timeout.as_millis()
            )
            .into());
        }
    }
}

/// Poll until the receiver admits again, so the next measurement starts from a
/// known state.
async fn poll_until_allow(
    sender: &Sender,
    started: Instant,
    timeout: Duration,
) -> Result<Flip, BoxError> {
    let allow = scenario_named("allow")?;
    let mut calls = 0_u64;
    let mut freshness_denials = 0_u64;
    loop {
        calls = calls.saturating_add(1);
        let sample = sender.drive_once(allow).await?;
        if sample.decision.verdict == "allow" {
            return Ok(Flip {
                elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
                calls,
                failure_code: String::new(),
                freshness_denials,
            });
        }
        if classify(&sample.decision.failure_code) == DenialKind::Freshness {
            freshness_denials = freshness_denials.saturating_add(1);
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "the receiver never admitted again within {} ms (last: {})",
                timeout.as_millis(),
                sample.decision.failure_code
            )
            .into());
        }
    }
}

/// Confirm that a freshness denial is the cut link rather than the per-second
/// clock artefact: a cut denies every call from here on, the artefact does not.
async fn denial_persists(sender: &Sender, confirmations: u32) -> Result<bool, BoxError> {
    let allow = scenario_named("allow")?;
    for _ in 0..confirmations {
        let sample = sender.drive_once(allow).await?;
        if sample.decision.verdict != "deny" {
            return Ok(false);
        }
        if classify(&sample.decision.failure_code) != DenialKind::Freshness {
            return Ok(false);
        }
    }
    Ok(true)
}

fn write_control(path: &Path, control: &ControlDocument) -> Result<(), BoxError> {
    write_json(
        path,
        &ControlDocument {
            schema: CONTROL_SCHEMA.to_string(),
            ..control.clone()
        },
    )
}

/// Confirm the path is admitting before a measurement, so the flip that follows
/// is the mechanism under test and not a warm-up artefact.
async fn require_admitting(sender: &Sender, what: &str) -> Result<(), BoxError> {
    let started = Instant::now();
    poll_until_allow(sender, started, Duration::from_secs(15))
        .await
        .map_err(|error| format!("the receiver was not admitting before the {what}: {error}"))?;
    Ok(())
}

/// One repeat of a flip measurement, kept as a distribution rather than a single
/// observation: the answer is polled, so one sample carries a whole poll of
/// resolution and a whole control-file poll period of origin-side latency.
#[derive(Debug, Default)]
struct FlipSeries {
    elapsed_ms: Vec<f64>,
    calls: Vec<u64>,
    recovery_ms: Vec<f64>,
    freshness_denials: u64,
    /// Every distinct denial message observed. All repeats denied for the same
    /// reason by construction (the poll only stops on the `DenialKind` it was
    /// asked for), but the kernel's message carries per-call identifiers, so the
    /// artifact keeps the set rather than pretending to one string.
    failure_codes: BTreeSet<String>,
}

impl FlipSeries {
    fn record(&mut self, flip: &Flip, recovery: &Flip) {
        self.failure_codes.insert(flip.failure_code.clone());
        self.elapsed_ms.push(flip.elapsed_ms);
        self.calls.push(flip.calls);
        self.recovery_ms.push(recovery.elapsed_ms);
        self.freshness_denials = self
            .freshness_denials
            .saturating_add(flip.freshness_denials)
            .saturating_add(recovery.freshness_denials);
    }

    fn median(&self) -> f64 {
        let mut ordered = self.elapsed_ms.clone();
        ordered.sort_by(f64::total_cmp);
        ordered.get(ordered.len() / 2).copied().unwrap_or_default()
    }
}

fn repeat_count(args: &Args) -> Result<u64, BoxError> {
    let repeats = args.count("repeats", 1)?;
    if repeats == 0 {
        return Err("--repeats must be at least one".into());
    }
    Ok(repeats)
}

/// Revoke a capability at Org A and measure how long the receiver keeps
/// admitting it. The revocation never touches the receiver's disk: it travels as
/// a signed epoch root on lane b plus Org A's signed leaf announcement.
///
/// The clock starts when the control document is written and stops at the first
/// observing call, so each sample includes up to one origin control-poll period
/// (the epoch tick) and one call of polling resolution. `--repeats` turns that
/// into a distribution instead of a single number.
async fn run_revoke(args: &Args) -> Result<(), BoxError> {
    let sender = Sender::connect(args).await?;
    let capability_id = args
        .optional("capability-id")
        .unwrap_or(&sender.treaty.capability_id)
        .to_string();
    let control_path = args.path("control")?;
    let timeout = Duration::from_millis(args.count("timeout-ms", 30_000)?);
    let repeats = repeat_count(args)?;

    let mut series = FlipSeries::default();
    for _ in 0..repeats {
        require_admitting(&sender, "revoke").await?;
        let started = Instant::now();
        write_control(
            &control_path,
            &ControlDocument {
                schema: CONTROL_SCHEMA.to_string(),
                cut: false,
                revoked_capability_ids: vec![capability_id.clone()],
            },
        )?;
        let flip = poll_until_denial(&sender, DenialKind::Revoked, started, timeout).await?;

        // Put the treaty back so the next repeat, and any later measurement,
        // starts from an admitting state.
        write_control(&control_path, &ControlDocument::default())?;
        let recovery = poll_until_allow(&sender, Instant::now(), timeout).await?;
        series.record(&flip, &recovery);
    }

    let stats = sender.stats().await?;
    let document = serde_json::json!({
        "capabilityId": capability_id,
        "repeats": repeats,
        "samplesMs": series.elapsed_ms,
        "callsUntilDeny": series.calls,
        "recoveryToAllowMs": series.recovery_ms,
        "failureCodes": series.failure_codes,
        "freshnessDenialsAbsorbed": series.freshness_denials,
        "revocationEpoch": stats.revocation_epoch,
    });
    if let Some(path) = args.optional("out") {
        write_json(Path::new(path), &document)?;
    }
    println!(
        "revoke to first denial: {:.3} ms median over {repeats} repeats",
        series.median()
    );
    Ok(())
}

/// Stop Org A's revocation clock and measure how long the receiver keeps
/// admitting on the last root it holds. The bound is the kernel's own freshness
/// window, so the answer is a property of the receiver, not of the link.
async fn run_cut(args: &Args) -> Result<(), BoxError> {
    let sender = Sender::connect(args).await?;
    let control_path = args.path("control")?;
    let timeout = Duration::from_millis(args.count("timeout-ms", 30_000)?);
    let confirmations = u32::try_from(args.count("cut-confirmations", 3)?)?;
    let repeats = repeat_count(args)?;

    let mut series = FlipSeries::default();
    for _ in 0..repeats {
        require_admitting(&sender, "cut").await?;
        let started = Instant::now();
        write_control(
            &control_path,
            &ControlDocument {
                schema: CONTROL_SCHEMA.to_string(),
                cut: true,
                revoked_capability_ids: Vec::new(),
            },
        )?;
        // The first freshness denial only counts once it proves permanent: the
        // per-second clock artefact produces one and then admits again.
        let mut absorbed = 0_u64;
        let flip = loop {
            let candidate =
                poll_until_denial(&sender, DenialKind::Freshness, started, timeout).await?;
            absorbed = absorbed.saturating_add(candidate.freshness_denials);
            if denial_persists(&sender, confirmations).await? {
                break Flip {
                    freshness_denials: absorbed,
                    ..candidate
                };
            }
            absorbed = absorbed.saturating_add(1);
            if started.elapsed() > timeout {
                return Err("the receiver never stopped admitting after the cut".into());
            }
        };

        write_control(&control_path, &ControlDocument::default())?;
        let recovery = poll_until_allow(&sender, Instant::now(), timeout).await?;
        series.record(&flip, &recovery);
    }

    let document = serde_json::json!({
        "repeats": repeats,
        "samplesMs": series.elapsed_ms,
        "callsUntilDeny": series.calls,
        "recoveryToAllowMs": series.recovery_ms,
        "failureCodes": series.failure_codes,
        "confirmations": confirmations,
        "freshnessDenialsAbsorbed": series.freshness_denials,
    });
    if let Some(path) = args.optional("out") {
        write_json(Path::new(path), &document)?;
    }
    println!(
        "cut to first denial: {:.3} ms median over {repeats} repeats",
        series.median()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const USAGE: &str = "\
usage: federated_call_pair <subcommand> [--flag value ...]

  keygen    --kernel-id ID --dir DIR
  directory --issuer-dir DIR --public FILE [--public FILE ...] --out-dir DIR
            --origin-kernel-id ID --receiver-kernel-id ID --sender-kernel-id ID
  origin    --dir DIR --directory FILE --trust FILE --treaty FILE
            --bind HOST:PORT --peer RECEIVER=HOST:PORT
            --handshake-out FILE --control FILE [--tick-ms MS]
            [--epoch-rate-out FILE]
  receiver  --dir DIR --directory FILE --trust FILE --treaty FILE
            --bind HOST:PORT --peer ORIGIN=HOST:PORT
            --handshake FILE --store-dir DIR --ready-out FILE
            [--admission-store sqlite|memory]
  send      --dir DIR --directory FILE --trust FILE --treaty FILE
            --bind HOST:PORT --peer RECEIVER=HOST:PORT
            --scenario NAME --calls N [--csv FILE] [--out FILE]
  baseline  (send flags) --calls N [--csv FILE] [--out FILE]
  load      (send flags) --workers N --calls N [--csv FILE] [--out FILE]
  race      (send flags) --workers N [--repeats N] [--csv FILE] [--out FILE]
  preflight (send flags) --target KERNEL_ID [--target KERNEL_ID]
            [--samples N] [--max-offset-ms N] [--out FILE]
  revoke    (send flags) --control FILE [--capability-id ID] [--repeats N]
            [--out FILE]
  cut       (send flags) --control FILE [--repeats N] [--out FILE]
";

fn main() -> Result<(), BoxError> {
    let mut argv = std::env::args().skip(1);
    let Some(subcommand) = argv.next() else {
        eprint!("{USAGE}");
        std::process::exit(2);
    };
    let args = Args::parse(argv)?;

    if subcommand == "keygen" {
        return run_keygen(&args);
    }
    if subcommand == "directory" {
        return run_directory(&args);
    }

    // Every networked role needs a multi-threaded runtime: the receiver's kernel
    // makes its co-sign hops from inside `evaluate_tool_call`, and the blocking
    // bridge that drives them is unsupported on a current-thread runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        // The receiver runs the whole kernel evaluation, and the co-sign hop it
        // makes part way through blocks on a QUIC round trip from the same stack.
        // The default worker stack is not enough for that depth in a debug build.
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        match subcommand.as_str() {
            "origin" => run_origin(&args).await,
            "receiver" => run_receiver(&args).await,
            "send" => run_send(&args).await,
            "baseline" => run_baseline(&args).await,
            "load" => run_load(&args).await,
            "race" => run_race(&args).await,
            "preflight" => run_preflight(&args).await,
            "revoke" => run_revoke(&args).await,
            "cut" => run_cut(&args).await,
            other => Err(format!("unknown subcommand {other}\n{USAGE}").into()),
        }
    })
}
