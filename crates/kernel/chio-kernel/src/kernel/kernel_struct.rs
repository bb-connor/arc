use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::*;

/// Configuration for the Chio Runtime Kernel.
pub struct KernelConfig {
    /// Ed25519 keypair for signing receipts and issuing capabilities.
    pub keypair: Keypair,

    /// Public keys of trusted Capability Authorities.
    pub ca_public_keys: Vec<chio_core::PublicKey>,

    /// Maximum allowed delegation depth.
    pub max_delegation_depth: u32,

    /// SHA-256 hash of the active policy (embedded in receipts).
    pub policy_hash: String,

    /// Whether nested sampling requests are allowed at all.
    pub allow_sampling: bool,

    /// Whether sampling requests may include tool-use affordances.
    pub allow_sampling_tool_use: bool,

    /// Whether nested elicitation requests are allowed.
    pub allow_elicitation: bool,

    /// Maximum total wall-clock duration permitted for one streamed tool result.
    pub max_stream_duration_secs: u64,

    /// Maximum total canonical payload size permitted for one streamed tool result.
    pub max_stream_total_bytes: u64,

    /// Whether durable receipts and kernel-signed checkpoints are mandatory
    /// prerequisites for this deployment.
    pub require_web3_evidence: bool,

    /// Allow process-local receipt logs when no durable receipt store is
    /// installed. This is for tests and local scaffolds only; protocol
    /// deployments should leave it false so successful dispatch requires
    /// durable receipt persistence before any tool side effect.
    pub allow_ephemeral_receipt_log: bool,

    /// Number of receipts between Merkle checkpoint snapshots. Default: 100.
    ///
    /// Set to 0 to disable automatic checkpointing for deployments that do not
    /// require web3 evidence.
    pub checkpoint_batch_size: u64,

    /// Optional receipt retention configuration.
    ///
    /// When `None` (default), retention is disabled and receipts accumulate
    /// indefinitely. When `Some(config)`, the kernel will archive receipts
    /// that exceed the time or size threshold.
    pub retention_config: Option<crate::receipt_store::RetentionConfig>,

    /// Per-process memory budget (bounded-structure caps + RSS soft ceiling).
    pub memory_budget: MemoryBudgetConfig,
}

impl KernelConfig {
    pub(crate) fn memory_budget_receipt_mirror_capacity(&self) -> usize {
        self.memory_budget.receipt_mirror_capacity
    }
    pub(crate) fn memory_budget_federation_cache_capacity(&self) -> usize {
        self.memory_budget.federation_cache_capacity
    }
    pub(crate) fn memory_budget_federation_cache_idle_ttl_secs(&self) -> u64 {
        self.memory_budget.federation_cache_idle_ttl_secs
    }
}

/// Boot-time configuration for the kernel-side hybrid signing path.
///
/// Mirrors the wire form of `chio_policy::CryptoFloor` (`allow_classical`,
/// `allow_hybrid`, `pq_required`) and pairs the floor with the operator's
/// 32-byte ML-DSA-65 keygen seed. Construct one of these from a parsed
/// HushSpec policy plus the boot-loaded PQ seed and pass it to
/// [`ChioKernel::with_hybrid_signing_backend`] with a verified self-quote
/// port to obtain a `Box<dyn SigningBackend>` for hybrid receipt signing.
///
/// A separate input from [`KernelConfig`]: the hybrid fields are not folded
/// into `KernelConfig`, so its wire form is unaffected.
#[derive(Debug, Clone, Default)]
pub struct HybridSigningConfig {
    /// Minimum cryptographic posture enforced on receipts, capability
    /// tokens, and compliance certificates. Default
    /// [`KernelCryptoFloor::AllowClassical`].
    pub crypto_floor: KernelCryptoFloor,

    /// Optional 32-byte ML-DSA-65 keygen seed. Required when
    /// `crypto_floor` is [`KernelCryptoFloor::AllowHybrid`] or
    /// [`KernelCryptoFloor::PqRequired`]; ignored under
    /// [`KernelCryptoFloor::AllowClassical`].
    pub pq_signing_seed: Option<[u8; 32]>,
}

pub(crate) fn capability_crypto_floor(
    floor: KernelCryptoFloor,
) -> chio_core::capability::crypto_floor::CapabilityCryptoFloor {
    match floor {
        KernelCryptoFloor::AllowClassical => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::AllowClassical
        }
        KernelCryptoFloor::AllowHybrid => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::AllowHybrid
        }
        KernelCryptoFloor::PqRequired => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::PqRequired
        }
    }
}

pub(crate) fn receipt_crypto_floor(
    floor: KernelCryptoFloor,
) -> chio_core::receipt::crypto_floor::ReceiptCryptoFloor {
    match floor {
        KernelCryptoFloor::AllowClassical => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical
        }
        KernelCryptoFloor::AllowHybrid => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowHybrid
        }
        KernelCryptoFloor::PqRequired => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
        }
    }
}

pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 300;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Default cap on the number of chunks RETAINED from one streamed tool result.
/// Bounds the accumulator `Vec<ToolCallChunk>` length and the per-chunk
/// receipt-signing preimage even when every chunk is tiny and the byte cap is
/// never reached. Generous for legitimate streams; `0` disables the cap.
pub const DEFAULT_MAX_STREAM_CHUNKS: u64 = 1_048_576;
pub const DEFAULT_CHECKPOINT_BATCH_SIZE: u64 = 100;
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10_737_418_240;

/// Per-process memory budget: bounded-structure capacities plus a process RSS
/// soft ceiling. The soft ceiling is the in-process analog of the cgroup hard
/// limit: the kernel sheds (Overloaded) before the OS OOM-kills it.
#[derive(Debug, Clone)]
pub struct MemoryBudgetConfig {
    pub receipt_mirror_capacity: usize,
    pub federation_cache_capacity: usize,
    pub federation_cache_idle_ttl_secs: u64,
    pub velocity_bucket_cap: usize,
    pub admission_key_cap: usize,
    pub journal_entry_cap: usize,
    /// Max number of chunks retained from one streamed tool result. Bounds the
    /// retained `Vec<ToolCallChunk>` and the per-chunk signing preimage so a flood
    /// of tiny chunks that never trips `max_stream_total_bytes` still cannot grow
    /// memory without bound. `0` disables the cap.
    pub max_stream_chunks: u64,
    /// Max number of DISTINCT tool names retained in each session journal's
    /// cumulative `tool_counts` map. Unlike the `entries` and
    /// `tool_sequence` rings, `tool_counts` is cumulative (it survives ring
    /// eviction so the behavioral-sequence guard can answer "was this tool ever
    /// invoked"), so a ring cannot bound it. Once a session reaches this many
    /// distinct tool names a previously-unseen name is dropped fail-closed: a
    /// dependent required-predecessor check then treats it as never-invoked and
    /// denies. Sized well above any legitimate (registry-bounded) tool set.
    pub journal_tool_counts_cap: usize,
    /// Process RSS soft ceiling in bytes. When set and exceeded, new admissions
    /// shed with Overloaded { Allocation }. Set to roughly 85-90% of the cgroup
    /// memory.max so the graceful stop fires before the kill. Stage A ships None.
    pub rss_soft_limit_bytes: Option<u64>,
    /// How often the RSS sampler reads /proc/self/statm.
    pub rss_sample_interval_secs: u64,
}

impl MemoryBudgetConfig {
    pub fn defaults() -> Self {
        Self {
            receipt_mirror_capacity: 4096,
            federation_cache_capacity: 8192,
            federation_cache_idle_ttl_secs: 3600,
            velocity_bucket_cap: 65_536,
            admission_key_cap: 4096,
            journal_entry_cap: 4096,
            max_stream_chunks: DEFAULT_MAX_STREAM_CHUNKS,
            journal_tool_counts_cap: 4096,
            rss_soft_limit_bytes: None,
            rss_sample_interval_secs: 30,
        }
    }
}

impl Default for MemoryBudgetConfig {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Owns the RSS sampler thread; signals stop and joins on drop. On non-Linux
/// hosts the sampler is a no-op and the soft limit is inert (cgroup and
/// try_reserve backstops still apply).
pub(crate) struct RssSamplerHandle {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl RssSamplerHandle {
    pub(crate) fn spawn(shed: Arc<AtomicBool>, soft_limit_bytes: u64, interval_secs: u64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let interval = std::time::Duration::from_secs(interval_secs.max(1));
        let join = std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !worker_stop.load(Ordering::SeqCst) {
                if let Some(rss) = read_process_rss_bytes() {
                    shed.store(rss > soft_limit_bytes, Ordering::Relaxed);
                }
                let mut waited = std::time::Duration::ZERO;
                let slice = std::time::Duration::from_millis(200);
                while waited < interval && !worker_stop.load(Ordering::SeqCst) {
                    std::thread::sleep(slice);
                    waited += slice;
                }
            }
        });
        Self {
            stop,
            join: Some(join),
        }
    }
}

impl Drop for RssSamplerHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn read_process_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(resident_pages.saturating_mul(linux_page_size()))
}

/// Real system page size in bytes, read once via `sysconf(_SC_PAGESIZE)` and
/// cached. Hosts with non-4-KiB pages (for example common 64-KiB-page ARM
/// deployments) would otherwise undercount RSS by the page-size ratio and shed
/// far past the configured soft ceiling. Falls back to 4096 only if the query
/// fails.
#[cfg(target_os = "linux")]
fn linux_page_size() -> u64 {
    use std::sync::OnceLock;
    static PAGE_SIZE: OnceLock<u64> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: `sysconf` with a compile-time constant name has no
        // preconditions; it returns the configured page size, or -1 on failure.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if raw > 0 {
            raw as u64
        } else {
            4096
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn read_process_rss_bytes() -> Option<u64> {
    None
}

/// The Chio Runtime Kernel.
///
/// This is the central component of the Chio protocol. It validates capabilities,
/// runs guards, dispatches tool calls, and signs receipts.
///
/// The kernel is designed to be the sole trusted mediator. It never exposes its
/// signing key, address, or internal state to the agent.
pub struct ChioKernel {
    pub(super) config: KernelConfig,
    pub(super) guards: Vec<Box<dyn Guard>>,
    pub(super) post_invocation_pipeline: crate::post_invocation::PostInvocationPipeline,
    pub(super) budget_store: Arc<dyn BudgetStore>,
    pub(super) budget_store_lock: Mutex<()>,
    /// Optional Phase-0 free-tier compute pool (M0 Pass CONTROL 1). When set,
    /// every private-use (free-tier) per-Pass charge also debits one aggregate
    /// `freetier:global:<YYYY-MM>` budget row, capping liability at
    /// `min(N x allotment, pool)`. `None` keeps the kernel pool-free.
    pub(super) free_tier_pool: Option<FreeTierPoolConfig>,
    pub(super) revocation_store: Arc<dyn RevocationStore>,
    pub(super) capability_authority: Box<dyn CapabilityAuthority>,
    pub(super) tool_servers: HashMap<ServerId, Box<dyn ToolServerConnection>>,
    pub(super) resource_providers: Vec<Box<dyn ResourceProvider>>,
    pub(super) prompt_providers: Vec<Box<dyn PromptProvider>>,
    pub(super) sessions: DashMap<SessionId, Arc<Session>>,
    pub(super) receipt_log: Mutex<ReceiptLog>,
    pub(super) child_receipt_log: Mutex<ChildReceiptLog>,
    /// Live entry-count gauges for the two receipt mirrors. Cloned from the
    /// ring's gauge at construction so telemetry and the
    /// bounded-structure registry (`bounded_structure_gauges`) can read the
    /// count without locking the log.
    pub(super) receipt_mirror_gauge: chio_bounded::SizeGauge,
    pub(super) child_receipt_mirror_gauge: chio_bounded::SizeGauge,
    pub(super) receipt_store: Option<Arc<dyn ReceiptStore>>,
    pub(super) receipt_store_write_lock: Mutex<()>,
    pub(super) payment_adapter: Option<Box<dyn PaymentAdapter>>,
    pub(super) price_oracle: Option<Box<dyn PriceOracle>>,
    pub(super) runtime_admission_hook: Option<Arc<dyn RuntimeAdmissionHook>>,
    pub(super) attestation_trust_policy: Option<AttestationTrustPolicy>,
    pub(super) capability_crypto_floor: KernelCryptoFloor,
    /// How many receipts per Merkle checkpoint batch. Default: 100.
    pub(super) checkpoint_batch_size: u64,
    /// Monotonic counter for checkpoint_seq values.
    pub(super) checkpoint_seq_counter: AtomicU64,
    /// seq of the last receipt included in the previous checkpoint batch.
    pub(super) last_checkpoint_seq: AtomicU64,
    /// Nonce replay store for DPoP proof verification. Required when any grant has dpop_required.
    pub(super) dpop_nonce_store: Option<dpop::DpopNonceStore>,
    /// Configuration for DPoP proof verification TTLs and clock skew.
    pub(super) dpop_config: Option<dpop::DpopConfig>,
    /// Execution-nonce config (TTL, capacity, strict-mode flag).
    /// When `None`, no nonce is minted on allow and strict verification is
    /// disabled (compatibility deployments keep working).
    pub(super) execution_nonce_config: Option<crate::execution_nonce::ExecutionNonceConfig>,
    /// Replay-prevention store for execution nonces. Shared with
    /// any tool server that delegates verification to the kernel. Boxed
    /// trait object so SQLite-backed stores can be plugged in.
    pub(super) execution_nonce_store: Option<Box<dyn crate::execution_nonce::ExecutionNonceStore>>,
    /// Replay store for governed approval tokens. Prevents a signed approval
    /// from being consumed more than once. Uses the same LRU + TTL pattern as
    /// DPoP nonce verification. Key: (request_id, governed_intent_hash).
    pub(super) approval_replay_store: Option<dpop::DpopNonceStore>,
    /// Emergency kill switch. When `true`, every evaluate entry point returns
    /// `Verdict::Deny` without performing capability validation or guard
    /// evaluation. Flipped by `emergency_stop` / `emergency_resume`.
    ///
    /// Reads use `Ordering::SeqCst` even on the hot path. The emergency check
    /// is a single atomic load per evaluate call (negligible cost relative to
    /// the guard pipeline) and `SeqCst` is the safest default for a rarely
    /// taken control path.
    pub(super) emergency_stopped: AtomicBool,
    /// Unix timestamp (seconds) at which the kill switch was last engaged.
    /// `0` means "never engaged" or "currently resumed". Written with
    /// `SeqCst` before `emergency_stopped` is set to `true`, cleared to `0`
    /// after `emergency_stopped` is set to `false`.
    pub(super) emergency_stopped_since: AtomicU64,
    /// Operator-supplied reason for the most recent emergency stop. Set on
    /// `emergency_stop`, cleared on `emergency_resume`. Stored behind
    /// ArcSwap so health probes can read the current reason without blocking.
    pub(super) emergency_stop_reason: ArcSwap<Option<String>>,
    /// Memory-provenance chain. When installed, every
    /// governed `MemoryWrite` action appends an entry after the allow
    /// receipt is signed, and every `MemoryRead` attaches the latest
    /// entry (or an `Unverified` marker) to its receipt as
    /// `memory_provenance` evidence metadata. `None` keeps the kernel
    /// backward-compatible: memory-shaped tool calls behave exactly as
    /// they do without a provenance chain installed.
    pub(super) memory_provenance: Option<Arc<dyn crate::memory_provenance::MemoryProvenanceStore>>,
    /// Cross-kernel federation peer set. When a request
    /// carries a `federated_origin_kernel_id` and that peer is pinned
    /// here (fresh), the kernel invokes `federation_cosigner` after
    /// locally signing the receipt to obtain the origin kernel's
    /// co-signature. Absent in non-federated deployments.
    pub(super) federation_peers:
        ArcSwap<HashMap<String, chio_federation::trust_establishment::FederationPeer>>,
    /// `ArcSwap` so trust-root rotations can land without holding a
    /// kernel mutex. Hex-keyed because `chio_core::PublicKey` does not
    /// implement `Hash`.
    pub(super) capability_trust_roots:
        ArcSwap<HashMap<String, chio_core::capability::attenuation::ScopeHash>>,
    /// Serializes read-modify-write updates to `capability_trust_roots`.
    /// Snapshot reads remain lock-free through ArcSwap.
    pub(super) capability_trust_roots_write_lock: Mutex<()>,
    /// Bilateral co-signer. Separate from the peer set so
    /// runtime can install it independently - for instance, a deployment
    /// can declare peers while still using a mock cosigner in tests.
    pub(super) federation_cosigner:
        Option<Arc<dyn chio_federation::bilateral::BilateralCoSigningProtocol>>,
    /// Locally-signed dual receipts, indexed by ChioReceipt.id.
    /// Populated only when the post-sign hook fires successfully. Kept
    /// in-memory; persistent storage plugs in via the federation-state
    /// APIs already in chio-federation.
    /// Capped, idle-swept, gauged instead of an unbounded DashMap: federated
    /// calls no longer grow kernel RSS without bound.
    pub(super) federation_dual_receipts:
        Mutex<chio_bounded::BoundedMap<String, chio_federation::bilateral::DualSignedReceipt>>,
    pub(super) federation_dual_receipts_gauge: chio_bounded::SizeGauge,
    /// DSSE signature-slice envelopes, indexed by ChioReceipt.id.
    /// These are emitted through the federation cosigner protocol rather than
    /// by loading Org A private key material in the tool-host kernel.
    pub(super) federation_dsse_envelopes:
        Mutex<chio_bounded::BoundedMap<String, chio_federation::bilateral_dsse::DsseEnvelope>>,
    pub(super) federation_dsse_envelopes_gauge: chio_bounded::SizeGauge,
    /// Optional durable backing for bilateral co-sign artifacts. When set, the
    /// co-sign hook writes through to it before caching and the
    /// accessors fall through to it on a cache miss.
    pub(super) federation_artifact_store:
        Option<std::sync::Arc<dyn crate::federation_artifact_store::FederationArtifactStore>>,
    /// Request-keyed tenant scope for receipts. Async evaluate futures
    /// can resume on a different worker after dispatch, so the scope is
    /// stored in this map rather than a thread-local.
    pub(super) receipt_tenant_ids: Arc<DashMap<String, String>>,
    /// Request-keyed copy of the receipt-version admission snapshot.
    /// Async evaluate futures may resume on a different Tokio worker
    /// after dispatch. This map keeps the admitted version and peer state
    /// available until the evaluation future finishes.
    pub(super) receipt_federation_admissions: Arc<DashMap<String, ReceiptFederationAdmission>>,
    /// Operator-declared kernel identifier used as the
    /// `org_b_kernel_id` in bilateral co-signing. Defaults to the hex
    /// encoding of the kernel's signing public key, but operators can
    /// override it to a stable DNS name via `with_federation_peers`.
    pub(super) federation_local_kernel_id: ArcSwap<Option<String>>,
    /// Mpsc-backed signing task handle. Owns a clone of `config.keypair` and
    /// pulls signing requests from a bounded channel; producers `.await` on
    /// backpressure rather than on a mutex. Spawned at [`ChioKernel::new`] and
    /// joined by [`ChioKernel::shutdown`]. Wrapped in `Arc` so shared kernel
    /// handles can pass the signing handle to in-flight evaluators without
    /// cloning the whole kernel.
    pub(super) signing_task: std::sync::Arc<signing_task::SigningTaskHandle>,
    /// Settlement observer slot. When `Some`, the kernel invokes the
    /// hook against every finalized receipt that carries a non-zero
    /// manifest price. Settlement runs strictly post-signing and never
    /// blocks dispatch; failures are surfaced through the retry/dead-
    /// letter machinery, not through this option.
    pub(super) settlement_observer: Option<std::sync::Arc<dyn chio_settle::SettlementHook>>,
    /// Recursive-delegation oracle handle. When `Some`, the verifier consults this
    /// arc-swap-backed snapshot on every delegated dispatch and denies
    /// the capability if any link in the chain (or the leaf) is in the
    /// revoked set. `None` falls back to the per-row
    /// `RevocationStore` lookup. Field always present so the struct
    /// shape stays feature-flag agnostic.
    pub(super) revocation_view: Option<std::sync::Arc<chio_kernel_core::RevocationView>>,
    pub(super) budget_registry: Mutex<chio_kernel_core::InMemoryBudgetRegistry>,
    /// RSS soft-ceiling shed flag. Set by the sampler when process RSS exceeds
    /// `memory_budget.rss_soft_limit_bytes`; read on the
    /// admission fast path alongside the emergency stop.
    pub(super) rss_shed: Arc<AtomicBool>,
    /// Owns the sampler thread when a soft limit is configured; joins on drop.
    pub(super) rss_sampler: Option<RssSamplerHandle>,
}

impl ChioKernel {
    /// Construct the hybrid signing backend the kernel would use under
    /// `hybrid`'s configured floor and PQ key material after the kernel
    /// self-quote gate has run.
    ///
    /// Threads the kernel's classical Ed25519 keypair into a
    /// [`chio_core::crypto::Ed25519Backend`] under
    /// [`KernelCryptoFloor::AllowClassical`], or composes it with an
    /// [`chio_core::crypto::MlDsa65Backend`] derived from `hybrid.pq_signing_seed`
    /// into a [`chio_core::crypto::HybridBackend`] under
    /// [`KernelCryptoFloor::AllowHybrid`] or [`KernelCryptoFloor::PqRequired`],
    /// but only after [`crate::boot::load_kernel_signing_backend_after_self_quote`]
    /// accepts `self_quote_bytes`.
    ///
    /// Receipt body construction continues to flow through the existing
    /// inline path (`build_and_sign_receipt`); callers that opt in to
    /// hybrid signing pass the returned backend through
    /// [`crate::sign_receipt_body_with_backend`] (along with the canonical
    /// content preimage the body's `content_hash` was derived from) before
    /// persistence, so the hybrid path recomputes `content_hash` inside the
    /// trust boundary and is WYSIWYS fail-closed just like the inline
    /// classical path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::boot::KernelBootError::SelfQuoteRejected`] when the
    /// self-quote verifier rejects a non-classical floor, or
    /// [`crate::boot::KernelBootError::SigningBackend`] when the configured
    /// floor needs a PQ key but `hybrid.pq_signing_seed` is `None`. Mirrors
    /// the policy-level check in `chio_policy::CryptoFloor::validate_with_pq_key`
    /// so the boot path catches the misconfiguration even when the policy crate
    /// is bypassed.
    pub fn with_hybrid_signing_backend(
        &mut self,
        hybrid: &HybridSigningConfig,
        self_quote_bytes: &[u8],
        verifier: &dyn crate::boot::KernelSelfQuoteVerifier,
    ) -> Result<Box<dyn chio_core::crypto::SigningBackend>, crate::boot::KernelBootError> {
        let backend = crate::boot::load_kernel_signing_backend_after_self_quote(
            hybrid.crypto_floor,
            self.config.keypair.clone(),
            hybrid.pq_signing_seed.as_ref(),
            self_quote_bytes,
            verifier,
        )?;
        self.capability_crypto_floor = hybrid.crypto_floor;
        Ok(backend)
    }
}

/// Board-approved configuration for the Phase-0 free-tier compute pool (M0 Pass
/// CONTROL 1). It bounds aggregate free-tier liability to a hard monthly ceiling
/// so the gift degrades to "the pool shrinks", never "the treasury drains": when
/// the aggregate term is exhausted the kernel denies fail-closed.
///
/// The config travels via the fallible [`ChioKernel::with_free_tier_pool`]
/// builder rather than `KernelConfig`, so `ChioKernel::new` stays infallible and
/// misconfiguration is rejected at install time.
///
/// Ceiling scope: the ceiling is enforced against the kernel's budget store, so
/// it is exactly as global as that store. The default in-memory store bounds one
/// process; a horizontally-scaled fleet must share one transactionally-atomic
/// budget store or each replica keeps its own `freetier:global` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeTierPoolConfig {
    /// Hard monthly ceiling, in allotment units, on aggregate free-tier spend
    /// across every Pass holder. Liability becomes `min(N x allotment, pool)`.
    pub monthly_pool_units: u64,
    /// The allotment unit. It MUST be the canonical Pass allotment unit
    /// `pass_gating::PASS_ALLOTMENT_UNIT` ("XCC"): a 3-uppercase-letter private-use
    /// code that carries no money leg and matches the unit Pass scopes are minted
    /// with, so the aggregate co-debit actually fires for real Pass charges.
    pub allotment_unit: String,
    /// Audit-only reference to the board approval that funded this pool. It never
    /// participates in any arithmetic; it only records provenance.
    pub board_approval_ref: String,
}

impl FreeTierPoolConfig {
    /// Validate the config fail-closed.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidFreeTierPoolConfig`] when `monthly_pool_units`
    /// is zero, `allotment_unit` is not the Pass allotment unit ("XCC"), or
    /// `board_approval_ref` is empty.
    pub fn validate(&self) -> Result<(), KernelError> {
        if self.monthly_pool_units == 0 {
            return Err(KernelError::InvalidFreeTierPoolConfig(
                "monthly_pool_units must be non-zero".to_string(),
            ));
        }
        let unit_ok = self.allotment_unit.len() == 3
            && self.allotment_unit.bytes().all(|b| b.is_ascii_uppercase());
        if !unit_ok {
            return Err(KernelError::InvalidFreeTierPoolConfig(
                "allotment_unit must be 3 uppercase ASCII letters".to_string(),
            ));
        }
        // The pool unit MUST be the canonical Pass allotment unit. Pass scopes are
        // minted with the fixed XCC unit (`pass_gating::PASS_ALLOTMENT_UNIT`), so a
        // pool configured with any other (shape-valid) unit such as the pinned `USD`
        // would never match a real Pass charge: the charge path takes the
        // `currency != pool.allotment_unit` branch and authorizes WITHOUT the
        // aggregate co-debit, silently disabling the monthly liability cap this config
        // exists to enforce. Require an exact match, fail-closed.
        if self.allotment_unit != crate::pass_gating::PASS_ALLOTMENT_UNIT {
            return Err(KernelError::InvalidFreeTierPoolConfig(format!(
                "allotment_unit must be the Pass allotment unit {}, got {}",
                crate::pass_gating::PASS_ALLOTMENT_UNIT,
                self.allotment_unit
            )));
        }
        if self.board_approval_ref.is_empty() {
            return Err(KernelError::InvalidFreeTierPoolConfig(
                "board_approval_ref must be present".to_string(),
            ));
        }
        Ok(())
    }

    /// Derive the aggregate pool budget-term id `"freetier:global:<YYYY-MM>"` from
    /// a Pass capability's `issued_at` (which is pinned to the first second of its
    /// active month, so the term is the same for every Pass in that month). The id
    /// is what keys the single shared `(term, grant_index 0)` budget row.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidFreeTierPoolConfig`] when `issued_at` is not a
    /// representable unix timestamp.
    pub fn window_ym_from_issued_at(issued_at: u64) -> Result<String, KernelError> {
        let secs = i64::try_from(issued_at).map_err(|_| {
            KernelError::InvalidFreeTierPoolConfig("issued_at out of range".to_string())
        })?;
        let dt = chrono::DateTime::from_timestamp(secs, 0).ok_or_else(|| {
            KernelError::InvalidFreeTierPoolConfig("issued_at not representable".to_string())
        })?;
        Ok(format!("freetier:global:{}", dt.format("%Y-%m")))
    }
}

#[cfg(test)]
mod free_tier_pool_config_tests {
    use super::FreeTierPoolConfig;

    fn cfg() -> FreeTierPoolConfig {
        FreeTierPoolConfig {
            monthly_pool_units: 1_000_000,
            allotment_unit: "XCC".to_string(),
            board_approval_ref: "board-2026-06-001".to_string(),
        }
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        assert!(cfg().validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_pool() {
        let mut c = cfg();
        c.monthly_pool_units = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_malformed_unit() {
        for bad in ["xcc", "XC", "XCCX", "X1C", ""] {
            let mut c = cfg();
            c.allotment_unit = bad.to_string();
            assert!(c.validate().is_err(), "unit `{bad}` must be rejected");
        }
    }

    #[test]
    fn validate_rejects_non_xcc_pool_unit() {
        // PR957 codex P2: the pool unit must be the canonical Pass allotment unit
        // (XCC). A shape-valid but pinned currency like USD would never match a real
        // Pass charge, silently disabling the monthly liability cap, so it is rejected
        // fail-closed even though it is three uppercase letters. Any other private-use
        // code is likewise rejected: Pass scopes only ever mint XCC.
        for non_xcc in ["USD", "ABC"] {
            let mut c = cfg();
            c.allotment_unit = non_xcc.to_string();
            assert!(
                c.validate().is_err(),
                "a non-XCC pool unit `{non_xcc}` must be rejected"
            );
        }
    }

    #[test]
    fn validate_rejects_empty_board_ref() {
        let mut c = cfg();
        c.board_approval_ref = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn window_term_id_is_month_scoped() {
        assert_eq!(
            FreeTierPoolConfig::window_ym_from_issued_at(0).unwrap(),
            "freetier:global:1970-01"
        );
        let term = FreeTierPoolConfig::window_ym_from_issued_at(1_780_704_000).unwrap();
        assert!(term.starts_with("freetier:global:2026-"), "got {term}");
    }
}

/// Grant index of the single aggregate free-tier pool budget row. All free-tier
/// charges in a month share `(freetier:global:<YYYY-MM>, 0)`.
pub(crate) const FREETIER_GLOBAL_GRANT_INDEX: usize = 0;

/// A hold taken against the aggregate free-tier pool alongside a per-Pass hold.
/// Carried on `BudgetChargeResult` so the pool exposure is reversed and
/// reconciled symmetrically with the per-Pass hold (no stale pool leak).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreeTierPoolHold {
    /// The `freetier:global:<YYYY-MM>` budget term this hold debits.
    pub term_id: String,
    /// Unique id of this pool hold, for symmetric reverse/reconcile.
    pub hold_id: String,
    /// Exposure units held against the pool (worst-case per-invocation cost).
    pub units: u64,
}

impl ChioKernel {
    /// Install the board-approved free-tier pool config. Fallible so misconfig is
    /// rejected at install time while `ChioKernel::new` stays infallible.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidFreeTierPoolConfig`] when the config fails
    /// [`FreeTierPoolConfig::validate`].
    pub fn with_free_tier_pool(mut self, config: FreeTierPoolConfig) -> Result<Self, KernelError> {
        config.validate()?;
        self.free_tier_pool = Some(config);
        Ok(self)
    }

    pub(crate) fn free_tier_pool_config(&self) -> Option<&FreeTierPoolConfig> {
        self.free_tier_pool.as_ref()
    }
}
