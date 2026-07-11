use super::*;

#[path = "types/runtime.rs"]
mod runtime;
pub(crate) use runtime::*;
#[path = "types/trust.rs"]
mod trust;
pub(crate) use trust::*;
#[path = "types/receipt.rs"]
mod receipt;
pub(crate) use receipt::*;
#[path = "types/passport.rs"]
mod passport_types;
pub(crate) use passport_types::*;
#[path = "types/proof.rs"]
mod proof;
pub(crate) use proof::*;
#[path = "types/workflow.rs"]
mod workflow;
pub(crate) use workflow::*;
#[path = "types/replay.rs"]
mod replay;
pub(crate) use replay::*;

/// Chio -- Chio.
///
/// Runtime security enforcement for AI agents via capability-based
/// authorization and signed audit receipts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum CheckMode {
    #[default]
    Preflight,
    Full,
}

impl CheckMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Full => "full",
        }
    }
}

#[derive(Parser)]
#[command(version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,

    /// Short alias for `--format json`.
    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    /// Output format for command results and terminal error reporting.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Optional SQLite database path for durable receipt persistence.
    #[arg(long, global = true)]
    pub(crate) receipt_db: Option<PathBuf>,

    /// Optional SQLite database path for durable capability revocation persistence.
    #[arg(long, global = true)]
    pub(crate) revocation_db: Option<PathBuf>,

    /// Optional file path for a persistent capability-authority seed.
    #[arg(long, global = true)]
    pub(crate) authority_seed_file: Option<PathBuf>,

    /// Optional SQLite database path for shared capability-authority state.
    #[arg(long, global = true)]
    pub(crate) authority_db: Option<PathBuf>,

    /// Optional SQLite database path for durable shared capability budget state.
    #[arg(long, global = true)]
    pub(crate) budget_db: Option<PathBuf>,

    /// Optional SQLite database path for durable remote MCP session tombstones.
    #[arg(long, global = true)]
    pub(crate) session_db: Option<PathBuf>,

    /// Optional shared trust-control service base URL.
    #[arg(long, global = true)]
    pub(crate) control_url: Option<String>,

    /// Bearer token used to authenticate to the shared trust-control service.
    /// Prefer `CHIO_CONTROL_TOKEN` env over the argv form so the bearer does
    /// not leak via `ps` / `/proc/<pid>/cmdline`.
    #[arg(
        long,
        global = true,
        env = "CHIO_CONTROL_TOKEN",
        hide_env_values = true
    )]
    pub(crate) control_token: Option<String>,
}

impl Cli {
    pub(crate) fn json_output(&self) -> bool {
        self.json || matches!(self.format, OutputFormat::Json)
    }
}

#[cfg(test)]
mod cli_env_tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Parse a `chio` argv into [`Cli`] on a thread with an 8 MiB stack.
    ///
    /// The release binary parses argv on the process main thread (8 MiB
    /// stack); the libtest harness runs each test on a worker thread with a
    /// ~2 MiB stack, which the monomorphised clap parser for the 25-variant
    /// `Commands` enum overflows. Driving the parse through an 8 MiB worker
    /// mirrors the production main-thread stack without changing the CLI
    /// surface. Process env vars are shared across threads, so clap's `env`
    /// fallbacks still observe the vars the caller set under `env_lock`.
    fn parse_cli<I>(argv: I) -> clap::error::Result<Cli>
    where
        I: IntoIterator<Item = &'static str>,
    {
        let argv: Vec<&'static str> = argv.into_iter().collect();
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(argv))
            .unwrap_or_else(|error| panic!("spawn 8 MiB parse thread: {error}"))
            .join()
            .unwrap_or_else(|_| panic!("parse thread must not panic"))
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn restore_env(name: &str, value: Option<OsString>) {
        if let Some(value) = value {
            std::env::set_var(name, value);
        } else {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn mcp_serve_http_reads_documented_token_env_vars() {
        let _guard = env_lock();
        let prior_auth = std::env::var_os("CHIO_AUTH_TOKEN");
        let prior_admin = std::env::var_os("CHIO_ADMIN_TOKEN");
        let prior_mcp_auth = std::env::var_os("CHIO_MCP_AUTH_TOKEN");
        let prior_mcp_admin = std::env::var_os("CHIO_MCP_ADMIN_TOKEN");
        std::env::set_var("CHIO_AUTH_TOKEN", "documented-auth-token");
        std::env::set_var("CHIO_ADMIN_TOKEN", "documented-admin-token");
        std::env::remove_var("CHIO_MCP_AUTH_TOKEN");
        std::env::remove_var("CHIO_MCP_ADMIN_TOKEN");

        let parsed = parse_cli([
            "chio",
            "mcp",
            "serve-http",
            "--policy",
            "policy.yaml",
            "--server-id",
            "mcp",
            "/bin/true",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        match parsed.command {
            Commands::Mcp {
                command:
                    McpCommands::ServeHttp {
                        auth_token,
                        admin_token,
                        ..
                    },
            } => {
                assert_eq!(auth_token.as_deref(), Some("documented-auth-token"));
                assert_eq!(admin_token.as_deref(), Some("documented-admin-token"));
            }
            _ => panic!("expected mcp serve-http command"),
        }

        restore_env("CHIO_AUTH_TOKEN", prior_auth);
        restore_env("CHIO_ADMIN_TOKEN", prior_admin);
        restore_env("CHIO_MCP_AUTH_TOKEN", prior_mcp_auth);
        restore_env("CHIO_MCP_ADMIN_TOKEN", prior_mcp_admin);
    }

    #[test]
    fn guard_publish_reads_registry_password_env_var() {
        let _guard = env_lock();
        let prior = std::env::var_os("CHIO_GUARD_REGISTRY_PASSWORD");
        std::env::set_var("CHIO_GUARD_REGISTRY_PASSWORD", "registry-password");

        let parsed = parse_cli([
            "chio",
            "guard",
            "publish",
            ".",
            "--ref",
            "oci://ghcr.io/chio/tool-gate:v1",
            "--epoch-id-seed",
            "seed-1",
            "--username",
            "registry-user",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        match parsed.command {
            Commands::Guard {
                command: GuardCommands::Publish { password, .. },
            } => {
                assert_eq!(password.as_deref(), Some("registry-password"));
            }
            _ => panic!("expected guard publish command"),
        }

        restore_env("CHIO_GUARD_REGISTRY_PASSWORD", prior);
    }

    #[test]
    fn guard_pull_reads_registry_password_env_var() {
        let _guard = env_lock();
        let prior = std::env::var_os("CHIO_GUARD_REGISTRY_PASSWORD");
        std::env::set_var("CHIO_GUARD_REGISTRY_PASSWORD", "registry-password");

        let parsed = parse_cli([
            "chio",
            "guard",
            "pull",
            "--ref",
            "oci://ghcr.io/chio/tool-gate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--username",
            "registry-user",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        match parsed.command {
            Commands::Guard {
                command: GuardCommands::Pull { password, .. },
            } => {
                assert_eq!(password.as_deref(), Some("registry-password"));
            }
            _ => panic!("expected guard pull command"),
        }

        restore_env("CHIO_GUARD_REGISTRY_PASSWORD", prior);
    }
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Spawn an agent subprocess and enforce policy via the kernel.
    Run {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// The agent command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Evaluate a single tool call against a policy (no subprocess).
    Check {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Evaluation mode. Preflight checks only policies that do not need tool output.
        #[arg(long, value_enum, default_value_t = CheckMode::Preflight)]
        mode: CheckMode,

        /// Tool name to evaluate.
        #[arg(long)]
        tool: String,

        /// Tool parameters as a JSON string.
        #[arg(long, default_value = "{}")]
        params: String,

        /// Server ID to use for the evaluation.
        #[arg(long, default_value = "*")]
        server: String,

        /// JSON value returned by the fixture-backed tool server in full mode.
        #[arg(long = "output-fixture", value_name = "JSON")]
        output_fixture: Option<PathBuf>,
    },

    /// Scaffold a runnable Chio example project with a governed demo flow.
    Init {
        /// Directory to create for the scaffolded project.
        path: PathBuf,
    },

    /// Protect an HTTP API with Chio using an OpenAPI spec-backed sidecar.
    Api {
        #[command(subcommand)]
        command: ApiCommands,
    },

    /// Serve an MCP-compatible edge backed by the Chio kernel.
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },

    /// Manage local trust-plane state such as persisted revocations.
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },

    /// Query and list receipts from the receipt store.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommands,
    },

    /// Export an offline evidence package from the local receipt database.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },

    /// Evaluate a conformance corpus and emit a signed certification artifact.
    Certify {
        #[command(subcommand)]
        command: CertifyCommands,
    },

    /// Resolve self-certifying did:chio identifiers into DID Documents.
    Did {
        #[command(subcommand)]
        command: DidCommands,
    },

    /// Create, verify, and present Agent Passport bundles.
    Passport {
        #[command(subcommand)]
        command: PassportCommands,
    },

    /// Issue, refresh, and anchor the portable Chio Pass reputation credential.
    ///
    /// The Chio Pass is a soulbound, portable reputation credential (NOT a
    /// passport): it gifts a metered free-tier allotment plus baseline gifted
    /// stream reads to one attested `did:chio`. These subcommands drive the
    /// board-approved control-plane orchestrator (the launch governance
    /// surface) end to end:
    ///
    /// - `issue` mints the first-window credential and its deterministic
    ///   `chiopass:<hash>` window-scoped capability.
    /// - `refresh` sizes the next monthly window from the prior window's
    ///   genuine-use scan (renew / dormant / not-reattested).
    /// - `anchor` folds issued and revoked Pass digests into a prepared
    ///   (un-broadcast) read-only on-chain root publication.
    Pass {
        #[command(subcommand)]
        command: PassCommands,
    },

    /// Verify proof bundles and Transaction Passport artifacts.
    Proof {
        #[command(subcommand)]
        command: ProofCommands,
    },

    /// Verify commerce proof bundles and payment evidence.
    Commerce {
        #[command(subcommand)]
        command: CommerceCommands,
    },

    /// Validate read-only workflow planning evidence before dispatch.
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommands,
    },

    /// Inspect local reputation scorecards from persisted receipts and lineage state.
    Reputation {
        #[command(subcommand)]
        command: ReputationCommands,
    },

    /// Generate, verify, and inspect ACP session compliance certificates.
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },

    /// Guard development lifecycle: scaffold, build, and inspect WASM guards.
    Guard {
        #[command(subcommand)]
        command: GuardCommands,
    },

    /// Run the cross-language conformance harness against a peer adapter.
    Conformance {
        #[command(subcommand)]
        command: ConformanceCommands,
    },

    /// Produce and verify cross-kernel federation artifacts.
    Federation {
        #[command(subcommand)]
        command: ChioFederationCommands,
    },

    /// Verify offline attestation evidence and buyer proof packages.
    Attest {
        #[command(subcommand)]
        command: ChioAttestCommands,
    },

    /// Evaluate local live-runtime admission artifacts.
    Runtime {
        #[command(subcommand)]
        command: ChioRuntimeCommands,
    },

    /// Receive, query, and relay pheromone artifacts.
    Pheromone {
        #[command(subcommand)]
        command: ChioPheromoneCommands,
    },

    /// Re-evaluate a captured receipt log against the current build.
    ///
    /// Reads a directory of signed receipts (or an NDJSON tee stream),
    /// re-verifies every signature, recomputes the Merkle root incrementally,
    /// and reports the first divergence by byte offset and JSON pointer.
    /// Composes with `chio tee` output.
    ///
    /// EXIT CODES:
    ///   0  All receipts (or tee frames) verify and root matches expectation.
    ///   10 Verdict drift: a receipt's allow/deny decision differs from the
    ///      current build for the same input.
    ///   20 Signature mismatch: Ed25519 verification failed on at least one
    ///      receipt or frame `tenant_sig`.
    ///   30 Parse error: malformed JSON or missing required field.
    ///   40 Schema mismatch: unsupported `schema_version` or schema validation
    ///      failed against the canonical-JSON schema set.
    ///   50 Redaction mismatch: `redaction_pass_id` unavailable, or rerunning
    ///      the redaction manifest produces a different result.
    Replay(ReplayArgs),

    /// Inspect local settlement lifecycle records.
    ///
    /// Lists pending IOU envelopes (minted but not yet settled),
    /// settled receipts (rows in `settlement_reconciliations` whose
    /// state is `settled`), and dead-lettered settlements (rows in
    /// `settle_dead_letters`).
    Settle {
        #[command(subcommand)]
        command: SettleCommands,
    },

    /// Query, diff, or list anchored roots in the lineage DAG.
    ///
    /// Surfaces the lineage graph (`chio-lineage`):
    /// - `query` walks forward or reverse from a seed node id over a
    ///   lineage JSON dump.
    /// - `diff` computes the symmetric edge diff between two dumps.
    /// - `roots` lists pinned-frontier artifacts in a directory.
    Lineage {
        #[command(subcommand)]
        command: LineageCommands,
    },

    /// Diagnose toolchain, registry, OTEL, and `chio.yaml` health.
    ///
    /// Probes (in order):
    ///
    /// 1. Toolchain version vs. workspace MSRV / `rust-toolchain.toml`.
    /// 2. OCI guard registry reachability.
    /// 3. Cosign guard-bundle freshness.
    /// 4. OTEL exporter endpoint resolution.
    /// 5. Kernel runtime `/metrics` (asserts the
    ///    `chio_kernel_dispatch_inflight` gauge is reachable).
    /// 6. `chio.yaml` schema validity.
    ///
    /// Exit codes follow the worst observed severity: 0 for ok / info /
    /// warning, 1 for error, 2 for fatal. The optional `--fix` flag
    /// runs idempotent repairs only; destructive operations are rejected.
    Doctor(DoctorArgs),

    /// chio-arena coliseum: run scenarios, replay bundles, evolve adversaries.
    ///
    /// `chio arena run scenarios/<name>.toml` loads a scenario, drives the
    /// kernel via the async surface, and writes a receipt bundle
    /// byte-compatible with the replay corpus under
    /// `target/arena/<scenario-id>/`. `chio arena replay <scenario-id>`
    /// resolves the bundle directory and delegates to `chio replay`.
    /// `chio arena evolve scenarios/<seed>.toml --generations N` runs the
    /// co-evolution driver under the bounded-budget gate.
    Arena {
        #[command(subcommand)]
        command: ArenaCommands,
    },

    /// Bind a provider under a signed model card.
    ///
    /// `chio bind <provider> --card <path>` loads the model card from
    /// `<path>` (canonical-JSON encoded per spec/schemas/model-card.v1.json),
    /// validates its structural shape, and prints the resolved
    /// `weights_hash` and `allowed_capability_set` so an operator can sanity
    /// check before promoting to production policy. The cosign bundle
    /// verify path consumes `chio-attest-verify` when `--bundle` is
    /// supplied; otherwise the helper prints the card fields without
    /// attesting authenticity.
    Bind {
        /// Provider identifier to bind under the card. Free-form string
        /// surfaced in the resolved-binding summary; not interpreted by
        /// the helper.
        provider: String,

        /// Path to the canonical-JSON encoded model card.
        #[arg(long, value_name = "PATH")]
        card: PathBuf,

        /// Optional path to the cosign bundle for the card. When supplied,
        /// the helper verifies the bundle through
        /// `chio_attest_verify::SigstoreVerifier::verify_bundle`
        /// and refuses to print the binding summary on failure.
        #[arg(long, value_name = "PATH")]
        bundle: Option<PathBuf>,

        /// Cosign certificate identity SAN regex required when `--bundle`
        /// is supplied. Forwarded verbatim to
        /// `chio_attest_verify::ExpectedIdentity::certificate_identity_regexp`.
        #[arg(long, value_name = "REGEX")]
        issuer_san_regex: Option<String>,

        /// OIDC issuer expected on the cosign certificate. Required with
        /// `--bundle`.
        #[arg(long, value_name = "URL")]
        issuer_oidc: Option<String>,

        /// Runtime weights binding mode. `required` and `required_with_pin`
        /// require `--bundle` so card verification cannot be silently skipped.
        #[arg(long, value_name = "MODE", default_value = "not_required")]
        weights_binding_mode: String,
    },

    /// Start the Chio sidecar with sensible zero-config defaults.
    ///
    /// Convenience alias for `chio api protect` aimed at SDK quickstart
    /// and chio-hermes integration users. It runs the same axum router
    /// (capability mint/release/validate, receipt verify, tool-call
    /// evaluate, HITL approval endpoints) but with:
    ///
    /// - no upstream proxy (the catch-all `/{*path}` 502s loud);
    /// - in-memory stores by default (no `--receipt-db`);
    /// - a friendly startup banner that prints the bound address.
    ///
    /// `chio api protect` remains the canonical name for production
    /// deployments that need `--upstream`, `--spec`, and persistent
    /// stores.
    Start {
        /// Address to listen on. Defaults to `127.0.0.1:9090` to
        /// match `chio-sdk-python`'s `ChioClient.DEFAULT_BASE_URL`.
        /// Pass `127.0.0.1:0` to bind an ephemeral port; the bound
        /// address is then printed in the startup banner.
        #[arg(long, default_value = "127.0.0.1:9090")]
        listen: String,

        /// Optional SQLite receipt store path. Defaults to in-memory
        /// so the first run leaves no on-disk artifacts.
        #[arg(long = "receipt-store")]
        receipt_store: Option<PathBuf>,

        /// Print the chio-hermes config snippet (env vars + slash
        /// commands) on startup so users can copy/paste into their
        /// shell before running their agent. Off by default to keep
        /// the banner short.
        #[arg(long, default_value_t = false)]
        print_config: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PassCommands {
    /// Mint the first-window Chio Pass reputation credential for one subject.
    ///
    /// Loads the board-approved launch governance surface
    /// (`ChioPassConfig::launch_default`) and calls the control-plane
    /// issuance entrypoint. The minted capability id is the deterministic
    /// `chiopass:<hash>` window-scoped id (subject + window only), so the same
    /// subject re-minted inside the same monthly window maps to a single budget
    /// row. The per-window distribution counters are sourced from the revocation
    /// oracle (`--revocation-db`), never recomputed at the entrypoint.
    Issue {
        /// Subject Ed25519 public key in hex. The Pass is soulbound to the
        /// `did:chio` derived from this key.
        #[arg(long)]
        subject_public_key: String,

        /// Attested trust tier governing the allotment SIZE only (never
        /// existence): one of unverified, attested, verified, premier.
        #[arg(long, default_value = "attested")]
        tier: String,

        /// UTC instant (Unix seconds) selecting the monthly attestation window.
        /// Defaults to now.
        #[arg(long)]
        now: Option<u64>,

        /// Trusted kernel signing key (hex) pinned into the genuine-use
        /// allowlist (registry RR2-TM-01). Repeatable and REQUIRED: at least one
        /// must be supplied (the local authority key is never trusted as a
        /// kernel key).
        #[arg(long = "accepted-kernel-key")]
        accepted_kernel_key: Vec<String>,

        /// Optional path to write the minted, signed Chio Pass credential JSON
        /// to. The written file is the issued-Pass artifact `chio pass anchor`
        /// consumes via `--issued-pass`.
        #[arg(long = "out-pass")]
        out_pass: Option<PathBuf>,

        /// Optional path to write the minted window-scoped capability token JSON
        /// to.
        #[arg(long = "out-capability")]
        out_capability: Option<PathBuf>,
    },

    /// Roll a Pass forward into its next monthly window from genuine use.
    ///
    /// Scans the prior window's genuine-use receipts (`--receipt-db`) via the
    /// control-plane refresh entrypoint and sizes the next window: renewed at
    /// tier size, withheld-dormant (zero allotment, baseline reads persist), or
    /// not-reattested (nothing minted).
    Refresh {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,

        /// Attested trust tier governing the next-window allotment SIZE.
        #[arg(long, default_value = "attested")]
        tier: String,

        /// UTC instant (Unix seconds) inside the PRIOR window. The next window is
        /// the contiguous monthly rollover. Defaults to now.
        #[arg(long)]
        now: Option<u64>,

        /// Optional UTC instant (Unix seconds) INSIDE the EXPIRING (prior) window
        /// the refresh renews. The wall-clock `now` alone cannot identify the
        /// expiring window at or just after a month boundary (it already lands in
        /// the NEW window), so pin the expiring window explicitly here; the minted
        /// next window is its contiguous monthly rollover. When omitted, the prior
        /// window is derived from `now` only when `now` is unambiguously inside a
        /// window's interior; a run within the rollover boundary fails closed and
        /// requires this flag.
        #[arg(long = "prior-window-at")]
        prior_window_at: Option<u64>,

        /// Operator intent to re-attest at rollover. The verdict is NOT trusted
        /// from this flag alone: it is only honored when a fresh nonce-bound
        /// `--reattestation-proof` presentation response is supplied and verifies
        /// for this subject. When the flag is set without a verifying proof the
        /// refresh fails closed.
        #[arg(long, default_value_t = false)]
        reattested: bool,

        /// Signed passport presentation-response JSON file proving a fresh
        /// rollover re-attestation challenge was answered by this subject. The CLI
        /// verifies it (nonce-bound, time-windowed, subject-bound) and derives the
        /// re-attestation verdict from the verified result, never from the bare
        /// `--reattested` flag.
        #[arg(long = "reattestation-proof")]
        reattestation_proof: Option<PathBuf>,

        /// Optional expected presentation-challenge JSON file the
        /// `--reattestation-proof` MUST answer. When supplied, the response is
        /// pinned to this exact challenge (nonce binding); when omitted, the
        /// response's self-contained challenge is verified for freshness.
        #[arg(long = "reattestation-challenge")]
        reattestation_challenge: Option<PathBuf>,

        /// Trusted kernel signing key (hex) pinned into the genuine-use
        /// allowlist (registry RR2-TM-01). Repeatable. When omitted, the local
        /// authority key is used as the trust anchor.
        #[arg(long = "accepted-kernel-key")]
        accepted_kernel_key: Vec<String>,

        /// Optional path to write the refreshed, signed Chio Pass credential JSON
        /// to (renewed/dormant outcomes only). The written file is the issued-Pass
        /// artifact `chio pass anchor` consumes via `--issued-pass`.
        #[arg(long = "out-pass")]
        out_pass: Option<PathBuf>,

        /// Optional path to write the refreshed window-scoped capability token JSON
        /// to (renewed/dormant outcomes only).
        #[arg(long = "out-capability")]
        out_capability: Option<PathBuf>,
    },

    /// Prepare (do NOT broadcast) the read-only Pass anchoring root publication.
    ///
    /// Folds the issued and revoked Pass digests into one anchorable Merkle root
    /// plus inclusion proofs, wraps it in a kernel checkpoint, and prepares the
    /// on-chain root-publication call data. Value-free: nothing moves on-chain.
    Anchor {
        /// Issued Chio Pass credential JSON file. Repeatable.
        #[arg(long = "issued-pass")]
        issued_pass: Vec<PathBuf>,

        /// Revoked Pass lifecycle-record JSON file. Repeatable. Each entry MUST be
        /// paired BY POSITION with a `--revoked-pass` original credential that
        /// proves its passport_id.
        #[arg(long = "revoked-record")]
        revoked_record: Vec<PathBuf>,

        /// Original signed Chio Pass credential JSON for a `--revoked-record`
        /// entry, paired BY POSITION. The revoked leaf's passport_id is proven by
        /// recomputing the Pass artifact id from this credential (and verifying its
        /// issuer signature), so a hand-written revoked record carrying a
        /// fabricated passport_id is rejected before anchoring. Repeatable; the
        /// count MUST equal the `--revoked-record` count.
        #[arg(long = "revoked-pass")]
        revoked_pass: Vec<PathBuf>,

        /// Trusted Pass-issuer DID (`did:chio`) whose issued Passes may be folded
        /// into the anchor batch. Repeatable. The operator's own DID (derived from
        /// the signing seed) is ALWAYS trusted; pin additional issuers here to
        /// anchor Passes issued by a distinct trusted authority. A Pass issued by
        /// any other DID is rejected before anchoring (fail-closed), so an operator
        /// cannot publish a membership root over foreign or self-issued Passes.
        #[arg(long = "trusted-pass-issuer")]
        trusted_pass_issuer: Vec<String>,

        /// Anchor-purpose signed Web3 identity binding JSON file.
        #[arg(long)]
        binding: PathBuf,

        /// EVM anchor target JSON file (chain id, contract, operator addresses).
        #[arg(long)]
        target: PathBuf,

        /// Public-witness descriptor JSON file for the anchor batch.
        #[arg(long)]
        witness: PathBuf,

        /// Batch issuance timestamp in Unix seconds. Defaults to now.
        #[arg(long)]
        issued_at: Option<u64>,

        /// Optional previous kernel-checkpoint JSON file for the per-operator
        /// sequence chain. Omit for the genesis batch (checkpoint_seq 0).
        #[arg(long = "previous-checkpoint")]
        previous_checkpoint: Option<PathBuf>,

        /// Optional path to write the signed RFC6962 anchor batch JSON (its
        /// `tree_root` and one inclusion proof per anchored digest) so the
        /// prepared root can be broadcast and inclusion later verified.
        #[arg(long = "out-batch")]
        out_batch: Option<PathBuf>,

        /// Optional path to write the kernel checkpoint JSON wrapping the anchor
        /// batch tree root under the operator's checkpoint sequence.
        #[arg(long = "out-checkpoint")]
        out_checkpoint: Option<PathBuf>,

        /// Optional path to write the prepared (un-broadcast) EVM root-publication
        /// call data JSON bound to the anchor-purpose identity binding.
        #[arg(long = "out-publication")]
        out_publication: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum DidCommands {
    /// Resolve a did:chio identifier or Ed25519 public key into a DID Document.
    Resolve {
        /// Fully-qualified did:chio identifier to resolve.
        #[arg(long, conflicts_with = "public_key")]
        did: Option<String>,
        /// Hex-encoded Ed25519 public key to resolve as did:chio.
        #[arg(long, conflicts_with = "did")]
        public_key: Option<String>,
        /// Optional receipt log service endpoint to include in the resolved document.
        #[arg(long = "receipt-log-url")]
        receipt_log_urls: Vec<String>,
        /// Optional passport lifecycle endpoint to include in the resolved document.
        #[arg(long = "passport-status-url")]
        passport_status_urls: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReputationCommands {
    /// Compute the local reputation scorecard for one subject.
    Local {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,
        /// Optional lower bound for the evaluated receipt window, in Unix seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper bound for the evaluated receipt window, in Unix seconds.
        #[arg(long)]
        until: Option<u64>,
        /// Optional policy file whose reputation scoring config should be applied for local evaluation.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Compare the live local reputation corpus against a portable passport artifact.
    Compare {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,
        /// Passport JSON file to compare against live local state.
        #[arg(long)]
        passport: PathBuf,
        /// Optional lower bound for the evaluated local receipt window, in Unix seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper bound for the evaluated local receipt window, in Unix seconds.
        #[arg(long)]
        until: Option<u64>,
        /// Optional HushSpec policy file whose local reputation scoring config should be applied.
        #[arg(long)]
        local_policy: Option<PathBuf>,
        /// Optional YAML or JSON verifier policy used to evaluate the passport during comparison.
        #[arg(long)]
        verifier_policy: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum CertCommands {
    /// Generate a compliance certificate for an ACP session.
    Generate {
        /// ACP session ID to certify.
        #[arg(long)]
        session_id: String,

        /// Path to the receipt database.
        #[arg(long)]
        receipt_db: PathBuf,

        /// Maximum invocation budget (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        budget_limit: u64,

        /// Output file for the certificate JSON.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Verify a compliance certificate.
    Verify {
        /// Path to the certificate JSON file.
        #[arg(long)]
        certificate: PathBuf,

        /// Trusted kernel public-key file used to verify the certificate
        /// signature. Raw 32-byte Ed25519 and algorithm-aware hex files are
        /// accepted.
        #[arg(long, value_name = "PATH")]
        trusted_kernel_pubkey: PathBuf,

        /// Enable full-bundle verification (re-verify all receipt signatures).
        #[arg(long, default_value_t = false)]
        full: bool,

        /// Path to the receipt database (required for full-bundle mode).
        #[arg(long)]
        receipt_db: Option<PathBuf>,
    },

    /// Inspect a compliance certificate and display its contents.
    Inspect {
        /// Path to the certificate JSON file.
        #[arg(long)]
        certificate: PathBuf,
    },
}
