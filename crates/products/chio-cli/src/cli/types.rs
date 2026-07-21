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

    /// Operator-supplied keyring configuration with a durable key log and independent trust roots.
    #[arg(long, global = true)]
    pub(crate) keyring_config: Option<PathBuf>,

    /// Canonical production broker composition with sealed signing-key custody.
    #[arg(long, global = true)]
    pub(crate) broker_config: Option<PathBuf>,

    /// Optional SQLite database path for shared capability-authority state.
    #[arg(long, global = true)]
    pub(crate) authority_db: Option<PathBuf>,

    /// Optional SQLite database path for durable shared capability budget state.
    #[arg(long, global = true)]
    pub(crate) budget_db: Option<PathBuf>,

    /// Settlement driver: `none` (default; the settle drive is inert) or
    /// `ops` (run the reference settlement hook when driving due attempts).
    #[arg(long, global = true, default_value = "none")]
    pub(crate) settlement_driver: String,

    /// Enable durable aggregate invocation admission for ordinary tool calls.
    #[arg(long, global = true, default_value_t = false)]
    pub(crate) aggregate_invocation_admission: bool,

    /// SQLite database path for durable aggregate and threshold admission operations.
    #[arg(long, global = true)]
    pub(crate) admission_operation_db: Option<PathBuf>,

    /// SQLite database path for durable threshold approval replay state.
    #[arg(long, global = true)]
    pub(crate) approval_db: Option<PathBuf>,

    /// Authenticated approver-directory YAML used to compile threshold policy.
    #[arg(long, global = true)]
    pub(crate) approver_directory: Option<PathBuf>,

    /// Independently configured authority trusted to sign threshold proposals.
    #[arg(
        long,
        global = true,
        env = "CHIO_THRESHOLD_PROPOSAL_AUTHORITY_PUBLIC_KEY",
        value_parser = parse_threshold_proposal_authority_public_key
    )]
    pub(crate) threshold_proposal_authority_public_key: Option<chio_core::PublicKey>,

    /// Optional SQLite database path for durable remote MCP session tombstones.
    #[arg(long, global = true)]
    pub(crate) session_db: Option<PathBuf>,

    /// Dedicated HMAC keyring used only for durable remote MCP resume records.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) resume_hmac_keyring: Option<PathBuf>,

    /// Comma-separated final trust-control endpoint URLs.
    ///
    /// Endpoints require HTTPS unless the host is a numeric loopback address.
    /// Control clients do not follow redirects. For private PKI, set
    /// `CHIO_CONTROL_TLS_ROOT_CA_FILE` to a regular, non-symlink PEM CA bundle.
    /// The configured bundle replaces the ambient public WebPKI roots.
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

    /// Independently pinned exact current capability-authority signer for fresh
    /// remote lookup envelopes and hosted MCP local-authority epoch matching.
    #[arg(
        long,
        global = true,
        env = "CHIO_CONTROL_AUTHORITY_PUBLIC_KEY",
        value_parser = parse_control_authority_public_key
    )]
    pub(crate) control_authority_public_key: Option<chio_core::PublicKey>,

    /// Previously active authority keys trusted only for durable remote artifacts.
    /// These keys cannot satisfy the current-signer pin. The complete current
    /// and historical bundle is limited to 256 unique keys.
    #[arg(
        long,
        global = true,
        env = "CHIO_CONTROL_AUTHORITY_TRUSTED_PUBLIC_KEYS",
        value_delimiter = ',',
        value_parser = parse_control_authority_public_key
    )]
    pub(crate) control_authority_trusted_public_keys: Vec<chio_core::PublicKey>,
}

fn parse_control_authority_public_key(value: &str) -> Result<chio_core::PublicKey, String> {
    chio_core::PublicKey::from_hex(value)
        .map_err(|error| format!("invalid control-authority public key: {error}"))
}

fn parse_threshold_proposal_authority_public_key(
    value: &str,
) -> Result<chio_core::PublicKey, String> {
    chio_core::PublicKey::from_hex(value)
        .map_err(|error| format!("invalid threshold proposal-authority public key: {error}"))
}

impl Cli {
    pub(crate) fn json_output(&self) -> bool {
        self.json || matches!(self.format, OutputFormat::Json)
    }
}

#[cfg(test)]
mod cli_env_tests {
    use super::*;
    use clap::CommandFactory as _;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Parse a `chio` argv into [`Cli`] on a thread with an 8 MiB stack.
    ///
    /// The release binary parses argv on the process main thread (8 MiB
    /// stack); the libtest harness runs each test on a worker thread with a
    /// ~2 MiB stack, which the monomorphised clap parser for the 24-variant
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
            "--cage-policy",
            "cage-policy.json",
            "--cage-policy-signer",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
    fn mcp_serve_http_parses_dedicated_resume_hmac_keyring() {
        let parsed = parse_cli([
            "chio",
            "--session-db",
            "sessions.sqlite3",
            "--resume-hmac-keyring",
            "resume-hmac-keyring.json",
            "mcp",
            "serve-http",
            "--policy",
            "policy.yaml",
            "--server-id",
            "mcp",
            "--cage-policy",
            "cage-policy.json",
            "--cage-policy-signer",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/bin/true",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        assert_eq!(parsed.session_db, Some(PathBuf::from("sessions.sqlite3")));
        assert_eq!(
            parsed.resume_hmac_keyring,
            Some(PathBuf::from("resume-hmac-keyring.json"))
        );
        assert!(matches!(
            parsed.command,
            Commands::Mcp {
                command: McpCommands::ServeHttp { .. }
            }
        ));
    }

    #[test]
    fn remote_control_authority_keys_parse_at_the_cli_boundary() {
        let _guard = env_lock();
        let prior_current = std::env::var_os("CHIO_CONTROL_AUTHORITY_PUBLIC_KEY");
        let prior_trusted = std::env::var_os("CHIO_CONTROL_AUTHORITY_TRUSTED_PUBLIC_KEYS");
        let current = chio_core::Keypair::from_seed(&[41_u8; 32]).public_key();
        let previous = chio_core::Keypair::from_seed(&[42_u8; 32]).public_key();
        std::env::set_var("CHIO_CONTROL_AUTHORITY_PUBLIC_KEY", current.to_hex());
        std::env::set_var(
            "CHIO_CONTROL_AUTHORITY_TRUSTED_PUBLIC_KEYS",
            format!("{},{}", previous.to_hex(), current.to_hex()),
        );

        let parsed = parse_cli(["chio", "run", "--policy", "policy.yaml", "/bin/true"])
            .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        assert_eq!(parsed.control_authority_public_key.as_ref(), Some(&current));
        assert_eq!(
            parsed.control_authority_trusted_public_keys,
            vec![previous, current]
        );

        restore_env("CHIO_CONTROL_AUTHORITY_PUBLIC_KEY", prior_current);
        restore_env("CHIO_CONTROL_AUTHORITY_TRUSTED_PUBLIC_KEYS", prior_trusted);
    }

    #[test]
    fn remote_control_long_help_states_transport_and_authority_contracts() {
        let help = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| Cli::command().render_long_help().to_string())
            .unwrap_or_else(|error| panic!("spawn 8 MiB help thread: {error}"))
            .join()
            .unwrap_or_else(|_| panic!("help thread must not panic"));

        for required in [
            "CHIO_CONTROL_TLS_ROOT_CA_FILE",
            "numeric loopback",
            "do not follow redirects",
            "exact current capability-authority signer",
            "cannot satisfy the current-signer pin",
            "256 unique keys",
        ] {
            assert!(help.contains(required), "long help omits `{required}`");
        }
    }

    #[test]
    fn ordinary_admission_authorities_parse_at_the_cli_boundary() {
        let proposal_authority = chio_core::Keypair::from_seed(&[43_u8; 32]).public_key();
        let proposal_authority_hex: &'static str =
            Box::leak(proposal_authority.to_hex().into_boxed_str());
        let parsed = parse_cli([
            "chio",
            "--aggregate-invocation-admission",
            "--admission-operation-db",
            "operations.sqlite3",
            "--approval-db",
            "approvals.sqlite3",
            "--approver-directory",
            "approvers.yaml",
            "--threshold-proposal-authority-public-key",
            proposal_authority_hex,
            "run",
            "--policy",
            "policy.yaml",
            "/bin/true",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        assert!(parsed.aggregate_invocation_admission);
        assert_eq!(
            parsed.admission_operation_db.as_deref(),
            Some(std::path::Path::new("operations.sqlite3"))
        );
        assert_eq!(
            parsed.approval_db.as_deref(),
            Some(std::path::Path::new("approvals.sqlite3"))
        );
        assert_eq!(
            parsed.approver_directory.as_deref(),
            Some(std::path::Path::new("approvers.yaml"))
        );
        assert_eq!(
            parsed.threshold_proposal_authority_public_key.as_ref(),
            Some(&proposal_authority)
        );
    }

    #[test]
    fn receipt_retention_repair_uses_the_advertised_nested_command() {
        let parsed = parse_cli([
            "chio",
            "receipt",
            "retention",
            "repair",
            "--archive",
            "archive.sqlite3",
        ]);
        assert!(
            parsed.is_ok(),
            "advertised `chio receipt retention repair` must parse: {:?}",
            parsed.err().map(|error| error.to_string())
        );
        assert!(
            parse_cli(["chio", "receipt", "retention-repair", "--archive", "a.sqlite3"])
                .is_err(),
            "the flat `retention-repair` spelling must not be accepted"
        );
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

    #[test]
    fn parses_keyring_runtime_configuration_path() {
        let parsed = parse_cli([
            "chio",
            "--authority-seed-file",
            "authority.seed",
            "--keyring-config",
            "keyring.yaml",
            "run",
            "--policy",
            "policy.yaml",
            "echo",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));
        assert_eq!(
            parsed.keyring_config.as_deref(),
            Some(std::path::Path::new("keyring.yaml"))
        );
        assert_eq!(
            parsed.authority_seed_file.as_deref(),
            Some(std::path::Path::new("authority.seed"))
        );
    }

    #[test]
    fn settle_drive_requires_at_least_one_trusted_kernel_public_key() {
        let parsed = parse_cli([
            "chio",
            "settle",
            "drive",
            "--iou-issuer-seed-file",
            "iou-issuer.seed",
        ]);
        assert!(parsed.is_err(), "settle drive must fail closed without a trust root");
    }

    #[test]
    fn settle_drive_requires_an_existing_iou_issuer_seed_argument() {
        let parsed = parse_cli([
            "chio",
            "settle",
            "drive",
            "--trusted-kernel-pubkey",
            "current.pub",
        ]);
        assert!(
            parsed.is_err(),
            "settle drive must require explicit IOU signing custody"
        );
    }

    #[test]
    fn settle_drive_accepts_current_and_historical_kernel_public_keys() {
        let parsed = parse_cli([
            "chio",
            "settle",
            "drive",
            "--iou-issuer-seed-file",
            "iou-issuer.seed",
            "--trusted-kernel-pubkey",
            "current.pub",
            "--trusted-kernel-pubkey",
            "historical.pub",
            "--trusted-iou-issuer-pubkey",
            "old-iou.pub",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));

        match parsed.command {
            Commands::Settle {
                command:
                    SettleCommands::Drive {
                        iou_issuer_seed_file,
                        trusted_kernel_pubkeys,
                        trusted_iou_issuer_pubkeys,
                        ..
                    },
            } => {
                assert_eq!(iou_issuer_seed_file, PathBuf::from("iou-issuer.seed"));
                assert_eq!(
                    trusted_kernel_pubkeys,
                    vec![PathBuf::from("current.pub"), PathBuf::from("historical.pub")]
                );
                assert_eq!(
                    trusted_iou_issuer_pubkeys,
                    vec![PathBuf::from("old-iou.pub")]
                );
            }
            _ => panic!("expected settle drive command"),
        }
    }

    #[test]
    fn settle_status_and_drive_reject_unbounded_counts() {
        assert!(parse_cli([
            "chio",
            "settle",
            "status",
            "--limit",
            "0",
        ])
        .is_err());
        assert!(parse_cli([
            "chio",
            "settle",
            "drive",
            "--iou-issuer-seed-file",
            "iou.seed",
            "--trusted-kernel-pubkey",
            "kernel.pub",
            "--batch",
            "4097",
        ])
        .is_err());
    }

    #[test]
    fn broker_product_configuration_is_explicit_and_global_for_mcp_runtimes() {
        let parsed_stdio = parse_cli([
            "chio",
            "--broker-config",
            "/etc/chio/broker-product.json",
            "mcp",
            "serve",
            "--policy",
            "policy.yaml",
            "--signed-manifest",
            "manifest.json",
            "--manifest-public-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--cage-policy",
            "cage-policy.json",
            "--cage-policy-signer",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/bin/true",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));
        assert_eq!(
            parsed_stdio.broker_config.as_deref(),
            Some(std::path::Path::new("/etc/chio/broker-product.json"))
        );

        let parsed_http = parse_cli([
            "chio",
            "mcp",
            "serve-http",
            "--policy",
            "policy.yaml",
            "--server-id",
            "upstream",
            "--signed-manifest",
            "manifest.json",
            "--manifest-public-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--cage-policy",
            "cage-policy.json",
            "--cage-policy-signer",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--broker-config",
            "/etc/chio/broker-product.json",
            "/bin/true",
        ])
        .unwrap_or_else(|error| panic!("CLI parse failed: {error}"));
        assert_eq!(
            parsed_http.broker_config.as_deref(),
            Some(std::path::Path::new("/etc/chio/broker-product.json"))
        );
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

    /// Inventory signed manifests and emit active-defense migration evidence.
    Security {
        #[command(subcommand)]
        command: SecurityCommands,
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
    /// state is `reconciled`), and dead-lettered settlements (rows in
    /// `settle_dead_letters`).
    Settle {
        #[command(subcommand)]
        command: SettleCommands,
    },

    /// Inspect and release capability budget holds in the durable budget store.
    Budget {
        #[command(subcommand)]
        command: BudgetCommands,
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
    /// - durable receipts by default (pass `--allow-ephemeral-receipts` for
    ///   the in-memory quickstart that leaves no on-disk artifacts);
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

        /// Optional SQLite receipt store path for a durable audit log.
        #[arg(long = "receipt-store")]
        receipt_store: Option<PathBuf>,

        /// Permit in-memory receipts, whose audit evidence is lost on every restart.
        #[arg(long, default_value_t = false)]
        allow_ephemeral_receipts: bool,

        /// Print the chio-hermes config snippet (env vars + slash
        /// commands) on startup so users can copy/paste into their
        /// shell before running their agent. Off by default to keep
        /// the banner short.
        #[arg(long, default_value_t = false)]
        print_config: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SecurityCommands {
    /// Verify registry evidence and atomically write a deterministic migration report.
    ShadowMigrate {
        /// Closed JSON inventory containing registered keys, manifests, receipts, and observations.
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Destination for the canonical JSON report.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },

    /// Provision a signed native MCP demo at migration stage Disabled.
    ///
    /// Disabled is legacy-authorized demo mode, not cage containment. The
    /// command creates demo-only private signers and must not be used as a
    /// production containment claim.
    ProvisionNativeMcpDemo {
        /// New absolute output directory, or an exact prior provision for an idempotent rerun.
        #[arg(long, value_name = "PATH")]
        output_dir: PathBuf,

        /// Exact absolute non-symlink directory committed to runtime policy paths.
        ///
        /// Defaults to the output directory. Provisioned artifacts are always
        /// created and validated under the output directory.
        #[arg(long, value_name = "PATH")]
        runtime_security_dir: Option<PathBuf>,

        /// Reviewed JSON tools/list fixture used to build the signed manifest.
        #[arg(long, value_name = "PATH")]
        tools_fixture: PathBuf,

        /// Exact absolute canonical MCP server executable bound into the launch policy.
        #[arg(long, value_name = "PATH")]
        target: PathBuf,

        /// One exact target argv element after the executable. Repeat for multiple elements.
        #[arg(long = "target-arg", value_name = "VALUE", allow_hyphen_values = true)]
        target_args: Vec<String>,

        /// Exact absolute canonical working directory. Defaults to the target's parent.
        #[arg(long, value_name = "PATH")]
        working_directory: Option<PathBuf>,

        /// Exact non-root UID applied to the target before sandboxing.
        #[arg(long, value_name = "UID")]
        execution_uid: u32,

        /// Exact non-root primary GID applied to the target before sandboxing.
        #[arg(long, value_name = "GID")]
        execution_gid: u32,

        /// Supplementary target GID in sorted ascending order. Repeat for multiple groups.
        #[arg(long = "execution-supplementary-gid", value_name = "GID")]
        execution_supplementary_gids: Vec<u32>,

        /// Server identifier committed to the manifest, policy, and migration ledger.
        #[arg(long, default_value = "docker-demo")]
        server_id: String,

        /// Human-readable server name committed to the signed manifest.
        #[arg(long, default_value = "Docker demo MCP")]
        server_name: String,

        /// Server version committed to the signed manifest.
        #[arg(long, default_value = "1")]
        server_version: String,
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
