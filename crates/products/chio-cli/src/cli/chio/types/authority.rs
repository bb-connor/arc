use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ChioAuthorityCommands {
    /// Create an operator-pinned public checkpoint for signed cluster replication.
    ReplicationInit {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        stream_id: String,
        #[arg(long)]
        out: PathBuf,
        /// Independent recovery root, pinned permanently in the new stream.
        #[arg(long)]
        recovery_public_key: Option<String>,
    },
    /// Rotate the local issuer with a bounded verification deadline.
    IssuerRotate {
        #[arg(long)]
        database: PathBuf,
        /// Exclusive Unix-second deadline; defaults to one hour of overlap.
        #[arg(long)]
        verify_until: Option<u64>,
    },
    /// Permanently retire a historical issuer in an initialized stream.
    IssuerRetire {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        public_key: String,
    },
    /// Revoke a historical issuer while retaining its public audit history.
    IssuerRevoke {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        public_key: String,
    },
    /// Use the independently pinned recovery root to replace all old issuers.
    IssuerRecover {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        recovery_key_file: PathBuf,
    },
    /// Pin an independently authenticated checkpoint on a follower (local only).
    ReplicationPin {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        anchor: PathBuf,
        /// Canonical checkpoint digest obtained through a separate trusted channel.
        #[arg(long)]
        expected_anchor_digest: String,
    },
    /// Issue capability leases, lease-scope bindings, and governance receipts.
    Issue {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Chio issuance request JSON.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,

        /// Local signing-key JSON. Keep this outside committed fixtures.
        #[arg(long, value_name = "PATH")]
        signing_keys: PathBuf,

        /// Output directory for the issuance bundle and split artifacts.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },

    /// Publish a signed revocation checkpoint from local authority state.
    Checkpoint {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Revocation publication request JSON.
        #[arg(long, value_name = "PATH")]
        revocations: PathBuf,

        /// Local signing-key JSON. Keep this outside committed fixtures.
        #[arg(long, value_name = "PATH")]
        signing_keys: PathBuf,

        /// Output path for the signed checkpoint JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Assemble verifier-owned trust inputs.
    TrustBundle {
        #[command(subcommand)]
        command: ChioTrustBundleCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioTrustBundleCommands {
    /// Assemble a strict verifier trust bundle.
    Assemble {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Verifier-owned peer, vendor, and action-class pins JSON.
        #[arg(long, value_name = "PATH")]
        peer_pins: PathBuf,

        /// Workflow intersection artifact JSON.
        #[arg(long, value_name = "PATH")]
        workflow_intersection: PathBuf,

        /// Disclosure policy JSON.
        #[arg(long, value_name = "PATH")]
        disclosure_policy: PathBuf,

        /// Signed revocation checkpoint JSON.
        #[arg(long, value_name = "PATH")]
        checkpoint: PathBuf,

        /// Output path for the verifier trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}
