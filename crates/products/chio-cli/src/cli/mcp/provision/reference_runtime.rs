//! `chio security provision-reference-runtime`: signed launch material for
//! one confined tool at an enforcing migration stage.
//!
//! The demo provisioner authorizes a launch without confining it. This
//! command binds a static position-independent cage helper, the target's
//! digest, argument list and working directory, the read and write grants
//! the manifest declares, and a migration ledger promoted through Shadow to
//! the requested stage, so the edge composes a cage-required launch from the
//! result on an enforcing host.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::{
    provision, require_exact_canonical_path, resolve_inputs, CageInitSource, ProvisionProfile,
    ProvisionedCeilings, ToolSurfaceSource,
};
use crate::CliError;

const REPORT_SCHEMA: &str = "chio.reference-runtime-provision-report.v1";
const ENFORCED_SECURITY_MODE: &str = "enforced_cage";
const ENFORCED_WARNING: &str = "The launch is confined only on a host that enforces the cage; the private signers in this directory belong to the operator and stay root-only.";
const SHADOW_SECURITY_MODE: &str = "shadow_legacy_authorized";
const SHADOW_WARNING: &str = "Shadow stage authorizes a legacy launch while the ledger records the cage posture; it is not containment.";

/// The migration stage the ledger is promoted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProvisionStage {
    /// Legacy launch recorded against the cage posture.
    Shadow,
    /// Cage-required launch.
    Enforced,
}

/// Arguments for `chio security provision-reference-runtime`.
#[derive(clap::Args, Debug)]
pub(crate) struct ProvisionReferenceRuntimeArgs {
    /// Directory to create with every artifact; an existing one is revalidated.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,

    /// Directory the runtime reads the ledger and receipt material from, when
    /// it differs from the output directory.
    #[arg(long, value_name = "PATH")]
    pub runtime_security_dir: Option<PathBuf>,

    /// Static position-independent `chio-cage-init` the policy binds.
    #[arg(long, value_name = "PATH")]
    pub cage_init: PathBuf,

    /// Reviewed `tools/list` fixture of the target.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "discover_tools",
        conflicts_with = "discover_tools"
    )]
    pub tools_fixture: Option<PathBuf>,

    /// Spawn the target once and review its own `tools/list`.
    #[arg(long)]
    pub discover_tools: bool,

    /// The wrapped MCP server executable.
    #[arg(long, value_name = "PATH")]
    pub target: PathBuf,

    /// Arguments of the wrapped server, in order.
    #[arg(long = "target-arg", value_name = "VALUE", allow_hyphen_values = true)]
    pub target_args: Vec<String>,

    /// Working directory of the wrapped server; its parent directory by default.
    #[arg(long, value_name = "PATH")]
    pub working_directory: Option<PathBuf>,

    /// A path the wrapped server may read; repeat for each grant.
    #[arg(long = "read-path", value_name = "PATH")]
    pub read_paths: Vec<PathBuf>,

    /// A path the wrapped server may write; repeat for each grant.
    #[arg(long = "write-path", value_name = "PATH")]
    pub write_paths: Vec<PathBuf>,

    /// Interpreter or shared object a dynamically linked target needs; each
    /// must also be a read path. A static target needs none.
    #[arg(long = "runtime-file", value_name = "PATH")]
    pub runtime_files: Vec<PathBuf>,

    #[arg(long, value_name = "UID")]
    pub execution_uid: u32,

    #[arg(long, value_name = "GID")]
    pub execution_gid: u32,

    #[arg(long = "execution-supplementary-gid", value_name = "GID")]
    pub execution_supplementary_gids: Vec<u32>,

    /// Server identifier the manifest and the policy bind.
    #[arg(long)]
    pub server_id: String,

    #[arg(long, default_value = "Chio reference tool")]
    pub server_name: String,

    #[arg(long, default_value = "1")]
    pub server_version: String,

    /// Stage the migration ledger is promoted to.
    #[arg(long, value_enum, default_value_t = ProvisionStage::Enforced)]
    pub stage: ProvisionStage,
}

pub(crate) fn cmd_provision_reference_runtime(
    args: &ProvisionReferenceRuntimeArgs,
) -> Result<(), CliError> {
    let ceilings = ProvisionedCeilings {
        read_paths: grant_set(&args.read_paths, "read path")?,
        write_paths: grant_set(&args.write_paths, "write path")?,
        runtime_files: grant_set(&args.runtime_files, "runtime file")?,
    };
    if let Some(file) = ceilings
        .runtime_files
        .iter()
        .find(|file| !ceilings.read_paths.contains(*file))
    {
        return Err(CliError::cli_other_error(format!(
            "runtime file {} must also be declared with --read-path",
            file.display()
        )));
    }
    let (stage, security_mode, warning) = match args.stage {
        ProvisionStage::Shadow => (
            chio_security_types::EnterpriseMigrationStage::Shadow,
            SHADOW_SECURITY_MODE,
            SHADOW_WARNING,
        ),
        ProvisionStage::Enforced => (
            chio_security_types::EnterpriseMigrationStage::Enforced,
            ENFORCED_SECURITY_MODE,
            ENFORCED_WARNING,
        ),
    };
    let profile = ProvisionProfile {
        report_schema: REPORT_SCHEMA,
        security_mode,
        warning,
        deployment_id_prefix: "chio.reference-runtime.",
        receipt_capability_id: "reference-runtime-launch",
        receipt_tenant_id: None,
        stage,
        cage_init: CageInitSource::Helper(args.cage_init.clone()),
        ceilings,
    };
    let inputs = resolve_inputs(
        profile,
        &args.output_dir,
        args.runtime_security_dir.as_deref(),
        match (&args.tools_fixture, args.discover_tools) {
            (Some(fixture), false) => ToolSurfaceSource::Fixture(fixture),
            _ => ToolSurfaceSource::Discovered,
        },
        &args.target,
        &args.target_args,
        args.working_directory.as_deref(),
        args.execution_uid,
        args.execution_gid,
        &args.execution_supplementary_gids,
        &args.server_id,
        &args.server_name,
        &args.server_version,
    )?;
    provision(&inputs)
}

/// Grants are exact canonical paths that exist, each named once.
fn grant_set(paths: &[PathBuf], label: &str) -> Result<BTreeSet<PathBuf>, CliError> {
    let mut grants = BTreeSet::new();
    for path in paths {
        let canonical = require_exact_canonical_path(path, label)?;
        if !grants.insert(canonical) {
            return Err(CliError::cli_other_error(format!(
                "{label} {} is declared more than once",
                path.display()
            )));
        }
    }
    Ok(grants)
}
