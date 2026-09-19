//! `chio security preflight`: prove a host, its credentials, its signed launch
//! material and its durable stores before the confined runtime starts.
//!
//! The command reuses the doctor framework: every check is one probe with a
//! severity, the report renders as text or as the doctor JSON envelope, and
//! the process exit code follows the worst severity, so a supervisor can gate
//! a launch on it.

use std::path::PathBuf;

use crate::doctor::security::{preflight_runner, LaunchMaterial, NamedStore, PreflightRequest};
use crate::doctor::ProbeConfig;
use crate::CliError;
use crate::{render_doctor_json, render_titled_human};

/// Arguments for `chio security preflight`.
#[derive(clap::Args, Debug)]
pub struct PreflightArgs {
    /// Emit the doctor JSON envelope on stdout instead of human text.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Fail when the host cannot enforce the cage or the launch material
    /// authorizes without confining. Without it those findings are warnings,
    /// which is what a developer host provisioning at migration stage
    /// Disabled expects.
    #[arg(long, default_value_t = false)]
    pub require_enforcement: bool,

    /// Publisher-signed manifest of the wrapped server.
    #[arg(long, value_name = "PATH", requires = "manifest_public_key")]
    pub signed_manifest: Option<PathBuf>,

    /// Independently registered public key that signed the manifest.
    #[arg(long, value_name = "PUBLIC_KEY", requires = "signed_manifest")]
    pub manifest_public_key: Option<String>,

    /// Canonical signed native-launch policy for the wrapped server.
    #[arg(long, value_name = "PATH", requires = "cage_policy_signer")]
    pub cage_policy: Option<PathBuf>,

    /// Independently pinned public key for the native-launch policy signer.
    #[arg(long, value_name = "PUBLIC_KEY", requires = "cage_policy")]
    pub cage_policy_signer: Option<String>,

    /// Server identifier the manifest and policy must belong to.
    #[arg(long, value_name = "SERVER_ID")]
    pub server_id: Option<String>,

    /// The wrapped MCP server command and its arguments, exactly as the
    /// launch passes them after `--`.
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// The durable stores the launch names through the global options.
#[derive(Debug, Default)]
pub struct PreflightStores {
    pub receipt_db: Option<PathBuf>,
    pub session_db: Option<PathBuf>,
    pub authority_db: Option<PathBuf>,
}

impl PreflightArgs {
    fn launch_material(&self) -> Result<Option<LaunchMaterial>, CliError> {
        let given = [
            self.signed_manifest.is_some(),
            self.cage_policy.is_some(),
            self.server_id.is_some(),
            !self.command.is_empty(),
        ];
        if given.iter().all(|present| !present) {
            return Ok(None);
        }
        let (Some(signed_manifest), Some(manifest_public_key), Some(cage_policy), Some(cage_policy_signer), Some(server_id), Some((command, args))) = (
            self.signed_manifest.clone(),
            self.manifest_public_key.clone(),
            self.cage_policy.clone(),
            self.cage_policy_signer.clone(),
            self.server_id.clone(),
            self.command.split_first(),
        ) else {
            return Err(CliError::cli_other_error(
                "checking launch material needs --signed-manifest, --manifest-public-key, --cage-policy, --cage-policy-signer, --server-id and the wrapped command after --"
                    .to_string(),
            ));
        };
        Ok(Some(LaunchMaterial {
            signed_manifest,
            manifest_public_key,
            cage_policy,
            cage_policy_signer,
            server_id,
            command: command.clone(),
            args: args.to_vec(),
        }))
    }
}

/// Entry point invoked from the security dispatch.
///
/// Like `chio doctor`, the process exit code is the worst severity: 0 for ok,
/// info or warning, 1 for error, 2 for fatal, and the JSON envelope carries
/// the same number.
pub fn cmd_security_preflight(
    args: &PreflightArgs,
    stores: PreflightStores,
    json_output: bool,
) -> Result<(), CliError> {
    let launch = args.launch_material()?;
    let stores = [
        ("receipt_db", stores.receipt_db),
        ("session_db", stores.session_db),
        ("authority_db", stores.authority_db),
    ]
    .into_iter()
    .filter_map(|(label, path)| path.map(|path| NamedStore { label, path }))
    .collect();
    let runner = preflight_runner(
        ProbeConfig::default(),
        PreflightRequest {
            require_enforcement: args.require_enforcement,
            launch,
            stores,
        },
    );
    let run = runner.run();

    {
        let mut stdout = std::io::stdout().lock();
        let rendered = if args.json || json_output {
            render_doctor_json(&mut stdout, &run)
        } else {
            render_titled_human(&mut stdout, "chio security preflight", &run)
        };
        rendered.map_err(|error| {
            CliError::cli_other_error(format!("preflight: failed to render the report: {error}"))
        })?;
    }

    let code = run.exit_code();
    if code == 0 {
        Ok(())
    } else {
        std::process::exit(code);
    }
}
