//! Signed launch material for one wrapped MCP command.
//!
//! The probe loads the signed manifest and the signed native-launch policy the
//! way the edge does at startup: signatures against the pinned keys, the
//! policy's target and argv against the wrapped command, the migration
//! ledger the policy names, and the server identity. What the edge would
//! refuse, the preflight reports before the launch.

use std::path::PathBuf;
use std::sync::Arc;

use super::super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

/// The material one launch presents.
#[derive(Debug, Clone)]
pub struct LaunchMaterial {
    pub signed_manifest: PathBuf,
    pub manifest_public_key: String,
    pub cage_policy: PathBuf,
    pub cage_policy_signer: String,
    pub server_id: String,
    pub command: String,
    pub args: Vec<String>,
}

/// Load the material the way the edge does and return how it authorizes the launch.
pub fn load_launch(material: &LaunchMaterial) -> Result<(), String> {
    let registry = chio_manifest::load_existing_verified_manifest_registry(
        &material.signed_manifest,
        &material.manifest_public_key,
        &material.server_id,
        chio_manifest::RuntimeToolTopology::local(),
    )
    .map_err(|error| format!("signed manifest: {error}"))?;
    let args: Vec<&str> = material.args.iter().map(String::as_str).collect();
    let launch = crate::mcp_cli::load_native_mcp_launch(
        &material.cage_policy,
        &material.cage_policy_signer,
        &material.command,
        &args,
        Some(Arc::new(registry)),
    )
    .map_err(|error| format!("native launch policy: {error}"))?;
    if launch.server_id() != material.server_id {
        return Err(format!(
            "native launch policy belongs to server {} rather than {}",
            launch.server_id(),
            material.server_id
        ));
    }
    Ok(())
}

/// Reports whether the signed launch material authorizes the wrapped command.
pub struct NativeLaunchProbe {
    material: Option<LaunchMaterial>,
}

impl NativeLaunchProbe {
    pub fn new(material: Option<LaunchMaterial>) -> Self {
        Self { material }
    }
}

impl Probe for NativeLaunchProbe {
    fn name(&self) -> &'static str {
        "security.native_launch"
    }

    fn run(&self, _config: &ProbeConfig) -> ProbeReport {
        let Some(material) = &self.material else {
            return ProbeReport::fail(
                self.name(),
                ProbeSeverity::Info,
                "urn:chio:error:cli:other",
                "no signed launch material was given, so the launch policy was not checked",
            )
            .with_help(
                "pass --signed-manifest, --manifest-public-key, --cage-policy, --cage-policy-signer, --server-id and the wrapped command after --",
            );
        };
        let outcome = load_launch(material);
        let kind = outcome.as_ref().map_or("refused", |()| "cage_required");
        let report = match outcome {
            Ok(()) => ProbeReport::ok(
                self.name(),
                "the signed launch material authorizes the wrapped command under the cage",
            ),
            Err(reason) => ProbeReport::fail(
                self.name(),
                ProbeSeverity::Error,
                "urn:chio:error:cli:other",
                format!("the edge would refuse this launch: {reason}"),
            )
            .with_help("provision the material for this exact command and server, and pin the keys that signed it"),
        };
        report
            .with_context("server_id", material.server_id.clone())
            .with_context("command", command_line(&material.command, &material.args))
            .with_context("launch", kind)
            .with_context(
                "signed_manifest",
                material.signed_manifest.display().to_string(),
            )
            .with_context("cage_policy", material.cage_policy.display().to_string())
    }
}

fn command_line(command: &str, args: &[String]) -> String {
    std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}
