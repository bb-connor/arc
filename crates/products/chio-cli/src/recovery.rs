//! Thin transport to the trusted Rust recovery host, with no local decisions.
use crate::CliError;
use chio_egress_contract::{
    ContractResponse, HttpEgressContract, client_builder_with_contract, send_with_contract,
};
use clap::Subcommand;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Subcommand)]
pub(crate) enum RecoveryCommands {
    /// Prove native protected setup, then qualify after an operator writer restart.
    Setup {
        #[command(subcommand)]
        command: SetupCommands,
    },
    /// Read signed audience-safe advice. Native resume rechecks current facts.
    Explain {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        capability: PathBuf,
        #[arg(long)]
        workflow_id: String,
    },
    /// Submit or replay one exact canonical command. Retain its ID on ambiguity.
    Command {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        capability: PathBuf,
        #[arg(long)]
        command: PathBuf,
    },
    /// Read the full exact preview under current approval authority.
    Review {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        capability: PathBuf,
        #[arg(long)]
        workflow_id: String,
    },
    /// Reconcile the original operation under current settlement authority.
    Settle {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        capability: PathBuf,
        #[arg(long)]
        workflow_id: String,
    },
}
#[derive(Debug, Subcommand)]
pub(crate) enum SetupCommands {
    /// Run the operator-pinned model-free benign and refused commands.
    Probe {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        capability: PathBuf,
        #[arg(long)]
        workflow_id: String,
        /// Independently trusted setup operator public key, as hex.
        #[arg(long, value_name = "HEX_PUBLIC_KEY")]
        operator_key: Option<String>,
    },
    /// Recover the same operation; readiness requires a pinned operator key.
    Qualify {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        capability: PathBuf,
        #[arg(long)]
        probe: PathBuf,
        /// Independently trusted setup operator public key, as hex.
        #[arg(long, value_name = "HEX_PUBLIC_KEY")]
        operator_key: Option<String>,
    },
}
fn refused() -> CliError {
    CliError::cli_other_error(
        "recovery transport refused or unavailable; retain the original command identity",
    )
}
fn bounded(path: &Path, limit: usize) -> Result<String, CliError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(refused());
    }
    String::from_utf8(bytes).map_err(|_| refused())
}

fn host_egress_contract(
    url: &reqwest::Url,
    local: bool,
    capability: &chio_core_types::capability::token::CapabilityToken,
) -> Result<HttpEgressContract, CliError> {
    let host = match url.host().ok_or_else(refused)? {
        url::Host::Domain(host) => host.trim_end_matches('.').to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => format!("[{address}]"),
    };
    let port = url.port_or_known_default().ok_or_else(refused)?;
    let authority = format!("{host}:{port}");
    let capability_body =
        chio_core_types::canonical_json_bytes(&capability.signing_body()).map_err(|_| refused())?;
    let identity = Sha256::digest(&capability_body);
    let contract = HttpEgressContract {
        tenant_egress_namespace: format!("recovery.client:{identity:x}:{authority}"),
        allowed_schemes: BTreeSet::from([url.scheme().to_owned()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: !local,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 262144,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .and_then(|()| contract.enforce_url(url.as_str(), 0).map(|_| ()))
        .map_err(|_| refused())?;
    Ok(contract)
}

struct TransportRuntime {
    runtime: Option<tokio::runtime::Runtime>,
}

impl TransportRuntime {
    fn new() -> Result<Self, ()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ())?;
        Ok(Self {
            runtime: Some(runtime),
        })
    }

    fn runtime(&self) -> Result<&tokio::runtime::Runtime, ()> {
        self.runtime.as_ref().ok_or(())
    }
}

impl Drop for TransportRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // A timed-out OS lookup may still be running on a blocking task.
            // Shutdown must release the transport caller on every exit path.
            runtime.shutdown_background();
        }
    }
}

fn dispatch(
    contract: &HttpEgressContract,
    url: reqwest::Url,
    bytes: Vec<u8>,
    timeout: Duration,
) -> Result<ContractResponse, CliError> {
    // A separate runtime thread also permits callers already inside Tokio.
    #[cfg(test)]
    let fixture = deadline_tests::fixture_for(&url);
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("chio-recovery-transport".to_owned())
            .spawn_scoped(scope, move || {
                let runtime = TransportRuntime::new()?;
                #[cfg(test)]
                if let Some(fixture) = &fixture {
                    fixture.start_blocking_lookup(runtime.runtime()?);
                }
                runtime.runtime()?.block_on(async move {
                    let client = client_builder_with_contract(contract)
                        .no_retries()
                        .timeout(timeout)
                        .build()
                        .map_err(|_| ())?;
                    let request = client
                        .post(url)
                        .header("content-type", "application/json")
                        .body(bytes)
                        .build()
                        .map_err(|_| ())?;
                    #[cfg(test)]
                    if let Some(fixture) = &fixture {
                        fixture.mark_dispatch_started();
                    }
                    tokio::time::timeout(timeout, send_with_contract(contract, &client, request))
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())
                })
            })
            .map_err(|_| refused())?
            .join()
            .map_err(|_| refused())?
            .map_err(|()| refused())
    })
}

pub(crate) fn run(command: RecoveryCommands) -> Result<(), CliError> {
    let (endpoint, capability, path, body, operator_key) = match command {
        RecoveryCommands::Setup {
            command:
                SetupCommands::Probe {
                    endpoint,
                    capability,
                    workflow_id,
                    operator_key,
                },
        } => (
            endpoint,
            capability,
            "setup/probe",
            ("workflow_id", workflow_id),
            operator_key,
        ),
        RecoveryCommands::Setup {
            command:
                SetupCommands::Qualify {
                    endpoint,
                    capability,
                    probe,
                    operator_key,
                },
        } => {
            let proof = bounded(&probe, 32768)?;
            let _: chio_core_types::recovery::SignedRecoverySetupProbeV1 =
                chio_core_types::recovery::decode_contract(proof.as_bytes())
                    .map_err(|_| refused())?;
            (
                endpoint,
                capability,
                "setup/qualify",
                ("probe", proof),
                operator_key,
            )
        }
        RecoveryCommands::Explain {
            endpoint,
            capability,
            workflow_id,
        } => (
            endpoint,
            capability,
            "explain",
            ("workflow_id", workflow_id),
            None,
        ),
        RecoveryCommands::Command {
            endpoint,
            capability,
            command,
        } => (
            endpoint,
            capability,
            "commands",
            ("command", bounded(&command, 32768)?),
            None,
        ),
        RecoveryCommands::Review {
            endpoint,
            capability,
            workflow_id,
        } => (
            endpoint,
            capability,
            "review",
            ("workflow_id", workflow_id),
            None,
        ),
        RecoveryCommands::Settle {
            endpoint,
            capability,
            workflow_id,
        } => (
            endpoint,
            capability,
            "settle",
            ("workflow_id", workflow_id),
            None,
        ),
    };
    let operator_key = operator_key
        .map(|key| chio_core_types::PublicKey::from_hex(&key).map_err(|_| refused()))
        .transpose()?;
    let mut url = reqwest::Url::parse(&endpoint).map_err(|_| refused())?;
    let local = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(refused());
    }
    // A service base is a directory, including a slashless mount path.
    // Appending an empty segment preserves already encoded path segments.
    if !url.path().ends_with('/') {
        url.path_segments_mut().map_err(|()| refused())?.push("");
    }
    let url = url
        .join(&format!("v1/recovery/{path}"))
        .map_err(|_| refused())?;
    let capability = bounded(&capability, 32768)?;
    let parsed_capability =
        chio_core_types::recovery::decode_recovery_capability(capability.as_bytes())
            .map_err(|_| refused())?;
    let egress_contract = host_egress_contract(&url, local, &parsed_capability)?;
    let wire: Value = serde_json::json!({"capability":capability,body.0:body.1});
    let bytes = chio_core_types::canonical_json_bytes(&wire).map_err(|_| refused())?;
    if bytes.len() > 65536 {
        return Err(refused());
    }
    let response = dispatch(
        &egress_contract,
        url,
        bytes,
        Duration::from_secs(if path.starts_with("setup/") { 120 } else { 20 }),
    )?;
    let status = response.status();
    let bytes = response.body();
    if !status.is_success() {
        // Only exact native status/category pairs cross into operator output.
        // Arbitrary upstream diagnostics and credentials stay private.
        return Err(match (status.as_u16(), bytes) {
            (400, b"recovery.invalid_command") => CliError::cli_other_error(
                "recovery.invalid_command: the native host rejected the command encoding or fields",
            ),
            (403, b"recovery.authority_denied") => CliError::cli_other_error(
                "recovery.authority_denied: current authority does not permit this action",
            ),
            (409, b"recovery.conflict") => CliError::cli_other_error(
                "recovery.conflict: the command conflicts with current state; retain its identity and refresh native advice",
            ),
            (409, b"recovery.unsupported_profile") => CliError::cli_other_error(
                "recovery.unsupported_profile: the native host does not support this recovery profile",
            ),
            (409, b"recovery.uncovered_mediation") => CliError::cli_other_error(
                "recovery.uncovered_mediation: a required native mediator is unavailable",
            ),
            (409, b"recovery.restart_required") => CliError::cli_other_error(
                "recovery.restart_required: the operator must restart the native writer",
            ),
            (409, b"recovery.unknown_effect") => CliError::cli_other_error(
                "recovery.unknown_effect: the original operation remains uncertain; reconcile it without resubmission",
            ),
            (409, b"recovery.probe_expired") => CliError::cli_other_error(
                "recovery.probe_expired: the retained setup probe has expired; request a fresh probe",
            ),
            (409, b"recovery.origin_refused") => CliError::cli_other_error(
                "recovery.origin_refused: the native host refused the original process origin",
            ),
            (413, b"recovery.projection_too_large") => CliError::cli_other_error(
                "recovery.projection_too_large: the requested recovery projection exceeded public wire bounds",
            ),
            (503, b"recovery.unavailable") => CliError::cli_other_error(
                "recovery.unavailable: the native host is unavailable; retain the original command identity",
            ),
            (503, b"recovery.busy") => CliError::cli_other_error(
                "recovery.busy: the native host is busy; retain the original command identity",
            ),
            _ => refused(),
        });
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| refused())?;
    if path == "explain" {
        // Structural validation only. Selecting the trusted issuer/key and
        // recomputing a classified basis are separate inspector operations.
        let view: chio_core_types::recovery::SignedRecoveryExplanationViewV1 =
            chio_core_types::recovery::decode_contract(bytes).map_err(|_| refused())?;
        view.body().validate().map_err(|_| refused())?;
    }
    if path == "setup/probe" {
        let proof: chio_core_types::recovery::SignedRecoverySetupProbeV1 =
            chio_core_types::recovery::decode_contract(bytes).map_err(|_| refused())?;
        if !proof.verify_signature().map_err(|_| refused())?
            || proof.body().benign_workflow.as_str() != body.1.as_str()
            || operator_key
                .as_ref()
                .is_some_and(|key| proof.authority_key() != key)
        {
            return Err(refused());
        }
        if operator_key.is_some() {
            eprintln!(
                "Pinned operator signature verified. Native probe retained. The operator must restart the serving writer, then run setup qualify with this exact proof."
            );
        } else {
            eprintln!(
                "Untrusted signed native probe retained. Supply an independently trusted --operator-key to authenticate it. The operator must restart the serving writer, then run setup qualify with this exact proof."
            );
        }
    } else if path == "setup/qualify" {
        let proof: chio_core_types::recovery::SignedRecoverySetupReportV1 =
            chio_core_types::recovery::decode_contract(bytes).map_err(|_| refused())?;
        let supplied_probe: chio_core_types::recovery::SignedRecoverySetupProbeV1 =
            chio_core_types::recovery::decode_contract(body.1.as_bytes()).map_err(|_| refused())?;
        if !proof.verify_signature().map_err(|_| refused())?
            || !supplied_probe.verify_signature().map_err(|_| refused())?
            || proof.authority_key() != supplied_probe.authority_key()
            || &proof.body().probe != supplied_probe.body()
            || operator_key
                .as_ref()
                .is_some_and(|key| proof.authority_key() != key)
        {
            return Err(refused());
        }
        if operator_key.is_some() {
            eprintln!(
                "Pinned operator signature verified. Native readiness evidence returned. Current capabilities and mediation remain required for every action."
            );
        } else {
            eprintln!(
                "Untrusted signed setup report returned. Supply an independently trusted --operator-key to authenticate it. Current capabilities and mediation remain required for every action."
            );
        }
    }
    if path.starts_with("setup/") {
        // Emit the exact signature-verified native envelope, without a newline.
        // These bytes are the input to the strict canonical qualify decoder.
        std::io::stdout().write_all(bytes)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery/deadline_tests.rs"]
mod deadline_tests;
