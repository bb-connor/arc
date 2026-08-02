use super::*;
use chio_api_protect::DEFAULT_UPSTREAM_REQUEST_TIMEOUT;
use chio_manifest::{load_existing_verified_manifest_registry, RuntimeToolTopology};
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::mcp_cli::payment_config::PaymentAdapterConfig;

#[path = "runtime/trust_serve.rs"]
mod trust_serve;
pub(crate) use trust_serve::{cmd_trust_serve, load_roster_policy};

pub(crate) fn resolve_sidecar_payment_adapter(
) -> Result<Option<Box<dyn chio_kernel::PaymentAdapter>>, CliError> {
    let config = PaymentAdapterConfig::from_env().map_err(|error| {
        CliError::cli_other_error(format!("invalid payment adapter configuration: {error}"))
    })?;
    sidecar_payment_adapter_from_config(config)
}

fn sidecar_payment_adapter_from_config(
    config: Option<PaymentAdapterConfig>,
) -> Result<Option<Box<dyn chio_kernel::PaymentAdapter>>, CliError> {
    match config {
        Some(config) => {
            config.validate().map_err(|error| {
                CliError::cli_other_error(format!(
                    "invalid payment adapter configuration: {error}"
                ))
            })?;
            Ok(Some(config.build_adapter()))
        }
        None => Ok(None),
    }
}

fn is_in_memory_sqlite_path(path: &Path) -> bool {
    path.to_str()
        .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
}

fn require_durable_or_ephemeral_optin(
    receipt_store: Option<&Path>,
    allow_ephemeral_receipts: bool,
    authority_seed_path: Option<&Path>,
) -> Result<(), CliError> {
    let ephemeral_receipts = receipt_store.is_none_or(is_in_memory_sqlite_path);
    if ephemeral_receipts && !allow_ephemeral_receipts {
        return Err(CliError::cli_other_error(
            "refusing to start without durable receipts: pass --receipt-store <path> for a \
             durable audit log on a filesystem path, or --allow-ephemeral-receipts to run with \
             in-memory receipts that are lost on every restart"
                .to_string(),
        ));
    }
    if ephemeral_receipts {
        tracing::warn!(
            target: "chio::sidecar",
            "running with in-memory receipts (--allow-ephemeral-receipts): audit evidence is lost on every restart"
        );
    }
    if authority_seed_path.is_none() {
        tracing::warn!(
            target: "chio::sidecar",
            "no --authority-seed-file: a fresh signer is generated per boot, so receipts signed before a restart are unverifiable"
        );
    }
    Ok(())
}

pub(crate) fn opt_in_ephemeral_revocation_for_local_session(
    kernel: &mut ChioKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
) {
    let durable_backend = revocation_db_path.is_some_and(|path| !is_in_memory_sqlite_path(path))
        || control_url.is_some();
    if !durable_backend {
        kernel.opt_in_ephemeral_revocation_store();
    }
}

fn durable_receipt_db_path(receipt_store: Option<&Path>) -> Option<&Path> {
    receipt_store.filter(|path| !is_in_memory_sqlite_path(path))
}

pub(crate) fn compose_cli_ordinary_runtime_kernel(
    kernel: ChioKernel,
    enable_aggregate_invocation_admission: bool,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<ChioKernel, CliError> {
    chio_control_plane::compose_ordinary_admission_runtime(
        kernel,
        chio_control_plane::OrdinaryAdmissionRuntimeConfig {
            enable_aggregate_invocation_admission,
            admission_operation_db_path,
            approval_db_path,
            budget_db_path,
            control_url,
            control_token,
        },
    )
}

const MAX_PARTITION_ESCROW_AUTHORITY_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn load_partition_escrow_remote_authority(
    descriptor_path: &Path,
    trusted_signer: &chio_core::PublicKey,
) -> Result<
    Arc<
        chio_control_plane::trust_control::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
    >,
    CliError,
> {
    let mut descriptor_file = std::fs::File::open(descriptor_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to open partition-escrow authority descriptor `{}`: {error}",
            descriptor_path.display()
        ))
    })?;
    let mut descriptor = Vec::new();
    Read::by_ref(&mut descriptor_file)
        .take((MAX_PARTITION_ESCROW_AUTHORITY_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut descriptor)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to read partition-escrow authority descriptor `{}`: {error}",
                descriptor_path.display()
            ))
        })?;
    if descriptor.len() > MAX_PARTITION_ESCROW_AUTHORITY_DESCRIPTOR_BYTES {
        return Err(CliError::cli_other_error(
            "partition-escrow authority descriptor exceeds its byte limit".to_string(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "partition-escrow authority clock is before the Unix epoch: {error}"
            ))
        })?
        .as_secs();
    chio_control_plane::trust_control::service_runtime::budget::SealedPartitionEscrowRemoteAuthority::from_canonical_descriptor(
        &descriptor,
        trusted_signer,
        now,
    )
    .map(Arc::new)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_cli_admission_runtime_kernel(
    kernel: ChioKernel,
    enable_aggregate_invocation_admission: bool,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    partition_escrow_authority_descriptor: Option<&Path>,
    partition_escrow_authority_signer: Option<&chio_core::PublicKey>,
) -> Result<ChioKernel, CliError> {
    match (
        partition_escrow_authority_descriptor,
        partition_escrow_authority_signer,
    ) {
        (None, None) => compose_cli_ordinary_runtime_kernel(
            kernel,
            enable_aggregate_invocation_admission,
            admission_operation_db_path,
            approval_db_path,
            budget_db_path,
            control_url,
            control_token,
        ),
        (Some(_), None) | (None, Some(_)) => Err(CliError::cli_other_error(
            "partition-escrow authority descriptor and pinned signer must be configured together"
                .to_string(),
        )),
        (Some(descriptor_path), Some(trusted_signer)) => {
            if enable_aggregate_invocation_admission || approval_db_path.is_some() {
                return Err(CliError::cli_other_error(
                    "partition-escrow admission cannot be mixed with ordinary aggregate or threshold admission flags"
                        .to_string(),
                ));
            }
            if kernel.threshold_approval_requirement_resolver().is_some() {
                return Err(CliError::cli_other_error(
                    "partition-escrow admission does not support a threshold approval policy"
                        .to_string(),
                ));
            }
            if budget_db_path.is_some() {
                return Err(CliError::cli_other_error(
                    "partition-escrow admission uses its sealed remote budget authority and forbids --budget-db"
                        .to_string(),
                ));
            }
            let operation_path = admission_operation_db_path.ok_or_else(|| {
                CliError::cli_other_error(
                    "partition-escrow admission requires --admission-operation-db".to_string(),
                )
            })?;
            let control_url = control_url.ok_or_else(|| {
                CliError::cli_other_error(
                    "partition-escrow admission requires --control-url".to_string(),
                )
            })?;
            let control_token = chio_control_plane::require_control_token(control_token)?;
            let authority =
                load_partition_escrow_remote_authority(descriptor_path, trusted_signer)?;
            chio_control_plane::compose_partition_escrow_remote_admission_runtime(
                kernel,
                chio_control_plane::PartitionEscrowRemoteAdmissionRuntimeConfig {
                    control_url,
                    control_token,
                    admission_operation_db_path: operation_path,
                    authority,
                },
            )
        }
    }
}

fn select_cli_kernel_signer(
    keyring_config_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
) -> Result<
    (
        Option<Keypair>,
        Option<chio_control_plane::KeyringRuntimeComposition>,
    ),
    CliError,
> {
    match (keyring_config_path, authority_seed_path, authority_db_path) {
        (Some(config_path), Some(seed_path), None) => {
            let (keypair, runtime) =
                load_keyring_runtime_from_authority_seed(config_path, seed_path)?;
            Ok((Some(keypair), Some(runtime)))
        }
        (None, Some(seed_path), None) => {
            Ok((Some(load_or_create_authority_keypair(seed_path)?), None))
        }
        (None, None, Some(path)) => Ok((
            Some(chio_store_sqlite::SqliteCapabilityAuthority::open(path)?.local_keypair()?),
            None,
        )),
        (None, None, None) => Ok((None, None)),
        (Some(_), None, _) => Err(CliError::cli_other_error(
            "--keyring-config requires --authority-seed-file for the active signing backend"
                .to_string(),
        )),
        (_, Some(_), Some(_)) => Err(CliError::cli_other_error(
            "use either --authority-seed-file or --authority-db, not both".to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn open_cli_durable_admission_runtime(
    mode: chio_kernel::admission_operation::DurableAdmissionMode,
    session_db_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    configured_kernel_keypair: Option<&Keypair>,
) -> Result<Option<chio_control_plane::DurableAdmissionRuntime>, CliError> {
    use chio_kernel::admission_operation::DurableAdmissionMode;

    chio_control_plane::validate_durable_admission_participant_paths(
        mode,
        control_url,
        revocation_db_path,
        budget_db_path,
    )?;
    if mode == DurableAdmissionMode::Off {
        return Ok(None);
    }
    let session_db_path = session_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "durable agent-economy admission requires --session-db so operations and tool outcomes survive restart"
                .to_string(),
        )
    })?;
    let mut paths = vec![("durable agent-economy admission database", session_db_path)];
    for (label, path) in [
        ("receipt database", receipt_db_path),
        ("revocation database", revocation_db_path),
        ("capability authority database", authority_db_path),
        ("ordinary admission budget database", budget_db_path),
        ("ordinary admission operation database", admission_operation_db_path),
        ("threshold approval database", approval_db_path),
    ] {
        if let Some(path) = path {
            paths.push((label, path));
        }
    }
    chio_control_plane::validate_distinct_database_paths(&paths)?;

    match (control_url, configured_kernel_keypair) {
        (Some(url), Some(keypair)) => {
            let token = chio_control_plane::require_control_token(control_token)?;
            chio_control_plane::DurableAdmissionRuntime::open_remote_with_kernel_keypair(
                session_db_path,
                url,
                token,
                keypair.clone(),
            )
            .map(Some)
        }
        (Some(url), None) => {
            let token = chio_control_plane::require_control_token(control_token)?;
            chio_control_plane::DurableAdmissionRuntime::open_remote(
                session_db_path,
                url,
                token,
            )
            .map(Some)
        }
        (None, Some(keypair)) => {
            chio_control_plane::DurableAdmissionRuntime::open_with_kernel_keypair(
                session_db_path,
                keypair.clone(),
            )
            .map(Some)
        }
        (None, None) => chio_control_plane::open_durable_admission_runtime(
            mode,
            Some(session_db_path),
        ),
    }
}

fn attach_cli_durable_admission_runtime(
    kernel: &mut ChioKernel,
    runtime: Option<&chio_control_plane::DurableAdmissionRuntime>,
) -> Result<(), CliError> {
    if kernel.durable_admission_mode()
        == chio_kernel::admission_operation::DurableAdmissionMode::Off
    {
        return Ok(());
    }
    runtime
        .ok_or_else(|| {
            CliError::cli_other_error(
                "durable agent-economy admission runtime is unavailable for an enabled policy"
                    .to_string(),
            )
        })?
        .attach(kernel)
}

pub(crate) fn cmd_run(
    policy_path: &Path,
    command: &[String],
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    keyring_config_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    enable_aggregate_invocation_admission: bool,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    approver_directory_path: Option<&Path>,
    threshold_proposal_authority_public_key: Option<&chio_core::PublicKey>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
    partition_escrow_authority_descriptor: Option<&Path>,
    partition_escrow_authority_signer: Option<&chio_core::PublicKey>,
) -> Result<(), CliError> {
    let loaded_policy = policy::load_policy_for_runtime(
        policy_path,
        approver_directory_path,
        threshold_proposal_authority_public_key,
    )?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
    let durable_admission_mode = loaded_policy.kernel.durable_admission_mode;

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        "loaded policy"
    );

    let (configured_kernel_kp, keyring_runtime) =
        select_cli_kernel_signer(keyring_config_path, authority_seed_path, authority_db_path)?;
    let durable_admission = open_cli_durable_admission_runtime(
        durable_admission_mode,
        session_db_path,
        receipt_db_path,
        revocation_db_path,
        authority_db_path,
        budget_db_path,
        admission_operation_db_path,
        approval_db_path,
        control_url,
        control_token,
        configured_kernel_kp.as_ref(),
    )?;
    let kernel_kp = configured_kernel_kp
        .or_else(|| {
            durable_admission
                .as_ref()
                .map(chio_control_plane::DurableAdmissionRuntime::kernel_keypair)
        })
        .unwrap_or_else(Keypair::generate);
    let mut kernel = match keyring_runtime.as_ref() {
        Some(runtime) => build_kernel_with_keyring_composition(loaded_policy, &kernel_kp, runtime)?,
        None => build_kernel(loaded_policy, &kernel_kp)?,
    };
    let receipt_store = configure_receipt_store(
        &mut kernel,
        receipt_db_path,
        control_url,
        control_token,
        control_authority_public_key,
        control_authority_trusted_public_keys,
    )?;
    if let Some(runtime) = keyring_runtime.as_ref() {
        let receipt_store = receipt_store.ok_or_else(|| {
            CliError::cli_other_error(
                "keyring runtime requires a durable normal receipt store".to_string(),
            )
        })?;
        runtime.attach_receipt_store(receipt_store)?;
    }
    if durable_admission.is_none() {
        configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
        opt_in_ephemeral_revocation_for_local_session(&mut kernel, revocation_db_path, control_url);
    }
    attach_cli_durable_admission_runtime(&mut kernel, durable_admission.as_ref())?;
    configure_capability_authority(
        &mut kernel,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        control_authority_public_key,
        control_authority_trusted_public_keys,
        None,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    let mut kernel = compose_cli_admission_runtime_kernel(
        kernel,
        enable_aggregate_invocation_admission,
        admission_operation_db_path,
        approval_db_path,
        budget_db_path,
        control_url,
        control_token,
        partition_escrow_authority_descriptor,
        partition_escrow_authority_signer,
    )?;

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps.clone())?;

    info!(
        capability_count = initial_caps.len(),
        agent_id = %session_agent_id,
        "issued initial capabilities to agent"
    );

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| CliError::cli_other_error("empty command".to_string()))?;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::cli_io_error("failed to open child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::cli_io_error("failed to open child stdout".to_string()))?;

    let mut transport = ChioTransport::new(child_stdout, child_stdin);

    let init_msg = KernelMessage::CapabilityList {
        capabilities: initial_caps.clone(),
    };
    transport.send(&init_msg)?;
    kernel.activate_session(&session_id)?;

    info!("sent initial capabilities to agent, entering message loop");

    let mut stats = SessionStats::default();

    loop {
        let agent_msg = match transport.recv() {
            Ok(msg) => msg,
            Err(TransportError::ConnectionClosed) => {
                debug!("agent closed connection");
                break;
            }
            Err(e) => {
                warn!(error = %e, "transport read error");
                break;
            }
        };

        let kernel_msgs = handle_agent_message(
            &mut kernel,
            &agent_msg,
            &session_id,
            &session_agent_id,
            &mut stats,
        );

        let mut write_failed = false;
        for kernel_msg in kernel_msgs {
            if let Err(e) = transport.send(&kernel_msg) {
                warn!(error = %e, "transport write error");
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }
    }

    if let Err(e) = kernel.begin_draining_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to mark session draining");
    }

    if let Err(e) = kernel.close_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to close session");
    }

    let status = child.wait()?;
    print_summary(&stats, status.code(), json_output);

    if status.success() {
        Ok(())
    } else {
        let code = status.code().unwrap_or(1);
        Err(CliError::transport_error(format!(
            "agent exited with code {code}"
        )))
    }
}

pub(crate) fn cmd_api_protect(
    upstream: &str,
    spec_path: Option<&Path>,
    listen_addr: &str,
    receipt_store: Option<&Path>,
    authority_seed_path: Option<&Path>,
    budget_db: Option<&Path>,
    revocation_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    allow_ephemeral_receipts: bool,
    upstream_timeout_secs: Option<u64>,
) -> Result<(), CliError> {
    require_durable_or_ephemeral_optin(
        receipt_store,
        allow_ephemeral_receipts,
        authority_seed_path,
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::transport_error(format!("failed to start async runtime: {error}"))
        })?;

    runtime.block_on(async move {
        let sidecar_control_token = std::env::var("CHIO_SIDECAR_CONTROL_TOKEN")
            .ok()
            .or_else(|| std::env::var("CHIO_API_PROTECT_CONTROL_TOKEN").ok())
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let signer_seed_hex = authority_seed_path
            .map(load_or_create_authority_keypair)
            .transpose()?
            .map(|keypair| keypair.seed_hex());
        let trusted_capability_issuers = parse_trusted_capability_issuers_from_env()?;
        let trusted_historical_receipt_signers =
            parse_trusted_historical_receipt_signers_from_env()?;
        let payment_adapter = resolve_sidecar_payment_adapter()?;
        let config = ProtectConfig {
            upstream: upstream.to_string(),
            spec_content: None,
            spec_path: spec_path.map(|path| path.display().to_string()),
            listen_addr: listen_addr.to_string(),
            receipt_db: durable_receipt_db_path(receipt_store)
                .map(|path| path.display().to_string()),
            allow_ephemeral_receipts,
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
            trusted_historical_receipt_signers,
            control_url: control_url.map(str::to_string),
            control_token: control_token.map(str::to_string),
            budget_db: budget_db.map(|path| path.display().to_string()),
            revocation_db: revocation_db.map(|path| path.display().to_string()),
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: upstream_timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_UPSTREAM_REQUEST_TIMEOUT),
        };
        ProtectProxy::new(config)
            .with_payment_adapter(payment_adapter)
            .run()
            .await
            .map_err(|error| {
                CliError::transport_error(format!("failed to start chio api protect: {error}"))
            })
    })
}

/// Empty OpenAPI spec used by `chio start` so the proxy can build the
/// route table without an upstream OpenAPI source. The catch-all
/// `/{*path}` proxy route still mounts; it just has no upstream to
/// forward to (pointing at `http://127.0.0.1:1`), so non-`/chio/*` and
/// non-`/v1/*` requests will fail loud at the egress contract instead
/// of silently succeeding. This is the intended behaviour for the
/// sidecar-only deployment shape.
pub(crate) const CHIO_START_SIDECAR_OPENAPI_SPEC: &str = r#"openapi: 3.1.0
info:
  title: chio-start-sidecar
  version: 0.0.0
paths: {}
"#;

pub(crate) const CHIO_START_NO_UPSTREAM_URL: &str = "http://127.0.0.1:1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_start(
    listen_addr: &str,
    receipt_store: Option<&Path>,
    authority_seed_path: Option<&Path>,
    budget_db: Option<&Path>,
    revocation_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    allow_ephemeral_receipts: bool,
    print_config: bool,
) -> Result<(), CliError> {
    require_durable_or_ephemeral_optin(
        receipt_store,
        allow_ephemeral_receipts,
        authority_seed_path,
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::transport_error(format!("failed to start async runtime: {error}"))
        })?;

    runtime.block_on(async move {
        let sidecar_control_token = std::env::var("CHIO_SIDECAR_CONTROL_TOKEN")
            .ok()
            .or_else(|| std::env::var("CHIO_API_PROTECT_CONTROL_TOKEN").ok())
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let signer_seed_hex = authority_seed_path
            .map(load_or_create_authority_keypair)
            .transpose()?
            .map(|keypair| keypair.seed_hex());
        let trusted_capability_issuers = parse_trusted_capability_issuers_from_env()?;
        let trusted_historical_receipt_signers =
            parse_trusted_historical_receipt_signers_from_env()?;
        let mediation_available =
            sidecar_mediation_available(budget_db, sidecar_control_token.as_deref());
        let payment_adapter = resolve_sidecar_payment_adapter()?;
        let config = ProtectConfig {
            // The chio-start shape never proxies upstream traffic; the
            // catch-all route exists only because the underlying axum
            // router shape is shared with `chio api protect`. Pointing
            // at port 1 ensures any caller that hits the catch-all
            // path gets a fast, loud failure rather than a subtle
            // forward.
            upstream: CHIO_START_NO_UPSTREAM_URL.to_string(),
            spec_content: Some(CHIO_START_SIDECAR_OPENAPI_SPEC.to_string()),
            spec_path: None,
            listen_addr: listen_addr.to_string(),
            receipt_db: durable_receipt_db_path(receipt_store)
                .map(|path| path.display().to_string()),
            allow_ephemeral_receipts,
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
            trusted_historical_receipt_signers,
            control_url: control_url.map(str::to_string),
            control_token: control_token.map(str::to_string),
            budget_db: budget_db.map(|path| path.display().to_string()),
            revocation_db: revocation_db.map(|path| path.display().to_string()),
            require_nonce: false,
            allow_advisory: false,
            // The chio-start shape never proxies upstream, so the hop ceiling is
            // moot; keep the default so the serve site's drain window is unchanged.
            upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        ProtectProxy::new(config)
            .with_payment_adapter(payment_adapter)
            .run_with_observer(move |bound_addr| {
                let base_url = format!("http://{bound_addr}");
                println!("chio sidecar listening on {base_url}");
                for line in start_sidecar_route_banner(mediation_available) {
                    println!("{line}");
                }
                if print_config {
                    println!();
                    println!("# chio-hermes quickstart -- copy into your shell:");
                    println!("export CHIO_SIDECAR_URL={base_url}");
                    println!("# then mint a capability:");
                    println!("#   hermes chio issue --description \"default backbay capability\" --json | jq -r .id");
                    println!("# and export it:");
                    println!("#   export CHIO_CAPABILITY_ID=<id-from-issue>");
                }
            })
            .await
            .map_err(|error| {
                CliError::transport_error(format!("failed to start chio sidecar: {error}"))
            })
    })
}

pub(crate) fn sidecar_mediation_available(
    budget_db: Option<&Path>,
    sidecar_control_token: Option<&str>,
) -> bool {
    budget_db.is_some() && sidecar_control_token.is_some()
}

pub(crate) fn start_sidecar_route_banner(mediation_available: bool) -> Vec<String> {
    let evaluate_route = if mediation_available {
        ", /v1/evaluate"
    } else {
        ""
    };
    let mut lines = vec![format!(
        "  routes: /chio/* (health, evaluate, verify), /v1/capabilities/{{,mint,validate,attenuate,release}}{evaluate_route}, /v1/receipts{{,/verify}}, /approvals/*"
    )];
    if !mediation_available {
        lines.push(
            "  note: mediated /v1/evaluate is disabled without a hold-capable budget store and a sidecar-control token; pass --budget-db <path> and set CHIO_SIDECAR_CONTROL_TOKEN to enable tool-call budget mediation"
                .to_string(),
        );
    }
    lines
}

pub(crate) fn parse_trusted_capability_issuers_from_env(
) -> Result<Vec<chio_core::PublicKey>, CliError> {
    let mut issuers = Vec::new();

    if let Ok(single_issuer) = std::env::var("CHIO_TRUSTED_ISSUER_KEY") {
        let single_issuer = single_issuer.trim();
        if !single_issuer.is_empty() {
            issuers.push(
                chio_core::PublicKey::from_hex(single_issuer).map_err(|error| {
                    CliError::transport_error(format!(
                        "failed to parse CHIO_TRUSTED_ISSUER_KEY as a public key: {error}"
                    ))
                })?,
            );
        }
    }

    if let Ok(multiple_issuers) = std::env::var("CHIO_TRUSTED_ISSUER_KEYS") {
        for issuer in multiple_issuers
            .split(',')
            .map(str::trim)
            .filter(|issuer| !issuer.is_empty())
        {
            let parsed = chio_core::PublicKey::from_hex(issuer).map_err(|error| {
                CliError::transport_error(format!(
                    "failed to parse CHIO_TRUSTED_ISSUER_KEYS entry as a public key: {error}"
                ))
            })?;
            if !issuers.contains(&parsed) {
                issuers.push(parsed);
            }
        }
    }

    Ok(issuers)
}

pub(crate) fn parse_trusted_historical_receipt_signers_from_env(
) -> Result<Vec<chio_core::PublicKey>, CliError> {
    let mut signers = Vec::new();
    let Ok(configured) = std::env::var("CHIO_TRUSTED_HISTORICAL_RECEIPT_SIGNER_KEYS") else {
        return Ok(signers);
    };
    for signer in configured
        .split(',')
        .map(str::trim)
        .filter(|signer| !signer.is_empty())
    {
        let parsed = chio_core::PublicKey::from_hex(signer).map_err(|error| {
            CliError::transport_error(format!(
                "failed to parse CHIO_TRUSTED_HISTORICAL_RECEIPT_SIGNER_KEYS entry as a public key: {error}"
            ))
        })?;
        if !signers.contains(&parsed) {
            signers.push(parsed);
        }
    }
    Ok(signers)
}

pub(crate) fn cmd_check(
    policy_path: &Path,
    mode: CheckMode,
    tool: &str,
    params_str: &str,
    server: &str,
    output_fixture: Option<&Path>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    keyring_config_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    enable_aggregate_invocation_admission: bool,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    approver_directory_path: Option<&Path>,
    threshold_proposal_authority_public_key: Option<&chio_core::PublicKey>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
    partition_escrow_authority_descriptor: Option<&Path>,
    partition_escrow_authority_signer: Option<&chio_core::PublicKey>,
) -> Result<(), CliError> {
    let loaded_policy = policy::load_policy_for_runtime(
        policy_path,
        approver_directory_path,
        threshold_proposal_authority_public_key,
    )?;
    let check_output = validate_check_mode(&loaded_policy, mode, output_fixture)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
    let durable_admission_mode = loaded_policy.kernel.durable_admission_mode;

    let (configured_kernel_kp, keyring_runtime) =
        select_cli_kernel_signer(keyring_config_path, authority_seed_path, authority_db_path)?;
    let durable_admission = open_cli_durable_admission_runtime(
        durable_admission_mode,
        session_db_path,
        receipt_db_path,
        revocation_db_path,
        authority_db_path,
        budget_db_path,
        admission_operation_db_path,
        approval_db_path,
        control_url,
        control_token,
        configured_kernel_kp.as_ref(),
    )?;
    let kernel_kp = configured_kernel_kp
        .or_else(|| {
            durable_admission
                .as_ref()
                .map(chio_control_plane::DurableAdmissionRuntime::kernel_keypair)
        })
        .unwrap_or_else(Keypair::generate);
    let mut kernel = match keyring_runtime.as_ref() {
        Some(runtime) => build_kernel_with_keyring_composition(loaded_policy, &kernel_kp, runtime)?,
        None => build_kernel(loaded_policy, &kernel_kp)?,
    };
    let receipt_store = configure_receipt_store(
        &mut kernel,
        receipt_db_path,
        control_url,
        control_token,
        control_authority_public_key,
        control_authority_trusted_public_keys,
    )?;
    if let Some(runtime) = keyring_runtime.as_ref() {
        let receipt_store = receipt_store.ok_or_else(|| {
            CliError::cli_other_error(
                "keyring runtime requires a durable normal receipt store".to_string(),
            )
        })?;
        runtime.attach_receipt_store(receipt_store)?;
    }
    if durable_admission.is_none() {
        configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
        opt_in_ephemeral_revocation_for_local_session(&mut kernel, revocation_db_path, control_url);
    }
    attach_cli_durable_admission_runtime(&mut kernel, durable_admission.as_ref())?;
    configure_capability_authority(
        &mut kernel,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        control_authority_public_key,
        control_authority_trusted_public_keys,
        None,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    let mut kernel = compose_cli_admission_runtime_kernel(
        kernel,
        enable_aggregate_invocation_admission,
        admission_operation_db_path,
        approval_db_path,
        budget_db_path,
        control_url,
        control_token,
        partition_escrow_authority_descriptor,
        partition_escrow_authority_signer,
    )?;

    kernel.register_tool_server(Box::new(CheckToolServer {
        id: server.to_string(),
        output: check_output,
    }));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let params: serde_json::Value = serde_json::from_str(params_str)?;
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let cap = match select_capability_for_request(&initial_caps, tool, server, &params) {
        Some(capability) => capability,
        None => kernel
            .issue_capability(&agent_pk, ChioScope::default(), 300)
            .map_err(|error| {
                CliError::transport_error(format!(
                    "failed to issue fallback empty capability: {error}"
                ))
            })?,
    };
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps)?;
    kernel.activate_session(&session_id)?;

    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new("check-001"),
        session_agent_id,
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        arguments: params.clone(),
        supplemental_authorization: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    }));

    let response = match kernel.evaluate_session_operation(&context, &operation)? {
        SessionOperationResponse::ToolCall(response) => response,
        SessionOperationResponse::RootList { .. }
        | SessionOperationResponse::ResourceList { .. }
        | SessionOperationResponse::ResourceRead { .. }
        | SessionOperationResponse::ResourceReadDenied { .. }
        | SessionOperationResponse::ResourceTemplateList { .. }
        | SessionOperationResponse::PromptList { .. }
        | SessionOperationResponse::PromptGet { .. }
        | SessionOperationResponse::Completion { .. }
        | SessionOperationResponse::CapabilityList { .. }
        | SessionOperationResponse::Heartbeat => {
            return Err(CliError::transport_error(
                "unexpected non-tool response while evaluating check command".to_string(),
            ));
        }
    };

    kernel.begin_draining_session(&session_id)?;
    kernel.close_session(&session_id)?;

    let verdict_str = verdict_label(response.verdict);

    if json_output {
        let output = serde_json::json!({
            "verdict": verdict_str,
            "tool": tool,
            "server": server,
            "params": params,
            "reason": response.reason,
            "receipt_id": response.receipt.id,
            "policy_hash": policy_identity.runtime_hash,
            "policy_source_hash": policy_identity.source_hash,
            "check_mode": mode.as_str(),
            "output_fixture": output_fixture.is_some(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("verdict:    {verdict_str}");
        println!("tool:       {tool}");
        println!("server:     {server}");
        if let Some(reason) = &response.reason {
            println!("reason:     {reason}");
        }
        println!("receipt_id: {}", response.receipt.id);
        println!("policy:     {}", policy_identity.runtime_hash);
        println!("source:     {}", policy_identity.source_hash);
        println!("mode:       {}", mode.as_str());
        println!("fixture:    {}", output_fixture.is_some());
    }

    match response.verdict {
        chio_kernel::Verdict::Allow => Ok(()),
        chio_kernel::Verdict::Deny => {
            std::process::exit(2);
        }
        chio_kernel::Verdict::PendingApproval => {
            // Treat approval-pending as a soft deny from the CLI
            // perspective; the orchestrator can resume once the
            // human has approved out-of-band.
            std::process::exit(3);
        }
    }
}

fn validate_check_mode(
    loaded_policy: &policy::LoadedPolicy,
    mode: CheckMode,
    output_fixture: Option<&Path>,
) -> Result<Option<serde_json::Value>, CliError> {
    match mode {
        CheckMode::Preflight => {
            if output_fixture.is_some() {
                return Err(CliError::cli_other_error(
                    "--output-fixture requires --mode full".to_string(),
                ));
            }
            if !loaded_policy.post_invocation_pipeline.is_empty() {
                return Err(CliError::cli_other_error(
                    "chio check preflight cannot evaluate post-output guards; use --mode full --output-fixture <JSON> so output-sensitive policy is evaluated against explicit fixture output".to_string(),
                ));
            }
            Ok(None)
        }
        CheckMode::Full => {
            let Some(output_fixture) = output_fixture else {
                return Err(CliError::cli_other_error(
                    "chio check --mode full requires --output-fixture <JSON>; use --mode preflight for admission-only checks".to_string(),
                ));
            };
            load_check_output_fixture(output_fixture).map(Some)
        }
    }
}

fn load_check_output_fixture(path: &Path) -> Result<serde_json::Value, CliError> {
    let content = fs::read_to_string(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read check output fixture {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse check output fixture {} as JSON: {error}",
            path.display()
        ))
    })
}

struct CheckToolServer {
    id: String,
    output: Option<serde_json::Value>,
}

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CheckToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        Ok(self.output.clone().unwrap_or_else(|| {
            serde_json::json!({
                "check_probe": true,
                "tool": tool_name,
                "arguments": arguments,
            })
        }))
    }
}

pub(crate) fn verdict_label(verdict: chio_kernel::Verdict) -> &'static str {
    match verdict {
        chio_kernel::Verdict::Allow => "ALLOW",
        chio_kernel::Verdict::Deny => "DENY",
        chio_kernel::Verdict::PendingApproval => "PENDING_APPROVAL",
    }
}

#[cfg(unix)]
fn shutdown_cli_active_defense(
    broker_runtime: &mut Option<chio_control_plane::security::ProductionBrokerProductRuntime>,
    asynchronous_runtime: Option<&tokio::runtime::Runtime>,
) -> Result<(), CliError> {
    match (broker_runtime.as_mut(), asynchronous_runtime) {
        (Some(runtime), Some(asynchronous_runtime)) => asynchronous_runtime
            .block_on(runtime.shutdown_active_defense())
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "production active-defense shutdown failed: {error}"
                ))
            }),
        (None, None) => Ok(()),
        _ => Err(CliError::cli_other_error(
            "production broker and active-defense runtime ownership diverged during shutdown"
                .to_string(),
        )),
    }
}

fn merge_cli_active_defense_results(
    operation: Result<(), CliError>,
    shutdown: Result<(), CliError>,
) -> Result<(), CliError> {
    match (operation, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation_error), Err(shutdown_error)) => Err(CliError::cli_other_error(format!(
            "production broker operation failed: {operation_error}; explicit active-defense shutdown also failed: {shutdown_error}"
        ))),
    }
}

fn finish_cli_active_defense_with_shutdown(
    operation: Result<(), CliError>,
    shutdown: impl FnOnce() -> Result<(), CliError>,
) -> Result<(), CliError> {
    merge_cli_active_defense_results(operation, shutdown())
}

pub(crate) fn cmd_mcp_serve(
    policy_path: Option<&Path>,
    preset: Option<&str>,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    signed_manifest_path: Option<&Path>,
    manifest_public_key: Option<&str>,
    cage_policy_path: &Path,
    cage_policy_signer: &str,
    page_size: usize,
    tools_list_changed: bool,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    keyring_config_path: Option<&Path>,
    broker_config_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    enable_aggregate_invocation_admission: bool,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    approver_directory_path: Option<&Path>,
    threshold_proposal_authority_public_key: Option<&chio_core::PublicKey>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
    partition_escrow_authority_descriptor: Option<&Path>,
    partition_escrow_authority_signer: Option<&chio_core::PublicKey>,
) -> Result<(), CliError> {
    // Resolve `--preset` to a materialized YAML on disk so the rest
    // of the plumbing can use `load_policy` unchanged. Keeping the
    // preset on disk also keeps the source_policy_hash deterministic
    // across runs so receipt verification continues to work.
    let materialized_preset = match (policy_path, preset) {
        (Some(_), None) => None,
        (None, Some(name)) => {
            let preset = policies::McpPreset::from_name(name).ok_or_else(|| {
                CliError::cli_other_error(format!("unknown --preset {name:?} (known: code-agent)"))
            })?;
            Some(preset.materialize_to_temp()?)
        }
        (Some(_), Some(_)) => {
            // clap's `conflicts_with` should prevent this, but we
            // guard defensively in case the CLI wiring ever drifts.
            return Err(CliError::cli_other_error(
                "--policy and --preset are mutually exclusive".to_string(),
            ));
        }
        (None, None) => {
            return Err(CliError::cli_other_error(
                "either --policy <path> or --preset <name> is required".to_string(),
            ));
        }
    };

    let resolved_policy_path: &Path = match (policy_path, &materialized_preset) {
        (Some(p), _) => p,
        (None, Some(m)) => m.path(),
        _ => unreachable!("policy path resolution validated above"),
    };

    let loaded_policy = policy::load_policy_for_runtime(
        resolved_policy_path,
        approver_directory_path,
        threshold_proposal_authority_public_key,
    )?;
    let policy_identity = loaded_policy.identity.clone();
    #[cfg(unix)]
    let active_defense_mode = loaded_policy.active_defense.mode;
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
    let durable_admission_mode = loaded_policy.kernel.durable_admission_mode;

    let (configured_kernel_kp, keyring_runtime) =
        select_cli_kernel_signer(keyring_config_path, authority_seed_path, authority_db_path)?;
    if broker_config_path.is_some() && keyring_runtime.is_none() {
        return Err(CliError::cli_other_error(
            "production broker composition requires an enterprise keyring-backed authority signer"
                .to_string(),
        ));
    }
    if broker_config_path.is_some()
        && (partition_escrow_authority_descriptor.is_some()
            || partition_escrow_authority_signer.is_some())
    {
        return Err(CliError::cli_other_error(
            "partition-escrow admission cannot be mixed with production broker composition"
                .to_string(),
        ));
    }

    let mut effective_receipt_db_path = receipt_db_path.map(Path::to_path_buf);
    let mut effective_revocation_db_path = revocation_db_path.map(Path::to_path_buf);
    let mut effective_budget_db_path = budget_db_path.map(Path::to_path_buf);
    let mut effective_admission_operation_db_path =
        admission_operation_db_path.map(Path::to_path_buf);
    let mut effective_approval_db_path = approval_db_path.map(Path::to_path_buf);
    let mut effective_aggregate_invocation_admission = enable_aggregate_invocation_admission;
    if broker_config_path.is_some()
        && (control_url.is_some()
            || control_token.is_some()
            || control_authority_public_key.is_some()
            || !control_authority_trusted_public_keys.is_empty())
    {
        return Err(CliError::cli_other_error(
            "production broker composition cannot split its receipt, revocation, or budget commit domain across a remote control plane"
                .to_string(),
        ));
    }
    #[cfg(unix)]
    let mut broker_runtime = match broker_config_path {
        Some(path) => Some(
            chio_control_plane::security::ProductionBrokerProductRuntime::open(
                path,
                keyring_runtime.as_ref().ok_or_else(|| {
                    CliError::cli_other_error(
                        "production broker keyring disappeared before startup".to_string(),
                    )
                })?,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("production broker startup failed: {error}"))
            })?,
        ),
        None => None,
    };
    #[cfg(not(unix))]
    if broker_config_path.is_some() {
        return Err(CliError::cli_other_error(
            "production broker composition requires Unix process isolation".to_string(),
        ));
    }
    #[cfg(unix)]
    if let Some(runtime) = broker_runtime.as_ref() {
        runtime
            .require_default_route_capability(&default_capabilities)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "production broker policy composition failed: {error}"
                ))
            })?;
        let paths = runtime
            .resolve_host_database_paths(
                receipt_db_path,
                revocation_db_path,
                budget_db_path,
                admission_operation_db_path,
                authority_db_path,
                approval_db_path,
                session_db_path,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "production broker database composition failed: {error}"
                ))
            })?;
        effective_receipt_db_path = Some(paths.receipt_database_path);
        effective_revocation_db_path = Some(paths.revocation_database_path);
        effective_budget_db_path = Some(paths.budget_database_path);
        effective_admission_operation_db_path = Some(paths.admission_operation_database_path);
        effective_approval_db_path = Some(paths.approval_database_path);
        effective_aggregate_invocation_admission = true;
    }

    let durable_admission = open_cli_durable_admission_runtime(
        durable_admission_mode,
        session_db_path,
        effective_receipt_db_path.as_deref(),
        if broker_config_path.is_some() {
            None
        } else {
            effective_revocation_db_path.as_deref()
        },
        authority_db_path,
        effective_budget_db_path.as_deref(),
        effective_admission_operation_db_path.as_deref(),
        effective_approval_db_path.as_deref(),
        control_url,
        control_token,
        configured_kernel_kp.as_ref(),
    )?;
    let kernel_kp = configured_kernel_kp
        .or_else(|| {
            durable_admission
                .as_ref()
                .map(chio_control_plane::DurableAdmissionRuntime::kernel_keypair)
        })
        .unwrap_or_else(Keypair::generate);

    #[cfg(unix)]
    if broker_runtime.is_some()
        && !matches!(
            active_defense_mode,
            chio_control_plane::security::ActiveDefenseMode::Enforce
        )
    {
        return Err(CliError::cli_other_error(
            "production broker composition requires active_defense.mode = enforce".to_string(),
        ));
    }

    let signed_manifest_path = signed_manifest_path.ok_or_else(|| {
        CliError::cli_other_error(
            "MCP serve requires --signed-manifest with an existing publisher-signed manifest"
                .to_string(),
        )
    })?;
    let manifest_public_key = manifest_public_key.ok_or_else(|| {
        CliError::cli_other_error(
            "MCP serve requires --manifest-public-key with an independently registered key"
                .to_string(),
        )
    })?;
    let ordinary_manifest_registry =
        load_manifest_for_mcp_kernel(signed_manifest_path, manifest_public_key, server_id)?;
    #[cfg(unix)]
    let (broker_manifest_registry, manifest_registry) = match broker_runtime.as_ref() {
        Some(runtime) => {
            let composed = runtime
                .compose_manifest_registry(ordinary_manifest_registry)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "production broker manifest installation failed: {error}"
                    ))
                })?;
            let registry = Arc::clone(composed.registry());
            (Some(composed), registry)
        }
        None => (None, Arc::new(ordinary_manifest_registry)),
    };
    #[cfg(not(unix))]
    let manifest_registry = Arc::new(ordinary_manifest_registry);
    #[cfg(unix)]
    if broker_runtime.is_none() {
        chio_control_plane::security::reject_unprotected_flow_manifest(manifest_registry.as_ref())
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    }
    #[cfg(not(unix))]
    chio_control_plane::security::reject_unprotected_flow_manifest(manifest_registry.as_ref())
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    #[cfg(unix)]
    let active_defense_runtime = match broker_runtime.as_mut() {
        Some(runtime) => {
            let asynchronous_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to start the production active-defense runtime: {error}"
                    ))
                })?;
            let startup_result = asynchronous_runtime
                .block_on(runtime.start_configured_active_defense(&loaded_policy))
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "production active-defense startup failed: {error}"
                    ))
                });
            if let Err(startup_error) = startup_result {
                return finish_cli_active_defense_with_shutdown(Err(startup_error), || {
                    asynchronous_runtime
                        .block_on(runtime.shutdown_active_defense())
                        .map_err(|error| {
                            CliError::cli_other_error(format!(
                                "production active-defense shutdown after failed startup failed: {error}"
                            ))
                        })
                });
            }
            Some(asynchronous_runtime)
        }
        None => None,
    };

    let entrypoint_result = (|| -> Result<(), CliError> {
        info!(
            policy_path = %resolved_policy_path.display(),
            preset = preset.unwrap_or(""),
            policy_format = loaded_policy.format_name(),
            source_policy_hash = %policy_identity.source_hash,
            runtime_policy_hash = %policy_identity.runtime_hash,
            server_id = server_id,
            "loaded policy for MCP edge"
        );

        #[cfg(unix)]
        let security_runtime = match (broker_runtime.as_ref(), broker_manifest_registry.as_ref()) {
            (Some(runtime), Some(manifests)) => Some(
                runtime
                    .build_security_runtime(manifests, &policy_identity.runtime_hash)
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production broker security composition failed: {error}"
                        ))
                    })?,
            ),
            (None, None) => None,
            _ => {
                return Err(CliError::cli_other_error(
                    "production broker manifest and runtime composition diverged".to_string(),
                ));
            }
        };
        #[cfg(not(unix))]
        let security_runtime = None;
        #[cfg(unix)]
        let broker_host = match broker_runtime.as_ref() {
            Some(_) => Some(chio_control_plane::ProductionBrokerKernelHostConfig {
                receipt_database_path: effective_receipt_db_path.as_deref().ok_or_else(|| {
                    CliError::cli_other_error(
                        "production broker receipt database was not resolved".to_string(),
                    )
                })?,
                revocation_database_path: effective_revocation_db_path.as_deref().ok_or_else(
                    || {
                        CliError::cli_other_error(
                            "production broker revocation database was not resolved".to_string(),
                        )
                    },
                )?,
                budget_database_path: effective_budget_db_path.as_deref().ok_or_else(|| {
                    CliError::cli_other_error(
                        "production broker budget database was not resolved".to_string(),
                    )
                })?,
                authority_seed_path,
                authority_database_path: authority_db_path,
            }),
            None => None,
        };
        #[cfg(unix)]
    let mut kernel = match (
        keyring_runtime.as_ref(),
        security_runtime,
        broker_runtime.as_ref(),
    ) {
        (Some(keyring), Some(security_runtime), Some(broker)) => {
            chio_control_plane::build_kernel_with_keyring_composition_and_production_broker_security_runtime(
                loaded_policy,
                &kernel_kp,
                keyring,
                broker,
                security_runtime,
                broker_host.ok_or_else(|| {
                    CliError::cli_other_error(
                        "production broker host composition was not resolved".to_string(),
                    )
                })?,
            )?
        }
        (None, Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "production broker composition lost its required keyring authority backend"
                    .to_string(),
            ));
        }
        (Some(runtime), security_runtime, None) => {
            build_kernel_with_keyring_composition_and_security_runtime(
                loaded_policy,
                &kernel_kp,
                runtime,
                security_runtime,
            )?
        }
        (None, security_runtime, None) => {
            build_kernel_with_security_runtime(loaded_policy, &kernel_kp, security_runtime)?
        }
        (_, None, Some(_)) => {
            return Err(CliError::cli_other_error(
                "production broker security runtime was not composed".to_string(),
            ));
        }
    };
        #[cfg(not(unix))]
        let mut kernel = match (keyring_runtime.as_ref(), security_runtime) {
            (Some(runtime), security_runtime) => {
                build_kernel_with_keyring_composition_and_security_runtime(
                    loaded_policy,
                    &kernel_kp,
                    runtime,
                    security_runtime,
                )?
            }
            (None, security_runtime) => {
                build_kernel_with_security_runtime(loaded_policy, &kernel_kp, security_runtime)?
            }
        };
        #[cfg(unix)]
        let receipt_store = if broker_runtime.is_some() {
            None
        } else {
            configure_receipt_store(
                &mut kernel,
                effective_receipt_db_path.as_deref(),
                control_url,
                control_token,
                control_authority_public_key,
                control_authority_trusted_public_keys,
            )?
        };
        #[cfg(not(unix))]
        let receipt_store = configure_receipt_store(
            &mut kernel,
            effective_receipt_db_path.as_deref(),
            control_url,
            control_token,
            control_authority_public_key,
            control_authority_trusted_public_keys,
        )?;
        if let Some(runtime) = keyring_runtime.as_ref().filter(|_| {
            #[cfg(unix)]
            {
                broker_runtime.is_none()
            }
            #[cfg(not(unix))]
            {
                true
            }
        }) {
            let receipt_store = receipt_store.ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring runtime requires a durable normal receipt store".to_string(),
                )
            })?;
            runtime.attach_receipt_store(receipt_store)?;
        }
        #[cfg(unix)]
        if broker_runtime.is_none() {
            if durable_admission.is_none() {
                configure_revocation_store(
                    &mut kernel,
                    effective_revocation_db_path.as_deref(),
                    control_url,
                    control_token,
                )?;
            }
            configure_capability_authority(
                &mut kernel,
                authority_seed_path,
                authority_db_path,
                effective_receipt_db_path.as_deref(),
                effective_budget_db_path.as_deref(),
                control_url,
                control_token,
                control_authority_public_key,
                control_authority_trusted_public_keys,
                None,
                issuance_policy,
                runtime_assurance_policy,
            )?;
        }
        #[cfg(not(unix))]
        {
            if durable_admission.is_none() {
                configure_revocation_store(
                    &mut kernel,
                    effective_revocation_db_path.as_deref(),
                    control_url,
                    control_token,
                )?;
            }
            configure_capability_authority(
                &mut kernel,
                authority_seed_path,
                authority_db_path,
                effective_receipt_db_path.as_deref(),
                effective_budget_db_path.as_deref(),
                control_url,
                control_token,
                control_authority_public_key,
                control_authority_trusted_public_keys,
                None,
                issuance_policy,
                runtime_assurance_policy,
            )?;
        }
        attach_cli_durable_admission_runtime(&mut kernel, durable_admission.as_ref())?;
        #[cfg(unix)]
        let mut kernel = if broker_runtime.is_some() {
            kernel
        } else {
            compose_cli_admission_runtime_kernel(
                kernel,
                effective_aggregate_invocation_admission,
                effective_admission_operation_db_path.as_deref(),
                effective_approval_db_path.as_deref(),
                effective_budget_db_path.as_deref(),
                control_url,
                control_token,
                partition_escrow_authority_descriptor,
                partition_escrow_authority_signer,
            )?
        };
        #[cfg(not(unix))]
        let mut kernel = compose_cli_admission_runtime_kernel(
            kernel,
            effective_aggregate_invocation_admission,
            effective_admission_operation_db_path.as_deref(),
            effective_approval_db_path.as_deref(),
            effective_budget_db_path.as_deref(),
            control_url,
            control_token,
            partition_escrow_authority_descriptor,
            partition_escrow_authority_signer,
        )?;

        let (wrapped_cmd, wrapped_args) = command
            .split_first()
            .ok_or_else(|| CliError::cli_other_error("empty MCP server command".to_string()))?;
        let wrapped_arg_refs = wrapped_args.iter().map(String::as_str).collect::<Vec<_>>();

        let admitted_manifest = manifest_registry
            .verified_manifest(server_id)
            .ok_or_else(|| {
                CliError::cli_other_error("admitted MCP manifest is unavailable".to_string())
            })?
            .manifest
            .clone();
        let native_launch = crate::mcp_cli::load_native_mcp_launch(
            cage_policy_path,
            cage_policy_signer,
            wrapped_cmd,
            &wrapped_arg_refs,
            Some(Arc::clone(&manifest_registry)),
        )?;
        if native_launch.server_id() != server_id {
            return Err(CliError::cli_other_error(
                "native MCP launch policy belongs to a different server".to_string(),
            ));
        }
        let adapted_server = AdaptedMcpServer::from_command(
            wrapped_cmd,
            &wrapped_arg_refs,
            McpAdapterConfig {
                server_id: server_id.to_string(),
                server_name: server_name.unwrap_or(server_id).to_string(),
                server_version: server_version
                    .unwrap_or(env!("CARGO_PKG_VERSION"))
                    .to_string(),
                public_key: manifest_public_key.to_string(),
            },
            native_launch,
        )?;
        let upstream_notification_source = adapted_server.notification_source();
        let serve_result = (|| -> Result<(), CliError> {
            let upstream_capabilities = adapted_server.upstream_capabilities();
            let manifest = adapted_server.manifest_clone();
            chio_mcp_adapter::verify_discovered_manifest_surface(&manifest, &admitted_manifest)?;
            if let Some(resource_provider) = adapted_server.resource_provider() {
                kernel.register_resource_provider(Box::new(resource_provider));
            }
            if let Some(prompt_provider) = adapted_server.prompt_provider() {
                kernel.register_prompt_provider(Box::new(prompt_provider));
            }
            kernel.register_tool_server(Box::new(adapted_server));

            let agent_kp = Keypair::generate();
            let agent_pk = agent_kp.public_key();
            let agent_id = agent_pk.to_hex();
            let capabilities =
                issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;

            info!(
                capability_count = capabilities.len(),
                upstream_resources = upstream_capabilities.resources_supported,
                upstream_prompts = upstream_capabilities.prompts_supported,
                upstream_completions = upstream_capabilities.completions_supported,
                wrapped_command = wrapped_cmd,
                "initialized MCP edge session"
            );

            let edge_config = McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size,
                tools_list_changed: tools_list_changed || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            };
            #[cfg(unix)]
            let security_context_authority = broker_runtime
                .as_ref()
                .map(|runtime| {
                    runtime.security_invocation_context_authority(None, &agent_id, &capabilities)
                })
                .transpose()
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "production security invocation authority composition failed: {error}"
                    ))
                })?;
            #[cfg(not(unix))]
            let security_context_authority =
                None::<std::sync::Arc<dyn chio_kernel::SecurityInvocationContextAuthority>>;
            let kernel = Arc::new(kernel);
            #[cfg(unix)]
            if let Some(runtime) = broker_runtime.as_ref() {
                runtime
                    .bind_active_response_kernel(Arc::clone(&kernel))
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production active-response kernel binding failed: {error}"
                        ))
                    })?;
            }
            let mut edge = match security_context_authority {
        Some(authority) => {
            ChioMcpEdge::new_with_shared_kernel_manifest_registry_arc_and_security_context_authority(
                edge_config,
                Arc::clone(&kernel),
                agent_id,
                capabilities,
                manifest_registry,
                authority,
            )
        }
        None => ChioMcpEdge::new_with_shared_kernel_and_manifest_registry_arc(
            edge_config,
            kernel,
            agent_id,
            capabilities,
            manifest_registry,
        ),
    }?;
            edge.attach_upstream_transport(Arc::clone(&upstream_notification_source));

            let result =
                edge.serve_stdio(std::io::BufReader::new(std::io::stdin()), std::io::stdout());
            drop(edge);
            Ok(result?)
        })();
        let shutdown_result = upstream_notification_source.shutdown().map_err(|error| {
            CliError::cli_other_error(format!(
                "MCP native transport terminal receipt persistence failed: {error}"
            ))
        });
        match (serve_result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(serve_error), Err(shutdown_error)) => Err(CliError::cli_other_error(format!(
            "MCP edge failed: {serve_error}; native transport shutdown also failed: {shutdown_error}"
        ))),
    }
    })();
    let completion_result = finish_cli_active_defense_with_shutdown(entrypoint_result, || {
        #[cfg(unix)]
        {
            shutdown_cli_active_defense(&mut broker_runtime, active_defense_runtime.as_ref())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    });
    #[cfg(unix)]
    drop(broker_runtime);
    #[cfg(unix)]
    drop(active_defense_runtime);
    completion_result
}

include!("runtime/http_and_trust.rs");

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod runtime_local_error_domain_tests;
