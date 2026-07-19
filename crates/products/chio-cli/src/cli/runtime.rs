use super::*;
use chio_api_protect::DEFAULT_UPSTREAM_REQUEST_TIMEOUT;
use chio_manifest::{load_existing_verified_manifest_registry, RuntimeToolTopology};
use std::sync::Arc;
use std::time::Duration;

#[path = "runtime/trust_serve.rs"]
mod trust_serve;
pub(crate) use trust_serve::cmd_trust_serve;

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
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
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

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        "loaded policy"
    );

    if authority_seed_path.is_some() && authority_db_path.is_some() {
        return Err(CliError::cli_other_error(
            "use either --authority-seed-file or --authority-db, not both".to_string(),
        ));
    }
    if keyring_config_path.is_some() && authority_seed_path.is_none() {
        return Err(CliError::cli_other_error(
            "--keyring-config requires --authority-seed-file for the active signing backend"
                .to_string(),
        ));
    }
    let (kernel_kp, keyring_runtime) =
        match (keyring_config_path, authority_seed_path, authority_db_path) {
            (Some(config_path), Some(seed_path), None) => {
                let (keypair, runtime) =
                    load_keyring_runtime_from_authority_seed(config_path, seed_path)?;
                (keypair, Some(runtime))
            }
            (None, Some(seed_path), None) => (load_or_create_authority_keypair(seed_path)?, None),
            (None, None, Some(path)) => (
                chio_store_sqlite::SqliteCapabilityAuthority::open(path)?.local_keypair()?,
                None,
            ),
            (None, None, None) => (Keypair::generate(), None),
            (Some(_), None, _) => {
                return Err(CliError::cli_other_error(
                "--keyring-config requires --authority-seed-file for the active signing backend"
                    .to_string(),
            ));
            }
            (_, Some(_), Some(_)) => {
                return Err(CliError::cli_other_error(
                    "use either --authority-seed-file or --authority-db, not both".to_string(),
                ));
            }
        };
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
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
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
    let mut kernel = compose_cli_ordinary_runtime_kernel(
        kernel,
        enable_aggregate_invocation_admission,
        admission_operation_db_path,
        approval_db_path,
        budget_db_path,
        control_url,
        control_token,
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
    upstream_timeout_secs: Option<u64>,
) -> Result<(), CliError> {
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
        let config = ProtectConfig {
            upstream: upstream.to_string(),
            spec_content: None,
            spec_path: spec_path.map(|path| path.display().to_string()),
            listen_addr: listen_addr.to_string(),
            receipt_db: receipt_store.map(|path| path.display().to_string()),
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
            upstream_request_timeout: upstream_timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_UPSTREAM_REQUEST_TIMEOUT),
        };
        ProtectProxy::new(config).run().await.map_err(|error| {
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

pub(crate) fn cmd_start(
    listen_addr: &str,
    receipt_store: Option<&Path>,
    authority_seed_path: Option<&Path>,
    print_config: bool,
) -> Result<(), CliError> {
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
            receipt_db: receipt_store.map(|path| path.display().to_string()),
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
            // The chio-start shape never proxies upstream, so the hop ceiling is
            // moot; keep the default so the serve site's drain window is unchanged.
            upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        ProtectProxy::new(config)
            .run_with_observer(move |bound_addr| {
                let base_url = format!("http://{bound_addr}");
                println!("chio sidecar listening on {base_url}");
                println!(
                    "  routes: /chio/* (health, evaluate, verify), /v1/capabilities/{{,mint,validate,attenuate,release}}, /v1/evaluate, /v1/receipts{{,/verify}}, /approvals/*"
                );
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
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
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

    if authority_seed_path.is_some() && authority_db_path.is_some() {
        return Err(CliError::cli_other_error(
            "use either --authority-seed-file or --authority-db, not both".to_string(),
        ));
    }
    if keyring_config_path.is_some() && authority_seed_path.is_none() {
        return Err(CliError::cli_other_error(
            "--keyring-config requires --authority-seed-file for the active signing backend"
                .to_string(),
        ));
    }
    let (kernel_kp, keyring_runtime) =
        match (keyring_config_path, authority_seed_path, authority_db_path) {
            (Some(config_path), Some(seed_path), None) => {
                let (keypair, runtime) =
                    load_keyring_runtime_from_authority_seed(config_path, seed_path)?;
                (keypair, Some(runtime))
            }
            (None, Some(seed_path), None) => (load_or_create_authority_keypair(seed_path)?, None),
            (None, None, Some(path)) => (
                chio_store_sqlite::SqliteCapabilityAuthority::open(path)?.local_keypair()?,
                None,
            ),
            (None, None, None) => (Keypair::generate(), None),
            (Some(_), None, _) => {
                return Err(CliError::cli_other_error(
                "--keyring-config requires --authority-seed-file for the active signing backend"
                    .to_string(),
            ));
            }
            (_, Some(_), Some(_)) => {
                return Err(CliError::cli_other_error(
                    "use either --authority-seed-file or --authority-db, not both".to_string(),
                ));
            }
        };
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
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
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
    let mut kernel = compose_cli_ordinary_runtime_kernel(
        kernel,
        enable_aggregate_invocation_admission,
        admission_operation_db_path,
        approval_db_path,
        budget_db_path,
        control_url,
        control_token,
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

    if authority_seed_path.is_some() && authority_db_path.is_some() {
        return Err(CliError::cli_other_error(
            "use either --authority-seed-file or --authority-db, not both".to_string(),
        ));
    }
    if keyring_config_path.is_some() && authority_seed_path.is_none() {
        return Err(CliError::cli_other_error(
            "--keyring-config requires --authority-seed-file for the active signing backend"
                .to_string(),
        ));
    }
    let (kernel_kp, keyring_runtime) =
        match (keyring_config_path, authority_seed_path, authority_db_path) {
            (Some(config_path), Some(seed_path), None) => {
                let (keypair, runtime) =
                    load_keyring_runtime_from_authority_seed(config_path, seed_path)?;
                (keypair, Some(runtime))
            }
            (None, Some(seed_path), None) => (load_or_create_authority_keypair(seed_path)?, None),
            (None, None, Some(path)) => (
                chio_store_sqlite::SqliteCapabilityAuthority::open(path)?.local_keypair()?,
                None,
            ),
            (None, None, None) => (Keypair::generate(), None),
            (Some(_), None, _) => {
                return Err(CliError::cli_other_error(
                "--keyring-config requires --authority-seed-file for the active signing backend"
                    .to_string(),
            ));
            }
            (_, Some(_), Some(_)) => {
                return Err(CliError::cli_other_error(
                    "use either --authority-seed-file or --authority-db, not both".to_string(),
                ));
            }
        };
    if broker_config_path.is_some() && keyring_runtime.is_none() {
        return Err(CliError::cli_other_error(
            "production broker composition requires an enterprise keyring-backed authority signer"
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
            configure_revocation_store(
                &mut kernel,
                effective_revocation_db_path.as_deref(),
                control_url,
                control_token,
            )?;
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
            configure_revocation_store(
                &mut kernel,
                effective_revocation_db_path.as_deref(),
                control_url,
                control_token,
            )?;
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
        #[cfg(unix)]
        let mut kernel = if broker_runtime.is_some() {
            kernel
        } else {
            compose_cli_ordinary_runtime_kernel(
                kernel,
                effective_aggregate_invocation_admission,
                effective_admission_operation_db_path.as_deref(),
                effective_approval_db_path.as_deref(),
                effective_budget_db_path.as_deref(),
                control_url,
                control_token,
            )?
        };
        #[cfg(not(unix))]
        let mut kernel = compose_cli_ordinary_runtime_kernel(
            kernel,
            effective_aggregate_invocation_admission,
            effective_admission_operation_db_path.as_deref(),
            effective_approval_db_path.as_deref(),
            effective_budget_db_path.as_deref(),
            control_url,
            control_token,
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

fn load_manifest_for_mcp_kernel(
    signed_manifest_path: &Path,
    manifest_public_key: &str,
    server_id: &str,
) -> Result<chio_manifest::VerifiedManifestRegistry, CliError> {
    load_existing_verified_manifest_registry(
        signed_manifest_path,
        manifest_public_key,
        server_id,
        RuntimeToolTopology::local(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to load admitted MCP manifest: {error}"))
    })
}

fn remote_authority_successors_from_env(
) -> Result<Vec<trust_control::service_runtime::PinnedAuthoritySuccessor>, CliError> {
    let Some(value) = std::env::var_os("CHIO_CONTROL_AUTHORITY_SUCCESSORS") else {
        return Ok(Vec::new());
    };
    let value = value.into_string().map_err(|_| {
        CliError::cli_other_error(
            "CHIO_CONTROL_AUTHORITY_SUCCESSORS is not valid UTF-8".to_string(),
        )
    })?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|entry| {
            let (generation, public_key) = entry.split_once(':').ok_or_else(|| {
                CliError::cli_other_error(
                    "control-authority successors must use generation:public-key entries"
                        .to_string(),
                )
            })?;
            let generation = generation.parse::<u64>().map_err(|_| {
                CliError::cli_other_error(
                    "control-authority successor generation is invalid".to_string(),
                )
            })?;
            Ok(trust_control::service_runtime::PinnedAuthoritySuccessor {
                generation,
                public_key: chio_core::PublicKey::from_hex(public_key)?,
            })
        })
        .collect()
}

pub(crate) fn cmd_mcp_serve_http(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    signed_manifest_path: Option<&Path>,
    manifest_public_key: Option<&str>,
    cage_policy_path: &Path,
    cage_policy_signer: &str,
    page_size: usize,
    tools_list_changed: bool,
    shared_hosted_owner: bool,
    listen: SocketAddr,
    auth_token: Option<&str>,
    auth_jwt_public_key: Option<&str>,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_introspection_client_id: Option<&str>,
    auth_introspection_client_secret: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_server_seed_file: Option<&Path>,
    identity_federation_seed_file: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    auth_jwt_issuer: Option<&str>,
    auth_jwt_audience: Option<&str>,
    admin_token: Option<&str>,
    remote_authority_workload_token: Option<&str>,
    public_base_url: Option<&str>,
    auth_servers: &[String],
    auth_authorization_endpoint: Option<&str>,
    auth_token_endpoint: Option<&str>,
    auth_registration_endpoint: Option<&str>,
    auth_jwks_uri: Option<&str>,
    auth_scopes: &[String],
    auth_subject: &str,
    auth_code_ttl_secs: u64,
    auth_access_token_ttl_secs: u64,
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
    resume_hmac_keyring_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
) -> Result<(), CliError> {
    let loaded_policy = policy::load_policy_for_runtime(
        policy_path,
        approver_directory_path,
        threshold_proposal_authority_public_key,
    )?;
    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %loaded_policy.identity.source_hash,
        runtime_policy_hash = %loaded_policy.identity.runtime_hash,
        server_id = server_id,
        listen_addr = %listen,
        "loaded policy for remote MCP edge"
    );

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::cli_other_error("empty MCP server command".to_string()))?;

    let auth_token = optional_secret_with_env_fallback(auth_token, "CHIO_MCP_AUTH_TOKEN");
    let admin_token = optional_secret_with_env_fallback(admin_token, "CHIO_MCP_ADMIN_TOKEN");
    let egress_contract = remote_mcp_auth_egress_contract(
        server_id,
        auth_jwt_discovery_url,
        auth_introspection_url,
        auth_jwt_provider_profile,
        auth_jwt_issuer,
        auth_jwks_uri,
    )?;

    remote_mcp::serve_http(remote_mcp::RemoteServeHttpConfig {
        listen,
        auth_token,
        auth_jwt_public_key: auth_jwt_public_key.map(ToOwned::to_owned),
        auth_jwt_discovery_url: auth_jwt_discovery_url.map(ToOwned::to_owned),
        auth_introspection_url: auth_introspection_url.map(ToOwned::to_owned),
        auth_introspection_client_id: auth_introspection_client_id.map(ToOwned::to_owned),
        auth_introspection_client_secret: auth_introspection_client_secret.map(ToOwned::to_owned),
        auth_jwt_provider_profile,
        auth_server_seed_path: auth_server_seed_file.map(Path::to_path_buf),
        identity_federation_seed_path: identity_federation_seed_file.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        auth_jwt_issuer: auth_jwt_issuer.map(ToOwned::to_owned),
        auth_jwt_audience: auth_jwt_audience.map(ToOwned::to_owned),
        admin_token,
        control_url: control_url.map(ToOwned::to_owned),
        control_token: control_token.map(ToOwned::to_owned),
        remote_authority_workload_token: remote_authority_workload_token.map(ToOwned::to_owned),
        control_authority_public_key: control_authority_public_key.cloned(),
        control_authority_trusted_public_keys: control_authority_trusted_public_keys.to_vec(),
        control_authority_successors: remote_authority_successors_from_env()?,
        control_authority_key_log_policy_path: std::env::var_os(
            "CHIO_CONTROL_AUTHORITY_KEY_LOG_POLICY_FILE",
        )
        .map(PathBuf::from),
        control_authority_key_log_verifier_db_path: std::env::var_os(
            "CHIO_CONTROL_AUTHORITY_KEY_LOG_VERIFIER_DB",
        )
        .map(PathBuf::from),
        remote_authority_tenant_id: std::env::var("CHIO_REMOTE_AUTHORITY_TENANT_ID").ok(),
        remote_authority_workload_id: std::env::var("CHIO_REMOTE_AUTHORITY_WORKLOAD_ID").ok(),
        remote_authority_workload_seed_path: std::env::var_os(
            "CHIO_REMOTE_AUTHORITY_WORKLOAD_SEED_FILE",
        )
        .map(PathBuf::from),
        remote_authority_session_admission_seed_path: std::env::var_os(
            "CHIO_REMOTE_AUTHORITY_SESSION_ADMISSION_SEED_FILE",
        )
        .map(PathBuf::from),
        remote_kernel_evidence_seed_path: std::env::var_os(
            "CHIO_REMOTE_KERNEL_EVIDENCE_SEED_FILE",
        )
        .map(PathBuf::from),
        public_base_url: public_base_url.map(ToOwned::to_owned),
        auth_servers: auth_servers.to_vec(),
        auth_authorization_endpoint: auth_authorization_endpoint.map(ToOwned::to_owned),
        auth_token_endpoint: auth_token_endpoint.map(ToOwned::to_owned),
        auth_registration_endpoint: auth_registration_endpoint.map(ToOwned::to_owned),
        auth_jwks_uri: auth_jwks_uri.map(ToOwned::to_owned),
        auth_scopes: auth_scopes.to_vec(),
        auth_subject: auth_subject.to_string(),
        auth_code_ttl_secs,
        auth_access_token_ttl_secs,
        receipt_db_path: receipt_db_path.map(std::path::Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(std::path::Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(std::path::Path::to_path_buf),
        keyring_config_path: keyring_config_path.map(std::path::Path::to_path_buf),
        broker_config_path: broker_config_path.map(std::path::Path::to_path_buf),
        authority_db_path: authority_db_path.map(std::path::Path::to_path_buf),
        budget_db_path: budget_db_path.map(std::path::Path::to_path_buf),
        aggregate_invocation_admission: enable_aggregate_invocation_admission,
        admission_operation_db_path: admission_operation_db_path.map(Path::to_path_buf),
        approval_db_path: approval_db_path.map(Path::to_path_buf),
        approver_directory_path: approver_directory_path.map(Path::to_path_buf),
        threshold_proposal_authority_public_key: threshold_proposal_authority_public_key.cloned(),
        session_db_path: session_db_path.map(std::path::Path::to_path_buf),
        resume_hmac_keyring_path: resume_hmac_keyring_path.map(Path::to_path_buf),
        policy_path: policy_path.to_path_buf(),
        server_id: server_id.to_string(),
        server_name: server_name.unwrap_or(server_id).to_string(),
        server_version: server_version
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        signed_manifest_path: signed_manifest_path.map(Path::to_path_buf),
        manifest_public_key: manifest_public_key.map(ToOwned::to_owned),
        native_launch_factory: Arc::new(crate::mcp_cli::SignedCagePolicyLaunchFactory::new(
            cage_policy_path.to_path_buf(),
            cage_policy_signer.to_string(),
        )?),
        page_size,
        tools_list_changed,
        shared_hosted_owner,
        wrapped_command: wrapped_cmd.clone(),
        wrapped_args: wrapped_args.to_vec(),
        egress_contract,
    })
}

pub(crate) fn remote_mcp_auth_egress_contract(
    server_id: &str,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_jwt_issuer: Option<&str>,
    auth_jwks_uri: Option<&str>,
) -> Result<Option<chio_egress_contract::HttpEgressContract>, CliError> {
    let mut urls = Vec::new();
    urls.extend(auth_jwt_discovery_url);
    urls.extend(auth_introspection_url);
    urls.extend(auth_jwks_uri);
    if auth_jwt_provider_profile.is_some() || auth_jwt_discovery_url.is_some() {
        urls.extend(auth_jwt_issuer);
    }
    if urls.is_empty() {
        return Ok(None);
    }

    let mut allowed_schemes = std::collections::BTreeSet::new();
    let mut allowed_authority_set = std::collections::BTreeSet::new();
    let mut deny_loopback = true;
    let mut deny_link_local = true;
    let mut deny_ipv6_ula = true;

    for raw_url in urls {
        let parsed = url::Url::parse(raw_url).map_err(|error| {
            CliError::cli_other_error(format!(
                "remote MCP auth egress URL `{raw_url}` is invalid: {error}"
            ))
        })?;
        allowed_schemes.insert(parsed.scheme().to_ascii_lowercase());
        allowed_authority_set.insert(cli_normalized_url_authority(&parsed)?);

        if let Some(host) = parsed.host() {
            match host {
                url::Host::Domain(domain) => {
                    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                    if matches!(normalized.as_str(), "localhost" | "localhost.localdomain") {
                        deny_loopback = false;
                    }
                }
                url::Host::Ipv4(address) => {
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if address.is_link_local() {
                        deny_link_local = false;
                    }
                }
                url::Host::Ipv6(address) => {
                    if let Some(mapped) = address.to_ipv4_mapped() {
                        if mapped.is_loopback() {
                            deny_loopback = false;
                        }
                        if mapped.is_link_local() {
                            deny_link_local = false;
                        }
                    }
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if is_cli_ipv6_unicast_link_local(&address) {
                        deny_link_local = false;
                    }
                    if is_cli_ipv6_unique_local(&address) {
                        deny_ipv6_ula = false;
                    }
                }
            }
        }
    }

    let contract = chio_egress_contract::HttpEgressContract {
        tenant_egress_namespace: format!("remote-mcp-auth:{server_id}"),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback,
        deny_link_local,
        deny_ipv6_ula,
        max_redirect_chain: 3,
        max_response_bytes: 1024 * 1024,
    };
    contract.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress contract is invalid: {error}"
        ))
    })?;
    Ok(Some(contract))
}

pub(crate) fn cli_normalized_url_authority(url: &url::Url) -> Result<String, CliError> {
    let host = url.host_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress URL `{url}` is missing an authority"
        ))
    })?;
    let host = match url.host() {
        Some(url::Host::Ipv6(_)) => format!("[{}]", host.to_ascii_lowercase()),
        Some(url::Host::Domain(_)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => host.to_ascii_lowercase(),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

pub(crate) fn is_cli_ipv6_unicast_link_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

pub(crate) fn is_cli_ipv6_unique_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

pub(crate) fn optional_secret_with_env_fallback(
    value: Option<&str>,
    fallback_env: &str,
) -> Option<String> {
    value.map(ToOwned::to_owned).or_else(|| {
        std::env::var(fallback_env)
            .ok()
            .filter(|value| !value.is_empty())
    })
}

pub(crate) fn require_revocation_db_path(
    revocation_db_path: Option<&Path>,
) -> Result<&Path, CliError> {
    revocation_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "trust commands require --revocation-db <path> so persisted trust state is explicit"
                .to_string(),
        )
    })
}

pub(crate) fn require_receipt_db_path(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "shared evidence commands require --receipt-db <path> when --control-url is not set"
                .to_string(),
        )
    })
}

pub(crate) fn parse_cluster_members(
    specs: &[String],
) -> Result<Vec<trust_control::ClusterMemberIdentity>, CliError> {
    specs
        .iter()
        .map(|spec| {
            let (node_url, public_key) = spec.split_once('=').ok_or_else(|| {
                CliError::cli_other_error(
                    "--cluster-member must use URL=ED25519_PUBLIC_KEY form".to_string(),
                )
            })?;
            if node_url.is_empty() || public_key.is_empty() {
                return Err(CliError::cli_other_error(
                    "--cluster-member URL and public key must be non-empty".to_string(),
                ));
            }
            let public_key = chio_core::PublicKey::from_hex(public_key).map_err(|error| {
                CliError::cli_other_error(format!(
                    "--cluster-member has an invalid public key: {error}"
                ))
            })?;
            Ok(trust_control::ClusterMemberIdentity {
                node_url: node_url.to_string(),
                public_key,
            })
        })
        .collect()
}

pub(crate) fn parse_tenant_read_tokens(
    specs: &[String],
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let mut parsed = std::collections::BTreeMap::new();
    for spec in specs {
        let (tenant, token) = spec.split_once('=').ok_or_else(|| {
            CliError::cli_other_error("--tenant-read-token must use tenant=token form".to_string())
        })?;
        if tenant.trim() != tenant || token.trim() != token {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must not contain surrounding whitespace"
                    .to_string(),
            ));
        }
        if tenant.chars().any(char::is_control) || token.chars().any(char::is_control) {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must not contain control characters"
                    .to_string(),
            ));
        }
        if tenant.is_empty() || token.is_empty() {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must be non-empty".to_string(),
            ));
        }
        if parsed
            .insert(tenant.to_string(), token.to_string())
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "duplicate --tenant-read-token for tenant {tenant}"
            )));
        }
    }
    Ok(parsed)
}

pub(crate) fn cmd_trust_revoke(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (newly_revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::service_runtime::client::build_client(url, token)?
            .revoke_capability(capability_id)?;
        (response.newly_revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.revoke(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": true,
            "newly_revoked": newly_revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       true");
        println!("newly_revoked: {newly_revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

pub(crate) fn cmd_trust_status(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::service_runtime::client::build_client(url, token)?
            .list_revocations(&trust_control::RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })?;
        let revoked = response.revoked.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "trust-control revocation response omitted revoked status for {capability_id}"
            ))
        })?;
        (revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.is_revoked(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       {revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod runtime_local_error_domain_tests;
