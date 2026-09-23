//! The real daemon and TLS peer consume the original native kernel capture.
use super::fixture::*;
use super::orchestration::*;
use super::roles::{assert_raw_absent, scan_tree_for_raw_canary};
use super::*;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationState, AdmissionOperationStore,
};
use chio_kernel::budget_store::BudgetInvocationState;
use chio_kernel::{BudgetStore, ToolCallOutput, Verdict};

#[cfg(feature = "real-linux-enforcement")]
#[path = "native_confined.rs"]
mod confined;
#[path = "native_host.rs"]
mod host;
#[path = "native_mcp.rs"]
mod mcp;
#[path = "native_response_tests.rs"]
mod responses;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeliveryRoute {
    Direct,
    ObservedMcp,
    #[cfg(feature = "real-linux-enforcement")]
    ConfinedMcp,
}

#[test]
fn native_kernel_broker_daemon_captures_once_and_sends_real_tls_without_secret_crossing(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    run_native_delivery(DeliveryRoute::Direct, None)
}

#[test]
fn native_kernel_broker_mcp_tool_preserves_original_capture_and_signed_completion(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    run_native_delivery(DeliveryRoute::ObservedMcp, None)
}

#[test]
fn native_kernel_broker_mcp_tool_keeps_capture_on_lost_or_invalid_completion(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for fault in [
        mcp::CompletionFault::LoseReply,
        mcp::CompletionFault::ChangeBody,
        mcp::CompletionFault::ExtraContent,
    ] {
        run_native_delivery(DeliveryRoute::ObservedMcp, Some(fault))?;
    }
    Ok(())
}

fn run_native_delivery(
    route: DeliveryRoute,
    fault: Option<mcp::CompletionFault>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mcp_route = route != DeliveryRoute::Direct;
    let directory = crate::private_tempdir()?;
    let kernel_directory = crate::private_tempdir()?;
    let tool_directory = crate::private_tempdir()?;
    let root = fs::canonicalize(directory.path())?;
    let canary = random_canary();
    let probe = CanaryProbe::from_bytes(&canary);
    let master = sealed_seed("native-broker-master", &[211; 32]);
    let broker_key = Keypair::from_seed(&[212; 32]);
    let signing = sealed_seed("native-broker-signing", &[212; 32]);
    let issuer = Keypair::from_seed(&[213; 32]);
    let authority_key = Keypair::from_seed(&[214; 32]);
    let caller = Keypair::from_seed(&[215; 32]);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let mut fixture = boundary_fixture(
        &root,
        port,
        broker_key.public_key(),
        issuer.public_key(),
        authority_key.public_key(),
        master.metadata()?.uid(),
    );
    // The native authority's independently selected audience binds both ports.
    fixture.config.parent_audience = fixture.config.broker_audience.clone();
    write_private(
        &fixture.config_path,
        &canonical_json_bytes(&fixture.config)?,
    );
    let mut command = helper_command(BROKER_HELPER, "broker", &root);
    command
        .stdin(Stdio::piped())
        .env(START_GATE_ENV, "1")
        .env(CONFIG_ENV, &fixture.config_path)
        .env(CERT_ENV, &fixture.certificate_path)
        .env(MASTER_FD_ENV, master.as_raw_fd().to_string())
        .env(SIGNING_FD_ENV, signing.as_raw_fd().to_string());
    inherit_seed_descriptors_in_child(&mut command, [master.as_raw_fd(), signing.as_raw_fd()]);
    let mut child = command.spawn()?;
    let mut ready = child.stdin.take().ok_or("native broker start gate")?;
    let mut broker = ManagedChild::new(child);
    let credential = CredentialRef {
        provider: CREDENTIAL_PROVIDER.into(),
        credential_id: CREDENTIAL_ID.into(),
        version: 1,
    };
    let tool = Arc::new(mcp::McpTool {
        // Broker custody is not the tool's working directory. The controller
        // separately scans every private tree after the live observation.
        directory: fs::canonicalize(tool_directory.path())?,
        peer: BrokerPeerIdentity {
            process_id: broker.id(),
            user_id: fixture.config.trusted_service_uid,
            group_id: rustix::process::getegid().as_raw(),
        },
        signer: broker_key.public_key(),
        probe: probe.clone(),
        calls: std::sync::atomic::AtomicUsize::new(0),
        prepared: std::sync::Mutex::new(None),
        prepared_stream: std::sync::Mutex::new(None),
        completion: std::sync::Mutex::new(None),
        fault,
    });
    #[cfg(feature = "real-linux-enforcement")]
    let confined = (route == DeliveryRoute::ConfinedMcp)
        .then(|| {
            confined::ConfinedDelivery::new(
                tool_directory.path(),
                &fixture.config,
                broker.id(),
                &authority_key,
            )
        })
        .transpose()?;
    let (connection, registry) = match route {
        DeliveryRoute::Direct => (None, host::manifests(&authority_key, false)?),
        DeliveryRoute::ObservedMcp => (
            Some(tool.clone() as Arc<dyn crate::kernel_admission::BrokerMcpToolConnection>),
            host::manifests(&authority_key, false)?,
        ),
        #[cfg(feature = "real-linux-enforcement")]
        DeliveryRoute::ConfinedMcp => {
            let confined = confined.as_ref().ok_or("confined delivery absent")?;
            (
                Some(confined.tool.clone()
                    as Arc<dyn crate::kernel_admission::BrokerMcpToolConnection>),
                confined.registry.clone(),
            )
        }
    };
    let host = host::NativeHost::new(
        kernel_directory.path(),
        &fixture.config,
        broker.id(),
        (&issuer, &caller, &authority_key),
        execution_request(port, credential.clone(), &issuer, &caller),
        connection,
        registry,
    )?;
    let runtime = mcp_route
        .then(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
        .transpose()?;
    let invoke = || match runtime.as_ref() {
        Some(runtime) => runtime.block_on(
            host.kernel
                .evaluate_tool_call_with_security_context(&host.request, &host.context),
        ),
        None => host
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&host.request, &host.context),
    };
    let authority_server = AuthorityRpcServer::bind(
        &fixture.config.authority_socket_path,
        broker_key.public_key(),
        Arc::new(Ed25519Backend::new(authority_key.clone())),
        host.handler.clone(),
        30,
    )?;
    let mut authority = AuthorityServerGuard::start(authority_server);
    ready.write_all(&[1])?;
    drop(ready);
    wait_for_broker(&mut broker, &fixture.config);
    provision_credential(
        &fixture.config.ipc_socket_path,
        &credential,
        &canary,
        &fixture.approver,
        &fixture.admin_subject,
    );
    let mut upstream_command = helper_command(UPSTREAM_HELPER, "upstream", &root);
    upstream_command
        .env(CERT_ENV, &fixture.certificate_path)
        .env(KEY_ENV, &fixture.private_key_path)
        .env(FALLBACK_MARKER_ENV, &fixture.fallback_marker_path)
        .env(CANARY_LENGTH_ENV, probe.length.to_string())
        .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256));
    let mut upstream = spawn_with_stdin(
        upstream_command,
        OwnedFd::from(listener),
        "native TLS observer",
    );
    let outcome = invoke();
    if fault.is_none() && !matches!(&outcome, Ok(response) if response.verdict == Verdict::Allow) {
        #[cfg(feature = "real-linux-enforcement")]
        if let Some(confined) = confined.as_ref() {
            confined.diagnose_preparation(&fixture.config);
        }
        let retained = host
            .authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &host.request.request_id)?,
                &host.authority.mutation_fence(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_millis()
                    .try_into()?,
            )?;
        eprintln!(
            "native broker final state: {:?}",
            retained.as_ref().map(|(operation, _)| operation.state())
        );
        let stopped = broker.kill_and_output();
        let upstream_diagnostic = if upstream.try_wait().is_some() {
            String::from_utf8_lossy(&upstream.wait_output().stderr).into_owned()
        } else {
            "upstream is still running".into()
        };
        panic!(
            "native broker denied: {:?}; broker diagnostic: {}; upstream: {}",
            outcome
                .as_ref()
                .map(|response| &response.reason)
                .map_err(|error| error.to_string()),
            String::from_utf8_lossy(&stopped.stderr),
            upstream_diagnostic,
        );
    }
    let response: BrokerExecuteResponse = if fault.is_some() {
        assert!(
            !matches!(&outcome, Ok(response) if response.verdict == Verdict::Allow),
            "{fault:?}: {outcome:?}"
        );
        tool.completion
            .lock()
            .map_err(|_| "MCP observation lock")?
            .clone()
            .ok_or("no independently observed broker completion")?
    } else {
        let outcome = outcome.as_ref().map_err(|error| error.to_string())?;
        let Some(ToolCallOutput::Value(value)) = &outcome.output else {
            return Err("native broker call has no value".into());
        };
        serde_json::from_value(value.clone())?
    };
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
    verify_execution_receipt(&response.receipt, &broker_key.public_key())?;
    assert_raw_absent(
        &canary,
        &canonical_json_bytes(&response)?,
        "native broker response and receipt",
    );
    assert_raw_absent(
        &canary,
        &canonical_json_bytes(&host.request)?,
        "native tool request",
    );
    #[cfg(feature = "real-linux-enforcement")]
    if let Some(confined) = confined.as_ref() {
        confined.verify_receipts(&canary)?;
    }
    let store = host.authority.admission_operation_store();
    let fence = host.authority.mutation_fence();
    let now_ms = || -> std::result::Result<u64, Box<dyn std::error::Error>> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?)
    };
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &host.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original native operation")?;
    if fault.is_some() {
        assert_eq!(
            operation.state(),
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            "{fault:?}: {outcome:?}"
        );
    } else {
        assert!(operation.state().is_terminal());
        assert_ne!(
            operation.state(),
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
    }
    let operation_id = operation.binding().operation_id();
    let (registration, original) = host
        .reader
        .read_registration(host.participant.as_ref(), operation_id, now_ms()?)?
        .ok_or("original broker registration")?;
    assert_eq!(original, host.execute);
    assert_eq!(response.receipt.body.operation_id, operation_id.as_str());
    assert_eq!(
        response.receipt.body.capture_event_id,
        registration.ids.capture_event_id
    );
    assert_eq!(response.receipt.body.quotas, registration.quotas);
    assert_eq!(
        registration.quotas.len(),
        3,
        "parent, aggregate and broker quotas"
    );
    let custody = store
        .load_admission_budget_custody(operation_id, &fence, now_ms()?)?
        .ok_or("original capture")?;
    assert_eq!(custody.invocation_state, BudgetInvocationState::Captured);
    let budget = host.authority.budget_store();
    for quota in &custody.invocation_quotas {
        let usage = budget
            .get_invocation_quota_usage(&quota.key)?
            .ok_or("quota usage")?;
        assert_eq!(usage.captured_invocations, 1);
        assert_eq!(usage.reserved_invocations, 0);
    }
    let events = budget.list_mutation_events(100, Some(&host.request.capability.id), None)?;
    let replay = invoke();
    if fault.is_some() {
        assert!(
            !matches!(&replay, Ok(response) if response.verdict == Verdict::Allow),
            "{fault:?}: {replay:?}"
        );
    } else {
        let replay = replay?;
        assert_eq!(replay.verdict, Verdict::Allow, "{replay:?}");
        assert_eq!(replay.output, outcome?.output);
    }
    assert_eq!(
        budget.list_mutation_events(100, Some(&host.request.capability.id), None)?,
        events
    );
    let client = BrokerIpcClient::new(
        BrokerIpcClientConfig {
            socket_path: fixture.config.ipc_socket_path.clone(),
            tenant_scope: TENANT_SCOPE.into(),
            timeout_ms: 3_000,
            expected_peer: BrokerPeerIdentity {
                process_id: broker.id(),
                user_id: fixture.config.trusted_service_uid,
                group_id: rustix::process::getegid().as_raw(),
            },
            trusted_receipt_signer: broker_key.public_key(),
        },
        Arc::new(Ed25519Backend::new(authority_key)),
    )?;
    for substitution in ["destination", "header", "body", "options", "proof"] {
        let mut changed = host.execute.clone();
        match substitution {
            "destination" => changed
                .request
                .destination
                .exact_path_and_query
                .push_str("-changed"),
            "header" => changed
                .request
                .headers
                .push(crate::protocol::HeaderField::normalized(
                    "x-changed",
                    b"true",
                )?),
            "body" => changed.request.body.push(b' '),
            "options" => changed.request.options.timeout_ms -= 1,
            _ => changed.proof.body.nonce.push_str("-replayed"),
        }
        assert!(client.execute(&changed).is_err(), "{substitution}");
    }
    let death_socket = client.connect_authenticated()?;
    let broker_output = broker.kill_and_output();
    assert_raw_absent(&canary, &broker_output.stdout, "native broker stdout");
    assert_raw_absent(&canary, &broker_output.stderr, "native broker stderr");
    let mut unavailable = helper_command(TOOL_HELPER, "tool_unavailable", &root);
    unavailable
        .env(
            REQUEST_ENV,
            hex::encode(canonical_json_bytes(&host.execute)?),
        )
        .env(
            RECEIPT_SIGNER_ENV,
            hex::encode(canonical_json_bytes(&broker_key.public_key())?),
        )
        .env(CANARY_LENGTH_ENV, probe.length.to_string())
        .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256));
    let output = spawn_with_stdin(
        unavailable,
        OwnedFd::from(death_socket),
        "native broker death observer",
    )
    .wait_output();
    assert!(output.status.success());
    assert_raw_absent(&canary, &output.stdout, "native tool stdout");
    assert_raw_absent(&canary, &output.stderr, "native tool stderr");
    assert!(std::str::from_utf8(&output.stdout)?.contains(FALLBACK_MARKER));
    write_private(&fixture.fallback_marker_path, b"complete");
    let upstream_output = upstream.wait_output();
    assert!(
        upstream_output.status.success(),
        "{}",
        String::from_utf8_lossy(&upstream_output.stderr)
    );
    let observed: UpstreamBoundaryReport =
        report_from_output(&upstream_output.stdout, UPSTREAM_REPORT_PREFIX);
    assert_eq!(observed.connection_count, 1);
    assert_eq!(observed.credential_matches, 1);
    assert!(observed.authorization_exact_bearer_canary);
    assert_eq!(
        observed.request_sha256,
        hex::encode(Sha256::digest(expected_boundary_http_request(
            &host.execute,
            &canary
        )))
    );
    assert_raw_absent(&canary, &upstream_output.stdout, "TLS observer stdout");
    assert_raw_absent(&canary, &upstream_output.stderr, "TLS observer stderr");
    assert_eq!(
        budget.list_mutation_events(100, Some(&host.request.capability.id), None)?,
        events
    );
    scan_tree_for_raw_canary(&canary, &root);
    scan_tree_for_raw_canary(&canary, kernel_directory.path());
    scan_tree_for_raw_canary(&canary, tool_directory.path());
    authority.stop();
    assert_eq!(
        tool.calls.load(Ordering::SeqCst),
        usize::from(route == DeliveryRoute::ObservedMcp)
    );
    responses::reject_signed_capture_substitutions(&host, operation_id, &response, &broker_key)?;
    let (after_verification, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &host.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("operation after historical verification")?;
    assert_eq!(after_verification.state(), operation.state());
    assert_eq!(
        budget.list_mutation_events(100, Some(&host.request.capability.id), None)?,
        events
    );
    Ok(())
}
