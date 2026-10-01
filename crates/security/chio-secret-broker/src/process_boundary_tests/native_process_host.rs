//! Exercise the shipped process host against the existing real TLS/broker fixture.
use super::*;
use serde_json::{json, Value};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn cli(binary: &Path, args: &[&str]) -> TestResult<Value> {
    let output = Command::new(binary).args(args).output()?;
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

fn path(path: &Path) -> &str {
    path.to_str().test_expect("fixture path is UTF-8")
}

fn serve(binary: &Path, state: &Path, socket: &Path) -> TestResult<ManagedChild> {
    let child = Command::new(binary)
        .args([
            "process",
            "serve",
            "--state",
            path(state),
            "--socket",
            path(socket),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut host = ManagedChild::new(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        if host.try_wait().is_some() {
            let output = host.wait_output();
            return Err(format!(
                "process host exited: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        assert!(
            Instant::now() < deadline,
            "process host readiness timed out"
        );
        thread::sleep(Duration::from_millis(10));
    }
    Ok(host)
}

fn stop(host: &mut ManagedChild) -> TestResult<Vec<u8>> {
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(host.id().try_into()?).ok_or("host PID")?,
        rustix::process::Signal::TERM,
    )?;
    let output = host.wait_output();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stderr)
}

fn invoke(socket: &Path, descriptor: &Value, request: &Value) -> TestResult<Value> {
    use std::io::BufRead;
    let mut operation = request.clone();
    operation["op"] = json!("invoke");
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&canonical_json_bytes(&json!({
        "protocol": "chio.process.v1", "credential": descriptor["credential"],
        "operation": operation
    }))?)?;
    stream.write_all(b"\n")?;
    let mut response = String::new();
    io::BufReader::new(stream).read_line(&mut response)?;
    let response: Value = serde_json::from_str(&response)?;
    assert_eq!(response["ok"], true, "{response}");
    Ok(response["result"].clone())
}

#[test]
#[cfg_attr(
    not(target_arch = "x86_64"),
    ignore = "requires Linux x86_64 cage enforcement"
)]
fn confined_broker_process_host_exports_original_call_and_replays_after_restart() -> TestResult {
    process_host(false)
}

#[test]
#[cfg_attr(
    not(target_arch = "x86_64"),
    ignore = "requires Linux x86_64 cage enforcement"
)]
fn governed_broker_process_host_verifies_original_keyring_authority() -> TestResult {
    process_host(true)
}

fn process_host(governed: bool) -> TestResult {
    // The owning release runner builds chio beside the original witness binary.
    let binary = fs::canonicalize(
        PathBuf::from(required_environment("CHIO_KEYLOG_WITNESS")).with_file_name("chio"),
    )?;
    let target = fs::canonicalize(required_environment("CHIO_BROKER_MCP_TOOL"))?;
    let helper = fs::canonicalize(required_environment("CHIO_CAGE_TEST_HELPER"))?;
    let directory = crate::private_tempdir()?;
    let root = fs::canonicalize(directory.path())?;
    let keyring = governed
        .then(|| keyring::KeyringDelivery::new(&root, &Keypair::from_seed(&[227; 32]).public_key()))
        .transpose()?
        .map(keyring::KeyringDelivery::into_process_host);
    let state = root.join("host");
    let socket = root.join("worker.sock");
    let security = root.join("launch");
    let anchor = tempfile::Builder::new()
        .prefix("chio-host-cage-")
        .tempdir_in("/dev/shm")?;
    fs::set_permissions(anchor.path(), fs::Permissions::from_mode(0o700))?;
    let canary = random_canary();
    let probe = CanaryProbe::from_bytes(&canary);
    let master = sealed_seed("process-host-broker-master", &[221; 32]);
    let broker_key = Keypair::from_seed(&[222; 32]);
    let signing = sealed_seed("process-host-broker-signing", &[222; 32]);
    let issuer = Keypair::from_seed(&[223; 32]);
    let authority_key = Keypair::from_seed(&[224; 32]);
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
    fixture.config.authority_socket_path = state.join("broker-authority.sock");
    fixture.config.parent_audience = fixture.config.broker_audience.clone();
    write_private(
        &fixture.config_path,
        &canonical_json_bytes(&fixture.config)?,
    );
    let seed = root.join("authority.seed");
    write_private(&seed, hex::encode([224; 32]).as_bytes());
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
    let mut ready = child.stdin.take().ok_or("broker start gate")?;
    let mut broker = ManagedChild::new(child);
    let binding = root.join("broker-binding.json");
    write_private(
        &binding,
        &canonical_json_bytes(&json!({
            "socket_path": fixture.config.ipc_socket_path,
            "authentication_digest": chio_core_types::sha256_hex(&canonical_json_bytes(&broker_key.public_key())?),
            "expected_peer_identity": {"pid": broker.id(), "uid": fixture.config.trusted_service_uid, "gid": rustix::process::getegid().as_raw()}
        }))?,
    );
    let tools = root.join("tools.json");
    let discovery = crate::prepared_mcp::PreparedBrokerMcpConfig::new(
        TENANT_SCOPE.into(),
        host::TOOL.into(),
        broker_key.public_key(),
    )?;
    write_private(
        &tools,
        &canonical_json_bytes(&json!({"tools":[discovery.tool_definition()]}))?,
    );
    let broker_public = broker_key.public_key().to_hex();
    let tool_args = [
        "--tenant-scope",
        TENANT_SCOPE,
        "--tool-name",
        host::TOOL,
        "--receipt-signer",
        &broker_public,
    ];
    let uid = fixture.config.trusted_service_uid.to_string();
    let gid = rustix::process::getegid().as_raw().to_string();
    let identity = chio_cage::ExecutionIdentity::from_observed_credentials(
        fixture.config.trusted_service_uid,
        rustix::process::getegid().as_raw(),
        rustix::process::getgroups()?
            .into_iter()
            .map(|group| group.as_raw())
            .collect(),
    )?;
    let supplementary_gids: Vec<_> = identity
        .supplementary_gids()
        .iter()
        .map(u32::to_string)
        .collect();
    let mut args = vec![
        "security",
        "provision-reference-runtime",
        "--output-dir",
        path(&security),
        "--tools-fixture",
        path(&tools),
        "--target",
        path(&target),
        "--cage-init",
        path(&helper),
        "--max-artifact-bytes",
        "67108864",
        "--receipt-rollback-anchor-root",
        path(anchor.path()),
        "--broker-binding",
        path(&binding),
        "--execution-uid",
        &uid,
        "--execution-gid",
        &gid,
        "--server-id",
        host::SERVER,
        "--server-name",
        "Native broker",
        "--server-version",
        "1.0.0",
    ];
    for argument in &tool_args {
        args.extend(["--target-arg", argument]);
    }
    for group in &supplementary_gids {
        args.extend(["--execution-supplementary-gid", group]);
    }
    let provisioned = cli(&binary, &args)?;
    let policy = root.join("policy.yaml");
    write_private(&policy, format!("kernel:\n  max_capability_ttl: 3600\n  delegation_depth_limit: 8\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: {}\n        tool: {}\n        operations: [invoke, delegate]\n        max_invocations: 2\n        ttl: 3600\n", host::SERVER, host::TOOL).as_bytes());
    let configuration = root.join("host-config.json");
    let mut target_argv = vec![path(&target)];
    target_argv.extend(tool_args);
    write_private(
        &configuration,
        &canonical_json_bytes(&json!({
            "schema": "chio.process.host.v1", "policy": policy,
            "servers": [{"id":host::SERVER, "command": target_argv, "request_timeout_seconds":30,
                "launch_policy":security.join("cage-launch-policy.json"), "launch_policy_signer":provisioned["cagePolicyPublicKey"]}],
            "limits":{"max_calls":2,"max_processes":1,"max_depth":0},
            "execution_nonces":true,
            "native_broker": {
                "keyring":keyring.as_ref().map(|keyring| keyring.process_host_config()),
                "security":{"tenant_id":TENANT_SCOPE,"isolation_epoch_id":"host-epoch-1","generation":1},
                "quota":{"issuer":issuer.public_key(),"audience":BROKER_AUDIENCE,"server_id":host::SERVER,"tool_name":host::TOOL,"provider_adapter_id":PROVIDER_ADAPTER_ID,"provider_adapter_version":1,"credential_placement":"bearer_authorization"},
                "broker_identity":broker_key.public_key(),"authority_seed_file":seed,"authority_public_key":authority_key.public_key(),
                "revocation_authority_domain":AUTHORITY_DOMAIN,"ipc_timeout_ms":3000,"fence_ttl_ms":10000,
                "operator_input_floor":{"kind":"known","owners":{},"compartments":[]},
                "classifier":{"id":"host-rules","version":"1","rules":[{"category":"private","expression":"PRIVATE_INPUT","confidence_basis_points":10000}],"category_labels":{"private":{"kind":"known","owners":{},"compartments":["private"]}}}
            }
        }))?,
    );
    cli(
        &binary,
        &[
            "process",
            "init",
            "--config",
            path(&configuration),
            "--state",
            path(&state),
            "--aggregate-invocations",
            "2",
        ],
    )?;
    let bootstrap: chio_core_types::receipt::body::ChioReceipt =
        serde_json::from_slice(&fs::read(state.join("process-bootstrap.json"))?)?;
    let parent: chio_core_types::capability::token::CapabilityToken =
        serde_json::from_value(bootstrap.action.parameters["capabilities"]["root"].clone())?;
    if let Some(keyring) = &keyring {
        keyring.rotate_process_host_authority(&parent)?;
    }
    let credential = CredentialRef {
        provider: CREDENTIAL_PROVIDER.into(),
        credential_id: CREDENTIAL_ID.into(),
        version: 1,
    };
    let mut execute = execution_request(
        port,
        credential.clone(),
        &issuer,
        &Keypair::from_seed(&[225; 32]),
    );
    execute.capability.body.parent_capability_id = parent.id.clone();
    execute.capability.body.subject = parent.subject.clone();
    execute.capability.body.proof.caller_public_key = parent.subject.clone();
    execute.capability = issue_capability(
        execute.capability.body,
        &Ed25519Backend::new(issuer.clone()),
        true,
    )?;
    let capability_file = root.join("broker-capability.json");
    let provider_request = root.join("provider-request.json");
    let prepared = root.join("prepared.json");
    write_private(
        &capability_file,
        &canonical_json_bytes(&execute.capability)?,
    );
    write_private(&provider_request, &canonical_json_bytes(&execute.request)?);
    cli(
        &binary,
        &[
            "process",
            "prepare-broker-call",
            "--state",
            path(&state),
            "--process",
            "root",
            "--operation-key",
            "original-send",
            "--capability",
            path(&capability_file),
            "--request",
            path(&provider_request),
            "--out",
            path(&prepared),
        ],
    )?;
    let prepared: Value = serde_json::from_slice(&fs::read(prepared)?)?;
    // This separately signed request contains private bytes inside the wire
    // byte array. Its separate quota remains available after the allowed call.
    // Keep it second because the private input must permanently taint this flow.
    let mut private_request = execute.request.clone();
    private_request.body = b"PRIVATE_INPUT".to_vec();
    let mut private_capability = execute.capability.body.clone();
    private_capability.capability_id.push_str("-private");
    private_capability.broker_quota_key_id.push_str("-private");
    private_capability.constraints.maximum_body_bytes = private_request.body.len() as u64;
    private_capability.constraints.required_body_sha256 = body_digest(&private_request.body);
    let private_capability =
        issue_capability(private_capability, &Ed25519Backend::new(issuer), true)?;
    write_private(
        &capability_file,
        &canonical_json_bytes(&private_capability)?,
    );
    write_private(&provider_request, &canonical_json_bytes(&private_request)?);
    let private_prepared_file = root.join("private-prepared.json");
    cli(
        &binary,
        &[
            "process",
            "prepare-broker-call",
            "--state",
            path(&state),
            "--process",
            "root",
            "--operation-key",
            "private-send",
            "--capability",
            path(&capability_file),
            "--request",
            path(&provider_request),
            "--out",
            path(&private_prepared_file),
        ],
    )?;
    let private_prepared: Value = serde_json::from_slice(&fs::read(private_prepared_file)?)?;
    let private_request = json!({"operation_key":"private-send","server_id":host::SERVER,"tool_name":host::TOOL,"arguments":private_prepared,"known_outcome_only":false});
    let descriptor_file = root.join("worker.json");
    cli(
        &binary,
        &[
            "process",
            "credential",
            "--state",
            path(&state),
            "--process",
            "root",
            "--socket",
            path(&socket),
            "--out",
            path(&descriptor_file),
        ],
    )?;
    let descriptor: Value = serde_json::from_slice(&fs::read(descriptor_file)?)?;
    if governed {
        let verifier = state.join("keylog-verifier.db");
        let retained = state.join("keylog-verifier.retained");
        fs::rename(&verifier, &retained)?;
        let refused = Command::new(&binary)
            .args([
                "process",
                "serve",
                "--state",
                path(&state),
                "--socket",
                path(&socket),
            ])
            .output();
        fs::rename(&retained, &verifier)?;
        let refused = refused?;
        probe.assert_absent(&refused.stderr, "missing key authority diagnostic");
        assert!(!refused.status.success() && !socket.exists());
        assert!(String::from_utf8_lossy(&refused.stderr)
            .contains("cannot open pinned key-log verifier"));
    }
    let request = json!({"operation_key":"original-send","server_id":host::SERVER,"tool_name":host::TOOL,"arguments":prepared,"known_outcome_only":false});
    let mut process = serve(&binary, &state, &socket)?;
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
    // Nonce admission and cage setup precede the provider connection. Start
    // the existing observer's unchanged accept window at provider readiness;
    // the entire invocation still has its original 30-second read deadline.
    let observer = thread::spawn(move || -> io::Result<ManagedChild> {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let mut descriptors = [PollFd::new(&listener, PollFlags::IN)];
        let ready = poll(
            &mut descriptors,
            Some(&Timespec {
                tv_sec: 30,
                tv_nsec: 0,
            }),
        )?;
        if ready != 1 || !descriptors[0].revents().contains(PollFlags::IN) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "provider connection was not ready within the invocation deadline",
            ));
        }
        Ok(spawn_with_stdin(
            upstream_command,
            OwnedFd::from(listener),
            "process host TLS observer",
        ))
    });
    let response = invoke(&socket, &descriptor, &request);
    let mut upstream = observer
        .join()
        .map_err(|_| "provider observer thread failed")??;
    let response = response?;
    if response["verdict"] != "allow" {
        let output = process.kill_and_output();
        probe.assert_absent(&output.stderr, "process host failure diagnostic");
        eprintln!(
            "process host diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = broker.kill_and_output();
        probe.assert_absent(&output.stderr, "broker failure diagnostic");
        eprintln!(
            "broker diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let connection =
            rusqlite::Connection::open(&fixture.config.databases.receipt_database_path)?;
        let completed: i64 = connection.query_row(
            "SELECT COUNT(*) FROM broker_execution_receipts",
            [],
            |row| row.get(0),
        )?;
        eprintln!("broker completed receipts: {completed}");
        let mut failures =
            connection.prepare("SELECT canonical_receipt FROM broker_failure_receipts")?;
        for bytes in failures.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
            let receipt = serde_json::from_slice(&bytes?)?;
            crate::receipt::verify_failure_receipt(&receipt, &broker_key.public_key())?;
            eprintln!("broker signed failure: {}", receipt.body.diagnostic_code);
        }
        if upstream.try_wait().is_some() {
            let output = upstream.wait_output();
            probe.assert_absent(&output.stderr, "upstream failure diagnostic");
            eprintln!(
                "upstream diagnostic: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        eprintln!(
            "retained failed process host: {}",
            directory.keep().display()
        );
    }
    assert_eq!(response["verdict"], "allow", "{response}");
    let denied = invoke(&socket, &descriptor, &private_request)?;
    assert_eq!(denied["verdict"], "deny", "{denied}");
    assert!(
        denied
            .to_string()
            .contains("native dispatch capture callback failed"),
        "callback refusal must preserve the kernel recovery boundary: {denied}"
    );
    let diagnostic = stop(&mut process)?;
    probe.assert_absent(&diagnostic, "process host policy diagnostic");
    assert!(
        String::from_utf8_lossy(&diagnostic).contains("source exceeds policy clearance"),
        "private input must reach the flow-clearance refusal"
    );
    let mut process = serve(&binary, &state, &socket)?;
    let replay = invoke(&socket, &descriptor, &request)?;
    assert_eq!(
        response, replay,
        "restart must replay the original nonce and receipt"
    );
    stop(&mut process)?;
    write_private(&fixture.fallback_marker_path, b"complete");
    let observed = upstream.wait_output();
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    let report: UpstreamBoundaryReport =
        report_from_output(&observed.stdout, UPSTREAM_REPORT_PREFIX);
    assert_eq!(report.connection_count, 1);
    let request_file = root.join("call-request.json");
    let response_file = root.join("response.json");
    let context_file = root.join("context.json");
    let artifact = root.join("observation.json");
    let kernel_key = root.join("kernel.pub");
    let pin = root.join("trusted-host.json");
    write_private(&request_file, &canonical_json_bytes(&request)?);
    write_private(&response_file, &canonical_json_bytes(&response)?);
    write_private(
        &context_file,
        &canonical_json_bytes(
            &json!({"runtime_id":descriptor["runtime_id"],"process_id":"root","capability_id":parent.id}),
        )?,
    );
    write_private(
        &kernel_key,
        descriptor["kernel_key"]
            .as_str()
            .ok_or("kernel key")?
            .as_bytes(),
    );
    let record: Value = serde_json::from_slice(&fs::read(state.join("host.json"))?)?;
    write_private(&pin, &canonical_json_bytes(&record["config"])?);
    cli(
        &binary,
        &[
            "process",
            "attest-call",
            "--state",
            path(&state),
            "--request",
            path(&request_file),
            "--context",
            path(&context_file),
            "--response",
            path(&response_file),
            "--out",
            path(&artifact),
        ],
    )?;
    let mut verify = vec![
        "process",
        "verify-call",
        "--artifact",
        path(&artifact),
        "--trusted-kernel-pubkey",
        path(&kernel_key),
        "--runtime-id",
        descriptor["runtime_id"].as_str().ok_or("runtime")?,
        "--request",
        path(&request_file),
        "--context",
        path(&context_file),
    ];
    assert!(
        !Command::new(&binary)
            .args(&verify)
            .output()?
            .status
            .success(),
        "broker evidence requires independent host pins"
    );
    verify.extend(["--trusted-broker-host-config", path(&pin)]);
    if let Some(keyring) = &keyring {
        assert!(
            !Command::new(&binary)
                .args(&verify)
                .output()?
                .status
                .success(),
            "governed parent evidence requires the observer's retained key-log verifier"
        );
        verify.extend(["--trusted-keylog-verifier", path(keyring.verifier_path())]);
    }
    let verified = cli(&binary, &verify)?;
    assert!(verified["checks"]
        .as_array()
        .ok_or("verification checks")?
        .contains(&json!("original_composite_capture")));
    assert_eq!(
        verified["checks"]
            .as_array()
            .ok_or("verification checks")?
            .contains(&json!("witnessed_parent_authority")),
        governed
    );
    assert_eq!(
        verified["artifact_schema"],
        "chio.process.call-observation.v3"
    );
    let mut wrong = record["config"].clone();
    wrong["native_broker"]["broker_identity"] = json!(authority_key.public_key());
    write_private(&pin, &canonical_json_bytes(&wrong)?);
    assert!(
        !Command::new(&binary)
            .args(&verify)
            .output()?
            .status
            .success(),
        "a different external broker identity must reject"
    );
    let output = broker.kill_and_output();
    assert_raw_absent(&canary, &output.stdout, "broker stdout");
    assert_raw_absent(&canary, &output.stderr, "broker stderr");
    scan_tree_for_raw_canary(&canary, &root);
    if let Some(keyring) = &keyring {
        // Retain only public observations and independently selected pins for
        // verification by a separately built observer after this host exits.
        write_private(&pin, &canonical_json_bytes(&record["config"])?);
        let public = crate::private_tempdir()?;
        for (source, name) in [
            (&artifact, "observation.json"),
            (&request_file, "request.json"),
            (&context_file, "context.json"),
            (&kernel_key, "kernel.pub"),
            (&pin, "trusted-host.json"),
        ] {
            fs::copy(source, public.path().join(name))?;
        }
        // The fixture's independent verifier has no open connection here;
        // its completed WAL was checkpointed when provisioning returned.
        fs::copy(
            keyring.verifier_path(),
            public.path().join("keylog-verifier.db"),
        )?;
        eprintln!(
            "governed broker public artifacts: {}",
            public.keep().display()
        );
    }
    Ok(())
}
