//! Qualification orchestration only. Every serving component uses production
//! broker construction, native provisioning and the shipped process host.
use super::fixture::*;
use super::orchestration::*;
use super::*;
use serde_json::{json, Value};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerRoute {
    server: String,
    tool: String,
    adapter: crate::generic_https::LocalHttpsAdapterConfig,
    path: String,
    credential_file: PathBuf,
    payload: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Campaign {
    directory: PathBuf,
    binary: PathBuf,
    broker_tool: PathBuf,
    cage_init: PathBuf,
    anchor: PathBuf,
    routes: Vec<ConsumerRoute>,
}

struct Service {
    child: ManagedChild,
    gate: Option<std::process::ChildStdin>,
    fixture: BoundaryFixture,
    credential: Vec<u8>,
}

fn cli(binary: &Path, args: &[String]) -> TestResult<Value> {
    let output = Command::new(binary).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "native provisioning failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn provision(
    campaign: &Campaign,
    route: &ConsumerRoute,
    fixture: &BoundaryFixture,
    child: &ManagedChild,
) -> TestResult<Value> {
    let root = fixture.config_path.parent().ok_or("fixture directory")?;
    let binding = root.join("binding.json");
    write_private(
        &binding,
        &canonical_json_bytes(&json!({
            "socket_path":fixture.config.ipc_socket_path,
            "authentication_digest":chio_core_types::sha256_hex(&canonical_json_bytes(&fixture.config.broker_identity)?),
            "expected_peer_identity":{"pid":child.id(),"uid":fixture.config.trusted_service_uid,"gid":rustix::process::getegid().as_raw()}
        }))?,
    );
    let tools = root.join("tools.json");
    let discovery = crate::prepared_mcp::PreparedBrokerMcpConfig::new(
        TENANT_SCOPE.into(),
        route.tool.clone(),
        fixture.config.broker_identity.clone(),
    )?;
    write_private(
        &tools,
        &canonical_json_bytes(&json!({"tools":[discovery.tool_definition()]}))?,
    );
    let policy = root.join("launch");
    let command = vec![
        campaign.broker_tool.display().to_string(),
        "--tenant-scope".into(),
        TENANT_SCOPE.into(),
        "--tool-name".into(),
        route.tool.clone(),
        "--receipt-signer".into(),
        fixture.config.broker_identity.to_hex(),
    ];
    let mut args: Vec<String> = [
        "security",
        "provision-reference-runtime",
        "--stage",
        "enforced",
        "--max-artifact-bytes",
        "67108864",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for (flag, value) in [
        ("--output-dir", policy.display().to_string()),
        ("--tools-fixture", tools.display().to_string()),
        ("--target", command[0].clone()),
        ("--cage-init", campaign.cage_init.display().to_string()),
        (
            "--receipt-rollback-anchor-root",
            campaign.anchor.display().to_string(),
        ),
        ("--broker-binding", binding.display().to_string()),
        (
            "--execution-uid",
            rustix::process::geteuid().as_raw().to_string(),
        ),
        (
            "--execution-gid",
            rustix::process::getegid().as_raw().to_string(),
        ),
        ("--server-id", route.server.clone()),
        ("--server-name", route.server.clone()),
        ("--server-version", "1".into()),
    ] {
        args.extend([flag.into(), value]);
    }
    for group in rustix::process::getgroups()? {
        if group != rustix::process::getegid() {
            args.extend([
                "--execution-supplementary-gid".into(),
                group.as_raw().to_string(),
            ]);
        }
    }
    for arg in &command[1..] {
        args.extend(["--target-arg".into(), arg.clone()]);
    }
    let result = cli(&campaign.binary, &args)?;
    Ok(
        json!({"id":route.server,"command":command,"request_timeout_seconds":30,
        "launch_policy":policy.join("cage-launch-policy.json"),"launch_policy_signer":result["cagePolicyPublicKey"]}),
    )
}

#[test]
fn native_consumer_services_helper_process() -> TestResult {
    if std::env::var(ROLE_ENV).as_deref() != Ok("consumer-services") {
        return Ok(());
    }
    let input = fs::read(required_environment(CONFIG_ENV))?;
    let campaign: Campaign = serde_json::from_slice(&input)?;
    if campaign.routes.is_empty() || campaign.routes.len() > 16 {
        return Err("invalid campaign routes".into());
    }
    let authority = Keypair::from_seed(&[224; 32]);
    let issuer = Keypair::from_seed(&[223; 32]);
    let authority_seed = campaign.directory.join("authority.seed");
    let issuer_seed = campaign.directory.join("issuer.seed");
    write_private(&authority_seed, hex::encode([224; 32]).as_bytes());
    write_private(&issuer_seed, hex::encode([223; 32]).as_bytes());
    let mut services = Vec::new();
    let mut servers = Vec::new();
    let mut routes = Vec::new();
    let mut grants = Vec::new();
    let mut policy = String::from("kernel:\n  max_capability_ttl: 3600\n  delegation_depth_limit: 8\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n");
    for (index, route) in campaign.routes.iter().enumerate() {
        let root = campaign.directory.join(format!("broker-{index}"));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let key_seed = [180 + index as u8; 32];
        let key = Keypair::from_seed(&key_seed);
        let master = sealed_seed("consumer-master", &[160 + index as u8; 32]);
        let signing = sealed_seed("consumer-signing", &key_seed);
        let mut fixture = boundary_fixture(
            &root,
            route.adapter.port,
            key.public_key(),
            issuer.public_key(),
            authority.public_key(),
            rustix::process::geteuid().as_raw(),
        );
        let socket_name = format!("authority-{index}.sock");
        fixture.config.authority_socket_path = campaign.directory.join("host").join(&socket_name);
        fixture.config.broker_audience = format!("consumer-broker-{index}");
        fixture.config.parent_audience = fixture.config.broker_audience.clone();
        fixture.config.broker_instance_id = format!("consumer-broker-{index}");
        fixture.config.local_adapter = Some(route.adapter.clone());
        write_private(
            &fixture.config_path,
            &canonical_json_bytes(&fixture.config)?,
        );
        let mut command = helper_command(BROKER_HELPER, "broker", &root);
        command
            .stderr(File::create(root.join("broker.stderr"))?)
            .stdout(File::create(root.join("broker.stdout"))?)
            .stdin(Stdio::piped())
            .env(START_GATE_ENV, "1")
            .env(CONFIG_ENV, &fixture.config_path)
            .env(MASTER_FD_ENV, master.as_raw_fd().to_string())
            .env(SIGNING_FD_ENV, signing.as_raw_fd().to_string());
        inherit_seed_descriptors_in_child(&mut command, [master.as_raw_fd(), signing.as_raw_fd()]);
        let mut child = command.spawn()?;
        let gate = child.stdin.take();
        let child = ManagedChild::new(child);
        servers.push(provision(&campaign, route, &fixture, &child)?);
        routes.push(json!({
            "quota":{"issuer":issuer.public_key(),"audience":fixture.config.broker_audience,"server_id":route.server,"tool_name":route.tool,"provider_adapter_id":PROVIDER_ADAPTER_ID,"provider_adapter_version":1,"credential_placement":"bearer_authorization"},
            "broker_identity":key.public_key(),"revocation_authority_domain":AUTHORITY_DOMAIN,"ipc_timeout_ms":3000,"authority_socket_name":socket_name,
            "preparation":{"issuer_seed_file":issuer_seed,"credential":{"provider":CREDENTIAL_PROVIDER,"credentialId":CREDENTIAL_ID,"version":1},
                "destination":{"scheme":"https","normalizedHost":route.adapter.server_name,"explicitPort":route.adapter.port,"method":"POST","exactPathAndQuery":route.path},
                "maximum_body_bytes":131072,"response_limit_bytes":16384,"timeout_ms":20000,"lifetime_seconds":300,"payload":route.payload}
        }));
        grants.push(json!({"server_id":route.server,"tool_name":route.tool}));
        policy.push_str(&format!("      - server: {}\n        tool: {}\n        operations: [invoke, delegate]\n        max_invocations: 24\n        ttl: 3600\n",route.server,route.tool));
        let credential = fs::read(&route.credential_file)?;
        services.push(Service {
            child,
            gate,
            fixture,
            credential,
        });
    }
    let policy_path = campaign.directory.join("policy.yaml");
    write_private(&policy_path, policy.as_bytes());
    write_private(
        &campaign.directory.join("config.json"),
        &canonical_json_bytes(&json!({
            "schema":"chio.process.host.v1","policy":policy_path,"servers":servers,"execution_nonces":true,
            "limits":{"max_calls":24,"max_processes":2,"max_depth":1},
            "children":[{"id":"coder","parent":"root","budget_share_bps":9000,"tools":grants}],
            "native_broker":{"keyring":null,"security":{"tenant_id":TENANT_SCOPE,"isolation_epoch_id":"consumer-epoch","generation":1},
                "routes":routes,"authority_seed_file":authority_seed,"authority_public_key":authority.public_key(),"fence_ttl_ms":10000,
                "operator_input_floor":{"kind":"known","owners":{},"compartments":[]},
                "classifier":{"id":"consumer-rules","version":"1","rules":[{"category":"private","expression":"PRIVATE_INPUT","confidence_basis_points":10000}],"category_labels":{"private":{"kind":"known","owners":{},"compartments":["private"]}}}}
        }))?,
    );
    println!("CHIO_CONSUMER_READY");
    io::stdout().flush()?;
    let mut gate = [0];
    io::stdin().read_exact(&mut gate)?;
    if gate != [1] {
        return Err("consumer startup gate refused".into());
    }
    for service in &mut services {
        service
            .gate
            .take()
            .ok_or("broker gate missing")?
            .write_all(&[1])?;
        wait_for_broker(&mut service.child, &service.fixture.config);
        provision_credential(
            &service.fixture.config.ipc_socket_path,
            &CredentialRef {
                provider: CREDENTIAL_PROVIDER.into(),
                credential_id: CREDENTIAL_ID.into(),
                version: 1,
            },
            &service.credential,
            &service.fixture.approver,
            &service.fixture.admin_subject,
        );
    }
    println!("CHIO_BROKERS_READY");
    io::stdout().flush()?;
    // The external campaign owns these children for its complete restart sequence.
    let _ = io::stdin().read(&mut gate)?;
    Ok(())
}
