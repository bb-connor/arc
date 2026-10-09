use super::*;
use chio_core_types::Keypair;
use chio_process::{ProcessLimits, ProcessStateLimits};
use chio_secret_broker::host_resource::HostResourceRoute;
use chio_security_types::clock::FixedClock;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

#[test]
fn resource_preparation_binds_original_caller_and_survives_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let policy = directory.path().join("policy.yaml");
    std::fs::write(&policy, "kernel:\n  max_capability_ttl: 3600\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: jobs-complete\n        tool: complete\n        operations: [invoke]\n        max_invocations: 24\n        ttl: 3600\n")?;
    let loaded = chio_control_plane::policy::load_policy(&policy)?;
    let scope = loaded.default_capabilities[0].scope.clone();
    let clock = Arc::new(FixedClock::from_millis(3_600_000));
    let host = super::super::super::state::kernel_with_clock(
        directory.path(),
        loaded,
        true,
        false,
        None,
        clock.clone(),
    )?;
    let kernel = Arc::new(host.kernel);
    let path = directory.path().join("process.db");
    let runtime = ProcessRuntime::open(&path, kernel.clone())?;
    let subject = Keypair::generate();
    let parent = kernel.issue_capability(&subject.public_key(), scope.clone(), 3600)?;
    let other_subject = Keypair::generate();
    let other = kernel.issue_capability(&other_subject.public_key(), scope, 3600)?;
    let limits = ProcessLimits {
        max_processes: 2,
        max_depth: 0,
        max_calls: 16,
        state: ProcessStateLimits::default(),
    };
    runtime.create_root("root", &parent, limits)?;
    runtime.create_root("other", &other, limits)?;
    runtime
        .registry()
        .provision_signers(&[("root".into(), &subject), ("other".into(), &other_subject)])?;
    let issuer = Keypair::generate();
    let quota = BrokerQuotaVerifierConfig {
        issuer: issuer.public_key(),
        audience: "jobs-complete-broker".into(),
        server_id: "jobs-complete".into(),
        tool_name: "complete".into(),
        provider_adapter_id: "host-resource".into(),
        provider_adapter_version: 1,
        credential_placement:
            chio_secret_broker::daemon_runtime::ProviderPlacementConfig::BearerAuthorization,
    };
    let route = HostResourceRoute {
        resource: "postgres-jobs".into(),
        tenant: "one".into(),
        operation: "complete".into(),
    };
    let config = PreparationConfig {
        issuer_seed_file: directory.path().join("issuer.seed"),
        credential: CredentialRef {
            provider: "jobs".into(),
            credential_id: "complete".into(),
            version: 1,
        },
        destination: BrokerDestination::parse(
            "https://jobs.chio.invalid:8443/execute",
            "POST",
            false,
        )?,
        maximum_body_bytes: 131072,
        response_limit_bytes: 131072,
        timeout_ms: 20000,
        lifetime_seconds: 60,
        payload: super::super::payload::PayloadConfig::CallerBoundResource {
            route: route.clone(),
        },
    };
    let route_key = (quota.server_id.clone(), quota.tool_name.clone());
    let mut preparer = Preparer {
        routes: BTreeMap::from([(
            route_key.clone(),
            Route {
                clock,
                quota,
                config,
                signer: Arc::new(Ed25519Backend::new(issuer)),
                binding: "a".repeat(64),
            },
        )]),
    };
    let arguments = json!({"job_id":"one", "expected_fence":2, "result":{"p95":12.5}});
    let prepare = |preparer: &Preparer, runtime: &ProcessRuntime, process, arguments: &Value| {
        preparer.prepare(
            runtime,
            PreparationRequest {
                process,
                operation_key: "original",
                server_id: "jobs-complete",
                tool_name: "complete",
                arguments,
            },
        )
    };
    let original = prepare(&preparer, &runtime, "root", &arguments)?;
    let execute: BrokerExecuteRequest = serde_json::from_value(original.clone())?;
    let decoded = route.decode(&execute.request.body)?;
    assert_eq!(
        decoded.caller_capability_sha256,
        sha256_hex(&canonical_json_bytes(&parent)?)
    );
    assert_eq!(execute.capability.body.parent_capability_id, parent.id);
    let alternate: BrokerExecuteRequest =
        serde_json::from_value(prepare(&preparer, &runtime, "other", &arguments)?)?;
    assert_ne!(execute.request.body, alternate.request.body);
    assert_ne!(execute.invocation_id, alternate.invocation_id);
    drop(runtime);
    let reopened = ProcessRuntime::open(path, kernel.clone())?;
    // Fresh issuance would now fail. Durable recovery must still return the
    // original signed bytes; it does not mint fresh dispatch authority.
    preparer
        .routes
        .get_mut(&route_key)
        .ok_or("missing route")?
        .clock = Arc::new(FixedClock::from_millis(10_000_000));
    assert_eq!(prepare(&preparer, &reopened, "root", &arguments)?, original);
    let mut changed = arguments.clone();
    changed["expected_fence"] = json!(3);
    assert!(matches!(
        prepare(&preparer, &reopened, "root", &changed),
        Err(ProcessError::Conflict)
    ));
    preparer
        .routes
        .get_mut(&route_key)
        .ok_or("missing route")?
        .binding = "b".repeat(64);
    assert!(matches!(
        prepare(&preparer, &reopened, "root", &arguments),
        Err(ProcessError::Conflict)
    ));
    Ok(())
}
