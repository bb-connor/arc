//! Bind actual Linux worker outcomes and modeled CLI verification contracts.

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use chio_core::{
    crypto::{Keypair, canonical_json_bytes, sha256_hex},
    receipt::{body::ChioReceipt, decision::ToolCallAction},
};
use serde_json::{Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn success(output: Output) -> Result<Value> {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(target_os = "linux")]
#[test]
fn supervised_outcomes_bind_multiple_graphs_and_authoritative_family_usage() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    success(Command::new("python3")
        .args(["-c", "import sys; from pathlib import Path; import swarm_outcomes; swarm_outcomes.exercise(sys.argv[1],Path(sys.argv[2]))"])
        .arg(env!("CARGO_BIN_EXE_chio")).arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?).output()?)?;
    let state = root.join("state");
    let artifact = root.join("outcomes.json");
    let summary = success(
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "attest-outcomes", "--state"])
            .arg(&state)
            .arg("--plan")
            .arg(state.join("outcomes-run-plan.json"))
            .arg("--out")
            .arg(&artifact)
            .output()?,
    )?;
    assert_eq!(summary["qualification_complete"], false);
    assert_eq!(summary["m5_acceptance_complete"], false);
    let runtime = summary["runtime_id"].as_str().ok_or("runtime")?;
    let key = state.join("authority.db.kernel.pub");
    let verify = |path: &Path, runtime: &str| -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "verify-outcomes", "--artifact"])
            .arg(path)
            .arg("--trusted-kernel-pubkey")
            .arg(&key)
            .arg("--runtime-id")
            .arg(runtime)
            .output()?)
    };
    let report = success(verify(&artifact, runtime)?)?;
    assert_eq!(report["graphs"], 2);
    assert_eq!(report["workers"], 4);
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(report["qualification_complete"], false);
    assert_eq!(report["m5_acceptance_complete"], false);
    assert_eq!(report["artifact_schema"], "chio.process.worker-outcomes.v3");
    assert_eq!(report["native_launches"], json!({}));
    assert!(!verify(&artifact, "another-runtime")?.status.success());
    let original: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
    let signer = chio_control_plane::load_existing_authority_keypair(
        &state.join("authority.db.kernel.seed"),
    )?;
    let params = &original.action.parameters;
    let mut states: Vec<_> = params["calls"]
        .as_object()
        .ok_or("calls")?
        .values()
        .map(|call| {
            call["action"]["parameters"]["operation"]["state"]
                .as_str()
                .ok_or("state")
        })
        .collect::<std::result::Result<_, _>>()?;
    states.sort();
    assert_eq!(
        states,
        [
            "compensated_before_dispatch",
            "compensated_before_dispatch",
            "completed",
            "completed"
        ]
    );
    let cases = [
        ("/aggregate/captured_invocations", json!(0)),
        ("/aggregate/captured_invocations", json!(3)),
        ("/aggregate/max_invocations", json!(99)),
        ("/aggregate/reserved_invocations", json!(1)),
        ("/aggregate/owner_id", json!("another-owner")),
        ("/runner/workers/0/state", json!("running")),
        ("/runner/workers/0/attempts", json!(0)),
        (
            "/runner/plan/workers/0/input/arguments",
            json!({"different":true}),
        ),
        (
            "/runner/plan/workers/0/input/request_id",
            json!("another-request"),
        ),
        ("/authorities", json!([params["authorities"][0]])),
        ("/authorities/1", params["authorities"][0].clone()),
        ("/calls/alice", params["calls"]["bob"].clone()),
        ("/observed_at_unix_ms", json!(1)),
        ("/schema", json!("chio.process.worker-outcomes.v9")),
    ];
    for (index, (pointer, replacement)) in cases.into_iter().enumerate() {
        let mut body = original.body();
        *body
            .action
            .parameters
            .pointer_mut(pointer)
            .ok_or("mutation target")? = replacement;
        let parameters = body.action.parameters.clone();
        body.action = ToolCallAction::from_parameters(parameters.clone())?;
        body.content_hash = sha256_hex(&canonical_json_bytes(&parameters)?);
        body.id.clear();
        let signed = ChioReceipt::sign(body, &signer)?;
        assert!(signed.verify_signature()?);
        let path = root.join(format!("substitution-{index}.json"));
        std::fs::write(&path, canonical_json_bytes(&signed)?)?;
        assert!(
            !verify(&path, runtime)?.status.success(),
            "accepted {pointer}"
        );
    }
    Ok(())
}

// This fixture is modeled verifier input with denied calls and zero captured
// invocations. It is newly signed and carries no native execution acceptance.
fn modeled_outcomes() -> Result<(ChioReceipt, Keypair)> {
    use chio_core_types::{
        capability::{
            aggregate_invocation::{
                AggregateBudgetDelegationMarker, verify_aggregate_invocation_budget,
            },
            attenuation::{
                DelegationLink, DelegationLinkBody, compute_attenuation_witness, scope_hash,
            },
            scope::{ChioScope, Operation, ToolGrant},
            token::{CapabilityToken, CapabilityTokenBody},
        },
        receipt::{body::ChioReceiptBody, decision::Decision, kinds::*},
    };
    use chio_swarm_authority::*;
    use std::collections::BTreeMap;
    let hash = |value: &Value| -> Result<String> { Ok(sha256_hex(&canonical_json_bytes(value)?)) };
    let signer = Keypair::from_seed(&[91; 32]);
    let root_subject = Keypair::from_seed(&[92; 32]);
    let runtime = "modeled-outcomes-current-abi";
    let now = 1_000_000;
    let expires = 2_000_000;
    let policy = sha256_hex(b"modeled-no-dispatch-policy");
    let issuer = format!("did:chio:{}", signer.public_key().to_hex());
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "modeled".into(),
            tool_name: "denied".into(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    };
    let root = CapabilityToken::sign_aggregate_family_root(
        CapabilityTokenBody {
            id: "modeled-root-capability".into(),
            issuer: signer.public_key(),
            subject: root_subject.public_key(),
            scope: scope.clone(),
            issued_at: 900,
            expires_at: expires / 1000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        2,
        &signer,
    )?;
    let budget = root
        .aggregate_invocation_budget
        .as_ref()
        .ok_or("family budget")?;
    let binding = budget.root_binding.as_ref().ok_or("root binding")?;
    let family = verify_aggregate_invocation_budget(&root, &[signer.public_key()], None)?
        .ok_or("verified family budget")?;
    let mut caps = BTreeMap::from([("root", root.clone())]);
    for (process, seed) in [("alice", 93), ("bob", 94)] {
        let subject = Keypair::from_seed(&[seed; 32]);
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: root.id.clone(),
                delegator: root.subject.clone(),
                delegatee: subject.public_key(),
                attenuations: vec![],
                timestamp: now / 1000,
                scope_hash: Some(scope_hash(&root.scope)?),
                aggregate_budget: Some(AggregateBudgetDelegationMarker {
                    root_binding_digest: binding.digest()?,
                    max_invocations: 2,
                }),
                cumulative_approval: None,
            },
            &root_subject,
        )?;
        let cap = CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("modeled-{process}-capability"),
                issuer: signer.public_key(),
                subject: subject.public_key(),
                scope: scope.clone(),
                issued_at: now / 1000,
                expires_at: expires / 1000,
                delegation_chain: vec![link],
                aggregate_invocation_budget: Some(budget.clone()),
            },
            &signer,
        )?;
        assert_eq!(
            verify_aggregate_invocation_budget(&cap, &[signer.public_key()], Some(&root))?,
            Some(family.clone())
        );
        caps.insert(process, cap);
    }
    let limits = chio_process::ProcessLimits {
        max_processes: 3,
        max_depth: 1,
        max_calls: 2,
        state: Default::default(),
    };
    let record = json!({
        "abi": chio_process::PROCESS_ABI, "written_by": "modeled CLI verifier fixture",
        "source_policy_hash": policy, "runtime_policy_hash": policy, "manifests": [],
        "config": {"schema": "chio.process.host.v1", "policy": "modeled-policy.yaml",
            "limits": limits, "servers": [],
            "children": [
                {"id": "alice", "parent": "root", "tools": [], "budget_share_bps": 5000},
                {"id": "bob", "parent": "root", "tools": [], "budget_share_bps": 5000}
            ]}
    });
    let manifest_digest = hash(&record["manifests"])?;
    let parameters =
        json!({"runtime_id": runtime, "capabilities": caps, "record_sha256": hash(&record)?});
    let bootstrap = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: now / 1000,
            capability_id: root.id.clone(),
            tool_server: "chio-process-host".into(),
            tool_name: "provision_swarm".into(),
            action: ToolCallAction::from_parameters(parameters.clone())?,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![],
            content_hash: hash(&parameters)?,
            policy_hash: policy.clone(),
            evidence: vec![],
            metadata: None,
            trust_level: TrustLevel::Verified,
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &signer,
    )?;
    let scope_hash = scope_hash(&scope)?;
    let node = |process: &str| {
        json!({"taskId": process, "parentTaskId": "root", "depth": 1,
        "scopeHash": scope_hash, "routePlanRef": format!("route-{process}"),
        "continuationTokenRef": format!("continue-{process}"), "budgetAllocationRef": format!("allocation-{process}")})
    };
    let mut graph: SwarmTaskGraph = serde_json::from_value(json!({
        "schema": CHIO_SWARM_TASK_GRAPH_SCHEMA, "graphId": "modeled-graph",
        "rootTransactionRef": bootstrap.id, "plannerSubject": root.subject.to_hex(),
        "issuer": issuer, "signature": "", "createdAtUnixMs": now, "expiresAtUnixMs": expires,
        "maxDepth": 1, "maxFanout": 2, "nodes": [{"taskId": "root", "depth": 0, "scopeHash": scope_hash}, node("alice"), node("bob")],
        "edges": [{"fromTaskId": "root", "toTaskId": "alice", "edgeType": "delegates"}, {"fromTaskId": "root", "toTaskId": "bob", "edgeType": "delegates"}],
        "joins": [], "budgetPoolRef": "modeled-pool", "revocationEpochRef": "modeled-epoch",
        "routePlanRefs": ["route-alice", "route-bob"]
    }))?;
    graph.signature = sign_swarm_task_graph(&graph, &signer)?;
    let epoch_root = hash(&json!({"revokedSubjects": [], "revokedTaskIds": []}))?;
    let mut epoch: SwarmRevocationEpoch = serde_json::from_value(json!({
        "schema": CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, "epochId": "modeled-epoch", "rootHash": epoch_root,
        "issuedAtUnixMs": now, "validUntilUnixMs": expires, "revokedSubjects": [], "revokedTaskIds": [],
        "issuer": issuer, "signature": ""
    }))?;
    epoch.signature = sign_swarm_revocation_epoch(&epoch, &signer)?;
    let mut bundle: SwarmAuthorityBundle = serde_json::from_value(json!({
        "taskGraph": graph, "continuationTokens": [], "witnessChains": [], "joinReceipts": [], "routePlanReceipts": [],
        "budgetPool": {"schema": CHIO_SWARM_BUDGET_POOL_SCHEMA, "poolId": "modeled-pool", "graphId": "modeled-graph", "currency": "tool_calls", "totalUnits": 2, "allocations": []},
        "revocationEpoch": epoch, "terminalReceipts": [], "nowUnixMs": now
    }))?;
    let mut calls = BTreeMap::new();
    let mut planned = Vec::new();
    let mut completed = Vec::new();
    for process in ["alice", "bob"] {
        let cap = &caps[process];
        let mut chain: SwarmDelegationWitnessChain = serde_json::from_value(json!({
            "schema": CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA, "chainId": format!("witness-{process}"),
            "graphId": "modeled-graph", "parentTaskId": "root", "childTaskId": process,
            "hops": [{"parentCapabilityDigest": hash(&serde_json::to_value(&root)?)?, "childCapabilityDigest": hash(&serde_json::to_value(cap)?)?,
                "parentScopeHash": scope_hash, "childScopeHash": scope_hash, "attenuationRuleId": "rule-subset-tool-invocation",
                "scopeSubsetProof": compute_attenuation_witness(&root.scope, &cap.scope)?, "expiresAtUnixMs": expires,
                "issuer": issuer, "policyDigest": policy, "witnessSignature": ""}]
        }))?;
        chain.hops[0].witness_signature =
            sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], &signer)?;
        let mut route: SwarmRoutePlanReceipt = serde_json::from_value(json!({
            "schema": CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA, "routePlanId": format!("route-{process}"), "graphId": "modeled-graph", "taskId": process,
            "selectedRoute": "chio:modeled", "candidateSetDigest": manifest_digest, "registrySnapshotHash": manifest_digest,
            "bridgeId": "chio", "protocolTarget": "chio://modeled-no-dispatch", "egressContractId": format!("chio:manifest:{manifest_digest}"),
            "egressConstraints": ["deny-private-network"], "attenuationDecision": "accepted", "policyDigest": policy,
            "expiresAtUnixMs": expires, "issuer": issuer, "signature": ""
        }))?;
        route.signature = sign_swarm_route_plan_receipt(&route, &signer)?;
        let mut token: SwarmContinuationToken = serde_json::from_value(json!({
            "schema": CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA, "tokenId": format!("continue-{process}"), "graphId": "modeled-graph",
            "childTaskId": process, "parentTaskId": "root", "parentReceiptIds": [bootstrap.id],
            "graphSha256": hash(&serde_json::to_value(&bundle.task_graph)?)?, "routePlanReceiptId": route.route_plan_id,
            "budgetAllocationId": format!("allocation-{process}"), "witnessChainRef": chain.chain_id, "witnessChainSha256": hash(&serde_json::to_value(&chain)?)?,
            "revocationEpochRef": "modeled-epoch", "revocationEpochRootHash": epoch_root, "sessionAnchorRef": runtime,
            "nonce": format!("modeled-nonce-{process}"), "mode": "single_use", "issuedAtUnixMs": now, "expiresAtUnixMs": expires,
            "issuer": issuer, "signature": ""
        }))?;
        token.signature = sign_swarm_continuation_token(&token, &signer)?;
        bundle.budget_pool.allocations.push(serde_json::from_value(json!({
            "allocationId": format!("allocation-{process}"), "taskId": process, "dimensionId": "tool_calls", "state": "active",
            "maxUnits": 1, "reservedUnits": 0, "activeUnits": 1, "consumedUnits": 0, "releasedUnits": 0, "reversedUnits": 0
        }))?);
        bundle.witness_chains.push(chain);
        bundle.route_plan_receipts.push(route);
        bundle.continuation_tokens.push(token);
        let operation_key = format!("modeled-denial-{process}");
        let request_id = format!(
            "process:{}",
            hash(&json!([runtime, process, operation_key]))?
        );
        let request = json!({"operation_key": operation_key, "server_id": "modeled", "tool_name": "denied", "arguments": {}, "known_outcome_only": false});
        let context =
            json!({"runtime_id": runtime, "process_id": process, "capability_id": cap.id});
        let mut body = bootstrap.body();
        body.id.clear();
        body.capability_id = cap.id.clone();
        body.tool_server = "modeled".into();
        body.tool_name = "denied".into();
        body.action = ToolCallAction::from_parameters(json!({}))?;
        body.decision = Some(Decision::Deny {
            reason: "modeled refusal".into(),
            guard: "modeled-test".into(),
        });
        body.receipt_kind = ReceiptKind::MediatedDecision;
        body.boundary_class = BoundaryClass::Prevent;
        body.observation_outcome = None;
        body.trust_level = TrustLevel::Mediated;
        body.content_hash = sha256_hex(b"null");
        body.metadata = Some(
            json!({"chio_process": {"runtime_id": runtime, "process_id": process, "operation_key": operation_key, "attempt": 1}, "receipt_context": {"request_id": request_id}}),
        );
        let decision = ChioReceipt::sign(body, &signer)?;
        let response = json!({"request_id": request_id, "verdict": "deny", "output": null, "reason": "modeled refusal",
            "terminal_state": {"state": "completed"}, "receipt_json": String::from_utf8(canonical_json_bytes(&decision)?)?, "execution_nonce_json": null});
        let parameters = json!({"schema": "chio.process.call-observation.v1", "runtime_id": runtime, "observed_at_unix_ms": now,
            "bootstrap": bootstrap, "request": request, "context": context, "response": response, "operation": null});
        let mut body = bootstrap.body();
        body.id.clear();
        body.tool_name = "attest_retained_call".into();
        body.action = ToolCallAction::from_parameters(parameters.clone())?;
        body.content_hash = hash(&parameters)?;
        calls.insert(process, ChioReceipt::sign(body, &signer)?);
        let mut input = request;
        input["process"] = json!(process);
        input["request_id"] = json!(request_id);
        input["capability_sha256"] = json!(hash(&serde_json::to_value(cap)?)?);
        planned.push(json!({"process": process, "input": input}));
        completed.push(json!({"process": process, "state": "completed", "attempts": 1}));
    }
    verify_swarm_authority_for_admission(&bundle, &[signer.public_key()])?;
    let parameters = json!({"schema": "chio.process.worker-outcomes.v1", "runtime_id": runtime,
        "observed_at_unix_ms": now, "bootstrap": bootstrap, "host_record": record, "authorities": [bundle],
        "runner": {"plan": {"schema": "chio.process.run.v1", "workers": planned}, "workers": completed},
        "aggregate": {"owner_id": family.owner_id, "max_invocations": 2, "reserved_invocations": 0, "captured_invocations": 0}, "calls": calls});
    let mut body = bootstrap.body();
    body.id.clear();
    body.tool_name = "attest_worker_outcomes".into();
    body.action = ToolCallAction::from_parameters(parameters.clone())?;
    body.content_hash = hash(&parameters)?;
    Ok((ChioReceipt::sign(body, &signer)?, signer))
}

#[test]
fn current_abi_outcomes_reports_preserve_incomplete_qualification_aliases() -> Result {
    use std::io::Read;

    use sha2::{Digest, Sha256};

    let directory = tempfile::tempdir()?;
    let (signed, signer) = modeled_outcomes()?;
    let artifact = directory.path().join("modeled-outcomes.json");
    let key = directory.path().join("modeled-kernel.pub");
    std::fs::write(&artifact, canonical_json_bytes(&signed)?)?;
    std::fs::write(&key, signer.public_key().to_hex())?;
    let cli = Path::new(env!("CARGO_BIN_EXE_chio")).canonicalize()?;
    let cli_sha256 = {
        let mut binary = std::fs::File::open(&cli)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let length = binary.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            digest.update(&buffer[..length]);
        }
        format!("{:x}", digest.finalize())
    };
    eprintln!("outcomes_cli_absolute_path={}", cli.display());
    eprintln!("outcomes_cli_sha256={cli_sha256}");
    let output = Command::new(&cli)
        .args(["process", "verify-outcomes", "--artifact"])
        .arg(&artifact)
        .arg("--trusted-kernel-pubkey")
        .arg(&key)
        .args(["--runtime-id", "modeled-outcomes-current-abi"])
        .output()?;
    eprintln!("outcomes_cli_exit_status={}", output.status);
    eprintln!("outcomes_cli_stdout_sha256={}", sha256_hex(&output.stdout));
    eprintln!(
        "outcomes_cli_stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    eprintln!(
        "outcomes_cli_stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = success(output)?;
    eprintln!("outcomes_cli_parsed={report}");
    assert_eq!(report["captured_invocations"], 0);
    assert_eq!(report["qualification_complete"], false);
    assert_eq!(report["m5_acceptance_complete"], false);
    Ok(())
}

#[test]
fn outcomes_cli_refuses_cross_abi_artifacts_without_migration() -> Result {
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/process-worker-outcomes");
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["process", "verify-outcomes", "--artifact"])
        .arg(fixtures.join("v1-network.json"))
        .arg("--trusted-kernel-pubkey")
        .arg(fixtures.join("v1-network-kernel.pub"))
        .args(["--runtime-id", "a86fa37d-97ec-4e6b-afbd-b178dd9a10a8"])
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("recorded under process ABI chio.process.abi.v2"));
    assert!(message.contains(chio_process::PROCESS_ABI));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn supervised_outcomes_exports_preserve_incomplete_qualification_aliases() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let fixture = success(Command::new("python3")
        .args(["-c", "import sys; from pathlib import Path; import swarm_outcomes; swarm_outcomes.exercise(sys.argv[1],Path(sys.argv[2]))"])
        .arg(env!("CARGO_BIN_EXE_chio")).arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?).output()?)?;
    assert_eq!(fixture["complete"], true);
    assert_eq!(
        fixture["workers"]
            .as_array()
            .ok_or("completed workers")?
            .len(),
        4
    );
    let state = root.join("state");
    let artifact = root.join("exported-worker-outcomes.json");
    let key = state.join("authority.db.kernel.pub");
    let summary_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["process", "attest-outcomes", "--state"])
        .arg(&state)
        .arg("--plan")
        .arg(state.join("outcomes-run-plan.json"))
        .arg("--out")
        .arg(&artifact)
        .output()?;
    eprintln!(
        "attest_outcomes_alias_stdout={}",
        String::from_utf8_lossy(&summary_output.stdout)
    );
    let summary = success(summary_output)?;
    let runtime = summary["runtime_id"].as_str().ok_or("runtime")?;
    let report = success(
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "verify-outcomes", "--artifact"])
            .arg(&artifact)
            .arg("--trusted-kernel-pubkey")
            .arg(&key)
            .arg("--runtime-id")
            .arg(runtime)
            .output()?,
    )?;
    assert_eq!(report["graphs"], 2);
    assert_eq!(report["workers"], 4);
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(report["artifact_schema"], "chio.process.worker-outcomes.v3");
    for check in ["execution_nonces", "receipt_log_inclusion"] {
        assert!(
            report["checks"]
                .as_array()
                .ok_or("checks")?
                .contains(&json!(check))
        );
    }
    let mut states = report["observed_operations"]
        .as_object()
        .ok_or("call outcomes")?
        .values()
        .map(|state| state.as_str().ok_or("call state"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    states.sort();
    assert_eq!(
        states,
        [
            "compensated_before_dispatch",
            "compensated_before_dispatch",
            "completed",
            "completed"
        ]
    );
    let signed: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
    assert!(signed.verify_signature()?);
    assert_eq!(summary["receipt_id"], signed.id);
    assert_eq!(summary["workers"], 4);
    assert_eq!(summary["qualification_complete"], false);
    assert_eq!(summary["m5_acceptance_complete"], false);
    Ok(())
}
