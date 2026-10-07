//! Export actual supervised worker effects, then reject re-signed semantic substitutions.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::{Command, Output};

use chio_core::{
    crypto::{canonical_json_bytes, sha256_hex, Keypair},
    receipt::{body::ChioReceipt, decision::ToolCallAction},
};
use serde_json::{json, Value};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn process(args: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("process")
        .args(args)
        .output()?)
}

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
fn completed_run_binds_actual_worker_results_and_rejects_semantic_substitutions() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let output = Command::new("python3")
        .args(["-c", "import sys; from pathlib import Path; import swarm; swarm.exercise(sys.argv[1], Path(sys.argv[2]), supervisor_only=True)"])
        .arg(env!("CARGO_BIN_EXE_chio"))
        .arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?)
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let state = root.join("state");
    let plan = state.join("reference-run-plan.json");
    let artifact = root.join("completed.json");
    let summary = success(process(&[
        "attest-run",
        "--state",
        state.to_str().ok_or("state path")?,
        "--plan",
        plan.to_str().ok_or("plan path")?,
        "--out",
        artifact.to_str().ok_or("artifact path")?,
    ])?)?;
    assert_eq!(summary["qualification_complete"], false);
    assert_eq!(summary["m5_acceptance_complete"], false);
    let runtime = summary["runtime_id"].as_str().ok_or("runtime ID")?;
    let key = state.join("authority.db.kernel.pub");
    let verify = |path: &Path, runtime: &str| -> Result<Output> {
        process(&[
            "verify-run",
            "--artifact",
            path.to_str().ok_or("artifact path")?,
            "--trusted-kernel-pubkey",
            key.to_str().ok_or("key path")?,
            "--runtime-id",
            runtime,
        ])
    };
    let report = success(verify(&artifact, runtime)?)?;
    assert_eq!(report["verified_workers"], json!(["alice", "bob"]));
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(report["qualification_complete"], false);
    assert_eq!(report["m5_acceptance_complete"], false);
    for check in ["execution_nonces", "receipt_log_inclusion"] {
        assert!(report["checks"]
            .as_array()
            .ok_or("checks")?
            .contains(&json!(check)));
        assert!(!report["unchecked"]
            .as_array()
            .ok_or("unchecked")?
            .contains(&json!(check)));
    }
    assert!(!verify(&artifact, "another-runtime")?.status.success());
    let original: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
    for worker in ["alice", "bob"] {
        assert!(
            original.action.parameters["results"][worker]["response"]["execution_nonce_json"]
                .is_string(),
            "the reference worker must retain its original execution nonce"
        );
    }
    let signer = chio_control_plane::load_existing_authority_keypair(
        &state.join("authority.db.kernel.seed"),
    )?;
    assert_eq!(signer.public_key(), original.kernel_key);
    // This proof and checkpoint really verify, but for a receipt from another
    // runtime. An outer signature must not make them evidence for this call.
    let tool_receipt: ChioReceipt = serde_json::from_str(
        original.action.parameters["results"]["alice"]["response"]["receipt_json"]
            .as_str()
            .ok_or("tool receipt")?,
    )?;
    let mut foreign_body = tool_receipt.body();
    foreign_body.id.clear();
    foreign_body.metadata.as_mut().ok_or("metadata")?["chio_process"]["runtime_id"] =
        json!("another-runtime");
    let foreign = ChioReceipt::sign(foreign_body, &signer)?;
    let foreign_bytes = canonical_json_bytes(&foreign)?;
    let tree = chio_core::merkle::MerkleTree::from_leaves(std::slice::from_ref(&foreign_bytes))?;
    let mut checkpoint = chio_kernel::checkpoint::build_checkpoint(
        1,
        1,
        1,
        std::slice::from_ref(&foreign_bytes),
        &signer,
    )?;
    checkpoint.body.issued_at = original.timestamp;
    checkpoint.signature = signer.sign(&canonical_json_bytes(&checkpoint.body)?);
    chio_kernel::checkpoint::validate_checkpoint(&checkpoint)?;
    let proof = chio_kernel::checkpoint::build_inclusion_proof(&tree, 0, 1, 1)?;
    assert!(proof.verify(&foreign_bytes, &checkpoint.body.merkle_root));
    let foreign_log = json!({"checkpoint": checkpoint, "inclusion": proof});
    let mut extra_nonce: Value = serde_json::from_str(
        original.action.parameters["results"]["alice"]["response"]["execution_nonce_json"]
            .as_str()
            .ok_or("nonce JSON")?,
    )?;
    extra_nonce["nonce"]["unrecognized_authority"] = json!(true);
    let retained_episode = original.action.parameters["results"]["alice"]["custody"]["history"]
        .as_array()
        .ok_or("custody history")?
        .iter()
        .position(|entry| entry["history"]["disposition"] == "retained_after_dispatch_commit")
        .ok_or("retained dispatch episode")?;
    let retained_pointer =
        format!("/results/alice/custody/history/{retained_episode}/history/disposition");
    let cases = [
        (
            "/results/alice/response/execution_nonce_json",
            json!(serde_json::to_string(&extra_nonce)?),
            "execution nonce fields",
        ),
        (
            "/results/alice/receipt_log",
            foreign_log,
            "receipt log inclusion",
        ),
        (
            "/results/alice/response/execution_nonce_json",
            original.action.parameters["results"]["bob"]["response"]["execution_nonce_json"]
                .clone(),
            "execution nonce differs",
        ),
        (
            "/results/alice/response/execution_nonce_json",
            Value::Null,
            "execution nonce differs",
        ),
        (
            "/results/alice/nonce/verified_at_unix_ms",
            json!(1),
            "issuance interval",
        ),
        ("/results/alice/receipt_log", Value::Null, "payload differs"),
        (
            "/results/alice/receipt_log",
            original.action.parameters["results"]["bob"]["receipt_log"].clone(),
            "receipt log inclusion",
        ),
        (
            "/results/alice/receipt_log/inclusion/leaf_index",
            json!(999),
            "receipt log inclusion",
        ),
        (
            "/results/alice/custody/terminal_receipt_id",
            json!("another-receipt"),
            "custody operation differs",
        ),
        (
            "/results/alice/custody/history",
            json!([]),
            "custody history is absent",
        ),
        (
            retained_pointer.as_str(),
            json!("released_before_dispatch"),
            "custody is not retained",
        ),
        (
            "/results/alice/custody/history/0/claim/intent/expectationId",
            json!("substituted-authority-generation"),
            "claim commitment differs",
        ),
        (
            "/results/alice/custody/history/0/operation/version",
            json!(999),
            "claim commitment differs",
        ),
        (
            "/host_record/config/limits/max_calls",
            json!(9999),
            "host record differs",
        ),
        (
            "/aggregate/captured_invocations",
            json!(0),
            "aggregate usage",
        ),
        (
            "/aggregate/reserved_invocations",
            json!(1),
            "aggregate usage",
        ),
        (
            "/aggregate/owner_id",
            json!("another-owner"),
            "aggregate usage",
        ),
        (
            "/runner/workers/0/state",
            json!("running"),
            "worker did not complete",
        ),
        (
            "/runner/plan/workers/0/input/arguments",
            json!({"substituted": true}),
            "runner input differs",
        ),
        (
            "/results/alice/context/process_id",
            json!("bob"),
            "invocation context differs",
        ),
        (
            "/results/alice/response/output",
            json!({"kind":"value", "value":"forged"}),
            "output content hash",
        ),
    ];
    for (index, (pointer, replacement, reason)) in cases.into_iter().enumerate() {
        let mut body = original.body();
        *body
            .action
            .parameters
            .pointer_mut(pointer)
            .ok_or("missing mutation target")? = replacement;
        let value = body.action.parameters.clone();
        body.action = ToolCallAction::from_parameters(value.clone())?;
        body.content_hash = sha256_hex(&canonical_json_bytes(&value)?);
        body.id.clear();
        let signed = ChioReceipt::sign(body, &signer)?;
        assert!(signed.verify_signature()?);
        let path = root.join(format!("substitution-{index}.json"));
        std::fs::write(&path, canonical_json_bytes(&signed)?)?;
        let denied = verify(&path, runtime)?;
        assert!(!denied.status.success(), "accepted {pointer}");
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains(reason),
            "{pointer}: {}",
            String::from_utf8_lossy(&denied.stderr)
        );
    }
    let mut copied = original.body();
    copied.id.clear();
    copied.action.parameters["results"]["alice"]["nonce"] =
        original.action.parameters["results"]["bob"]["nonce"].clone();
    copied.action.parameters["results"]["alice"]["response"]["execution_nonce_json"] =
        original.action.parameters["results"]["bob"]["response"]["execution_nonce_json"].clone();
    copied.content_hash = sha256_hex(&canonical_json_bytes(&copied.action.parameters)?);
    copied.action = ToolCallAction::from_parameters(copied.action.parameters)?;
    let copied = ChioReceipt::sign(copied, &signer)?;
    let path = root.join("coherent-copied-nonce.json");
    std::fs::write(&path, canonical_json_bytes(&copied)?)?;
    let denied = verify(&path, runtime)?;
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("execution nonce differs"));
    // Unsigned payload edits also fail at the signature boundary.
    let mut altered: Value = serde_json::to_value(&original)?;
    altered["action"]["parameters"]["runtime_id"] = json!("tampered");
    let path = root.join("broken-signature.json");
    std::fs::write(&path, serde_json::to_vec(&altered)?)?;
    assert!(!verify(&path, runtime)?.status.success());
    Ok(())
}

// Newly signed modeled verifier input. The two captured calls are signed fixture
// claims, not host execution or native qualification. Existing retained records
// are never copied or resealed to make this current-ABI fixture.
fn modeled_completed_fanout() -> Result<(ChioReceipt, Keypair)> {
    use chio_core_types::{
        capability::{
            aggregate_invocation::{
                verify_aggregate_invocation_budget, AggregateBudgetDelegationMarker,
            },
            attenuation::{
                compute_attenuation_witness, scope_hash, DelegationLink, DelegationLinkBody,
            },
            scope::{ChioScope, Operation, ToolGrant},
            token::{CapabilityToken, CapabilityTokenBody},
        },
        receipt::{body::ChioReceiptBody, decision::Decision, kinds::*},
    };
    use chio_kernel::admission_operation::{
        runtime_participant::{
            RuntimeParticipantClaimEvidenceV1, RuntimeParticipantClaimHistoryV1,
            RuntimeParticipantClaimIntentInput, RuntimeParticipantClaimIntentV1,
            RuntimeParticipantClaimReferenceV1, RuntimeParticipantDisposition,
            RuntimeParticipantPhase, RuntimeParticipantResourceV1,
        },
        AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionOperationKind, AdmissionOperationV1,
        AdmissionParticipantRequirements, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
        RuntimeReplayParticipantKind, SideEffectClass,
    };
    use chio_swarm_authority::*;
    use std::collections::BTreeMap;
    let hash = |value: &Value| -> Result<String> { Ok(sha256_hex(&canonical_json_bytes(value)?)) };
    let signer = Keypair::from_seed(&[101; 32]);
    let root_subject = Keypair::from_seed(&[102; 32]);
    let runtime = "modeled-completed-fanout-current-abi";
    let now = 1_000_000;
    let expires = 2_000_000;
    let policy = sha256_hex(b"modeled-completed-fanout-policy");
    let issuer = format!("did:chio:{}", signer.public_key().to_hex());
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "modeled".into(),
            tool_name: "observed".into(),
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
    for (process, seed) in [("alice", 103), ("bob", 104)] {
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
        "joins": [{"joinId": "modeled-join", "parentTaskIds": ["alice", "bob"], "nextTaskId": "root"}], "budgetPoolRef": "modeled-pool", "revocationEpochRef": "modeled-epoch",
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
    }
    verify_swarm_authority_for_admission(&bundle, &[signer.public_key()])?;
    let mut results = BTreeMap::new();
    let mut parents = Vec::new();
    let mut planned = Vec::new();
    let mut completed = Vec::new();
    for process in ["alice", "bob"] {
        let cap = &caps[process];
        let token = bundle
            .continuation_tokens
            .iter()
            .find(|token| token.child_task_id == process)
            .ok_or("task continuation")?;
        let route = bundle
            .route_plan_receipts
            .iter()
            .find(|route| route.route_plan_id == token.route_plan_receipt_id)
            .ok_or("task route")?;
        let witness = bundle
            .witness_chains
            .iter()
            .find(|witness| Some(&witness.chain_id) == token.witness_chain_ref.as_ref())
            .ok_or("task witness")?;
        let reference = |id: &str, artifact: Value| -> Result<Value> {
            Ok(json!({"evidence_id": id, "artifact_sha256": hash(&artifact)?}))
        };
        let refs = json!({
            "task_graph": reference(&bundle.task_graph.graph_id, serde_json::to_value(&bundle.task_graph)?)?,
            "continuation_token": reference(&token.token_id, serde_json::to_value(token)?)?,
            "route_plan_receipt": reference(&route.route_plan_id, serde_json::to_value(route)?)?,
            "delegation_witness": reference(&witness.chain_id, serde_json::to_value(witness)?)?,
            "revocation_epoch": reference(&bundle.revocation_epoch.epoch_id, serde_json::to_value(&bundle.revocation_epoch)?)?,
            "budget_pool": reference(&bundle.budget_pool.pool_id, serde_json::to_value(&bundle.budget_pool)?)?,
        });
        let operation_key = format!("modeled-completed-{process}");
        let request_id = format!(
            "process:{}",
            hash(&json!([runtime, process, operation_key]))?
        );
        let request = json!({"operation_key": operation_key, "server_id": "modeled", "tool_name": "observed", "arguments": {}, "known_outcome_only": false});
        let context =
            json!({"runtime_id": runtime, "process_id": process, "capability_id": cap.id});
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace: AuthenticatedRequestNamespace::for_local_system(
                AdmissionIdentifier::try_new("runtime_id", runtime)?,
            )?,
            request_id: AdmissionIdentifier::try_new("request_id", &request_id)?,
            capability_id: AdmissionIdentifier::try_new("capability_id", &cap.id)?,
            authorization_capability_hash: AdmissionDigest::try_new(
                "capability_hash",
                hash(&serde_json::to_value(cap)?)?,
            )?,
            request_binding: AdmissionRequestBindingV1::new(
                AdmissionDigest::try_new("immutable_request_hash", hash(&request)?)?,
                AdmissionParticipantRequirements {
                    broker_attempt: true,
                    budget_capture: true,
                    ..AdmissionParticipantRequirements::NONE
                },
            )?,
            policy_hash: AdmissionDigest::try_new("policy_hash", &policy)?,
            effect_class: SideEffectClass::SideEffecting,
        })?;
        let operation = AdmissionOperationV1::prepare(binding.clone(), 1)?.to_persisted();
        let episode =
            AdmissionIdentifier::try_new("episode_id", format!("modeled-episode-{process}"))?;
        let intent = RuntimeParticipantClaimIntentV1::new(RuntimeParticipantClaimIntentInput {
            episode_id: episode.clone(),
            runtime_authority_id: AdmissionIdentifier::try_new("runtime_id", runtime)?,
            expectation_id: AdmissionIdentifier::try_new(
                "expectation_id",
                "modeled-runtime-generation",
            )?,
            request_binding_hash: binding.request_binding_hash().clone(),
            grant_index: 0,
            phase: RuntimeParticipantPhase::Dispatch,
            plan_digest: AdmissionDigest::try_new(
                "plan_digest",
                hash(&json!([runtime, process, "modeled-custody-plan"]))?,
            )?,
            resources: vec![RuntimeParticipantResourceV1::new(
                RuntimeReplayParticipantKind::SwarmContinuation,
                AdmissionIdentifier::try_new("continuation_id", &token.token_id)?,
                AdmissionDigest::try_new(
                    "continuation_digest",
                    hash(&serde_json::to_value(token)?)?,
                )?,
            )],
        })?;
        let claim = json!({"schema": "chio.runtime-participant-claim.v1", "operationId": binding.operation_id(),
            "intent": intent, "ledgerDigest": hash(&json!([runtime, process, "modeled-ledger"]))?, "recordedAtUnixMs": now});
        let claim_digest = sha256_hex(&canonical_json_bytes(&(
            "chio.runtime-participant-claim-commit.v1",
            (&claim, &operation),
        ))?);
        let claim_reference = RuntimeParticipantClaimReferenceV1::new(
            binding.operation_id().clone(),
            episode,
            AdmissionDigest::try_new("claim_digest", claim_digest)?,
        );
        let history = RuntimeParticipantClaimEvidenceV1 {
            history: RuntimeParticipantClaimHistoryV1 {
                reference: claim_reference.clone(),
                intent: intent.clone(),
                disposition: RuntimeParticipantDisposition::RetainedAfterDispatchCommit,
            },
            claim,
            operation,
        };
        history.verify()?;
        let value = json!({"modeled": true, "process": process});
        let mut body = bootstrap.body();
        body.id.clear();
        body.capability_id = cap.id.clone();
        body.tool_server = "modeled".into();
        body.tool_name = "observed".into();
        body.action = ToolCallAction::from_parameters(json!({}))?;
        body.decision = Some(Decision::Allow);
        body.receipt_kind = ReceiptKind::MediatedDecision;
        body.boundary_class = BoundaryClass::Prevent;
        body.observation_outcome = None;
        body.trust_level = TrustLevel::Mediated;
        body.content_hash = hash(&value)?;
        body.metadata = Some(json!({
            "chio_process": {"runtime_id": runtime, "process_id": process, "operation_key": operation_key, "attempt": 1},
            "receipt_context": {"request_id": request_id},
            "route": {"bridge": route.bridge_id, "protocolTarget": route.protocol_target, "selectedRoute": route.selected_route},
            "chio_runtime": {
                "verified_swarm_request_binding": {"graph_id": bundle.task_graph.graph_id, "task_id": process,
                    "capability_sha256": hash(&serde_json::to_value(cap)?)?, "scope_sha256": hash(&serde_json::to_value(&cap.scope)?)?,
                    "evidence_refs_sha256": hash(&refs)?},
                "operation_owned_replay": {"reference": claim_reference, "plan_sha256": intent.plan_digest(),
                    "resources_sha256": sha256_hex(&canonical_json_bytes(&intent.resources())?)},
            },
        }));
        let receipt = ChioReceipt::sign(body, &signer)?;
        assert!(receipt.verify_signature()?);
        let response = json!({"request_id": request_id, "verdict": "allow", "output": {"kind": "value", "value": value},
            "reason": null, "terminal_state": {"state": "completed"},
            "receipt_json": String::from_utf8(canonical_json_bytes(&receipt)?)?, "execution_nonce_json": null});
        let custody = json!({"operation_id": binding.operation_id(), "request_id": request_id, "capability_id": cap.id,
            "request_binding_sha256": binding.request_binding_hash(), "state": "completed", "terminal_receipt_id": receipt.id,
            "history": [history]});
        results.insert(process, json!({"request": request, "context": context, "response": response, "custody": custody}));
        parents.push(SwarmJoinParentReceipt {
            task_id: process.into(),
            receipt_id: receipt.id,
        });
        let mut input = request;
        input["process"] = json!(process);
        input["request_id"] = json!(request_id);
        input["capability_sha256"] = json!(hash(&serde_json::to_value(cap)?)?);
        planned.push(json!({"process": process, "input": input}));
        completed.push(json!({"process": process, "state": "completed", "attempts": 1}));
    }
    let result_digest = hash(&serde_json::to_value(&results)?)?;
    let ids: Vec<_> = parents
        .iter()
        .map(|parent| parent.receipt_id.clone())
        .collect();
    bundle.join_receipts.push(mint_swarm_join_receipt(
        SwarmJoinReceiptMintRequest {
            join_id: "modeled-join".into(),
            graph_id: bundle.task_graph.graph_id.clone(),
            chain_id: runtime.into(),
            dag_ordinal: 1,
            hlc_unix_ms: now,
            parent_task_receipts: parents,
            expected_parent_receipt_ids: ids.clone(),
            actual_parent_receipt_ids: ids,
            join_predicate: "all_success".into(),
            result_digest: result_digest.clone(),
            next_task_id: "root".into(),
        },
        &signer,
    )?);
    let mut terminal = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.into(),
        receipt_id: "modeled-terminal-fanout".into(),
        graph_id: bundle.task_graph.graph_id.clone(),
        chain_id: runtime.into(),
        terminal_task_ids: vec!["root".into()],
        completed_task_ids: vec!["root".into(), "alice".into(), "bob".into()],
        join_receipt_ids: vec!["modeled-join".into()],
        route_plan_receipt_ids: bundle.task_graph.route_plan_refs.clone(),
        budget_pool_id: bundle.budget_pool.pool_id.clone(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "tool_calls".into(),
            reserved_units: 0,
            active_units: 2,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: 2,
        }],
        revocation_epoch_ref: bundle.revocation_epoch.epoch_id.clone(),
        result_digest,
        completed_at_unix_ms: now,
        issuer,
        signature: String::new(),
    };
    terminal.signature = sign_swarm_terminal_graph_receipt(&terminal, &signer)?;
    bundle.terminal_receipts.push(terminal);
    verify_swarm_authority_bundle(&bundle, &[signer.public_key()])?;
    let parameters = json!({"schema": "chio.process.completed-fanout.v2", "runtime_id": runtime,
        "bootstrap": bootstrap, "host_record": record, "authority": bundle, "results": results,
        "runner": {"plan": {"schema": "chio.process.run.v1", "workers": planned}, "workers": completed},
        "aggregate": {"profile": "chio.aggregate-family-invocation.v1", "owner_id": family.owner_id,
            "max_invocations": 2, "reserved_invocations": 0, "captured_invocations": 2}, "confinement": {}});
    let mut body = bootstrap.body();
    body.id.clear();
    body.tool_name = "attest_completed_fanout".into();
    body.action = ToolCallAction::from_parameters(parameters.clone())?;
    body.content_hash = hash(&parameters)?;
    Ok((ChioReceipt::sign(body, &signer)?, signer))
}

#[test]
fn current_abi_completed_run_reports_preserve_incomplete_qualification_aliases() -> Result {
    let directory = tempfile::tempdir()?;
    let (signed, signer) = modeled_completed_fanout()?;
    assert!(signed.verify_signature()?);
    let artifact = directory.path().join("modeled-completed-fanout.json");
    let key = directory.path().join("modeled-kernel.pub");
    std::fs::write(&artifact, canonical_json_bytes(&signed)?)?;
    std::fs::write(&key, signer.public_key().to_hex())?;
    let output = process(&[
        "verify-run",
        "--artifact",
        artifact.to_str().ok_or("artifact path")?,
        "--trusted-kernel-pubkey",
        key.to_str().ok_or("key path")?,
        "--runtime-id",
        "modeled-completed-fanout-current-abi",
    ])?;
    eprintln!(
        "verify_run_alias_stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = success(output)?;
    assert_eq!(report["schema"], "chio.process.run-verification.v1");
    assert_eq!(
        report["artifact_schema"],
        "chio.process.completed-fanout.v2"
    );
    assert_eq!(report["verified_workers"], json!(["alice", "bob"]));
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(report["verified_native_launches"], 0);
    for check in [
        "actual_join_parents",
        "terminal_result",
        "continuation_custody",
        "aggregate_usage",
    ] {
        assert!(report["checks"]
            .as_array()
            .ok_or("checks")?
            .contains(&json!(check)));
    }
    for unchecked in ["execution_nonces", "receipt_log_inclusion"] {
        assert!(report["unchecked"]
            .as_array()
            .ok_or("unchecked")?
            .contains(&json!(unchecked)));
    }
    assert_eq!(report["qualification_complete"], false);
    assert_eq!(report["m5_acceptance_complete"], false);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn completed_run_exports_preserve_incomplete_qualification_aliases() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let fixture = success(Command::new("python3")
        .args(["-c", "import sys,json; from pathlib import Path; import swarm; print(json.dumps(swarm.exercise(sys.argv[1],Path(sys.argv[2]),supervisor_only=True)))"])
        .arg(env!("CARGO_BIN_EXE_chio")).arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?).output()?)?;
    assert_eq!(fixture["effects"], 2);
    let state = root.join("state");
    let artifact = root.join("exported-completed-fanout.json");
    let key = state.join("authority.db.kernel.pub");
    let summary_output = process(&[
        "attest-run",
        "--state",
        state.to_str().ok_or("state path")?,
        "--plan",
        state
            .join("reference-run-plan.json")
            .to_str()
            .ok_or("plan path")?,
        "--out",
        artifact.to_str().ok_or("artifact path")?,
    ])?;
    eprintln!(
        "attest_run_alias_stdout={}",
        String::from_utf8_lossy(&summary_output.stdout)
    );
    let summary = success(summary_output)?;
    let runtime = summary["runtime_id"].as_str().ok_or("runtime")?;
    let report = success(process(&[
        "verify-run",
        "--artifact",
        artifact.to_str().ok_or("artifact path")?,
        "--trusted-kernel-pubkey",
        key.to_str().ok_or("key path")?,
        "--runtime-id",
        runtime,
    ])?)?;
    assert_eq!(report["verified_workers"], json!(["alice", "bob"]));
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(
        report["artifact_schema"],
        "chio.process.completed-fanout.v3"
    );
    for check in [
        "execution_nonces",
        "receipt_log_inclusion",
        "continuation_custody",
    ] {
        assert!(report["checks"]
            .as_array()
            .ok_or("checks")?
            .contains(&json!(check)));
    }
    let signed: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
    assert!(signed.verify_signature()?);
    assert_eq!(summary["receipt_id"], signed.id);
    assert_eq!(summary["workers"], 2);
    assert_eq!(summary["qualification_complete"], false);
    assert_eq!(summary["m5_acceptance_complete"], false);
    Ok(())
}
