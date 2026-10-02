use std::io::Write;
use std::path::{Path, PathBuf};

use chio_core_types::capability::attenuation::validate_attenuation;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_runtime_core::outcome_continuation::{
    ArtifactOutcome, OutcomeEffectArguments, OutcomeEffectRequest, OutcomeEffectRule,
    OutcomeEffectSlot, SignedArtifactOutcome, ARTIFACT_OUTCOME_SCHEMA,
};
use serde_json::{json, Value};

mod gates;
mod graph;
mod process;
mod workload;
use gates::{Gate, Result};

const NOW: u64 = 1_800_000_000_000;
const BACKENDS: [&str; 2] = ["chio", "ledger"];

fn scope(server: &str, tool: &str) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: server.into(),
            tool_name: tool.into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn fixture() -> Result<(OutcomeEffectRule, OutcomeEffectRequest, Vec<u8>)> {
    let artifact = canonical_json_bytes(&scope("source-checkout", "read"))?;
    let contract = json!({"schema":"scope-contract.experimental.v1","ceiling":scope("source-checkout","read"),"required":scope("source-checkout","read")});
    let candidate: ChioScope = serde_json::from_slice(&artifact)?;
    validate_attenuation(&scope("source-checkout", "read"), &candidate)?;
    validate_attenuation(&candidate, &scope("source-checkout", "read"))?;
    let rule = OutcomeEffectRule {
        slot: OutcomeEffectSlot {
            receiver_id: Keypair::from_seed(&[41; 32]).public_key().to_hex(),
            workflow_id: "repair-read-policy".into(),
            step_id: "publish-approved-scope".into(),
        },
        predecessor_step_id: "verify-owner-scope-contract".into(),
        verifier_key: Keypair::from_seed(&[42; 32]).public_key(),
        contract_sha256: sha256_hex(&canonical_json_bytes(&contract)?),
        server_id: "artifact-registry".into(),
        tool_name: "publish".into(),
        resource: "review-queue".into(),
        valid_from_unix_ms: NOW - 1000,
        valid_until_unix_ms: NOW + 1000,
    };
    let evidence = SignedArtifactOutcome::sign(
        ArtifactOutcome {
            schema: ARTIFACT_OUTCOME_SCHEMA.into(),
            slot: rule.slot.clone(),
            predecessor_step_id: rule.predecessor_step_id.clone(),
            contract_sha256: rule.contract_sha256.clone(),
            artifact_sha256: sha256_hex(&artifact),
            passed: true,
            verified_at_unix_ms: NOW,
        },
        &Keypair::from_seed(&[42; 32]),
    )?;
    let request = OutcomeEffectRequest {
        arguments: OutcomeEffectArguments {
            artifact_sha256: sha256_hex(&artifact),
            resource: rule.resource.clone(),
        },
        evidence,
    };
    Ok((rule, request, artifact))
}

fn append_effect(directory: &Path) -> Result<Value> {
    let (_, request, artifact) = fixture()?;
    let value = json!({"artifactSha256":request.arguments.artifact_sha256,"resource":request.arguments.resource});
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("effects.log"))?;
    writeln!(file, "{}", serde_json::to_string(&value)?)?;
    file.sync_all()?;
    let mut approved = std::fs::File::create(directory.join("approved.scope.json"))?;
    approved.write_all(&artifact)?;
    approved.sync_all()?;
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(value)
}

fn count(directory: &Path) -> Result<usize> {
    match std::fs::read_to_string(directory.join("effects.log")) {
        Ok(text) => Ok(text.lines().count()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn substitutions(root: &Path) -> Result<Value> {
    let cases = [
        "valid",
        "key",
        "contract",
        "predecessor",
        "receiver",
        "workflow",
        "step",
        "artifact",
        "resource",
        "failed",
        "future",
        "old",
        "server",
        "tool",
        "unsigned",
        "schema",
    ];
    let mut rows = Vec::new();
    for case in cases {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let directory = root.join("substitutions").join(case).join(backend);
            let (rule, valid, _) = fixture()?;
            let gate = Gate::open(backend, &directory, &rule)?;
            let mut changed = valid.clone();
            let mut signer = Keypair::from_seed(&[42; 32]);
            let mut server = rule.server_id.as_str();
            let mut tool = rule.tool_name.as_str();
            match case {
                "key" => signer = Keypair::from_seed(&[43; 32]),
                "contract" => {
                    changed.evidence.body.contract_sha256 = sha256_hex(b"easier contract")
                }
                "predecessor" => changed.evidence.body.predecessor_step_id = "unverified".into(),
                "receiver" => changed.evidence.body.slot.receiver_id = "another-owner".into(),
                "workflow" => changed.evidence.body.slot.workflow_id = "another-workflow".into(),
                "step" => changed.evidence.body.slot.step_id = "another-step".into(),
                "artifact" => changed.arguments.artifact_sha256 = sha256_hex(b"untested"),
                "resource" => changed.arguments.resource = "production".into(),
                "failed" => changed.evidence.body.passed = false,
                "future" => changed.evidence.body.verified_at_unix_ms = NOW + 1,
                "old" => changed.evidence.body.verified_at_unix_ms = NOW - 1001,
                "server" => server = "unselected-server",
                "tool" => tool = "delete",
                "valid" | "unsigned" | "schema" => {}
                _ => return Err("unhandled case".into()),
            }
            changed.evidence = SignedArtifactOutcome::sign(changed.evidence.body, &signer)?;
            if case == "unsigned" {
                changed.evidence.body.artifact_sha256 = sha256_hex(b"rewritten");
                changed.arguments.artifact_sha256 = changed.evidence.body.artifact_sha256.clone();
            }
            if case == "schema" {
                changed.evidence.body.schema = "other-protocol".into();
                // Isolate schema rejection from signature rejection. The typed
                // constructor deliberately cannot sign an unsupported schema.
                changed.evidence.signature =
                    signer.sign(&canonical_json_bytes(&changed.evidence.body)?);
            }
            let initial = gate
                .prepare(&changed, server, tool, NOW)
                .and_then(|prepared| gate.claim(&prepared, server, tool, NOW));
            let accepted = initial.is_ok();
            if let Ok(permit) = initial {
                let result = append_effect(&directory)?;
                gate.complete(permit, &result)?;
            }
            assert_eq!(accepted, case == "valid", "{backend} {case}");
            let initial_effects = count(&directory)?;
            let followup = gate
                .prepare(&valid, &rule.server_id, &rule.tool_name, NOW)
                .and_then(|prepared| gate.claim(&prepared, &rule.server_id, &rule.tool_name, NOW));
            let followup_allowed = followup.is_ok();
            if let Ok(permit) = followup {
                let result = append_effect(&directory)?;
                gate.complete(permit, &result)?;
            }
            assert_eq!(followup_allowed, case != "valid");
            assert_eq!(initial_effects, usize::from(accepted));
            assert_eq!(count(&directory)?, 1);
            observations.push(json!({"accepted":accepted,"initialEffects":initial_effects,"validFollowupAllowed":followup_allowed,"totalEffects":count(&directory)?,"state":gate.status(&rule)?.0}));
        }
        assert_eq!(observations[0], observations[1], "{case}");
        rows.push(json!({"case":case,"chio":observations[0],"ledger":observations[1]}));
    }
    Ok(json!(rows))
}

fn transitions(root: &Path) -> Result<Value> {
    let mut rows = Vec::new();
    for case in [
        "revocation_after_prepare",
        "expiry_after_prepare",
        "argument_after_prepare",
        "fresh_signature_after_completion",
        "fresh_candidate_after_completion",
        "two_prepared_authorizations",
    ] {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let directory = root.join("transitions").join(case).join(backend);
            let (rule, request, _) = fixture()?;
            let gate = Gate::open(backend, &directory, &rule)?;
            let mut prepared = gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW)?;
            let mut now = NOW;
            match case {
                "revocation_after_prepare" => gate.revoke(&rule)?,
                "expiry_after_prepare" => now = rule.valid_until_unix_ms,
                "argument_after_prepare" => prepared.arguments_mut().resource = "production".into(),
                _ => {
                    let second_prepared = if case == "two_prepared_authorizations" {
                        Some(gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW)?)
                    } else {
                        None
                    };
                    let first = gate.claim(
                        second_prepared.as_ref().unwrap_or(&prepared),
                        &rule.server_id,
                        &rule.tool_name,
                        NOW,
                    )?;
                    gate.complete(first, &append_effect(&directory)?)?;
                }
            }
            drop(gate);
            let reopened = Gate::open(backend, &directory, &rule)?;
            let second = if case.starts_with("fresh_") {
                let mut fresh = request.clone();
                fresh.evidence.body.verified_at_unix_ms = NOW + 1;
                if case == "fresh_candidate_after_completion" {
                    fresh.evidence.body.artifact_sha256 = sha256_hex(b"another verified artifact");
                    fresh.arguments.artifact_sha256 = fresh.evidence.body.artifact_sha256.clone();
                }
                fresh.evidence = SignedArtifactOutcome::sign(
                    fresh.evidence.body,
                    &Keypair::from_seed(&[42; 32]),
                )?;
                reopened
                    .prepare(&fresh, &rule.server_id, &rule.tool_name, NOW + 1)
                    .and_then(|p| reopened.claim(&p, &rule.server_id, &rule.tool_name, NOW + 1))
            } else {
                reopened.claim(&prepared, &rule.server_id, &rule.tool_name, now)
            };
            assert!(second.is_err(), "{case} {backend}");
            let expected =
                usize::from(case.starts_with("fresh_") || case == "two_prepared_authorizations");
            assert_eq!(count(&directory)?, expected);
            observations.push(
                json!({"secondAllowed":false,"effects":expected,"state":reopened.status(&rule)?.0}),
            );
        }
        assert_eq!(observations[0], observations[1]);
        rows.push(json!({"case":case,"chio":observations[0],"ledger":observations[1]}));
    }
    Ok(json!(rows))
}

fn run(root: &Path) -> Result<Value> {
    let (rule, request, artifact) = fixture()?;
    std::fs::write(root.join("candidate.scope.json"), artifact)?;
    std::fs::write(
        root.join("receiver-rule.json"),
        serde_json::to_vec_pretty(&rule)?,
    )?;
    std::fs::write(
        root.join("effect-request.json"),
        serde_json::to_vec_pretty(&request)?,
    )?;
    let substitutions = substitutions(root)?;
    let transitions = transitions(root)?;
    let faults = process::compare(root)?;
    let workflow = workload::compare(root)?;
    let ledger_handles = ledger_handles(root)?;
    let report = json!({
        "experiment":"matched-outcome-ledger-comparison",
        "commonSubstitutionCases":substitutions,"commonTransitionCases":transitions,
        "processFaults":faults,"kernelArtifactWorkflows":workflow,"ledgerHandleChecks":ledger_handles,
        "separationObserved":false,
        "scope":"Outcome gates under identical trusted kernel/tool and storage assumptions; not a comparison of complete protocols",
        "limits":["No timing or integration-effort superiority claim","No protection against store rollback, dishonest verifier or cloned receiver authority","Static native-policy workload, not independently administered remote agents"]
    });
    std::fs::write(
        root.join("comparison.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

fn ledger_handles(root: &Path) -> Result<Value> {
    let directory = root.join("ledger-handles");
    let (rule, request, _) = fixture()?;
    let gate = Gate::open("ledger", &directory, &rule)?;
    let first = gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW)?;
    let second = gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW)?;
    let (gates::Prepared::Ledger { handle: a, .. }, gates::Prepared::Ledger { handle: b, .. }) =
        (&first, &second)
    else {
        return Err("wrong baseline preparation".into());
    };
    assert_ne!(a, b, "exchange must really issue fresh opaque references");
    let mut forged = first.clone();
    let gates::Prepared::Ledger { handle, .. } = &mut forged else {
        return Err("wrong baseline preparation".into());
    };
    *handle = sha256_hex(b"caller-invented-handle");
    assert!(gate
        .claim(&forged, &rule.server_id, &rule.tool_name, NOW)
        .is_err());
    assert_eq!(count(&directory)?, 0);
    let permit = gate.claim(&first, &rule.server_id, &rule.tool_name, NOW)?;
    gate.complete(permit, &append_effect(&directory)?)?;
    assert!(gate
        .claim(&second, &rule.server_id, &rule.tool_name, NOW)
        .is_err());
    assert_eq!(count(&directory)?, 1);
    Ok(
        json!({"freshHandlesObserved":true,"forgedHandleRejected":true,"freshHandleDidNotRefillBudget":true,"physicalEffects":1}),
    )
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "--repair-audit-worker") {
        if args.len() != 4 {
            return Err("audit worker requires trusted base, packet and output".into());
        }
        return graph::repair::git_recovery::audit::worker(
            Path::new(&args[1]),
            Path::new(&args[2]),
            Path::new(&args[3]),
        );
    }
    if args.first().is_some_and(|s| s == "--audit-repair-bundle") {
        if args.len() != 3 && args.len() != 4 {
            return Err("usage: --audit-repair-bundle TRUSTED_BASE PACKET [NEW_OUTPUT]".into());
        }
        let root = if let Some(path) = args.get(3) {
            let path = PathBuf::from(path);
            std::fs::create_dir(&path)?;
            path
        } else {
            tempfile::tempdir()?.keep()
        };
        let result = graph::repair::git_recovery::audit::audit(
            Path::new(&args[1]),
            Path::new(&args[2]),
            &root,
        )?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        println!("Audit evidence: {}", root.display());
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "--git-repair-worker") {
        if args.len() != 3 {
            return Err("Git worker requires owner directory and mode".into());
        }
        return graph::repair::git_recovery::worker(Path::new(&args[1]), &args[2]);
    }
    if args.first().is_some_and(|s| {
        s == "--repair"
            || s == "--repair-receiver-check"
            || s == "--repair-git-recovery"
            || s == "--repair-artifact-audit"
            || s == "--repair-work-reuse"
            || s == "--repair-exchange"
    }) {
        if args.len() != 3 && args.len() != 4 {
            return Err(
                "usage: --repair BASE_SOURCE_TREE CANDIDATE_SOURCE_TREE [NEW_OUTPUT_DIRECTORY]"
                    .into(),
            );
        }
        let root = if let Some(path) = args.get(3) {
            let path = PathBuf::from(path);
            std::fs::create_dir(&path)?;
            path
        } else {
            tempfile::tempdir()?.keep()
        };
        let report = if args[0] == "--repair-exchange" {
            graph::repair::exchange::compare(&root, Path::new(&args[1]), Path::new(&args[2]))?
        } else if args[0] == "--repair-work-reuse" {
            graph::repair::work_reuse::compare(&root, Path::new(&args[1]), Path::new(&args[2]))?
        } else if args[0] == "--repair-artifact-audit" {
            graph::repair::git_recovery::audit::compare(
                &root,
                Path::new(&args[1]),
                Path::new(&args[2]),
            )?
        } else if args[0] == "--repair-git-recovery" {
            graph::repair::git_recovery::compare(&root, Path::new(&args[1]), Path::new(&args[2]))?
        } else if args[0] == "--repair-receiver-check" {
            graph::repair::compare_receiver_check(&root, Path::new(&args[1]), Path::new(&args[2]))?
        } else {
            graph::repair::compare(&root, Path::new(&args[1]), Path::new(&args[2]))?
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        println!("Repair evidence: {}", root.display());
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "--graph-probe") {
        if args.len() != 2 {
            return Err("graph probe requires its trusted test specification".into());
        }
        return graph::probe(Path::new(&args[1]));
    }
    if args.first().is_some_and(|s| s == "--graph-courier") {
        if args.len() != 3 {
            return Err("graph courier requires public job and checkpoint mode".into());
        }
        return graph::courier(Path::new(&args[1]), &args[2]);
    }
    if args.first().is_some_and(|s| s == "--graph-worker") {
        if args.len() != 3 {
            return Err("graph worker requires owner directory and fault mode".into());
        }
        return graph::worker(Path::new(&args[1]), &args[2]);
    }
    if args
        .first()
        .is_some_and(|s| s == "--graph" || s == "--isolated-graph")
    {
        if args.len() > 2 {
            return Err("usage: --graph [NEW_OUTPUT_DIRECTORY]".into());
        }
        let root = if let Some(path) = args.get(1) {
            let path = PathBuf::from(path);
            std::fs::create_dir(&path)?;
            path
        } else {
            tempfile::tempdir()?.keep()
        };
        let report = if args[0] == "--isolated-graph" {
            graph::compare_isolated(&root)?
        } else {
            graph::compare(&root)?
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        println!("Graph evidence: {}", root.display());
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "--worker") {
        if args.len() != 4 {
            return Err("invalid worker arguments".into());
        }
        return process::worker(&args[1], Path::new(&args[2]), &args[3]);
    }
    if args.len() > 1 {
        return Err("usage: chio-outcome-ledger-comparison [NEW_OUTPUT_DIRECTORY]".into());
    }
    let root = if let Some(path) = args.first() {
        let root = PathBuf::from(path);
        std::fs::create_dir(&root)?;
        root
    } else {
        tempfile::tempdir()?.keep()
    };
    let report = run(&root)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    println!("Evidence: {}", root.display());
    Ok(())
}
